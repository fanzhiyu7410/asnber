/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * schema 运行时注册、封存校验与销毁。
 *
 * 职责：创建类型树、追加类型/字段/命名记录、封存期结构校验与资源释放。
 * 依赖：core/asnber_context.h、schema/asnber_schema.h。
 * 所有权：所有内容复制进上下文级分配；调用方描述符可立即释放。
 */

#include <cstring>

#include "schema/detail/schema_internal.h"

namespace asnber {
namespace schema_detail {

/* ===== 分配与复制 ===== */

asnber_err_t allocateSchema(Context *ctx, size_t size, void **out) noexcept
{
    return contextAllocate(ctx, size, AllocationKind::kSchema, out);
}

// count * elementSize 是否超出 size_t 可表达范围。
// GCC/Clang 用溢出内建，避免把常量范围比较判成恒假
// （Clang -Wtautological-constant-out-of-range-compare）；其他编译器用除法回退。
bool countOverflowsSize(size_t count, size_t elementSize) noexcept
{
#if defined(__GNUC__) || defined(__clang__)
    size_t total = 0;
    return __builtin_mul_overflow(count, elementSize, &total) != 0;
#else
    return count != 0 && elementSize > SIZE_MAX / count;
#endif
}

asnber_err_t copyText(Context *ctx, const char *src, const char **out,
                    asnber_err_t invalidCode) noexcept
{
    if (src == nullptr || src[0] == '\0') {
        contextSetError(ctx, invalidCode, SIZE_MAX, 0);
        return invalidCode;
    }
    const size_t len = std::strlen(src);
    char *dst = nullptr;
    void *raw = nullptr;
    const asnber_err_t rc = allocateSchema(ctx, len + 1, &raw);
    if (rc != ASNBER_OK) {
        return rc;
    }
    dst = static_cast<char *>(raw);
    std::memcpy(dst, src, len + 1);
    *out = dst;
    return ASNBER_OK;
}

asnber_err_t copyBytes(Context *ctx, const void *src, size_t size,
                     const uint8_t **out, asnber_err_t invalidCode) noexcept
{
    if (src == nullptr || size == 0) {
        contextSetError(ctx, invalidCode, SIZE_MAX, 0);
        return invalidCode;
    }
    void *raw = nullptr;
    const asnber_err_t rc = allocateSchema(ctx, size, &raw);
    if (rc != ASNBER_OK) {
        return rc;
    }
    std::memcpy(raw, src, size);
    *out = static_cast<const uint8_t *>(raw);
    return ASNBER_OK;
}

} /* namespace schema_detail */
} /* namespace asnber */

namespace asnber {

using namespace schema_detail;

namespace {

/* ===== 封存校验 ===== */

asnber_err_t sealCheckFields(Context *ctx, Schema *schema) noexcept
{
    for (uint32_t i = 0; i < schema->typeCount; ++i) {
        SchemaType *type = &schema->types[i];
        const bool isChoice =
            type->kind == static_cast<uint32_t>(ASNBER_TYPE_KIND_CHOICE);
        const bool isOf = isOfKind(type->kind);
        const bool isAny =
            type->kind == static_cast<uint32_t>(ASNBER_TYPE_KIND_ANY);

        if (isAny) {
            if (type->fieldCount != 0) {
                contextSetError(ctx, ASNBER_E_SCHEMA_FIELD, SIZE_MAX, 0);
                return ASNBER_E_SCHEMA_FIELD;
            }
            if (type->constraintCount != 0) {
                contextSetError(ctx, ASNBER_E_SCHEMA_TYPE, SIZE_MAX, 0);
                return ASNBER_E_SCHEMA_TYPE;
            }
            continue;
        }

        if (isOf && type->fieldCount != 0) {
            contextSetError(ctx, ASNBER_E_SCHEMA_FIELD, SIZE_MAX, 0);
            return ASNBER_E_SCHEMA_FIELD;
        }
        for (uint32_t j = 0; j < type->fieldCount; ++j) {
            SchemaField *field = &type->fields[j];
            if (field->typeId == 0 || field->typeId > schema->typeCount) {
                contextSetError(ctx, ASNBER_E_SCHEMA_TYPE, SIZE_MAX, 0);
                return ASNBER_E_SCHEMA_TYPE;
            }
            if ((field->flags &
                 ~(ASNBER_FIELD_OPTIONAL | ASNBER_FIELD_EXTENSION)) != 0) {
                contextSetError(ctx, ASNBER_E_INVALID_CONFIG, SIZE_MAX, 0);
                return ASNBER_E_INVALID_CONFIG;
            }
            if (isChoice &&
                (field->flags != 0 || field->defaultSize != 0)) {
                contextSetError(ctx, ASNBER_E_SCHEMA_FIELD, SIZE_MAX, 0);
                return ASNBER_E_SCHEMA_FIELD;
            }
            if (field->defaultSize != 0 &&
                !schemaValidateDefaultTlv(field->defaultTlv,
                                          field->defaultSize)) {
                contextSetError(ctx, ASNBER_E_SCHEMA_DEFAULT, SIZE_MAX, 0);
                return ASNBER_E_SCHEMA_DEFAULT;
            }
            const asnber_err_t rc = validateSchemaConstraintArray(
                ctx, field->constraints, field->constraintCount);
            if (rc != ASNBER_OK) {
                return rc;
            }
        }
    }
    return ASNBER_OK;
}

/* 字段名重复检查（seal 期对每个类型重新确认）。 */
asnber_err_t sealCheckNames(Context *ctx, Schema *schema) noexcept
{
    for (uint32_t i = 0; i < schema->typeCount; ++i) {
        const SchemaType *type = &schema->types[i];
        const asnber_err_t typeRc = validateSchemaConstraintArray(
            ctx, type->constraints, type->constraintCount);
        if (typeRc != ASNBER_OK) {
            return typeRc;
        }
        for (uint32_t j = 0; j < type->fieldCount; ++j) {
            for (uint32_t k = j + 1; k < type->fieldCount; ++k) {
                if (std::strcmp(type->fields[j].name,
                                type->fields[k].name) == 0) {
                    contextSetError(ctx, ASNBER_E_SCHEMA_FIELD, SIZE_MAX, 0);
                    return ASNBER_E_SCHEMA_FIELD;
                }
            }
        }
    }
    return ASNBER_OK;
}

asnber_err_t sealCheckTags(Context *ctx, Schema *schema) noexcept
{
    for (uint32_t i = 0; i < schema->typeCount; ++i) {
        const SchemaType *type = &schema->types[i];
        const uint32_t setKind = static_cast<uint32_t>(ASNBER_TYPE_KIND_SET);
        const uint32_t choiceKind =
            static_cast<uint32_t>(ASNBER_TYPE_KIND_CHOICE);
        const bool isSet = type->kind == setKind;
        const bool isChoice = type->kind == choiceKind;

        if (type->kind == static_cast<uint32_t>(ASNBER_TYPE_KIND_SEQUENCE)) {
            for (uint32_t j = 0; j < type->fieldCount; ++j) {
                const SchemaType *fieldType =
                    findType(schema, type->fields[j].typeId);
                const bool isAnyField =
                    fieldType != nullptr &&
                    fieldType->kind == static_cast<uint32_t>(ASNBER_TYPE_KIND_ANY);
                const bool unwrappedAny =
                    isAnyField &&
                    fieldType->tagMode ==
                        static_cast<uint32_t>(ASNBER_TAG_MODE_DEFAULT);
                if (unwrappedAny) {
                    /* 无包装 ANY 无标签，只能作为末位字段；不参与标签唯一性，
                       也不是后续字段的后继标签。 */
                    if (j + 1 != type->fieldCount) {
                        contextSetError(ctx, ASNBER_E_SCHEMA_TYPE, SIZE_MAX, 0);
                        return ASNBER_E_SCHEMA_TYPE;
                    }
                    continue;
                }
                if ((type->fields[j].flags & ASNBER_FIELD_OPTIONAL) == 0 &&
                    type->fields[j].defaultSize == 0) {
                    continue;
                }
                TagSet first = {};
                if (!collectTags(*schema, type->fields[j].typeId, 0, &first)) {
                    contextSetError(ctx, ASNBER_E_SCHEMA_TYPE, SIZE_MAX, 0);
                    return ASNBER_E_SCHEMA_TYPE;
                }
                for (uint32_t k = j + 1; k < type->fieldCount; ++k) {
                    const SchemaType *laterType =
                        findType(schema, type->fields[k].typeId);
                    if (laterType != nullptr &&
                        laterType->kind ==
                            static_cast<uint32_t>(ASNBER_TYPE_KIND_ANY) &&
                        laterType->tagMode ==
                            static_cast<uint32_t>(ASNBER_TAG_MODE_DEFAULT)) {
                        /* 末位无包装 ANY 不提供后继标签。 */
                        continue;
                    }
                    TagSet later = {};
                    if (!collectTags(*schema, type->fields[k].typeId, 0,
                                     &later)) {
                        contextSetError(ctx, ASNBER_E_SCHEMA_TYPE, SIZE_MAX, 0);
                        return ASNBER_E_SCHEMA_TYPE;
                    }
                    if (tagsIntersect(first, later)) {
                        contextSetError(ctx, ASNBER_E_SCHEMA_TYPE, SIZE_MAX, 0);
                        return ASNBER_E_SCHEMA_TYPE;
                    }
                }
            }
        }

        if (isSet || isChoice) {
            for (uint32_t j = 0; j < type->fieldCount; ++j) {
                const SchemaType *fieldType =
                    findType(schema, type->fields[j].typeId);
                if (fieldType != nullptr &&
                    fieldType->kind ==
                        static_cast<uint32_t>(ASNBER_TYPE_KIND_ANY) &&
                    fieldType->tagMode ==
                        static_cast<uint32_t>(ASNBER_TAG_MODE_DEFAULT)) {
                    /* SET/CHOICE 依赖标签识别字段，无包装 ANY 无法判定。 */
                    contextSetError(ctx, ASNBER_E_SCHEMA_TYPE, SIZE_MAX, 0);
                    return ASNBER_E_SCHEMA_TYPE;
                }
                TagSet first = {};
                if (!collectTags(*schema, type->fields[j].typeId, 0, &first)) {
                    contextSetError(ctx, ASNBER_E_SCHEMA_TYPE, SIZE_MAX, 0);
                    return ASNBER_E_SCHEMA_TYPE;
                }
                for (uint32_t k = j + 1; k < type->fieldCount; ++k) {
                    TagSet later = {};
                    if (!collectTags(*schema, type->fields[k].typeId, 0,
                                     &later)) {
                        contextSetError(ctx, ASNBER_E_SCHEMA_TYPE, SIZE_MAX, 0);
                        return ASNBER_E_SCHEMA_TYPE;
                    }
                    if (tagsIntersect(first, later)) {
                        contextSetError(ctx, ASNBER_E_SCHEMA_TYPE, SIZE_MAX, 0);
                        return ASNBER_E_SCHEMA_TYPE;
                    }
                }
            }
        }
    }
    return ASNBER_OK;
}

} /* namespace */

/* ===== 对外内部接口 ===== */

uint32_t schemaCrc32c(const uint8_t *data, size_t size, size_t zeroOffset,
                      size_t zeroLength) noexcept
{
    uint32_t crc = 0xFFFFFFFFU;
    for (size_t i = 0; i < size; ++i) {
        const bool zeroed = i >= zeroOffset && i < zeroOffset + zeroLength;
        const uint8_t byte = zeroed ? 0 : data[i];
        crc ^= static_cast<uint32_t>(byte);
        for (uint32_t bit = 0; bit < 8; ++bit) {
            const uint32_t mask =
                static_cast<uint32_t>(0u - (crc & UINT32_C(1)));
            crc = (crc >> 1) ^ (0x82F63B78U & mask);
        }
    }
    return crc ^ 0xFFFFFFFFU;
}

asnber_err_t schemaCreate(Context *ctx, uint32_t defaultTagMode,
                        Schema **outSchema) noexcept
{
    *outSchema = nullptr;
    if (!validTagMode(defaultTagMode)) {
        contextSetError(ctx, ASNBER_E_INVALID_ARG, SIZE_MAX, 0);
        return ASNBER_E_INVALID_ARG;
    }

    void *raw = nullptr;
    const asnber_err_t rc =
        allocateSchema(ctx, sizeof(Schema), &raw);
    if (rc != ASNBER_OK) {
        return rc;
    }
    Schema *schema = static_cast<Schema *>(raw);
    std::memset(schema, 0, sizeof(*schema));
    schema->ctx = ctx;
    schema->moduleTagMode = defaultTagMode;
    schema->magic = kSchemaMagic;
    *outSchema = schema;
    return ASNBER_OK;
}

asnber_err_t schemaAddType(Context *ctx, Schema *schema,
                         const asnber_type_desc_t *desc, uint32_t *outTypeId,
                         bool allowUnregisteredElement) noexcept
{
    *outTypeId = 0;
    if (schema->sealed) {
        contextSetError(ctx, ASNBER_E_INVALID_STATE, SIZE_MAX, 0);
        return ASNBER_E_INVALID_STATE;
    }
    if (desc->struct_size != sizeof(asnber_type_desc_t) ||
        desc->reserved[0] != 0 || desc->reserved[1] != 0) {
        contextSetError(ctx, ASNBER_E_INVALID_CONFIG, SIZE_MAX, 0);
        return ASNBER_E_INVALID_CONFIG;
    }
    return appendType(ctx, schema, desc, allowUnregisteredElement, outTypeId);
}

asnber_err_t schemaAddField(Context *ctx, Schema *schema, uint32_t parentTypeId,
                          const asnber_field_desc_t *desc) noexcept
{
    if (schema->sealed) {
        contextSetError(ctx, ASNBER_E_INVALID_STATE, SIZE_MAX, 0);
        return ASNBER_E_INVALID_STATE;
    }
    if (desc->struct_size != sizeof(asnber_field_desc_t) ||
        desc->reserved[0] != 0 || desc->reserved[1] != 0) {
        contextSetError(ctx, ASNBER_E_INVALID_CONFIG, SIZE_MAX, 0);
        return ASNBER_E_INVALID_CONFIG;
    }
    return appendField(ctx, schema, parentTypeId, desc);
}

asnber_err_t schemaAddName(Context *ctx, Schema *schema, uint32_t typeId,
                         const char *name, uint32_t kind, uint32_t flags,
                         int64_t value) noexcept
{
    const char *copied = nullptr;
    asnber_err_t rc = copyText(ctx, name, &copied, ASNBER_E_SCHEMA_FORMAT);
    if (rc != ASNBER_OK) {
        return rc;
    }

    if (schema->nameCount == schema->nameCapacity) {
        rc = growNames(ctx, schema);
        if (rc != ASNBER_OK) {
            contextRelease(ctx, const_cast<char *>(copied));
            return rc;
        }
    }

    SchemaName *entry = &schema->names[schema->nameCount];
    entry->typeId = typeId;
    entry->name = copied;
    entry->kind = kind;
    entry->flags = flags;
    entry->value = value;
    ++schema->nameCount;
    return ASNBER_OK;
}

asnber_err_t schemaSetRoot(Context *ctx, Schema *schema,
                         uint32_t rootTypeId) noexcept
{
    if (schema->sealed) {
        contextSetError(ctx, ASNBER_E_INVALID_STATE, SIZE_MAX, 0);
        return ASNBER_E_INVALID_STATE;
    }
    if (rootTypeId > schema->typeCount) {
        contextSetError(ctx, ASNBER_E_SCHEMA_TYPE, SIZE_MAX, 0);
        return ASNBER_E_SCHEMA_TYPE;
    }
    schema->rootTypeId = rootTypeId;
    return ASNBER_OK;
}

asnber_err_t schemaSeal(Context *ctx, Schema *schema) noexcept
{
    if (schema->sealed) {
        return ASNBER_OK;
    }

    if (schema->rootTypeId > schema->typeCount) {
        contextSetError(ctx, ASNBER_E_SCHEMA_TYPE, SIZE_MAX, 0);
        return ASNBER_E_SCHEMA_TYPE;
    }

    for (uint32_t i = 0; i < schema->typeCount; ++i) {
        SchemaType *type = &schema->types[i];
        asnber_err_t rc = validateTypeCombination(
            type->kind, type->tagClass, type->tagNumber, type->tagMode);
        if (rc != ASNBER_OK) {
            contextSetError(ctx, rc, SIZE_MAX, 0);
            return rc;
        }
        if (isOfKind(type->kind)) {
            if (type->elementTypeId == 0 ||
                type->elementTypeId > schema->typeCount) {
                contextSetError(ctx, ASNBER_E_SCHEMA_TYPE, SIZE_MAX, 0);
                return ASNBER_E_SCHEMA_TYPE;
            }
        } else if (type->elementTypeId != 0) {
            contextSetError(ctx, ASNBER_E_SCHEMA_TYPE, SIZE_MAX, 0);
            return ASNBER_E_SCHEMA_TYPE;
        }
    }

    asnber_err_t rc = sealCheckFields(ctx, schema);
    if (rc != ASNBER_OK) {
        return rc;
    }
    rc = sealCheckNames(ctx, schema);
    if (rc != ASNBER_OK) {
        return rc;
    }
    rc = sealCheckTags(ctx, schema);
    if (rc != ASNBER_OK) {
        return rc;
    }

    schema->sealed = true;
    return ASNBER_OK;
}

void schemaDestroy(Schema *schema) noexcept
{
    if (schema == nullptr || schema->magic != kSchemaMagic) {
        return;
    }
    Context *ctx = schema->ctx;
    for (uint32_t i = 0; i < schema->typeCount; ++i) {
        SchemaType *type = &schema->types[i];
        for (uint32_t j = 0; j < type->fieldCount; ++j) {
            contextRelease(ctx, const_cast<char *>(type->fields[j].name));
            contextRelease(ctx,
                          const_cast<uint8_t *>(type->fields[j].defaultTlv));
            destroyConstraintArray(ctx, type->fields[j].constraints,
                                   type->fields[j].constraintCount);
        }
        contextRelease(ctx, type->fields);
        contextRelease(ctx, const_cast<char *>(type->name));
        destroyConstraintArray(ctx, type->constraints, type->constraintCount);
    }
    for (uint32_t i = 0; i < schema->nameCount; ++i) {
        contextRelease(ctx, const_cast<char *>(schema->names[i].name));
    }
    contextRelease(ctx, schema->names);
    contextRelease(ctx, schema->types);
    schema->magic = 0;
    contextRelease(ctx, schema);
}

} /* namespace asnber */
