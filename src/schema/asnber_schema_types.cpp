/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * schema 运行时注册：类型规则与类型/字段追加。
 *
 * 职责：类型组合校验、数组增长、类型查找与重名检查，以及把公开描述符
 *       复制成内部类型/字段记录。
 * 依赖：schema/asnber_schema.h。
 */

#include <cstring>

#include "schema/detail/schema_internal.h"

namespace asnber {
namespace schema_detail {

/* ===== 基础校验 ===== */


bool validTagMode(uint32_t mode) noexcept
{
    return mode <= static_cast<uint32_t>(ASNBER_TAG_MODE_IMPLICIT);
}

bool canonicalUniversalTag(uint32_t kind, uint32_t tagNumber) noexcept
{
    if (kind == static_cast<uint32_t>(ASNBER_TYPE_KIND_SEQUENCE) ||
        kind == static_cast<uint32_t>(ASNBER_TYPE_KIND_SEQUENCE_OF)) {
        return tagNumber == 0 || tagNumber == 16;
    }
    if (kind == static_cast<uint32_t>(ASNBER_TYPE_KIND_SET) ||
        kind == static_cast<uint32_t>(ASNBER_TYPE_KIND_SET_OF)) {
        return tagNumber == 0 || tagNumber == 17;
    }
    return false;
}

bool isOfKind(uint32_t kind) noexcept
{
    return kind == static_cast<uint32_t>(ASNBER_TYPE_KIND_SEQUENCE_OF) ||
           kind == static_cast<uint32_t>(ASNBER_TYPE_KIND_SET_OF);
}

/* docs/02 5.2 与 docs/11 第 4、10 节的类型组合校验。 */
asnber_err_t validateTypeCombination(uint32_t kind, uint32_t tagClass,
                                   uint32_t tagNumber, uint32_t tagMode) noexcept
{
    if (kind > static_cast<uint32_t>(ASNBER_TYPE_KIND_ANY) ||
        tagClass > static_cast<uint32_t>(ASNBER_TAG_PRIVATE) ||
        !validTagMode(tagMode)) {
        return ASNBER_E_SCHEMA_TYPE;
    }

    const uint32_t choice = static_cast<uint32_t>(ASNBER_TYPE_KIND_CHOICE);
    const uint32_t simple = static_cast<uint32_t>(ASNBER_TYPE_KIND_SIMPLE);
    const uint32_t anyKind = static_cast<uint32_t>(ASNBER_TYPE_KIND_ANY);
    const uint32_t universal = static_cast<uint32_t>(ASNBER_TAG_UNIVERSAL);
    const uint32_t defaultMode = static_cast<uint32_t>(ASNBER_TAG_MODE_DEFAULT);
    const uint32_t explicitMode = static_cast<uint32_t>(ASNBER_TAG_MODE_EXPLICIT);
    const uint32_t implicitMode = static_cast<uint32_t>(ASNBER_TAG_MODE_IMPLICIT);

    if (kind == anyKind) {
        /* ANY 无自身标签：默认形态为 UNIVERSAL 0；或使用非 UNIVERSAL 外层
           EXPLICIT 包装。IMPLICIT 对 ANY 无意义，禁止。 */
        if (tagMode == defaultMode) {
            if (tagClass != universal || tagNumber != 0) {
                return ASNBER_E_SCHEMA_TYPE;
            }
            return ASNBER_OK;
        }
        if (tagMode == explicitMode) {
            if (tagClass == universal) {
                return ASNBER_E_SCHEMA_TYPE;
            }
            return ASNBER_OK;
        }
        return ASNBER_E_SCHEMA_TYPE;
    }

    if (kind == choice) {
        if (tagMode == implicitMode) {
            return ASNBER_E_SCHEMA_TYPE;
        }
        if (tagMode == defaultMode) {
            if (tagClass != universal || tagNumber != 0) {
                return ASNBER_E_SCHEMA_TYPE;
            }
        } else if (tagMode == explicitMode) {
            if (tagClass == universal) {
                return ASNBER_E_SCHEMA_TYPE;
            }
        }
        return ASNBER_OK;
    }

    if (tagClass == universal && tagMode != defaultMode) {
        return ASNBER_E_SCHEMA_TYPE;
    }

    if (kind == simple) {
        if (tagClass == universal && tagNumber == 0) {
            return ASNBER_E_SCHEMA_TYPE;
        }
        return ASNBER_OK;
    }

    if (tagClass == universal && !canonicalUniversalTag(kind, tagNumber)) {
        return ASNBER_E_SCHEMA_TYPE;
    }
    return ASNBER_OK;
}

/* ===== 类型/字段数组增长 ===== */

asnber_err_t growTypes(Context *ctx, Schema *schema) noexcept
{
    const uint32_t newCapacity =
        schema->typeCapacity == 0 ? 4 : schema->typeCapacity * 2;
    if (newCapacity > UINT32_MAX / 2 ||
        countOverflowsSize(static_cast<size_t>(newCapacity),
                           sizeof(SchemaType))) {
        contextSetError(ctx, ASNBER_E_NOMEM, SIZE_MAX, 0);
        return ASNBER_E_NOMEM;
    }
    void *raw = nullptr;
    const asnber_err_t rc =
        allocateSchema(ctx, newCapacity * sizeof(SchemaType), &raw);
    if (rc != ASNBER_OK) {
        return rc;
    }
    SchemaType *next = static_cast<SchemaType *>(raw);
    std::memset(next, 0, newCapacity * sizeof(SchemaType));
    if (schema->types != nullptr) {
        std::memcpy(next, schema->types,
                    schema->typeCount * sizeof(SchemaType));
        contextRelease(ctx, schema->types);
    }
    schema->types = next;
    schema->typeCapacity = newCapacity;
    return ASNBER_OK;
}

asnber_err_t growFields(Context *ctx, SchemaType *type) noexcept
{
    const uint32_t newCapacity =
        type->fieldCapacity == 0 ? 4 : type->fieldCapacity * 2;
    if (newCapacity > UINT32_MAX / 2 ||
        countOverflowsSize(static_cast<size_t>(newCapacity),
                           sizeof(SchemaField))) {
        contextSetError(ctx, ASNBER_E_NOMEM, SIZE_MAX, 0);
        return ASNBER_E_NOMEM;
    }
    void *raw = nullptr;
    const asnber_err_t rc =
        allocateSchema(ctx, newCapacity * sizeof(SchemaField), &raw);
    if (rc != ASNBER_OK) {
        return rc;
    }
    SchemaField *next = static_cast<SchemaField *>(raw);
    std::memset(next, 0, newCapacity * sizeof(SchemaField));
    if (type->fields != nullptr) {
        std::memcpy(next, type->fields,
                    type->fieldCount * sizeof(SchemaField));
        contextRelease(ctx, type->fields);
    }
    type->fields = next;
    type->fieldCapacity = newCapacity;
    return ASNBER_OK;
}

asnber_err_t growNames(Context *ctx, Schema *schema) noexcept
{
    const uint32_t newCapacity =
        schema->nameCapacity == 0 ? 4 : schema->nameCapacity * 2;
    if (newCapacity > UINT32_MAX / 2 ||
        countOverflowsSize(static_cast<size_t>(newCapacity),
                           sizeof(SchemaName))) {
        contextSetError(ctx, ASNBER_E_NOMEM, SIZE_MAX, 0);
        return ASNBER_E_NOMEM;
    }
    void *raw = nullptr;
    const asnber_err_t rc =
        allocateSchema(ctx, newCapacity * sizeof(SchemaName), &raw);
    if (rc != ASNBER_OK) {
        return rc;
    }
    SchemaName *next = static_cast<SchemaName *>(raw);
    std::memset(next, 0, newCapacity * sizeof(SchemaName));
    if (schema->names != nullptr) {
        std::memcpy(next, schema->names,
                    schema->nameCount * sizeof(SchemaName));
        contextRelease(ctx, schema->names);
    }
    schema->names = next;
    schema->nameCapacity = newCapacity;
    return ASNBER_OK;
}

/* ===== 查找 ===== */

SchemaType *findType(Schema *schema, uint32_t typeId) noexcept
{
    if (typeId == 0 || typeId > schema->typeCount) {
        return nullptr;
    }
    return &schema->types[typeId - 1];
}

const SchemaType *findType(const Schema *schema, uint32_t typeId) noexcept
{
    if (typeId == 0 || typeId > schema->typeCount) {
        return nullptr;
    }
    return &schema->types[typeId - 1];
}

bool typeNameExists(const Schema *schema, const char *name,
                    uint32_t limit) noexcept
{
    for (uint32_t i = 0; i < limit; ++i) {
        if (std::strcmp(schema->types[i].name, name) == 0) {
            return true;
        }
    }
    return false;
}

bool fieldNameExists(const SchemaType *type, const char *name) noexcept
{
    for (uint32_t i = 0; i < type->fieldCount; ++i) {
        if (std::strcmp(type->fields[i].name, name) == 0) {
            return true;
        }
    }
    return false;
}

/* ===== 类型追加 ===== */

asnber_err_t appendType(Context *ctx, Schema *schema,
                      const asnber_type_desc_t *desc,
                      bool allowUnregisteredElement,
                      uint32_t *outTypeId) noexcept
{
    asnber_err_t rc = validateTypeCombination(
        static_cast<uint32_t>(desc->kind),
        static_cast<uint32_t>(desc->tag_class), desc->tag_number,
        static_cast<uint32_t>(desc->tag_mode));
    if (rc != ASNBER_OK) {
        contextSetError(ctx, rc, SIZE_MAX, 0);
        return rc;
    }
    if ((desc->flags & ~ASNBER_TYPE_EXTENSIBLE) != 0) {
        contextSetError(ctx, ASNBER_E_INVALID_CONFIG, SIZE_MAX, 0);
        return ASNBER_E_INVALID_CONFIG;
    }
    if (desc->constraint_count != 0 && desc->constraints == nullptr) {
        contextSetError(ctx, ASNBER_E_INVALID_ARG, SIZE_MAX, 0);
        return ASNBER_E_INVALID_ARG;
    }

    if (typeNameExists(schema, desc->name, schema->typeCount)) {
        contextSetError(ctx, ASNBER_E_SCHEMA_TYPE, SIZE_MAX, 0);
        return ASNBER_E_SCHEMA_TYPE;
    }

    const uint32_t elementId = desc->element_type_id;
    if (isOfKind(static_cast<uint32_t>(desc->kind))) {
        if (elementId == 0 ||
            (!allowUnregisteredElement && elementId > schema->typeCount)) {
            contextSetError(ctx, ASNBER_E_SCHEMA_TYPE, SIZE_MAX, 0);
            return ASNBER_E_SCHEMA_TYPE;
        }
    } else if (elementId != 0) {
        contextSetError(ctx, ASNBER_E_SCHEMA_TYPE, SIZE_MAX, 0);
        return ASNBER_E_SCHEMA_TYPE;
    }

    if (static_cast<uint32_t>(desc->kind) ==
            static_cast<uint32_t>(ASNBER_TYPE_KIND_ANY) &&
        desc->constraint_count != 0) {
        /* ANY 是开放类型，不得挂约束。 */
        contextSetError(ctx, ASNBER_E_SCHEMA_TYPE, SIZE_MAX, 0);
        return ASNBER_E_SCHEMA_TYPE;
    }

    SchemaConstraint *constraints = nullptr;
    uint32_t constraintCount = 0;
    rc = copyConstraints(ctx, desc->constraints, desc->constraint_count,
                         &constraints, &constraintCount);
    if (rc != ASNBER_OK) {
        return rc;
    }

    const char *name = nullptr;
    rc = copyText(ctx, desc->name, &name, ASNBER_E_INVALID_ARG);
    if (rc != ASNBER_OK) {
        destroyConstraintArray(ctx, constraints, constraintCount);
        return rc;
    }

    if (schema->typeCount == schema->typeCapacity) {
        rc = growTypes(ctx, schema);
        if (rc != ASNBER_OK) {
            contextRelease(ctx, const_cast<char *>(name));
            destroyConstraintArray(ctx, constraints, constraintCount);
            return rc;
        }
    }

    SchemaType *type = &schema->types[schema->typeCount];
    std::memset(type, 0, sizeof(*type));
    type->name = name;
    type->kind = static_cast<uint32_t>(desc->kind);
    type->tagClass = static_cast<uint32_t>(desc->tag_class);
    type->tagNumber = desc->tag_number;
    type->tagMode = static_cast<uint32_t>(desc->tag_mode);
    type->elementTypeId = elementId;
    type->flags = desc->flags;
    type->constraints = constraints;
    type->constraintCount = constraintCount;

    ++schema->typeCount;
    *outTypeId = schema->typeCount;
    return ASNBER_OK;
}

/* ===== 字段追加 ===== */

asnber_err_t appendField(Context *ctx, Schema *schema, uint32_t parentTypeId,
                       const asnber_field_desc_t *desc) noexcept
{
    SchemaType *parent = findType(schema, parentTypeId);
    if (parent == nullptr) {
        contextSetError(ctx, ASNBER_E_SCHEMA_TYPE, SIZE_MAX, 0);
        return ASNBER_E_SCHEMA_TYPE;
    }
    if (desc->type_id == 0 || desc->type_id > schema->typeCount) {
        contextSetError(ctx, ASNBER_E_SCHEMA_TYPE, SIZE_MAX, 0);
        return ASNBER_E_SCHEMA_TYPE;
    }
    if ((desc->flags & ~(ASNBER_FIELD_OPTIONAL | ASNBER_FIELD_EXTENSION)) != 0) {
        contextSetError(ctx, ASNBER_E_INVALID_CONFIG, SIZE_MAX, 0);
        return ASNBER_E_INVALID_CONFIG;
    }
    if (desc->default_value == nullptr && desc->default_value_size != 0) {
        contextSetError(ctx, ASNBER_E_SCHEMA_DEFAULT, SIZE_MAX, 0);
        return ASNBER_E_SCHEMA_DEFAULT;
    }
    if (desc->default_value_size != 0 &&
        !schemaValidateDefaultTlv(
            static_cast<const uint8_t *>(desc->default_value),
            desc->default_value_size)) {
        contextSetError(ctx, ASNBER_E_SCHEMA_DEFAULT, SIZE_MAX, 0);
        return ASNBER_E_SCHEMA_DEFAULT;
    }
    if (desc->field_constraint_count != 0 &&
        desc->field_constraints == nullptr) {
        contextSetError(ctx, ASNBER_E_INVALID_ARG, SIZE_MAX, 0);
        return ASNBER_E_INVALID_ARG;
    }
    if (parent->kind == static_cast<uint32_t>(ASNBER_TYPE_KIND_CHOICE) &&
        (desc->flags != 0 || desc->default_value_size != 0)) {
        contextSetError(ctx, ASNBER_E_SCHEMA_FIELD, SIZE_MAX, 0);
        return ASNBER_E_SCHEMA_FIELD;
    }
    if (isOfKind(parent->kind)) {
        contextSetError(ctx, ASNBER_E_SCHEMA_FIELD, SIZE_MAX, 0);
        return ASNBER_E_SCHEMA_FIELD;
    }
    if (parent->kind == static_cast<uint32_t>(ASNBER_TYPE_KIND_ANY)) {
        /* ANY 是开放类型，不得挂字段。 */
        contextSetError(ctx, ASNBER_E_SCHEMA_FIELD, SIZE_MAX, 0);
        return ASNBER_E_SCHEMA_FIELD;
    }
    if (fieldNameExists(parent, desc->name)) {
        contextSetError(ctx, ASNBER_E_SCHEMA_FIELD, SIZE_MAX, 0);
        return ASNBER_E_SCHEMA_FIELD;
    }

    SchemaConstraint *constraints = nullptr;
    uint32_t constraintCount = 0;
    asnber_err_t rc = copyConstraints(
        ctx, desc->field_constraints, desc->field_constraint_count,
        &constraints, &constraintCount);
    if (rc != ASNBER_OK) {
        return rc;
    }

    const char *name = nullptr;
    rc = copyText(ctx, desc->name, &name, ASNBER_E_INVALID_ARG);
    if (rc != ASNBER_OK) {
        destroyConstraintArray(ctx, constraints, constraintCount);
        return rc;
    }

    const uint8_t *defaultTlv = nullptr;
    if (desc->default_value_size != 0) {
        rc = copyBytes(ctx, desc->default_value, desc->default_value_size,
                       &defaultTlv, ASNBER_E_SCHEMA_DEFAULT);
        if (rc != ASNBER_OK) {
            contextRelease(ctx, const_cast<char *>(name));
            destroyConstraintArray(ctx, constraints, constraintCount);
            return rc;
        }
    }

    if (parent->fieldCount == parent->fieldCapacity) {
        rc = growFields(ctx, parent);
        if (rc != ASNBER_OK) {
            contextRelease(ctx, const_cast<char *>(name));
            contextRelease(ctx, const_cast<uint8_t *>(defaultTlv));
            destroyConstraintArray(ctx, constraints, constraintCount);
            return rc;
        }
    }

    SchemaField *field = &parent->fields[parent->fieldCount];
    std::memset(field, 0, sizeof(*field));
    field->name = name;
    field->typeId = desc->type_id;
    field->flags = desc->flags;
    field->defaultTlv = defaultTlv;
    field->defaultSize = defaultTlv == nullptr ? 0 : desc->default_value_size;
    field->constraints = constraints;
    field->constraintCount = constraintCount;

    ++parent->fieldCount;
    return ASNBER_OK;
}

} /* namespace schema_detail */
} /* namespace asnber */
