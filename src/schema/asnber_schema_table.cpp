/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 已编译描述表加载入口与构树。
 *
 * 职责：把 docs/11-描述表格式.md 的字节布局映射到与运行时注册完全相同的
 *       内部类型树，并按第 9 节顺序返回错误码。
 * 依赖：schema/detail/schema_table_internal.h。
 * 所有权：加载产生的名称、约束、默认值全部为上下文级分配；失败时销毁
 *         已创建的 schema，不返回部分类型树。
 */

#include "schema/detail/schema_table_internal.h"

namespace asnber {

using namespace schema_table_detail;

namespace {

/* docs/11 第 2 节：0=AUTOMATIC、2=IMPLICIT 均归一为 IMPLICIT；
 * 1=EXPLICIT；3=未声明归一为 DEFAULT。 */
uint32_t normalizedModuleTagMode(uint32_t headerMode) noexcept
{
    switch (headerMode) {
    case 0:
    case 2:
        return static_cast<uint32_t>(ASNBER_TAG_MODE_IMPLICIT);
    case 1:
        return static_cast<uint32_t>(ASNBER_TAG_MODE_EXPLICIT);
    default:
        return static_cast<uint32_t>(ASNBER_TAG_MODE_DEFAULT);
    }
}

asnber_err_t buildTree(Context *ctx, const TableView &view,
                     uint32_t rootTypeId, Schema **outSchema) noexcept
{
    const uint32_t headerMode = readU32(view.data, kOffModuleTagMode);
    Schema *schema = nullptr;
    asnber_err_t rc =
        schemaCreate(ctx, normalizedModuleTagMode(headerMode), &schema);
    if (rc != ASNBER_OK) {
        return rc;
    }

    for (uint32_t i = 0; i < view.typeCount; ++i) {
        const uint64_t rec =
            static_cast<uint64_t>(view.typeOffset) +
            static_cast<uint64_t>(i) * kSchemaTypeRecordSize;
        const uint32_t constraintStart = readU32(view.data, rec + 28);
        const uint32_t constraintCount = readU32(view.data, rec + 32);

        ConstraintPack pack = {};
        rc = packConstraints(ctx, view, constraintStart, constraintCount,
                             &pack);
        if (rc != ASNBER_OK) {
            schemaDestroy(schema);
            return rc;
        }

        asnber_type_desc_t desc = {};
        desc.struct_size = sizeof(asnber_type_desc_t);
        desc.name = reinterpret_cast<const char *>(
            view.data + readU32(view.data, rec));
        desc.kind = static_cast<asnber_type_kind_t>(
            readU16(view.data, rec + 4));
        desc.tag_class = static_cast<asnber_tag_class_t>(view.data[rec + 8]);
        desc.tag_number = readU32(view.data, rec + 12);
        desc.tag_mode =
            static_cast<asnber_tag_mode_t>(view.data[rec + 6]);
        desc.element_type_id = readU32(view.data, rec + 16);
        desc.flags = view.data[rec + 7];
        desc.constraints = pack.descs;
        desc.constraint_count = pack.count;

        uint32_t typeId = 0;
        rc = schemaAddType(ctx, schema, &desc, &typeId, true);
        freeConstraintPack(ctx, &pack);
        if (rc != ASNBER_OK) {
            schemaDestroy(schema);
            return rc;
        }
    }

    for (uint32_t i = 0; i < view.typeCount; ++i) {
        const uint64_t rec =
            static_cast<uint64_t>(view.typeOffset) +
            static_cast<uint64_t>(i) * kSchemaTypeRecordSize;
        const uint32_t fieldStart = readU32(view.data, rec + 20);
        const uint32_t fieldCount = readU32(view.data, rec + 24);
        const uint32_t typeId = i + 1;

        for (uint32_t j = 0; j < fieldCount; ++j) {
            const uint64_t fieldRec =
                static_cast<uint64_t>(view.fieldOffset) +
                static_cast<uint64_t>(fieldStart + j) *
                    kSchemaFieldRecordSize;
            const uint32_t constraintStart =
                readU32(view.data, fieldRec + 16);
            const uint32_t constraintCount =
                readU32(view.data, fieldRec + 20);

            ConstraintPack pack = {};
            rc = packConstraints(ctx, view, constraintStart,
                                 constraintCount, &pack);
            if (rc != ASNBER_OK) {
                schemaDestroy(schema);
                return rc;
            }

            asnber_field_desc_t desc = {};
            desc.struct_size = sizeof(asnber_field_desc_t);
            desc.name = reinterpret_cast<const char *>(
                view.data + readU32(view.data, fieldRec));
            desc.type_id = readU32(view.data, fieldRec + 4);
            desc.flags = readU16(view.data, fieldRec + 8);
            const uint32_t defaultIndex =
                readU32(view.data, fieldRec + 12);
            if (defaultIndex != 0) {
                const uint64_t defaultRec =
                    static_cast<uint64_t>(view.defaultOffset) +
                    static_cast<uint64_t>(defaultIndex - 1) *
                        kSchemaDefaultRecordSize;
                const uint32_t dataOffset =
                    readU32(view.data, defaultRec);
                const uint32_t dataSize =
                    readU32(view.data, defaultRec + 4);
                desc.default_value = view.data + dataOffset;
                desc.default_value_size = dataSize;
            }
            desc.field_constraints = pack.descs;
            desc.field_constraint_count = pack.count;

            rc = schemaAddField(ctx, schema, typeId, &desc);
            freeConstraintPack(ctx, &pack);
            if (rc != ASNBER_OK) {
                schemaDestroy(schema);
                return rc;
            }
        }
    }

    for (uint32_t i = 0; i < view.nameCount; ++i) {
        const uint64_t rec =
            static_cast<uint64_t>(view.nameOffset) +
            static_cast<uint64_t>(i) * kSchemaNameRecordSize;
        const char *name = reinterpret_cast<const char *>(
            view.data + readU32(view.data, rec + 4));
        rc = schemaAddName(ctx, schema, readU32(view.data, rec), name,
                           readU16(view.data, rec + 8),
                           readU16(view.data, rec + 10),
                           readI64(view.data, rec + 16));
        if (rc != ASNBER_OK) {
            schemaDestroy(schema);
            return rc;
        }
    }

    schema->rootTypeId = rootTypeId;
    rc = schemaSeal(ctx, schema);
    if (rc != ASNBER_OK) {
        schemaDestroy(schema);
        return rc;
    }
    *outSchema = schema;
    return ASNBER_OK;
}

} /* namespace */

asnber_err_t schemaLoadWithRoot(Context *ctx, const asnber_schema_table_t *table,
                              uint32_t rootTypeId, Schema **outSchema) noexcept
{
    *outSchema = nullptr;
    if (table == nullptr || table->data == nullptr || table->size == 0) {
        contextSetError(ctx, ASNBER_E_INVALID_ARG, SIZE_MAX, 0);
        return ASNBER_E_INVALID_ARG;
    }
    if (table->struct_size != sizeof(asnber_schema_table_t) ||
        table->reserved != 0) {
        contextSetError(ctx, ASNBER_E_INVALID_CONFIG, SIZE_MAX, 0);
        return ASNBER_E_INVALID_CONFIG;
    }
    if (static_cast<uint64_t>(table->size) > ctx->m_maxInputBytes) {
        contextSetError(ctx, ASNBER_E_INPUT_LIMIT, SIZE_MAX, 0);
        return ASNBER_E_INPUT_LIMIT;
    }
    if (table->size < kSchemaHeaderSize) {
        contextSetError(ctx, ASNBER_E_SCHEMA_FORMAT, 0, 0);
        return ASNBER_E_SCHEMA_FORMAT;
    }

    TableView view = {};
    asnber_err_t rc = validateHeader(ctx, table, &view);
    if (rc != ASNBER_OK) {
        return rc;
    }
    /* 调用方指定的根越界属于参数错误；表头自身的根仍按格式校验。 */
    if (rootTypeId != 0 && rootTypeId > view.typeCount) {
        contextSetError(ctx, ASNBER_E_INVALID_ARG, SIZE_MAX, 0);
        return ASNBER_E_INVALID_ARG;
    }
    rc = validateRegions(ctx, view);
    if (rc != ASNBER_OK) {
        return rc;
    }
    rc = validateTypeRecords(ctx, view);
    if (rc != ASNBER_OK) {
        return rc;
    }
    rc = validateFieldRecords(ctx, view);
    if (rc != ASNBER_OK) {
        return rc;
    }
    rc = validateConstraintRecords(ctx, view);
    if (rc != ASNBER_OK) {
        return rc;
    }
    rc = validateDefaultRecords(ctx, view);
    if (rc != ASNBER_OK) {
        return rc;
    }
    rc = validateNameRecords(ctx, view);
    if (rc != ASNBER_OK) {
        return rc;
    }
    /* 0 表示沿用描述表头部记录的根，与 schemaLoad 完全等价。 */
    return buildTree(ctx, view, rootTypeId != 0 ? rootTypeId : view.rootTypeId,
                     outSchema);
}

asnber_err_t schemaLoad(Context *ctx, const asnber_schema_table_t *table,
                      Schema **outSchema) noexcept
{
    return schemaLoadWithRoot(ctx, table, 0, outSchema);
}

} /* namespace asnber */
