/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 描述表加载：约束记录打包。
 *
 * 职责：把约束表记录转换成运行时的 asnber_constraint_t 描述符，ENUM 值数组
 *       单独分配；失败时释放已分配部分。
 * 依赖：schema/detail/schema_table_internal.h。
 */

#include <cstring>

#include "schema/detail/schema_table_internal.h"

namespace asnber {
namespace schema_table_detail {

void freeConstraintPack(Context *ctx, ConstraintPack *pack) noexcept
{
    if (pack->enums != nullptr) {
        for (uint32_t i = 0; i < pack->count; ++i) {
            contextRelease(ctx, pack->enums[i]);
        }
        contextRelease(ctx, pack->enums);
    }
    contextRelease(ctx, pack->descs);
    pack->descs = nullptr;
    pack->enums = nullptr;
    pack->count = 0;
}

asnber_err_t packConstraints(Context *ctx, const TableView &view,
                           uint32_t start, uint32_t count,
                           ConstraintPack *pack) noexcept
{
    pack->descs = nullptr;
    pack->enums = nullptr;
    pack->count = 0;
    if (count == 0) {
        return ASNBER_OK;
    }

    void *descRaw = nullptr;
    asnber_err_t rc = contextAllocate(
        ctx, static_cast<size_t>(count) * sizeof(asnber_constraint_t),
        AllocationKind::kSchema, &descRaw);
    if (rc != ASNBER_OK) {
        return rc;
    }
    pack->descs = static_cast<asnber_constraint_t *>(descRaw);
    std::memset(pack->descs, 0, static_cast<size_t>(count) *
                                  sizeof(asnber_constraint_t));
    pack->count = count;

    void *enumRaw = nullptr;
    rc = contextAllocate(ctx, static_cast<size_t>(count) * sizeof(int64_t *),
                         AllocationKind::kSchema, &enumRaw);
    if (rc != ASNBER_OK) {
        freeConstraintPack(ctx, pack);
        return rc;
    }
    pack->enums = static_cast<int64_t **>(enumRaw);
    std::memset(pack->enums, 0,
                static_cast<size_t>(count) * sizeof(int64_t *));

    for (uint32_t i = 0; i < count; ++i) {
        const uint64_t rec =
            static_cast<uint64_t>(view.constraintOffset) +
            static_cast<uint64_t>(start + i) * kSchemaConstraintRecordSize;
        asnber_constraint_t *desc = &pack->descs[i];
        desc->struct_size = sizeof(asnber_constraint_t);
        desc->kind =
            static_cast<asnber_constraint_kind_t>(readU16(view.data, rec));
        desc->flags = 0;
        const uint16_t flags = readU16(view.data, rec + 2);
        desc->lower.struct_size = sizeof(asnber_bound_t);
        desc->lower.is_unbounded =
            static_cast<int32_t>(flags & 0x0001u);
        desc->lower.value = readI64(view.data, rec + 28);
        desc->upper.struct_size = sizeof(asnber_bound_t);
        desc->upper.is_unbounded =
            static_cast<int32_t>((flags >> 1) & 0x0001u);
        desc->upper.value = readI64(view.data, rec + 36);

        if (desc->kind == ASNBER_CONSTRAINT_ENUM) {
            const uint32_t enumOff = readU32(view.data, rec + 4);
            const uint32_t enumCount = readU32(view.data, rec + 8);
            void *valuesRaw = nullptr;
            rc = contextAllocate(ctx,
                                 static_cast<size_t>(enumCount) *
                                     sizeof(int64_t),
                                 AllocationKind::kSchema, &valuesRaw);
            if (rc != ASNBER_OK) {
                freeConstraintPack(ctx, pack);
                return rc;
            }
            int64_t *values = static_cast<int64_t *>(valuesRaw);
            for (uint32_t j = 0; j < enumCount; ++j) {
                values[j] = readI64(view.data,
                                    static_cast<uint64_t>(enumOff) +
                                        static_cast<uint64_t>(j) * 8);
            }
            pack->enums[i] = values;
            desc->enum_values = values;
            desc->enum_count = enumCount;
        } else {
            const uint32_t lowerOff = readU32(view.data, rec + 12);
            const uint32_t lowerSize = readU32(view.data, rec + 16);
            const uint32_t upperOff = readU32(view.data, rec + 20);
            const uint32_t upperSize = readU32(view.data, rec + 24);
            if (lowerOff != 0) {
                desc->lower.decimal =
                    reinterpret_cast<const char *>(view.data + lowerOff);
                desc->lower.decimal_size = lowerSize;
            }
            if (upperOff != 0) {
                desc->upper.decimal =
                    reinterpret_cast<const char *>(view.data + upperOff);
                desc->upper.decimal_size = upperSize;
            }
        }
    }
    return ASNBER_OK;
}

} /* namespace schema_table_detail */
} /* namespace asnber */
