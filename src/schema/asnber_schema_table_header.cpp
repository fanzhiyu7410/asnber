/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 描述表加载：文件头与区域校验。
 *
 * 职责：校验魔数、格式版本、头尺寸、字节序、校验和与保留字段，再校验
 *       字符串池及五张表区域的边界互不重叠。
 * 依赖：schema/detail/schema_table_internal.h。
 */

#include "schema/detail/schema_table_internal.h"

namespace asnber {
namespace schema_table_detail {

namespace {

constexpr uint8_t kTableMagic[8] = {0x41, 0x53, 0x4E, 0x31,
                                    0x53, 0x43, 0x48, 0x1A};

bool rangeValid(uint32_t offset, uint32_t count, uint32_t recordSize,
                uint64_t total, Region *out) noexcept
{
    const uint64_t begin = offset;
    const uint64_t bytes = static_cast<uint64_t>(count) * recordSize;
    if (begin > total || bytes > total - begin) {
        return false;
    }
    out->begin = begin;
    out->end = begin + bytes;
    return true;
}

} /* namespace */

uint16_t readU16(const uint8_t *data, uint64_t offset) noexcept
{
    return static_cast<uint16_t>(
        static_cast<uint32_t>(data[offset]) |
        (static_cast<uint32_t>(data[offset + 1]) << 8));
}

uint32_t readU32(const uint8_t *data, uint64_t offset) noexcept
{
    return static_cast<uint32_t>(data[offset]) |
           (static_cast<uint32_t>(data[offset + 1]) << 8) |
           (static_cast<uint32_t>(data[offset + 2]) << 16) |
           (static_cast<uint32_t>(data[offset + 3]) << 24);
}

uint64_t readU64(const uint8_t *data, uint64_t offset) noexcept
{
    const uint64_t low = readU32(data, offset);
    const uint64_t high = readU32(data, offset + 4);
    return low | (high << 32);
}

int64_t readI64(const uint8_t *data, uint64_t offset) noexcept
{
    const uint64_t raw = readU64(data, offset);
    if (raw <= static_cast<uint64_t>(INT64_MAX)) {
        return static_cast<int64_t>(raw);
    }
    const uint64_t magnitude = UINT64_MAX - raw;
    return -static_cast<int64_t>(magnitude) - 1;
}

bool regionsOverlap(const Region &a, const Region &b) noexcept
{
    return a.begin < b.end && b.begin < a.end;
}

/* 32 位目标上 size_t 窄于 uint64_t：错误详情偏移饱和到 size_t 上限。 */
size_t errorOffset(uint64_t offset) noexcept
{
    return offset > static_cast<uint64_t>(SIZE_MAX) ? SIZE_MAX
                                                    : static_cast<size_t>(offset);
}

asnber_err_t formatError(Context *ctx, uint64_t offset) noexcept
{
    contextSetError(ctx, ASNBER_E_SCHEMA_FORMAT, errorOffset(offset), 0);
    return ASNBER_E_SCHEMA_FORMAT;
}

asnber_err_t validateHeader(Context *ctx, const asnber_schema_table_t *table,
                          TableView *view) noexcept
{
    const uint8_t *data = static_cast<const uint8_t *>(table->data);
    const uint64_t total = table->size;

    if (total < kSchemaHeaderSize) {
        return formatError(ctx, kOffHeaderSize);
    }
    for (uint32_t i = 0; i < 8; ++i) {
        if (data[i] != kTableMagic[i]) {
            return formatError(ctx, i);
        }
    }

    const uint32_t formatVersion = readU32(data, kOffFormatVersion);
    const uint32_t major = formatVersion >> 16;
    const uint32_t minor = formatVersion & 0xFFFFu;
    const uint32_t requestedMajor = table->format_version >> 16;
    const uint32_t requestedMinor = table->format_version & 0xFFFFu;
    if (table->format_version != formatVersion ||
        requestedMajor != kSchemaFormatMajor ||
        requestedMinor > kSchemaFormatMinor || major != kSchemaFormatMajor ||
        minor > kSchemaFormatMinor) {
        return formatError(ctx, kOffFormatVersion);
    }

    const uint32_t headerSize = readU32(data, kOffHeaderSize);
    if (headerSize < kSchemaHeaderSize || headerSize > total) {
        return formatError(ctx, kOffHeaderSize);
    }
    if (readU32(data, kOffEndianness) != UINT32_C(0x01020304)) {
        return formatError(ctx, kOffEndianness);
    }
    if (readU32(data, kOffModuleTagMode) > 3) {
        return formatError(ctx, kOffModuleTagMode);
    }
    if (readU32(data, kOffFlags) != 1) {
        return formatError(ctx, kOffFlags);
    }
    if (readU32(data, kOffChecksumAlg) != 1) {
        return formatError(ctx, kOffChecksumAlg);
    }
    if (readU64(data, kOffTotalSize) != total) {
        return formatError(ctx, kOffTotalSize);
    }
    if (readU32(data, kOffReserved0) != 0 ||
        readU32(data, kOffReserved1) != 0 ||
        readU32(data, kOffReserved2) != 0) {
        return formatError(ctx, kOffReserved0);
    }

    /* header_size 低于旧基线 100 时 root_type_id 视作 0（兼容旧基线）。 */
    const uint32_t rootTypeId =
        headerSize >= kSchemaHeaderLegacyBaseSize
            ? readU32(data, kOffRootTypeId)
            : 0;
    /* header_size 低于当前基线 108 时无名称表（offset/count 均为 0）。 */
    const uint32_t nameOffset = headerSize >= kSchemaHeaderBaseSize
                                    ? readU32(data, kOffNameTableOffset)
                                    : 0;
    const uint32_t nameCount = headerSize >= kSchemaHeaderBaseSize
                                   ? readU32(data, kOffNameCount)
                                   : 0;

    const uint32_t stored = readU32(data, kOffChecksum);
    const uint32_t computed =
        schemaCrc32c(data, table->size, kOffChecksum, 4);
    if (stored != computed) {
        return formatError(ctx, kOffChecksum);
    }

    view->data = data;
    view->total = total;
    view->headerSize = headerSize;
    view->rootTypeId = rootTypeId;
    view->stringOffset = readU32(data, kOffStringPoolOffset);
    view->stringSize = readU32(data, kOffStringPoolSize);
    view->typeOffset = readU32(data, kOffTypeTableOffset);
    view->typeCount = readU32(data, kOffTypeCount);
    view->fieldOffset = readU32(data, kOffFieldTableOffset);
    view->fieldCount = readU32(data, kOffFieldCount);
    view->constraintOffset = readU32(data, kOffConstraintTableOffset);
    view->constraintCount = readU32(data, kOffConstraintCount);
    view->defaultOffset = readU32(data, kOffDefaultTableOffset);
    view->defaultCount = readU32(data, kOffDefaultCount);
    view->nameOffset = nameOffset;
    view->nameCount = nameCount;
    return ASNBER_OK;
}

asnber_err_t validateRegions(Context *ctx, const TableView &view) noexcept
{
    Region regions[6] = {};
    uint32_t regionCount = 0;

    if (view.stringSize == 0) {
        return formatError(ctx, kOffStringPoolSize);
    }
    if (view.stringOffset < view.headerSize ||
        view.stringOffset > view.total ||
        view.stringSize > view.total - view.stringOffset) {
        return formatError(ctx, kOffStringPoolOffset);
    }
    if (view.data[view.stringOffset] != 0) {
        return formatError(ctx, view.stringOffset);
    }
    regions[regionCount].begin = view.stringOffset;
    regions[regionCount].end =
        static_cast<uint64_t>(view.stringOffset) + view.stringSize;
    ++regionCount;

    Region typeRegion = {};
    Region fieldRegion = {};
    Region constraintRegion = {};
    Region defaultRegion = {};

    if (view.typeCount != 0) {
        if (!rangeValid(view.typeOffset, view.typeCount,
                        kSchemaTypeRecordSize, view.total, &typeRegion) ||
            typeRegion.begin < view.headerSize) {
            return formatError(ctx, kOffTypeTableOffset);
        }
        regions[regionCount++] = typeRegion;
    }
    if (view.fieldCount != 0) {
        if (!rangeValid(view.fieldOffset, view.fieldCount,
                        kSchemaFieldRecordSize, view.total, &fieldRegion) ||
            fieldRegion.begin < view.headerSize) {
            return formatError(ctx, kOffFieldTableOffset);
        }
        regions[regionCount++] = fieldRegion;
    }
    if (view.constraintCount != 0) {
        if (!rangeValid(view.constraintOffset, view.constraintCount,
                        kSchemaConstraintRecordSize, view.total,
                        &constraintRegion) ||
            constraintRegion.begin < view.headerSize) {
            return formatError(ctx, kOffConstraintTableOffset);
        }
        regions[regionCount++] = constraintRegion;
    }
    if (view.defaultCount != 0) {
        if (!rangeValid(view.defaultOffset, view.defaultCount,
                        kSchemaDefaultRecordSize, view.total,
                        &defaultRegion) ||
            defaultRegion.begin < view.headerSize) {
            return formatError(ctx, kOffDefaultTableOffset);
        }
        regions[regionCount++] = defaultRegion;
    }

    Region nameRegion = {};
    if (view.nameCount != 0) {
        if (!rangeValid(view.nameOffset, view.nameCount,
                        kSchemaNameRecordSize, view.total, &nameRegion) ||
            nameRegion.begin < view.headerSize) {
            return formatError(ctx, kOffNameTableOffset);
        }
        regions[regionCount++] = nameRegion;
    }

    for (uint32_t i = 0; i < regionCount; ++i) {
        for (uint32_t j = i + 1; j < regionCount; ++j) {
            if (regionsOverlap(regions[i], regions[j])) {
                return formatError(ctx, regions[j].begin);
            }
        }
    }
    return ASNBER_OK;
}

} /* namespace schema_table_detail */
} /* namespace asnber */
