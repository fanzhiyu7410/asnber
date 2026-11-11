/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 描述表加载内部共享定义。
 *
 * 只允许 src/schema 同一子系统的 cpp 包含。字节布局偏移、小端读取、
 * 表视图与区域，以及约束打包接口集中在此，避免多处重复定义。
 */

#ifndef ASNBER_SCHEMA_TABLE_INTERNAL_H_INCLUDED
#define ASNBER_SCHEMA_TABLE_INTERNAL_H_INCLUDED

#include <asnber/asnber.h>

#include <cstddef>
#include <cstdint>

#include "schema/asnber_schema.h"

namespace asnber {
namespace schema_table_detail {

constexpr uint32_t kOffFormatVersion = 8;
constexpr uint32_t kOffHeaderSize = 12;
constexpr uint32_t kOffEndianness = 16;
constexpr uint32_t kOffModuleTagMode = 20;
constexpr uint32_t kOffFlags = 24;
constexpr uint32_t kOffChecksumAlg = 28;
constexpr uint32_t kOffTotalSize = 32;
constexpr uint32_t kOffStringPoolOffset = 40;
constexpr uint32_t kOffStringPoolSize = 44;
constexpr uint32_t kOffTypeTableOffset = 48;
constexpr uint32_t kOffTypeCount = 52;
constexpr uint32_t kOffFieldTableOffset = 56;
constexpr uint32_t kOffFieldCount = 60;
constexpr uint32_t kOffConstraintTableOffset = 64;
constexpr uint32_t kOffConstraintCount = 68;
constexpr uint32_t kOffDefaultTableOffset = 72;
constexpr uint32_t kOffDefaultCount = 76;
constexpr uint32_t kOffChecksum = 80;
constexpr uint32_t kOffReserved0 = 84;
constexpr uint32_t kOffReserved1 = 88;
constexpr uint32_t kOffReserved2 = 92;
constexpr uint32_t kOffRootTypeId = 96; /* header_size >= 100 时有效 */
constexpr uint32_t kOffNameTableOffset = 100; /* header_size >= 108 时有效 */
constexpr uint32_t kOffNameCount = 104;       /* header_size >= 108 时有效 */

uint16_t readU16(const uint8_t *data, uint64_t offset) noexcept;
uint32_t readU32(const uint8_t *data, uint64_t offset) noexcept;
uint64_t readU64(const uint8_t *data, uint64_t offset) noexcept;
int64_t readI64(const uint8_t *data, uint64_t offset) noexcept;

struct TableView {
    const uint8_t *data;
    uint64_t total;
    uint32_t headerSize;
    uint32_t rootTypeId;
    uint32_t stringOffset;
    uint32_t stringSize;
    uint32_t typeOffset;
    uint32_t typeCount;
    uint32_t fieldOffset;
    uint32_t fieldCount;
    uint32_t constraintOffset;
    uint32_t constraintCount;
    uint32_t defaultOffset;
    uint32_t defaultCount;
    uint32_t nameOffset;
    uint32_t nameCount;
};

struct Region {
    uint64_t begin;
    uint64_t end;
};

bool regionsOverlap(const Region &a, const Region &b) noexcept;
size_t errorOffset(uint64_t offset) noexcept;
asnber_err_t formatError(Context *ctx, uint64_t offset) noexcept;

/* ===== 记录到描述符的转换 ===== */

struct ConstraintPack {
    asnber_constraint_t *descs;
    uint32_t count;
    int64_t **enums;
};

/* 校验顺序即 docs/11 第 9 节的错误码优先级，调用方不得调整。 */
asnber_err_t validateHeader(Context *ctx, const asnber_schema_table_t *table,
                          TableView *view) noexcept;
asnber_err_t validateRegions(Context *ctx, const TableView &view) noexcept;
asnber_err_t validateTypeRecords(Context *ctx, const TableView &view) noexcept;
asnber_err_t validateFieldRecords(Context *ctx, const TableView &view) noexcept;
asnber_err_t validateConstraintRecords(Context *ctx,
                                     const TableView &view) noexcept;
asnber_err_t validateDefaultRecords(Context *ctx,
                                  const TableView &view) noexcept;
asnber_err_t validateNameRecords(Context *ctx, const TableView &view) noexcept;

void freeConstraintPack(Context *ctx, ConstraintPack *pack) noexcept;
asnber_err_t packConstraints(Context *ctx, const TableView &view,
                           uint32_t start, uint32_t count,
                           ConstraintPack *pack) noexcept;

} /* namespace schema_table_detail */
} /* namespace asnber */

#endif /* ASNBER_SCHEMA_TABLE_INTERNAL_H_INCLUDED */
