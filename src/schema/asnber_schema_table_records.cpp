/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 描述表加载：逐记录校验。
 *
 * 职责：按 docs/11 第 9 节顺序校验类型、字段、约束、默认值与名称记录；
 *       字符串/十进制引用必须落在字符串池内，约束上下界必须自洽。
 * 依赖：schema/detail/schema_table_internal.h。
 */

#include <cstring>

#include "schema/detail/schema_table_internal.h"

namespace asnber {
namespace schema_table_detail {

namespace {

/* 类型名/字段名引用的字符串必须非空且在池内 NUL 结尾。 */
bool stringRefValid(const TableView &view, uint32_t offset) noexcept
{
    if (offset == 0 || view.stringSize == 0) {
        return false;
    }
    const uint64_t begin = view.stringOffset;
    const uint64_t end = begin + view.stringSize;
    if (offset <= begin || offset >= end) {
        return false;
    }
    for (uint64_t pos = offset; pos < end; ++pos) {
        if (view.data[pos] == 0) {
            return true;
        }
    }
    return false;
}

/* 十进制文本引用：长度已知，必须整段位于池内且末尾为 NUL。 */
bool decimalRefValid(const TableView &view, uint32_t offset,
                     uint32_t size) noexcept
{
    if (size == 0) {
        return false;
    }
    const uint64_t begin = view.stringOffset;
    const uint64_t end = begin + view.stringSize;
    const uint64_t textBegin = offset;
    const uint64_t textEnd = textBegin + size;
    if (textBegin <= begin || textEnd >= end) {
        return false;
    }
    if (textEnd > view.total) {
        return false;
    }
    return view.data[textEnd] == 0;
}

bool decimalCharsValid(const uint8_t *data, uint32_t offset,
                       uint32_t size) noexcept
{
    if (size == 0) {
        return false;
    }
    const uint64_t end = static_cast<uint64_t>(offset) + size;
    uint64_t pos = offset;
    bool negative = false;
    if (data[pos] == '-') {
        negative = true;
        ++pos;
        if (pos == end) {
            return false;
        }
    }
    const uint64_t digits = end - pos;
    if (digits > 1 && data[pos] == '0') {
        return false;
    }
    for (; pos < end; ++pos) {
        if (data[pos] < '0' || data[pos] > '9') {
            return false;
        }
    }
    if (negative && digits == 1 && data[end - 1] == '0') {
        return false; /* "-0" 非法 */
    }
    return true;
}

/* 比较两个已校验的规范十进制文本，返回 -1/0/1。 */
int compareDecimalText(const uint8_t *data, uint32_t leftOffset,
                       uint32_t leftSize, uint32_t rightOffset,
                       uint32_t rightSize) noexcept
{
    const bool leftNegative = data[leftOffset] == '-';
    const bool rightNegative = data[rightOffset] == '-';
    const uint64_t leftPos = leftNegative ? 1u : 0u;
    const uint64_t rightPos = rightNegative ? 1u : 0u;
    const uint64_t leftDigits = leftSize - leftPos;
    const uint64_t rightDigits = rightSize - rightPos;

    int magnitude = 0;
    if (leftDigits != rightDigits) {
        magnitude = leftDigits < rightDigits ? -1 : 1;
    } else {
        for (uint64_t i = 0; i < leftDigits; ++i) {
            const uint8_t lc = data[leftOffset + leftPos + i];
            const uint8_t rc = data[rightOffset + rightPos + i];
            if (lc != rc) {
                magnitude = lc < rc ? -1 : 1;
                break;
            }
        }
    }

    if (leftNegative != rightNegative) {
        return leftNegative ? -1 : 1;
    }
    return leftNegative ? -magnitude : magnitude;
}

/* 类型或引用该类型的字段上是否存在有限上界的 SIZE 约束；返回最小上界。 */
bool finiteSizeUpperBound(const TableView &view, uint32_t typeId,
                          int64_t *outUpper) noexcept
{
    const uint64_t typeRec =
        static_cast<uint64_t>(view.typeOffset) +
        static_cast<uint64_t>(typeId - 1) * kSchemaTypeRecordSize;

    bool found = false;
    int64_t best = 0;
    auto consider = [&](uint32_t start, uint32_t count) noexcept {
        for (uint32_t i = 0; i < count; ++i) {
            const uint64_t rec =
                static_cast<uint64_t>(view.constraintOffset) +
                static_cast<uint64_t>(start + i) * kSchemaConstraintRecordSize;
            if (readU16(view.data, rec) != 1) {
                continue; /* 仅 SIZE */
            }
            if ((readU16(view.data, rec + 2) & 0x0002u) != 0) {
                continue; /* 上界无界 */
            }
            const int64_t upper = readI64(view.data, rec + 36);
            if (!found || upper < best) {
                best = upper;
                found = true;
            }
        }
    };

    consider(readU32(view.data, typeRec + 28), readU32(view.data, typeRec + 32));

    for (uint32_t i = 0; i < view.fieldCount; ++i) {
        const uint64_t fieldRec =
            static_cast<uint64_t>(view.fieldOffset) +
            static_cast<uint64_t>(i) * kSchemaFieldRecordSize;
        if (readU32(view.data, fieldRec + 4) != typeId) {
            continue;
        }
        consider(readU32(view.data, fieldRec + 16),
                 readU32(view.data, fieldRec + 20));
    }

    if (found) {
        *outUpper = best;
    }
    return found;
}

} /* namespace */

asnber_err_t validateTypeRecords(Context *ctx, const TableView &view) noexcept
{
    for (uint32_t i = 0; i < view.typeCount; ++i) {
        const uint64_t rec =
            static_cast<uint64_t>(view.typeOffset) +
            static_cast<uint64_t>(i) * kSchemaTypeRecordSize;
        if (!stringRefValid(view, readU32(view.data, rec))) {
            return formatError(ctx, rec);
        }
        if (readU16(view.data, rec + 4) > 6) {
            contextSetError(ctx, ASNBER_E_SCHEMA_TYPE, errorOffset(rec + 4), 0);
            return ASNBER_E_SCHEMA_TYPE;
        }
        if (view.data[rec + 6] > 2) {
            contextSetError(ctx, ASNBER_E_SCHEMA_TYPE, errorOffset(rec + 6), 0);
            return ASNBER_E_SCHEMA_TYPE;
        }
        if ((view.data[rec + 7] & ~0x01u) != 0 ||
            view.data[rec + 9] != 0 || readU16(view.data, rec + 10) != 0 ||
            readU32(view.data, rec + 36) != 0 ||
            readU32(view.data, rec + 40) != 0 ||
            readU32(view.data, rec + 44) != 0) {
            return formatError(ctx, rec + 7);
        }
        if (view.data[rec + 8] > 3) {
            contextSetError(ctx, ASNBER_E_SCHEMA_TYPE, errorOffset(rec + 8), 0);
            return ASNBER_E_SCHEMA_TYPE;
        }

        const uint32_t fieldStart = readU32(view.data, rec + 20);
        const uint32_t fieldCount = readU32(view.data, rec + 24);
        if (fieldStart > view.fieldCount ||
            fieldCount > view.fieldCount - fieldStart ||
            fieldCount > view.fieldCount) {
            contextSetError(ctx, ASNBER_E_SCHEMA_FIELD, errorOffset(rec + 20), 0);
            return ASNBER_E_SCHEMA_FIELD;
        }
        const uint32_t constraintStart = readU32(view.data, rec + 28);
        const uint32_t constraintCount = readU32(view.data, rec + 32);
        if (constraintStart > view.constraintCount ||
            constraintCount > view.constraintCount - constraintStart) {
            contextSetError(ctx, ASNBER_E_SCHEMA_CONSTRAINT, errorOffset(rec + 28), 0);
            return ASNBER_E_SCHEMA_CONSTRAINT;
        }

        const uint32_t kind = readU16(view.data, rec + 4);
        if ((kind == 4 || kind == 5 || kind == 6) && fieldCount != 0) {
            contextSetError(ctx, ASNBER_E_SCHEMA_FIELD, errorOffset(rec + 20), 0);
            return ASNBER_E_SCHEMA_FIELD;
        }
    }

    for (uint32_t i = 0; i < view.typeCount; ++i) {
        const uint64_t recA =
            static_cast<uint64_t>(view.typeOffset) +
            static_cast<uint64_t>(i) * kSchemaTypeRecordSize;
        const uint32_t startA = readU32(view.data, recA + 20);
        const uint32_t countA = readU32(view.data, recA + 24);
        if (countA == 0) {
            continue;
        }
        const Region regionA = {startA, static_cast<uint64_t>(startA) + countA};
        for (uint32_t j = i + 1; j < view.typeCount; ++j) {
            const uint64_t recB =
                static_cast<uint64_t>(view.typeOffset) +
                static_cast<uint64_t>(j) * kSchemaTypeRecordSize;
            const uint32_t startB = readU32(view.data, recB + 20);
            const uint32_t countB = readU32(view.data, recB + 24);
            if (countB == 0) {
                continue;
            }
            const Region regionB = {
                startB, static_cast<uint64_t>(startB) + countB};
            if (regionsOverlap(regionA, regionB)) {
                contextSetError(ctx, ASNBER_E_SCHEMA_FIELD, errorOffset(recB + 20), 0);
                return ASNBER_E_SCHEMA_FIELD;
            }
        }
    }

    if (view.rootTypeId != 0 && view.rootTypeId > view.typeCount) {
        return formatError(ctx, kOffRootTypeId);
    }
    return ASNBER_OK;
}

asnber_err_t validateFieldRecords(Context *ctx, const TableView &view) noexcept
{
    for (uint32_t i = 0; i < view.fieldCount; ++i) {
        const uint64_t rec =
            static_cast<uint64_t>(view.fieldOffset) +
            static_cast<uint64_t>(i) * kSchemaFieldRecordSize;
        if (!stringRefValid(view, readU32(view.data, rec))) {
            return formatError(ctx, rec);
        }
        const uint32_t typeId = readU32(view.data, rec + 4);
        if (typeId == 0 || typeId > view.typeCount) {
            contextSetError(ctx, ASNBER_E_SCHEMA_TYPE, errorOffset(rec + 4), 0);
            return ASNBER_E_SCHEMA_TYPE;
        }
        if ((readU16(view.data, rec + 8) & ~0x0003u) != 0 ||
            readU16(view.data, rec + 10) != 0 ||
            readU32(view.data, rec + 24) != 0 ||
            readU32(view.data, rec + 28) != 0) {
            return formatError(ctx, rec + 8);
        }
        const uint32_t defaultIndex = readU32(view.data, rec + 12);
        if (defaultIndex > view.defaultCount) {
            contextSetError(ctx, ASNBER_E_SCHEMA_DEFAULT, errorOffset(rec + 12), 0);
            return ASNBER_E_SCHEMA_DEFAULT;
        }
        const uint32_t constraintStart = readU32(view.data, rec + 16);
        const uint32_t constraintCount = readU32(view.data, rec + 20);
        if (constraintStart > view.constraintCount ||
            constraintCount > view.constraintCount - constraintStart) {
            contextSetError(ctx, ASNBER_E_SCHEMA_CONSTRAINT, errorOffset(rec + 16), 0);
            return ASNBER_E_SCHEMA_CONSTRAINT;
        }
    }
    return ASNBER_OK;
}

asnber_err_t validateConstraintRecords(Context *ctx,
                                     const TableView &view) noexcept
{
    for (uint32_t i = 0; i < view.constraintCount; ++i) {
        const uint64_t rec =
            static_cast<uint64_t>(view.constraintOffset) +
            static_cast<uint64_t>(i) * kSchemaConstraintRecordSize;
        const uint32_t kind = readU16(view.data, rec);
        if (kind > 4) {
            return formatError(ctx, rec);
        }
        const uint16_t flags = readU16(view.data, rec + 2);
        if ((flags & ~0x0003u) != 0 || readU32(view.data, rec + 44) != 0) {
            return formatError(ctx, rec + 2);
        }
        const bool lowerUnbounded = (flags & 0x0001u) != 0;
        const bool upperUnbounded = (flags & 0x0002u) != 0;

        const uint32_t enumOff = readU32(view.data, rec + 4);
        const uint32_t enumCount = readU32(view.data, rec + 8);
        if (kind == 2) {
            if (enumCount == 0) {
                return formatError(ctx, rec + 8);
            }
            if ((enumOff & 7u) != 0 || enumOff > view.total ||
                static_cast<uint64_t>(enumCount) * sizeof(int64_t) >
                    view.total - enumOff) {
                contextSetError(ctx, ASNBER_E_SCHEMA_CONSTRAINT, errorOffset(rec + 4), 0);
                return ASNBER_E_SCHEMA_CONSTRAINT;
            }
            for (uint32_t a = 0; a < enumCount; ++a) {
                const int64_t valueA = readI64(
                    view.data, static_cast<uint64_t>(enumOff) +
                                   static_cast<uint64_t>(a) * 8);
                for (uint32_t b = a + 1; b < enumCount; ++b) {
                    const int64_t valueB = readI64(
                        view.data, static_cast<uint64_t>(enumOff) +
                                       static_cast<uint64_t>(b) * 8);
                    if (valueA == valueB) {
                        return formatError(ctx, rec + 4);
                    }
                }
            }
        } else if (enumOff != 0 || enumCount != 0) {
            return formatError(ctx, rec + 4);
        }

        const uint32_t lowerOff = readU32(view.data, rec + 12);
        const uint32_t lowerSize = readU32(view.data, rec + 16);
        const uint32_t upperOff = readU32(view.data, rec + 20);
        const uint32_t upperSize = readU32(view.data, rec + 24);
        if ((lowerOff != 0 || lowerSize != 0) &&
            !decimalRefValid(view, lowerOff, lowerSize)) {
            return formatError(ctx, rec + 12);
        }
        if ((upperOff != 0 || upperSize != 0) &&
            !decimalRefValid(view, upperOff, upperSize)) {
            return formatError(ctx, rec + 20);
        }
        if (lowerOff != 0 &&
            !decimalCharsValid(view.data, lowerOff, lowerSize)) {
            return formatError(ctx, rec + 12);
        }
        if (upperOff != 0 &&
            !decimalCharsValid(view.data, upperOff, upperSize)) {
            return formatError(ctx, rec + 20);
        }

        const int64_t lowerValue = readI64(view.data, rec + 28);
        const int64_t upperValue = readI64(view.data, rec + 36);

        switch (kind) {
        case 0: /* RANGE */
            if (!lowerUnbounded && !upperUnbounded) {
                if (lowerOff != 0 && upperOff != 0) {
                    if (compareDecimalText(view.data, lowerOff, lowerSize,
                                           upperOff, upperSize) > 0) {
                        return formatError(ctx, rec + 12);
                    }
                } else if (lowerValue > upperValue) {
                    return formatError(ctx, rec + 28);
                }
            }
            break;
        case 1: /* SIZE */
            if (lowerUnbounded || lowerValue < 0) {
                return formatError(ctx, rec + 28);
            }
            if (!upperUnbounded && upperValue < lowerValue) {
                return formatError(ctx, rec + 36);
            }
            break;
        case 3: /* MAX：上界无界，下界固定为 0 且不得给出 lower */
            if (!upperUnbounded || lowerUnbounded || lowerValue != 0 ||
                lowerOff != 0 || upperOff != 0) {
                return formatError(ctx, rec + 2);
            }
            break;
        case 4: /* BIGINT_RANGE */
            if (lowerOff == 0 && upperOff == 0) {
                return formatError(ctx, rec + 12);
            }
            if (lowerOff != 0 && upperOff != 0 &&
                compareDecimalText(view.data, lowerOff, lowerSize, upperOff,
                                   upperSize) > 0) {
                return formatError(ctx, rec + 12);
            }
            break;
        default:
            break;
        }
    }
    return ASNBER_OK;
}

asnber_err_t validateDefaultRecords(Context *ctx, const TableView &view) noexcept
{
    Region occupied[8] = {};
    uint32_t occupiedCount = 0;
    occupied[occupiedCount++] = {0, view.headerSize};
    occupied[occupiedCount++] = {
        view.stringOffset,
        static_cast<uint64_t>(view.stringOffset) + view.stringSize};

    if (view.typeCount != 0) {
        occupied[occupiedCount++] = {
            view.typeOffset, static_cast<uint64_t>(view.typeOffset) +
                                 static_cast<uint64_t>(view.typeCount) *
                                     kSchemaTypeRecordSize};
    }
    if (view.fieldCount != 0) {
        occupied[occupiedCount++] = {
            view.fieldOffset, static_cast<uint64_t>(view.fieldOffset) +
                                  static_cast<uint64_t>(view.fieldCount) *
                                      kSchemaFieldRecordSize};
    }
    if (view.constraintCount != 0) {
        occupied[occupiedCount++] = {
            view.constraintOffset,
            static_cast<uint64_t>(view.constraintOffset) +
                static_cast<uint64_t>(view.constraintCount) *
                    kSchemaConstraintRecordSize};
    }
    if (view.defaultCount != 0) {
        occupied[occupiedCount++] = {
            view.defaultOffset,
            static_cast<uint64_t>(view.defaultOffset) +
                static_cast<uint64_t>(view.defaultCount) *
                    kSchemaDefaultRecordSize};
    }
    if (view.nameCount != 0) {
        occupied[occupiedCount++] = {
            view.nameOffset, static_cast<uint64_t>(view.nameOffset) +
                                 static_cast<uint64_t>(view.nameCount) *
                                     kSchemaNameRecordSize};
    }

    for (uint32_t i = 0; i < view.defaultCount; ++i) {
        const uint64_t rec =
            static_cast<uint64_t>(view.defaultOffset) +
            static_cast<uint64_t>(i) * kSchemaDefaultRecordSize;
        const uint32_t dataOffset = readU32(view.data, rec);
        const uint32_t dataSize = readU32(view.data, rec + 4);
        if (dataSize == 0 || dataOffset < view.headerSize ||
            dataOffset > view.total ||
            dataSize > view.total - dataOffset) {
            contextSetError(ctx, ASNBER_E_SCHEMA_DEFAULT, errorOffset(rec), 0);
            return ASNBER_E_SCHEMA_DEFAULT;
        }
        const Region region = {
            dataOffset, static_cast<uint64_t>(dataOffset) + dataSize};
        for (uint32_t j = 0; j < occupiedCount; ++j) {
            if (regionsOverlap(region, occupied[j])) {
                contextSetError(ctx, ASNBER_E_SCHEMA_DEFAULT, errorOffset(rec), 0);
                return ASNBER_E_SCHEMA_DEFAULT;
            }
        }
        if (!schemaValidateDefaultTlv(view.data + dataOffset, dataSize)) {
            contextSetError(ctx, ASNBER_E_SCHEMA_DEFAULT, errorOffset(rec), 0);
            return ASNBER_E_SCHEMA_DEFAULT;
        }
    }
    return ASNBER_OK;
}

asnber_err_t validateNameRecords(Context *ctx, const TableView &view) noexcept
{
    const uint32_t simpleKind = static_cast<uint32_t>(ASNBER_TYPE_KIND_SIMPLE);
    const uint32_t universal = static_cast<uint32_t>(ASNBER_TAG_UNIVERSAL);

    for (uint32_t i = 0; i < view.nameCount; ++i) {
        const uint64_t rec =
            static_cast<uint64_t>(view.nameOffset) +
            static_cast<uint64_t>(i) * kSchemaNameRecordSize;
        const uint32_t typeId = readU32(view.data, rec);
        if (typeId == 0 || typeId > view.typeCount) {
            return formatError(ctx, rec);
        }
        const uint32_t nameOff = readU32(view.data, rec + 4);
        if (!stringRefValid(view, nameOff)) {
            return formatError(ctx, rec + 4);
        }
        const uint32_t kind = readU16(view.data, rec + 8);
        if (kind > 1) {
            return formatError(ctx, rec + 8);
        }
        const uint16_t flags = readU16(view.data, rec + 10);
        if ((flags & ~0x0001u) != 0) {
            return formatError(ctx, rec + 10);
        }
        if (readU32(view.data, rec + 12) != 0) {
            return formatError(ctx, rec + 12);
        }
        const int64_t value = readI64(view.data, rec + 16);

        const uint64_t typeRec =
            static_cast<uint64_t>(view.typeOffset) +
            static_cast<uint64_t>(typeId - 1) * kSchemaTypeRecordSize;
        const uint32_t typeKind = readU16(view.data, typeRec + 4);
        const uint32_t tagClass = view.data[typeRec + 8];
        const uint32_t tagNumber = readU32(view.data, typeRec + 12);
        const uint32_t typeFlags = view.data[typeRec + 7];

        if (kind == 0) { /* BIT_NAME */
            if (flags != 0) {
                return formatError(ctx, rec + 10);
            }
            if (typeKind != simpleKind || tagClass != universal ||
                tagNumber != 3) {
                return formatError(ctx, rec);
            }
            if (value < 0 || value > 65535) {
                return formatError(ctx, rec + 16);
            }
            int64_t upper = 0;
            if (finiteSizeUpperBound(view, typeId, &upper) && value >= upper) {
                return formatError(ctx, rec + 16);
            }
        } else { /* NUMBER_NAME */
            if (typeKind != simpleKind || tagClass != universal ||
                (tagNumber != 10 && tagNumber != 2)) {
                return formatError(ctx, rec);
            }
            if ((flags & 0x0001u) != 0 &&
                (typeFlags & ASNBER_TYPE_EXTENSIBLE) == 0) {
                return formatError(ctx, rec + 10);
            }
        }

        for (uint32_t j = 0; j < i; ++j) {
            const uint64_t prev =
                static_cast<uint64_t>(view.nameOffset) +
                static_cast<uint64_t>(j) * kSchemaNameRecordSize;
            if (readU32(view.data, prev) != typeId) {
                continue;
            }
            const uint32_t prevOff = readU32(view.data, prev + 4);
            const uint32_t prevKind = readU16(view.data, prev + 8);
            if (std::strcmp(
                    reinterpret_cast<const char *>(view.data + nameOff),
                    reinterpret_cast<const char *>(view.data + prevOff)) == 0) {
                return formatError(ctx, rec + 4);
            }
            if (prevKind != kind) {
                return formatError(ctx, rec + 8);
            }
            if (readI64(view.data, prev + 16) == value) {
                return formatError(ctx, rec + 16);
            }
        }
    }
    return ASNBER_OK;
}

} /* namespace schema_table_detail */
} /* namespace asnber */
