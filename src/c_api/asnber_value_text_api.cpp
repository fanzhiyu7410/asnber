/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 语义读取：UTF-8 文本、大整数十进制与结构时间。
 *
 * 职责：按 docs/02 6.6 与 docs/03 的字符集/时间规则解析。
 * 依赖：types/asnber_dom.h、types/asnber_value.h。
 */

// ============================================================================
// 依赖与前置声明
// ============================================================================

#include <asnber/asnber.h>

#include "types/asnber_dom.h"
#include "types/asnber_value.h"

#include <cstring>

namespace {

asnber::Node *nodeOf(const asnber_node_t *handle) noexcept
{
    return const_cast<asnber::Node *>(
        static_cast<const asnber::Node *>(static_cast<const void *>(handle)));
}

/* ----------------------------------------------------------------------------
 * UTF-8 编解码
 * -------------------------------------------------------------------------- */

bool decodeUtf8(const uint8_t *bytes, size_t size, size_t *pos,
                uint32_t *outCodePoint) noexcept
{
    size_t cursor = *pos;
    if (cursor >= size) {
        return false;
    }
    const uint8_t first = bytes[cursor];
    if (first < 0x80u) {
        *outCodePoint = first;
        *pos = cursor + 1;
        return true;
    }

    size_t remaining = 0;
    uint32_t codePoint = 0;
    uint32_t minimum = 0;
    if (first >= 0xC2u && first <= 0xDFu) {
        remaining = 1;
        codePoint = first & 0x1Fu;
        minimum = 0x80u;
    } else if (first >= 0xE0u && first <= 0xEFu) {
        remaining = 2;
        codePoint = first & 0x0Fu;
        minimum = 0x800u;
    } else if (first >= 0xF0u && first <= 0xF4u) {
        remaining = 3;
        codePoint = first & 0x07u;
        minimum = 0x10000u;
    } else {
        return false;
    }

    if (remaining > size - cursor - 1) {
        return false;
    }
    for (size_t i = 0; i < remaining; ++i) {
        const uint8_t next = bytes[cursor + 1 + i];
        if ((next & 0xC0u) != 0x80u) {
            return false;
        }
        codePoint = (codePoint << 6) | (next & 0x3Fu);
    }

    if (codePoint < minimum || codePoint > 0x10FFFFu ||
        (codePoint >= 0xD800u && codePoint <= 0xDFFFu)) {
        return false;
    }
    *outCodePoint = codePoint;
    *pos = cursor + 1 + remaining;
    return true;
}

size_t encodeUtf8(uint32_t codePoint, char *out) noexcept
{
    if (codePoint < 0x80u) {
        out[0] = static_cast<char>(codePoint);
        return 1;
    }
    if (codePoint < 0x800u) {
        out[0] = static_cast<char>(0xC0u | (codePoint >> 6));
        out[1] = static_cast<char>(0x80u | (codePoint & 0x3Fu));
        return 2;
    }
    if (codePoint < 0x10000u) {
        out[0] = static_cast<char>(0xE0u | (codePoint >> 12));
        out[1] = static_cast<char>(0x80u | ((codePoint >> 6) & 0x3Fu));
        out[2] = static_cast<char>(0x80u | (codePoint & 0x3Fu));
        return 3;
    }
    out[0] = static_cast<char>(0xF0u | (codePoint >> 18));
    out[1] = static_cast<char>(0x80u | ((codePoint >> 12) & 0x3Fu));
    out[2] = static_cast<char>(0x80u | ((codePoint >> 6) & 0x3Fu));
    out[3] = static_cast<char>(0x80u | (codePoint & 0x3Fu));
    return 4;
}

/* ----------------------------------------------------------------------------
 * 大整数十进制
 * -------------------------------------------------------------------------- */

asnber_err_t bigintDecimal(const asnber::Node *node, const char **out_text,
                         size_t *out_size) noexcept
{
    const uint32_t tag = asnber::universalTagNumber(node);
    if (tag != 2u) {
        return ASNBER_E_INVALID_VALUE;
    }
    if (asnber::nodeIsConstructed(node) || node->contentSize == 0 ||
        node->content == nullptr) {
        return ASNBER_E_MALFORMED_VALUE;
    }

    const size_t size = node->contentSize;
    if (size > (SIZE_MAX - 8) / 3) {
        return ASNBER_E_MEMORY_LIMIT;
    }
    const size_t digitsCapacity = size * 3 + 4;
    const size_t textCapacity = size * 3 + 3;

    void *digitsMemory = nullptr;
    asnber_err_t rc =
        asnber::documentAllocate(node->document, digitsCapacity, &digitsMemory);
    if (rc != ASNBER_OK) {
        return rc;
    }
    uint8_t *digits = static_cast<uint8_t *>(digitsMemory);
    std::memset(digits, 0, digitsCapacity);

    /* 先求绝对值字节（负数按二进制补码取反加一，进位从最低字节开始）。 */
    void *magnitudeMemory = nullptr;
    rc = asnber::documentAllocate(node->document, size, &magnitudeMemory);
    if (rc != ASNBER_OK) {
        return rc;
    }
    uint8_t *magnitude = static_cast<uint8_t *>(magnitudeMemory);

    const bool negative = (node->content[0] & 0x80u) != 0;
    if (negative) {
        uint16_t carry = 1;
        for (size_t i = size; i > 0; --i) {
            const uint16_t value = static_cast<uint16_t>(
                                       (~static_cast<uint32_t>(
                                            node->content[i - 1]) &
                                        0xFFu)) +
                                   carry;
            magnitude[i - 1] = static_cast<uint8_t>(value & 0xFFu);
            carry = static_cast<uint16_t>(value >> 8);
        }
    } else {
        std::memcpy(magnitude, node->content, size);
    }

    /* 逐字节把绝对值累积到十进制数字串（little-endian）。 */
    size_t digitCount = 1;
    for (size_t i = 0; i < size; ++i) {
        uint32_t carry = magnitude[i];
        for (size_t j = 0; j < digitCount; ++j) {
            const uint32_t value =
                static_cast<uint32_t>(digits[j]) * 256u + carry;
            digits[j] = static_cast<uint8_t>(value % 10u);
            carry = value / 10u;
        }
        while (carry != 0) {
            digits[digitCount++] = static_cast<uint8_t>(carry % 10u);
            carry /= 10u;
        }
    }

    while (digitCount > 1 && digits[digitCount - 1] == 0) {
        --digitCount;
    }

    void *textMemory = nullptr;
    rc = asnber::documentAllocate(node->document, textCapacity, &textMemory);
    if (rc != ASNBER_OK) {
        return rc;
    }
    char *text = static_cast<char *>(textMemory);

    size_t written = 0;
    if (negative) {
        text[written++] = '-';
    }
    for (size_t i = digitCount; i > 0; --i) {
        text[written++] = static_cast<char>('0' + digits[i - 1]);
    }
    text[written] = '\0';

    *out_text = text;
    *out_size = written;
    return ASNBER_OK;
}

/* ----------------------------------------------------------------------------
 * 时间解析
 * -------------------------------------------------------------------------- */

bool readDigits(const uint8_t *bytes, size_t size, size_t *pos, size_t count,
                int *outValue) noexcept
{
    if (count > size - *pos) {
        return false;
    }
    int value = 0;
    for (size_t i = 0; i < count; ++i) {
        const uint8_t ch = bytes[*pos + i];
        if (ch < '0' || ch > '9') {
            return false;
        }
        value = value * 10 + static_cast<int>(ch - '0');
    }
    *pos += count;
    *outValue = value;
    return true;
}

bool isDigit(const uint8_t *bytes, size_t size, size_t pos) noexcept
{
    return pos < size && bytes[pos] >= '0' && bytes[pos] <= '9';
}

int daysInMonth(int year, int month) noexcept
{
    static const int kDays[12] = {31, 28, 31, 30, 31, 30,
                                  31, 31, 30, 31, 30, 31};
    if (month == 2) {
        const bool leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
        return leap ? 29 : 28;
    }
    return kDays[month - 1];
}

asnber_err_t getTimeValue(const asnber::Node *node, asnber_time_t *out_time) noexcept
{
    const uint32_t tag = asnber::universalTagNumber(node);
    if (tag != 23u && tag != 24u) {
        return ASNBER_E_INVALID_VALUE;
    }
    if (asnber::nodeIsConstructed(node) || node->content == nullptr) {
        return ASNBER_E_MALFORMED_VALUE;
    }

    const bool generalized = tag == 24u;
    const bool der = node->document->encoding == ASNBER_ENCODING_DER;
    const uint8_t *bytes = node->content;
    const size_t size = node->contentSize;
    size_t pos = 0;

    int year = 0;
    int month = 0;
    int day = 0;
    int hour = 0;
    int minute = 0;
    int second = 0;

    if (!generalized) {
        int shortYear = 0;
        if (!readDigits(bytes, size, &pos, 2, &shortYear)) {
            return ASNBER_E_MALFORMED_VALUE;
        }
        year = shortYear < 50 ? 2000 + shortYear : 1900 + shortYear;
    } else if (!readDigits(bytes, size, &pos, 4, &year)) {
        return ASNBER_E_MALFORMED_VALUE;
    }

    if (!readDigits(bytes, size, &pos, 2, &month) ||
        !readDigits(bytes, size, &pos, 2, &day) ||
        !readDigits(bytes, size, &pos, 2, &hour) ||
        !readDigits(bytes, size, &pos, 2, &minute)) {
        return ASNBER_E_MALFORMED_VALUE;
    }

    bool hasSeconds = false;
    if (isDigit(bytes, size, pos)) {
        if (!readDigits(bytes, size, &pos, 2, &second)) {
            return ASNBER_E_MALFORMED_VALUE;
        }
        hasSeconds = true;
        if (pos < size && isDigit(bytes, size, pos)) {
            return ASNBER_E_MALFORMED_VALUE;
        }
    }

    bool fractional = false;
    uint32_t nanosecond = 0;
    if (generalized && pos < size &&
        (bytes[pos] == '.' || bytes[pos] == ',')) {
        ++pos;
        const size_t fractionStart = pos;
        uint32_t value = 0;
        size_t digits = 0;
        while (isDigit(bytes, size, pos)) {
            if (digits < 9) {
                value = value * 10u + static_cast<uint32_t>(bytes[pos] - '0');
                ++digits;
            }
            ++pos;
        }
        if (pos == fractionStart) {
            return ASNBER_E_MALFORMED_VALUE;
        }
        while (digits < 9) {
            value *= 10u;
            ++digits;
        }
        nanosecond = value;
        fractional = true;
    }

    bool hasOffset = false;
    bool local = false;
    int offsetMinutes = 0;

    if (pos < size) {
        if (bytes[pos] == 'Z') {
            ++pos;
        } else if (bytes[pos] == '+' || bytes[pos] == '-') {
            const bool negativeOffset = bytes[pos] == '-';
            ++pos;
            int offsetHour = 0;
            int offsetMinute = 0;
            if (!readDigits(bytes, size, &pos, 2, &offsetHour) ||
                !readDigits(bytes, size, &pos, 2, &offsetMinute)) {
                return ASNBER_E_MALFORMED_VALUE;
            }
            if (offsetHour > 14 || offsetMinute > 59 ||
                (offsetHour == 14 && offsetMinute != 0)) {
                return ASNBER_E_MALFORMED_VALUE;
            }
            if (der && offsetMinute != 0) {
                return ASNBER_E_NON_CANONICAL;
            }
            hasOffset = true;
            offsetMinutes = offsetHour * 60 + offsetMinute;
            if (negativeOffset) {
                offsetMinutes = -offsetMinutes;
            }
        } else {
            return ASNBER_E_MALFORMED_VALUE;
        }
    } else {
        local = true;
    }

    if (pos != size) {
        return ASNBER_E_MALFORMED_VALUE;
    }

    if (der && local) {
        return ASNBER_E_NON_CANONICAL;
    }
    if (der && !hasSeconds) {
        return ASNBER_E_NON_CANONICAL;
    }

    if (month < 1 || month > 12 || day < 1 ||
        day > daysInMonth(year, month) || hour > 23 || minute > 59) {
        return ASNBER_E_MALFORMED_VALUE;
    }
    if (second > 60 || (der && second > 59)) {
        return der ? ASNBER_E_NON_CANONICAL : ASNBER_E_MALFORMED_VALUE;
    }

    std::memset(out_time, 0, sizeof(asnber_time_t));
    out_time->struct_size = sizeof(asnber_time_t);
    out_time->year = static_cast<int32_t>(year);
    out_time->month = static_cast<uint8_t>(month);
    out_time->day = static_cast<uint8_t>(day);
    out_time->hour = static_cast<uint8_t>(hour);
    out_time->minute = static_cast<uint8_t>(minute);
    out_time->second = static_cast<uint8_t>(second);
    out_time->nanosecond = fractional ? nanosecond : 0;
    out_time->utc_offset_minutes = static_cast<int16_t>(offsetMinutes);

    uint32_t flags = generalized ? ASNBER_TIME_GENERALIZED : ASNBER_TIME_UTC;
    if (fractional) {
        flags |= ASNBER_TIME_FRACTIONAL;
    }
    if (hasOffset) {
        flags |= ASNBER_TIME_HAS_OFFSET;
    } else if (local) {
        flags |= ASNBER_TIME_LOCAL;
    }
    out_time->flags = flags;
    return ASNBER_OK;
}

} /* namespace */

// ============================================================================
// 类型定义
// ============================================================================

// 无文件级类型。

// ============================================================================
// 静态常量 / 内部辅助类型
// ============================================================================

// 无文件级常量。

// ============================================================================
// 构造与析构
// ============================================================================

// 无独立生命周期。

// ============================================================================
// 公共接口
// ============================================================================

extern "C" asnber_err_t asnber_node_get_utf8(const asnber_node_t *handle,
                                         const char **out_text,
                                         size_t *out_size)
{
    if (handle == nullptr || out_text == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber::Node *node = nodeOf(handle);
    const uint32_t tag = asnber::universalTagNumber(node);

    const bool asciiFamily = tag == 18u || tag == 19u || tag == 22u ||
                             tag == 26u;
    const bool utf8 = tag == 12u;
    const bool bmp = tag == 30u;
    const bool universal = tag == 28u;
    if (!asciiFamily && !utf8 && !bmp && !universal) {
        /* T61/Teletex 与白名单外字符集统一返回 CONVERSION；
         * 原始字节走 asnber_node_get_raw_string。 */
        return ASNBER_E_CONVERSION;
    }

    const uint8_t *data = nullptr;
    size_t size = 0;
    asnber_err_t rc = asnber::mergePrimitiveContent(node, &data, &size);
    if (rc != ASNBER_OK) {
        /* docs/02 6.6：合并阶段失败按转换失败上报；资源上限错误保留原码。 */
        return rc == ASNBER_E_MALFORMED_VALUE ? ASNBER_E_CONVERSION : rc;
    }
    if (size == 0) {
        *out_text = nullptr;
        *out_size = 0;
        return ASNBER_OK;
    }
    if (size > (SIZE_MAX - 2) / 2) {
        return ASNBER_E_MEMORY_LIMIT;
    }

    const size_t capacity = size * 2 + 2;
    void *buffer = nullptr;
    rc = asnber::documentAllocate(node->document, capacity, &buffer);
    if (rc != ASNBER_OK) {
        return rc;
    }
    char *text = static_cast<char *>(buffer);

    if (asciiFamily || utf8) {
        if (utf8) {
            size_t cursor = 0;
            while (cursor < size) {
                uint32_t codePoint = 0;
                if (!decodeUtf8(data, size, &cursor, &codePoint)) {
                    return ASNBER_E_CONVERSION;
                }
            }
        } else {
            for (size_t i = 0; i < size; ++i) {
                if (data[i] >= 0x80u) {
                    return ASNBER_E_CONVERSION;
                }
            }
        }
        std::memcpy(text, data, size);
        text[size] = '\0';
        *out_text = text;
        *out_size = size;
        return ASNBER_OK;
    }

    size_t written = 0;
    if (bmp) {
        if (size % 2u != 0) {
            return ASNBER_E_CONVERSION;
        }
        for (size_t i = 0; i < size; i += 2) {
            uint32_t codePoint =
                (static_cast<uint32_t>(data[i]) << 8) | data[i + 1];
            if (codePoint >= 0xD800u && codePoint <= 0xDBFFu) {
                if (i + 3 >= size) {
                    return ASNBER_E_CONVERSION;
                }
                const uint32_t low =
                    (static_cast<uint32_t>(data[i + 2]) << 8) | data[i + 3];
                if (low < 0xDC00u || low > 0xDFFFu) {
                    return ASNBER_E_CONVERSION;
                }
                codePoint = 0x10000u + ((codePoint - 0xD800u) << 10) +
                            (low - 0xDC00u);
                i += 2;
            } else if (codePoint >= 0xDC00u && codePoint <= 0xDFFFu) {
                return ASNBER_E_CONVERSION;
            }
            written += encodeUtf8(codePoint, text + written);
        }
    } else {
        if (size % 4u != 0) {
            return ASNBER_E_CONVERSION;
        }
        for (size_t i = 0; i < size; i += 4) {
            const uint32_t codePoint = (static_cast<uint32_t>(data[i]) << 24) |
                                       (static_cast<uint32_t>(data[i + 1]) << 16) |
                                       (static_cast<uint32_t>(data[i + 2]) << 8) |
                                       static_cast<uint32_t>(data[i + 3]);
            if (codePoint > 0x10FFFFu ||
                (codePoint >= 0xD800u && codePoint <= 0xDFFFu)) {
                return ASNBER_E_CONVERSION;
            }
            written += encodeUtf8(codePoint, text + written);
        }
    }

    text[written] = '\0';
    *out_text = text;
    *out_size = written;
    return ASNBER_OK;
}

extern "C" asnber_err_t asnber_node_get_bigint_decimal(const asnber_node_t *handle,
                                                   const char **out_text,
                                                   size_t *out_size)
{
    if (handle == nullptr || out_text == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return bigintDecimal(nodeOf(handle), out_text, out_size);
}

extern "C" asnber_err_t asnber_node_get_time(const asnber_node_t *handle,
                                         asnber_time_t *out_time)
{
    if (handle == nullptr || out_time == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (out_time->struct_size != sizeof(asnber_time_t)) {
        return ASNBER_E_INVALID_CONFIG;
    }
    return getTimeValue(nodeOf(handle), out_time);
}
