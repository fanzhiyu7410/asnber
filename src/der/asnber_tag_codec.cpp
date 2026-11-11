/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * DER 标签与长度字段写出实现。
 *
 * 标签首字节之后按 base-128 变长续字节编码；长度按最小字节数写出，
 * 不使用不定长形式。
 */

#include "asnber_tag_codec.h"

namespace asnber {
namespace der_detail {

size_t tagFieldBytes(uint32_t number) noexcept
{
    if (number < 31) {
        return 1;
    }
    /* 首字节后跟若干 base-128 续字节，续字节数至少 1。 */
    size_t groups = 1;
    uint32_t remaining = number >> 7;
    while (remaining != 0) {
        ++groups;
        remaining >>= 7;
    }
    return 1 + groups;
}

size_t lengthFieldBytes(size_t length) noexcept
{
    if (length < 128) {
        return 1;
    }
    size_t bytes = 0;
    size_t remaining = length;
    while (remaining != 0) {
        ++bytes;
        remaining >>= 8;
    }
    return 1 + bytes;
}

void writeTag(uint8_t *dst, uint32_t tagClass, uint32_t tagNumber,
              bool constructed) noexcept
{
    uint8_t first = static_cast<uint8_t>((tagClass & 0x3U) << 6);
    if (constructed) {
        first |= 0x20U;
    }
    if (tagNumber < 31) {
        dst[0] = static_cast<uint8_t>(first | tagNumber);
        return;
    }
    dst[0] = static_cast<uint8_t>(first | 0x1FU);
    /* base-128 变长：31–127 一个续字节，128–16383 两个，依此类推。
       uint32_t 最多需要 5 个续字节，parts 容量覆盖全部取值。 */
    uint8_t parts[5] = {0};
    size_t count = 0;
    uint32_t remaining = tagNumber;
    while (remaining != 0) {
        parts[sizeof(parts) - 1 - count] =
            static_cast<uint8_t>(remaining & 0x7FU);
        ++count;
        remaining >>= 7;
    }
    for (size_t i = 0; i < count; ++i) {
        uint8_t byte = parts[sizeof(parts) - count + i];
        if (i + 1 < count) {
            byte |= 0x80U;
        }
        dst[1 + i] = byte;
    }
}

size_t writeLength(uint8_t *dst, size_t length) noexcept
{
    if (length < 128) {
        dst[0] = static_cast<uint8_t>(length);
        return 1;
    }
    size_t bytes = 0;
    size_t remaining = length;
    while (remaining != 0) {
        ++bytes;
        remaining >>= 8;
    }
    dst[0] = static_cast<uint8_t>(0x80U | bytes);
    for (size_t i = 0; i < bytes; ++i) {
        dst[1 + i] = static_cast<uint8_t>((length >> (8 * (bytes - 1 - i))) &
                                          0xFFU);
    }
    return 1 + bytes;
}

} /* namespace der_detail */
} /* namespace asnber */
