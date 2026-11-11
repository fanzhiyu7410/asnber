/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

#include "crc32c.h"

namespace asnberc {

uint32_t crc32c(const uint8_t *data, size_t size, size_t zeroOffset,
                size_t zeroLength) noexcept
{
    uint32_t crc = UINT32_C(0xFFFFFFFF);
    for (size_t i = 0; i < size; ++i) {
        const bool zeroed = i >= zeroOffset && i < zeroOffset + zeroLength;
        const uint8_t byte = zeroed ? 0u : data[i];
        crc ^= static_cast<uint32_t>(byte);
        for (uint32_t bit = 0; bit < 8; ++bit) {
            const uint32_t mask =
                static_cast<uint32_t>(0u - (crc & UINT32_C(1)));
            crc = (crc >> 1) ^ (UINT32_C(0x82F63B78) & mask);
        }
    }
    return crc ^ UINT32_C(0xFFFFFFFF);
}

} /* namespace asnberc */
