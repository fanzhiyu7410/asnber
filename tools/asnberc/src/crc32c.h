/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 软件 CRC32C（Castagnoli）实现。
 * 参数与 docs/11-描述表格式.md §2.1 一致：
 * 反射多项式 0x82F63B78、初值 0xFFFFFFFF、输入/输出反射、xorout 0xFFFFFFFF。
 * zeroOffset/zeroLength 指定校验时按 0 参与的字节区间（用于 checksum 字段自身）。
 */
#ifndef ASNBERC_CRC32C_H_INCLUDED
#define ASNBERC_CRC32C_H_INCLUDED

#include <cstddef>
#include <cstdint>

namespace asnberc {

uint32_t crc32c(const uint8_t *data, size_t size, size_t zeroOffset,
                size_t zeroLength) noexcept;

} /* namespace asnberc */

#endif /* ASNBERC_CRC32C_H_INCLUDED */
