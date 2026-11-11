/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * DER 标签与长度字段的宽度计算与写出。
 *
 * 通用 DER 编码器与 schema 感知编码共用的唯一实现，避免两套字节生成
 * 逻辑各自漂移。
 */

#ifndef ASNBER_DER_TAG_CODEC_H_INCLUDED
#define ASNBER_DER_TAG_CODEC_H_INCLUDED

#include <cstddef>
#include <cstdint>

namespace asnber {
namespace der_detail {

size_t tagFieldBytes(uint32_t tagNumber) noexcept;
size_t lengthFieldBytes(size_t contentSize) noexcept;
void writeTag(uint8_t *dst, uint32_t tagClass, uint32_t tagNumber,
              bool constructed) noexcept;
size_t writeLength(uint8_t *dst, size_t length) noexcept;

} /* namespace der_detail */
} /* namespace asnber */

#endif /* ASNBER_DER_TAG_CODEC_H_INCLUDED */
