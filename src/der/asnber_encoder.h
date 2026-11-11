/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * DER 编码器内部接口：测量与写出。
 *
 * 职责：把已封存文档树按通用 DER 规范化规则编码为字节流；SET/SET OF
 *       子元素按（标签类别、标签号、编码字节）升序排列。
 * 依赖：core/asnber_context.h、types/asnber_dom.h。
 * 所有权：dst 由调用方提供；临时缓冲由上下文级分配并在函数内释放。
 */
#ifndef ASNBER_SRC_DER_ASNBER_ENCODER_H_INCLUDED
#define ASNBER_SRC_DER_ASNBER_ENCODER_H_INCLUDED

#include <cstddef>

#include "../core/asnber_context.h"
#include "../types/asnber_dom.h"

namespace asnber {

/* 计算整棵文档树的 DER 编码字节数；溢出或超限写入上下文错误。 */
asnber_err_t derMeasureDocument(Context *ctx, const Document *doc,
                              size_t *outSize) noexcept;

/* 按 DER 写出到 dst；调用方保证 dst 至少有 size 字节。 */
asnber_err_t derEncodeDocument(Context *ctx, const Document *doc, uint8_t *dst,
                             size_t size) noexcept;

} /* namespace asnber */

#endif /* ASNBER_SRC_DER_ASNBER_ENCODER_H_INCLUDED */
