/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * schema 感知 DER 编码。
 *
 * 职责：按 schema 输出字段顺序、省略等于 DEFAULT 的字段、对 SET/SET OF
 *       做 DER 排序，并对 EXPLICIT ANY 重新加外层包装；无 schema 的通用
 *       编码路径不受影响。
 * 依赖：core/asnber_context.h、schema/asnber_schema.h、types/asnber_dom.h。
 * 所有权：只读文档与 schema；临时排序缓冲由上下文分配并释放。
 */

#ifndef ASNBER_SRC_SCHEMA_ASNBER_SCHEMA_ENCODE_H_INCLUDED
#define ASNBER_SRC_SCHEMA_ASNBER_SCHEMA_ENCODE_H_INCLUDED

#include <asnber/asnber.h>

#include <cstddef>

#include "../core/asnber_context.h"
#include "../types/asnber_dom.h"
#include "asnber_schema.h"

namespace asnber {

asnber_err_t schemaMeasureDocument(Context *ctx, const Document *doc,
                                 const Schema *schema, size_t *outSize) noexcept;
asnber_err_t schemaEncodeDocument(Context *ctx, const Document *doc,
                                const Schema *schema, uint8_t *dst,
                                size_t capacity) noexcept;

} /* namespace asnber */

#endif /* ASNBER_SRC_SCHEMA_ASNBER_SCHEMA_ENCODE_H_INCLUDED */
