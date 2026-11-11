/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 语义读取共用辅助：构造形式内容合并与文本分配。
 *
 * 职责：为 asnber_node_get_octets / get_raw_string / get_utf8 等提供按序
 *       合并基本叶子内容的内部实现。
 * 依赖：types/asnber_dom.h。
 */
#ifndef ASNBER_SRC_TYPES_ASNBER_VALUE_H_INCLUDED
#define ASNBER_SRC_TYPES_ASNBER_VALUE_H_INCLUDED

#include "types/asnber_dom.h"

#include <cstddef>
#include <cstdint>

namespace asnber {

/* 递归统计基本叶子内容总字节数；溢出返回 ASNBER_E_MEMORY_LIMIT。 */
asnber_err_t collectContentSize(const Node *node, size_t *outTotal) noexcept;

/* 按序把基本叶子内容复制到 dst；capacity 必须等于统计值。 */
void copyContent(const Node *node, uint8_t *dst, size_t capacity,
                 size_t *cursor) noexcept;

/* 节点的 UNIVERSAL 标签号；非 UNIVERSAL 返回 UINT32_MAX。 */
uint32_t universalTagNumber(const Node *node) noexcept;

/*
 * 合并读取：基本节点直接返回借用内容；构造节点按序合并叶子内容并分配
 * 到文档 arena。空构造节点返回 out_data = NULL、out_size = 0。
 */
asnber_err_t mergePrimitiveContent(const Node *node, const uint8_t **out_data,
                                 size_t *out_size) noexcept;

} /* namespace asnber */

#endif /* ASNBER_SRC_TYPES_ASNBER_VALUE_H_INCLUDED */
