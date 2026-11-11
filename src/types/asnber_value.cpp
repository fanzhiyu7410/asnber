/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 语义读取共用辅助实现。
 */

// ============================================================================
// 依赖与前置声明
// ============================================================================

#include "types/asnber_value.h"

#include <cstring>

namespace asnber {

// ============================================================================
// 类型定义
// ============================================================================

// 类型定义位于 asnber_value.h。

// ============================================================================
// 静态常量 / 内部辅助类型
// ============================================================================

// 无文件级常量。

// ============================================================================
// 构造与析构
// ============================================================================

// 辅助函数无独立生命周期。

// ============================================================================
// 公共接口
// ============================================================================

asnber_err_t collectContentSize(const Node *node, size_t *outTotal) noexcept
{
    if (node == nullptr || outTotal == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }

    size_t total = 0;
    if (nodeIsConstructed(node)) {
        const Node *child = node->firstChild;
        while (child != nullptr) {
            size_t childTotal = 0;
            const asnber_err_t rc = collectContentSize(child, &childTotal);
            if (rc != ASNBER_OK) {
                return rc;
            }
            if (total > SIZE_MAX - childTotal) {
                return ASNBER_E_MEMORY_LIMIT;
            }
            total += childTotal;
            child = child->nextSibling;
        }
    } else {
        total = node->contentSize;
    }

    *outTotal = total;
    return ASNBER_OK;
}

void copyContent(const Node *node, uint8_t *dst, size_t capacity,
                 size_t *cursor) noexcept
{
    (void)capacity;
    if (nodeIsConstructed(node)) {
        const Node *child = node->firstChild;
        while (child != nullptr) {
            copyContent(child, dst, capacity, cursor);
            child = child->nextSibling;
        }
    } else if (node->content != nullptr && node->contentSize != 0) {
        std::memcpy(dst + *cursor, node->content, node->contentSize);
        *cursor += node->contentSize;
    }
}

uint32_t universalTagNumber(const Node *node) noexcept
{
    if (node == nullptr || node->tagClass != ASNBER_TAG_UNIVERSAL) {
        return UINT32_MAX;
    }
    return node->tagNumber;
}

asnber_err_t mergePrimitiveContent(const Node *node, const uint8_t **out_data,
                                 size_t *out_size) noexcept
{
    if (node == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }

    if (!nodeIsConstructed(node)) {
        *out_data = node->content;
        *out_size = node->contentSize;
        return ASNBER_OK;
    }

    size_t total = 0;
    asnber_err_t rc = collectContentSize(node, &total);
    if (rc != ASNBER_OK) {
        return rc;
    }
    if (total == 0) {
        *out_data = nullptr;
        *out_size = 0;
        return ASNBER_OK;
    }

    void *buffer = nullptr;
    rc = documentAllocate(node->document, total, &buffer);
    if (rc != ASNBER_OK) {
        return rc;
    }
    uint8_t *dst = static_cast<uint8_t *>(buffer);
    size_t cursor = 0;
    copyContent(node, dst, total, &cursor);
    *out_data = dst;
    *out_size = total;
    return ASNBER_OK;
}

} /* namespace asnber */
