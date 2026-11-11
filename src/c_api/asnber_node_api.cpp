/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 节点只读访问与原始内容读取。
 *
 * 职责：把 C 句柄转换为内部 Node/Document，并提供无分配的元数据访问。
 * 依赖：types/asnber_dom.h。
 */

// ============================================================================
// 依赖与前置声明
// ============================================================================

#include <asnber/asnber.h>

#include <cstring>

#include "types/asnber_dom.h"

namespace {

asnber::Document *documentOf(const asnber_doc_t *handle) noexcept
{
    return const_cast<asnber::Document *>(
        static_cast<const asnber::Document *>(static_cast<const void *>(handle)));
}

const asnber::Node *nodeOf(const asnber_node_t *handle) noexcept
{
    return static_cast<const asnber::Node *>(static_cast<const void *>(handle));
}

} /* namespace */

// ============================================================================
// 类型定义
// ============================================================================

// 内部类型位于 types/asnber_dom.h。

// ============================================================================
// 静态常量 / 内部辅助类型
// ============================================================================

// 无文件级常量。

// ============================================================================
// 构造与析构
// ============================================================================

// 节点没有独立生命周期。

// ============================================================================
// 公共接口
// ============================================================================

extern "C" const asnber_node_t *asnber_doc_root(const asnber_doc_t *handle)
{
    if (handle == nullptr) {
        return nullptr;
    }
    asnber::Document *doc = documentOf(handle);
    if (doc->magic != asnber::kDocumentMagic) {
        return nullptr;
    }
    return reinterpret_cast<const asnber_node_t *>(doc->root);
}

extern "C" asnber_encoding_t asnber_doc_source_encoding(const asnber_doc_t *handle)
{
    if (handle == nullptr) {
        return ASNBER_ENCODING_NONE;
    }
    asnber::Document *doc = documentOf(handle);
    if (doc->magic != asnber::kDocumentMagic) {
        return ASNBER_ENCODING_NONE;
    }
    return doc->encoding;
}

extern "C" asnber_tag_class_t asnber_node_tag_class(const asnber_node_t *handle)
{
    const asnber::Node *node = nodeOf(handle);
    if (node == nullptr) {
        return ASNBER_TAG_UNIVERSAL;
    }
    return static_cast<asnber_tag_class_t>(node->tagClass);
}

extern "C" uint32_t asnber_node_tag_number(const asnber_node_t *handle)
{
    const asnber::Node *node = nodeOf(handle);
    return node == nullptr ? 0 : node->tagNumber;
}

extern "C" asnber_encoding_form_t asnber_node_encoding_form(
    const asnber_node_t *handle)
{
    const asnber::Node *node = nodeOf(handle);
    if (node == nullptr) {
        return ASNBER_FORM_PRIMITIVE;
    }
    return asnber::nodeIsConstructed(node) ? ASNBER_FORM_CONSTRUCTED
                                         : ASNBER_FORM_PRIMITIVE;
}

extern "C" int asnber_node_is_indefinite(const asnber_node_t *handle)
{
    const asnber::Node *node = nodeOf(handle);
    if (node == nullptr) {
        return 0;
    }
    return (node->flags & asnber::kNodeFlagIndefinite) != 0 ? 1 : 0;
}

extern "C" size_t asnber_node_child_count(const asnber_node_t *handle)
{
    return asnber::nodeChildCount(nodeOf(handle));
}

extern "C" const asnber_node_t *asnber_node_child_at(const asnber_node_t *handle,
                                                 size_t index)
{
    const asnber::Node *node = nodeOf(handle);
    if (node == nullptr || asnber::nodeIsAny(node)) {
        /* ANY 节点不展开，子节点访问一律返回 NULL。 */
        return nullptr;
    }
    const asnber::Node *child = node->firstChild;
    size_t current = 0;
    while (child != nullptr) {
        if (current == index) {
            return reinterpret_cast<const asnber_node_t *>(child);
        }
        ++current;
        child = child->nextSibling;
    }
    return nullptr;
}

extern "C" const asnber_node_t *asnber_node_child_by_name(
    const asnber_node_t *handle, const char *field_name)
{
    const asnber::Node *node = nodeOf(handle);
    if (node == nullptr || field_name == nullptr || asnber::nodeIsAny(node)) {
        return nullptr;
    }
    for (const asnber::Node *child = node->firstChild; child != nullptr;
         child = child->nextSibling) {
        if (child->fieldName != nullptr &&
            std::strcmp(child->fieldName, field_name) == 0) {
            return reinterpret_cast<const asnber_node_t *>(child);
        }
    }
    return nullptr;
}

extern "C" const char *asnber_node_field_name(const asnber_node_t *handle)
{
    const asnber::Node *node = nodeOf(handle);
    return node == nullptr ? nullptr : node->fieldName;
}

extern "C" const asnber_node_t *asnber_node_parent(const asnber_node_t *handle)
{
    const asnber::Node *node = nodeOf(handle);
    if (node == nullptr || node->parent == nullptr) {
        return nullptr;
    }
    return reinterpret_cast<const asnber_node_t *>(node->parent);
}

extern "C" asnber_err_t asnber_node_content(const asnber_node_t *handle,
                                        const uint8_t **out_data,
                                        size_t *out_size)
{
    if (handle == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber::Node *node = nodeOf(handle);
    if (asnber::nodeIsAny(node)) {
        /* ANY 返回原始内容字节（不含 tag/len），构造型同样返回切片。 */
        *out_data = node->content;
        *out_size = node->contentSize;
        return ASNBER_OK;
    }
    if (asnber::nodeIsConstructed(node)) {
        return ASNBER_E_INVALID_STATE;
    }

    *out_data = node->content;
    *out_size = node->contentSize;
    return ASNBER_OK;
}

extern "C" const uint8_t *asnber_node_tlv(const asnber_node_t *handle,
                                        size_t *out_size)
{
    if (out_size != nullptr) {
        *out_size = 0;
    }
    const asnber::Node *node = nodeOf(handle);
    if (node == nullptr || node->document == nullptr) {
        return nullptr;
    }
    if (asnber::nodeIsAny(node) && node->rawTlv != nullptr) {
        /* ANY 的原始完整 TLV 独立于文档输入缓冲保存。 */
        if (out_size != nullptr) {
            *out_size = node->rawTlvSize;
        }
        return node->rawTlv;
    }
    if (node->tlvOffset == SIZE_MAX || node->document->input == nullptr) {
        /* runtime 构树节点没有原始 TLV。 */
        return nullptr;
    }
    if (out_size != nullptr) {
        *out_size = node->tlvSize;
    }
    return node->document->input + node->tlvOffset;
}

extern "C" size_t asnber_node_offset(const asnber_node_t *handle)
{
    const asnber::Node *node = nodeOf(handle);
    if (node == nullptr || node->tlvOffset == SIZE_MAX) {
        return SIZE_MAX;
    }
    return node->tlvOffset;
}
