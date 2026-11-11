/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * DOM 构建侧独占实现：ANY 节点创建与内容挂载。
 * ASNBER_FEATURE_BUILD_API=0 时本文件不参与编译。
 */

#include "types/asnber_dom.h"

#include <cstring>

namespace asnber {

asnber_err_t documentCreateAnyNode(Document *doc, Node *parent,
                                 uint32_t tagClass, uint32_t tagNumber,
                                 bool constructed, uint32_t depth,
                                 const uint8_t *rawTlv, size_t rawTlvSize,
                                 const uint8_t *content, size_t contentSize,
                                 Node **outNode) noexcept
{
    if (rawTlv == nullptr || rawTlvSize == 0) {
        return ASNBER_E_INVALID_ARG;
    }
    if (content == nullptr && contentSize != 0) {
        return ASNBER_E_INVALID_ARG;
    }

    Node *node = nullptr;
    asnber_err_t rc = documentCreateNode(doc, parent, tagClass, tagNumber,
                                       constructed, depth, SIZE_MAX, rawTlvSize,
                                       content, contentSize, &node);
    if (rc != ASNBER_OK) {
        return rc;
    }

    node->flags |= kNodeFlagAny;
    node->rawTlv = rawTlv;
    node->rawTlvSize = rawTlvSize;
    *outNode = node;
    return ASNBER_OK;
}

asnber_err_t documentSetNodeContent(Document *doc, Node *node,
                                  const uint8_t *data, size_t size) noexcept
{
    if (doc == nullptr || node == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (data == nullptr && size != 0) {
        return ASNBER_E_INVALID_ARG;
    }
    if (node->document != doc || doc->magic != kDocumentMagic) {
        return ASNBER_E_INVALID_ARG;
    }
    if (doc->sealed) {
        contextSetError(doc->ctx, ASNBER_E_INVALID_STATE, SIZE_MAX, node->depth);
        return ASNBER_E_INVALID_STATE;
    }
    if (nodeIsAny(node)) {
        /* ANY 节点以保留的原始 TLV 为准，禁止改写内容。 */
        contextSetError(doc->ctx, ASNBER_E_INVALID_STATE, SIZE_MAX, node->depth);
        return ASNBER_E_INVALID_STATE;
    }
    if (nodeIsConstructed(node)) {
        contextSetError(doc->ctx, ASNBER_E_INVALID_STATE, SIZE_MAX, node->depth);
        return ASNBER_E_INVALID_STATE;
    }
    if ((node->flags & kNodeFlagHasContent) != 0) {
        contextSetError(doc->ctx, ASNBER_E_INVALID_STATE, SIZE_MAX, node->depth);
        return ASNBER_E_INVALID_STATE;
    }

    if (size != 0) {
        void *copy = nullptr;
        asnber_err_t rc = documentAllocate(doc, size, &copy);
        if (rc != ASNBER_OK) {
            return rc;
        }
        std::memcpy(copy, data, size);
        node->content = static_cast<const uint8_t *>(copy);
    } else {
        node->content = nullptr;
    }
    node->contentSize = size;
    node->flags |= kNodeFlagHasContent;
    return ASNBER_OK;
}

asnber_err_t documentAttachNodeContent(Document *doc, Node *node,
                                     const uint8_t *data, size_t size) noexcept
{
    if (doc == nullptr || node == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (node->document != doc) {
        return ASNBER_E_INVALID_ARG;
    }
    if (doc->sealed) {
        return ASNBER_E_INVALID_STATE;
    }
    if (nodeIsAny(node) || nodeIsConstructed(node) ||
        (node->flags & kNodeFlagHasContent) != 0) {
        return ASNBER_E_INVALID_STATE;
    }
    node->content = data;
    node->contentSize = size;
    node->flags |= kNodeFlagHasContent;
    return ASNBER_OK;
}

} /* namespace asnber */
