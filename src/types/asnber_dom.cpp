/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * DOM 实现：文档/节点创建、arena 分配、内容挂载与封存校验。
 *
 * 分区见 docs/08 第 4 节。本文件不递归析构；封存校验的递归深度受
 * 上下文 max_depth 约束。
 */

// ============================================================================
// 依赖与前置声明
// ============================================================================

#include "types/asnber_dom.h"

#include <cstring>

namespace asnber {

namespace {

/* arena 默认块大小；大对象按实际尺寸单独成块。 */
constexpr size_t kArenaBlockSize = 4096;

} /* namespace */

// ============================================================================
// 类型定义
// ============================================================================

// 类型定义位于 asnber_dom.h。

// ============================================================================
// 静态常量 / 内部辅助类型
// ============================================================================

// 常量位于 asnber_dom.h 与上方匿名命名空间。

// ============================================================================
// 构造与析构
// ============================================================================

asnber_err_t documentCreate(Context *ctx, Document **outDoc) noexcept
{
    if (ctx == nullptr || outDoc == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *outDoc = nullptr;

    void *memory = nullptr;
    asnber_err_t rc =
        contextAllocate(ctx, sizeof(Document), AllocationKind::kDocument, &memory);
    if (rc != ASNBER_OK) {
        return rc;
    }

    Document *doc = static_cast<Document *>(memory);
    std::memset(doc, 0, sizeof(Document));
    doc->ctx = ctx;
    doc->root = nullptr;
    doc->input = nullptr;
    doc->inputSize = 0;
    doc->ownsInput = false;
    doc->sealed = false;
    doc->fromDecode = false;
    doc->encoding = ASNBER_ENCODING_NONE;
    doc->blocks = nullptr;
    doc->nodeCount = 0;
    doc->magic = kDocumentMagic;

    *outDoc = doc;
    return ASNBER_OK;
}

void documentDestroy(Document *doc) noexcept
{
    if (doc == nullptr || doc->magic != kDocumentMagic) {
        return;
    }

    ArenaBlock *block = doc->blocks;
    while (block != nullptr) {
        ArenaBlock *next = block->next;
        contextRelease(doc->ctx, block);
        block = next;
    }
    doc->blocks = nullptr;

    Context *ctx = doc->ctx;
    doc->magic = 0;
    doc->ctx = nullptr;
    contextRelease(ctx, doc);
}

// ============================================================================
// 公共接口
// ============================================================================

asnber_err_t documentAllocate(Document *doc, size_t size, void **outPtr) noexcept
{
    if (outPtr == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *outPtr = nullptr;
    if (doc == nullptr || doc->magic != kDocumentMagic) {
        return ASNBER_E_INVALID_STATE;
    }
    if (size == 0) {
        return ASNBER_E_INVALID_ARG;
    }

    const size_t alignment = alignof(std::max_align_t);
    const size_t aligned = alignUp(size, alignment);
    if (aligned < size) {
        return ASNBER_E_MEMORY_LIMIT;
    }

    ArenaBlock *block = doc->blocks;
    if (block != nullptr && block->used <= block->capacity &&
        aligned <= block->capacity - block->used) {
        void *ptr = reinterpret_cast<unsigned char *>(block + 1) + block->used;
        block->used += aligned;
        *outPtr = ptr;
        return ASNBER_OK;
    }

    const size_t capacity = aligned > kArenaBlockSize ? aligned : kArenaBlockSize;
    if (capacity > SIZE_MAX - sizeof(ArenaBlock)) {
        return ASNBER_E_MEMORY_LIMIT;
    }

    void *memory = nullptr;
    asnber_err_t rc = contextAllocate(doc->ctx, sizeof(ArenaBlock) + capacity,
                                    AllocationKind::kArenaBlock, &memory);
    if (rc != ASNBER_OK) {
        return rc;
    }

    ArenaBlock *created = static_cast<ArenaBlock *>(memory);
    created->next = doc->blocks;
    created->used = aligned;
    created->capacity = capacity;
    doc->blocks = created;

    *outPtr = static_cast<void *>(created + 1);
    return ASNBER_OK;
}

asnber_err_t documentCreateNode(Document *doc, Node *parent, uint32_t tagClass,
                              uint32_t tagNumber, bool constructed,
                              uint32_t depth, size_t tlvOffset,
                              size_t tlvSize, const uint8_t *content,
                              size_t contentSize, Node **outNode) noexcept
{
    if (outNode == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *outNode = nullptr;
    if (doc == nullptr || doc->magic != kDocumentMagic) {
        return ASNBER_E_INVALID_STATE;
    }
    if (doc->sealed) {
        contextSetError(doc->ctx, ASNBER_E_INVALID_STATE, SIZE_MAX, depth);
        return ASNBER_E_INVALID_STATE;
    }
    if (parent != nullptr && parent->document != doc) {
        contextSetError(doc->ctx, ASNBER_E_INVALID_ARG, SIZE_MAX, depth);
        return ASNBER_E_INVALID_ARG;
    }
    if (parent != nullptr && nodeIsAny(parent)) {
        /* ANY 以保留的原始 TLV 完整表达，不得再挂子节点。 */
        contextSetError(doc->ctx, ASNBER_E_INVALID_STATE, SIZE_MAX, depth);
        return ASNBER_E_INVALID_STATE;
    }
    if (parent != nullptr && !nodeIsConstructed(parent)) {
        contextSetError(doc->ctx, ASNBER_E_INVALID_STATE, SIZE_MAX, depth);
        return ASNBER_E_INVALID_STATE;
    }
    if (parent == nullptr && doc->root != nullptr) {
        contextSetError(doc->ctx, ASNBER_E_INVALID_STATE, SIZE_MAX, depth);
        return ASNBER_E_INVALID_STATE;
    }
    if (doc->nodeCount >= doc->ctx->m_maxNodes) {
        contextSetError(doc->ctx, ASNBER_E_NODE_LIMIT, SIZE_MAX, depth);
        return ASNBER_E_NODE_LIMIT;
    }

    void *memory = nullptr;
    asnber_err_t rc = documentAllocate(doc, sizeof(Node), &memory);
    if (rc != ASNBER_OK) {
        return rc;
    }

    Node *node = static_cast<Node *>(memory);
    std::memset(node, 0, sizeof(Node));
    node->tagClass = tagClass;
    node->tagNumber = tagNumber;
    node->flags = constructed ? kNodeFlagConstructed : 0;
    node->depth = depth;
    node->tlvOffset = tlvOffset;
    node->tlvSize = tlvSize;
    node->content = content;
    node->contentSize = contentSize;
    if (content != nullptr || contentSize != 0) {
        node->flags |= kNodeFlagHasContent;
    }
    node->parent = parent;
    node->document = doc;
    node->oidText = nullptr;

    if (parent == nullptr) {
        doc->root = node;
    } else if (parent->lastChild == nullptr) {
        parent->firstChild = node;
        parent->lastChild = node;
    } else {
        parent->lastChild->nextSibling = node;
        parent->lastChild = node;
    }

    ++doc->nodeCount;
    *outNode = node;
    return ASNBER_OK;
}

asnber_err_t documentSetFieldName(Document *doc, Node *node,
                                const char *name) noexcept
{
    if (doc == nullptr || node == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (node->document != doc) {
        return ASNBER_E_INVALID_ARG;
    }
    if (name == nullptr) {
        node->fieldName = nullptr;
        return ASNBER_OK;
    }
    const size_t length = std::strlen(name) + 1;
    void *copy = nullptr;
    const asnber_err_t rc = documentAllocate(doc, length, &copy);
    if (rc != ASNBER_OK) {
        return rc;
    }
    std::memcpy(copy, name, length);
    node->fieldName = static_cast<const char *>(copy);
    return ASNBER_OK;
}

asnber_err_t documentSeal(Document *doc) noexcept
{
    if (doc == nullptr || doc->magic != kDocumentMagic) {
        return ASNBER_E_INVALID_ARG;
    }
    if (doc->sealed) {
        return ASNBER_OK;
    }
    if (doc->root == nullptr) {
        contextSetError(doc->ctx, ASNBER_E_INVALID_STATE, SIZE_MAX, 0);
        return ASNBER_E_INVALID_STATE;
    }

    /* 迭代校验所有节点：基本节点必须有内容，构造节点不得有内容。 */
    Node *node = doc->root;
    while (node != nullptr) {
        if (nodeIsAny(node)) {
            /* ANY 节点由原始 TLV 完整表达，内容存在性不做结构校验。 */
        } else if (nodeIsConstructed(node)) {
            if ((node->flags & kNodeFlagHasContent) != 0) {
                contextSetError(doc->ctx, ASNBER_E_INVALID_STATE, SIZE_MAX,
                                node->depth);
                return ASNBER_E_INVALID_STATE;
            }
        } else if ((node->flags & kNodeFlagHasContent) == 0) {
            contextSetError(doc->ctx, ASNBER_E_INVALID_STATE, SIZE_MAX,
                            node->depth);
            return ASNBER_E_INVALID_STATE;
        }

        if (node->firstChild != nullptr) {
            node = node->firstChild;
        } else if (node->nextSibling != nullptr) {
            node = node->nextSibling;
        } else {
            while (node != nullptr && node->nextSibling == nullptr) {
                node = node->parent;
            }
            if (node != nullptr) {
                node = node->nextSibling;
            }
        }
    }

    doc->sealed = true;
    return ASNBER_OK;
}

bool nodeIsConstructed(const Node *node) noexcept
{
    return node != nullptr && (node->flags & kNodeFlagConstructed) != 0;
}

bool nodeIsAny(const Node *node) noexcept
{
    return node != nullptr && (node->flags & kNodeFlagAny) != 0;
}

size_t nodeChildCount(const Node *node) noexcept
{
    size_t count = 0;
    if (node == nullptr || nodeIsAny(node)) {
        return 0;
    }
    const Node *child = node->firstChild;
    while (child != nullptr) {
        ++count;
        child = child->nextSibling;
    }
    return count;
}

} /* namespace asnber */
