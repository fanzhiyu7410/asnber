/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * DOM 内部模型：文档、节点与文档级 arena。
 *
 * 职责：定义 docs/04-数据与内存模型.md 第 2 节的节点表示，并提供构树、
 *       封存、arena 分配等内部操作。
 * 依赖：仅依赖 core/asnber_context.h 与公共 ABI。
 * 所有权：Document/Node 均由文档级 arena 或上下文级分配持有；节点地址
 *         稳定，追加子节点不会使已有节点指针失效。
 */
#ifndef ASNBER_SRC_TYPES_ASNBER_DOM_H_INCLUDED
#define ASNBER_SRC_TYPES_ASNBER_DOM_H_INCLUDED

#include <asnber/asnber.h>

#include <cstddef>
#include <cstdint>

#include "../core/asnber_context.h"

namespace asnber {

struct Document;
struct Node;

/* 文档 arena 块；data 紧跟在结构体之后，按 max_align_t 对齐。 */
struct alignas(std::max_align_t) ArenaBlock {
    ArenaBlock *next;
    size_t used;
    size_t capacity;
};

/* 节点标志位，仅内部使用。 */
constexpr uint32_t kNodeFlagConstructed = UINT32_C(1) << 0;
constexpr uint32_t kNodeFlagIndefinite = UINT32_C(1) << 1;
constexpr uint32_t kNodeFlagHasContent = UINT32_C(1) << 2;
constexpr uint32_t kNodeFlagDecoded = UINT32_C(1) << 3;
/* ANY/开放类型节点：保留完整原始 TLV，不展开、不改写。 */
constexpr uint32_t kNodeFlagAny = UINT32_C(1) << 4;

constexpr uint32_t kDocumentMagic = UINT32_C(0x444F4331); /* "DOC1" */

/*
 * 节点。字段布局对应 docs/04 第 2 节；content 指向输入切片或文档 arena，
 * 构造节点为 NULL。tlvOffset 为 SIZE_MAX 表示 runtime 构树节点。
 */
struct Node {
    uint32_t tagClass;
    uint32_t tagNumber;
    uint32_t flags;
    uint32_t depth;
    size_t tlvOffset;
    size_t tlvSize;
    const uint8_t *content;
    size_t contentSize;
    const uint8_t *rawTlv;          /* ANY 原始完整 TLV；其他节点为 NULL */
    size_t rawTlvSize;
    Node *parent;
    Node *firstChild;
    Node *nextSibling;
    Node *lastChild;
    Document *document;
    const char *fieldName;          /* schema 解码时复制进 arena；否则 NULL */
    const char *oidText;            /* 惰性 OID 点分文本缓存 */
};

/* 文档。input 为借用或复制后的输入基址；runtime 构树文档 input 为 NULL。 */
struct Document {
    Context *ctx;
    Node *root;
    const uint8_t *input;
    size_t inputSize;
    bool ownsInput;
    bool sealed;
    bool fromDecode;
    asnber_encoding_t encoding;
    ArenaBlock *blocks;
    uint64_t nodeCount;
    uint32_t magic;
};

/* 创建空文档（未封存、ASNBER_ENCODING_NONE）。 */
asnber_err_t documentCreate(Context *ctx, Document **outDoc) noexcept;

/* 销毁文档：释放全部 arena 块与文档对象。 */
void documentDestroy(Document *doc) noexcept;

/* 封存并校验结构；已封存返回 ASNBER_OK。 */
asnber_err_t documentSeal(Document *doc) noexcept;

/* 从文档 arena 分配对齐内存。 */
asnber_err_t documentAllocate(Document *doc, size_t size, void **outPtr) noexcept;

/*
 * 创建节点并按 parent 追加。depth 由调用方给出（解码时为输入嵌套深度）。
 * tlvOffset = SIZE_MAX 表示 runtime 构树；content 可为 NULL。
 */
asnber_err_t documentCreateNode(Document *doc, Node *parent, uint32_t tagClass,
                              uint32_t tagNumber, bool constructed,
                              uint32_t depth, size_t tlvOffset,
                              size_t tlvSize, const uint8_t *content,
                              size_t contentSize, Node **outNode) noexcept;

/* 把内容复制进文档 arena 并标记节点已有内容。 */
asnber_err_t documentSetNodeContent(Document *doc, Node *node,
                                  const uint8_t *data, size_t size) noexcept;

/*
 * 创建 ANY/开放类型节点：保留完整原始 TLV（rawTlv，由调用方保证生命周期，
 * 或已位于文档 arena）与原始内容切片 content/contentSize；不创建子节点。
 * 节点带 kNodeFlagAny，封存后不可改写。
 */
asnber_err_t documentCreateAnyNode(Document *doc, Node *parent,
                                 uint32_t tagClass, uint32_t tagNumber,
                                 bool constructed, uint32_t depth,
                                 const uint8_t *rawTlv, size_t rawTlvSize,
                                 const uint8_t *content, size_t contentSize,
                                 Node **outNode) noexcept;

/* 把已位于文档 arena 的缓冲直接挂到节点（不再复制）。 */
asnber_err_t documentAttachNodeContent(Document *doc, Node *node,
                                     const uint8_t *data,
                                     size_t size) noexcept;

/* 把字段名复制进文档 arena 并挂到节点；name == NULL 清除。 */
asnber_err_t documentSetFieldName(Document *doc, Node *node,
                                const char *name) noexcept;

/* 节点是否处于构造形态。 */
bool nodeIsConstructed(const Node *node) noexcept;

/* 节点是否为 ANY/开放类型节点。 */
bool nodeIsAny(const Node *node) noexcept;

/* 统计子节点数量（O(n)）；ANY 节点固定为 0。 */
size_t nodeChildCount(const Node *node) noexcept;

} /* namespace asnber */

#endif /* ASNBER_SRC_TYPES_ASNBER_DOM_H_INCLUDED */
