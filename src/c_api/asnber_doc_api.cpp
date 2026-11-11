/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * runtime 构树 C API：文档创建/封存、节点创建与内容设置。
 *
 * 职责：校验公共参数并调用 types/asnber_dom.h 的构树操作。
 * 依赖：types/asnber_dom.h、core/asnber_context.h。
 */

// ============================================================================
// 依赖与前置声明
// ============================================================================

#include <asnber/asnber.h>

#include "core/asnber_context.h"
#include "types/asnber_dom.h"

#include <cstring>

namespace {

asnber::Document *documentOf(asnber_doc_t *handle) noexcept
{
    return static_cast<asnber::Document *>(static_cast<void *>(handle));
}

asnber::Node *nodeOf(asnber_node_t *handle) noexcept
{
    return static_cast<asnber::Node *>(static_cast<void *>(handle));
}

/* 返回子标识符的 base-128 编码字节数。 */
size_t subidentifierOctets(uint64_t value) noexcept
{
    size_t count = 1;
    while (value >= 128) {
        value >>= 7;
        ++count;
    }
    return count;
}

void encodeSubidentifier(uint64_t value, uint8_t *out,
                         size_t *outCursor) noexcept
{
    uint8_t parts[10];
    size_t count = 0;
    do {
        parts[count++] = static_cast<uint8_t>(value & 0x7Fu);
        value >>= 7;
    } while (value != 0);

    size_t cursor = *outCursor;
    for (size_t i = count; i > 0; --i) {
        uint8_t byte = parts[i - 1];
        if (i > 1) {
            byte |= 0x80u;
        }
        out[cursor++] = byte;
    }
    *outCursor = cursor;
}

/* 单个完整 TLV 头部信息；headerSize 不含内容。 */
struct TlvHeader {
    uint32_t tagClass;
    uint32_t tagNumber;
    bool constructed;
    size_t headerSize;
    size_t contentSize;
};

/*
 * 严格解析恰好一个完整、长度确定的 TLV。成功要求 headerSize + contentSize
 * 等于 size，否则按截断/尾随分别报错；outErrorOffset 记录首个问题字节。
 */
asnber_err_t parseSingleTlv(const uint8_t *tlv, size_t size, TlvHeader *out,
                          size_t *outErrorOffset) noexcept
{
    size_t pos = 0;
    const uint8_t first = tlv[pos++];
    out->tagClass = (first >> 6) & 0x3U;
    out->constructed = (first & 0x20U) != 0;

    if ((first & 0x1FU) == 0x1FU) {
        /* 高位标签：base-128 continuation，首字节不得是 0x80。 */
        uint32_t number = 0;
        bool firstPart = true;
        while (true) {
            if (pos >= size) {
                *outErrorOffset = pos;
                return ASNBER_E_TRUNCATED;
            }
            const uint8_t part = tlv[pos];
            if (firstPart && part == 0x80U) {
                *outErrorOffset = pos;
                return ASNBER_E_MALFORMED_TAG;
            }
            firstPart = false;
            if (number > (UINT32_MAX >> 7)) {
                *outErrorOffset = pos;
                return ASNBER_E_MALFORMED_TAG;
            }
            number = (number << 7) | (part & 0x7FU);
            ++pos;
            if ((part & 0x80U) == 0) {
                break;
            }
        }
        out->tagNumber = number;
    } else {
        out->tagNumber = first & 0x1FU;
    }

    if (pos >= size) {
        *outErrorOffset = pos;
        return ASNBER_E_TRUNCATED;
    }
    const uint8_t lengthByte = tlv[pos++];
    size_t contentSize = 0;
    if (lengthByte < 0x80U) {
        contentSize = lengthByte;
    } else if (lengthByte == 0x80U) {
        *outErrorOffset = pos - 1;
        return ASNBER_E_INDEFINITE_NOT_ALLOWED;
    } else {
        const size_t octets = lengthByte & 0x7FU;
        if (octets > sizeof(size_t)) {
            *outErrorOffset = pos - 1;
            return ASNBER_E_MALFORMED_LENGTH;
        }
        if (octets > size - pos) {
            *outErrorOffset = pos;
            return ASNBER_E_TRUNCATED;
        }
        for (size_t i = 0; i < octets; ++i) {
            contentSize = (contentSize << 8) | tlv[pos++];
        }
    }

    out->headerSize = pos;
    out->contentSize = contentSize;
    if (contentSize > size - pos) {
        *outErrorOffset = size;
        return ASNBER_E_TRUNCATED;
    }
    if (contentSize < size - pos) {
        *outErrorOffset = pos + contentSize;
        return ASNBER_E_TRAILING_DATA;
    }
    return ASNBER_OK;
}

/* 解析十进制无符号数；失败返回 false。 */
bool parseDecimal(const char *text, size_t *cursor, uint64_t *outValue) noexcept
{
    size_t pos = *cursor;
    if (text[pos] < '0' || text[pos] > '9') {
        return false;
    }
    uint64_t value = 0;
    while (text[pos] >= '0' && text[pos] <= '9') {
        const uint64_t digit = static_cast<uint64_t>(text[pos] - '0');
        if (value > (UINT64_MAX - digit) / 10) {
            return false;
        }
        value = value * 10 + digit;
        ++pos;
    }
    *cursor = pos;
    *outValue = value;
    return true;
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

extern "C" asnber_err_t asnber_doc_create(asnber_ctx_t *ctxHandle,
                                       asnber_doc_t **out_doc)
{
    if (ctxHandle == nullptr || out_doc == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_doc = nullptr;

    asnber::Context *ctx =
        static_cast<asnber::Context *>(static_cast<void *>(ctxHandle));
    if (ctx->m_magic != asnber::kContextMagic || ctx->m_dead) {
        return ASNBER_E_INVALID_ARG;
    }

    asnber::Document *doc = nullptr;
    const asnber_err_t rc = asnber::documentCreate(ctx, &doc);
    if (rc != ASNBER_OK) {
        return rc;
    }

    *out_doc = reinterpret_cast<asnber_doc_t *>(doc);
    return ASNBER_OK;
}

extern "C" asnber_err_t asnber_doc_seal(asnber_doc_t *handle)
{
    if (handle == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber::Document *doc = documentOf(handle);
    if (doc->magic != asnber::kDocumentMagic) {
        return ASNBER_E_INVALID_ARG;
    }
    return asnber::documentSeal(doc);
}

extern "C" asnber_err_t asnber_node_create(asnber_doc_t *docHandle,
                                       asnber_node_t *parentHandle,
                                       asnber_tag_class_t tag_class,
                                       uint32_t tag_number, int constructed,
                                       asnber_node_t **out_node)
{
    if (docHandle == nullptr || out_node == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_node = nullptr;

    asnber::Document *doc = documentOf(docHandle);
    if (doc->magic != asnber::kDocumentMagic) {
        return ASNBER_E_INVALID_ARG;
    }

    if (tag_class < ASNBER_TAG_UNIVERSAL || tag_class > ASNBER_TAG_PRIVATE) {
        return ASNBER_E_INVALID_ARG;
    }
    if (tag_class == ASNBER_TAG_UNIVERSAL && tag_number == 0) {
        /* UNIVERSAL 0 是 EOC，不是合法内容类型。 */
        asnber::contextSetError(doc->ctx, ASNBER_E_INVALID_ARG, SIZE_MAX, 0);
        return ASNBER_E_INVALID_ARG;
    }

    asnber::Node *parent = nullptr;
    uint32_t depth = 0;
    if (parentHandle != nullptr) {
        parent = nodeOf(parentHandle);
        if (parent->document != doc) {
            asnber::contextSetError(doc->ctx, ASNBER_E_INVALID_ARG, SIZE_MAX, 0);
            return ASNBER_E_INVALID_ARG;
        }
        depth = parent->depth + 1;
    }

    asnber::Node *node = nullptr;
    const asnber_err_t rc = asnber::documentCreateNode(
        doc, parent, static_cast<uint32_t>(tag_class), tag_number,
        constructed != 0, depth, SIZE_MAX, 0, nullptr, 0, &node);
    if (rc != ASNBER_OK) {
        return rc;
    }

    *out_node = reinterpret_cast<asnber_node_t *>(node);
    return ASNBER_OK;
}

extern "C" asnber_err_t asnber_node_create_any(asnber_doc_t *docHandle,
                                          asnber_node_t *parentHandle,
                                          const uint8_t *tlv, size_t tlv_size,
                                          asnber_node_t **out_node)
{
    if (docHandle == nullptr || out_node == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_node = nullptr;

    asnber::Document *doc = documentOf(docHandle);
    if (doc->magic != asnber::kDocumentMagic) {
        return ASNBER_E_INVALID_ARG;
    }
    if (tlv == nullptr || tlv_size == 0) {
        asnber::contextSetError(doc->ctx, ASNBER_E_INVALID_ARG, 0, 0);
        return ASNBER_E_INVALID_ARG;
    }

    TlvHeader header{};
    size_t errorOffset = 0;
    const asnber_err_t parseRc =
        parseSingleTlv(tlv, tlv_size, &header, &errorOffset);
    if (parseRc != ASNBER_OK) {
        asnber::contextSetError(doc->ctx, parseRc, errorOffset, 0);
        return parseRc;
    }

    asnber::Node *parent = nullptr;
    uint32_t depth = 0;
    if (parentHandle != nullptr) {
        parent = nodeOf(parentHandle);
        if (parent->document != doc) {
            asnber::contextSetError(doc->ctx, ASNBER_E_INVALID_ARG, SIZE_MAX, 0);
            return ASNBER_E_INVALID_ARG;
        }
        depth = parent->depth + 1;
    }

    void *copy = nullptr;
    asnber_err_t rc = asnber::documentAllocate(doc, tlv_size, &copy);
    if (rc != ASNBER_OK) {
        return rc;
    }
    std::memcpy(copy, tlv, tlv_size);
    const uint8_t *raw = static_cast<const uint8_t *>(copy);

    asnber::Node *node = nullptr;
    rc = asnber::documentCreateAnyNode(doc, parent, header.tagClass,
                                     header.tagNumber, header.constructed,
                                     depth, raw, tlv_size,
                                     raw + header.headerSize,
                                     header.contentSize, &node);
    if (rc != ASNBER_OK) {
        return rc;
    }

    *out_node = reinterpret_cast<asnber_node_t *>(node);
    return ASNBER_OK;
}

// ============================================================================
// 内容设置
// ============================================================================

extern "C" asnber_err_t asnber_node_set_content(asnber_node_t *nodeHandle,
                                            const uint8_t *data, size_t size)
{
    if (nodeHandle == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber::Node *node = nodeOf(nodeHandle);
    if (node->document == nullptr ||
        node->document->magic != asnber::kDocumentMagic) {
        return ASNBER_E_INVALID_ARG;
    }
    return asnber::documentSetNodeContent(node->document, node, data, size);
}

extern "C" asnber_err_t asnber_node_set_bool(asnber_node_t *nodeHandle, int value)
{
    if (nodeHandle == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const uint8_t content = value != 0 ? 0xFFu : 0x00u;
    return asnber_node_set_content(nodeHandle, &content, 1);
}

extern "C" asnber_err_t asnber_node_set_int64(asnber_node_t *nodeHandle,
                                          int64_t value)
{
    if (nodeHandle == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }

    uint8_t bytes[8];
    const uint64_t raw = static_cast<uint64_t>(value);
    for (size_t i = 0; i < 8; ++i) {
        bytes[7 - i] = static_cast<uint8_t>((raw >> (8 * i)) & 0xFFu);
    }

    size_t first = 0;
    if (value >= 0) {
        while (first < 7 && bytes[first] == 0x00u &&
               bytes[first + 1] < 0x80u) {
            ++first;
        }
    } else {
        while (first < 7 && bytes[first] == 0xFFu &&
               (bytes[first + 1] & 0x80u) != 0) {
            ++first;
        }
    }

    const size_t size = 8 - first;
    return asnber_node_set_content(nodeHandle, bytes + first, size);
}

extern "C" asnber_err_t asnber_node_set_oid(asnber_node_t *nodeHandle,
                                        const char *dotted)
{
    if (nodeHandle == nullptr || dotted == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber::Node *node = nodeOf(nodeHandle);
    if (node->document == nullptr ||
        node->document->magic != asnber::kDocumentMagic) {
        return ASNBER_E_INVALID_ARG;
    }

    /* 第一遍：校验点分文本并计算编码长度。 */
    size_t cursor = 0;
    uint64_t firstArc = 0;
    uint64_t secondArc = 0;
    if (!parseDecimal(dotted, &cursor, &firstArc) || dotted[cursor] != '.') {
        return ASNBER_E_INVALID_VALUE;
    }
    ++cursor;
    if (!parseDecimal(dotted, &cursor, &secondArc) || firstArc > 2) {
        return ASNBER_E_INVALID_VALUE;
    }
    if (firstArc < 2 && secondArc > 39) {
        return ASNBER_E_INVALID_VALUE;
    }

    if (secondArc > UINT64_MAX - firstArc * 40u) {
        return ASNBER_E_INVALID_VALUE;
    }
    uint64_t combined = firstArc * 40u + secondArc;

    size_t total = subidentifierOctets(combined);
    while (dotted[cursor] == '.') {
        ++cursor;
        uint64_t arc = 0;
        if (!parseDecimal(dotted, &cursor, &arc)) {
            return ASNBER_E_INVALID_VALUE;
        }
        const size_t octets = subidentifierOctets(arc);
        if (total > SIZE_MAX - octets) {
            return ASNBER_E_INVALID_VALUE;
        }
        total += octets;
    }
    if (dotted[cursor] != '\0') {
        return ASNBER_E_INVALID_VALUE;
    }

    /* 第二遍：写入文档 arena。 */
    void *buffer = nullptr;
    const asnber_err_t rc =
        asnber::documentAllocate(node->document, total, &buffer);
    if (rc != ASNBER_OK) {
        return rc;
    }

    uint8_t *encoded = static_cast<uint8_t *>(buffer);
    size_t outCursor = 0;
    encodeSubidentifier(combined, encoded, &outCursor);

    cursor = 0;
    (void)parseDecimal(dotted, &cursor, &firstArc);
    ++cursor;
    (void)parseDecimal(dotted, &cursor, &secondArc);
    while (dotted[cursor] == '.') {
        ++cursor;
        uint64_t arc = 0;
        (void)parseDecimal(dotted, &cursor, &arc);
        encodeSubidentifier(arc, encoded, &outCursor);
    }

    return asnber::documentAttachNodeContent(node->document, node, encoded,
                                           total);
}

extern "C" asnber_err_t asnber_node_set_utf8(asnber_node_t *nodeHandle,
                                         const char *text, size_t size)
{
    if (nodeHandle == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (text == nullptr && size != 0) {
        return ASNBER_E_INVALID_ARG;
    }
    return asnber_node_set_content(nodeHandle,
                                 reinterpret_cast<const uint8_t *>(text),
                                 size);
}
