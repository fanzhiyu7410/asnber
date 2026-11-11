/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 通用 DER 编码器。
 *
 * 职责：遍历已封存文档树，按最小长度、最小标签、SET/SET OF 排序等 DER
 *       规则写出字节；不做 schema 感知语义（DEFAULT 省略）。
 * 依赖：core/asnber_context.h、types/asnber_dom.h。
 * 所有权：临时缓冲为上下文级分配，函数返回前释放；dst 由调用方提供。
 */

#include "asnber_encoder.h"

#include "asnber_tag_codec.h"

namespace asnber {
namespace {

using namespace der_detail;

constexpr uint32_t kUniversalTagSet = 17;

struct ChildRecord {
    size_t offset;
    size_t size;
    uint32_t tagClass;
    uint32_t tagNumber;
};

bool encodedSizeOf(const Node *node, size_t *outSize,
                   asnber_err_t *outError) noexcept;

bool contentSizeOf(const Node *node, size_t *outSize,
                   asnber_err_t *outError) noexcept
{
    if (!nodeIsConstructed(node)) {
        *outSize = node->contentSize;
        return true;
    }
    size_t total = 0;
    for (const Node *child = node->firstChild; child != nullptr;
         child = child->nextSibling) {
        size_t encoded = 0;
        if (!encodedSizeOf(child, &encoded, outError)) {
            return false;
        }
        if (encoded > SIZE_MAX - total) {
            *outError = ASNBER_E_OUTPUT_LIMIT;
            return false;
        }
        total += encoded;
    }
    *outSize = total;
    return true;
}

bool encodedSizeOf(const Node *node, size_t *outSize,
                   asnber_err_t *outError) noexcept
{
    if (nodeIsAny(node)) {
        /* ANY 直接写回保留的原始 TLV，不再加包装层。 */
        if (node->rawTlv == nullptr || node->rawTlvSize < 2) {
            *outError = ASNBER_E_INVALID_STATE;
            return false;
        }
        *outSize = node->rawTlvSize;
        return true;
    }

    size_t contentSize = 0;
    if (!contentSizeOf(node, &contentSize, outError)) {
        return false;
    }
    const size_t headerBytes =
        tagFieldBytes(node->tagNumber) + lengthFieldBytes(contentSize);
    if (contentSize > SIZE_MAX - headerBytes) {
        *outError = ASNBER_E_OUTPUT_LIMIT;
        return false;
    }
    *outSize = headerBytes + contentSize;
    return true;
}

int compareRecords(const ChildRecord &left, const ChildRecord &right,
                   const uint8_t *scratch) noexcept
{
    if (left.tagClass != right.tagClass) {
        return left.tagClass < right.tagClass ? -1 : 1;
    }
    if (left.tagNumber != right.tagNumber) {
        return left.tagNumber < right.tagNumber ? -1 : 1;
    }
    const size_t common =
        left.size < right.size ? left.size : right.size;
    for (size_t i = 0; i < common; ++i) {
        const uint8_t a = scratch[left.offset + i];
        const uint8_t b = scratch[right.offset + i];
        if (a != b) {
            return a < b ? -1 : 1;
        }
    }
    if (left.size != right.size) {
        return left.size < right.size ? -1 : 1;
    }
    return 0;
}

asnber_err_t encodeNode(Context *ctx, const Node *node, uint8_t *dst,
                      size_t *cursor) noexcept;

asnber_err_t encodeSortedConstructed(Context *ctx, const Node *node,
                                   uint8_t *dst, size_t contentSize,
                                   size_t *cursor) noexcept
{
    const size_t count = nodeChildCount(node);
    if (count == 0) {
        return ASNBER_OK;
    }

    void *scratchRaw = nullptr;
    void *recordsRaw = nullptr;
    const asnber_err_t scratchRc = contextAllocate(
        ctx, contentSize == 0 ? 1 : contentSize, AllocationKind::kGeneric,
        &scratchRaw);
    if (scratchRc != ASNBER_OK) {
        return scratchRc;
    }
    const asnber_err_t recordsRc = contextAllocate(
        ctx, count * sizeof(ChildRecord), AllocationKind::kGeneric,
        &recordsRaw);
    if (recordsRc != ASNBER_OK) {
        contextRelease(ctx, scratchRaw);
        return recordsRc;
    }

    uint8_t *scratch = static_cast<uint8_t *>(scratchRaw);
    ChildRecord *records = static_cast<ChildRecord *>(recordsRaw);

    size_t scratchCursor = 0;
    size_t index = 0;
    asnber_err_t rc = ASNBER_OK;
    for (const Node *child = node->firstChild; child != nullptr;
         child = child->nextSibling) {
        if (index >= count) {
            rc = ASNBER_E_INTERNAL;
            break;
        }
        const size_t before = scratchCursor;
        rc = encodeNode(ctx, child, scratch, &scratchCursor);
        if (rc != ASNBER_OK) {
            break;
        }
        records[index].offset = before;
        records[index].size = scratchCursor - before;
        records[index].tagClass = child->tagClass;
        records[index].tagNumber = child->tagNumber;
        ++index;
    }
    if (rc != ASNBER_OK) {
        contextRelease(ctx, recordsRaw);
        contextRelease(ctx, scratchRaw);
        return rc;
    }

    /* 插入排序：数量为字段/元素数，规模小且不在热路径。 */
    for (size_t i = 1; i < index; ++i) {
        ChildRecord current = records[i];
        size_t j = i;
        while (j > 0 && compareRecords(records[j - 1], current, scratch) > 0) {
            records[j] = records[j - 1];
            --j;
        }
        records[j] = current;
    }

    size_t out = *cursor;
    for (size_t i = 0; i < index; ++i) {
        for (size_t k = 0; k < records[i].size; ++k) {
            dst[out + k] = scratch[records[i].offset + k];
        }
        out += records[i].size;
    }
    *cursor = out;

    contextRelease(ctx, recordsRaw);
    contextRelease(ctx, scratchRaw);
    return ASNBER_OK;
}

asnber_err_t encodeNode(Context *ctx, const Node *node, uint8_t *dst,
                      size_t *cursor) noexcept
{
    if (nodeIsAny(node)) {
        /* ANY 原样写回保留的 TLV；节点被改写导致缺 TLV 视为无效状态。 */
        if (node->rawTlv == nullptr || node->rawTlvSize < 2) {
            contextSetError(ctx, ASNBER_E_INVALID_STATE, SIZE_MAX, 0);
            return ASNBER_E_INVALID_STATE;
        }
        for (size_t i = 0; i < node->rawTlvSize; ++i) {
            dst[*cursor + i] = node->rawTlv[i];
        }
        *cursor += node->rawTlvSize;
        return ASNBER_OK;
    }

    size_t contentSize = 0;
    asnber_err_t rc = ASNBER_OK;
    if (!contentSizeOf(node, &contentSize, &rc)) {
        if (rc == ASNBER_OK) {
            rc = ASNBER_E_INTERNAL;
        }
        contextSetError(ctx, rc, SIZE_MAX, 0);
        return rc;
    }

    const bool constructed = nodeIsConstructed(node);
    const size_t tagBytes = tagFieldBytes(node->tagNumber);
    writeTag(dst + *cursor, node->tagClass, node->tagNumber, constructed);
    writeLength(dst + *cursor + tagBytes, contentSize);
    *cursor += tagBytes + lengthFieldBytes(contentSize);

    if (!constructed) {
        if (contentSize != 0) {
            for (size_t i = 0; i < contentSize; ++i) {
                dst[*cursor + i] = node->content[i];
            }
            *cursor += contentSize;
        }
        return ASNBER_OK;
    }

    if (node->tagClass == ASNBER_TAG_UNIVERSAL &&
        node->tagNumber == kUniversalTagSet) {
        return encodeSortedConstructed(ctx, node, dst, contentSize, cursor);
    }

    for (const Node *child = node->firstChild; child != nullptr;
         child = child->nextSibling) {
        rc = encodeNode(ctx, child, dst, cursor);
        if (rc != ASNBER_OK) {
            return rc;
        }
    }
    return ASNBER_OK;
}

} /* namespace */

asnber_err_t derMeasureDocument(Context *ctx, const Document *doc,
                              size_t *outSize) noexcept
{
    if (doc == nullptr || doc->root == nullptr) {
        contextSetError(ctx, ASNBER_E_INVALID_STATE, SIZE_MAX, 0);
        return ASNBER_E_INVALID_STATE;
    }
    size_t encodedSize = 0;
    asnber_err_t rc = ASNBER_OK;
    if (!encodedSizeOf(doc->root, &encodedSize, &rc)) {
        if (rc == ASNBER_OK) {
            rc = ASNBER_E_INTERNAL;
        }
        contextSetError(ctx, rc, SIZE_MAX, 0);
        return rc;
    }
    *outSize = encodedSize;
    return ASNBER_OK;
}

asnber_err_t derEncodeDocument(Context *ctx, const Document *doc, uint8_t *dst,
                             size_t size) noexcept
{
    size_t cursor = 0;
    const asnber_err_t rc = encodeNode(ctx, doc->root, dst, &cursor);
    if (rc == ASNBER_OK && cursor != size) {
        contextSetError(ctx, ASNBER_E_INTERNAL, SIZE_MAX, 0);
        return ASNBER_E_INTERNAL;
    }
    return rc;
}

} /* namespace asnber */
