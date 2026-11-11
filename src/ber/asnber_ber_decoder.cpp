/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * BER 解码实现：标签、确定长度、构造/基本形态与完整嵌套。
 *
 * encoding == DER 时额外做严格规范化校验（最短长度、最短标签、BOOLEAN/
 * INTEGER/BIT STRING/OID/时间、字符串禁止构造形态、SET/SET OF 排序），
 * 违反返回 ASNBER_E_NON_CANONICAL；encoding == BER 时不做这些校验。
 * 不定长与 EOC 在两种模式下均拒绝。
 */

// ============================================================================
// 依赖与前置声明
// ============================================================================

#include "ber/asnber_ber_decoder.h"

#include "types/asnber_dom.h"

#include <cstring>

namespace asnber {

namespace {

/* 解析状态，避免在递归中重复传参。 */
struct ParseState {
    Document *doc;
    const uint8_t *input;
    size_t inputSize;
    uint32_t maxDepth;
    uint32_t depthLimit; /* 实际生效的深度上限 */
    bool der;            /* true 表示 DER 严格校验 */
};

/* 记录错误并返回错误码，便于单行传播。 */
asnber_err_t fail(ParseState &state, asnber_err_t code, size_t offset,
                uint32_t depth) noexcept
{
    contextSetError(state.doc->ctx, code, offset, depth);
    return code;
}

/*
 * limit 小于完整输入时，越界意味着父容器声明长度不足（LENGTH_MISMATCH）；
 * limit 等于输入末尾时，越界意味着输入被截断（TRUNCATED）。
 */
asnber_err_t limitFailure(ParseState &state, size_t limit, size_t offset,
                        uint32_t depth) noexcept
{
    if (limit >= state.inputSize) {
        return fail(state, ASNBER_E_TRUNCATED, offset, depth);
    }
    return fail(state, ASNBER_E_LENGTH_MISMATCH, offset, depth);
}

/*
 * 解析一个 TLV。pos 必须小于 limit；返回时 *outEnd 为该 TLV 结束位置。
 * limit 是父容器内容结束位置（顶层为 inputSize）。
 */
asnber_err_t parseElement(ParseState &state, size_t pos, size_t limit,
                        uint32_t depth, Node *parent, size_t *outEnd) noexcept;

/* 通用标签中 DER 禁止构造形态的类型（字符串、OID、BIT STRING 等）。 */
bool derForbidsConstructed(uint32_t tagClass, uint32_t tagNumber) noexcept
{
    if (tagClass != ASNBER_TAG_UNIVERSAL) {
        return false;
    }
    switch (tagNumber) {
    case 1:  /* BOOLEAN */
    case 2:  /* INTEGER */
    case 3:  /* BIT STRING */
    case 4:  /* OCTET STRING */
    case 6:  /* OBJECT IDENTIFIER */
    case 10: /* ENUMERATED */
    case 12: /* UTF8String */
    case 18: /* NumericString */
    case 19: /* PrintableString */
    case 20: /* TeletexString */
    case 21: /* VideotexString */
    case 22: /* IA5String */
    case 23: /* UTCTime */
    case 24: /* GeneralizedTime */
    case 25: /* GraphicString */
    case 26: /* VisibleString */
    case 27: /* GeneralString */
    case 28: /* UniversalString */
    case 30: /* BMPString */
        return true;
    default:
        return false;
    }
}

bool allDigits(const uint8_t *data, size_t size) noexcept
{
    for (size_t i = 0; i < size; ++i) {
        if (data[i] < '0' || data[i] > '9') {
            return false;
        }
    }
    return true;
}

bool validDerUtcTime(const uint8_t *data, size_t size) noexcept
{
    if (size != 13 || data[12] != 'Z') {
        return false;
    }
    if (!allDigits(data, 12)) {
        return false;
    }
    const int month = (data[2] - '0') * 10 + (data[3] - '0');
    const int day = (data[4] - '0') * 10 + (data[5] - '0');
    const int hour = (data[6] - '0') * 10 + (data[7] - '0');
    const int minute = (data[8] - '0') * 10 + (data[9] - '0');
    const int second = (data[10] - '0') * 10 + (data[11] - '0');
    return month >= 1 && month <= 12 && day >= 1 && day <= 31 &&
           hour <= 23 && minute <= 59 && second <= 59;
}

bool validDerGeneralizedTime(const uint8_t *data, size_t size) noexcept
{
    if (size < 15) {
        return false;
    }
    if (!allDigits(data, 14)) {
        return false;
    }
    const int month = (data[4] - '0') * 10 + (data[5] - '0');
    const int day = (data[6] - '0') * 10 + (data[7] - '0');
    const int hour = (data[8] - '0') * 10 + (data[9] - '0');
    const int minute = (data[10] - '0') * 10 + (data[11] - '0');
    const int second = (data[12] - '0') * 10 + (data[13] - '0');
    if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 ||
        minute > 59 || second > 59) {
        return false;
    }

    size_t pos = 14;
    if (pos < size && data[pos] == '.') {
        ++pos;
        const size_t fractionStart = pos;
        while (pos < size && data[pos] >= '0' && data[pos] <= '9') {
            ++pos;
        }
        if (pos == fractionStart) {
            return false;
        }
        /* DER 要求小数部分删除全部尾随零。 */
        if (data[pos - 1] == '0') {
            return false;
        }
    }
    return pos + 1 == size && data[pos] == 'Z';
}

bool validDerOid(const uint8_t *data, size_t size) noexcept
{
    if (size == 0) {
        return false;
    }
    bool atSubidentifierStart = true;
    for (size_t i = 0; i < size; ++i) {
        const uint8_t byte = data[i];
        if (atSubidentifierStart && byte == 0x80u) {
            return false; /* 非最短 base128 */
        }
        atSubidentifierStart = (byte & 0x80u) == 0;
    }
    return atSubidentifierStart; /* 最后一段必须正常终结 */
}

/*
 * DER 基本类型内容校验。返回 ASNBER_OK 表示合法；否则返回错误码（已记录）。
 * 仅处理 UNIVERSAL 标签；其他标签类别内容不受通用规则约束。
 */
asnber_err_t validateDerPrimitive(ParseState &state, uint32_t tagClass,
                                uint32_t tagNumber, size_t contentStart,
                                size_t contentSize, size_t pos,
                                uint32_t depth) noexcept
{
    if (tagClass != ASNBER_TAG_UNIVERSAL) {
        return ASNBER_OK;
    }
    const uint8_t *content = state.input + contentStart;

    switch (tagNumber) {
    case 1: /* BOOLEAN */
        if (contentSize != 1 || (content[0] != 0x00u && content[0] != 0xFFu)) {
            return fail(state, ASNBER_E_NON_CANONICAL, pos, depth);
        }
        break;
    case 2:  /* INTEGER */
    case 10: /* ENUMERATED */
        if (contentSize == 0) {
            return fail(state, ASNBER_E_MALFORMED_VALUE, contentStart, depth);
        }
        if (contentSize >= 2 &&
            ((content[0] == 0x00u && content[1] < 0x80u) ||
             (content[0] == 0xFFu && content[1] >= 0x80u))) {
            return fail(state, ASNBER_E_NON_CANONICAL, contentStart, depth);
        }
        break;
    case 3: /* BIT STRING */
        if (contentSize == 0) {
            return fail(state, ASNBER_E_NON_CANONICAL, contentStart, depth);
        }
        {
            const uint8_t unused = content[0];
            if (unused > 7u || (contentSize == 1 && unused != 0)) {
                return fail(state, ASNBER_E_NON_CANONICAL, contentStart, depth);
            }
        }
        break;
    case 6: /* OBJECT IDENTIFIER */
        if (!validDerOid(content, contentSize)) {
            return fail(state, ASNBER_E_NON_CANONICAL, contentStart, depth);
        }
        break;
    case 16: /* SEQUENCE */
    case 17: /* SET / SET OF */
        return fail(state, ASNBER_E_NON_CANONICAL, pos, depth);
    case 23: /* UTCTime */
        if (!validDerUtcTime(content, contentSize)) {
            return fail(state, ASNBER_E_NON_CANONICAL, contentStart, depth);
        }
        break;
    case 24: /* GeneralizedTime */
        if (!validDerGeneralizedTime(content, contentSize)) {
            return fail(state, ASNBER_E_NON_CANONICAL, contentStart, depth);
        }
        break;
    default:
        break;
    }
    return ASNBER_OK;
}

/* SET/SET OF 子元素 DER 顺序：先按标签升序，同标签再按编码字节字典序。 */
asnber_err_t validateDerSetOrder(ParseState &state, const Node *node,
                               uint32_t depth) noexcept
{
    const Node *previous = node->firstChild;
    if (previous == nullptr) {
        return ASNBER_OK;
    }
    for (const Node *current = previous->nextSibling; current != nullptr;
         current = current->nextSibling) {
        int order = 0;
        if (previous->tagClass != current->tagClass) {
            order = previous->tagClass < current->tagClass ? -1 : 1;
        } else if (previous->tagNumber != current->tagNumber) {
            order = previous->tagNumber < current->tagNumber ? -1 : 1;
        } else {
            const uint8_t *left = state.input + previous->tlvOffset;
            const uint8_t *right = state.input + current->tlvOffset;
            const size_t common = previous->tlvSize < current->tlvSize
                                      ? previous->tlvSize
                                      : current->tlvSize;
            for (size_t i = 0; i < common; ++i) {
                if (left[i] != right[i]) {
                    order = left[i] < right[i] ? -1 : 1;
                    break;
                }
            }
            if (order == 0 && previous->tlvSize != current->tlvSize) {
                order = previous->tlvSize < current->tlvSize ? -1 : 1;
            }
        }
        if (order > 0) {
            return fail(state, ASNBER_E_NON_CANONICAL, current->tlvOffset, depth);
        }
        previous = current;
    }
    return ASNBER_OK;
}


asnber_err_t parseChildren(ParseState &state, Node *node, size_t contentStart,
                         size_t contentEnd, uint32_t depth) noexcept
{
    size_t cursor = contentStart;
    while (cursor < contentEnd) {
        size_t childEnd = cursor;
        asnber_err_t rc = parseElement(state, cursor, contentEnd, depth, node,
                                     &childEnd);
        if (rc != ASNBER_OK) {
            return rc;
        }
        if (childEnd <= cursor) {
            /* 防御性检查：解析器不得原地踏步。 */
            return fail(state, ASNBER_E_INTERNAL, cursor, depth);
        }
        cursor = childEnd;
    }
    if (cursor != contentEnd) {
        return fail(state, ASNBER_E_LENGTH_MISMATCH, contentEnd, depth);
    }
    return ASNBER_OK;
}

/*
 * 解析不定长构造内容的子元素，直到匹配的 EOC（00 00）。
 * 成功时 *outEnd 为 EOC 之后的位置；找不到 EOC 时按边界返回 TRUNCATED
 * 或 LENGTH_MISMATCH。
 */
asnber_err_t parseChildrenUntilEoc(ParseState &state, Node *node,
                                 size_t cursor, size_t limit, uint32_t depth,
                                 size_t *outEnd) noexcept
{
    while (true) {
        if (cursor >= limit) {
            return limitFailure(state, limit, cursor, depth);
        }
        if (state.input[cursor] == 0x00u) {
            if (cursor + 1 >= limit) {
                return limitFailure(state, limit, cursor, depth);
            }
            if (state.input[cursor + 1] != 0x00u) {
                /* UNIVERSAL 0 只能是 EOC，长度必须为 0。 */
                return fail(state, ASNBER_E_MALFORMED_TAG, cursor, depth);
            }
            *outEnd = cursor + 2;
            return ASNBER_OK;
        }
        size_t childEnd = cursor;
        asnber_err_t rc =
            parseElement(state, cursor, limit, depth, node, &childEnd);
        if (rc != ASNBER_OK) {
            return rc;
        }
        if (childEnd <= cursor) {
            return fail(state, ASNBER_E_INTERNAL, cursor, depth);
        }
        cursor = childEnd;
    }
}

asnber_err_t parseElement(ParseState &state, size_t pos, size_t limit,
                        uint32_t depth, Node *parent, size_t *outEnd) noexcept
{
    if (depth > state.depthLimit) {
        return fail(state, ASNBER_E_DEPTH_LIMIT, pos, depth);
    }

    /* --- 标签字节 --- */
    if (pos >= limit) {
        return limitFailure(state, limit, pos, depth);
    }
    const uint8_t tagByte = state.input[pos];
    const uint32_t tagClass = (tagByte >> 6) & 0x3u;
    const bool constructed = (tagByte & 0x20u) != 0;
    uint32_t tagNumber = tagByte & 0x1Fu;
    size_t cursor = pos + 1;

    if (tagNumber == 0x1Fu) {
        bool firstSubOctet = true;
        uint32_t value = 0;
        while (true) {
            if (cursor >= limit) {
                return limitFailure(state, limit, cursor, depth);
            }
            const uint8_t octet = state.input[cursor];
            ++cursor;
            if (state.der && firstSubOctet && octet == 0x80u) {
                return fail(state, ASNBER_E_NON_CANONICAL, cursor - 1, depth);
            }
            if (value > (UINT32_MAX - (octet & 0x7Fu)) / 128u) {
                return fail(state, ASNBER_E_MALFORMED_TAG, cursor - 1, depth);
            }
            value = value * 128u + (octet & 0x7Fu);
            firstSubOctet = false;
            if ((octet & 0x80u) == 0) {
                break;
            }
        }
        if (state.der && value < 0x1Fu) {
            /* 小于 31 的 tag number 必须用单字节形式。 */
            return fail(state, ASNBER_E_NON_CANONICAL, pos, depth);
        }
        tagNumber = value;
    }
    if (tagClass == ASNBER_TAG_UNIVERSAL && tagNumber == 0) {
        /* 顶层裸 EOC 始终非法；DER 在构造内容中出现 EOC 按 3005 拒绝。 */
        if (state.der && parent != nullptr) {
            return fail(state, ASNBER_E_INDEFINITE_NOT_ALLOWED, pos, depth);
        }
        return fail(state, ASNBER_E_MALFORMED_TAG, pos, depth);
    }

    /* --- 长度 --- */
    if (cursor >= limit) {
        return limitFailure(state, limit, cursor, depth);
    }
    const uint8_t firstLength = state.input[cursor];
    size_t contentSize = 0;
    bool indefinite = false;
    if (firstLength < 0x80u) {
        contentSize = firstLength;
        cursor += 1;
    } else if (firstLength == 0x80u) {
        if (state.der) {
            return fail(state, ASNBER_E_INDEFINITE_NOT_ALLOWED, cursor, depth);
        }
        if (!constructed) {
            /* 不定长只能用于构造型编码。 */
            return fail(state, ASNBER_E_MALFORMED_LENGTH, cursor, depth);
        }
        indefinite = true;
        cursor += 1;
    } else {
        const size_t octets = static_cast<size_t>(firstLength & 0x7Fu);
        if (octets > sizeof(size_t)) {
            return fail(state, ASNBER_E_MALFORMED_LENGTH, cursor, depth);
        }
        cursor += 1;
        if (octets > limit - cursor) {
            return limitFailure(state, limit, cursor, depth);
        }
        if (state.der && octets > 1 && state.input[cursor] == 0) {
            return fail(state, ASNBER_E_NON_CANONICAL, cursor, depth);
        }
        for (size_t i = 0; i < octets; ++i) {
            const uint8_t octet = state.input[cursor + i];
            if (contentSize > (SIZE_MAX - octet) / 256u) {
                return fail(state, ASNBER_E_MALFORMED_LENGTH, cursor + i, depth);
            }
            contentSize = contentSize * 256u + octet;
        }
        cursor += octets;
        if (state.der && contentSize < 0x80u) {
            /* 能用一个字节表示的长度必须用短形式。 */
            return fail(state, ASNBER_E_NON_CANONICAL, cursor - octets - 1,
                        depth);
        }
    }

    const size_t contentStart = cursor;
    size_t contentEnd = contentStart;
    if (!indefinite) {
        if (contentSize > state.inputSize - contentStart) {
            /* 内容越过输入末尾。 */
            return fail(state, ASNBER_E_TRUNCATED, state.inputSize, depth);
        }
        contentEnd = contentStart + contentSize;
        if (contentEnd > limit) {
            return limitFailure(state, limit, contentStart, depth);
        }
    }

    const size_t tlvOffset = pos;
    /* 不定长的完整长度（含 EOC）在子元素解析完成后回填。 */
    const size_t tlvSize = indefinite ? 0 : contentEnd - pos;

    Node *node = nullptr;
    asnber_err_t rc = documentCreateNode(
        state.doc, parent, tagClass, tagNumber, constructed, depth, tlvOffset,
        tlvSize, constructed ? nullptr : state.input + contentStart,
        constructed ? 0 : contentSize, &node);
    if (rc != ASNBER_OK) {
        return rc;
    }
    node->flags |= kNodeFlagDecoded;

    if (state.der) {
        if (constructed) {
            if (derForbidsConstructed(tagClass, tagNumber)) {
                return fail(state, ASNBER_E_NON_CANONICAL, pos, depth);
            }
        } else {
            rc = validateDerPrimitive(state, tagClass, tagNumber, contentStart,
                                      contentSize, pos, depth);
            if (rc != ASNBER_OK) {
                return rc;
            }
        }
    }

    if (indefinite) {
        size_t endAfterEoc = contentStart;
        rc = parseChildrenUntilEoc(state, node, contentStart, limit, depth + 1,
                                   &endAfterEoc);
        if (rc != ASNBER_OK) {
            return rc;
        }
        node->tlvSize = endAfterEoc - pos;
        node->flags |= kNodeFlagIndefinite;
        *outEnd = endAfterEoc;
        return ASNBER_OK;
    }

    if (constructed) {
        rc = parseChildren(state, node, contentStart, contentEnd, depth + 1);
        if (rc != ASNBER_OK) {
            return rc;
        }
        if (state.der && tagClass == ASNBER_TAG_UNIVERSAL && tagNumber == 17) {
            rc = validateDerSetOrder(state, node, depth);
            if (rc != ASNBER_OK) {
                return rc;
            }
        }
    }

    *outEnd = contentEnd;
    return ASNBER_OK;
}

} /* namespace */

// ============================================================================
// 类型定义
// ============================================================================

// ParseState 定义于上方匿名命名空间。

// ============================================================================
// 静态常量 / 内部辅助类型
// ============================================================================

// 无文件级常量。

// ============================================================================
// 构造与析构
// ============================================================================

// 解码器无独立生命周期对象。

// ============================================================================
// 公共接口
// ============================================================================

asnber_err_t decodeBuffer(Context *ctx, const uint8_t *data, size_t size,
                        uint32_t maxDepth, bool copyInput, bool allowTrailing,
                        asnber_encoding_t encoding, Document **outDoc,
                        size_t *consumed) noexcept
{
    if (outDoc == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *outDoc = nullptr;

    if (ctx == nullptr || ctx->m_magic != kContextMagic || ctx->m_dead) {
        return ASNBER_E_INVALID_ARG;
    }
    if (data == nullptr && size != 0) {
        contextSetError(ctx, ASNBER_E_INVALID_ARG, SIZE_MAX, 0);
        return ASNBER_E_INVALID_ARG;
    }
    if (static_cast<uint64_t>(size) > ctx->m_maxInputBytes) {
        contextSetError(ctx, ASNBER_E_INPUT_LIMIT, SIZE_MAX, 0);
        return ASNBER_E_INPUT_LIMIT;
    }

    Document *doc = nullptr;
    asnber_err_t rc = documentCreate(ctx, &doc);
    if (rc != ASNBER_OK) {
        return rc;
    }

    const uint8_t *input = data;
    bool ownsInput = false;
    if (copyInput && size != 0) {
        void *copy = nullptr;
        rc = documentAllocate(doc, size, &copy);
        if (rc != ASNBER_OK) {
            documentDestroy(doc);
            return rc;
        }
        std::memcpy(copy, data, size);
        input = static_cast<const uint8_t *>(copy);
        ownsInput = true;
    }

    doc->input = input;
    doc->inputSize = size;
    doc->ownsInput = ownsInput;
    doc->encoding = encoding;

    if (size == 0) {
        contextSetError(ctx, ASNBER_E_TRUNCATED, 0, 0);
        documentDestroy(doc);
        return ASNBER_E_TRUNCATED;
    }

    ParseState state{doc, input, size, maxDepth, maxDepth,
                     encoding == ASNBER_ENCODING_DER};
    size_t rootEnd = 0;
    rc = parseElement(state, 0, size, 0, nullptr, &rootEnd);
    if (rc != ASNBER_OK) {
        documentDestroy(doc);
        return rc;
    }

    if (rootEnd < size && !allowTrailing) {
        contextSetError(ctx, ASNBER_E_TRAILING_DATA, rootEnd, 0);
        documentDestroy(doc);
        return ASNBER_E_TRAILING_DATA;
    }

    rc = documentSeal(doc);
    if (rc != ASNBER_OK) {
        documentDestroy(doc);
        return rc;
    }
    doc->sealed = true;
    doc->fromDecode = true;

    if (consumed != nullptr) {
        *consumed = rootEnd;
    }
    *outDoc = doc;
    return ASNBER_OK;
}

asnber_err_t readReaderInput(Context *ctx, const asnber_reader_t *reader,
                           uint8_t **outBuffer, size_t *outUsed) noexcept
{
    if (outBuffer == nullptr || outUsed == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *outBuffer = nullptr;
    *outUsed = 0;
    if (ctx == nullptr || ctx->m_magic != kContextMagic || ctx->m_dead ||
        reader == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (reader->struct_size != sizeof(asnber_reader_t) || reader->read == nullptr) {
        contextSetError(ctx, ASNBER_E_INVALID_CONFIG, SIZE_MAX, 0);
        return ASNBER_E_INVALID_CONFIG;
    }

    const size_t initialCapacity = 4096;
    void *raw = nullptr;
    asnber_err_t rc = contextAllocate(ctx, initialCapacity,
                                    AllocationKind::kGeneric, &raw);
    if (rc != ASNBER_OK) {
        return rc;
    }
    uint8_t *buffer = static_cast<uint8_t *>(raw);
    size_t capacity = initialCapacity;
    size_t used = 0;

    while (true) {
        size_t got = 0;
        rc = reader->read(reader->user, buffer + used, capacity - used, &got);
        if (rc != ASNBER_OK) {
            /* IO 回调失败按契约包装，原始码只进 callback_code。 */
            contextSetIoError(ctx, ASNBER_E_IO_READ,
                              static_cast<int32_t>(rc), used, 0);
            contextRelease(ctx, buffer);
            return ASNBER_E_IO_READ;
        }
        if (got > capacity - used) {
            contextSetError(ctx, ASNBER_E_INVALID_CONFIG, used, 0);
            contextRelease(ctx, buffer);
            return ASNBER_E_INVALID_CONFIG;
        }
        used += got;
        if (got == 0) {
            break;
        }
        if (static_cast<uint64_t>(used) > ctx->m_maxInputBytes) {
            contextSetError(ctx, ASNBER_E_INPUT_LIMIT, used, 0);
            contextRelease(ctx, buffer);
            return ASNBER_E_INPUT_LIMIT;
        }
        if (used == capacity) {
            const size_t next =
                capacity > SIZE_MAX / 2 ? SIZE_MAX : capacity * 2;
            if (next == capacity) {
                contextSetError(ctx, ASNBER_E_INPUT_LIMIT, used, 0);
                contextRelease(ctx, buffer);
                return ASNBER_E_INPUT_LIMIT;
            }
            void *grown = nullptr;
            rc = contextAllocate(ctx, next, AllocationKind::kGeneric, &grown);
            if (rc != ASNBER_OK) {
                contextRelease(ctx, buffer);
                return rc;
            }
            std::memcpy(grown, buffer, used);
            contextRelease(ctx, buffer);
            buffer = static_cast<uint8_t *>(grown);
            capacity = next;
        }
    }

    *outBuffer = buffer;
    *outUsed = used;
    return ASNBER_OK;
}

} /* namespace asnber */
