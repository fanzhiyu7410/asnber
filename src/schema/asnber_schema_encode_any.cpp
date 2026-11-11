/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * schema 感知编码的 ANY 与保留 TLV 处理：原始 TLV 切片、ANY 尺寸、
 * 保留字节的规范 DER 校验与写出。
 */

#include "schema/detail/schema_encode_internal.h"

#include <cstring>

namespace asnber {
namespace schema_encode_detail {

bool rawTlvOf(const Document *doc, const Node *node, const uint8_t **outData,
              size_t *outSize)
{
    if (node->tlvOffset == SIZE_MAX || node->tlvOffset >= doc->inputSize ||
        node->tlvSize > doc->inputSize - node->tlvOffset) {
        return false;
    }
    *outData = doc->input + node->tlvOffset;
    *outSize = node->tlvSize;
    return true;
}

/*
 * 取节点的完整原始 TLV：ANY 节点用自身保留的字节（解码与 runtime 构树
 * 皆然），其余节点沿用文档输入切片。
 */
bool rawTlvOfNode(const Document *doc, const Node *node,
                  const uint8_t **outData, size_t *outSize)
{
    if (nodeIsAny(node) && node->rawTlv != nullptr && node->rawTlvSize != 0) {
        *outData = node->rawTlv;
        *outSize = node->rawTlvSize;
        return true;
    }
    return rawTlvOf(doc, node, outData, outSize);
}

bool sizeAny(const EncState &st, const SchemaType *type, const Node *node,
             size_t *outSize, asnber_err_t *outError)
{
    /* DEFAULT ANY 的节点就是原始 TLV；EXPLICIT ANY 的节点是外层包装，
       内层 TLV 保存在 content 中。 */
    if (!nodeIsAny(node)) {
        const uint8_t *raw = nullptr;
        size_t rawSize = 0;
        if (!rawTlvOfNode(st.doc, node, &raw, &rawSize)) {
            *outError = ASNBER_E_INVALID_STATE;
            return false;
        }
        if (!validateRetainedDer(st.ctx, raw, rawSize, outError)) {
            if (*outError == ASNBER_E_NON_CANONICAL) {
                noteEncodePath(st, type->name, nullptr);
            }
            return false;
        }
        if (effectiveTagMode(st.schema, type) == ASNBER_TAG_MODE_EXPLICIT) {
            const size_t header = tagFieldBytes(type->tagNumber) +
                                  lengthFieldBytes(rawSize);
            *outSize = header + rawSize;
        } else {
            *outSize = rawSize;
        }
        return true;
    }

    const size_t inner = node->contentSize;
    if (effectiveTagMode(st.schema, type) == ASNBER_TAG_MODE_EXPLICIT) {
        if (!validateRetainedDer(st.ctx, node->content, inner, outError)) {
            if (*outError == ASNBER_E_NON_CANONICAL) {
                noteEncodePath(st, type->name, nullptr);
            }
            return false;
        }
        const size_t header =
            tagFieldBytes(type->tagNumber) + lengthFieldBytes(inner);
        *outSize = header + inner;
    } else {
        const uint8_t *raw = nullptr;
        size_t rawSize = 0;
        if (!rawTlvOfNode(st.doc, node, &raw, &rawSize)) {
            *outError = ASNBER_E_INVALID_STATE;
            return false;
        }
        if (!validateRetainedDer(st.ctx, raw, rawSize, outError)) {
            if (*outError == ASNBER_E_NON_CANONICAL) {
                noteEncodePath(st, type->name, nullptr);
            }
            return false;
        }
        *outSize = rawSize;
    }
    return true;
}

/*
 * 保留的原始 TLV（ANY 内层、未知字段）在 schema 感知 DER 编码中必须是
 * 规范 DER。复用解码器的 DER 严格校验，不做隐式重新编码。
 */
bool validateRetainedDer(Context *ctx, const uint8_t *tlv, size_t size,
                         asnber_err_t *outError)
{
    if (tlv == nullptr || size == 0) {
        *outError = ASNBER_E_INVALID_STATE;
        return false;
    }
    Document *tmp = nullptr;
    size_t used = 0;
    const asnber_err_t rc =
        decodeBuffer(ctx, tlv, size, ctx->m_maxDepth, false, false,
                     ASNBER_ENCODING_DER, &tmp, &used);
    if (rc == ASNBER_OK) {
        documentDestroy(tmp);
        return true;
    }
    if (rc == ASNBER_E_NOMEM || rc == ASNBER_E_MEMORY_LIMIT ||
        rc == ASNBER_E_STATIC_POOL_EXHAUSTED || rc == ASNBER_E_DEPTH_LIMIT ||
        rc == ASNBER_E_NODE_LIMIT || rc == ASNBER_E_INPUT_LIMIT) {
        /* 资源/预算类失败不是数据非规范：透传原错误码，避免误导排查。 */
        *outError = rc;
        return false;
    }
    *outError = ASNBER_E_NON_CANONICAL;
    return false;
}

bool writeAny(const EncState &st, const SchemaType *type, const Node *node,
              uint8_t *dst, size_t capacity, size_t *outUsed,
              asnber_err_t *outError)
{
    const bool explicitMode =
        effectiveTagMode(st.schema, type) == ASNBER_TAG_MODE_EXPLICIT;
    const uint8_t *raw = nullptr;
    size_t rawSize = 0;
    if (!rawTlvOfNode(st.doc, node, &raw, &rawSize)) {
        *outError = ASNBER_E_INVALID_STATE;
        return false;
    }

    if (explicitMode) {
        /* 内层原始 TLV 由 content 承载；按 schema 重新加外层包装。 */
        const uint8_t *inner = nodeIsAny(node) ? node->content : raw;
        const size_t innerSize = nodeIsAny(node) ? node->contentSize : rawSize;
        return writeTaggedContent(st, type->tagClass, type->tagNumber, true,
                                  inner, innerSize, dst, capacity, outUsed,
                                  outError);
    }
    if (rawSize > capacity) {
        *outError = ASNBER_E_OUTPUT_LIMIT;
        return false;
    }
    std::memcpy(dst, raw, rawSize);
    *outUsed = rawSize;
    return true;
}

} /* namespace schema_encode_detail */
} /* namespace asnber */
