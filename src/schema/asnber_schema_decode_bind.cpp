/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * schema 感知解码：字段绑定。
 *
 * 职责：按 SEQUENCE/SET/CHOICE/SEQUENCE_OF/SET_OF/ANY 规则把 DOM 节点
 *       绑定到 schema 类型与字段，复制字段名进文档 arena，按选项处理
 *       未知字段；不修改节点时供文档校验复用。
 * 依赖：core/asnber_context.h、schema/asnber_schema.h、types/asnber_dom.h。
 */

#include <asnber/asnber.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>

#include "schema/detail/schema_decode_internal.h"

namespace asnber {
namespace schema_decode_detail {

namespace {

constexpr size_t kPathBytes = 256;

/* 从完整 TLV 计算内容切片；不定长去掉结尾 EOC。 */
bool contentSlice(const uint8_t *tlv, size_t size, const uint8_t **outData,
                  size_t *outSize)
{
    if (tlv == nullptr || size < 2) {
        return false;
    }
    size_t offset = 1;
    if ((tlv[0] & 0x1F) == 0x1F) {
        while (offset < size) {
            const uint8_t byte = tlv[offset++];
            if ((byte & 0x80) == 0) {
                break;
            }
        }
    }
    if (offset >= size) {
        return false;
    }
    const uint8_t lengthByte = tlv[offset++];
    if (lengthByte == 0x80) {
        if (size < offset + 2) {
            return false;
        }
        *outData = tlv + offset;
        *outSize = size - offset - 2;
        return true;
    }
    size_t length = 0;
    if ((lengthByte & 0x80) == 0) {
        length = lengthByte;
    } else {
        const size_t count = lengthByte & 0x7F;
        if (count == 0 || count > 8 || offset + count > size) {
            return false;
        }
        for (size_t i = 0; i < count; ++i) {
            length = (length << 8) | tlv[offset + i];
        }
        offset += count;
    }
    if (length > size - offset) {
        return false;
    }
    *outData = tlv + offset;
    *outSize = length;
    return true;
}

int unknownChild(BindContext &bind, const asnber::Node *child, const char *path)
{
    if (bind.strict) {
        asnber::contextSetErrorWithPath(bind.ctx, ASNBER_E_SCHEMA_FIELD,
                                      child->tlvOffset, child->depth, path);
        return ASNBER_E_SCHEMA_FIELD;
    }
    if (bind.warn) {
        asnber::contextAddWarning(bind.ctx, ASNBER_E_SCHEMA_FIELD, child->tlvOffset,
                                child->depth, nullptr, "unknown field");
    }
    return ASNBER_OK;
}

int bindField(BindContext &bind, const asnber::SchemaField &field,
              asnber::Node *child, uint32_t depth, const char *path)
{
    char childPath[kPathBytes];
    std::snprintf(childPath, sizeof(childPath), "%s/%s", path, field.name);
    if (bind.mutate && child->fieldName == nullptr) {
        const asnber_err_t rc =
            asnber::documentSetFieldName(bind.doc, child, field.name);
        if (rc != ASNBER_OK) {
            return rc;
        }
    }
    const int rc = bindType(bind, field.typeId, child, field.name, false,
                            depth + 1, childPath);
    if (rc != ASNBER_OK) {
        return rc;
    }
    return evalConstraints(bind, field.constraints, field.constraintCount,
                           child, childPath);
}

int bindOf(BindContext &bind, const asnber::SchemaType *type,
           asnber::Node *node, uint32_t depth, const char *path)
{
    const asnber::SchemaType *element = typeAt(bind.schema, type->elementTypeId);
    if (element == nullptr) {
        asnber::contextSetErrorWithPath(bind.ctx, ASNBER_E_SCHEMA_TYPE,
                                      node->tlvOffset, node->depth, path);
        return ASNBER_E_SCHEMA_TYPE;
    }
    uint32_t index = 0;
    for (asnber::Node *child = node->firstChild; child != nullptr;
         child = child->nextSibling) {
        char childPath[kPathBytes];
        std::snprintf(childPath, sizeof(childPath), "%s/[%u]", path,
                      static_cast<unsigned int>(index));
        const int rc = bindType(bind, type->elementTypeId, child, nullptr, false,
                                depth + 1, childPath);
        if (rc != ASNBER_OK) {
            return rc;
        }
        ++index;
    }
    if (type->constraintCount != 0) {
        bool sizeOnly = true;
        for (uint32_t i = 0; i < type->constraintCount; ++i) {
            if (type->constraints[i].kind != ASNBER_CONSTRAINT_SIZE &&
                type->constraints[i].kind != ASNBER_CONSTRAINT_MAX) {
                sizeOnly = false;
            }
        }
        if (sizeOnly) {
            for (uint32_t i = 0; i < type->constraintCount; ++i) {
                const asnber::SchemaConstraint &c = type->constraints[i];
                /* 先判有符号负数，避免其转 size_t 后回绕成巨大值。 */
                if (!c.lowerUnbounded &&
                    (c.lower.value < 0 ||
                     index < static_cast<size_t>(c.lower.value))) {
                    asnber::contextSetErrorWithPath(
                        bind.ctx, ASNBER_E_SCHEMA_CONSTRAINT, node->tlvOffset,
                        node->depth, path);
                    return ASNBER_E_SCHEMA_CONSTRAINT;
                }
                if (!c.upperUnbounded &&
                    (c.upper.value < 0 ||
                     index > static_cast<size_t>(c.upper.value))) {
                    asnber::contextSetErrorWithPath(
                        bind.ctx, ASNBER_E_SCHEMA_CONSTRAINT, node->tlvOffset,
                        node->depth, path);
                    return ASNBER_E_SCHEMA_CONSTRAINT;
                }
            }
        } else {
            const int rc = evalConstraints(bind, type->constraints,
                                           type->constraintCount, node, path);
            if (rc != ASNBER_OK) {
                return rc;
            }
        }
    }
    return ASNBER_OK;
}

int bindSequence(BindContext &bind, const asnber::SchemaType *type,
                 asnber::Node *node, uint32_t depth, const char *path)
{
    uint32_t cursor = 0;
    for (asnber::Node *child = node->firstChild; child != nullptr;
         child = child->nextSibling) {
        size_t match = SIZE_MAX;
        for (uint32_t i = cursor; i < type->fieldCount; ++i) {
            const asnber::SchemaType *fieldType =
                typeAt(bind.schema, type->fields[i].typeId);
            if (fieldType != nullptr && tagMatches(bind.schema, fieldType,
                                                   child, false)) {
                match = i;
                break;
            }
        }
        if (match == SIZE_MAX) {
            const int rc = unknownChild(bind, child, path);
            if (rc != ASNBER_OK) {
                return rc;
            }
            continue;
        }
        for (uint32_t i = cursor; i < match; ++i) {
            if ((type->fields[i].flags & ASNBER_FIELD_OPTIONAL) == 0 &&
                type->fields[i].defaultSize == 0) {
                asnber::contextSetErrorWithPath(bind.ctx, ASNBER_E_SCHEMA_FIELD,
                                              child->tlvOffset, child->depth,
                                              path);
                return ASNBER_E_SCHEMA_FIELD;
            }
        }
        const int rc = bindField(bind, type->fields[match], child, depth, path);
        if (rc != ASNBER_OK) {
            return rc;
        }
        cursor = static_cast<uint32_t>(match) + 1;
    }

    for (uint32_t i = cursor; i < type->fieldCount; ++i) {
        const asnber::SchemaType *fieldType =
            typeAt(bind.schema, type->fields[i].typeId);
        if (fieldType != nullptr &&
            fieldType->kind == ASNBER_TYPE_KIND_ANY) {
            if ((type->fields[i].flags & ASNBER_FIELD_OPTIONAL) == 0) {
                asnber::contextSetErrorWithPath(bind.ctx, ASNBER_E_SCHEMA_FIELD,
                                              node->tlvOffset, node->depth,
                                              path);
                return ASNBER_E_SCHEMA_FIELD;
            }
            continue;
        }
        if ((type->fields[i].flags & ASNBER_FIELD_OPTIONAL) == 0 &&
            type->fields[i].defaultSize == 0) {
            asnber::contextSetErrorWithPath(bind.ctx, ASNBER_E_SCHEMA_FIELD,
                                          node->tlvOffset, node->depth, path);
            return ASNBER_E_SCHEMA_FIELD;
        }
    }
    return ASNBER_OK;
}

int bindSet(BindContext &bind, const asnber::SchemaType *type, asnber::Node *node,
            uint32_t depth, const char *path)
{
    for (asnber::Node *child = node->firstChild; child != nullptr;
         child = child->nextSibling) {
        size_t match = SIZE_MAX;
        for (uint32_t i = 0; i < type->fieldCount; ++i) {
            const asnber::SchemaType *fieldType =
                typeAt(bind.schema, type->fields[i].typeId);
            if (fieldType != nullptr && tagMatches(bind.schema, fieldType,
                                                   child, false)) {
                match = i;
                break;
            }
        }
        if (match == SIZE_MAX) {
            const int rc = unknownChild(bind, child, path);
            if (rc != ASNBER_OK) {
                return rc;
            }
            continue;
        }
        const int rc = bindField(bind, type->fields[match], child, depth, path);
        if (rc != ASNBER_OK) {
            return rc;
        }
    }

    for (uint32_t i = 0; i < type->fieldCount; ++i) {
        if ((type->fields[i].flags & ASNBER_FIELD_OPTIONAL) != 0 ||
            type->fields[i].defaultSize != 0) {
            continue;
        }
        bool present = false;
        for (asnber::Node *child = node->firstChild; child != nullptr;
             child = child->nextSibling) {
            const asnber::SchemaType *fieldType =
                typeAt(bind.schema, type->fields[i].typeId);
            if (fieldType != nullptr && tagMatches(bind.schema, fieldType,
                                                   child, false)) {
                present = true;
                break;
            }
        }
        if (!present) {
            asnber::contextSetErrorWithPath(bind.ctx, ASNBER_E_SCHEMA_FIELD,
                                          node->tlvOffset, node->depth, path);
            return ASNBER_E_SCHEMA_FIELD;
        }
    }
    return ASNBER_OK;
}

int bindChoice(BindContext &bind, const asnber::SchemaType *type,
               asnber::Node *node, uint32_t depth, const char *path)
{
    for (uint32_t i = 0; i < type->fieldCount; ++i) {
        const asnber::SchemaType *branch =
            typeAt(bind.schema, type->fields[i].typeId);
        if (branch != nullptr && tagMatches(bind.schema, branch, node, false)) {
            return bindField(bind, type->fields[i], node, depth, path);
        }
    }
    asnber::contextSetErrorWithPath(bind.ctx, ASNBER_E_SCHEMA_TYPE,
                                  node->tlvOffset, node->depth, path);
    return ASNBER_E_SCHEMA_TYPE;
}

int markAny(BindContext &bind, const asnber::SchemaType *type, asnber::Node *node,
            uint32_t depth, const char *path)
{
    (void)depth;
    if (!bind.mutate) {
        return ASNBER_OK;
    }
    if (node->tlvOffset == SIZE_MAX || node->tlvOffset >= bind.doc->inputSize) {
        asnber::contextSetErrorWithPath(bind.ctx, ASNBER_E_SCHEMA_TYPE,
                                      node->tlvOffset, node->depth, path);
        return ASNBER_E_SCHEMA_TYPE;
    }
    const uint8_t *raw = bind.doc->input + node->tlvOffset;
    if (node->tlvSize > bind.doc->inputSize - node->tlvOffset) {
        asnber::contextSetErrorWithPath(bind.ctx, ASNBER_E_SCHEMA_TYPE,
                                      node->tlvOffset, node->depth, path);
        return ASNBER_E_SCHEMA_TYPE;
    }

    const uint8_t *inner = nullptr;
    size_t innerSize = 0;
    if (effectiveTagMode(bind.schema, type) == ASNBER_TAG_MODE_EXPLICIT) {
        if (!((node->flags & asnber::kNodeFlagConstructed) != 0) || node->firstChild == nullptr ||
            node->firstChild->nextSibling != nullptr) {
            asnber::contextSetErrorWithPath(bind.ctx, ASNBER_E_SCHEMA_TYPE,
                                          node->tlvOffset, node->depth, path);
            return ASNBER_E_SCHEMA_TYPE;
        }
        const asnber::Node *child = node->firstChild;
        if (child->tlvOffset == SIZE_MAX ||
            child->tlvSize > bind.doc->inputSize - child->tlvOffset) {
            asnber::contextSetErrorWithPath(bind.ctx, ASNBER_E_SCHEMA_TYPE,
                                          node->tlvOffset, node->depth, path);
            return ASNBER_E_SCHEMA_TYPE;
        }
        inner = bind.doc->input + child->tlvOffset;
        innerSize = child->tlvSize;
    } else {
        const uint8_t *content = nullptr;
        size_t contentSize = 0;
        if (!contentSlice(raw, node->tlvSize, &content, &contentSize)) {
            asnber::contextSetErrorWithPath(bind.ctx, ASNBER_E_SCHEMA_TYPE,
                                          node->tlvOffset, node->depth, path);
            return ASNBER_E_SCHEMA_TYPE;
        }
        inner = content;
        innerSize = contentSize;
    }

    node->flags |= asnber::kNodeFlagAny;
    node->rawTlv = raw;
    node->rawTlvSize = node->tlvSize;
    node->content = inner;
    node->contentSize = innerSize;
    return ASNBER_OK;
}

} /* namespace */

int bindType(BindContext &bind, uint32_t typeId, asnber::Node *node,
             const char *fieldName, bool unwrapped, uint32_t depth,
             const char *path)
{
    const asnber::SchemaType *type = typeAt(bind.schema, typeId);
    if (type == nullptr) {
        asnber::contextSetErrorWithPath(bind.ctx, ASNBER_E_SCHEMA_TYPE,
                                      node->tlvOffset, node->depth, path);
        return ASNBER_E_SCHEMA_TYPE;
    }
    if (depth > bind.maxDepth) {
        asnber::contextSetErrorWithPath(bind.ctx, ASNBER_E_DEPTH_LIMIT,
                                      node->tlvOffset, node->depth, path);
        return ASNBER_E_DEPTH_LIMIT;
    }
    if (fieldName != nullptr && bind.mutate && node->fieldName == nullptr) {
        const asnber_err_t rc =
            asnber::documentSetFieldName(bind.doc, node, fieldName);
        if (rc != ASNBER_OK) {
            return rc;
        }
    }
    (void)fieldName;

    if (type->kind == ASNBER_TYPE_KIND_ANY) {
        if (!unwrapped &&
            effectiveTagMode(bind.schema, type) == ASNBER_TAG_MODE_EXPLICIT) {
            uint32_t cls = 0;
            uint32_t num = 0;
            if (!expectedTag(bind.schema, type, false, &cls, &num) ||
                node->tagClass != cls || node->tagNumber != num) {
                asnber::contextSetErrorWithPath(bind.ctx, ASNBER_E_SCHEMA_TYPE,
                                              node->tlvOffset, node->depth,
                                              path);
                return ASNBER_E_SCHEMA_TYPE;
            }
        }
        return markAny(bind, type, node, depth, path);
    }

    if (!unwrapped &&
        effectiveTagMode(bind.schema, type) == ASNBER_TAG_MODE_EXPLICIT) {
        uint32_t cls = 0;
        uint32_t num = 0;
        if (!expectedTag(bind.schema, type, false, &cls, &num) ||
            node->tagClass != cls || node->tagNumber != num) {
            asnber::contextSetErrorWithPath(bind.ctx, ASNBER_E_SCHEMA_TYPE,
                                          node->tlvOffset, node->depth, path);
            return ASNBER_E_SCHEMA_TYPE;
        }
        if (!((node->flags & asnber::kNodeFlagConstructed) != 0) || node->firstChild == nullptr ||
            node->firstChild->nextSibling != nullptr) {
            asnber::contextSetErrorWithPath(bind.ctx, ASNBER_E_SCHEMA_TYPE,
                                          node->tlvOffset, node->depth, path);
            return ASNBER_E_SCHEMA_TYPE;
        }
        if (type->kind == ASNBER_TYPE_KIND_SIMPLE) {
            /* 描述表对 SIMPLE 只记录外层显式标签，内层通用标签不可知，
               因此剥离外层包装后不再校验内层标签，直接评估约束。 */
            return evalConstraints(bind, type->constraints,
                                   type->constraintCount, node->firstChild,
                                   path);
        }
        return bindType(bind, typeId, node->firstChild, nullptr, true,
                        depth, path);
    }

    if (!tagMatches(bind.schema, type, node, unwrapped)) {
        asnber::contextSetErrorWithPath(bind.ctx, ASNBER_E_SCHEMA_TYPE,
                                      node->tlvOffset, node->depth, path);
        return ASNBER_E_SCHEMA_TYPE;
    }

    switch (type->kind) {
    case ASNBER_TYPE_KIND_SEQUENCE:
        return bindSequence(bind, type, node, depth, path);
    case ASNBER_TYPE_KIND_SET:
        return bindSet(bind, type, node, depth, path);
    case ASNBER_TYPE_KIND_CHOICE:
        return bindChoice(bind, type, node, depth, path);
    case ASNBER_TYPE_KIND_SEQUENCE_OF:
    case ASNBER_TYPE_KIND_SET_OF:
        return bindOf(bind, type, node, depth, path);
    default:
        return evalConstraints(bind, type->constraints, type->constraintCount,
                               node, path);
    }
}

} /* namespace schema_decode_detail */
} /* namespace asnber */
