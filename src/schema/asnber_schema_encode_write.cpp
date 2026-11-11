/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * schema 感知编码的写出：带标签内容写出、SET/SET OF 的 DER 排序、
 * SEQUENCE 字段写出，以及 writeOf 的递归写出。
 */

#include "schema/detail/schema_encode_internal.h"

#include <cstring>

namespace asnber {
namespace schema_encode_detail {

bool writeTaggedContent(const EncState &st, uint32_t tagClass,
                        uint32_t tagNumber, bool constructed,
                        const uint8_t *content, size_t contentSize,
                        uint8_t *dst, size_t capacity, size_t *outUsed,
                        asnber_err_t *outError)
{
    (void)st;
    const size_t header = tagFieldBytes(tagNumber) +
                          lengthFieldBytes(contentSize);
    if (header + contentSize > capacity) {
        *outError = ASNBER_E_OUTPUT_LIMIT;
        return false;
    }
    writeTag(dst, tagClass, tagNumber, constructed);
    const size_t lengthBytes = writeLength(dst + tagFieldBytes(tagNumber),
                                           contentSize);
    if (header != tagFieldBytes(tagNumber) + lengthBytes) {
        *outError = ASNBER_E_INVALID_STATE;
        return false;
    }
    if (contentSize != 0) {
        std::memcpy(dst + header, content, contentSize);
    }
    *outUsed = header + contentSize;
    return true;
}

void writeSorted(const uint8_t *buffer, size_t *offsets, size_t *sizes,
                 size_t count)
{
    /* 插入排序：按完整 TLV 字节序升序。 */
    for (size_t i = 1; i < count; ++i) {
        size_t j = i;
        while (j > 0) {
            const size_t a = offsets[j - 1];
            const size_t b = offsets[j];
            const size_t na = sizes[j - 1];
            const size_t nb = sizes[j];
            const uint8_t *pa = buffer + a;
            const uint8_t *pb = buffer + b;
            const size_t compare = na < nb ? na : nb;
            int order = 0;
            for (size_t k = 0; k < compare; ++k) {
                if (pa[k] != pb[k]) {
                    order = pa[k] < pb[k] ? -1 : 1;
                    break;
                }
            }
            if (order == 0) {
                order = na < nb ? -1 : (na > nb ? 1 : 0);
            }
            if (order <= 0) {
                break;
            }
            const size_t tmpOffset = offsets[j - 1];
            offsets[j - 1] = offsets[j];
            offsets[j] = tmpOffset;
            const size_t tmpSize = sizes[j - 1];
            sizes[j - 1] = sizes[j];
            sizes[j] = tmpSize;
            --j;
        }
    }
}

bool writeSetOf(const EncState &st, uint32_t typeId, const Node *node,
                uint32_t tagClass, uint32_t tagNumber, uint8_t *dst,
                size_t capacity, size_t *outUsed, asnber_err_t *outError)
{
    size_t count = 0;
    size_t total = 0;
    for (const Node *child = node->firstChild; child != nullptr;
         child = child->nextSibling) {
        size_t childSize = 0;
        if (!sizeOf(st, typeId, child, false, &childSize, outError)) {
            return false;
        }
        total += childSize;
        ++count;
    }
    const size_t header =
        tagFieldBytes(tagNumber) + lengthFieldBytes(total);
    if (header + total > capacity) {
        *outError = ASNBER_E_OUTPUT_LIMIT;
        return false;
    }
    if (count == 0) {
        writeTag(dst, tagClass, tagNumber, true);
        writeLength(dst + tagFieldBytes(tagNumber), 0);
        *outUsed = header;
        return true;
    }

    void *tempRaw = nullptr;
    void *offsetRaw = nullptr;
    void *sizeRaw = nullptr;
    if (contextAllocate(st.ctx, total, AllocationKind::kGeneric, &tempRaw) !=
            ASNBER_OK ||
        contextAllocate(st.ctx, count * sizeof(size_t),
                        AllocationKind::kGeneric, &offsetRaw) != ASNBER_OK ||
        contextAllocate(st.ctx, count * sizeof(size_t),
                        AllocationKind::kGeneric, &sizeRaw) != ASNBER_OK) {
        if (tempRaw != nullptr) {
            contextRelease(st.ctx, tempRaw);
        }
        if (offsetRaw != nullptr) {
            contextRelease(st.ctx, offsetRaw);
        }
        *outError = ASNBER_E_NOMEM;
        return false;
    }
    uint8_t *temp = static_cast<uint8_t *>(tempRaw);
    size_t *offsets = static_cast<size_t *>(offsetRaw);
    size_t *sizes = static_cast<size_t *>(sizeRaw);
    size_t cursor = 0;
    size_t index = 0;
    for (const Node *child = node->firstChild; child != nullptr;
         child = child->nextSibling) {
        offsets[index] = cursor;
        size_t used = 0;
        if (!writeOf(st, typeId, child, false, temp + cursor, total - cursor,
                     &used, outError)) {
            contextRelease(st.ctx, sizeRaw);
            contextRelease(st.ctx, offsetRaw);
            contextRelease(st.ctx, tempRaw);
            return false;
        }
        sizes[index] = used;
        cursor += used;
        ++index;
    }
    writeSorted(temp, offsets, sizes, count);

    writeTag(dst, tagClass, tagNumber, true);
    writeLength(dst + tagFieldBytes(tagNumber), total);
    size_t pos = header;
    for (size_t i = 0; i < count; ++i) {
        std::memcpy(dst + pos, temp + offsets[i], sizes[i]);
        pos += sizes[i];
    }
    contextRelease(st.ctx, sizeRaw);
    contextRelease(st.ctx, offsetRaw);
    contextRelease(st.ctx, tempRaw);
    *outUsed = pos;
    return true;
}

/* SEQUENCE：已知字段按 schema 顺序，未知字段按 DOM 原序追加。 */
bool writeSequenceFields(const EncState &st, const SchemaType *type,
                         const Node *node, uint8_t *dst, size_t capacity,
                         size_t *outUsed, asnber_err_t *outError)
{
    const Node **slots = nullptr;
    if (!allocateFieldSlots(st, type->fieldCount, &slots, outError)) {
        return false;
    }
    matchFields(st, type, node, slots);
    size_t pos = 0;
    bool ok = true;
    for (uint32_t i = 0; i < type->fieldCount && ok; ++i) {
        const SchemaField &field = type->fields[i];
        const Node *child = slots[i];
        if (child == nullptr) {
            if ((field.flags & ASNBER_FIELD_OPTIONAL) != 0 ||
                field.defaultSize != 0) {
                continue;
            }
            *outError = ASNBER_E_SCHEMA_FIELD;
            noteEncodePath(st, type->name, field.name);
            ok = false;
            break;
        }
        if (isDefaultEqual(st.doc, child, field)) {
            continue;
        }
        size_t used = 0;
        if (!writeOf(st, field.typeId, child, false, dst + pos, capacity - pos,
                     &used, outError)) {
            ok = false;
            break;
        }
        pos += used;
    }
    if (ok) {
        for (const Node *child = node->firstChild; child != nullptr;
             child = child->nextSibling) {
            if (isKnownFieldChild(child, slots, type->fieldCount)) {
                continue;
            }
            const uint8_t *raw = nullptr;
            size_t rawSize = 0;
            if (!rawTlvOfNode(st.doc, child, &raw, &rawSize)) {
                *outError = ASNBER_E_INVALID_STATE;
                ok = false;
                break;
            }
            if (rawSize > capacity - pos) {
                *outError = ASNBER_E_OUTPUT_LIMIT;
                ok = false;
                break;
            }
            std::memcpy(dst + pos, raw, rawSize);
            pos += rawSize;
        }
    }
    releaseFieldSlots(st, slots);
    if (!ok) {
        return false;
    }
    *outUsed = pos;
    return true;
}

/* SET：已知字段参与 DER 标签排序；出现未知字段直接拒绝。 */
bool writeSet(const EncState &st, const SchemaType *type, const Node *node,
              uint32_t cls, uint32_t num, uint8_t *dst, size_t capacity,
              size_t *outUsed, asnber_err_t *outError)
{
    const Node **slots = nullptr;
    if (!allocateFieldSlots(st, type->fieldCount, &slots, outError)) {
        return false;
    }
    matchFields(st, type, node, slots);

    bool ok = true;
    for (const Node *child = node->firstChild; child != nullptr;
         child = child->nextSibling) {
        if (!isKnownFieldChild(child, slots, type->fieldCount)) {
            *outError = ASNBER_E_SCHEMA_FIELD;
            noteEncodePath(st, type->name, nullptr);
            ok = false;
            break;
        }
    }

    size_t fieldTotal = 0;
    uint32_t count = 0;
    for (uint32_t i = 0; i < type->fieldCount && ok; ++i) {
        const SchemaField &field = type->fields[i];
        const Node *child = slots[i];
        if (child == nullptr) {
            if ((field.flags & ASNBER_FIELD_OPTIONAL) != 0 ||
                field.defaultSize != 0) {
                continue;
            }
            *outError = ASNBER_E_SCHEMA_FIELD;
            noteEncodePath(st, type->name, field.name);
            ok = false;
            break;
        }
        if (isDefaultEqual(st.doc, child, field)) {
            continue;
        }
        size_t childSize = 0;
        if (!sizeOf(st, field.typeId, child, false, &childSize, outError)) {
            ok = false;
            break;
        }
        if (fieldTotal > SIZE_MAX - childSize) {
            *outError = ASNBER_E_OUTPUT_LIMIT;
            ok = false;
            break;
        }
        fieldTotal += childSize;
        ++count;
    }

    const size_t header = tagFieldBytes(num) + lengthFieldBytes(fieldTotal);
    if (ok && header + fieldTotal > capacity) {
        *outError = ASNBER_E_OUTPUT_LIMIT;
        ok = false;
    }
    if (ok) {
        writeTag(dst, cls, num, true);
        writeLength(dst + tagFieldBytes(num), fieldTotal);
        if (fieldTotal == 0) {
            *outUsed = header;
        } else {
            void *tempRaw = nullptr;
            void *offsetRaw = nullptr;
            void *sizeRaw = nullptr;
            if (contextAllocate(st.ctx, fieldTotal,
                                AllocationKind::kGeneric, &tempRaw) !=
                    ASNBER_OK ||
                contextAllocate(st.ctx, count * sizeof(size_t),
                                AllocationKind::kGeneric, &offsetRaw) !=
                    ASNBER_OK ||
                contextAllocate(st.ctx, count * sizeof(size_t),
                                AllocationKind::kGeneric, &sizeRaw) !=
                    ASNBER_OK) {
                if (tempRaw != nullptr) {
                    contextRelease(st.ctx, tempRaw);
                }
                if (offsetRaw != nullptr) {
                    contextRelease(st.ctx, offsetRaw);
                }
                *outError = ASNBER_E_NOMEM;
                ok = false;
            } else {
                uint8_t *temp = static_cast<uint8_t *>(tempRaw);
                size_t *offsets = static_cast<size_t *>(offsetRaw);
                size_t *sizes = static_cast<size_t *>(sizeRaw);
                size_t cursor = 0;
                size_t index = 0;
                for (uint32_t i = 0; i < type->fieldCount; ++i) {
                    const Node *child = slots[i];
                    if (child == nullptr ||
                        isDefaultEqual(st.doc, child, type->fields[i])) {
                        continue;
                    }
                    offsets[index] = cursor;
                    size_t used = 0;
                    if (!writeOf(st, type->fields[i].typeId, child, false,
                                 temp + cursor, fieldTotal - cursor, &used,
                                 outError)) {
                        ok = false;
                        break;
                    }
                    sizes[index] = used;
                    cursor += used;
                    ++index;
                }
                if (ok) {
                    writeSorted(temp, offsets, sizes, count);
                    size_t pos = header;
                    for (size_t i = 0; i < count; ++i) {
                        std::memcpy(dst + pos, temp + offsets[i], sizes[i]);
                        pos += sizes[i];
                    }
                    *outUsed = pos;
                }
                contextRelease(st.ctx, sizeRaw);
                contextRelease(st.ctx, offsetRaw);
                contextRelease(st.ctx, tempRaw);
            }
        }
    }
    releaseFieldSlots(st, slots);
    return ok;
}

bool writeOf(const EncState &st, uint32_t typeId, const Node *node,
             bool unwrapped, uint8_t *dst, size_t capacity, size_t *outUsed,
             asnber_err_t *outError)
{
    const SchemaType *type = typeAt(st.schema, typeId);
    if (type == nullptr || node == nullptr) {
        *outError = ASNBER_E_INVALID_STATE;
        return false;
    }
    if (type->kind == ASNBER_TYPE_KIND_ANY || nodeIsAny(node)) {
        return writeAny(st, type, node, dst, capacity, outUsed, outError);
    }
    if (!unwrapped &&
        effectiveTagMode(st.schema, type) == ASNBER_TAG_MODE_EXPLICIT) {
        if (node->firstChild == nullptr ||
            node->firstChild->nextSibling != nullptr) {
            *outError = ASNBER_E_INVALID_STATE;
            return false;
        }
        size_t base = 0;
        if (!sizeOf(st, typeId, node->firstChild, true, &base, outError)) {
            return false;
        }
        const size_t header = tagFieldBytes(type->tagNumber) +
                              lengthFieldBytes(base);
        if (header + base > capacity) {
            *outError = ASNBER_E_OUTPUT_LIMIT;
            return false;
        }
        writeTag(dst, type->tagClass, type->tagNumber, true);
        writeLength(dst + tagFieldBytes(type->tagNumber), base);
        size_t used = 0;
        if (!writeOf(st, typeId, node->firstChild, true, dst + header,
                     capacity - header, &used, outError)) {
            return false;
        }
        *outUsed = header + used;
        return true;
    }
    if (type->kind == ASNBER_TYPE_KIND_CHOICE) {
        const int32_t index = branchIndex(st.schema, type, node);
        if (index < 0) {
            *outError = ASNBER_E_SCHEMA_TYPE;
            noteEncodePath(st, type->name, nullptr);
            return false;
        }
        return writeOf(st, type->fields[index].typeId, node, false, dst,
                       capacity, outUsed, outError);
    }
    size_t content = 0;
    if (!sizeOf(st, typeId, node, unwrapped, &content, outError)) {
        return false;
    }
    uint32_t cls = 0;
    uint32_t num = 0;
    bool constructed = false;
    typeTag(st.schema, type, unwrapped, &cls, &num, &constructed);
    if (unwrapped && type->kind == ASNBER_TYPE_KIND_SIMPLE &&
        effectiveTagMode(st.schema, type) == ASNBER_TAG_MODE_EXPLICIT) {
        /* 与 sizeOf 保持一致：内层通用标签取自 DOM 节点。 */
        cls = node->tagClass;
        num = node->tagNumber;
        constructed = false;
    }

    if (type->kind == ASNBER_TYPE_KIND_SET) {
        return writeSet(st, type, node, cls, num, dst, capacity, outUsed,
                        outError);
    }
    if (type->kind == ASNBER_TYPE_KIND_SET_OF) {
        /* [n] IMPLICIT SET OF 使用类型自身的上下文标签。 */
        return writeSetOf(st, type->elementTypeId, node, cls, num, dst,
                          capacity, outUsed, outError);
    }
    if (type->kind == ASNBER_TYPE_KIND_SEQUENCE_OF) {
        /* 顺序编码子元素。content 需按子元素 TLV 之和计算，不能复用
           sizeOf（其结果已包含本层标签/长度头）。 */
        size_t seqContent = 0;
        for (const Node *child = node->firstChild; child != nullptr;
             child = child->nextSibling) {
            size_t childSize = 0;
            if (!sizeOf(st, type->elementTypeId, child, false, &childSize,
                        outError)) {
                return false;
            }
            if (seqContent > SIZE_MAX - childSize) {
                *outError = ASNBER_E_OUTPUT_LIMIT;
                return false;
            }
            seqContent += childSize;
        }
        const size_t header =
            tagFieldBytes(num) + lengthFieldBytes(seqContent);
        if (header + seqContent > capacity) {
            *outError = ASNBER_E_OUTPUT_LIMIT;
            return false;
        }
        writeTag(dst, cls, num, constructed);
        writeLength(dst + tagFieldBytes(num), seqContent);
        size_t pos = header;
        for (const Node *child = node->firstChild; child != nullptr;
             child = child->nextSibling) {
            size_t used = 0;
            if (!writeOf(st, type->elementTypeId, child, false, dst + pos,
                         capacity - pos, &used, outError)) {
                return false;
            }
            pos += used;
        }
        *outUsed = pos;
        return true;
    }
    if (type->kind == ASNBER_TYPE_KIND_SEQUENCE) {
        /* SEQUENCE：已知字段按 schema 顺序，未知字段按 DOM 原序追加。 */
        size_t fieldTotal = 0;
        if (!sizeSequenceFields(st, type, node, &fieldTotal, outError)) {
            return false;
        }
        const size_t header =
            tagFieldBytes(num) + lengthFieldBytes(fieldTotal);
        if (header + fieldTotal > capacity) {
            *outError = ASNBER_E_OUTPUT_LIMIT;
            return false;
        }
        writeTag(dst, cls, num, constructed);
        writeLength(dst + tagFieldBytes(num), fieldTotal);
        size_t inner = 0;
        if (!writeSequenceFields(st, type, node, dst + header, fieldTotal,
                                 &inner, outError)) {
            return false;
        }
        *outUsed = header + inner;
        return true;
    }

    if (type->kind != ASNBER_TYPE_KIND_SIMPLE) {
        *outError = ASNBER_E_INVALID_STATE;
        return false;
    }

    if ((node->flags & kNodeFlagConstructed) != 0) {
        const size_t header = tagFieldBytes(num) + lengthFieldBytes(content);
        if (header + content > capacity) {
            *outError = ASNBER_E_OUTPUT_LIMIT;
            return false;
        }
        writeTag(dst, cls, num, true);
        writeLength(dst + tagFieldBytes(num), content);
        size_t pos = header;
        for (const Node *child = node->firstChild; child != nullptr;
             child = child->nextSibling) {
            const uint8_t *raw = nullptr;
            size_t rawSize = 0;
            if (!rawTlvOfNode(st.doc, child, &raw, &rawSize)) {
                *outError = ASNBER_E_INVALID_STATE;
                return false;
            }
            if (rawSize > capacity - pos) {
                *outError = ASNBER_E_OUTPUT_LIMIT;
                return false;
            }
            std::memcpy(dst + pos, raw, rawSize);
            pos += rawSize;
        }
        *outUsed = pos;
        return true;
    }
    return writeTaggedContent(st, cls, num, false, node->content,
                              node->contentSize, dst, capacity, outUsed,
                              outError);
}

} /* namespace schema_encode_detail */
} /* namespace asnber */
