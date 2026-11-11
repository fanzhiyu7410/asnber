/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * schema 感知编码的尺寸测量：DEFAULT 判定、字段槽位匹配、字段求和，
 * 以及 sizeOf 的递归尺寸计算。
 */

#include "schema/detail/schema_encode_internal.h"

#include <cstring>

namespace asnber {
namespace schema_encode_detail {

bool isDefaultEqual(const Document *doc, const Node *child,
                    const SchemaField &field)
{
    if (field.defaultSize == 0) {
        return false;
    }
    const uint8_t *raw = nullptr;
    size_t rawSize = 0;
    if (!rawTlvOfNode(doc, child, &raw, &rawSize)) {
        return false;
    }
    return rawSize == field.defaultSize &&
           std::memcmp(raw, field.defaultTlv, rawSize) == 0;
}

/* 运行时构树文档的子节点没有字段名；只有这种文档才允许按位置回退。 */
bool hasNamedChildren(const Node *node)
{
    for (const Node *child = node->firstChild; child != nullptr;
         child = child->nextSibling) {
        if (child->fieldName != nullptr) {
            return true;
        }
    }
    return false;
}

bool allocateFieldSlots(const EncState &st, uint32_t count,
                        const Node ***outSlots, asnber_err_t *outError)
{
    *outSlots = nullptr;
    if (count == 0) {
        return true;
    }
    void *raw = nullptr;
    if (contextAllocate(st.ctx, static_cast<size_t>(count) * sizeof(const Node *),
                        AllocationKind::kGeneric, &raw) != ASNBER_OK) {
        *outError = ASNBER_E_NOMEM;
        return false;
    }
    *outSlots = static_cast<const Node **>(raw);
    return true;
}

void releaseFieldSlots(const EncState &st, const Node **slots)
{
    if (slots != nullptr) {
        contextRelease(
            st.ctx,
            const_cast<void *>(reinterpret_cast<const void *>(slots)));
    }
}

/* 为每个 schema 字段找出对应子节点；命名文档按字段名，构树文档按位置。 */
void matchFields(const EncState &st, const SchemaType *type, const Node *node,
                 const Node **slots)
{
    const bool named = hasNamedChildren(node);
    uint32_t positional = 0;
    for (uint32_t i = 0; i < type->fieldCount; ++i) {
        const SchemaField &field = type->fields[i];
        const Node *child = nullptr;
        if (field.name != nullptr) {
            child = namedChild(node, field.name);
        }
        if (child == nullptr && !named) {
            /* 运行时构树文档没有字段名：按子节点顺序回退。 */
            const Node *candidate = node->firstChild;
            for (uint32_t k = 0; candidate != nullptr && k < positional; ++k) {
                candidate = candidate->nextSibling;
            }
            if (candidate != nullptr) {
                const SchemaType *ft = typeAt(st.schema, field.typeId);
                if (ft != nullptr && tagMatches(st.schema, ft, candidate,
                                                false)) {
                    child = candidate;
                    ++positional;
                }
            }
        }
        slots[i] = child;
    }
}

bool isKnownFieldChild(const Node *child, const Node **slots, uint32_t count)
{
    for (uint32_t i = 0; i < count; ++i) {
        if (slots[i] == child) {
            return true;
        }
    }
    return false;
}

bool sumKnownFields(const EncState &st, const SchemaType *type,
                    const Node **slots, size_t *outTotal, asnber_err_t *outError)
{
    size_t total = 0;
    for (uint32_t i = 0; i < type->fieldCount; ++i) {
        const SchemaField &field = type->fields[i];
        const Node *child = slots[i];
        if (child == nullptr) {
            if ((field.flags & ASNBER_FIELD_OPTIONAL) != 0 ||
                field.defaultSize != 0) {
                continue;
            }
            *outError = ASNBER_E_SCHEMA_FIELD;
            noteEncodePath(st, type->name, field.name);
            return false;
        }
        if (isDefaultEqual(st.doc, child, field)) {
            continue;
        }
        size_t childSize = 0;
        if (!sizeOf(st, field.typeId, child, false, &childSize, outError)) {
            return false;
        }
        if (total > SIZE_MAX - childSize) {
            *outError = ASNBER_E_OUTPUT_LIMIT;
            return false;
        }
        total += childSize;
    }
    *outTotal = total;
    return true;
}

bool addRetainedChild(const EncState &st, const Node *child, size_t *total,
                      asnber_err_t *outError)
{
    const uint8_t *raw = nullptr;
    size_t rawSize = 0;
    if (!rawTlvOfNode(st.doc, child, &raw, &rawSize)) {
        *outError = ASNBER_E_INVALID_STATE;
        return false;
    }
    if (!validateRetainedDer(st.ctx, raw, rawSize, outError)) {
        return false;
    }
    if (rawSize > SIZE_MAX - *total) {
        *outError = ASNBER_E_OUTPUT_LIMIT;
        return false;
    }
    *total += rawSize;
    return true;
}

/* SEQUENCE：已知字段按 schema 顺序，未知字段按 DOM 原序追加。 */
bool sizeSequenceFields(const EncState &st, const SchemaType *type,
                        const Node *node, size_t *outContent,
                        asnber_err_t *outError)
{
    const Node **slots = nullptr;
    if (!allocateFieldSlots(st, type->fieldCount, &slots, outError)) {
        return false;
    }
    matchFields(st, type, node, slots);
    size_t total = 0;
    bool ok = sumKnownFields(st, type, slots, &total, outError);
    if (ok) {
        for (const Node *child = node->firstChild; child != nullptr;
             child = child->nextSibling) {
            if (isKnownFieldChild(child, slots, type->fieldCount)) {
                continue;
            }
            if (!addRetainedChild(st, child, &total, outError)) {
                if (*outError == ASNBER_E_NON_CANONICAL) {
                    noteEncodePath(st, type->name, nullptr);
                }
                ok = false;
                break;
            }
        }
    }
    releaseFieldSlots(st, slots);
    if (!ok) {
        return false;
    }
    *outContent = total;
    return true;
}

/* SET：不做已知/未知合并排序；未知字段直接拒绝，绝不产出非法 DER。 */
bool sizeSetFields(const EncState &st, const SchemaType *type, const Node *node,
                   size_t *outContent, asnber_err_t *outError)
{
    const Node **slots = nullptr;
    if (!allocateFieldSlots(st, type->fieldCount, &slots, outError)) {
        return false;
    }
    matchFields(st, type, node, slots);
    size_t total = 0;
    bool ok = sumKnownFields(st, type, slots, &total, outError);
    if (ok) {
        for (const Node *child = node->firstChild; child != nullptr;
             child = child->nextSibling) {
            if (!isKnownFieldChild(child, slots, type->fieldCount)) {
                *outError = ASNBER_E_SCHEMA_FIELD;
                noteEncodePath(st, type->name, nullptr);
                ok = false;
                break;
            }
        }
    }
    releaseFieldSlots(st, slots);
    if (!ok) {
        return false;
    }
    *outContent = total;
    return true;
}

bool sizeOf(const EncState &st, uint32_t typeId, const Node *node,
            bool unwrapped, size_t *outSize, asnber_err_t *outError)
{
    const SchemaType *type = typeAt(st.schema, typeId);
    if (type == nullptr || node == nullptr) {
        *outError = ASNBER_E_INVALID_STATE;
        return false;
    }
    /* ANY 节点不按声明结构展开：无论其所在字段声明为何种类型，都只写回
       节点保留的原始字节。解码得到的 ANY 只出现在 ANY 字段上，因此该规则
       不改变既有解码文档的编码结果。 */
    if (type->kind == ASNBER_TYPE_KIND_ANY || nodeIsAny(node)) {
        return sizeAny(st, type, node, outSize, outError);
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
        *outSize = header + base;
        return true;
    }
    if (type->kind == ASNBER_TYPE_KIND_CHOICE) {
        const int32_t index = branchIndex(st.schema, type, node);
        if (index < 0) {
            *outError = ASNBER_E_SCHEMA_TYPE;
            noteEncodePath(st, type->name, nullptr);
            return false;
        }
        return sizeOf(st, type->fields[index].typeId, node, false, outSize,
                      outError);
    }

    size_t content = 0;
    if (type->kind == ASNBER_TYPE_KIND_SEQUENCE) {
        if (!sizeSequenceFields(st, type, node, &content, outError)) {
            return false;
        }
    } else if (type->kind == ASNBER_TYPE_KIND_SET) {
        if (!sizeSetFields(st, type, node, &content, outError)) {
            return false;
        }
    } else if (type->kind == ASNBER_TYPE_KIND_SEQUENCE_OF ||
               type->kind == ASNBER_TYPE_KIND_SET_OF) {
        for (const Node *child = node->firstChild; child != nullptr;
             child = child->nextSibling) {
            size_t childSize = 0;
            if (!sizeOf(st, type->elementTypeId, child, false, &childSize,
                        outError)) {
                return false;
            }
            if (content > SIZE_MAX - childSize) {
                *outError = ASNBER_E_OUTPUT_LIMIT;
                return false;
            }
            content += childSize;
        }
    } else if ((node->flags & kNodeFlagConstructed) != 0) {
        for (const Node *child = node->firstChild; child != nullptr;
             child = child->nextSibling) {
            const uint8_t *raw = nullptr;
            size_t rawSize = 0;
            if (!rawTlvOfNode(st.doc, child, &raw, &rawSize)) {
                *outError = ASNBER_E_INVALID_STATE;
                return false;
            }
            if (content > SIZE_MAX - rawSize) {
                *outError = ASNBER_E_OUTPUT_LIMIT;
                return false;
            }
            content += rawSize;
        }
    } else {
        content = node->contentSize;
    }

    uint32_t cls = 0;
    uint32_t num = 0;
    bool constructed = false;
    typeTag(st.schema, type, unwrapped, &cls, &num, &constructed);
    (void)cls;
    if (unwrapped && type->kind == ASNBER_TYPE_KIND_SIMPLE &&
        effectiveTagMode(st.schema, type) == ASNBER_TAG_MODE_EXPLICIT) {
        /* 描述表只记录 EXPLICIT 外层标签，内层通用标签不可知，
           按 DOM 节点自身的标签写出。 */
        num = node->tagNumber;
    }
    const size_t header = tagFieldBytes(num) + lengthFieldBytes(content);
    if (content > SIZE_MAX - header) {
        *outError = ASNBER_E_OUTPUT_LIMIT;
        return false;
    }
    *outSize = header + content;
    return true;
}

} /* namespace schema_encode_detail */
} /* namespace asnber */
