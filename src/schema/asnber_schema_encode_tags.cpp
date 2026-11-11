/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * schema 感知编码的标签与长度字段计算：类型标签推导、字段字节数、
 * 标签/长度写出，以及子节点标签匹配与 CHOICE 分支定位。
 */

#include "schema/detail/schema_encode_internal.h"

#include <cstring>

namespace asnber {
namespace schema_encode_detail {

const asnber::SchemaType *typeAt(const Schema *schema, uint32_t typeId)
{
    if (schema == nullptr || typeId == 0 || typeId > schema->typeCount) {
        return nullptr;
    }
    return &schema->types[typeId - 1];
}

uint32_t effectiveTagMode(const Schema *schema, const SchemaType *type)
{
    return type->tagMode == ASNBER_TAG_MODE_DEFAULT ? schema->moduleTagMode
                                                  : type->tagMode;
}

uint32_t universalTagOf(const SchemaType *type)
{
    switch (type->kind) {
    case ASNBER_TYPE_KIND_SEQUENCE:
    case ASNBER_TYPE_KIND_SEQUENCE_OF:
        return 16;
    case ASNBER_TYPE_KIND_SET:
    case ASNBER_TYPE_KIND_SET_OF:
        return 17;
    default:
        return type->tagNumber;
    }
}

void typeTag(const Schema *schema, const SchemaType *type, bool unwrapped,
             uint32_t *outClass, uint32_t *outNumber, bool *outConstructed)
{
    const bool explicitMode =
        !unwrapped && effectiveTagMode(schema, type) == ASNBER_TAG_MODE_EXPLICIT;
    if (explicitMode) {
        *outClass = type->tagClass;
        *outNumber = type->tagNumber;
        *outConstructed = true;
        return;
    }
    switch (type->kind) {
    case ASNBER_TYPE_KIND_SEQUENCE:
    case ASNBER_TYPE_KIND_SEQUENCE_OF:
        /* IMPLICIT 覆盖的构造类型改用类型自身的非通用标签；显式包装剥离后
           回到通用 SEQUENCE 标签。 */
        if (!unwrapped && type->tagClass != ASNBER_TAG_UNIVERSAL) {
            *outClass = type->tagClass;
            *outNumber = type->tagNumber;
        } else {
            *outClass = ASNBER_TAG_UNIVERSAL;
            *outNumber = 16;
        }
        *outConstructed = true;
        return;
    case ASNBER_TYPE_KIND_SET:
    case ASNBER_TYPE_KIND_SET_OF:
        if (!unwrapped && type->tagClass != ASNBER_TAG_UNIVERSAL) {
            *outClass = type->tagClass;
            *outNumber = type->tagNumber;
        } else {
            *outClass = ASNBER_TAG_UNIVERSAL;
            *outNumber = 17;
        }
        *outConstructed = true;
        return;
    default:
        if (type->tagClass == ASNBER_TAG_UNIVERSAL) {
            *outClass = ASNBER_TAG_UNIVERSAL;
            *outNumber = universalTagOf(type);
        } else {
            *outClass = type->tagClass;
            *outNumber = type->tagNumber;
        }
        *outConstructed = false;
        return;
    }
}

const Node *namedChild(const Node *parent, const char *name)
{
    if (name == nullptr) {
        return nullptr;
    }
    for (const Node *child = parent->firstChild; child != nullptr;
         child = child->nextSibling) {
        if (child->fieldName != nullptr &&
            std::strcmp(child->fieldName, name) == 0) {
            return child;
        }
    }
    return nullptr;
}

bool tagMatches(const Schema *schema, const SchemaType *type, const Node *node,
                bool unwrapped)
{
    if (type->kind == ASNBER_TYPE_KIND_ANY) {
        return true;
    }
    if (type->kind == ASNBER_TYPE_KIND_CHOICE &&
        effectiveTagMode(schema, type) != ASNBER_TAG_MODE_EXPLICIT) {
        for (uint32_t i = 0; i < type->fieldCount; ++i) {
            const SchemaType *branch = typeAt(schema, type->fields[i].typeId);
            if (branch != nullptr && tagMatches(schema, branch, node, false)) {
                return true;
            }
        }
        return false;
    }
    uint32_t cls = 0;
    uint32_t num = 0;
    bool constructed = false;
    typeTag(schema, type, unwrapped, &cls, &num, &constructed);
    return node->tagClass == cls && node->tagNumber == num;
}

int32_t branchIndex(const Schema *schema, const SchemaType *type,
                    const Node *node)
{
    for (uint32_t i = 0; i < type->fieldCount; ++i) {
        const SchemaType *branch = typeAt(schema, type->fields[i].typeId);
        if (branch == nullptr) {
            continue;
        }
        if (node->fieldName != nullptr &&
            type->fields[i].name != nullptr &&
            std::strcmp(node->fieldName, type->fields[i].name) == 0) {
            return static_cast<int32_t>(i);
        }
        if (tagMatches(schema, branch, node, false)) {
            return static_cast<int32_t>(i);
        }
    }
    return -1;
}

} /* namespace schema_encode_detail */
} /* namespace asnber */
