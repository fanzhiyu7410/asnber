/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * schema 感知解码：期望标签计算与节点标签匹配。
 *
 * 职责：按类型种类、标签模式（DEFAULT/IMPLICIT/EXPLICIT）与是否已剥离
 *       外层显式包装，计算期望标签并判定节点是否匹配；CHOICE 未包装时
 *       由分支决定。
 * 依赖：schema/asnber_schema.h、types/asnber_dom.h。
 */

#include <cstddef>
#include <cstdint>

#include "schema/detail/schema_decode_internal.h"

namespace asnber {
namespace schema_decode_detail {

namespace {

uint32_t universalTagOf(const asnber::SchemaType *type)
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

} /* namespace */

const asnber::SchemaType *typeAt(const asnber::Schema *schema, uint32_t typeId)
{
    if (schema == nullptr || typeId == 0 || typeId > schema->typeCount) {
        return nullptr;
    }
    return &schema->types[typeId - 1];
}

uint32_t effectiveTagMode(const asnber::Schema *schema,
                          const asnber::SchemaType *type)
{
    if (type->tagMode == ASNBER_TAG_MODE_DEFAULT) {
        return schema->moduleTagMode;
    }
    return type->tagMode;
}

/* 计算类型的期望标签；CHOICE（无外层包装）返回 false 表示由分支决定。 */
bool expectedTag(const asnber::Schema *schema, const asnber::SchemaType *type,
                 bool unwrapped, uint32_t *outClass, uint32_t *outNumber)
{
    if (type->kind == ASNBER_TYPE_KIND_CHOICE &&
        effectiveTagMode(schema, type) != ASNBER_TAG_MODE_EXPLICIT) {
        return false;
    }
    if (!unwrapped &&
        effectiveTagMode(schema, type) == ASNBER_TAG_MODE_EXPLICIT) {
        *outClass = type->tagClass;
        *outNumber = type->tagNumber;
        return true;
    }
    /* 剥离显式包装后，内层始终回到通用 SEQUENCE/SET 标签。 */
    if (unwrapped) {
        if (type->kind == ASNBER_TYPE_KIND_SEQUENCE ||
            type->kind == ASNBER_TYPE_KIND_SEQUENCE_OF) {
            *outClass = ASNBER_TAG_UNIVERSAL;
            *outNumber = 16;
            return true;
        }
        if (type->kind == ASNBER_TYPE_KIND_SET ||
            type->kind == ASNBER_TYPE_KIND_SET_OF) {
            *outClass = ASNBER_TAG_UNIVERSAL;
            *outNumber = 17;
            return true;
        }
    }
    /* IMPLICIT 覆盖的构造类型改用类型自身的非通用标签。 */
    if (type->kind == ASNBER_TYPE_KIND_SEQUENCE ||
        type->kind == ASNBER_TYPE_KIND_SEQUENCE_OF) {
        *outClass = type->tagClass;
        *outNumber =
            type->tagClass == ASNBER_TAG_UNIVERSAL ? 16 : type->tagNumber;
        return true;
    }
    if (type->kind == ASNBER_TYPE_KIND_SET ||
        type->kind == ASNBER_TYPE_KIND_SET_OF) {
        *outClass = type->tagClass;
        *outNumber =
            type->tagClass == ASNBER_TAG_UNIVERSAL ? 17 : type->tagNumber;
        return true;
    }
    if (type->tagClass == ASNBER_TAG_UNIVERSAL) {
        *outClass = ASNBER_TAG_UNIVERSAL;
        *outNumber = universalTagOf(type);
        return true;
    }
    *outClass = type->tagClass;
    *outNumber = type->tagNumber;
    return true;
}

bool tagMatches(const asnber::Schema *schema, const asnber::SchemaType *type,
                const asnber::Node *node, bool unwrapped)
{
    if (type->kind == ASNBER_TYPE_KIND_ANY) {
        /* 无包装 ANY 接受任意 TLV。EXPLICIT ANY 先看外层标签，否则
           SEQUENCE 里靠前的可选 ANY 会吞掉下一个字段。 */
        if (!unwrapped &&
            effectiveTagMode(schema, type) == ASNBER_TAG_MODE_EXPLICIT) {
            uint32_t cls = 0;
            uint32_t num = 0;
            if (!expectedTag(schema, type, false, &cls, &num)) {
                return false;
            }
            return node->tagClass == cls && node->tagNumber == num;
        }
        return true;
    }
    if (type->kind == ASNBER_TYPE_KIND_CHOICE &&
        (effectiveTagMode(schema, type) != ASNBER_TAG_MODE_EXPLICIT ||
         unwrapped)) {
        for (uint32_t i = 0; i < type->fieldCount; ++i) {
            const asnber::SchemaType *branch =
                typeAt(schema, type->fields[i].typeId);
            if (branch != nullptr && tagMatches(schema, branch, node, false)) {
                return true;
            }
        }
        return false;
    }
    uint32_t cls = 0;
    uint32_t num = 0;
    if (!expectedTag(schema, type, unwrapped, &cls, &num)) {
        return false;
    }
    return node->tagClass == cls && node->tagNumber == num;
}

} /* namespace schema_decode_detail */
} /* namespace asnber */
