/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * schema 感知解码：约束求值。
 *
 * 职责：把 INTEGER/ENUMERATED 内容转成规范十进制文本，与 SIZE/ENUM/
 *       上下界约束比较；构造字符串按子节点累加长度。
 * 依赖：core/asnber_context.h、schema/asnber_schema.h、types/asnber_dom.h。
 */

#include <asnber/asnber.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "schema/detail/schema_decode_internal.h"

namespace asnber {
namespace schema_decode_detail {

namespace {

constexpr size_t kDecimalDigits = 2048;

bool integerToDecimal(const uint8_t *data, size_t size, char *out,
                      size_t capacity, bool *outNegative)
{
    if (size == 0 || capacity < 2) {
        return false;
    }
    const bool negative = (data[0] & 0x80) != 0;
    uint8_t magnitude[512];
    if (size > sizeof(magnitude)) {
        return false;
    }
    uint32_t carry = negative ? 1U : 0U;
    for (size_t i = size; i > 0; --i) {
        uint32_t value = static_cast<uint32_t>(data[i - 1]);
        if (negative) {
            value = (~value & 0xFFU) + carry;
            carry = value >> 8;
            value &= 0xFFU;
        }
        magnitude[i - 1] = static_cast<uint8_t>(value);
    }

    char digits[kDecimalDigits];
    size_t count = 1;
    digits[0] = '0';
    for (size_t i = 0; i < size; ++i) {
        uint32_t value = magnitude[i];
        for (size_t d = 0; d < count; ++d) {
            const uint32_t total =
                static_cast<uint32_t>(digits[d] - '0') * 256U + value;
            digits[d] = static_cast<char>('0' + (total % 10U));
            value = total / 10U;
        }
        while (value != 0) {
            if (count >= sizeof(digits)) {
                return false;
            }
            digits[count++] = static_cast<char>('0' + (value % 10U));
            value /= 10U;
        }
    }
    while (count > 1 && digits[count - 1] == '0') {
        --count;
    }
    const size_t total = count + (negative ? 1 : 0);
    if (total + 1 > capacity) {
        return false;
    }
    size_t pos = 0;
    if (negative) {
        out[pos++] = '-';
    }
    for (size_t i = count; i > 0; --i) {
        out[pos++] = digits[i - 1];
    }
    out[pos] = '\0';
    *outNegative = negative;
    return true;
}

/* 比较自身产出的规范十进制文本与 schema 边界文本。 */
bool compareDecimalText(const char *left, size_t leftSize, const char *right,
                        size_t rightSize, int *outOrder)
{
    if (left == nullptr || right == nullptr || outOrder == nullptr) {
        return false;
    }
    size_t li = 0;
    size_t ri = 0;
    const bool lneg = leftSize != 0 && left[0] == '-';
    const bool rneg = rightSize != 0 && right[0] == '-';
    if (lneg) {
        ++li;
    }
    if (rneg) {
        ++ri;
    }
    if (leftSize <= li || rightSize <= ri) {
        return false;
    }
    if (lneg != rneg) {
        *outOrder = lneg ? -1 : 1;
        return true;
    }
    const size_t ldigits = leftSize - li;
    const size_t rdigits = rightSize - ri;
    int order = 0;
    if (ldigits != rdigits) {
        order = ldigits < rdigits ? -1 : 1;
    } else {
        for (size_t i = 0; i < ldigits; ++i) {
            if (left[li + i] != right[ri + i]) {
                order = left[li + i] < right[ri + i] ? -1 : 1;
                break;
            }
        }
    }
    *outOrder = lneg ? -order : order;
    return true;
}

bool parseSmallDecimal(const char *text, int64_t *outValue)
{
    if (text == nullptr || *text == '\0') {
        return false;
    }
    bool negative = false;
    size_t pos = 0;
    if (text[0] == '-') {
        negative = true;
        pos = 1;
    }
    if (text[pos] == '\0') {
        return false;
    }
    int64_t value = 0;
    for (; text[pos] != '\0'; ++pos) {
        if (text[pos] < '0' || text[pos] > '9') {
            return false;
        }
        if (value > (INT64_MAX - 9) / 10) {
            return false;
        }
        value = value * 10 + (text[pos] - '0');
    }
    *outValue = negative ? -value : value;
    return true;
}

bool compareToBound(const char *value, size_t valueSize,
                    const asnber::SchemaBound &bound, int *outOrder)
{
    if (bound.hasDecimal) {
        return compareDecimalText(value, valueSize, bound.decimal,
                                  bound.decimalSize, outOrder);
    }
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "%lld",
                  static_cast<long long>(bound.value));
    return compareDecimalText(value, valueSize, buffer,
                              std::strlen(buffer), outOrder);
}

/* 汇总基本节点内容长度（构造字符串按子节点累加）。 */
size_t primitiveLength(const asnber::Node *node)
{
    if (!((node->flags & asnber::kNodeFlagConstructed) != 0)) {
        return node->contentSize;
    }
    size_t total = 0;
    for (const asnber::Node *child = node->firstChild; child != nullptr;
         child = child->nextSibling) {
        total += primitiveLength(child);
    }
    return total;
}

int evalSimpleConstraint(BindContext &bind,
                         const asnber::SchemaConstraint &constraint,
                         const asnber::Node *node, const char *path)
{
    if (constraint.kind == ASNBER_CONSTRAINT_SIZE) {
        const size_t length = primitiveLength(node);
        if (!constraint.lowerUnbounded &&
            length < static_cast<size_t>(constraint.lower.value)) {
            asnber::contextSetErrorWithPath(bind.ctx, ASNBER_E_SCHEMA_CONSTRAINT,
                                          node->tlvOffset, node->depth, path);
            return ASNBER_E_SCHEMA_CONSTRAINT;
        }
        if (!constraint.upperUnbounded &&
            length > static_cast<size_t>(constraint.upper.value)) {
            asnber::contextSetErrorWithPath(bind.ctx, ASNBER_E_SCHEMA_CONSTRAINT,
                                          node->tlvOffset, node->depth, path);
            return ASNBER_E_SCHEMA_CONSTRAINT;
        }
        return ASNBER_OK;
    }

    /*
     * 数值约束只接受基本编码的数值节点。通用标签下允许 INTEGER 与
     * ENUMERATED；非通用标签（IMPLICIT 覆盖）由类型自身决定语义，
     * 此处只拒绝构造形态。
     */
    const bool constructed =
        (node->flags & asnber::kNodeFlagConstructed) != 0;
    const bool universalNumeric =
        node->tagClass == ASNBER_TAG_UNIVERSAL &&
        (node->tagNumber == 2 || node->tagNumber == 10);
    if (constructed ||
        (node->tagClass == ASNBER_TAG_UNIVERSAL && !universalNumeric)) {
        asnber::contextSetErrorWithPath(bind.ctx, ASNBER_E_SCHEMA_CONSTRAINT,
                                      node->tlvOffset, node->depth, path);
        return ASNBER_E_SCHEMA_CONSTRAINT;
    }

    char decimal[kDecimalDigits];
    bool negative = false;
    if (!integerToDecimal(node->content, node->contentSize, decimal,
                          sizeof(decimal), &negative)) {
        asnber::contextSetErrorWithPath(bind.ctx, ASNBER_E_SCHEMA_CONSTRAINT,
                                      node->tlvOffset, node->depth, path);
        return ASNBER_E_SCHEMA_CONSTRAINT;
    }
    if (constraint.kind == ASNBER_CONSTRAINT_ENUM) {
        int64_t value = 0;
        if (!parseSmallDecimal(decimal, &value)) {
            asnber::contextSetErrorWithPath(bind.ctx, ASNBER_E_SCHEMA_CONSTRAINT,
                                          node->tlvOffset, node->depth, path);
            return ASNBER_E_SCHEMA_CONSTRAINT;
        }
        bool found = false;
        for (uint32_t i = 0; i < constraint.enumCount; ++i) {
            if (constraint.enumValues[i] == value) {
                found = true;
                break;
            }
        }
        if (!found) {
            asnber::contextSetErrorWithPath(bind.ctx, ASNBER_E_SCHEMA_CONSTRAINT,
                                          node->tlvOffset, node->depth, path);
            return ASNBER_E_SCHEMA_CONSTRAINT;
        }
        return ASNBER_OK;
    }

    int order = 0;
    if (!constraint.lowerUnbounded) {
        if (!compareToBound(decimal, std::strlen(decimal), constraint.lower,
                            &order)) {
            asnber::contextSetErrorWithPath(bind.ctx, ASNBER_E_SCHEMA_CONSTRAINT,
                                          node->tlvOffset, node->depth, path);
            return ASNBER_E_SCHEMA_CONSTRAINT;
        }
        if (order < 0) {
            asnber::contextSetErrorWithPath(bind.ctx, ASNBER_E_SCHEMA_CONSTRAINT,
                                          node->tlvOffset, node->depth, path);
            return ASNBER_E_SCHEMA_CONSTRAINT;
        }
    }
    if (!constraint.upperUnbounded) {
        if (!compareToBound(decimal, std::strlen(decimal), constraint.upper,
                            &order)) {
            asnber::contextSetErrorWithPath(bind.ctx, ASNBER_E_SCHEMA_CONSTRAINT,
                                          node->tlvOffset, node->depth, path);
            return ASNBER_E_SCHEMA_CONSTRAINT;
        }
        if (order > 0) {
            asnber::contextSetErrorWithPath(bind.ctx, ASNBER_E_SCHEMA_CONSTRAINT,
                                          node->tlvOffset, node->depth, path);
            return ASNBER_E_SCHEMA_CONSTRAINT;
        }
    }
    return ASNBER_OK;
}

} /* namespace */

int evalConstraints(BindContext &bind, const asnber::SchemaConstraint *constraints,
                    uint32_t count, const asnber::Node *node,
                    const char *path)
{
    for (uint32_t i = 0; i < count; ++i) {
        const int rc = evalSimpleConstraint(bind, constraints[i], node, path);
        if (rc != ASNBER_OK) {
            return rc;
        }
    }
    return ASNBER_OK;
}

} /* namespace schema_decode_detail */
} /* namespace asnber */
