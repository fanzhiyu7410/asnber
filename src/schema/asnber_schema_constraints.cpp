/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * schema 运行时注册：约束校验与复制。
 *
 * 职责：规范十进制文本比较、约束描述自洽校验、约束数组深拷贝与释放。
 * 依赖：schema/asnber_schema.h。
 */

#include <cstring>

#include "schema/detail/schema_internal.h"

namespace asnber {

namespace {

bool validDecimalText(const char *text, size_t size) noexcept
{
    if (text == nullptr || size == 0) {
        return false;
    }
    size_t pos = 0;
    bool negative = false;
    if (text[pos] == '-') {
        negative = true;
        ++pos;
        if (pos == size) {
            return false;
        }
    }
    const size_t digits = size - pos;
    if (digits > 1 && text[pos] == '0') {
        return false;
    }
    for (; pos < size; ++pos) {
        if (text[pos] < '0' || text[pos] > '9') {
            return false;
        }
    }
    if (negative && digits == 1 && text[size - 1] == '0') {
        return false; /* "-0" 非法 */
    }
    return true;
}

} /* namespace */

bool schemaCompareDecimal(const char *left, size_t leftSize,
                          const char *right, size_t rightSize,
                          int *outOrder) noexcept
{
    if (outOrder == nullptr || !validDecimalText(left, leftSize) ||
        !validDecimalText(right, rightSize)) {
        return false;
    }
    bool leftNegative = leftSize > 0 && left[0] == '-';
    bool rightNegative = rightSize > 0 && right[0] == '-';
    size_t leftPos = leftNegative ? 1 : 0;
    size_t rightPos = rightNegative ? 1 : 0;
    size_t leftDigits = leftSize - leftPos;
    size_t rightDigits = rightSize - rightPos;

    int magnitude;
    if (leftDigits != rightDigits) {
        magnitude = leftDigits < rightDigits ? -1 : 1;
    } else {
        magnitude = 0;
        for (size_t i = 0; i < leftDigits; ++i) {
            const char lc = left[leftPos + i];
            const char rc = right[rightPos + i];
            if (lc != rc) {
                magnitude = lc < rc ? -1 : 1;
                break;
            }
        }
    }

    if (leftNegative != rightNegative) {
        *outOrder = leftNegative ? -1 : 1;
    } else if (leftNegative) {
        *outOrder = -magnitude;
    } else {
        *outOrder = magnitude;
    }
    return true;
}

namespace schema_detail {

/* 校验公共 bound 描述；返回 ASNBER_OK 表示可复制。 */
asnber_err_t validateBoundDesc(Context *ctx, const asnber_bound_t &bound) noexcept
{
    if (bound.struct_size != sizeof(asnber_bound_t) || bound.reserved != 0) {
        contextSetError(ctx, ASNBER_E_INVALID_CONFIG, SIZE_MAX, 0);
        return ASNBER_E_INVALID_CONFIG;
    }
    if (bound.is_unbounded != 0 && bound.is_unbounded != 1) {
        contextSetError(ctx, ASNBER_E_INVALID_CONFIG, SIZE_MAX, 0);
        return ASNBER_E_INVALID_CONFIG;
    }
    if (bound.decimal == nullptr && bound.decimal_size != 0) {
        contextSetError(ctx, ASNBER_E_INVALID_ARG, SIZE_MAX, 0);
        return ASNBER_E_INVALID_ARG;
    }
    if (bound.decimal != nullptr && bound.decimal_size == 0) {
        contextSetError(ctx, ASNBER_E_INVALID_ARG, SIZE_MAX, 0);
        return ASNBER_E_INVALID_ARG;
    }
    if (bound.decimal != nullptr &&
        !validDecimalText(bound.decimal, bound.decimal_size)) {
        contextSetError(ctx, ASNBER_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
        return ASNBER_E_SCHEMA_CONSTRAINT;
    }
    return ASNBER_OK;
}

asnber_err_t validateConstraintDesc(Context *ctx,
                                  const asnber_constraint_t &constraint) noexcept
{
    if (constraint.struct_size != sizeof(asnber_constraint_t) ||
        constraint.flags != 0 || constraint.reserved[0] != 0 ||
        constraint.reserved[1] != 0) {
        contextSetError(ctx, ASNBER_E_INVALID_CONFIG, SIZE_MAX, 0);
        return ASNBER_E_INVALID_CONFIG;
    }
    const uint32_t kind = static_cast<uint32_t>(constraint.kind);
    if (kind > static_cast<uint32_t>(ASNBER_CONSTRAINT_BIGINT_RANGE)) {
        contextSetError(ctx, ASNBER_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
        return ASNBER_E_SCHEMA_CONSTRAINT;
    }

    if (kind == static_cast<uint32_t>(ASNBER_CONSTRAINT_ENUM)) {
        if (constraint.enum_values == nullptr || constraint.enum_count == 0) {
            contextSetError(ctx, ASNBER_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
            return ASNBER_E_SCHEMA_CONSTRAINT;
        }
        for (uint32_t i = 0; i < constraint.enum_count; ++i) {
            for (uint32_t j = i + 1; j < constraint.enum_count; ++j) {
                if (constraint.enum_values[i] == constraint.enum_values[j]) {
                    contextSetError(ctx, ASNBER_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
                    return ASNBER_E_SCHEMA_CONSTRAINT;
                }
            }
        }
        return ASNBER_OK;
    }
    if (constraint.enum_values != nullptr || constraint.enum_count != 0) {
        contextSetError(ctx, ASNBER_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
        return ASNBER_E_SCHEMA_CONSTRAINT;
    }

    asnber_err_t rc = validateBoundDesc(ctx, constraint.lower);
    if (rc != ASNBER_OK) {
        return rc;
    }
    rc = validateBoundDesc(ctx, constraint.upper);
    if (rc != ASNBER_OK) {
        return rc;
    }

    switch (kind) {
    case static_cast<uint32_t>(ASNBER_CONSTRAINT_RANGE):
        if (constraint.lower.is_unbounded == 0 &&
            constraint.upper.is_unbounded == 0) {
            if (constraint.lower.decimal != nullptr &&
                constraint.upper.decimal != nullptr) {
                int order = 0;
                if (!schemaCompareDecimal(constraint.lower.decimal,
                                          constraint.lower.decimal_size,
                                          constraint.upper.decimal,
                                          constraint.upper.decimal_size,
                                          &order) ||
                    order > 0) {
                    contextSetError(ctx, ASNBER_E_SCHEMA_CONSTRAINT, SIZE_MAX,
                                    0);
                    return ASNBER_E_SCHEMA_CONSTRAINT;
                }
            } else if (constraint.lower.value > constraint.upper.value) {
                contextSetError(ctx, ASNBER_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
                return ASNBER_E_SCHEMA_CONSTRAINT;
            }
        }
        break;
    case static_cast<uint32_t>(ASNBER_CONSTRAINT_SIZE):
        if (constraint.lower.is_unbounded != 0 || constraint.lower.value < 0) {
            contextSetError(ctx, ASNBER_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
            return ASNBER_E_SCHEMA_CONSTRAINT;
        }
        if (constraint.upper.is_unbounded == 0 &&
            constraint.upper.value < constraint.lower.value) {
            contextSetError(ctx, ASNBER_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
            return ASNBER_E_SCHEMA_CONSTRAINT;
        }
        break;
    case static_cast<uint32_t>(ASNBER_CONSTRAINT_MAX):
        if (constraint.upper.is_unbounded != 1 ||
            constraint.lower.is_unbounded != 0 ||
            constraint.lower.value != 0 ||
            constraint.lower.decimal != nullptr ||
            constraint.upper.decimal != nullptr) {
            contextSetError(ctx, ASNBER_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
            return ASNBER_E_SCHEMA_CONSTRAINT;
        }
        break;
    case static_cast<uint32_t>(ASNBER_CONSTRAINT_BIGINT_RANGE):
        if (constraint.lower.decimal == nullptr &&
            constraint.upper.decimal == nullptr) {
            contextSetError(ctx, ASNBER_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
            return ASNBER_E_SCHEMA_CONSTRAINT;
        }
        if (constraint.lower.decimal != nullptr &&
            constraint.upper.decimal != nullptr) {
            int order = 0;
            if (!schemaCompareDecimal(constraint.lower.decimal,
                                      constraint.lower.decimal_size,
                                      constraint.upper.decimal,
                                      constraint.upper.decimal_size,
                                      &order) ||
                order > 0) {
                contextSetError(ctx, ASNBER_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
                return ASNBER_E_SCHEMA_CONSTRAINT;
            }
        }
        break;
    default:
        break;
    }
    return ASNBER_OK;
}

/* ===== 约束复制 ===== */

void destroyConstraintArray(Context *ctx, SchemaConstraint *constraints,
                            uint32_t count) noexcept
{
    if (constraints == nullptr) {
        return;
    }
    for (uint32_t i = 0; i < count; ++i) {
        contextRelease(ctx, const_cast<char *>(constraints[i].lower.decimal));
        contextRelease(ctx, const_cast<char *>(constraints[i].upper.decimal));
        contextRelease(ctx, const_cast<int64_t *>(constraints[i].enumValues));
    }
    contextRelease(ctx, constraints);
}

asnber_err_t copyBound(Context *ctx, const asnber_bound_t &src,
                     SchemaBound *dst) noexcept
{
    dst->unbounded = src.is_unbounded != 0;
    dst->hasDecimal = src.decimal != nullptr && src.decimal_size != 0;
    dst->value = src.value;
    dst->decimal = nullptr;
    dst->decimalSize = 0;
    if (dst->hasDecimal) {
        char *copied = nullptr;
        void *raw = nullptr;
        const asnber_err_t rc = allocateSchema(ctx, src.decimal_size, &raw);
        if (rc != ASNBER_OK) {
            return rc;
        }
        copied = static_cast<char *>(raw);
        std::memcpy(copied, src.decimal, src.decimal_size);
        dst->decimal = copied;
        dst->decimalSize = src.decimal_size;
    }
    return ASNBER_OK;
}

asnber_err_t copyConstraints(Context *ctx, const asnber_constraint_t *src,
                           uint32_t count, SchemaConstraint **out,
                           uint32_t *outCount) noexcept
{
    *out = nullptr;
    *outCount = 0;
    if (count == 0) {
        return ASNBER_OK;
    }
    if (src == nullptr ||
        countOverflowsSize(static_cast<size_t>(count),
                           sizeof(SchemaConstraint))) {
        contextSetError(ctx, ASNBER_E_INVALID_ARG, SIZE_MAX, 0);
        return ASNBER_E_INVALID_ARG;
    }

    SchemaConstraint *array = nullptr;
    void *raw = nullptr;
    asnber_err_t rc = allocateSchema(ctx, count * sizeof(SchemaConstraint), &raw);
    if (rc != ASNBER_OK) {
        return rc;
    }
    array = static_cast<SchemaConstraint *>(raw);
    std::memset(array, 0, count * sizeof(SchemaConstraint));

    for (uint32_t i = 0; i < count; ++i) {
        rc = validateConstraintDesc(ctx, src[i]);
        if (rc != ASNBER_OK) {
            destroyConstraintArray(ctx, array, i);
            return rc;
        }
        array[i].kind = static_cast<uint32_t>(src[i].kind);
        array[i].lowerUnbounded = src[i].lower.is_unbounded != 0;
        array[i].upperUnbounded = src[i].upper.is_unbounded != 0;

        if (array[i].kind == static_cast<uint32_t>(ASNBER_CONSTRAINT_ENUM)) {
            if (countOverflowsSize(static_cast<size_t>(src[i].enum_count),
                                   sizeof(int64_t))) {
                destroyConstraintArray(ctx, array, i);
                contextSetError(ctx, ASNBER_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
                return ASNBER_E_SCHEMA_CONSTRAINT;
            }
            void *enumRaw = nullptr;
            rc = allocateSchema(ctx, src[i].enum_count * sizeof(int64_t),
                                &enumRaw);
            if (rc != ASNBER_OK) {
                destroyConstraintArray(ctx, array, i);
                return rc;
            }
            int64_t *values = static_cast<int64_t *>(enumRaw);
            std::memcpy(values, src[i].enum_values,
                        src[i].enum_count * sizeof(int64_t));
            array[i].enumValues = values;
            array[i].enumCount = src[i].enum_count;
            continue;
        }

        rc = copyBound(ctx, src[i].lower, &array[i].lower);
        if (rc != ASNBER_OK) {
            destroyConstraintArray(ctx, array, i);
            return rc;
        }
        rc = copyBound(ctx, src[i].upper, &array[i].upper);
        if (rc != ASNBER_OK) {
            destroyConstraintArray(ctx, array, i);
            return rc;
        }
    }

    *out = array;
    *outCount = count;
    return ASNBER_OK;
}

/* 封存期内部约束复检。 */
asnber_err_t validateSchemaConstraint(Context *ctx,
                                    const SchemaConstraint &c) noexcept
{
    const uint32_t kind = c.kind;
    if (kind > static_cast<uint32_t>(ASNBER_CONSTRAINT_BIGINT_RANGE)) {
        contextSetError(ctx, ASNBER_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
        return ASNBER_E_SCHEMA_CONSTRAINT;
    }
    if (kind == static_cast<uint32_t>(ASNBER_CONSTRAINT_ENUM)) {
        if (c.enumValues == nullptr || c.enumCount == 0) {
            contextSetError(ctx, ASNBER_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
            return ASNBER_E_SCHEMA_CONSTRAINT;
        }
        for (uint32_t i = 0; i < c.enumCount; ++i) {
            for (uint32_t j = i + 1; j < c.enumCount; ++j) {
                if (c.enumValues[i] == c.enumValues[j]) {
                    contextSetError(ctx, ASNBER_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
                    return ASNBER_E_SCHEMA_CONSTRAINT;
                }
            }
        }
        return ASNBER_OK;
    }

    const SchemaBound *bounds[2] = {&c.lower, &c.upper};
    for (const SchemaBound *bound : bounds) {
        if (bound->hasDecimal && !validDecimalText(bound->decimal,
                                                   bound->decimalSize)) {
            contextSetError(ctx, ASNBER_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
            return ASNBER_E_SCHEMA_CONSTRAINT;
        }
    }

    switch (kind) {
    case static_cast<uint32_t>(ASNBER_CONSTRAINT_RANGE):
        if (!c.lower.unbounded && !c.upper.unbounded) {
            if (c.lower.hasDecimal && c.upper.hasDecimal) {
                int order = 0;
                if (!schemaCompareDecimal(c.lower.decimal, c.lower.decimalSize,
                                          c.upper.decimal, c.upper.decimalSize,
                                          &order) ||
                    order > 0) {
                    contextSetError(ctx, ASNBER_E_SCHEMA_CONSTRAINT, SIZE_MAX,
                                    0);
                    return ASNBER_E_SCHEMA_CONSTRAINT;
                }
            } else if (c.lower.value > c.upper.value) {
                contextSetError(ctx, ASNBER_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
                return ASNBER_E_SCHEMA_CONSTRAINT;
            }
        }
        break;
    case static_cast<uint32_t>(ASNBER_CONSTRAINT_SIZE):
        if (c.lower.unbounded || c.lower.value < 0) {
            contextSetError(ctx, ASNBER_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
            return ASNBER_E_SCHEMA_CONSTRAINT;
        }
        if (!c.upper.unbounded && c.upper.value < c.lower.value) {
            contextSetError(ctx, ASNBER_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
            return ASNBER_E_SCHEMA_CONSTRAINT;
        }
        break;
    case static_cast<uint32_t>(ASNBER_CONSTRAINT_MAX):
        if (!c.upper.unbounded || c.lower.unbounded || c.lower.value != 0 ||
            c.lower.hasDecimal || c.upper.hasDecimal) {
            contextSetError(ctx, ASNBER_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
            return ASNBER_E_SCHEMA_CONSTRAINT;
        }
        break;
    case static_cast<uint32_t>(ASNBER_CONSTRAINT_BIGINT_RANGE):
        if (!c.lower.hasDecimal && !c.upper.hasDecimal) {
            contextSetError(ctx, ASNBER_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
            return ASNBER_E_SCHEMA_CONSTRAINT;
        }
        if (c.lower.hasDecimal && c.upper.hasDecimal) {
            int order = 0;
            if (!schemaCompareDecimal(c.lower.decimal, c.lower.decimalSize,
                                      c.upper.decimal, c.upper.decimalSize,
                                      &order) ||
                order > 0) {
                contextSetError(ctx, ASNBER_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
                return ASNBER_E_SCHEMA_CONSTRAINT;
            }
        }
        break;
    default:
        break;
    }
    return ASNBER_OK;
}

asnber_err_t validateSchemaConstraintArray(Context *ctx,
                                         const SchemaConstraint *array,
                                         uint32_t count) noexcept
{
    for (uint32_t i = 0; i < count; ++i) {
        const asnber_err_t rc = validateSchemaConstraint(ctx, array[i]);
        if (rc != ASNBER_OK) {
            return rc;
        }
    }
    return ASNBER_OK;
}

} /* namespace schema_detail */
} /* namespace asnber */
