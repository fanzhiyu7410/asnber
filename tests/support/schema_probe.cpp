/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * 测试专用 schema 探针实现。包含内部头以读取类型树，仅用于测试断言。
 */

#include "schema_probe.h"

#include <cstring>

#include "schema/asnber_schema.h"

namespace {

const asnber::Schema *schemaOf(const asnber_schema_t *handle) noexcept
{
    if (handle == nullptr) {
        return nullptr;
    }
    const asnber::Schema *schema =
        static_cast<const asnber::Schema *>(
            static_cast<const void *>(handle));
    if (schema->magic != asnber::kSchemaMagic) {
        return nullptr;
    }
    return schema;
}

int copyName(const char *src, char *dst, size_t capacity) noexcept
{
    if (src == nullptr) {
        return 0;
    }
    const size_t len = std::strlen(src);
    if (len + 1 > capacity) {
        return 0;
    }
    std::memcpy(dst, src, len + 1);
    return 1;
}

void fillBound(const asnber::SchemaBound &bound,
               asnber_test_bound_info *out) noexcept
{
    out->is_unbounded = bound.unbounded ? 1 : 0;
    out->value = bound.value;
    out->decimal_size = bound.decimalSize;
    out->decimal[0] = '\0';
    if (bound.decimal != nullptr && bound.decimalSize > 0 &&
        bound.decimalSize < sizeof(out->decimal)) {
        std::memcpy(out->decimal, bound.decimal, bound.decimalSize);
        out->decimal[bound.decimalSize] = '\0';
    }
}

int fillConstraint(const asnber::SchemaConstraint &constraint,
                   asnber_test_constraint_info *out) noexcept
{
    std::memset(out, 0, sizeof(*out));
    out->kind = constraint.kind;
    out->lower_unbounded = constraint.lowerUnbounded ? 1 : 0;
    out->upper_unbounded = constraint.upperUnbounded ? 1 : 0;
    fillBound(constraint.lower, &out->lower);
    fillBound(constraint.upper, &out->upper);
    if (constraint.kind ==
        static_cast<uint32_t>(ASNBER_CONSTRAINT_ENUM)) {
        if (constraint.enumCount > ASNBER_TEST_MAX_ENUM) {
            return 0;
        }
        out->enum_count = constraint.enumCount;
        for (uint32_t i = 0; i < constraint.enumCount; ++i) {
            out->enum_values[i] = constraint.enumValues[i];
        }
    }
    return 1;
}

} /* namespace */

extern "C" uint32_t asnber_test_schema_type_count(
    const asnber_schema_t *schema)
{
    const asnber::Schema *internal = schemaOf(schema);
    return internal == nullptr ? 0 : internal->typeCount;
}

extern "C" uint32_t asnber_test_schema_module_tag_mode(
    const asnber_schema_t *schema)
{
    const asnber::Schema *internal = schemaOf(schema);
    return internal == nullptr ? 0 : internal->moduleTagMode;
}

extern "C" uint32_t asnber_test_schema_root_type_id(
    const asnber_schema_t *schema)
{
    const asnber::Schema *internal = schemaOf(schema);
    return internal == nullptr ? 0 : internal->rootTypeId;
}

extern "C" int asnber_test_schema_sealed(const asnber_schema_t *schema)
{
    const asnber::Schema *internal = schemaOf(schema);
    return internal != nullptr && internal->sealed ? 1 : 0;
}

extern "C" int asnber_test_schema_type_info(const asnber_schema_t *schema,
                                          uint32_t type_id,
                                          asnber_test_type_info *out)
{
    const asnber::Schema *internal = schemaOf(schema);
    if (internal == nullptr || out == nullptr || type_id == 0 ||
        type_id > internal->typeCount) {
        return 0;
    }
    const asnber::SchemaType &type = internal->types[type_id - 1];
    std::memset(out, 0, sizeof(*out));
    if (!copyName(type.name, out->name, sizeof(out->name))) {
        return 0;
    }
    out->kind = type.kind;
    out->tag_class = type.tagClass;
    out->tag_number = type.tagNumber;
    out->tag_mode = type.tagMode;
    out->element_type_id = type.elementTypeId;
    out->flags = type.flags;
    out->field_count = type.fieldCount;
    out->constraint_count = type.constraintCount;
    return 1;
}

extern "C" int asnber_test_schema_field_info(const asnber_schema_t *schema,
                                           uint32_t type_id, uint32_t index,
                                           asnber_test_field_info *out)
{
    const asnber::Schema *internal = schemaOf(schema);
    if (internal == nullptr || out == nullptr || type_id == 0 ||
        type_id > internal->typeCount) {
        return 0;
    }
    const asnber::SchemaType &type = internal->types[type_id - 1];
    if (index >= type.fieldCount) {
        return 0;
    }
    const asnber::SchemaField &field = type.fields[index];
    std::memset(out, 0, sizeof(*out));
    if (!copyName(field.name, out->name, sizeof(out->name))) {
        return 0;
    }
    out->type_id = field.typeId;
    out->flags = field.flags;
    out->default_size = field.defaultSize;
    out->constraint_count = field.constraintCount;
    return 1;
}

extern "C" int asnber_test_schema_type_constraint(
    const asnber_schema_t *schema, uint32_t type_id, uint32_t index,
    asnber_test_constraint_info *out)
{
    const asnber::Schema *internal = schemaOf(schema);
    if (internal == nullptr || out == nullptr || type_id == 0 ||
        type_id > internal->typeCount) {
        return 0;
    }
    const asnber::SchemaType &type = internal->types[type_id - 1];
    if (index >= type.constraintCount) {
        return 0;
    }
    return fillConstraint(type.constraints[index], out);
}

extern "C" int asnber_test_schema_field_constraint(
    const asnber_schema_t *schema, uint32_t type_id, uint32_t field_index,
    uint32_t index, asnber_test_constraint_info *out)
{
    const asnber::Schema *internal = schemaOf(schema);
    if (internal == nullptr || out == nullptr || type_id == 0 ||
        type_id > internal->typeCount) {
        return 0;
    }
    const asnber::SchemaType &type = internal->types[type_id - 1];
    if (field_index >= type.fieldCount) {
        return 0;
    }
    const asnber::SchemaField &field = type.fields[field_index];
    if (index >= field.constraintCount) {
        return 0;
    }
    return fillConstraint(field.constraints[index], out);
}

extern "C" const uint8_t *asnber_test_schema_field_default(
    const asnber_schema_t *schema, uint32_t type_id, uint32_t field_index,
    size_t *out_size)
{
    const asnber::Schema *internal = schemaOf(schema);
    if (out_size != nullptr) {
        *out_size = 0;
    }
    if (internal == nullptr || type_id == 0 ||
        type_id > internal->typeCount) {
        return nullptr;
    }
    const asnber::SchemaType &type = internal->types[type_id - 1];
    if (field_index >= type.fieldCount) {
        return nullptr;
    }
    const asnber::SchemaField &field = type.fields[field_index];
    if (out_size != nullptr) {
        *out_size = field.defaultSize;
    }
    return field.defaultTlv;
}
