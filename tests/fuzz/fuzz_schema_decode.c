/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * libFuzzer harness：schema 感知解码与 asnber_doc_validate。
 *
 * 固定 schema 各跑一遍：PKIX 表（真实描述表）、最小手工表，以及一份
 * 覆盖各 kind/约束/标签形态的富表。所有 schema 与上下文进程内只建一次，
 * 解码必须使用 schema 所属的上下文（跨上下文会被前置校验拒绝）。
 */
#include <asnber/asnber.h>
#include <pkix_schema.h>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "fuzz_common.h"

static asnber_ctx_t    *g_ctx = NULL;
static asnber_ctx_t    *g_other_ctx = NULL;
static asnber_schema_t *g_pkix_schema = NULL;
static asnber_schema_t *g_min_schema = NULL;
static asnber_schema_t *g_rich_schema = NULL;
static asnber_schema_t *g_seq_schema = NULL;
static asnber_schema_t *g_set_schema = NULL;
static asnber_schema_t *g_simple_schema = NULL;
static asnber_schema_t *g_choice_schema = NULL;
static asnber_schema_t *g_any_req_schema = NULL;
static asnber_schema_t *g_of_range_schema = NULL;
static asnber_schema_t *g_nested_schema = NULL;
static asnber_schema_t *g_expl_root_schema = NULL;
static asnber_schema_t *g_any_expl_root_schema = NULL;
static asnber_schema_t *g_unsealed_schema = NULL;
static asnber_schema_t *g_noroot_schema = NULL;
static asnber_schema_t *g_foreign_schema = NULL;
static int            g_init_done = 0;
static int            g_edge_done = 0;
static const uint8_t  kDefaultIntTlv[3] = {0x02, 0x01, 0x03};
static const uint8_t  kDefaultBoolTlv[3] = {0x01, 0x01, 0xFF};

static asnber_bound_t bound_value(int64_t value)
{
    asnber_bound_t bound;
    memset(&bound, 0, sizeof(bound));
    bound.struct_size = sizeof(bound);
    bound.value = value;
    return bound;
}

static asnber_bound_t bound_unbounded(void)
{
    asnber_bound_t bound;
    memset(&bound, 0, sizeof(bound));
    bound.struct_size = sizeof(bound);
    bound.is_unbounded = 1;
    return bound;
}

static asnber_bound_t bound_decimal(const char *text)
{
    asnber_bound_t bound;
    memset(&bound, 0, sizeof(bound));
    bound.struct_size = sizeof(bound);
    bound.decimal = text;
    bound.decimal_size = strlen(text);
    return bound;
}

static asnber_constraint_t constraint_range(int64_t lower, int64_t upper)
{
    asnber_constraint_t c;
    memset(&c, 0, sizeof(c));
    c.struct_size = sizeof(c);
    c.kind = ASNBER_CONSTRAINT_RANGE;
    c.lower = bound_value(lower);
    c.upper = bound_value(upper);
    return c;
}

static asnber_constraint_t constraint_size(int64_t lower, int64_t upper)
{
    asnber_constraint_t c;
    memset(&c, 0, sizeof(c));
    c.struct_size = sizeof(c);
    c.kind = ASNBER_CONSTRAINT_SIZE;
    c.lower = bound_value(lower);
    c.upper = bound_value(upper);
    return c;
}

static asnber_constraint_t constraint_max(int64_t lower)
{
    asnber_constraint_t c;
    memset(&c, 0, sizeof(c));
    c.struct_size = sizeof(c);
    c.kind = ASNBER_CONSTRAINT_MAX;
    c.lower = bound_value(lower);
    c.upper = bound_unbounded();
    return c;
}

static asnber_constraint_t constraint_bigint(const char *lower, const char *upper)
{
    asnber_constraint_t c;
    memset(&c, 0, sizeof(c));
    c.struct_size = sizeof(c);
    c.kind = ASNBER_CONSTRAINT_BIGINT_RANGE;
    c.lower = bound_decimal(lower);
    c.upper = bound_decimal(upper);
    return c;
}

static asnber_constraint_t constraint_enum(const int64_t *values, uint32_t count)
{
    asnber_constraint_t c;
    memset(&c, 0, sizeof(c));
    c.struct_size = sizeof(c);
    c.kind = ASNBER_CONSTRAINT_ENUM;
    c.enum_values = values;
    c.enum_count = count;
    return c;
}

static int add_type(asnber_schema_t *schema, const char *name,
                    asnber_type_kind_t kind, asnber_tag_class_t tag_class,
                    uint32_t tag_number, asnber_tag_mode_t tag_mode,
                    uint32_t element_type_id,
                    const asnber_constraint_t *constraints, uint32_t count,
                    uint32_t flags, uint32_t *out_id)
{
    asnber_type_desc_t type;
    memset(&type, 0, sizeof(type));
    type.struct_size = sizeof(type);
    type.name = name;
    type.kind = kind;
    type.tag_class = tag_class;
    type.tag_number = tag_number;
    type.tag_mode = tag_mode;
    type.element_type_id = element_type_id;
    type.flags = flags;
    type.constraints = constraints;
    type.constraint_count = count;
    return asnber_schema_add_type(schema, &type, out_id);
}

static int add_field(asnber_schema_t *schema, uint32_t parent_id,
                     const char *name, uint32_t type_id, uint32_t flags,
                     const void *default_value, size_t default_size,
                     const asnber_constraint_t *constraints, uint32_t count)
{
    asnber_field_desc_t field;
    memset(&field, 0, sizeof(field));
    field.struct_size = sizeof(field);
    field.name = name;
    field.type_id = type_id;
    field.flags = flags;
    field.default_value = default_value;
    field.default_value_size = default_size;
    field.field_constraints = constraints;
    field.field_constraint_count = count;
    return asnber_schema_add_field(schema, parent_id, &field);
}

static asnber_schema_t *build_rich_schema(void)
{
    static const int64_t kEnumValues[3] = {1, 3, 5};
    asnber_schema_t *schema = NULL;
    asnber_constraint_t c;
    uint32_t t_range = 0;
    uint32_t t_enum = 0;
    uint32_t t_enum_tagged = 0;
    uint32_t t_big = 0;
    uint32_t t_oct = 0;
    uint32_t t_max_oct = 0;
    uint32_t t_expl = 0;
    uint32_t t_impl = 0;
    uint32_t t_oid = 0;
    uint32_t t_bool = 0;
    uint32_t t_choice = 0;
    uint32_t t_elem_int = 0;
    uint32_t t_seq_of = 0;
    uint32_t t_set_of = 0;
    uint32_t t_inner_set = 0;
    uint32_t t_expl_seq = 0;
    uint32_t t_expl_choice = 0;
    uint32_t t_impl_seq = 0;
    uint32_t t_impl_set_of = 0;
    uint32_t t_impl_set = 0;
    uint32_t t_any_expl = 0;
    uint32_t t_any_bare = 0;
    uint32_t t_root = 0;

    if (asnber_schema_create(g_ctx, ASNBER_TAG_MODE_DEFAULT, &schema) != ASNBER_OK) {
        return NULL;
    }

    c = constraint_range(-5, 7);
    if (add_type(schema, "Ranged", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL,
                 2, ASNBER_TAG_MODE_DEFAULT, 0, &c, 1, 0, &t_range) != ASNBER_OK) {
        goto fail;
    }
    c = constraint_enum(kEnumValues, 3);
    if (add_type(schema, "EnumImplicit", ASNBER_TYPE_KIND_SIMPLE,
                 ASNBER_TAG_CONTEXT, 11, ASNBER_TAG_MODE_IMPLICIT, 0, &c, 1, 0,
                 &t_enum) != ASNBER_OK) {
        goto fail;
    }
    if (add_type(schema, "EnumTagged", ASNBER_TYPE_KIND_SIMPLE,
                 ASNBER_TAG_UNIVERSAL, 10, ASNBER_TAG_MODE_DEFAULT, 0, &c, 1, 0,
                 &t_enum_tagged) != ASNBER_OK) {
        goto fail;
    }
    c = constraint_bigint("-100000000000000000000", "100000000000000000000");
    if (add_type(schema, "BigInt", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_CONTEXT, 6,
                 ASNBER_TAG_MODE_IMPLICIT, 0, &c, 1, 0, &t_big) != ASNBER_OK) {
        goto fail;
    }
    c = constraint_size(2, 4);
    if (add_type(schema, "OctetSized", ASNBER_TYPE_KIND_SIMPLE,
                 ASNBER_TAG_UNIVERSAL, 4, ASNBER_TAG_MODE_DEFAULT, 0, &c, 1, 0,
                 &t_oct) != ASNBER_OK) {
        goto fail;
    }
    c = constraint_max(0);
    if (add_type(schema, "MaxOctet", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_CONTEXT,
                 7, ASNBER_TAG_MODE_IMPLICIT, 0, &c, 1, 0, &t_max_oct) !=
        ASNBER_OK) {
        goto fail;
    }
    c = constraint_range(0, 10);
    if (add_type(schema, "ExplicitInt", ASNBER_TYPE_KIND_SIMPLE,
                 ASNBER_TAG_CONTEXT, 0, ASNBER_TAG_MODE_EXPLICIT, 0, &c, 1, 0,
                 &t_expl) != ASNBER_OK) {
        goto fail;
    }
    if (add_type(schema, "ImplicitInt", ASNBER_TYPE_KIND_SIMPLE,
                 ASNBER_TAG_CONTEXT, 5, ASNBER_TAG_MODE_IMPLICIT, 0, &c, 1, 0,
                 &t_impl) != ASNBER_OK) {
        goto fail;
    }
    if (add_type(schema, "Oid", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 6,
                 ASNBER_TAG_MODE_DEFAULT, 0, NULL, 0, 0, &t_oid) != ASNBER_OK) {
        goto fail;
    }
    if (add_type(schema, "Flag", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 1,
                 ASNBER_TAG_MODE_DEFAULT, 0, NULL, 0, 0, &t_bool) != ASNBER_OK) {
        goto fail;
    }
    if (add_type(schema, "Choice", ASNBER_TYPE_KIND_CHOICE, ASNBER_TAG_UNIVERSAL,
                 0, ASNBER_TAG_MODE_DEFAULT, 0, NULL, 0, 0, &t_choice) !=
        ASNBER_OK) {
        goto fail;
    }
    if (add_field(schema, t_choice, "oid", t_oid, 0, NULL, 0, NULL, 0) !=
            ASNBER_OK ||
        add_field(schema, t_choice, "flag", t_bool, 0, NULL, 0, NULL, 0) !=
            ASNBER_OK) {
        goto fail;
    }
    if (add_type(schema, "ElemInt", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL,
                 2, ASNBER_TAG_MODE_DEFAULT, 0, NULL, 0, 0, &t_elem_int) !=
        ASNBER_OK) {
        goto fail;
    }
    c = constraint_size(1, 3);
    if (add_type(schema, "SeqOfOid", ASNBER_TYPE_KIND_SEQUENCE_OF,
                 ASNBER_TAG_CONTEXT, 9, ASNBER_TAG_MODE_EXPLICIT, t_oid, &c, 1, 0,
                 &t_seq_of) != ASNBER_OK) {
        goto fail;
    }
    c = constraint_size(1, 2);
    if (add_type(schema, "SetOfInt", ASNBER_TYPE_KIND_SET_OF, ASNBER_TAG_CONTEXT,
                 10, ASNBER_TAG_MODE_EXPLICIT, t_elem_int, &c, 1, 0,
                 &t_set_of) != ASNBER_OK) {
        goto fail;
    }
    if (add_type(schema, "InnerSet", ASNBER_TYPE_KIND_SET, ASNBER_TAG_CONTEXT, 8,
                 ASNBER_TAG_MODE_EXPLICIT, 0, NULL, 0, 0, &t_inner_set) !=
        ASNBER_OK) {
        goto fail;
    }
    if (add_field(schema, t_inner_set, "present", t_bool, 0, NULL, 0, NULL,
                  0) != ASNBER_OK ||
        add_field(schema, t_inner_set, "count", t_range,
                  ASNBER_FIELD_OPTIONAL, NULL, 0, NULL, 0) != ASNBER_OK) {
        goto fail;
    }
    if (add_type(schema, "ExplicitSeq", ASNBER_TYPE_KIND_SEQUENCE,
                 ASNBER_TAG_CONTEXT, 2, ASNBER_TAG_MODE_EXPLICIT, 0, NULL, 0, 0,
                 &t_expl_seq) != ASNBER_OK) {
        goto fail;
    }
    if (add_field(schema, t_expl_seq, "x", t_elem_int, 0, NULL, 0, NULL, 0) !=
        ASNBER_OK) {
        goto fail;
    }
    if (add_type(schema, "ExplicitChoice", ASNBER_TYPE_KIND_CHOICE,
                 ASNBER_TAG_CONTEXT, 12, ASNBER_TAG_MODE_EXPLICIT, 0, NULL, 0, 0,
                 &t_expl_choice) != ASNBER_OK) {
        goto fail;
    }
    if (add_field(schema, t_expl_choice, "oid", t_oid, 0, NULL, 0, NULL, 0) !=
            ASNBER_OK ||
        add_field(schema, t_expl_choice, "flag", t_bool, 0, NULL, 0, NULL,
                  0) != ASNBER_OK) {
        goto fail;
    }
    if (add_type(schema, "ImplicitSeq", ASNBER_TYPE_KIND_SEQUENCE,
                 ASNBER_TAG_CONTEXT, 13, ASNBER_TAG_MODE_IMPLICIT, 0, NULL, 0, 0,
                 &t_impl_seq) != ASNBER_OK) {
        goto fail;
    }
    if (add_field(schema, t_impl_seq, "x", t_elem_int, 0, NULL, 0, NULL, 0) !=
        ASNBER_OK) {
        goto fail;
    }
    c = constraint_size(1, 2);
    if (add_type(schema, "ImplicitSetOf", ASNBER_TYPE_KIND_SET_OF,
                 ASNBER_TAG_CONTEXT, 14, ASNBER_TAG_MODE_IMPLICIT, t_elem_int, &c,
                 1, 0, &t_impl_set_of) != ASNBER_OK) {
        goto fail;
    }
    if (add_type(schema, "ImplicitSet", ASNBER_TYPE_KIND_SET, ASNBER_TAG_CONTEXT,
                 15, ASNBER_TAG_MODE_IMPLICIT, 0, NULL, 0, 0, &t_impl_set) !=
        ASNBER_OK) {
        goto fail;
    }
    if (add_field(schema, t_impl_set, "x", t_elem_int, 0, NULL, 0, NULL, 0) !=
        ASNBER_OK) {
        goto fail;
    }
    if (add_type(schema, "ExplicitAny", ASNBER_TYPE_KIND_ANY, ASNBER_TAG_CONTEXT,
                 3, ASNBER_TAG_MODE_EXPLICIT, 0, NULL, 0, 0, &t_any_expl) !=
        ASNBER_OK) {
        goto fail;
    }
    if (add_type(schema, "BareAny", ASNBER_TYPE_KIND_ANY, ASNBER_TAG_UNIVERSAL, 0,
                 ASNBER_TAG_MODE_DEFAULT, 0, NULL, 0, 0, &t_any_bare) !=
        ASNBER_OK) {
        goto fail;
    }
    if (add_type(schema, "RichRoot", ASNBER_TYPE_KIND_SEQUENCE,
                 ASNBER_TAG_UNIVERSAL, 16, ASNBER_TAG_MODE_DEFAULT, 0, NULL, 0, 0,
                 &t_root) != ASNBER_OK) {
        goto fail;
    }
    if (add_field(schema, t_root, "ranged", t_range, 0, NULL, 0, NULL, 0) !=
            ASNBER_OK ||
        add_field(schema, t_root, "big", t_big, ASNBER_FIELD_OPTIONAL, NULL, 0,
                  NULL, 0) != ASNBER_OK ||
        add_field(schema, t_root, "enum", t_enum, ASNBER_FIELD_OPTIONAL, NULL, 0,
                  NULL, 0) != ASNBER_OK ||
        add_field(schema, t_root, "enumTagged", t_enum_tagged,
                  ASNBER_FIELD_OPTIONAL, NULL, 0, NULL, 0) != ASNBER_OK ||
        add_field(schema, t_root, "oct", t_oct, ASNBER_FIELD_OPTIONAL, NULL, 0,
                  NULL, 0) != ASNBER_OK ||
        add_field(schema, t_root, "maxOct", t_max_oct, ASNBER_FIELD_OPTIONAL,
                  NULL, 0, NULL, 0) != ASNBER_OK ||
        add_field(schema, t_root, "expl", t_expl, ASNBER_FIELD_OPTIONAL, NULL, 0,
                  NULL, 0) != ASNBER_OK ||
        add_field(schema, t_root, "impl", t_impl, ASNBER_FIELD_OPTIONAL, NULL, 0,
                  NULL, 0) != ASNBER_OK ||
        add_field(schema, t_root, "choice", t_choice, ASNBER_FIELD_OPTIONAL,
                  NULL, 0, NULL, 0) != ASNBER_OK ||
        add_field(schema, t_root, "seqOf", t_seq_of, ASNBER_FIELD_OPTIONAL,
                  NULL, 0, NULL, 0) != ASNBER_OK ||
        add_field(schema, t_root, "setOf", t_set_of, ASNBER_FIELD_OPTIONAL,
                  NULL, 0, NULL, 0) != ASNBER_OK ||
        add_field(schema, t_root, "innerSet", t_inner_set, ASNBER_FIELD_OPTIONAL,
                  NULL, 0, NULL, 0) != ASNBER_OK ||
        add_field(schema, t_root, "explSeq", t_expl_seq, ASNBER_FIELD_OPTIONAL,
                  NULL, 0, NULL, 0) != ASNBER_OK ||
        add_field(schema, t_root, "explChoice", t_expl_choice,
                  ASNBER_FIELD_OPTIONAL, NULL, 0, NULL, 0) != ASNBER_OK ||
        add_field(schema, t_root, "implSeq", t_impl_seq, ASNBER_FIELD_OPTIONAL,
                  NULL, 0, NULL, 0) != ASNBER_OK ||
        add_field(schema, t_root, "implSetOf", t_impl_set_of,
                  ASNBER_FIELD_OPTIONAL, NULL, 0, NULL, 0) != ASNBER_OK ||
        add_field(schema, t_root, "implSet", t_impl_set,
                  ASNBER_FIELD_OPTIONAL, NULL, 0, NULL, 0) != ASNBER_OK ||
        add_field(schema, t_root, "defInt", t_range, 0, kDefaultIntTlv,
                  sizeof(kDefaultIntTlv), NULL, 0) != ASNBER_OK ||
        add_field(schema, t_root, "anyExpl", t_any_expl, ASNBER_FIELD_OPTIONAL,
                  NULL, 0, NULL, 0) != ASNBER_OK ||
        add_field(schema, t_root, "anyBare", t_any_bare, ASNBER_FIELD_OPTIONAL,
                  NULL, 0, NULL, 0) != ASNBER_OK) {
        goto fail;
    }
    if (asnber_schema_set_root(schema, t_root) != ASNBER_OK ||
        asnber_schema_seal(schema) != ASNBER_OK) {
        goto fail;
    }
    return schema;

fail:
    {
        asnber_error_info_t info;
        memset(&info, 0, sizeof(info));
        info.struct_size = sizeof(info);
        (void)asnber_ctx_get_error(g_ctx, &info);
        fprintf(stderr, "rich build failed: code=%d offset=%zu path=%s\n",
                (int)info.code, info.offset, info.path ? info.path : "-");
    }
    asnber_schema_destroy(schema);
    return NULL;
}

static asnber_schema_t *build_seq_schema(void)
{
    asnber_schema_t *schema = NULL;
    uint32_t t_int = 0;
    uint32_t t_root = 0;
    if (asnber_schema_create(g_ctx, ASNBER_TAG_MODE_DEFAULT, &schema) != ASNBER_OK) {
        return NULL;
    }
    if (add_type(schema, "Int", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 2,
                 ASNBER_TAG_MODE_DEFAULT, 0, NULL, 0, 0, &t_int) != ASNBER_OK ||
        add_type(schema, "Root", ASNBER_TYPE_KIND_SEQUENCE, ASNBER_TAG_UNIVERSAL,
                 16, ASNBER_TAG_MODE_DEFAULT, 0, NULL, 0, 0, &t_root) !=
            ASNBER_OK ||
        add_field(schema, t_root, "a", t_int, 0, NULL, 0, NULL, 0) !=
            ASNBER_OK ||
        asnber_schema_set_root(schema, t_root) != ASNBER_OK ||
        asnber_schema_seal(schema) != ASNBER_OK) {
        goto fail;
    }
    return schema;
fail:
    asnber_schema_destroy(schema);
    return NULL;
}

static asnber_schema_t *build_set_schema(void)
{
    asnber_schema_t *schema = NULL;
    uint32_t t_int = 0;
    uint32_t t_oct = 0;
    uint32_t t_bool = 0;
    uint32_t t_root = 0;
    if (asnber_schema_create(g_ctx, ASNBER_TAG_MODE_DEFAULT, &schema) != ASNBER_OK) {
        return NULL;
    }
    if (add_type(schema, "Int", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 2,
                 ASNBER_TAG_MODE_DEFAULT, 0, NULL, 0, 0, &t_int) != ASNBER_OK ||
        add_type(schema, "Oct", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 4,
                 ASNBER_TAG_MODE_DEFAULT, 0, NULL, 0, 0, &t_oct) != ASNBER_OK ||
        add_type(schema, "Flag", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 1,
                 ASNBER_TAG_MODE_DEFAULT, 0, NULL, 0, 0, &t_bool) != ASNBER_OK ||
        add_type(schema, "Root", ASNBER_TYPE_KIND_SET, ASNBER_TAG_UNIVERSAL, 17,
                 ASNBER_TAG_MODE_DEFAULT, 0, NULL, 0, 0, &t_root) != ASNBER_OK ||
        add_field(schema, t_root, "a", t_int, 0, NULL, 0, NULL, 0) !=
            ASNBER_OK ||
        add_field(schema, t_root, "b", t_oct, ASNBER_FIELD_OPTIONAL, NULL, 0,
                  NULL, 0) != ASNBER_OK ||
        add_field(schema, t_root, "d", t_bool, 0, kDefaultBoolTlv,
                  sizeof(kDefaultBoolTlv), NULL, 0) != ASNBER_OK ||
        asnber_schema_set_root(schema, t_root) != ASNBER_OK ||
        asnber_schema_seal(schema) != ASNBER_OK) {
        goto fail;
    }
    return schema;
fail:
    asnber_schema_destroy(schema);
    return NULL;
}

static asnber_schema_t *build_simple_rootschema(void)
{
    asnber_schema_t *schema = NULL;
    uint32_t t_int = 0;
    if (asnber_schema_create(g_ctx, ASNBER_TAG_MODE_DEFAULT, &schema) != ASNBER_OK) {
        return NULL;
    }
    if (add_type(schema, "Int", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 2,
                 ASNBER_TAG_MODE_DEFAULT, 0, NULL, 0, 0, &t_int) != ASNBER_OK ||
        asnber_schema_set_root(schema, t_int) != ASNBER_OK ||
        asnber_schema_seal(schema) != ASNBER_OK) {
        goto fail;
    }
    return schema;
fail:
    asnber_schema_destroy(schema);
    return NULL;
}

static asnber_schema_t *build_choice_schema(void)
{
    asnber_schema_t *schema = NULL;
    uint32_t t_oid = 0;
    uint32_t t_bool = 0;
    uint32_t t_root = 0;
    if (asnber_schema_create(g_ctx, ASNBER_TAG_MODE_DEFAULT, &schema) != ASNBER_OK) {
        return NULL;
    }
    if (add_type(schema, "Oid", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 6,
                 ASNBER_TAG_MODE_DEFAULT, 0, NULL, 0, 0, &t_oid) != ASNBER_OK ||
        add_type(schema, "Flag", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 1,
                 ASNBER_TAG_MODE_DEFAULT, 0, NULL, 0, 0, &t_bool) != ASNBER_OK ||
        add_type(schema, "Root", ASNBER_TYPE_KIND_CHOICE, ASNBER_TAG_UNIVERSAL, 0,
                 ASNBER_TAG_MODE_DEFAULT, 0, NULL, 0, 0, &t_root) != ASNBER_OK ||
        add_field(schema, t_root, "oid", t_oid, 0, NULL, 0, NULL, 0) !=
            ASNBER_OK ||
        add_field(schema, t_root, "flag", t_bool, 0, NULL, 0, NULL, 0) !=
            ASNBER_OK ||
        asnber_schema_set_root(schema, t_root) != ASNBER_OK ||
        asnber_schema_seal(schema) != ASNBER_OK) {
        goto fail;
    }
    return schema;
fail:
    asnber_schema_destroy(schema);
    return NULL;
}

static asnber_schema_t *build_any_req_schema(void)
{
    asnber_schema_t *schema = NULL;
    uint32_t t_int = 0;
    uint32_t t_any = 0;
    uint32_t t_root = 0;
    if (asnber_schema_create(g_ctx, ASNBER_TAG_MODE_DEFAULT, &schema) != ASNBER_OK) {
        return NULL;
    }
    if (add_type(schema, "Int", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 2,
                 ASNBER_TAG_MODE_DEFAULT, 0, NULL, 0, 0, &t_int) != ASNBER_OK ||
        add_type(schema, "Any", ASNBER_TYPE_KIND_ANY, ASNBER_TAG_UNIVERSAL, 0,
                 ASNBER_TAG_MODE_DEFAULT, 0, NULL, 0, 0, &t_any) != ASNBER_OK ||
        add_type(schema, "Root", ASNBER_TYPE_KIND_SEQUENCE, ASNBER_TAG_UNIVERSAL,
                 16, ASNBER_TAG_MODE_DEFAULT, 0, NULL, 0, 0, &t_root) !=
            ASNBER_OK ||
        add_field(schema, t_root, "a", t_int, 0, NULL, 0, NULL, 0) !=
            ASNBER_OK ||
        add_field(schema, t_root, "any", t_any, 0, NULL, 0, NULL, 0) !=
            ASNBER_OK ||
        asnber_schema_set_root(schema, t_root) != ASNBER_OK ||
        asnber_schema_seal(schema) != ASNBER_OK) {
        goto fail;
    }
    return schema;
fail:
    asnber_schema_destroy(schema);
    return NULL;
}

/* 三层嵌套 SEQUENCE：配合 doc_validate 的低 max_depth 触发绑定期深度限制。 */
static asnber_schema_t *build_nested_schema(void)
{
    asnber_schema_t *schema = NULL;
    uint32_t t_int = 0;
    uint32_t t_leaf = 0;
    uint32_t t_mid = 0;
    uint32_t t_root = 0;
    if (asnber_schema_create(g_ctx, ASNBER_TAG_MODE_DEFAULT, &schema) != ASNBER_OK) {
        return NULL;
    }
    if (add_type(schema, "Int", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 2,
                 ASNBER_TAG_MODE_DEFAULT, 0, NULL, 0, 0, &t_int) != ASNBER_OK ||
        add_type(schema, "Leaf", ASNBER_TYPE_KIND_SEQUENCE, ASNBER_TAG_UNIVERSAL,
                 16, ASNBER_TAG_MODE_DEFAULT, 0, NULL, 0, 0, &t_leaf) !=
            ASNBER_OK ||
        add_field(schema, t_leaf, "x", t_int, 0, NULL, 0, NULL, 0) !=
            ASNBER_OK ||
        add_type(schema, "Mid", ASNBER_TYPE_KIND_SEQUENCE, ASNBER_TAG_UNIVERSAL,
                 16, ASNBER_TAG_MODE_DEFAULT, 0, NULL, 0, 0, &t_mid) !=
            ASNBER_OK ||
        add_field(schema, t_mid, "x", t_int, 0, NULL, 0, NULL, 0) !=
            ASNBER_OK ||
        add_field(schema, t_mid, "leaf", t_leaf, 0, NULL, 0, NULL, 0) !=
            ASNBER_OK ||
        add_type(schema, "Root", ASNBER_TYPE_KIND_SEQUENCE, ASNBER_TAG_UNIVERSAL,
                 16, ASNBER_TAG_MODE_DEFAULT, 0, NULL, 0, 0, &t_root) !=
            ASNBER_OK ||
        add_field(schema, t_root, "x", t_int, 0, NULL, 0, NULL, 0) !=
            ASNBER_OK ||
        add_field(schema, t_root, "mid", t_mid, 0, NULL, 0, NULL, 0) !=
            ASNBER_OK ||
        asnber_schema_set_root(schema, t_root) != ASNBER_OK ||
        asnber_schema_seal(schema) != ASNBER_OK) {
        goto fail;
    }
    return schema;
fail:
    asnber_schema_destroy(schema);
    return NULL;
}

/* 根类型自身带 EXPLICIT 包装：入口直接校验外层标签。 */
static asnber_schema_t *build_expl_root_schema(void)
{
    asnber_schema_t *schema = NULL;
    uint32_t t_int = 0;
    uint32_t t_root = 0;
    if (asnber_schema_create(g_ctx, ASNBER_TAG_MODE_DEFAULT, &schema) != ASNBER_OK) {
        return NULL;
    }
    if (add_type(schema, "Int", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 2,
                 ASNBER_TAG_MODE_DEFAULT, 0, NULL, 0, 0, &t_int) != ASNBER_OK ||
        add_type(schema, "Root", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_CONTEXT, 0,
                 ASNBER_TAG_MODE_EXPLICIT, 0, NULL, 0, 0, &t_root) != ASNBER_OK ||
        asnber_schema_set_root(schema, t_root) != ASNBER_OK ||
        asnber_schema_seal(schema) != ASNBER_OK) {
        goto fail;
    }
    return schema;
fail:
    asnber_schema_destroy(schema);
    return NULL;
}

static asnber_schema_t *build_any_expl_root_schema(void)
{
    asnber_schema_t *schema = NULL;
    uint32_t t_root = 0;
    if (asnber_schema_create(g_ctx, ASNBER_TAG_MODE_DEFAULT, &schema) != ASNBER_OK) {
        return NULL;
    }
    if (add_type(schema, "Root", ASNBER_TYPE_KIND_ANY, ASNBER_TAG_CONTEXT, 3,
                 ASNBER_TAG_MODE_EXPLICIT, 0, NULL, 0, 0, &t_root) != ASNBER_OK ||
        asnber_schema_set_root(schema, t_root) != ASNBER_OK ||
        asnber_schema_seal(schema) != ASNBER_OK) {
        goto fail;
    }
    return schema;
fail:
    asnber_schema_destroy(schema);
    return NULL;
}

/* SEQUENCE OF 带元素值域约束：用于覆盖 bindOf 的非 SIZE 约束分支。 */
static asnber_schema_t *build_of_range_schema(void)
{
    asnber_schema_t *schema = NULL;
    asnber_constraint_t c;
    uint32_t t_int = 0;
    uint32_t t_root = 0;
    if (asnber_schema_create(g_ctx, ASNBER_TAG_MODE_DEFAULT, &schema) != ASNBER_OK) {
        return NULL;
    }
    if (add_type(schema, "Int", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 2,
                 ASNBER_TAG_MODE_DEFAULT, 0, NULL, 0, 0, &t_int) != ASNBER_OK) {
        goto fail;
    }
    c = constraint_range(-5, 7);
    if (add_type(schema, "Root", ASNBER_TYPE_KIND_SEQUENCE_OF,
                 ASNBER_TAG_UNIVERSAL, 16, ASNBER_TAG_MODE_DEFAULT, t_int, &c, 1,
                 0, &t_root) != ASNBER_OK ||
        asnber_schema_set_root(schema, t_root) != ASNBER_OK ||
        asnber_schema_seal(schema) != ASNBER_OK) {
        goto fail;
    }
    return schema;
fail:
    asnber_schema_destroy(schema);
    return NULL;
}

static asnber_schema_t *build_unsealed_schema(void)
{
    asnber_schema_t *schema = NULL;
    uint32_t t_int = 0;
    if (asnber_schema_create(g_ctx, ASNBER_TAG_MODE_DEFAULT, &schema) != ASNBER_OK) {
        return NULL;
    }
    if (add_type(schema, "Int", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 2,
                 ASNBER_TAG_MODE_DEFAULT, 0, NULL, 0, 0, &t_int) != ASNBER_OK) {
        asnber_schema_destroy(schema);
        return NULL;
    }
    return schema;
}

static asnber_schema_t *build_noroot_schema(void)
{
    asnber_schema_t *schema = NULL;
    uint32_t t_int = 0;
    if (asnber_schema_create(g_ctx, ASNBER_TAG_MODE_DEFAULT, &schema) != ASNBER_OK) {
        return NULL;
    }
    if (add_type(schema, "Int", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 2,
                 ASNBER_TAG_MODE_DEFAULT, 0, NULL, 0, 0, &t_int) != ASNBER_OK ||
        asnber_schema_seal(schema) != ASNBER_OK) {
        asnber_schema_destroy(schema);
        return NULL;
    }
    return schema;
}

static asnber_schema_t *build_foreign_schema(void)
{
    asnber_schema_t *schema = NULL;
    uint32_t t_int = 0;
    if (g_other_ctx == NULL ||
        asnber_schema_create(g_other_ctx, ASNBER_TAG_MODE_DEFAULT, &schema) !=
            ASNBER_OK) {
        return NULL;
    }
    if (add_type(schema, "Int", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 2,
                 ASNBER_TAG_MODE_DEFAULT, 0, NULL, 0, 0, &t_int) != ASNBER_OK ||
        asnber_schema_set_root(schema, t_int) != ASNBER_OK ||
        asnber_schema_seal(schema) != ASNBER_OK) {
        asnber_schema_destroy(schema);
        return NULL;
    }
    return schema;
}

static void init_options(asnber_decode_options_t *options, uint32_t flags,
                          uint32_t max_depth)
{
    asnber_decode_options_init(options);
    options->struct_size = sizeof(*options);
    options->encoding = ASNBER_ENCODING_BER;
    options->flags = flags;
    options->max_depth = max_depth;
}

static void decode_one(const asnber_schema_t *schema, const uint8_t *data,
                       size_t size, uint32_t flags, uint32_t max_depth)
{
    asnber_decode_options_t options;
    asnber_doc_t *doc = NULL;
    size_t consumed = 0;

    init_options(&options, flags, max_depth);
    (void)asnber_decode_buffer_with_schema(g_ctx, data, size, schema, &options,
                                         &doc, &consumed);
    if (doc != NULL) {
        fuzz_walk(asnber_doc_root(doc));
        (void)asnber_doc_validate(g_ctx, doc, schema, NULL);
        if (flags != 0) {
            init_options(&options, ASNBER_DECODE_STRICT_SCHEMA, 0);
            (void)asnber_doc_validate(g_ctx, doc, schema, &options);
        }
        asnber_doc_destroy(doc);
    }
}

/* options == NULL 的有效解码路径：按 BER 且无额外标志。 */
static void decode_null_options(const asnber_schema_t *schema,
                                const uint8_t *data, size_t size)
{
    asnber_doc_t *doc = NULL;
    size_t consumed = 0;

    (void)asnber_decode_buffer_with_schema(g_ctx, data, size, schema, NULL,
                                         &doc, &consumed);
    if (doc != NULL) {
        fuzz_walk(asnber_doc_root(doc));
        asnber_doc_destroy(doc);
    }
}

static void decode_reader(const asnber_schema_t *schema, const uint8_t *data,
                          size_t size)
{
    fuzz_mem_reader_t mem;
    asnber_reader_t reader;
    asnber_decode_options_t options;
    asnber_doc_t *doc = NULL;
    size_t consumed = 0;

    mem.data = data;
    mem.size = size;
    mem.pos = 0;
    memset(&reader, 0, sizeof(reader));
    reader.struct_size = sizeof(reader);
    reader.user = &mem;
    reader.read = fuzz_mem_read;

    (void)asnber_decode_reader_with_schema(g_ctx, &reader, schema, NULL, &doc,
                                         &consumed);
    if (doc != NULL) {
        fuzz_walk(asnber_doc_root(doc));
        asnber_doc_destroy(doc);
    }

    /* reader 路径会把输入复制进文档，再走一遍带选项的分支。 */
    mem.pos = 0;
    init_options(&options, ASNBER_DECODE_STRICT_SCHEMA, 0);
    (void)asnber_decode_reader_with_schema(g_ctx, &reader, schema, &options,
                                         &doc, &consumed);
    if (doc != NULL) {
        fuzz_walk(asnber_doc_root(doc));
        asnber_doc_destroy(doc);
    }
}

static void decode_generic_then_validate(const uint8_t *data, size_t size)
{
    asnber_decode_options_t options;
    asnber_doc_t *doc = NULL;
    size_t consumed = 0;

    init_options(&options, 0, 0);
    (void)asnber_decode_buffer(g_ctx, data, size, &options, &doc, &consumed);
    if (doc == NULL) {
        return;
    }
    (void)asnber_doc_validate(g_ctx, doc, g_rich_schema, NULL);
    init_options(&options, ASNBER_DECODE_STRICT_SCHEMA, 0);
    (void)asnber_doc_validate(g_ctx, doc, g_rich_schema, &options);
    init_options(&options, ASNBER_DECODE_WARN_UNKNOWN_FIELD, 0);
    (void)asnber_doc_validate(g_ctx, doc, g_seq_schema, &options);
    /* 低 max_depth 让三层嵌套输入在绑定期触发深度限制。 */
    init_options(&options, 0, 2);
    (void)asnber_doc_validate(g_ctx, doc, g_nested_schema, &options);
    asnber_doc_destroy(doc);
}

static asnber_err_t always_fail_read(void *user, uint8_t *dst, size_t capacity,
                                   size_t *out_size)
{
    (void)user;
    (void)dst;
    (void)capacity;
    if (out_size != NULL) {
        *out_size = 0;
    }
    return ASNBER_E_IO_READ;
}

static void run_edge_cases_once(void)
{
    static const uint8_t kProbe[3] = {0x02, 0x01, 0x05};
    asnber_decode_options_t options;
    asnber_reader_t reader;
    asnber_doc_t *doc = NULL;
    size_t consumed = 0;

    /* 入口参数校验。 */
    (void)asnber_decode_buffer_with_schema(g_ctx, kProbe, sizeof(kProbe),
                                         g_rich_schema, NULL, NULL, NULL);
    (void)asnber_decode_buffer_with_schema(NULL, kProbe, sizeof(kProbe),
                                         g_rich_schema, NULL, &doc, &consumed);
    (void)asnber_decode_buffer_with_schema(g_ctx, NULL, 1, g_rich_schema, NULL,
                                         &doc, &consumed);
    (void)asnber_decode_buffer_with_schema(g_ctx, kProbe, sizeof(kProbe), NULL,
                                         NULL, &doc, &consumed);
    (void)asnber_decode_buffer_with_schema(g_ctx, kProbe, sizeof(kProbe),
                                         g_foreign_schema, NULL, &doc,
                                         &consumed);
    (void)asnber_decode_buffer_with_schema(g_ctx, kProbe, sizeof(kProbe),
                                         g_unsealed_schema, NULL, &doc,
                                         &consumed);
    (void)asnber_decode_buffer_with_schema(g_ctx, kProbe, sizeof(kProbe),
                                         g_noroot_schema, NULL, &doc,
                                         &consumed);

    /* 选项校验的每个失败分支。 */
    init_options(&options, 0, 0);
    options.struct_size = 0;
    (void)asnber_decode_buffer_with_schema(g_ctx, kProbe, sizeof(kProbe),
                                         g_rich_schema, &options, &doc,
                                         &consumed);
    init_options(&options, 0, 0);
    options.reserved[0] = 1;
    (void)asnber_decode_buffer_with_schema(g_ctx, kProbe, sizeof(kProbe),
                                         g_rich_schema, &options, &doc,
                                         &consumed);
    init_options(&options, 0, 0);
    options.reserved[1] = 1;
    (void)asnber_decode_buffer_with_schema(g_ctx, kProbe, sizeof(kProbe),
                                         g_rich_schema, &options, &doc,
                                         &consumed);
    init_options(&options, 0, 0);
    options.reserved[2] = 1;
    (void)asnber_decode_buffer_with_schema(g_ctx, kProbe, sizeof(kProbe),
                                         g_rich_schema, &options, &doc,
                                         &consumed);
    init_options(&options, 0, 0);
    options.encoding = ASNBER_ENCODING_CER;
    (void)asnber_decode_buffer_with_schema(g_ctx, kProbe, sizeof(kProbe),
                                         g_rich_schema, &options, &doc,
                                         &consumed);
    init_options(&options, 0, 0);
    options.flags = 1u << 31;
    (void)asnber_decode_buffer_with_schema(g_ctx, kProbe, sizeof(kProbe),
                                         g_rich_schema, &options, &doc,
                                         &consumed);
    init_options(&options, 0, 0xFFFFFFFFu);
    (void)asnber_decode_buffer_with_schema(g_ctx, kProbe, sizeof(kProbe),
                                         g_rich_schema, &options, &doc,
                                         &consumed);

    /* reader 入口校验。 */
    (void)asnber_decode_reader_with_schema(g_ctx, NULL, g_rich_schema, NULL,
                                         &doc, &consumed);
    memset(&reader, 0, sizeof(reader));
    reader.struct_size = 0;
    reader.read = fuzz_mem_read;
    (void)asnber_decode_reader_with_schema(g_ctx, &reader, g_rich_schema, NULL,
                                         &doc, &consumed);
    reader.struct_size = sizeof(reader);
    reader.read = NULL;
    (void)asnber_decode_reader_with_schema(g_ctx, &reader, g_rich_schema, NULL,
                                         &doc, &consumed);
    reader.read = always_fail_read;
    reader.user = NULL;
    (void)asnber_decode_reader_with_schema(g_ctx, &reader, g_rich_schema, NULL,
                                         &doc, &consumed);
    (void)asnber_decode_reader_with_schema(NULL, &reader, g_rich_schema, NULL,
                                         &doc, &consumed);
    (void)asnber_decode_reader_with_schema(g_ctx, &reader, g_rich_schema, NULL,
                                         NULL, &consumed);

    /* doc_validate 入口校验。 */
    (void)asnber_doc_validate(NULL, NULL, g_rich_schema, NULL);
    (void)asnber_doc_validate(g_ctx, NULL, g_rich_schema, NULL);
    init_options(&options, 0, 0);
    (void)asnber_decode_buffer(g_ctx, kProbe, sizeof(kProbe), &options, &doc,
                             &consumed);
    if (doc != NULL) {
        (void)asnber_doc_validate(g_ctx, doc, NULL, NULL);
        (void)asnber_doc_validate(g_ctx, doc, g_foreign_schema, NULL);
        (void)asnber_doc_validate(g_ctx, doc, g_unsealed_schema, NULL);
        (void)asnber_doc_validate(g_ctx, doc, g_noroot_schema, NULL);
        options.struct_size = 0;
        (void)asnber_doc_validate(g_ctx, doc, g_rich_schema, &options);
        /* 句柄类型交叉：魔术校验先拒绝，不会解引用后续字段。 */
        {
            asnber_doc_t *tmp = NULL;
            (void)asnber_decode_buffer_with_schema(
                g_ctx, kProbe, sizeof(kProbe), (const asnber_schema_t *)doc,
                NULL, &tmp, &consumed);
            (void)asnber_doc_validate(g_ctx, (const asnber_doc_t *)g_rich_schema,
                                    g_rich_schema, NULL);
        }
        asnber_doc_destroy(doc);
    }
}

static void ensure_schemas(void)
{
    asnber_schema_table_t table;

    if (g_init_done) {
        return;
    }
    g_init_done = 1;

    g_ctx = fuzz_ctx_create();
    if (g_ctx == NULL) {
        return;
    }

    memset(&table, 0, sizeof(table));
    table.struct_size = sizeof(table);
    table.data = kPKIXFlattened2009Schema;
    table.size = kPKIXFlattened2009Schema_size;
    table.format_version = 1u << 16;
    (void)asnber_schema_load(g_ctx, &table, &g_pkix_schema);

    g_min_schema = fuzz_min_schema_create(g_ctx);
    g_rich_schema = build_rich_schema();
    g_seq_schema = build_seq_schema();
    g_set_schema = build_set_schema();
    g_simple_schema = build_simple_rootschema();
    g_choice_schema = build_choice_schema();
    g_any_req_schema = build_any_req_schema();
    g_of_range_schema = build_of_range_schema();
    g_nested_schema = build_nested_schema();
    g_expl_root_schema = build_expl_root_schema();
    g_any_expl_root_schema = build_any_expl_root_schema();
    g_unsealed_schema = build_unsealed_schema();
    g_noroot_schema = build_noroot_schema();

    g_other_ctx = fuzz_ctx_create();
    g_foreign_schema = build_foreign_schema();

    if (g_rich_schema == NULL || g_seq_schema == NULL ||
        g_set_schema == NULL || g_simple_schema == NULL ||
        g_choice_schema == NULL || g_any_req_schema == NULL) {
        fprintf(stderr, "schema build failed: rich=%p seq=%p set=%p simple=%p "
                        "choice=%p anyreq=%p\n",
                (void *)g_rich_schema, (void *)g_seq_schema,
                (void *)g_set_schema, (void *)g_simple_schema,
                (void *)g_choice_schema, (void *)g_any_req_schema);
    }
}

static void run_all_schemas(const uint8_t *data, size_t size)
{
    const asnber_schema_t *schemas[] = {
        g_rich_schema, g_seq_schema, g_set_schema, g_simple_schema,
        g_choice_schema, g_any_req_schema, g_of_range_schema, g_nested_schema,
        g_expl_root_schema, g_any_expl_root_schema,
    };
    const size_t count = sizeof(schemas) / sizeof(schemas[0]);
    size_t i;

    for (i = 0; i < count; ++i) {
        if (schemas[i] != NULL) {
            decode_one(schemas[i], data, size, 0, 0);
        }
    }

    if (g_rich_schema != NULL) {
        decode_one(g_rich_schema, data, size, ASNBER_DECODE_STRICT_SCHEMA, 0);
        decode_one(g_rich_schema, data, size,
                   ASNBER_DECODE_WARN_UNKNOWN_FIELD, 0);
        decode_one(g_rich_schema, data, size, ASNBER_DECODE_COPY_INPUT, 0);
        decode_one(g_rich_schema, data, size, ASNBER_DECODE_ALLOW_TRAILING, 0);
        decode_one(g_rich_schema, data, size,
                   ASNBER_DECODE_STRICT_SCHEMA | ASNBER_DECODE_WARN_UNKNOWN_FIELD,
                   0);
        decode_one(g_rich_schema, data, size, 0, 2);
        decode_null_options(g_rich_schema, data, size);
        decode_reader(g_rich_schema, data, size);
    }
    if (g_pkix_schema != NULL) {
        decode_one(g_pkix_schema, data, size, 0, 0);
        decode_one(g_pkix_schema, data, size, ASNBER_DECODE_STRICT_SCHEMA, 0);
        decode_reader(g_pkix_schema, data, size);
    }
    if (g_min_schema != NULL) {
        decode_one(g_min_schema, data, size, 0, 0);
    }
    decode_generic_then_validate(data, size);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ensure_schemas();
    if (g_ctx == NULL) {
        return 0;
    }
    if (!g_edge_done) {
        g_edge_done = 1;
        run_edge_cases_once();
    }
    run_all_schemas(data, size);
    return 0;
}
