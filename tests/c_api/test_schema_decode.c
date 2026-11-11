/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * schema 感知解码与编码：字段绑定、未知字段策略、DEFAULT 省略、CHOICE
 * 分派、OF 元素绑定、ANY 保留 TLV、约束求值、SET/SET OF 排序、
 * asnber_doc_validate 与真实证书的 ANY 实测。
 */
#include <asnber/asnber.h>

#include <stddef.h>
#include <string.h>

#include "../data/cert_ec_selfsigned.h"
#include "../data/cert_rsa_pss_selfsigned.h"
#include "../data/cert_rsa_selfsigned.h"
#include "check.h"
#include "test_compare.h"

/* ---------- 辅助 ---------- */

static asnber_type_desc_t make_type(const char *name, asnber_type_kind_t kind,
                                  asnber_tag_class_t tag_class,
                                  uint32_t tag_number, asnber_tag_mode_t mode,
                                  uint32_t element_type_id)
{
    asnber_type_desc_t desc;
    memset(&desc, 0, sizeof(desc));
    desc.struct_size = sizeof(desc);
    desc.name = name;
    desc.kind = kind;
    desc.tag_class = tag_class;
    desc.tag_number = tag_number;
    desc.tag_mode = mode;
    desc.element_type_id = element_type_id;
    return desc;
}

static asnber_field_desc_t make_field(const char *name, uint32_t type_id,
                                    uint32_t flags)
{
    asnber_field_desc_t desc;
    memset(&desc, 0, sizeof(desc));
    desc.struct_size = sizeof(desc);
    desc.name = name;
    desc.type_id = type_id;
    desc.flags = flags;
    return desc;
}

static asnber_bound_t make_bound(int64_t value)
{
    asnber_bound_t bound;
    memset(&bound, 0, sizeof(bound));
    bound.struct_size = sizeof(bound);
    bound.value = value;
    return bound;
}

static asnber_bound_t make_decimal_bound(const char *text)
{
    asnber_bound_t bound;
    memset(&bound, 0, sizeof(bound));
    bound.struct_size = sizeof(bound);
    bound.decimal = text;
    bound.decimal_size = strlen(text);
    return bound;
}

static asnber_constraint_t make_range(int64_t lower, int64_t upper)
{
    asnber_constraint_t constraint;
    memset(&constraint, 0, sizeof(constraint));
    constraint.struct_size = sizeof(constraint);
    constraint.kind = ASNBER_CONSTRAINT_RANGE;
    constraint.lower = make_bound(lower);
    constraint.upper = make_bound(upper);
    return constraint;
}

static asnber_constraint_t make_size(int64_t lower, int64_t upper)
{
    asnber_constraint_t constraint;
    memset(&constraint, 0, sizeof(constraint));
    constraint.struct_size = sizeof(constraint);
    constraint.kind = ASNBER_CONSTRAINT_SIZE;
    constraint.lower = make_bound(lower);
    constraint.upper = make_bound(upper);
    return constraint;
}

/* 解码并返回文档；失败时断言所在用例已由调用方检查。 */
static asnber_err_t decode_schema(asnber_ctx_t *ctx, const asnber_schema_t *schema,
                                const uint8_t *data, size_t size,
                                uint32_t flags, asnber_doc_t **out_doc)
{
    asnber_decode_options_t options;
    asnber_decode_options_init(&options);
    options.encoding = ASNBER_ENCODING_BER;
    options.flags = flags;
    size_t consumed = 0;
    return asnber_decode_buffer_with_schema(ctx, data, size, schema, &options,
                                          out_doc, &consumed);
}

static asnber_err_t encode_both(asnber_ctx_t *ctx, const asnber_schema_t *schema,
                              const asnber_doc_t *doc, uint8_t *schemaOut,
                              size_t schemaCapacity, size_t *schemaSize,
                              uint8_t *genericOut, size_t genericCapacity,
                              size_t *genericSize)
{
    asnber_buf_t buf;
    memset(&buf, 0, sizeof(buf));

    asnber_encode_options_t withSchema;
    asnber_encode_options_init(&withSchema);
    withSchema.schema = schema;
    const asnber_err_t rc = asnber_encode_buffer(ctx, doc, &withSchema, &buf);
    if (rc != ASNBER_OK) {
        return rc;
    }
    if (buf.size > schemaCapacity) {
        asnber_buf_release(ctx, &buf);
        return ASNBER_E_OUTPUT_LIMIT;
    }
    memcpy(schemaOut, buf.data, buf.size);
    *schemaSize = buf.size;
    asnber_buf_release(ctx, &buf);

    memset(&buf, 0, sizeof(buf));
    const asnber_err_t genericRc = asnber_encode_buffer(ctx, doc, NULL, &buf);
    if (genericRc != ASNBER_OK) {
        return genericRc;
    }
    if (buf.size > genericCapacity) {
        asnber_buf_release(ctx, &buf);
        return ASNBER_E_OUTPUT_LIMIT;
    }
    memcpy(genericOut, buf.data, buf.size);
    *genericSize = buf.size;
    asnber_buf_release(ctx, &buf);
    return ASNBER_OK;
}

/* 用 STRICT_SCHEMA 对既有文档重新校验。 */
static asnber_err_t validate_strict(asnber_ctx_t *ctx, const asnber_doc_t *doc,
                                  const asnber_schema_t *schema)
{
    asnber_decode_options_t options;
    asnber_decode_options_init(&options);
    options.encoding = ASNBER_ENCODING_BER;
    options.flags = ASNBER_DECODE_STRICT_SCHEMA;
    asnber_ctx_clear_warnings(ctx);
    return asnber_doc_validate(ctx, doc, schema, &options);
}

/* ---------- 用例 ---------- */

    /* ===== 1. 字段绑定 + DEFAULT 省略 ===== */
static int check_binding_default(asnber_ctx_t *ctx)
{
    {
        asnber_schema_t *schema = NULL;
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        uint32_t intId = 0;
        uint32_t seqId = 0;
        asnber_type_desc_t intType =
            make_type("Int", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 2,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &intType, &intId) ==
                        ASNBER_OK);
        asnber_type_desc_t seqType =
            make_type("Pair", ASNBER_TYPE_KIND_SEQUENCE, ASNBER_TAG_UNIVERSAL, 16,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &seqType, &seqId) ==
                        ASNBER_OK);
        asnber_field_desc_t aField = make_field("a", intId, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_field(schema, seqId, &aField) ==
                        ASNBER_OK);
        static const uint8_t kDefaultZero[3] = {0x02, 0x01, 0x00};
        asnber_field_desc_t bField = make_field("b", intId, 0);
        bField.default_value = kDefaultZero;
        bField.default_value_size = sizeof(kDefaultZero);
        ASNBER_TEST_CHECK(asnber_schema_add_field(schema, seqId, &bField) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_set_root(schema, seqId) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);

        /* 显式携带 DEFAULT 值：解码命名、编码按 DEFAULT 省略。 */
        static const uint8_t kWithDefault[8] = {0x30, 0x06, 0x02, 0x01,
                                                0x05, 0x02, 0x01, 0x00};
        static const uint8_t kOmitting[5] = {0x30, 0x03, 0x02, 0x01, 0x05};
        asnber_doc_t *doc = NULL;
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kWithDefault,
                                      sizeof(kWithDefault), 0, &doc) ==
                        ASNBER_OK);
        const asnber_node_t *root = asnber_doc_root(doc);
        ASNBER_TEST_CHECK(asnber_node_child_count(root) == 2);
        const asnber_node_t *a = asnber_node_child_by_name(root, "a");
        const asnber_node_t *b = asnber_node_child_by_name(root, "b");
        ASNBER_TEST_CHECK(a != NULL && b != NULL);
        ASNBER_TEST_CHECK(asnber_node_field_name(a) != NULL);
        int64_t value = 0;
        ASNBER_TEST_CHECK(asnber_node_get_int64(a, &value) == ASNBER_OK);
        ASNBER_TEST_CHECK(value == 5);

        uint8_t schemaOut[16];
        uint8_t genericOut[16];
        size_t schemaSize = 0;
        size_t genericSize = 0;
        ASNBER_TEST_CHECK(encode_both(ctx, schema, doc, schemaOut,
                                    sizeof(schemaOut), &schemaSize, genericOut,
                                    sizeof(genericOut), &genericSize) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(schemaOut, schemaSize, kOmitting,
                                    sizeof(kOmitting)));
        ASNBER_TEST_CHECK(bytes_equal(genericOut, genericSize, kWithDefault,
                                    sizeof(kWithDefault)));
        asnber_doc_destroy(doc);

        /* 缺省 DEFAULT 字段：解码通过，编码保持省略。 */
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kOmitting, sizeof(kOmitting),
                                      0, &doc) == ASNBER_OK);
        root = asnber_doc_root(doc);
        ASNBER_TEST_CHECK(asnber_node_child_count(root) == 1);
        ASNBER_TEST_CHECK(asnber_node_child_by_name(root, "a") != NULL);
        ASNBER_TEST_CHECK(encode_both(ctx, schema, doc, schemaOut,
                                    sizeof(schemaOut), &schemaSize, genericOut,
                                    sizeof(genericOut), &genericSize) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(schemaOut, schemaSize, kOmitting,
                                    sizeof(kOmitting)));
        asnber_doc_destroy(doc);
        asnber_schema_destroy(schema);
    }
    return 0;
}

    /* ===== 2. 未知字段策略 ===== */
static int check_unknown_field_policy(asnber_ctx_t *ctx)
{
    {
        asnber_schema_t *schema = NULL;
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        uint32_t intId = 0;
        uint32_t seqId = 0;
        asnber_type_desc_t intType =
            make_type("Int", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 2,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &intType, &intId) ==
                        ASNBER_OK);
        asnber_type_desc_t seqType =
            make_type("OnlyA", ASNBER_TYPE_KIND_SEQUENCE, ASNBER_TAG_UNIVERSAL, 16,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &seqType, &seqId) ==
                        ASNBER_OK);
        asnber_field_desc_t aField = make_field("a", intId, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_field(schema, seqId, &aField) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_set_root(schema, seqId) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);

        static const uint8_t kUnknown[8] = {0x30, 0x06, 0x02, 0x01,
                                            0x05, 0x04, 0x01, 0x00};
        asnber_doc_t *doc = NULL;
        /* 默认：静默保留。 */
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kUnknown, sizeof(kUnknown),
                                      0, &doc) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_child_count(asnber_doc_root(doc)) == 2);
        asnber_doc_destroy(doc);

        /* WARN：保留并产生一条告警，偏移指向未知字段。 */
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kUnknown, sizeof(kUnknown),
                                      ASNBER_DECODE_WARN_UNKNOWN_FIELD,
                                      &doc) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_ctx_warning_count(ctx) == 1);
        asnber_warning_t warning;
        memset(&warning, 0, sizeof(warning));
        warning.struct_size = sizeof(warning);
        ASNBER_TEST_CHECK(asnber_ctx_get_warning(ctx, 0, &warning) == ASNBER_OK);
        ASNBER_TEST_CHECK(warning.code == ASNBER_E_SCHEMA_FIELD);
        ASNBER_TEST_CHECK(warning.offset == 5);
        asnber_doc_destroy(doc);

        /* STRICT：立即失败并写入路径与偏移。 */
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kUnknown, sizeof(kUnknown),
                                      ASNBER_DECODE_STRICT_SCHEMA, &doc) ==
                        ASNBER_E_SCHEMA_FIELD);
        asnber_error_info_t info;
        memset(&info, 0, sizeof(info));
        info.struct_size = sizeof(info);
        ASNBER_TEST_CHECK(asnber_ctx_get_error(ctx, &info) == ASNBER_OK);
        ASNBER_TEST_CHECK(info.code == ASNBER_E_SCHEMA_FIELD);
        ASNBER_TEST_CHECK(info.offset == 5);
        ASNBER_TEST_CHECK(info.path != NULL);

        /* STRICT 与 WARN 同时设置：严格优先，不产生告警。 */
        asnber_ctx_clear_warnings(ctx);
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kUnknown, sizeof(kUnknown),
                                      ASNBER_DECODE_STRICT_SCHEMA |
                                          ASNBER_DECODE_WARN_UNKNOWN_FIELD,
                                      &doc) == ASNBER_E_SCHEMA_FIELD);
        ASNBER_TEST_CHECK(asnber_ctx_warning_count(ctx) == 0);
        asnber_schema_destroy(schema);
    }
    return 0;
}

    /* ===== 2b. 未知字段默认保留与严格校验 ===== */
static int check_unknown_field_strict(asnber_ctx_t *ctx)
{
    {
        asnber_schema_t *schema = NULL;
        uint32_t intId = 0;
        uint32_t seqId = 0;
        asnber_type_desc_t intType =
            make_type("Int", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 2,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &intType, &intId) ==
                        ASNBER_OK);
        asnber_type_desc_t seqType =
            make_type("ExtSeq", ASNBER_TYPE_KIND_SEQUENCE, ASNBER_TAG_UNIVERSAL, 16,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        seqType.flags = ASNBER_TYPE_EXTENSIBLE;
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &seqType, &seqId) ==
                        ASNBER_OK);
        asnber_field_desc_t aField = make_field("a", intId, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_field(schema, seqId, &aField) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_set_root(schema, seqId) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);

        static const uint8_t kKnownFirst[8] = {0x30, 0x06, 0x02, 0x01,
                                               0x05, 0x04, 0x01, 0x00};
        static const uint8_t kUnknownFirst[8] = {0x30, 0x06, 0x04, 0x01,
                                                 0x00, 0x02, 0x01, 0x05};
        static const uint8_t kMultiUnknown[11] = {
            0x30, 0x09, 0x02, 0x01, 0x05, 0x04,
            0x01, 0x01, 0x04, 0x01, 0x02};
        uint8_t schemaOut[32];
        uint8_t genericOut[32];
        size_t schemaSize = 0;
        size_t genericSize = 0;
        asnber_doc_t *doc = NULL;

        /* extensible：已知在前、未知在后逐字节往返。 */
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kKnownFirst,
                                      sizeof(kKnownFirst), 0, &doc) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_child_count(asnber_doc_root(doc)) == 2);
        ASNBER_TEST_CHECK(encode_both(ctx, schema, doc, schemaOut,
                                    sizeof(schemaOut), &schemaSize, genericOut,
                                    sizeof(genericOut), &genericSize) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(schemaOut, schemaSize, kKnownFirst,
                                    sizeof(kKnownFirst)));
        ASNBER_TEST_CHECK(bytes_equal(genericOut, genericSize, kKnownFirst,
                                    sizeof(kKnownFirst)));
        ASNBER_TEST_CHECK(validate_strict(ctx, doc, schema) ==
                        ASNBER_E_SCHEMA_FIELD);
        asnber_error_info_t info;
        memset(&info, 0, sizeof(info));
        info.struct_size = sizeof(info);
        ASNBER_TEST_CHECK(asnber_ctx_get_error(ctx, &info) == ASNBER_OK);
        ASNBER_TEST_CHECK(info.code == ASNBER_E_SCHEMA_FIELD);
        ASNBER_TEST_CHECK(info.offset == 5);
        ASNBER_TEST_CHECK(info.path != NULL);
        asnber_doc_destroy(doc);

        /* 未知在前：schema 编码把已知字段前置，未知字段保持相对顺序。 */
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kUnknownFirst,
                                      sizeof(kUnknownFirst), 0, &doc) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(encode_both(ctx, schema, doc, schemaOut,
                                    sizeof(schemaOut), &schemaSize, genericOut,
                                    sizeof(genericOut), &genericSize) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(schemaOut, schemaSize, kKnownFirst,
                                    sizeof(kKnownFirst)));
        ASNBER_TEST_CHECK(bytes_equal(genericOut, genericSize, kUnknownFirst,
                                    sizeof(kUnknownFirst)));
        asnber_doc_destroy(doc);

        /* 多个未知字段之间不重排。 */
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kMultiUnknown,
                                      sizeof(kMultiUnknown), 0, &doc) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(encode_both(ctx, schema, doc, schemaOut,
                                    sizeof(schemaOut), &schemaSize, genericOut,
                                    sizeof(genericOut), &genericSize) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(schemaOut, schemaSize, kMultiUnknown,
                                    sizeof(kMultiUnknown)));
        asnber_doc_destroy(doc);
        asnber_schema_destroy(schema);

        /* 非 extensible SEQUENCE：未知字段同样默认保留，严格路径报错。 */
        schema = NULL;
        intId = 0;
        seqId = 0;
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &intType, &intId) ==
                        ASNBER_OK);
        seqType = make_type("PlainSeq", ASNBER_TYPE_KIND_SEQUENCE,
                            ASNBER_TAG_UNIVERSAL, 16, ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &seqType, &seqId) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_add_field(schema, seqId, &aField) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_set_root(schema, seqId) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kKnownFirst,
                                      sizeof(kKnownFirst), 0, &doc) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(encode_both(ctx, schema, doc, schemaOut,
                                    sizeof(schemaOut), &schemaSize, genericOut,
                                    sizeof(genericOut), &genericSize) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(schemaOut, schemaSize, kKnownFirst,
                                    sizeof(kKnownFirst)));
        ASNBER_TEST_CHECK(validate_strict(ctx, doc, schema) ==
                        ASNBER_E_SCHEMA_FIELD);
        asnber_doc_destroy(doc);
        asnber_schema_destroy(schema);
    }
    return 0;
}

    /* ===== 2c. SET 未知字段：schema 编码拒绝 ===== */
static int check_set_unknown_field(asnber_ctx_t *ctx)
{
    {
        asnber_schema_t *schema = NULL;
        uint32_t intId = 0;
        uint32_t setId = 0;
        asnber_type_desc_t intType =
            make_type("Int", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 2,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &intType, &intId) ==
                        ASNBER_OK);
        asnber_type_desc_t setType =
            make_type("Bag", ASNBER_TYPE_KIND_SET, ASNBER_TAG_UNIVERSAL, 17,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &setType, &setId) ==
                        ASNBER_OK);
        asnber_field_desc_t aField = make_field("a", intId, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_field(schema, setId, &aField) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_set_root(schema, setId) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);

        static const uint8_t kSetUnknown[8] = {0x31, 0x06, 0x02, 0x01,
                                               0x05, 0x04, 0x01, 0x00};
        static const uint8_t kSetKnown[5] = {0x31, 0x03, 0x02, 0x01, 0x05};
        asnber_doc_t *doc = NULL;
        asnber_buf_t buf;
        memset(&buf, 0, sizeof(buf));

        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kSetUnknown,
                                      sizeof(kSetUnknown), 0, &doc) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_child_count(asnber_doc_root(doc)) == 2);
        asnber_encode_options_t options;
        asnber_encode_options_init(&options);
        options.schema = schema;
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, &options, &buf) ==
                        ASNBER_E_SCHEMA_FIELD);
        ASNBER_TEST_CHECK(asnber_buf_release(ctx, &buf) == ASNBER_OK);
        ASNBER_TEST_CHECK(validate_strict(ctx, doc, schema) ==
                        ASNBER_E_SCHEMA_FIELD);
        /* 无 schema 通用编码仍可写出（按 DER 规范化）。 */
        memset(&buf, 0, sizeof(buf));
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, NULL, &buf) == ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(buf.data, buf.size, kSetUnknown,
                                    sizeof(kSetUnknown)));
        ASNBER_TEST_CHECK(asnber_buf_release(ctx, &buf) == ASNBER_OK);
        asnber_doc_destroy(doc);

        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kSetKnown, sizeof(kSetKnown),
                                      0, &doc) == ASNBER_OK);
        memset(&buf, 0, sizeof(buf));
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, &options, &buf) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(buf.data, buf.size, kSetKnown,
                                    sizeof(kSetKnown)));
        ASNBER_TEST_CHECK(asnber_buf_release(ctx, &buf) == ASNBER_OK);
        ASNBER_TEST_CHECK(validate_strict(ctx, doc, schema) == ASNBER_OK);
        asnber_doc_destroy(doc);
        asnber_schema_destroy(schema);
    }
    return 0;
}

    /* ===== 2d. ANY 与保留 TLV 的 DER 一致性 ===== */
static int check_any_der_consistency(asnber_ctx_t *ctx)
{
    {
        asnber_schema_t *schema = NULL;
        uint32_t anyId = 0;
        uint32_t boxId = 0;
        asnber_type_desc_t anyType =
            make_type("Open", ASNBER_TYPE_KIND_ANY, ASNBER_TAG_UNIVERSAL, 0,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &anyType, &anyId) ==
                        ASNBER_OK);
        asnber_type_desc_t boxType =
            make_type("Box", ASNBER_TYPE_KIND_SEQUENCE, ASNBER_TAG_UNIVERSAL, 16,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &boxType, &boxId) ==
                        ASNBER_OK);
        asnber_field_desc_t anyField = make_field("open", anyId, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_field(schema, boxId, &anyField) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_set_root(schema, boxId) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);

        static const uint8_t kNonMinimalAny[6] = {0x30, 0x04, 0x04,
                                                  0x81, 0x01, 0x00};
        static const uint8_t kIndefiniteAny[9] = {0x30, 0x07, 0x30, 0x80, 0x02,
                                                  0x01, 0x05, 0x00, 0x00};
        asnber_doc_t *doc = NULL;
        asnber_buf_t buf;

        /* 非最短长度 ANY：BER 可解码，schema 感知编码拒绝，通用编码原样回写。 */
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kNonMinimalAny,
                                      sizeof(kNonMinimalAny), 0, &doc) ==
                        ASNBER_OK);
        memset(&buf, 0, sizeof(buf));
        asnber_encode_options_t options;
        asnber_encode_options_init(&options);
        options.schema = schema;
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, &options, &buf) ==
                        ASNBER_E_NON_CANONICAL);
        ASNBER_TEST_CHECK(asnber_buf_release(ctx, &buf) == ASNBER_OK);
        memset(&buf, 0, sizeof(buf));
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, NULL, &buf) == ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(buf.data, buf.size, kNonMinimalAny,
                                    sizeof(kNonMinimalAny)));
        ASNBER_TEST_CHECK(asnber_buf_release(ctx, &buf) == ASNBER_OK);
        asnber_doc_destroy(doc);

        /* BER 不定长 ANY：同上。 */
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kIndefiniteAny,
                                      sizeof(kIndefiniteAny), 0, &doc) ==
                        ASNBER_OK);
        memset(&buf, 0, sizeof(buf));
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, &options, &buf) ==
                        ASNBER_E_NON_CANONICAL);
        ASNBER_TEST_CHECK(asnber_buf_release(ctx, &buf) == ASNBER_OK);
        memset(&buf, 0, sizeof(buf));
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, NULL, &buf) == ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(buf.data, buf.size, kIndefiniteAny,
                                    sizeof(kIndefiniteAny)));
        ASNBER_TEST_CHECK(asnber_buf_release(ctx, &buf) == ASNBER_OK);
        asnber_doc_destroy(doc);
        asnber_schema_destroy(schema);

        /* 未知字段的非规范 TLV：schema 路径拒绝，通用路径按 DER 规范化。 */
        schema = NULL;
        uint32_t intId = 0;
        uint32_t seqId = 0;
        asnber_type_desc_t intType =
            make_type("Int", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 2,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &intType, &intId) ==
                        ASNBER_OK);
        asnber_type_desc_t seqType =
            make_type("PlainSeq", ASNBER_TYPE_KIND_SEQUENCE, ASNBER_TAG_UNIVERSAL,
                      16, ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &seqType, &seqId) ==
                        ASNBER_OK);
        asnber_field_desc_t aField = make_field("a", intId, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_field(schema, seqId, &aField) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_set_root(schema, seqId) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);
        asnber_encode_options_init(&options);
        options.schema = schema;

        static const uint8_t kNonMinimalUnknown[9] = {
            0x30, 0x07, 0x02, 0x01, 0x05, 0x04, 0x81, 0x01, 0x00};
        static const uint8_t kNonMinimalUnknownGeneric[8] = {
            0x30, 0x06, 0x02, 0x01, 0x05, 0x04, 0x01, 0x00};
        static const uint8_t kIndefiniteUnknown[12] = {
            0x30, 0x0A, 0x02, 0x01, 0x05, 0x24,
            0x80, 0x02, 0x01, 0x05, 0x00, 0x00};
        static const uint8_t kIndefiniteUnknownGeneric[10] = {
            0x30, 0x08, 0x02, 0x01, 0x05, 0x24, 0x03, 0x02, 0x01, 0x05};
        static const uint8_t kLongTagUnknown[9] = {
            0x30, 0x07, 0x02, 0x01, 0x05, 0x1F, 0x02, 0x01, 0x05};
        static const uint8_t kLongTagUnknownGeneric[8] = {
            0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x05};

        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kNonMinimalUnknown,
                                      sizeof(kNonMinimalUnknown), 0, &doc) ==
                        ASNBER_OK);
        memset(&buf, 0, sizeof(buf));
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, &options, &buf) ==
                        ASNBER_E_NON_CANONICAL);
        ASNBER_TEST_CHECK(asnber_buf_release(ctx, &buf) == ASNBER_OK);
        memset(&buf, 0, sizeof(buf));
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, NULL, &buf) == ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(buf.data, buf.size,
                                    kNonMinimalUnknownGeneric,
                                    sizeof(kNonMinimalUnknownGeneric)));
        ASNBER_TEST_CHECK(asnber_buf_release(ctx, &buf) == ASNBER_OK);
        asnber_doc_destroy(doc);

        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kIndefiniteUnknown,
                                      sizeof(kIndefiniteUnknown), 0, &doc) ==
                        ASNBER_OK);
        memset(&buf, 0, sizeof(buf));
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, &options, &buf) ==
                        ASNBER_E_NON_CANONICAL);
        ASNBER_TEST_CHECK(asnber_buf_release(ctx, &buf) == ASNBER_OK);
        memset(&buf, 0, sizeof(buf));
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, NULL, &buf) == ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(buf.data, buf.size,
                                    kIndefiniteUnknownGeneric,
                                    sizeof(kIndefiniteUnknownGeneric)));
        ASNBER_TEST_CHECK(asnber_buf_release(ctx, &buf) == ASNBER_OK);
        asnber_doc_destroy(doc);

        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kLongTagUnknown,
                                      sizeof(kLongTagUnknown), 0, &doc) ==
                        ASNBER_OK);
        memset(&buf, 0, sizeof(buf));
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, &options, &buf) ==
                        ASNBER_E_NON_CANONICAL);
        ASNBER_TEST_CHECK(asnber_buf_release(ctx, &buf) == ASNBER_OK);
        memset(&buf, 0, sizeof(buf));
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, NULL, &buf) == ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(buf.data, buf.size, kLongTagUnknownGeneric,
                                    sizeof(kLongTagUnknownGeneric)));
        ASNBER_TEST_CHECK(asnber_buf_release(ctx, &buf) == ASNBER_OK);
        asnber_doc_destroy(doc);
        asnber_schema_destroy(schema);
    }
    return 0;
}

    /* ===== 3. CHOICE 分派 ===== */
static int check_choice_dispatch(asnber_ctx_t *ctx)
{
    {
        asnber_schema_t *schema = NULL;
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        uint32_t intId = 0;
        uint32_t strId = 0;
        uint32_t choiceId = 0;
        asnber_type_desc_t intType =
            make_type("Int", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 2,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &intType, &intId) ==
                        ASNBER_OK);
        asnber_type_desc_t strType =
            make_type("Str", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 12,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &strType, &strId) ==
                        ASNBER_OK);
        asnber_type_desc_t choiceType =
            make_type("Choice", ASNBER_TYPE_KIND_CHOICE, ASNBER_TAG_UNIVERSAL, 0,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &choiceType, &choiceId) ==
                        ASNBER_OK);
        asnber_field_desc_t intField = make_field("intValue", intId, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_field(schema, choiceId, &intField) ==
                        ASNBER_OK);
        asnber_field_desc_t strField = make_field("textValue", strId, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_field(schema, choiceId, &strField) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_set_root(schema, choiceId) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);

        static const uint8_t kText[5] = {0x0C, 0x03, 0x61, 0x62, 0x63};
        asnber_doc_t *doc = NULL;
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kText, sizeof(kText), 0,
                                      &doc) == ASNBER_OK);
        const asnber_node_t *root = asnber_doc_root(doc);
        ASNBER_TEST_CHECK(root != NULL);
        const char *branch = asnber_node_field_name(root);
        ASNBER_TEST_CHECK(branch != NULL);
        ASNBER_TEST_CHECK(strcmp(branch, "textValue") == 0);
        const uint8_t *content = NULL;
        size_t contentSize = 0;
        ASNBER_TEST_CHECK(asnber_node_content(root, &content, &contentSize) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(contentSize == 3);
        ASNBER_TEST_CHECK(memcmp(content, "abc", 3) == 0);
        asnber_doc_destroy(doc);
        asnber_schema_destroy(schema);
    }
    return 0;
}

    /* ===== 4. OF 绑定与 SIZE 区分字节数/元素数 ===== */
static int check_of_binding(asnber_ctx_t *ctx)
{
    {
        asnber_schema_t *schema = NULL;
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        uint32_t intId = 0;
        uint32_t ofId = 0;

        asnber_constraint_t sizeRange = make_size(1, 3);
        asnber_type_desc_t intType =
            make_type("Int", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 2,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &intType, &intId) ==
                        ASNBER_OK);
        asnber_type_desc_t ofType =
            make_type("Ints", ASNBER_TYPE_KIND_SEQUENCE_OF, ASNBER_TAG_UNIVERSAL,
                      16, ASNBER_TAG_MODE_DEFAULT, intId);
        ofType.constraints = &sizeRange;
        ofType.constraint_count = 1;
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &ofType, &ofId) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_set_root(schema, ofId) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);

        static const uint8_t kThree[11] = {0x30, 0x09, 0x02, 0x01, 0x01, 0x02,
                                           0x01, 0x02, 0x02, 0x01, 0x03};
        static const uint8_t kFour[14] = {0x30, 0x0C, 0x02, 0x01, 0x01, 0x02,
                                          0x01, 0x02, 0x02, 0x01, 0x03, 0x02,
                                          0x01, 0x04};
        asnber_doc_t *doc = NULL;
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kThree, sizeof(kThree), 0,
                                      &doc) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_child_count(asnber_doc_root(doc)) == 3);
        asnber_doc_destroy(doc);
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kFour, sizeof(kFour), 0,
                                      &doc) == ASNBER_E_SCHEMA_CONSTRAINT);
        ASNBER_TEST_CHECK(doc == NULL);
        asnber_schema_destroy(schema);
    }

    {
        /* OCTET STRING 的 SIZE 按字节数。 */
        asnber_schema_t *schema = NULL;
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        uint32_t octId = 0;
        asnber_constraint_t sizeRange = make_size(2, 4);
        asnber_type_desc_t octType =
            make_type("Octets", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 4,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        octType.constraints = &sizeRange;
        octType.constraint_count = 1;
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &octType, &octId) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_set_root(schema, octId) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);

        static const uint8_t kOk[4] = {0x04, 0x02, 0xAA, 0xBB};
        static const uint8_t kTooLong[7] = {0x04, 0x05, 0xAA, 0xBB,
                                            0xCC, 0xDD, 0xEE};
        asnber_doc_t *doc = NULL;
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kOk, sizeof(kOk), 0,
                                      &doc) == ASNBER_OK);
        asnber_doc_destroy(doc);
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kTooLong, sizeof(kTooLong),
                                      0, &doc) == ASNBER_E_SCHEMA_CONSTRAINT);
        asnber_schema_destroy(schema);
    }
    return 0;
}

    /* ===== 5. RANGE / ENUM / MAX / BIGINT ===== */
static int check_constraints(asnber_ctx_t *ctx)
{
    {
        asnber_schema_t *schema = NULL;
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        uint32_t rangeId = 0;
        asnber_constraint_t range = make_range(0, 10);
        asnber_type_desc_t rangeType =
            make_type("Ranged", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 2,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        rangeType.constraints = &range;
        rangeType.constraint_count = 1;
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &rangeType, &rangeId) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_set_root(schema, rangeId) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);

        static const uint8_t kTen[3] = {0x02, 0x01, 0x0A};
        static const uint8_t kEleven[3] = {0x02, 0x01, 0x0B};
        asnber_doc_t *doc = NULL;
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kTen, sizeof(kTen), 0,
                                      &doc) == ASNBER_OK);
        asnber_doc_destroy(doc);
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kEleven, sizeof(kEleven), 0,
                                      &doc) == ASNBER_E_SCHEMA_CONSTRAINT);
        asnber_schema_destroy(schema);
    }

    {
        /* ENUM 与负值。 */
        asnber_schema_t *schema = NULL;
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        static const int64_t kValues[2] = {1, 3};
        asnber_constraint_t enumConstraint;
        memset(&enumConstraint, 0, sizeof(enumConstraint));
        enumConstraint.struct_size = sizeof(enumConstraint);
        enumConstraint.kind = ASNBER_CONSTRAINT_ENUM;
        enumConstraint.enum_values = kValues;
        enumConstraint.enum_count = 2;
        uint32_t enumId = 0;
        asnber_type_desc_t enumType =
            make_type("Enum", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 2,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        enumType.constraints = &enumConstraint;
        enumType.constraint_count = 1;
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &enumType, &enumId) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_set_root(schema, enumId) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);

        static const uint8_t kOne[3] = {0x02, 0x01, 0x01};
        static const uint8_t kTwo[3] = {0x02, 0x01, 0x02};
        asnber_doc_t *doc = NULL;
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kOne, sizeof(kOne), 0,
                                      &doc) == ASNBER_OK);
        asnber_doc_destroy(doc);
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kTwo, sizeof(kTwo), 0,
                                      &doc) == ASNBER_E_SCHEMA_CONSTRAINT);
        asnber_schema_destroy(schema);
    }

    {
        /* MAX：下界 0、上界无界。 */
        asnber_schema_t *schema = NULL;
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        asnber_constraint_t maxConstraint;
        memset(&maxConstraint, 0, sizeof(maxConstraint));
        maxConstraint.struct_size = sizeof(maxConstraint);
        maxConstraint.kind = ASNBER_CONSTRAINT_MAX;
        maxConstraint.lower = make_bound(0);
        asnber_bound_t upper;
        memset(&upper, 0, sizeof(upper));
        upper.struct_size = sizeof(upper);
        upper.is_unbounded = 1;
        maxConstraint.upper = upper;
        uint32_t maxId = 0;
        asnber_type_desc_t maxType =
            make_type("NonNegative", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL,
                      2, ASNBER_TAG_MODE_DEFAULT, 0);
        maxType.constraints = &maxConstraint;
        maxType.constraint_count = 1;
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &maxType, &maxId) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_set_root(schema, maxId) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);

        static const uint8_t kZero[3] = {0x02, 0x01, 0x00};
        static const uint8_t kMinusOne[3] = {0x02, 0x01, 0xFF};
        asnber_doc_t *doc = NULL;
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kZero, sizeof(kZero), 0,
                                      &doc) == ASNBER_OK);
        asnber_doc_destroy(doc);
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kMinusOne, sizeof(kMinusOne),
                                      0, &doc) == ASNBER_E_SCHEMA_CONSTRAINT);
        asnber_schema_destroy(schema);
    }

    {
        /* BIGINT：超出 int64 的边界按十进制比较。 */
        asnber_schema_t *schema = NULL;
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        static const char kLower[] = "-9223372036854775808";
        static const char kUpper[] = "9223372036854775808";
        asnber_constraint_t bigint;
        memset(&bigint, 0, sizeof(bigint));
        bigint.struct_size = sizeof(bigint);
        bigint.kind = ASNBER_CONSTRAINT_BIGINT_RANGE;
        bigint.lower = make_decimal_bound(kLower);
        bigint.upper = make_decimal_bound(kUpper);
        uint32_t bigId = 0;
        asnber_type_desc_t bigType =
            make_type("BigInt", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 2,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        bigType.constraints = &bigint;
        bigType.constraint_count = 1;
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &bigType, &bigId) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_set_root(schema, bigId) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);

        /* 2^63 = 0x8000000000000000，需前置 0x00 保证为非负。 */
        static const uint8_t kAtUpper[11] = {0x02, 0x09, 0x00, 0x80, 0x00, 0x00,
                                             0x00, 0x00, 0x00, 0x00, 0x00};
        static const uint8_t kAboveUpper[11] = {0x02, 0x09, 0x00, 0x80, 0x00,
                                                0x00, 0x00, 0x00, 0x00, 0x00,
                                                0x01};
        static const uint8_t kAtLower[10] = {0x02, 0x08, 0x80, 0x00, 0x00,
                                             0x00, 0x00, 0x00, 0x00, 0x00};
        asnber_doc_t *doc = NULL;
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kAtUpper, sizeof(kAtUpper),
                                      0, &doc) == ASNBER_OK);
        asnber_doc_destroy(doc);
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kAtLower, sizeof(kAtLower),
                                      0, &doc) == ASNBER_OK);
        asnber_doc_destroy(doc);
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kAboveUpper,
                                      sizeof(kAboveUpper), 0, &doc) ==
                        ASNBER_E_SCHEMA_CONSTRAINT);
        asnber_schema_destroy(schema);
    }
    return 0;
}

    /* ===== 6. SET 与 SET OF 的 DER 排序 ===== */
static int check_set_sorting(asnber_ctx_t *ctx)
{
    {
        asnber_schema_t *schema = NULL;
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        uint32_t intId = 0;
        uint32_t octId = 0;
        uint32_t setId = 0;
        asnber_type_desc_t intType =
            make_type("Int", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 2,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &intType, &intId) ==
                        ASNBER_OK);
        asnber_type_desc_t octType =
            make_type("Octets", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 4,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &octType, &octId) ==
                        ASNBER_OK);
        asnber_type_desc_t setType =
            make_type("Bag", ASNBER_TYPE_KIND_SET, ASNBER_TAG_UNIVERSAL, 17,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &setType, &setId) ==
                        ASNBER_OK);
        asnber_field_desc_t aField = make_field("a", intId, 0);
        asnber_field_desc_t bField = make_field("b", octId, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_field(schema, setId, &aField) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_add_field(schema, setId, &bField) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_set_root(schema, setId) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);

        static const uint8_t kBagIn[9] = {0x31, 0x07, 0x04, 0x02, 0xAA,
                                          0xBB, 0x02, 0x01, 0x05};
        static const uint8_t kBagSorted[9] = {0x31, 0x07, 0x02, 0x01, 0x05,
                                              0x04, 0x02, 0xAA, 0xBB};
        asnber_doc_t *doc = NULL;
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kBagIn, sizeof(kBagIn), 0,
                                      &doc) == ASNBER_OK);
        uint8_t schemaOut[16];
        uint8_t genericOut[16];
        size_t schemaSize = 0;
        size_t genericSize = 0;
        ASNBER_TEST_CHECK(encode_both(ctx, schema, doc, schemaOut,
                                    sizeof(schemaOut), &schemaSize, genericOut,
                                    sizeof(genericOut), &genericSize) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(schemaOut, schemaSize, kBagSorted,
                                    sizeof(kBagSorted)));
        ASNBER_TEST_CHECK(bytes_equal(genericOut, genericSize, kBagSorted,
                                    sizeof(kBagSorted)));
        asnber_doc_destroy(doc);
        asnber_schema_destroy(schema);
    }

    {
        /* SET 字段使用 context 标签：编码按完整 TLV（标签优先）排序，
         * 与 schema 字段声明顺序无关。 */
        asnber_schema_t *schema = NULL;
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        uint32_t tag2Id = 0;
        uint32_t tag0Id = 0;
        uint32_t setId = 0;
        asnber_type_desc_t tag2Type =
            make_type("CtxTag2", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_CONTEXT, 2,
                      ASNBER_TAG_MODE_IMPLICIT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &tag2Type, &tag2Id) ==
                        ASNBER_OK);
        asnber_type_desc_t tag0Type =
            make_type("CtxTag0", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_CONTEXT, 0,
                      ASNBER_TAG_MODE_IMPLICIT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &tag0Type, &tag0Id) ==
                        ASNBER_OK);
        asnber_type_desc_t setType =
            make_type("CtxBag", ASNBER_TYPE_KIND_SET, ASNBER_TAG_UNIVERSAL, 17,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &setType, &setId) ==
                        ASNBER_OK);
        /* 声明顺序故意与标签顺序相反，迫使编码器实际排序。 */
        asnber_field_desc_t tag2Field = make_field("late", tag2Id, 0);
        asnber_field_desc_t tag0Field = make_field("early", tag0Id, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_field(schema, setId, &tag2Field) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_add_field(schema, setId, &tag0Field) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_set_root(schema, setId) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);

        static const uint8_t kIn[8] = {0x31, 0x06, 0x82, 0x01, 0x06,
                                       0x80, 0x01, 0x05};
        static const uint8_t kSorted[8] = {0x31, 0x06, 0x80, 0x01, 0x05,
                                           0x82, 0x01, 0x06};
        asnber_doc_t *doc = NULL;
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kIn, sizeof(kIn), 0,
                                      &doc) == ASNBER_OK);
        uint8_t schemaOut[16];
        uint8_t genericOut[16];
        size_t schemaSize = 0;
        size_t genericSize = 0;
        ASNBER_TEST_CHECK(encode_both(ctx, schema, doc, schemaOut,
                                    sizeof(schemaOut), &schemaSize, genericOut,
                                    sizeof(genericOut), &genericSize) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(schemaOut, schemaSize, kSorted,
                                    sizeof(kSorted)));
        ASNBER_TEST_CHECK(bytes_equal(genericOut, genericSize, kSorted,
                                    sizeof(kSorted)));
        asnber_doc_destroy(doc);

        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kSorted, sizeof(kSorted), 0,
                                      &doc) == ASNBER_OK);
        ASNBER_TEST_CHECK(encode_both(ctx, schema, doc, schemaOut,
                                    sizeof(schemaOut), &schemaSize, genericOut,
                                    sizeof(genericOut), &genericSize) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(schemaOut, schemaSize, kSorted,
                                    sizeof(kSorted)));
        ASNBER_TEST_CHECK(bytes_equal(genericOut, genericSize, kSorted,
                                    sizeof(kSorted)));
        asnber_doc_destroy(doc);
        asnber_schema_destroy(schema);
    }

    {
        /* SET OF INTEGER：编码按元素完整 TLV 排序。 */
        asnber_schema_t *schema = NULL;
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        uint32_t intId = 0;
        uint32_t ofId = 0;
        asnber_type_desc_t intType =
            make_type("Int", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 2,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &intType, &intId) ==
                        ASNBER_OK);
        asnber_type_desc_t ofType =
            make_type("IntSet", ASNBER_TYPE_KIND_SET_OF, ASNBER_TAG_UNIVERSAL, 17,
                      ASNBER_TAG_MODE_DEFAULT, intId);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &ofType, &ofId) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_set_root(schema, ofId) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);

        static const uint8_t kIn[8] = {0x31, 0x06, 0x02, 0x01,
                                       0x06, 0x02, 0x01, 0x05};
        static const uint8_t kSorted[8] = {0x31, 0x06, 0x02, 0x01,
                                           0x05, 0x02, 0x01, 0x06};
        asnber_doc_t *doc = NULL;
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kIn, sizeof(kIn), 0,
                                      &doc) == ASNBER_OK);
        uint8_t schemaOut[16];
        uint8_t genericOut[16];
        size_t schemaSize = 0;
        size_t genericSize = 0;
        ASNBER_TEST_CHECK(encode_both(ctx, schema, doc, schemaOut,
                                    sizeof(schemaOut), &schemaSize, genericOut,
                                    sizeof(genericOut), &genericSize) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(schemaOut, schemaSize, kSorted,
                                    sizeof(kSorted)));
        ASNBER_TEST_CHECK(bytes_equal(genericOut, genericSize, kSorted,
                                    sizeof(kSorted)));
        asnber_doc_destroy(doc);

        /* 已排序输入重新解码再编码：结果保持不变（排序幂等）。 */
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kSorted, sizeof(kSorted), 0,
                                      &doc) == ASNBER_OK);
        ASNBER_TEST_CHECK(encode_both(ctx, schema, doc, schemaOut,
                                    sizeof(schemaOut), &schemaSize, genericOut,
                                    sizeof(genericOut), &genericSize) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(schemaOut, schemaSize, kSorted,
                                    sizeof(kSorted)));
        ASNBER_TEST_CHECK(bytes_equal(genericOut, genericSize, kSorted,
                                    sizeof(kSorted)));
        asnber_doc_destroy(doc);
        asnber_schema_destroy(schema);
    }

    {
        /* SET OF ANY：异构元素解码 + DER 排序回写。 */
        asnber_schema_t *schema = NULL;
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        uint32_t anyId = 0;
        uint32_t ofId = 0;
        asnber_type_desc_t anyType =
            make_type("AnyType", ASNBER_TYPE_KIND_ANY, ASNBER_TAG_UNIVERSAL, 0,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &anyType, &anyId) ==
                        ASNBER_OK);
        asnber_constraint_t sizeRange = make_size(1, 4);
        asnber_type_desc_t ofType =
            make_type("AttributeSet", ASNBER_TYPE_KIND_SET_OF,
                      ASNBER_TAG_UNIVERSAL, 17, ASNBER_TAG_MODE_DEFAULT, anyId);
        ofType.constraints = &sizeRange;
        ofType.constraint_count = 1;
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &ofType, &ofId) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_set_root(schema, ofId) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);

        static const uint8_t kUnsorted[13] = {0x31, 0x0B, 0x05, 0x00, 0x02, 0x01,
                                              0x05, 0x04, 0x02, 0xAA, 0xBB, 0x30,
                                              0x00};
        static const uint8_t kSorted[13] = {0x31, 0x0B, 0x02, 0x01, 0x05, 0x04,
                                            0x02, 0xAA, 0xBB, 0x05, 0x00, 0x30,
                                            0x00};
        asnber_doc_t *doc = NULL;
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kUnsorted, sizeof(kUnsorted),
                                      0, &doc) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_child_count(asnber_doc_root(doc)) == 4);
        for (size_t i = 0; i < 4; ++i) {
            ASNBER_TEST_CHECK(asnber_node_child_count(
                                asnber_node_child_at(asnber_doc_root(doc), i)) == 0);
        }
        uint8_t schemaOut[16];
        uint8_t genericOut[16];
        size_t schemaSize = 0;
        size_t genericSize = 0;
        ASNBER_TEST_CHECK(encode_both(ctx, schema, doc, schemaOut,
                                    sizeof(schemaOut), &schemaSize, genericOut,
                                    sizeof(genericOut), &genericSize) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(schemaOut, schemaSize, kSorted,
                                    sizeof(kSorted)));
        ASNBER_TEST_CHECK(bytes_equal(genericOut, genericSize, kSorted,
                                    sizeof(kSorted)));
        asnber_doc_destroy(doc);

        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kSorted, sizeof(kSorted), 0,
                                      &doc) == ASNBER_OK);
        ASNBER_TEST_CHECK(encode_both(ctx, schema, doc, schemaOut,
                                    sizeof(schemaOut), &schemaSize, genericOut,
                                    sizeof(genericOut), &genericSize) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(schemaOut, schemaSize, kSorted,
                                    sizeof(kSorted)));
        asnber_doc_destroy(doc);
        asnber_schema_destroy(schema);
    }
    return 0;
}

    /* ===== 7. EXPLICIT ANY 重新包装 ===== */
static int check_explicit_any(asnber_ctx_t *ctx)
{
    {
        asnber_schema_t *schema = NULL;
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        uint32_t oidId = 0;
        uint32_t anyId = 0;
        uint32_t valueId = 0;
        uint32_t seqId = 0;
        asnber_type_desc_t oidType =
            make_type("Oid", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 6,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &oidType, &oidId) ==
                        ASNBER_OK);
        asnber_type_desc_t anyType =
            make_type("AnyType", ASNBER_TYPE_KIND_ANY, ASNBER_TAG_UNIVERSAL, 0,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &anyType, &anyId) ==
                        ASNBER_OK);
        asnber_type_desc_t valueType =
            make_type("WrappedAny", ASNBER_TYPE_KIND_ANY, ASNBER_TAG_CONTEXT, 1,
                      ASNBER_TAG_MODE_EXPLICIT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &valueType, &valueId) ==
                        ASNBER_OK);
        asnber_type_desc_t seqType =
            make_type("WithWrapped", ASNBER_TYPE_KIND_SEQUENCE,
                      ASNBER_TAG_UNIVERSAL, 16, ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &seqType, &seqId) ==
                        ASNBER_OK);
        asnber_field_desc_t idField = make_field("id", oidId, 0);
        asnber_field_desc_t valueField = make_field("value", valueId, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_field(schema, seqId, &idField) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_add_field(schema, seqId, &valueField) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_set_root(schema, seqId) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);

        /* 内层为 OCTET STRING。 */
        static const uint8_t kOctetsIn[11] = {0x30, 0x09, 0x06, 0x01, 0x2A,
                                              0xA1, 0x04, 0x04, 0x02, 0xAA,
                                              0xBB};
        asnber_doc_t *doc = NULL;
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kOctetsIn, sizeof(kOctetsIn),
                                      0, &doc) == ASNBER_OK);
        const asnber_node_t *root = asnber_doc_root(doc);
        const asnber_node_t *value = asnber_node_child_by_name(root, "value");
        ASNBER_TEST_CHECK(value != NULL);
        ASNBER_TEST_CHECK(asnber_node_child_count(value) == 0);
        size_t tlvSize = 0;
        const uint8_t *tlv = asnber_node_tlv(value, &tlvSize);
        ASNBER_TEST_CHECK(tlvSize == 6);
        ASNBER_TEST_CHECK(tlv != NULL && tlv[0] == 0xA1);
        const uint8_t *content = NULL;
        size_t contentSize = 0;
        ASNBER_TEST_CHECK(asnber_node_content(value, &content, &contentSize) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(contentSize == 4);
        ASNBER_TEST_CHECK(bytes_equal(content, contentSize, kOctetsIn + 7, 4));

        uint8_t schemaOut[16];
        uint8_t genericOut[16];
        size_t schemaSize = 0;
        size_t genericSize = 0;
        ASNBER_TEST_CHECK(encode_both(ctx, schema, doc, schemaOut,
                                    sizeof(schemaOut), &schemaSize, genericOut,
                                    sizeof(genericOut), &genericSize) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(schemaOut, schemaSize, kOctetsIn,
                                    sizeof(kOctetsIn)));
        ASNBER_TEST_CHECK(bytes_equal(genericOut, genericSize, kOctetsIn,
                                    sizeof(kOctetsIn)));
        asnber_doc_destroy(doc);

        /* 内层为 SEQUENCE。 */
        static const uint8_t kSeqIn[9] = {0x30, 0x07, 0x06, 0x01,
                                          0x2A, 0xA1, 0x02, 0x30, 0x00};
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kSeqIn, sizeof(kSeqIn), 0,
                                      &doc) == ASNBER_OK);
        root = asnber_doc_root(doc);
        value = asnber_node_child_by_name(root, "value");
        ASNBER_TEST_CHECK(value != NULL);
        ASNBER_TEST_CHECK(asnber_node_child_count(value) == 0);
        ASNBER_TEST_CHECK(asnber_node_content(value, &content, &contentSize) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(contentSize == 2);
        ASNBER_TEST_CHECK(content[0] == 0x30 && content[1] == 0x00);
        ASNBER_TEST_CHECK(encode_both(ctx, schema, doc, schemaOut,
                                    sizeof(schemaOut), &schemaSize, genericOut,
                                    sizeof(genericOut), &genericSize) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(schemaOut, schemaSize, kSeqIn,
                                    sizeof(kSeqIn)));
        asnber_doc_destroy(doc);
        asnber_schema_destroy(schema);
    }
    return 0;
}

    /* ===== 8. asnber_doc_validate ===== */
static int check_doc_validate(asnber_ctx_t *ctx)
{
    {
        asnber_schema_t *schema = NULL;
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        uint32_t intId = 0;
        uint32_t seqId = 0;
        asnber_type_desc_t intType =
            make_type("Int", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 2,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &intType, &intId) ==
                        ASNBER_OK);
        asnber_type_desc_t seqType =
            make_type("Single", ASNBER_TYPE_KIND_SEQUENCE, ASNBER_TAG_UNIVERSAL, 16,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &seqType, &seqId) ==
                        ASNBER_OK);
        asnber_field_desc_t aField = make_field("a", intId, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_field(schema, seqId, &aField) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_set_root(schema, seqId) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);

        static const uint8_t kGood[5] = {0x30, 0x03, 0x02, 0x01, 0x05};
        static const uint8_t kBadChild[5] = {0x30, 0x03, 0x04, 0x01, 0x05};
        static const uint8_t kBadRoot[5] = {0x31, 0x03, 0x02, 0x01, 0x05};
        asnber_doc_t *doc = NULL;
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kGood, sizeof(kGood), 0,
                                      &doc) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_doc_validate(ctx, doc, schema, NULL) == ASNBER_OK);
        asnber_doc_destroy(doc);

        size_t consumed = 0;
        /* 根标签不匹配：schema 类型错误。 */
        ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, kBadRoot, sizeof(kBadRoot),
                                           NULL, &doc, &consumed) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_doc_validate(ctx, doc, schema, NULL) ==
                        ASNBER_E_SCHEMA_TYPE);
        asnber_doc_destroy(doc);

        /* 必选字段缺失：schema 字段错误。 */
        ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, kBadChild, sizeof(kBadChild),
                                           NULL, &doc, &consumed) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_doc_validate(ctx, doc, schema, NULL) ==
                        ASNBER_E_SCHEMA_FIELD);

        /* 同一文档走 schema 编码：必选字段无法绑定同样报字段错误。 */
        asnber_encode_options_t encodeOptions;
        asnber_encode_options_init(&encodeOptions);
        encodeOptions.schema = schema;
        asnber_buf_t encoded;
        memset(&encoded, 0, sizeof(encoded));
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, &encodeOptions, &encoded) ==
                        ASNBER_E_SCHEMA_FIELD);
        ASNBER_TEST_CHECK(encoded.data == NULL && encoded.size == 0);
        asnber_doc_destroy(doc);
        asnber_schema_destroy(schema);
    }
    return 0;
}

    /* ===== 9. 真实证书：AlgorithmIdentifier.parameters 的 ANY ===== */
static int check_real_certificate_any(asnber_ctx_t *ctx)
{
    {
        asnber_schema_t *schema = NULL;
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        uint32_t oidId = 0;
        uint32_t anyId = 0;
        uint32_t algId = 0;
        uint32_t tbsId = 0;
        uint32_t bitStrId = 0;
        uint32_t certId = 0;
        asnber_type_desc_t oidType =
            make_type("Oid", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 6,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &oidType, &oidId) ==
                        ASNBER_OK);
        asnber_type_desc_t anyType =
            make_type("AnyType", ASNBER_TYPE_KIND_ANY, ASNBER_TAG_UNIVERSAL, 0,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &anyType, &anyId) ==
                        ASNBER_OK);
        asnber_type_desc_t algType =
            make_type("AlgorithmIdentifier", ASNBER_TYPE_KIND_SEQUENCE,
                      ASNBER_TAG_UNIVERSAL, 16, ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &algType, &algId) ==
                        ASNBER_OK);
        asnber_field_desc_t algField = make_field("algorithm", oidId, 0);
        asnber_field_desc_t paramField =
            make_field("parameters", anyId, ASNBER_FIELD_OPTIONAL);
        ASNBER_TEST_CHECK(asnber_schema_add_field(schema, algId, &algField) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_add_field(schema, algId, &paramField) ==
                        ASNBER_OK);

        asnber_type_desc_t tbsType =
            make_type("TbsCertificate", ASNBER_TYPE_KIND_SEQUENCE,
                      ASNBER_TAG_UNIVERSAL, 16, ASNBER_TAG_MODE_DEFAULT, 0);
        tbsType.flags = ASNBER_TYPE_EXTENSIBLE;
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &tbsType, &tbsId) ==
                        ASNBER_OK);
        asnber_type_desc_t bitType =
            make_type("BitString", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 3,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &bitType, &bitStrId) ==
                        ASNBER_OK);
        asnber_type_desc_t certType =
            make_type("Certificate", ASNBER_TYPE_KIND_SEQUENCE,
                      ASNBER_TAG_UNIVERSAL, 16, ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &certType, &certId) ==
                        ASNBER_OK);
        asnber_field_desc_t tbsField = make_field("tbsCertificate", tbsId, 0);
        asnber_field_desc_t sigField =
            make_field("signatureAlgorithm", algId, 0);
        asnber_field_desc_t valueField =
            make_field("signatureValue", bitStrId, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_field(schema, certId, &tbsField) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_add_field(schema, certId, &sigField) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_add_field(schema, certId, &valueField) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_set_root(schema, certId) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);

        asnber_doc_t *doc = NULL;

        /* RSA：parameters = NULL。 */
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kCertRsaSelfsigned,
                                      kCertRsaSelfsignedSize, 0, &doc) ==
                        ASNBER_OK);
        const asnber_node_t *root = asnber_doc_root(doc);
        ASNBER_TEST_CHECK(root != NULL);
        ASNBER_TEST_CHECK(asnber_node_field_name(root) == NULL);
        const asnber_node_t *alg =
            asnber_node_child_by_name(root, "signatureAlgorithm");
        ASNBER_TEST_CHECK(alg != NULL);
        ASNBER_TEST_CHECK(asnber_node_child_count(alg) == 2);
        const asnber_node_t *params =
            asnber_node_child_by_name(alg, "parameters");
        ASNBER_TEST_CHECK(params != NULL);
        ASNBER_TEST_CHECK(asnber_node_child_count(params) == 0);
        size_t size = 0;
        const uint8_t *tlv = asnber_node_tlv(params, &size);
        ASNBER_TEST_CHECK(size == 2);
        ASNBER_TEST_CHECK(tlv != NULL && tlv[0] == 0x05 && tlv[1] == 0x00);
        asnber_doc_destroy(doc);

        /* RSA-PSS：parameters 为 SEQUENCE，ANY 不展开。 */
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kCertRsaPssSelfsigned,
                                      kCertRsaPssSelfsignedSize, 0, &doc) ==
                        ASNBER_OK);
        root = asnber_doc_root(doc);
        alg = asnber_node_child_by_name(root, "signatureAlgorithm");
        ASNBER_TEST_CHECK(alg != NULL);
        params = asnber_node_child_by_name(alg, "parameters");
        ASNBER_TEST_CHECK(params != NULL);
        ASNBER_TEST_CHECK(asnber_node_child_count(params) == 0);
        tlv = asnber_node_tlv(params, &size);
        ASNBER_TEST_CHECK(size > 2);
        ASNBER_TEST_CHECK(tlv != NULL && tlv[0] == 0x30);
        asnber_doc_destroy(doc);

        /* EC：ecdsa-with-SHA256 不带 parameters。 */
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kCertEcSelfsigned,
                                      kCertEcSelfsignedSize, 0, &doc) ==
                        ASNBER_OK);
        root = asnber_doc_root(doc);
        alg = asnber_node_child_by_name(root, "signatureAlgorithm");
        ASNBER_TEST_CHECK(alg != NULL);
        ASNBER_TEST_CHECK(asnber_node_child_count(alg) == 1);
        ASNBER_TEST_CHECK(asnber_node_child_by_name(alg, "parameters") == NULL);
        asnber_doc_destroy(doc);

        asnber_schema_destroy(schema);
    }
    return 0;
}

    /* ===== 10. 回归：ENUMERATED 与 IMPLICIT 标签的约束/绑定 ===== */
static int check_enum_implicit_regression(asnber_ctx_t *ctx)
{
    {
        /* ENUMERATED（universal tag 10）参与 ENUM 约束求值。 */
        asnber_schema_t *schema = NULL;
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        static const int64_t kEnums[3] = {1, 3, 5};
        asnber_constraint_t enumConstraint;
        memset(&enumConstraint, 0, sizeof(enumConstraint));
        enumConstraint.struct_size = sizeof(enumConstraint);
        enumConstraint.kind = ASNBER_CONSTRAINT_ENUM;
        enumConstraint.enum_values = kEnums;
        enumConstraint.enum_count = 3;
        uint32_t enumId = 0;
        asnber_type_desc_t enumType =
            make_type("Enum", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 10,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        enumType.constraints = &enumConstraint;
        enumType.constraint_count = 1;
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &enumType, &enumId) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_set_root(schema, enumId) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);

        static const uint8_t kEnumOk[3] = {0x0A, 0x01, 0x03};
        static const uint8_t kEnumBad[3] = {0x0A, 0x01, 0x02};
        asnber_doc_t *doc = NULL;
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kEnumOk, sizeof(kEnumOk), 0,
                                      &doc) == ASNBER_OK);
        int64_t value = 0;
        ASNBER_TEST_CHECK(asnber_node_get_int64(asnber_doc_root(doc), &value) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(value == 3);
        asnber_doc_destroy(doc);
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kEnumBad, sizeof(kEnumBad),
                                      0, &doc) == ASNBER_E_SCHEMA_CONSTRAINT);
        asnber_schema_destroy(schema);
    }

    {
        /* IMPLICIT 隐式覆盖的 INTEGER：RANGE 约束按数值求值。 */
        asnber_schema_t *schema = NULL;
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        asnber_constraint_t range = make_range(0, 10);
        uint32_t intId = 0;
        asnber_type_desc_t intType =
            make_type("ImplicitInt", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_CONTEXT, 0,
                      ASNBER_TAG_MODE_IMPLICIT, 0);
        intType.constraints = &range;
        intType.constraint_count = 1;
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &intType, &intId) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_set_root(schema, intId) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);

        static const uint8_t kImplicitOk[3] = {0x80, 0x01, 0x05};
        static const uint8_t kImplicitBad[3] = {0x80, 0x01, 0x0B};
        asnber_doc_t *doc = NULL;
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kImplicitOk,
                                      sizeof(kImplicitOk), 0, &doc) ==
                        ASNBER_OK);
        /* 非通用标签节点不提供数值读取，直接核对内容。 */
        const uint8_t *content = NULL;
        size_t contentSize = 0;
        ASNBER_TEST_CHECK(asnber_node_content(asnber_doc_root(doc), &content,
                                          &contentSize) == ASNBER_OK);
        ASNBER_TEST_CHECK(contentSize == 1 && content != NULL &&
                        content[0] == 0x05);
        asnber_doc_destroy(doc);
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kImplicitBad,
                                      sizeof(kImplicitBad), 0, &doc) ==
                        ASNBER_E_SCHEMA_CONSTRAINT);
        asnber_schema_destroy(schema);
    }

    {
        /* IMPLICIT 隐式覆盖的 SEQUENCE：按类型自身标签匹配。 */
        asnber_schema_t *schema = NULL;
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        uint32_t intId = 0;
        uint32_t seqId = 0;
        asnber_type_desc_t intType =
            make_type("Int", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 2,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &intType, &intId) ==
                        ASNBER_OK);
        asnber_type_desc_t seqType =
            make_type("ImplicitSeq", ASNBER_TYPE_KIND_SEQUENCE, ASNBER_TAG_CONTEXT,
                      13, ASNBER_TAG_MODE_IMPLICIT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &seqType, &seqId) ==
                        ASNBER_OK);
        asnber_field_desc_t xField = make_field("x", intId, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_field(schema, seqId, &xField) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_set_root(schema, seqId) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);

        static const uint8_t kImplSeq[5] = {0xAD, 0x03, 0x02, 0x01, 0x05};
        asnber_doc_t *doc = NULL;
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kImplSeq, sizeof(kImplSeq),
                                      0, &doc) == ASNBER_OK);
        const asnber_node_t *root = asnber_doc_root(doc);
        const asnber_node_t *x = asnber_node_child_by_name(root, "x");
        ASNBER_TEST_CHECK(x != NULL);
        int64_t value = 0;
        ASNBER_TEST_CHECK(asnber_node_get_int64(x, &value) == ASNBER_OK);
        ASNBER_TEST_CHECK(value == 5);
        asnber_doc_destroy(doc);
        asnber_schema_destroy(schema);
    }

    {
        /* IMPLICIT 覆盖的 SEQUENCE：schema 编码往返稳定在类型自身 context 标签。 */
        asnber_schema_t *schema = NULL;
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        uint32_t intId = 0;
        uint32_t seqId = 0;
        asnber_type_desc_t intType =
            make_type("Int", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 2,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &intType, &intId) ==
                        ASNBER_OK);
        asnber_type_desc_t seqType =
            make_type("ImplicitSeq", ASNBER_TYPE_KIND_SEQUENCE, ASNBER_TAG_CONTEXT,
                      13, ASNBER_TAG_MODE_IMPLICIT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &seqType, &seqId) ==
                        ASNBER_OK);
        asnber_field_desc_t xField = make_field("x", intId, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_field(schema, seqId, &xField) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_set_root(schema, seqId) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);

        static const uint8_t kImplSeq[5] = {0xAD, 0x03, 0x02, 0x01, 0x05};
        asnber_doc_t *doc = NULL;
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kImplSeq, sizeof(kImplSeq),
                                      0, &doc) == ASNBER_OK);
        asnber_encode_options_t options;
        asnber_encode_options_init(&options);
        options.schema = schema;
        asnber_buf_t buf;
        memset(&buf, 0, sizeof(buf));
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, &options, &buf) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(buf.data, buf.size, kImplSeq,
                                    sizeof(kImplSeq)));
        asnber_doc_destroy(doc);

        /* 编码结果再解码：字段值与原始输入一致。 */
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, buf.data, buf.size, 0,
                                      &doc) == ASNBER_OK);
        const asnber_node_t *root = asnber_doc_root(doc);
        int64_t value = 0;
        ASNBER_TEST_CHECK(asnber_node_get_int64(asnber_node_child_by_name(root, "x"),
                                            &value) == ASNBER_OK);
        ASNBER_TEST_CHECK(value == 5);
        asnber_doc_destroy(doc);
        ASNBER_TEST_CHECK(asnber_buf_release(ctx, &buf) == ASNBER_OK);
        asnber_schema_destroy(schema);
    }

    {
        /* IMPLICIT 覆盖的 SET：schema 编码沿用 DER SET OF 排序并往返稳定。 */
        asnber_schema_t *schema = NULL;
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        uint32_t intId = 0;
        uint32_t octId = 0;
        uint32_t setId = 0;
        asnber_type_desc_t intType =
            make_type("Int", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 2,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &intType, &intId) ==
                        ASNBER_OK);
        asnber_type_desc_t octType =
            make_type("Octets", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 4,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &octType, &octId) ==
                        ASNBER_OK);
        asnber_type_desc_t setType =
            make_type("ImplicitSet", ASNBER_TYPE_KIND_SET, ASNBER_TAG_CONTEXT, 14,
                      ASNBER_TAG_MODE_IMPLICIT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &setType, &setId) ==
                        ASNBER_OK);
        asnber_field_desc_t aField = make_field("a", intId, 0);
        asnber_field_desc_t bField = make_field("b", octId, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_field(schema, setId, &aField) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_add_field(schema, setId, &bField) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_set_root(schema, setId) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);

        static const uint8_t kImplSet[8] = {0xAE, 0x06, 0x02, 0x01, 0x05,
                                            0x04, 0x01, 0x41};
        asnber_doc_t *doc = NULL;
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kImplSet, sizeof(kImplSet),
                                      0, &doc) == ASNBER_OK);
        asnber_encode_options_t options;
        asnber_encode_options_init(&options);
        options.schema = schema;
        asnber_buf_t buf;
        memset(&buf, 0, sizeof(buf));
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, &options, &buf) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(buf.data, buf.size, kImplSet,
                                    sizeof(kImplSet)));
        asnber_doc_destroy(doc);

        ASNBER_TEST_CHECK(decode_schema(ctx, schema, buf.data, buf.size, 0,
                                      &doc) == ASNBER_OK);
        const asnber_node_t *root = asnber_doc_root(doc);
        int64_t a = 0;
        const uint8_t *b = NULL;
        size_t bSize = 0;
        ASNBER_TEST_CHECK(asnber_node_get_int64(asnber_node_child_by_name(root, "a"),
                                            &a) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_get_octets(asnber_node_child_by_name(root, "b"),
                                             &b, &bSize) == ASNBER_OK);
        ASNBER_TEST_CHECK(a == 5 && b != NULL && bSize == 1 && b[0] == 0x41);
        asnber_doc_destroy(doc);
        ASNBER_TEST_CHECK(asnber_buf_release(ctx, &buf) == ASNBER_OK);
        asnber_schema_destroy(schema);
    }

    {
        /* IMPLICIT 覆盖的 SEQUENCE OF：schema 编码保持元素顺序并往返稳定。 */
        asnber_schema_t *schema = NULL;
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        uint32_t intId = 0;
        uint32_t ofId = 0;
        asnber_type_desc_t intType =
            make_type("Int", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 2,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &intType, &intId) ==
                        ASNBER_OK);
        asnber_type_desc_t ofType =
            make_type("ImplicitSeqOf", ASNBER_TYPE_KIND_SEQUENCE_OF,
                      ASNBER_TAG_CONTEXT, 15, ASNBER_TAG_MODE_IMPLICIT, intId);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &ofType, &ofId) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_set_root(schema, ofId) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);

        static const uint8_t kImplSeqOf[8] = {0xAF, 0x06, 0x02, 0x01, 0x05,
                                              0x02, 0x01, 0x06};
        asnber_doc_t *doc = NULL;
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kImplSeqOf,
                                      sizeof(kImplSeqOf), 0, &doc) == ASNBER_OK);
        asnber_encode_options_t options;
        asnber_encode_options_init(&options);
        options.schema = schema;
        asnber_buf_t buf;
        memset(&buf, 0, sizeof(buf));
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, &options, &buf) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(buf.data, buf.size, kImplSeqOf,
                                    sizeof(kImplSeqOf)));
        asnber_doc_destroy(doc);

        ASNBER_TEST_CHECK(decode_schema(ctx, schema, buf.data, buf.size, 0,
                                      &doc) == ASNBER_OK);
        const asnber_node_t *root = asnber_doc_root(doc);
        ASNBER_TEST_CHECK(asnber_node_child_count(root) == 2);
        int64_t first = 0;
        int64_t second = 0;
        ASNBER_TEST_CHECK(asnber_node_get_int64(asnber_node_child_at(root, 0),
                                            &first) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_get_int64(asnber_node_child_at(root, 1),
                                            &second) == ASNBER_OK);
        ASNBER_TEST_CHECK(first == 5 && second == 6);
        asnber_doc_destroy(doc);
        ASNBER_TEST_CHECK(asnber_buf_release(ctx, &buf) == ASNBER_OK);
        asnber_schema_destroy(schema);
    }

    {
        /* IMPLICIT 覆盖的 SET OF：[16] 反向输入经 schema 编码按 DER 排序，
         * 并稳定在类型自身 context 标签。 */
        asnber_schema_t *schema = NULL;
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        uint32_t intId = 0;
        uint32_t ofId = 0;
        asnber_type_desc_t intType =
            make_type("Int", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 2,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &intType, &intId) ==
                        ASNBER_OK);
        asnber_type_desc_t ofType =
            make_type("ImplicitSetOf", ASNBER_TYPE_KIND_SET_OF,
                      ASNBER_TAG_CONTEXT, 16, ASNBER_TAG_MODE_IMPLICIT, intId);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &ofType, &ofId) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_set_root(schema, ofId) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);

        static const uint8_t kImplSetOfIn[8] = {0xB0, 0x06, 0x02, 0x01, 0x06,
                                                0x02, 0x01, 0x05};
        static const uint8_t kImplSetOfSorted[8] = {0xB0, 0x06, 0x02, 0x01,
                                                    0x05, 0x02, 0x01, 0x06};
        asnber_doc_t *doc = NULL;
        ASNBER_TEST_CHECK(decode_schema(ctx, schema, kImplSetOfIn,
                                      sizeof(kImplSetOfIn), 0, &doc) ==
                        ASNBER_OK);
        asnber_encode_options_t options;
        asnber_encode_options_init(&options);
        options.schema = schema;
        asnber_buf_t buf;
        memset(&buf, 0, sizeof(buf));
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, &options, &buf) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(buf.data, buf.size, kImplSetOfSorted,
                                    sizeof(kImplSetOfSorted)));
        asnber_doc_destroy(doc);

        ASNBER_TEST_CHECK(decode_schema(ctx, schema, buf.data, buf.size, 0,
                                      &doc) == ASNBER_OK);
        const asnber_node_t *root = asnber_doc_root(doc);
        ASNBER_TEST_CHECK(asnber_node_child_count(root) == 2);
        int64_t first = 0;
        int64_t second = 0;
        ASNBER_TEST_CHECK(asnber_node_get_int64(asnber_node_child_at(root, 0),
                                            &first) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_get_int64(asnber_node_child_at(root, 1),
                                            &second) == ASNBER_OK);
        ASNBER_TEST_CHECK(first == 5 && second == 6);
        asnber_doc_destroy(doc);
        ASNBER_TEST_CHECK(asnber_buf_release(ctx, &buf) == ASNBER_OK);
        asnber_schema_destroy(schema);
    }

    {
        /* 高 tag 号按 base-128 变长编码；schema 编码与通用编码均往返稳定。 */
        static const uint8_t kTag31[4] = {0x9F, 0x1F, 0x01, 0x05};
        static const uint8_t kTag127[4] = {0x9F, 0x7F, 0x01, 0x05};
        static const uint8_t kTag128[5] = {0x9F, 0x81, 0x00, 0x01, 0x05};
        static const uint8_t kTag16383[5] = {0x9F, 0xFF, 0x7F, 0x01, 0x05};
        static const uint8_t kTag16384[6] = {0x9F, 0x81, 0x80, 0x00,
                                             0x01, 0x05};
        static const uint8_t kTag2097151[6] = {0x9F, 0xFF, 0xFF, 0x7F,
                                               0x01, 0x05};
        static const uint8_t kTagMax[8] = {0x9F, 0x8F, 0xFF, 0xFF, 0xFF,
                                           0x7F, 0x01, 0x05};

        struct HighTagCase {
            uint32_t number;
            const uint8_t *tlv;
            size_t size;
        };
        static const struct HighTagCase kCases[] = {
            {31, kTag31, sizeof(kTag31)},
            {127, kTag127, sizeof(kTag127)},
            {128, kTag128, sizeof(kTag128)},
            {16383, kTag16383, sizeof(kTag16383)},
            {16384, kTag16384, sizeof(kTag16384)},
            {2097151, kTag2097151, sizeof(kTag2097151)},
            {4294967295u, kTagMax, sizeof(kTagMax)},
        };

        for (size_t i = 0; i < sizeof(kCases) / sizeof(kCases[0]); ++i) {
            asnber_schema_t *schema = NULL;
            ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                               &schema) == ASNBER_OK);
            uint32_t typeId = 0;
            asnber_type_desc_t type =
                make_type("HighTag", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_CONTEXT,
                          kCases[i].number, ASNBER_TAG_MODE_IMPLICIT, 0);
            ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &type, &typeId) ==
                            ASNBER_OK);
            ASNBER_TEST_CHECK(asnber_schema_set_root(schema, typeId) == ASNBER_OK);
            ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);

            asnber_doc_t *doc = NULL;
            ASNBER_TEST_CHECK(decode_schema(ctx, schema, kCases[i].tlv,
                                          kCases[i].size, 0, &doc) == ASNBER_OK);
            asnber_encode_options_t options;
            asnber_encode_options_init(&options);
            options.schema = schema;
            asnber_buf_t buf;
            memset(&buf, 0, sizeof(buf));
            ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, &options, &buf) ==
                            ASNBER_OK);
            ASNBER_TEST_CHECK(bytes_equal(buf.data, buf.size, kCases[i].tlv,
                                        kCases[i].size));
            asnber_doc_destroy(doc);

            /* 编码结果再解码：内容字节与原始输入一致。 */
            ASNBER_TEST_CHECK(decode_schema(ctx, schema, buf.data, buf.size, 0,
                                          &doc) == ASNBER_OK);
            const uint8_t *content = NULL;
            size_t contentSize = 0;
            ASNBER_TEST_CHECK(asnber_node_content(asnber_doc_root(doc), &content,
                                              &contentSize) == ASNBER_OK);
            ASNBER_TEST_CHECK(content != NULL && contentSize == 1 &&
                            content[0] == 0x05);
            asnber_doc_destroy(doc);
            ASNBER_TEST_CHECK(asnber_buf_release(ctx, &buf) == ASNBER_OK);

            /* 通用编码（无 schema）同样按 base-128 写出。 */
            ASNBER_TEST_CHECK(decode_schema(ctx, schema, kCases[i].tlv,
                                          kCases[i].size, 0, &doc) == ASNBER_OK);
            memset(&buf, 0, sizeof(buf));
            ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, NULL, &buf) ==
                            ASNBER_OK);
            ASNBER_TEST_CHECK(bytes_equal(buf.data, buf.size, kCases[i].tlv,
                                        kCases[i].size));
            asnber_doc_destroy(doc);
            ASNBER_TEST_CHECK(asnber_buf_release(ctx, &buf) == ASNBER_OK);
            asnber_schema_destroy(schema);
        }
    }
    return 0;
}

int main(void)
{
    asnber_ctx_config_t config;
    asnber_ctx_config_init(&config);
    asnber_ctx_t *ctx = NULL;
    ASNBER_TEST_CHECK(asnber_ctx_create(&config, &ctx) == ASNBER_OK);

    ASNBER_TEST_CHECK(check_binding_default(ctx) == 0);
    ASNBER_TEST_CHECK(check_unknown_field_policy(ctx) == 0);
    ASNBER_TEST_CHECK(check_unknown_field_strict(ctx) == 0);
    ASNBER_TEST_CHECK(check_set_unknown_field(ctx) == 0);
    ASNBER_TEST_CHECK(check_any_der_consistency(ctx) == 0);
    ASNBER_TEST_CHECK(check_choice_dispatch(ctx) == 0);
    ASNBER_TEST_CHECK(check_of_binding(ctx) == 0);
    ASNBER_TEST_CHECK(check_constraints(ctx) == 0);
    ASNBER_TEST_CHECK(check_set_sorting(ctx) == 0);
    ASNBER_TEST_CHECK(check_explicit_any(ctx) == 0);
    ASNBER_TEST_CHECK(check_doc_validate(ctx) == 0);
    ASNBER_TEST_CHECK(check_real_certificate_any(ctx) == 0);
    ASNBER_TEST_CHECK(check_enum_implicit_regression(ctx) == 0);

    asnber_ctx_destroy(ctx);
    return 0;
}
