/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * runtime ANY 构树入口 asnber_node_create_any：合法性判定、字节复制与所有权、
 * 节点元数据推导、禁止子节点，以及 schema / 无 schema 两条编码路径的
 * 逐字节往返。
 */
#include <asnber/asnber.h>

#include <stddef.h>
#include <string.h>

#include "check.h"
#include "test_compare.h"

/* asnber_tag.h 的标签号必须与 X.690 一致；编译期锁定，避免常量漂移。 */
#if ASNBER_UNIVERSAL_SEQUENCE != 16
#error "ASNBER_UNIVERSAL_SEQUENCE must be 16"
#endif
#if ASNBER_UNIVERSAL_SET != 17
#error "ASNBER_UNIVERSAL_SET must be 17"
#endif
#if ASNBER_UNIVERSAL_INTEGER != 2
#error "ASNBER_UNIVERSAL_INTEGER must be 2"
#endif
#if ASNBER_UNIVERSAL_OID != 6
#error "ASNBER_UNIVERSAL_OID must be 6"
#endif
#if ASNBER_PRIMITIVE != 0 || ASNBER_CONSTRUCTED != 1
#error "ASNBER_PRIMITIVE/ASNBER_CONSTRUCTED must be 0/1"
#endif

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

static asnber_field_desc_t make_field(const char *name, uint32_t type_id)
{
    asnber_field_desc_t desc;
    memset(&desc, 0, sizeof(desc));
    desc.struct_size = sizeof(desc);
    desc.name = name;
    desc.type_id = type_id;
    return desc;
}

/* 构建 SEQUENCE { OID, ANY } 最小架构，根为 SEQUENCE。 */
static asnber_schema_t *make_algorithm_schema(asnber_ctx_t *ctx)
{
    asnber_schema_t *schema = NULL;
    if (asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT, &schema) != ASNBER_OK) {
        return NULL;
    }
    uint32_t oid_id = 0;
    asnber_type_desc_t oid_type =
        make_type("Oid", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 6,
                  ASNBER_TAG_MODE_DEFAULT, 0);
    if (asnber_schema_add_type(schema, &oid_type, &oid_id) != ASNBER_OK) {
        asnber_schema_destroy(schema);
        return NULL;
    }
    uint32_t any_id = 0;
    asnber_type_desc_t any_type =
        make_type("AnyValue", ASNBER_TYPE_KIND_ANY, ASNBER_TAG_UNIVERSAL, 0,
                  ASNBER_TAG_MODE_DEFAULT, 0);
    if (asnber_schema_add_type(schema, &any_type, &any_id) != ASNBER_OK) {
        asnber_schema_destroy(schema);
        return NULL;
    }
    uint32_t seq_id = 0;
    asnber_type_desc_t seq_type =
        make_type("AlgorithmIdentifier", ASNBER_TYPE_KIND_SEQUENCE,
                  ASNBER_TAG_UNIVERSAL, 16, ASNBER_TAG_MODE_DEFAULT, 0);
    if (asnber_schema_add_type(schema, &seq_type, &seq_id) != ASNBER_OK) {
        asnber_schema_destroy(schema);
        return NULL;
    }
    asnber_field_desc_t algorithm = make_field("algorithm", oid_id);
    if (asnber_schema_add_field(schema, seq_id, &algorithm) != ASNBER_OK) {
        asnber_schema_destroy(schema);
        return NULL;
    }
    asnber_field_desc_t parameters = make_field("parameters", any_id);
    if (asnber_schema_add_field(schema, seq_id, &parameters) != ASNBER_OK ||
        asnber_schema_set_root(schema, seq_id) != ASNBER_OK ||
        asnber_schema_seal(schema) != ASNBER_OK) {
        asnber_schema_destroy(schema);
        return NULL;
    }
    return schema;
}

/* 由内向外构造 layers 层 SEQUENCE 包裹的 INTEGER 5，返回总字节数。 */
static size_t wrap_nested_sequences(uint8_t *out, size_t capacity,
                                    size_t layers)
{
    size_t size = 3;
    if (capacity < size) {
        return 0;
    }
    out[0] = 0x02;
    out[1] = 0x01;
    out[2] = 0x05;
    for (size_t i = 0; i < layers; ++i) {
        const size_t header = size < 0x80 ? 2 : (size < 0x100 ? 3 : 4);
        if (size + header > capacity) {
            return 0;
        }
        memmove(out + header, out, size);
        out[0] = 0x30;
        if (header == 2) {
            out[1] = (uint8_t)size;
        } else if (header == 3) {
            out[1] = 0x81;
            out[2] = (uint8_t)size;
        } else {
            out[1] = 0x82;
            out[2] = (uint8_t)(size >> 8);
            out[3] = (uint8_t)size;
        }
        size += header;
    }
    return size;
}

/* 把原始 TLV 放进 SEQUENCE { OID, ANY } 并按 schema 编码，返回编码错误码。 */
static asnber_err_t encode_any_with_schema(asnber_ctx_t *ctx, const uint8_t *tlv,
                                         size_t size)
{
    asnber_schema_t *schema = make_algorithm_schema(ctx);
    if (schema == NULL) {
        return ASNBER_E_INVALID_STATE;
    }
    asnber_doc_t *doc = NULL;
    if (asnber_doc_create(ctx, &doc) != ASNBER_OK) {
        asnber_schema_destroy(schema);
        return ASNBER_E_INVALID_STATE;
    }
    asnber_node_t *root = NULL;
    asnber_node_t *oid = NULL;
    asnber_node_t *any = NULL;
    asnber_err_t rc = asnber_node_create(
        doc, NULL, ASNBER_TAG_UNIVERSAL, ASNBER_UNIVERSAL_SEQUENCE,
        ASNBER_CONSTRUCTED, &root);
    if (rc == ASNBER_OK) {
        rc = asnber_node_create(doc, root, ASNBER_TAG_UNIVERSAL,
                              ASNBER_UNIVERSAL_OID, ASNBER_PRIMITIVE, &oid);
    }
    if (rc == ASNBER_OK) {
        rc = asnber_node_set_oid(oid, "1.2.840.113549.1.1.1");
    }
    if (rc == ASNBER_OK) {
        rc = asnber_node_create_any(doc, root, tlv, size, &any);
    }
    if (rc == ASNBER_OK) {
        rc = asnber_doc_seal(doc);
    }
    asnber_encode_options_t options;
    asnber_encode_options_init(&options);
    options.schema = schema;
    asnber_buf_t buf;
    memset(&buf, 0, sizeof(buf));
    if (rc == ASNBER_OK) {
        rc = asnber_encode_buffer(ctx, doc, &options, &buf);
    }
    if (buf.data != NULL) {
        (void)asnber_buf_release(ctx, &buf);
    }
    asnber_doc_destroy(doc);
    asnber_schema_destroy(schema);
    return rc;
}

static int encode_compare(asnber_ctx_t *ctx, asnber_doc_t *doc,
                          const asnber_schema_t *schema,
                          const uint8_t *expected, size_t expected_size)
{
    asnber_encode_options_t options;
    asnber_encode_options_init(&options);
    options.schema = schema;

    asnber_buf_t buf;
    memset(&buf, 0, sizeof(buf));
    ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, &options, &buf) == ASNBER_OK);
    ASNBER_TEST_CHECK(bytes_equal(buf.data, buf.size, expected, expected_size));
    ASNBER_TEST_CHECK(asnber_buf_release(ctx, &buf) == ASNBER_OK);
    return 0;
}

/* 校验节点元数据与保留字节。 */
static int check_any_metadata(const asnber_node_t *node, asnber_tag_class_t tag_class,
                              uint32_t tag_number, int constructed,
                              const uint8_t *tlv, size_t tlv_size,
                              size_t content_size)
{
    size_t actual_tlv_size = 0;
    const uint8_t *actual_tlv = asnber_node_tlv(node, &actual_tlv_size);
    ASNBER_TEST_CHECK(actual_tlv != NULL);
    ASNBER_TEST_CHECK(actual_tlv_size == tlv_size);
    ASNBER_TEST_CHECK(bytes_equal(actual_tlv, actual_tlv_size, tlv, tlv_size));

    ASNBER_TEST_CHECK(asnber_node_tag_class(node) == tag_class);
    ASNBER_TEST_CHECK(asnber_node_tag_number(node) == tag_number);
    ASNBER_TEST_CHECK(asnber_node_encoding_form(node) ==
                    (constructed ? ASNBER_FORM_CONSTRUCTED
                                 : ASNBER_FORM_PRIMITIVE));
    ASNBER_TEST_CHECK(asnber_node_child_count(node) == 0);
    ASNBER_TEST_CHECK(asnber_node_child_at(node, 0) == NULL);

    const uint8_t *content = NULL;
    size_t actual_content = 0;
    ASNBER_TEST_CHECK(asnber_node_content(node, &content, &actual_content) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(actual_content == content_size);
    if (content_size > 0) {
        ASNBER_TEST_CHECK(content != NULL);
    }
    return 0;
}

/* 失败后读取上下文错误模型，校验错误码与 offset。 */
static int check_error(asnber_ctx_t *ctx, asnber_err_t expected_code,
                       size_t expected_offset, int has_offset)
{
    asnber_error_info_t info;
    memset(&info, 0, sizeof(info));
    info.struct_size = sizeof(info);
    ASNBER_TEST_CHECK(asnber_ctx_get_error(ctx, &info) == ASNBER_OK);
    ASNBER_TEST_CHECK(info.code == expected_code);
    if (has_offset) {
        ASNBER_TEST_CHECK(info.offset == expected_offset);
    }
    return 0;
}

/* ---------- 用例 ---------- */

int main(void)
{
    asnber_ctx_config_t config;
    asnber_ctx_config_init(&config);
    asnber_ctx_t *ctx = NULL;
    ASNBER_TEST_CHECK(asnber_ctx_create(&config, &ctx) == ASNBER_OK);

    static const uint8_t kNullTlv[2] = {0x05, 0x00};
    static const uint8_t kSeqTlv[5] = {0x30, 0x03, 0x02, 0x01, 0x05};
    static const uint8_t kContextTlv[6] = {0xA1, 0x04, 0x04, 0x02, 0xAA, 0xBB};

    /* ===== 1. 能力位与公共入口一致性 ===== */
    {
        ASNBER_TEST_CHECK(asnber_has_capability(ASNBER_CAP_ANY_OPEN_TYPE) == 1);

        asnber_doc_t *doc = NULL;
        ASNBER_TEST_CHECK(asnber_doc_create(ctx, &doc) == ASNBER_OK);
        asnber_node_t *node = NULL;
        ASNBER_TEST_CHECK(asnber_node_create_any(doc, NULL, kNullTlv,
                                             sizeof(kNullTlv), &node) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(node != NULL);
        ASNBER_TEST_CHECK(asnber_doc_seal(doc) == ASNBER_OK);
        asnber_doc_destroy(doc);
    }

    /* ===== 2. 合法 TLV：基本 / 构造 / 上下文标签 ===== */
    {
        asnber_doc_t *doc = NULL;
        ASNBER_TEST_CHECK(asnber_doc_create(ctx, &doc) == ASNBER_OK);
        asnber_node_t *node = NULL;
        ASNBER_TEST_CHECK(asnber_node_create_any(doc, NULL, kNullTlv,
                                             sizeof(kNullTlv), &node) ==
                        ASNBER_OK);
        const asnber_node_t *root = asnber_doc_root(doc);
        ASNBER_TEST_CHECK(root == node);
        ASNBER_TEST_CHECK(check_any_metadata(root, ASNBER_TAG_UNIVERSAL, 5, 0,
                                           kNullTlv, sizeof(kNullTlv), 0) == 0);
        ASNBER_TEST_CHECK(asnber_doc_seal(doc) == ASNBER_OK);
        asnber_doc_destroy(doc);
    }

    {
        asnber_doc_t *doc = NULL;
        ASNBER_TEST_CHECK(asnber_doc_create(ctx, &doc) == ASNBER_OK);
        asnber_node_t *node = NULL;
        ASNBER_TEST_CHECK(asnber_node_create_any(doc, NULL, kSeqTlv,
                                             sizeof(kSeqTlv), &node) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(check_any_metadata(asnber_doc_root(doc),
                                           ASNBER_TAG_UNIVERSAL, 16, 1, kSeqTlv,
                                           sizeof(kSeqTlv), 3) == 0);
        asnber_doc_destroy(doc);
    }

    {
        asnber_doc_t *doc = NULL;
        ASNBER_TEST_CHECK(asnber_doc_create(ctx, &doc) == ASNBER_OK);
        asnber_node_t *node = NULL;
        ASNBER_TEST_CHECK(asnber_node_create_any(doc, NULL, kContextTlv,
                                             sizeof(kContextTlv), &node) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(check_any_metadata(asnber_doc_root(doc),
                                           ASNBER_TAG_CONTEXT, 1, 1, kContextTlv,
                                           sizeof(kContextTlv), 4) == 0);
        asnber_doc_destroy(doc);
    }

    /* ===== 3. 调用方缓冲复制后可变 ===== */
    {
        uint8_t mutable_tlv[5] = {0x30, 0x03, 0x02, 0x01, 0x05};
        asnber_doc_t *doc = NULL;
        ASNBER_TEST_CHECK(asnber_doc_create(ctx, &doc) == ASNBER_OK);
        asnber_node_t *node = NULL;
        ASNBER_TEST_CHECK(asnber_node_create_any(doc, NULL, mutable_tlv,
                                             sizeof(mutable_tlv), &node) ==
                        ASNBER_OK);
        mutable_tlv[4] = 0x07;
        size_t tlv_size = 0;
        const uint8_t *tlv = asnber_node_tlv(node, &tlv_size);
        ASNBER_TEST_CHECK(tlv != NULL);
        ASNBER_TEST_CHECK(tlv[4] == 0x05);
        asnber_doc_destroy(doc);
    }

    /* ===== 4. 嵌套在 SEQUENCE 与无 schema 往返 ===== */
    {
        static const uint8_t kExpected[7] = {0x30, 0x05, 0x30, 0x03,
                                             0x02, 0x01, 0x05};
        asnber_doc_t *doc = NULL;
        ASNBER_TEST_CHECK(asnber_doc_create(ctx, &doc) == ASNBER_OK);
        asnber_node_t *root = NULL;
        ASNBER_TEST_CHECK(asnber_node_create(doc, NULL, ASNBER_TAG_UNIVERSAL, 16, 1,
                                         &root) == ASNBER_OK);
        asnber_node_t *child = NULL;
        ASNBER_TEST_CHECK(asnber_node_create_any(doc, root, kSeqTlv,
                                             sizeof(kSeqTlv), &child) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_child_count(root) == 1);
        ASNBER_TEST_CHECK(asnber_doc_seal(doc) == ASNBER_OK);
        ASNBER_TEST_CHECK(encode_compare(ctx, doc, NULL, kExpected,
                                       sizeof(kExpected)) == 0);
        asnber_doc_destroy(doc);
    }

    /* ===== 5. schema 感知往返：建树 → 编码 → 解码 → 再编码 ===== */
    {
        /* SEQUENCE { OID rsaEncryption, NULL }。 */
        static const uint8_t kExpected[15] = {
            0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
            0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00};
        asnber_schema_t *schema = make_algorithm_schema(ctx);
        ASNBER_TEST_CHECK(schema != NULL);

        asnber_doc_t *doc = NULL;
        ASNBER_TEST_CHECK(asnber_doc_create(ctx, &doc) == ASNBER_OK);
        asnber_node_t *root = NULL;
        ASNBER_TEST_CHECK(asnber_node_create(doc, NULL, ASNBER_TAG_UNIVERSAL, 16, 1,
                                         &root) == ASNBER_OK);
        asnber_node_t *oid = NULL;
        ASNBER_TEST_CHECK(asnber_node_create(doc, root, ASNBER_TAG_UNIVERSAL, 6, 0,
                                         &oid) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_set_oid(oid, "1.2.840.113549.1.1.1") ==
                        ASNBER_OK);
        asnber_node_t *any_node = NULL;
        ASNBER_TEST_CHECK(asnber_node_create_any(doc, root, kNullTlv,
                                             sizeof(kNullTlv), &any_node) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_doc_seal(doc) == ASNBER_OK);
        ASNBER_TEST_CHECK(encode_compare(ctx, doc, schema, kExpected,
                                       sizeof(kExpected)) == 0);

        /* 解码同一份 DER 后再编码，逐字节一致。 */
        asnber_decode_options_t decode_options;
        asnber_decode_options_init(&decode_options);
        decode_options.encoding = ASNBER_ENCODING_DER;
        asnber_doc_t *decoded = NULL;
        size_t consumed = 0;
        ASNBER_TEST_CHECK(asnber_decode_buffer_with_schema(
                            ctx, kExpected, sizeof(kExpected), schema,
                            &decode_options, &decoded, &consumed) == ASNBER_OK);
        ASNBER_TEST_CHECK(consumed == sizeof(kExpected));
        const asnber_node_t *params =
            asnber_node_child_by_name(asnber_doc_root(decoded), "parameters");
        ASNBER_TEST_CHECK(params != NULL);
        ASNBER_TEST_CHECK(check_any_metadata(params, ASNBER_TAG_UNIVERSAL, 5, 0,
                                           kNullTlv, sizeof(kNullTlv), 0) == 0);
        ASNBER_TEST_CHECK(encode_compare(ctx, decoded, schema, kExpected,
                                       sizeof(kExpected)) == 0);

        asnber_doc_destroy(decoded);
        asnber_doc_destroy(doc);
        asnber_schema_destroy(schema);
    }

    /* ===== 6. 非规范 DER 的 ANY：创建接受，schema 编码拒绝 ===== */
    {
        /* INTEGER 5 带冗余前导零：TLV 结构完整，但不是规范 DER。 */
        static const uint8_t kNonCanonical[4] = {0x02, 0x02, 0x00, 0x05};
        static const uint8_t kRawRoundTrip[17] = {
            0x30, 0x0F, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7,
            0x0D, 0x01, 0x01, 0x01, 0x02, 0x02, 0x00, 0x05};
        asnber_schema_t *schema = make_algorithm_schema(ctx);
        ASNBER_TEST_CHECK(schema != NULL);

        asnber_doc_t *doc = NULL;
        ASNBER_TEST_CHECK(asnber_doc_create(ctx, &doc) == ASNBER_OK);
        asnber_node_t *root = NULL;
        ASNBER_TEST_CHECK(asnber_node_create(doc, NULL, ASNBER_TAG_UNIVERSAL, 16, 1,
                                         &root) == ASNBER_OK);
        asnber_node_t *oid = NULL;
        ASNBER_TEST_CHECK(asnber_node_create(doc, root, ASNBER_TAG_UNIVERSAL, 6, 0,
                                         &oid) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_set_oid(oid, "1.2.840.113549.1.1.1") ==
                        ASNBER_OK);
        asnber_node_t *any_node = NULL;
        ASNBER_TEST_CHECK(asnber_node_create_any(doc, root, kNonCanonical,
                                             sizeof(kNonCanonical),
                                             &any_node) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_doc_seal(doc) == ASNBER_OK);

        /* schema 感知编码按 DER 校验保留 TLV，拒绝且不产出字节。 */
        asnber_encode_options_t options;
        asnber_encode_options_init(&options);
        options.schema = schema;
        asnber_buf_t buf;
        memset(&buf, 0, sizeof(buf));
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, &options, &buf) ==
                        ASNBER_E_NON_CANONICAL);
        ASNBER_TEST_CHECK(buf.data == NULL);
        ASNBER_TEST_CHECK(buf.size == 0);

        /* 无 schema 编码不做规范化，原样写出保留的 TLV。 */
        ASNBER_TEST_CHECK(encode_compare(ctx, doc, NULL, kRawRoundTrip,
                                       sizeof(kRawRoundTrip)) == 0);

        asnber_doc_destroy(doc);
        asnber_schema_destroy(schema);
    }

    /* ===== 7. 资源上限透传：保留 TLV 超深时返回 DEPTH_LIMIT ===== */
    {
        asnber_ctx_config_t shallow;
        asnber_ctx_config_init(&shallow);
        shallow.max_depth = 2;
        asnber_ctx_t *shallow_ctx = NULL;
        ASNBER_TEST_CHECK(asnber_ctx_create(&shallow, &shallow_ctx) == ASNBER_OK);

        /* 三层 SEQUENCE 嵌套：解码深度超过 max_depth = 2。 */
        static const uint8_t kNested[9] = {0x30, 0x07, 0x30, 0x05, 0x30,
                                           0x03, 0x02, 0x01, 0x05};
        asnber_schema_t *schema = make_algorithm_schema(shallow_ctx);
        ASNBER_TEST_CHECK(schema != NULL);

        asnber_doc_t *doc = NULL;
        ASNBER_TEST_CHECK(asnber_doc_create(shallow_ctx, &doc) == ASNBER_OK);
        asnber_node_t *root = NULL;
        ASNBER_TEST_CHECK(asnber_node_create(doc, NULL, ASNBER_TAG_UNIVERSAL, 16, 1,
                                         &root) == ASNBER_OK);
        asnber_node_t *oid = NULL;
        ASNBER_TEST_CHECK(asnber_node_create(doc, root, ASNBER_TAG_UNIVERSAL, 6, 0,
                                         &oid) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_set_oid(oid, "1.2.840.113549.1.1.1") ==
                        ASNBER_OK);
        asnber_node_t *any_node = NULL;
        ASNBER_TEST_CHECK(asnber_node_create_any(doc, root, kNested,
                                             sizeof(kNested), &any_node) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_doc_seal(doc) == ASNBER_OK);

        asnber_encode_options_t options;
        asnber_encode_options_init(&options);
        options.schema = schema;
        asnber_buf_t buf;
        memset(&buf, 0, sizeof(buf));
        ASNBER_TEST_CHECK(asnber_encode_buffer(shallow_ctx, doc, &options, &buf) ==
                        ASNBER_E_DEPTH_LIMIT);
        ASNBER_TEST_CHECK(buf.data == NULL && buf.size == 0);
        asnber_doc_destroy(doc);
        asnber_schema_destroy(schema);
        asnber_ctx_destroy(shallow_ctx);
    }

    /* ===== 7b. ANY 内层深度复用上下文 max_depth ===== */
    {
        asnber_ctx_config_t config;
        asnber_ctx_config_init(&config); /* 默认 max_depth = 64 */
        asnber_ctx_t *ctx = NULL;
        ASNBER_TEST_CHECK(asnber_ctx_create(&config, &ctx) == ASNBER_OK);

        /* 70 层 SEQUENCE 超过默认 64：schema 编码校验保留 TLV 返回 DEPTH_LIMIT。 */
        uint8_t deep[512];
        const size_t deep_size =
            wrap_nested_sequences(deep, sizeof(deep), 70);
        ASNBER_TEST_CHECK(deep_size > 0);
        ASNBER_TEST_CHECK(encode_any_with_schema(ctx, deep, deep_size) ==
                        ASNBER_E_DEPTH_LIMIT);

        /* 3 层嵌套在默认预算内：编码成功。 */
        uint8_t shallow[64];
        const size_t shallow_size =
            wrap_nested_sequences(shallow, sizeof(shallow), 3);
        ASNBER_TEST_CHECK(shallow_size > 0);
        ASNBER_TEST_CHECK(encode_any_with_schema(ctx, shallow, shallow_size) ==
                        ASNBER_OK);

        asnber_ctx_destroy(ctx);
    }

    /* ===== 8. 负例：空输入、截断、尾随、不定长、畸形标签/长度 ===== */
    {
        static const uint8_t kTruncated[4] = {0x30, 0x03, 0x02, 0x01};
        static const uint8_t kTrailing[6] = {0x30, 0x03, 0x02, 0x01, 0x05, 0xFF};
        static const uint8_t kIndefinite[4] = {0x30, 0x80, 0x00, 0x00};
        static const uint8_t kHighTagIncomplete[1] = {0x1F};
        static const uint8_t kHighTagBadFirst[2] = {0x1F, 0x80};
        static const uint8_t kLengthTooLong[2] = {0x04, 0x89};

        asnber_doc_t *doc = NULL;
        ASNBER_TEST_CHECK(asnber_doc_create(ctx, &doc) == ASNBER_OK);
        asnber_node_t *node = NULL;

        asnber_ctx_clear_error(ctx);
        ASNBER_TEST_CHECK(asnber_node_create_any(doc, NULL, NULL, 0, &node) ==
                        ASNBER_E_INVALID_ARG);
        ASNBER_TEST_CHECK(node == NULL);

        ASNBER_TEST_CHECK(asnber_node_create_any(doc, NULL, kTruncated,
                                             sizeof(kTruncated), &node) ==
                        ASNBER_E_TRUNCATED);
        ASNBER_TEST_CHECK(check_error(ctx, ASNBER_E_TRUNCATED, 4, 1) == 0);

        ASNBER_TEST_CHECK(asnber_node_create_any(doc, NULL, kTrailing,
                                             sizeof(kTrailing), &node) ==
                        ASNBER_E_TRAILING_DATA);
        ASNBER_TEST_CHECK(check_error(ctx, ASNBER_E_TRAILING_DATA, 5, 1) == 0);

        ASNBER_TEST_CHECK(asnber_node_create_any(doc, NULL, kIndefinite,
                                             sizeof(kIndefinite), &node) ==
                        ASNBER_E_INDEFINITE_NOT_ALLOWED);
        ASNBER_TEST_CHECK(check_error(ctx, ASNBER_E_INDEFINITE_NOT_ALLOWED, 1, 1) ==
                        0);

        ASNBER_TEST_CHECK(asnber_node_create_any(doc, NULL, kHighTagIncomplete,
                                             sizeof(kHighTagIncomplete),
                                             &node) == ASNBER_E_TRUNCATED);
        ASNBER_TEST_CHECK(check_error(ctx, ASNBER_E_TRUNCATED, 1, 1) == 0);

        ASNBER_TEST_CHECK(asnber_node_create_any(doc, NULL, kHighTagBadFirst,
                                             sizeof(kHighTagBadFirst), &node) ==
                        ASNBER_E_MALFORMED_TAG);
        ASNBER_TEST_CHECK(check_error(ctx, ASNBER_E_MALFORMED_TAG, 1, 1) == 0);

        ASNBER_TEST_CHECK(asnber_node_create_any(doc, NULL, kLengthTooLong,
                                             sizeof(kLengthTooLong), &node) ==
                        ASNBER_E_MALFORMED_LENGTH);

        ASNBER_TEST_CHECK(asnber_doc_seal(doc) == ASNBER_E_INVALID_STATE);
        asnber_doc_destroy(doc);
    }

    /* ===== 9. ANY 不得挂子节点、不得设置内容 ===== */
    {
        asnber_doc_t *doc = NULL;
        ASNBER_TEST_CHECK(asnber_doc_create(ctx, &doc) == ASNBER_OK);
        asnber_node_t *any_node = NULL;
        ASNBER_TEST_CHECK(asnber_node_create_any(doc, NULL, kSeqTlv,
                                             sizeof(kSeqTlv), &any_node) ==
                        ASNBER_OK);
        asnber_node_t *child = NULL;
        ASNBER_TEST_CHECK(asnber_node_create(doc, any_node, ASNBER_TAG_UNIVERSAL, 2,
                                         0, &child) == ASNBER_E_INVALID_STATE);
        ASNBER_TEST_CHECK(child == NULL);
        ASNBER_TEST_CHECK(asnber_node_set_content(any_node, kNullTlv,
                                              sizeof(kNullTlv)) ==
                        ASNBER_E_INVALID_STATE);
        ASNBER_TEST_CHECK(asnber_doc_seal(doc) == ASNBER_OK);
        asnber_doc_destroy(doc);
    }

    /* ===== 10. OID 文本校验、内容 setter 参数与跨文档 parent ===== */
    {
        static const uint8_t kAnyNull[2] = {0x05, 0x00};
        asnber_doc_t *doc = NULL;
        ASNBER_TEST_CHECK(asnber_doc_create(ctx, &doc) == ASNBER_OK);
        asnber_node_t *oid = NULL;
        ASNBER_TEST_CHECK(asnber_node_create(doc, NULL, ASNBER_TAG_UNIVERSAL, 6, 0,
                                         &oid) == ASNBER_OK);

        ASNBER_TEST_CHECK(asnber_node_set_oid(NULL, "1.2") ==
                        ASNBER_E_INVALID_ARG);
        ASNBER_TEST_CHECK(asnber_node_set_oid(oid, NULL) == ASNBER_E_INVALID_ARG);
        ASNBER_TEST_CHECK(asnber_node_set_oid(oid, "abc") == ASNBER_E_INVALID_VALUE);
        ASNBER_TEST_CHECK(asnber_node_set_oid(oid, "1") == ASNBER_E_INVALID_VALUE);
        ASNBER_TEST_CHECK(asnber_node_set_oid(oid, "1.") == ASNBER_E_INVALID_VALUE);
        ASNBER_TEST_CHECK(asnber_node_set_oid(oid, "3.1") == ASNBER_E_INVALID_VALUE);
        ASNBER_TEST_CHECK(asnber_node_set_oid(oid, "1.40") ==
                        ASNBER_E_INVALID_VALUE);
        ASNBER_TEST_CHECK(asnber_node_set_oid(oid, "1.2.") ==
                        ASNBER_E_INVALID_VALUE);
        ASNBER_TEST_CHECK(asnber_node_set_oid(oid, "1.2x") ==
                        ASNBER_E_INVALID_VALUE);
        ASNBER_TEST_CHECK(asnber_node_set_oid(oid, "1.2.-3") ==
                        ASNBER_E_INVALID_VALUE);
        ASNBER_TEST_CHECK(asnber_node_set_oid(oid, "2.39.1.2.3") == ASNBER_OK);

        ASNBER_TEST_CHECK(asnber_node_set_content(NULL, kAnyNull,
                                              sizeof(kAnyNull)) ==
                        ASNBER_E_INVALID_ARG);
        ASNBER_TEST_CHECK(asnber_node_set_bool(NULL, 1) == ASNBER_E_INVALID_ARG);
        ASNBER_TEST_CHECK(asnber_node_set_int64(NULL, 1) == ASNBER_E_INVALID_ARG);
        ASNBER_TEST_CHECK(asnber_node_set_utf8(NULL, "x", 1) ==
                        ASNBER_E_INVALID_ARG);
        ASNBER_TEST_CHECK(asnber_node_set_utf8(oid, NULL, 1) ==
                        ASNBER_E_INVALID_ARG);

        asnber_doc_t *other = NULL;
        ASNBER_TEST_CHECK(asnber_doc_create(ctx, &other) == ASNBER_OK);
        asnber_node_t *foreign_parent = NULL;
        ASNBER_TEST_CHECK(asnber_node_create(other, NULL, ASNBER_TAG_UNIVERSAL, 16,
                                         1, &foreign_parent) == ASNBER_OK);
        asnber_node_t *node = NULL;
        ASNBER_TEST_CHECK(asnber_node_create_any(doc, foreign_parent, kAnyNull,
                                             sizeof(kAnyNull), &node) ==
                        ASNBER_E_INVALID_ARG);
        ASNBER_TEST_CHECK(node == NULL);

        ASNBER_TEST_CHECK(asnber_node_create(doc, foreign_parent,
                                         ASNBER_TAG_UNIVERSAL, 2, 0,
                                         &node) == ASNBER_E_INVALID_ARG);
        ASNBER_TEST_CHECK(node == NULL);

        asnber_doc_t *docOut = NULL;
        ASNBER_TEST_CHECK(asnber_doc_create(NULL, &docOut) == ASNBER_E_INVALID_ARG);
        ASNBER_TEST_CHECK(asnber_doc_create(ctx, NULL) == ASNBER_E_INVALID_ARG);
        ASNBER_TEST_CHECK(asnber_doc_seal(NULL) == ASNBER_E_INVALID_ARG);
        ASNBER_TEST_CHECK(asnber_node_create(NULL, NULL, ASNBER_TAG_UNIVERSAL, 16,
                                         1, &node) == ASNBER_E_INVALID_ARG);
        ASNBER_TEST_CHECK(asnber_node_create(doc, NULL, ASNBER_TAG_UNIVERSAL, 16, 1,
                                         NULL) == ASNBER_E_INVALID_ARG);
        ASNBER_TEST_CHECK(asnber_node_create(doc, NULL, (asnber_tag_class_t)4, 16, 1,
                                         &node) == ASNBER_E_INVALID_ARG);
        ASNBER_TEST_CHECK(asnber_node_create(doc, NULL, ASNBER_TAG_UNIVERSAL, 0, 0,
                                         &node) == ASNBER_E_INVALID_ARG);
        ASNBER_TEST_CHECK(asnber_node_create_any(NULL, NULL, kAnyNull,
                                             sizeof(kAnyNull), &node) ==
                        ASNBER_E_INVALID_ARG);
        ASNBER_TEST_CHECK(asnber_node_create_any(doc, NULL, NULL, 0, &node) ==
                        ASNBER_E_INVALID_ARG);
        ASNBER_TEST_CHECK(node == NULL);

        ASNBER_TEST_CHECK(asnber_doc_seal(doc) == ASNBER_OK);
        asnber_doc_destroy(doc);
        asnber_doc_destroy(other);
    }

    asnber_ctx_destroy(ctx);
    return 0;
}
