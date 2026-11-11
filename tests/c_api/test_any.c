/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * ANY/开放类型：schema 注册与封存拒绝、描述表 kind = 6、节点语义
 * （原始 TLV 完整保留、child_count = 0、content 返回原始内容）、
 * 编码原样回写，以及真实证书 AlgorithmIdentifier.parameters 的实测。
 */
#include <asnber/asnber.h>

#include <stddef.h>
#include <string.h>

#include "../data/cert_ec_selfsigned.h"
#include "../data/cert_rsa_pss_selfsigned.h"
#include "../data/cert_rsa_selfsigned.h"
#include "check.h"
#include "test_compare.h"
#include "schema_probe.h"

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

static asnber_type_desc_t make_any(const char *name)
{
    return make_type(name, ASNBER_TYPE_KIND_ANY, ASNBER_TAG_UNIVERSAL, 0,
                     ASNBER_TAG_MODE_DEFAULT, 0);
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

static asnber_bound_t make_bound(int64_t value)
{
    asnber_bound_t bound;
    memset(&bound, 0, sizeof(bound));
    bound.struct_size = sizeof(bound);
    bound.value = value;
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

/*
 * 通过 schema-aware 解码把一段完整 TLV 解析为 ANY 根节点，验证节点语义
 * 并做无 schema 通用编码回写。expected_constructed 为 -1 表示不检查形态。
 * （原实现依赖内部探针构造 ANY 节点；现改走公共 API，解除共享库符号限制。）
 */
static int roundtrip_any(asnber_ctx_t *ctx, const uint8_t *tlv, size_t size,
                         int expected_constructed, size_t expected_content)
{
    asnber_schema_t *schema = NULL;
    ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                       &schema) == ASNBER_OK);
    asnber_type_desc_t any_type = make_any("AnyRoot");
    uint32_t any_id = 0;
    ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &any_type, &any_id) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_schema_set_root(schema, any_id) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);

    asnber_decode_options_t options;
    asnber_decode_options_init(&options);
    options.encoding = ASNBER_ENCODING_BER;

    asnber_doc_t *doc = NULL;
    size_t consumed = 0;
    ASNBER_TEST_CHECK(asnber_decode_buffer_with_schema(
                        ctx, tlv, size, schema, &options, &doc, &consumed) ==
                    ASNBER_OK);
    const asnber_node_t *node = asnber_doc_root(doc);
    ASNBER_TEST_CHECK(node != NULL);

    /* 节点语义：ANY 不展开，TLV 完整保留。 */
    ASNBER_TEST_CHECK(asnber_node_child_count(node) == 0);
    ASNBER_TEST_CHECK(asnber_node_child_at(node, 0) == NULL);
    ASNBER_TEST_CHECK(asnber_node_child_by_name(node, "x") == NULL);

    size_t tlv_size = 0;
    const uint8_t *raw = asnber_node_tlv(node, &tlv_size);
    ASNBER_TEST_CHECK(raw != NULL);
    ASNBER_TEST_CHECK(tlv_size == size);
    ASNBER_TEST_CHECK(bytes_equal(raw, tlv_size, tlv, size));

    const uint8_t *content = NULL;
    size_t content_size = 0;
    ASNBER_TEST_CHECK(asnber_node_content(node, &content, &content_size) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(content_size == expected_content);
    if (expected_constructed >= 0) {
        ASNBER_TEST_CHECK(asnber_node_encoding_form(node) ==
                        (expected_constructed ? ASNBER_FORM_CONSTRUCTED
                                              : ASNBER_FORM_PRIMITIVE));
    }

    asnber_buf_t buf;
    memset(&buf, 0, sizeof(buf));
    ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, NULL, &buf) == ASNBER_OK);
    ASNBER_TEST_CHECK(bytes_equal(buf.data, buf.size, tlv, size));
    ASNBER_TEST_CHECK(asnber_buf_release(ctx, &buf) == ASNBER_OK);
    asnber_doc_destroy(doc);
    asnber_schema_destroy(schema);
    return 0;
}

/* 取出真实证书签名 AlgorithmIdentifier 的 parameters 原始 TLV。 */
static const uint8_t *cert_parameters_tlv(asnber_doc_t *doc, size_t *out_size)
{
    const asnber_node_t *root = asnber_doc_root(doc);
    if (root == NULL) {
        return NULL;
    }
    const asnber_node_t *sig_alg = asnber_node_child_at(root, 1);
    if (sig_alg == NULL) {
        return NULL;
    }
    const asnber_node_t *params = asnber_node_child_at(sig_alg, 1);
    if (params == NULL) {
        return NULL;
    }
    return asnber_node_tlv(params, out_size);
}

/* ---------- 最小描述表（kind = 6） ---------- */

static void put_u16(uint8_t *data, size_t offset, uint32_t value)
{
    data[offset] = (uint8_t)(value & 0xFFu);
    data[offset + 1] = (uint8_t)((value >> 8) & 0xFFu);
}

static void put_u32(uint8_t *data, size_t offset, uint32_t value)
{
    for (int i = 0; i < 4; ++i) {
        data[offset + (size_t)i] = (uint8_t)((value >> (8 * i)) & 0xFFu);
    }
}

static void put_u64(uint8_t *data, size_t offset, uint64_t value)
{
    for (int i = 0; i < 8; ++i) {
        data[offset + (size_t)i] = (uint8_t)((value >> (8 * i)) & 0xFFu);
    }
}

static uint32_t crc32c(const uint8_t *data, size_t size)
{
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < size; ++i) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; ++bit) {
            const uint32_t mask =
                (uint32_t)(-(int32_t)(crc & 1u)) & 0x82F63B78u;
            crc = (crc >> 1) ^ mask;
        }
    }
    return ~crc;
}

/* 构造只含一个 kind = 6 类型的描述表。 */
static void build_any_table(uint8_t *data, size_t size)
{
    memset(data, 0, size);

    static const uint8_t magic[8] = {0x41, 0x53, 0x4E, 0x31,
                                     0x53, 0x43, 0x48, 0x1A};
    memcpy(data, magic, sizeof(magic));
    put_u32(data, 8, 1u << 16);        /* format_version 1.0 */
    put_u32(data, 12, 100);            /* header_size */
    put_u32(data, 16, 0x01020304u);    /* endianness */
    put_u32(data, 20, 0);              /* module_tag_mode AUTOMATIC */
    put_u32(data, 24, 1);              /* flags: 校验和启用 */
    put_u32(data, 28, 1);              /* checksum_alg: CRC32C */
    put_u64(data, 32, (uint64_t)size);
    put_u32(data, 40, 100);            /* string_pool_offset */
    put_u32(data, 44, 9);              /* string_pool_size：含结尾 NUL */
    put_u32(data, 48, 112);            /* type_table_offset */
    put_u32(data, 52, 1);              /* type_count */
    /* 字段/约束/默认值表均为空。 */
    put_u32(data, 96, 1);              /* root_type_id */

    /* 字符串池：0x00 哨兵 + "AnyType" + NUL；109..111 为对齐填充。 */
    data[100] = 0x00;
    memcpy(data + 101, "AnyType", 7);
    data[108] = 0x00;

    /* 类型记录：name_off = 101，kind = 6，其余标签字段全 0。 */
    put_u32(data, 112, 101);
    put_u16(data, 116, 6);

    put_u32(data, 80, 0);
    put_u32(data, 80, crc32c(data, size));
}

/* ---------- 用例 ---------- */

int main(void)
{
    asnber_ctx_config_t config;
    asnber_ctx_config_init(&config);
    asnber_ctx_t *ctx = NULL;
    ASNBER_TEST_CHECK(asnber_ctx_create(&config, &ctx) == ASNBER_OK);

    /* ===== 1. schema 运行时：ANY 注册与非法组合 ===== */
    {
        asnber_schema_t *schema = NULL;
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        asnber_type_desc_t any_type = make_any("AnyType");
        uint32_t any_id = 0;
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &any_type, &any_id) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(any_id == 1);

        asnber_test_type_info info;
        ASNBER_TEST_CHECK(asnber_test_schema_type_info(schema, any_id, &info) == 1);
        ASNBER_TEST_CHECK(info.kind == 6);
        ASNBER_TEST_CHECK(info.tag_class == ASNBER_TAG_UNIVERSAL);
        ASNBER_TEST_CHECK(info.tag_number == 0);
        ASNBER_TEST_CHECK(info.element_type_id == 0);
        ASNBER_TEST_CHECK(info.field_count == 0);
        ASNBER_TEST_CHECK(info.constraint_count == 0);

        /* ANY 不得挂字段。 */
        asnber_field_desc_t field = make_field("payload", any_id);
        ASNBER_TEST_CHECK(asnber_schema_add_field(schema, any_id, &field) ==
                        ASNBER_E_SCHEMA_FIELD);
        ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);
        asnber_schema_destroy(schema);
    }

    {
        /* ANY 不得挂类型级约束。 */
        asnber_schema_t *schema = NULL;
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        asnber_type_desc_t any_type = make_any("AnyWithConstraint");
        asnber_constraint_t range = make_range(0, 10);
        any_type.constraints = &range;
        any_type.constraint_count = 1;
        uint32_t id = 0;
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &any_type, &id) ==
                        ASNBER_E_SCHEMA_TYPE);
        asnber_schema_destroy(schema);
    }

    {
        /* ANY 只允许无包装（UNIVERSAL 0 + DEFAULT）或非 UNIVERSAL 的
           EXPLICIT 外层包装；IMPLICIT 与 CONTEXT DEFAULT 均非法。 */
        asnber_schema_t *schema = NULL;
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        uint32_t id = 0;

        asnber_type_desc_t context_tag =
            make_type("AnyContext", ASNBER_TYPE_KIND_ANY, ASNBER_TAG_CONTEXT, 0,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &context_tag, &id) ==
                        ASNBER_E_SCHEMA_TYPE);

        asnber_type_desc_t explicit_universal =
            make_type("AnyExplicitUniversal", ASNBER_TYPE_KIND_ANY,
                      ASNBER_TAG_UNIVERSAL, 0, ASNBER_TAG_MODE_EXPLICIT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &explicit_universal, &id) ==
                        ASNBER_E_SCHEMA_TYPE);

        asnber_type_desc_t implicit_tag =
            make_type("AnyImplicit", ASNBER_TYPE_KIND_ANY, ASNBER_TAG_CONTEXT, 0,
                      ASNBER_TAG_MODE_IMPLICIT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &implicit_tag, &id) ==
                        ASNBER_E_SCHEMA_TYPE);

        asnber_type_desc_t explicit_context =
            make_type("AnyExplicit", ASNBER_TYPE_KIND_ANY, ASNBER_TAG_CONTEXT, 1,
                      ASNBER_TAG_MODE_EXPLICIT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &explicit_context, &id) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(id == 1);

        asnber_type_desc_t with_element =
            make_type("AnyOf", ASNBER_TYPE_KIND_ANY, ASNBER_TAG_UNIVERSAL, 0,
                      ASNBER_TAG_MODE_DEFAULT, 1);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &with_element, &id) ==
                        ASNBER_E_SCHEMA_TYPE);

        asnber_schema_destroy(schema);
    }

    /* ===== 1b. ANY OPTIONAL 的 seal 规则 ===== */
    {
        /* SEQUENCE { OID, ANY OPTIONAL } 可封存。 */
        asnber_schema_t *schema = NULL;
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        uint32_t oid_id = 0;
        uint32_t any_id = 0;
        uint32_t seq_id = 0;
        asnber_type_desc_t oid_type =
            make_type("Oid", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 6,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &oid_type, &oid_id) ==
                        ASNBER_OK);
        asnber_type_desc_t any_type = make_any("AnyType");
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &any_type, &any_id) ==
                        ASNBER_OK);
        asnber_type_desc_t seq_type =
            make_type("AlgorithmIdentifier", ASNBER_TYPE_KIND_SEQUENCE,
                      ASNBER_TAG_UNIVERSAL, 16, ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &seq_type, &seq_id) ==
                        ASNBER_OK);
        asnber_field_desc_t oid_field = make_field("algorithm", oid_id);
        ASNBER_TEST_CHECK(asnber_schema_add_field(schema, seq_id, &oid_field) ==
                        ASNBER_OK);
        asnber_field_desc_t any_field = make_field("parameters", any_id);
        any_field.flags = ASNBER_FIELD_OPTIONAL;
        ASNBER_TEST_CHECK(asnber_schema_add_field(schema, seq_id, &any_field) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_set_root(schema, seq_id) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);

        asnber_decode_options_t options;
        asnber_decode_options_init(&options);
        options.encoding = ASNBER_ENCODING_BER;

        /* 带 NULL parameters。 */
        static const uint8_t kWithNull[7] = {0x30, 0x05, 0x06, 0x01,
                                             0x2A, 0x05, 0x00};
        asnber_doc_t *doc = NULL;
        size_t consumed = 0;
        ASNBER_TEST_CHECK(asnber_decode_buffer_with_schema(
                            ctx, kWithNull, sizeof(kWithNull), schema,
                            &options, &doc, &consumed) == ASNBER_OK);
        const asnber_node_t *root = asnber_doc_root(doc);
        ASNBER_TEST_CHECK(root != NULL);
        ASNBER_TEST_CHECK(asnber_node_child_count(root) == 2);
        const asnber_node_t *any_node =
            asnber_node_child_by_name(root, "parameters");
        ASNBER_TEST_CHECK(any_node != NULL);
        ASNBER_TEST_CHECK(asnber_node_child_count(any_node) == 0);
        size_t any_size = 0;
        const uint8_t *any_tlv = asnber_node_tlv(any_node, &any_size);
        ASNBER_TEST_CHECK(any_size == 2);
        ASNBER_TEST_CHECK(any_tlv != NULL);
        ASNBER_TEST_CHECK(any_tlv[0] == 0x05 && any_tlv[1] == 0x00);
        asnber_doc_destroy(doc);

        /* 缺省 OPTIONAL ANY。 */
        static const uint8_t kWithoutAny[5] = {0x30, 0x03, 0x06, 0x01, 0x2A};
        ASNBER_TEST_CHECK(asnber_decode_buffer_with_schema(
                            ctx, kWithoutAny, sizeof(kWithoutAny), schema,
                            &options, &doc, &consumed) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_child_count(asnber_doc_root(doc)) == 1);
        asnber_doc_destroy(doc);

        asnber_schema_destroy(schema);
    }

    {
        /* 末位 ANY 必选形态同样可封存与解码。 */
        asnber_schema_t *schema = NULL;
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        uint32_t oid_id = 0;
        uint32_t any_id = 0;
        uint32_t seq_id = 0;
        asnber_type_desc_t oid_type =
            make_type("Oid", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 6,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &oid_type, &oid_id) ==
                        ASNBER_OK);
        asnber_type_desc_t any_type = make_any("AnyType");
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &any_type, &any_id) ==
                        ASNBER_OK);
        asnber_type_desc_t seq_type =
            make_type("MandatoryTail", ASNBER_TYPE_KIND_SEQUENCE,
                      ASNBER_TAG_UNIVERSAL, 16, ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &seq_type, &seq_id) ==
                        ASNBER_OK);
        asnber_field_desc_t oid_field = make_field("algorithm", oid_id);
        asnber_field_desc_t any_field = make_field("parameters", any_id);
        ASNBER_TEST_CHECK(asnber_schema_add_field(schema, seq_id, &oid_field) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_add_field(schema, seq_id, &any_field) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_set_root(schema, seq_id) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);

        asnber_decode_options_t options;
        asnber_decode_options_init(&options);
        options.encoding = ASNBER_ENCODING_BER;
        static const uint8_t kWithNull[7] = {0x30, 0x05, 0x06, 0x01,
                                             0x2A, 0x05, 0x00};
        static const uint8_t kMissing[5] = {0x30, 0x03, 0x06, 0x01, 0x2A};
        asnber_doc_t *doc = NULL;
        size_t consumed = 0;
        ASNBER_TEST_CHECK(asnber_decode_buffer_with_schema(
                            ctx, kWithNull, sizeof(kWithNull), schema,
                            &options, &doc, &consumed) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_child_count(asnber_doc_root(doc)) == 2);
        asnber_doc_destroy(doc);
        ASNBER_TEST_CHECK(asnber_decode_buffer_with_schema(
                            ctx, kMissing, sizeof(kMissing), schema, &options,
                            &doc, &consumed) == ASNBER_E_SCHEMA_FIELD);
        asnber_schema_destroy(schema);
    }

    {
        /* 非末位 DEFAULT-ANY 与非空 SET 中的 DEFAULT-ANY 均被拒。 */
        asnber_schema_t *schema = NULL;
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        uint32_t oid_id = 0;
        uint32_t any_id = 0;
        uint32_t seq_id = 0;
        uint32_t set_id = 0;
        asnber_type_desc_t oid_type =
            make_type("Oid", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 6,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &oid_type, &oid_id) ==
                        ASNBER_OK);
        asnber_type_desc_t any_type = make_any("AnyType");
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &any_type, &any_id) ==
                        ASNBER_OK);
        asnber_type_desc_t seq_type =
            make_type("BadSequence", ASNBER_TYPE_KIND_SEQUENCE,
                      ASNBER_TAG_UNIVERSAL, 16, ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &seq_type, &seq_id) ==
                        ASNBER_OK);
        asnber_field_desc_t any_field = make_field("anyFirst", any_id);
        ASNBER_TEST_CHECK(asnber_schema_add_field(schema, seq_id, &any_field) ==
                        ASNBER_OK);
        asnber_field_desc_t oid_field = make_field("oidLater", oid_id);
        ASNBER_TEST_CHECK(asnber_schema_add_field(schema, seq_id, &oid_field) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_E_SCHEMA_TYPE);

        asnber_schema_destroy(schema);
    }

    {
        /* SET 依赖标签消歧，不允许 DEFAULT-ANY。 */
        asnber_schema_t *schema = NULL;
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        uint32_t any_id = 0;
        uint32_t set_id = 0;
        asnber_type_desc_t any_type = make_any("AnyType");
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &any_type, &any_id) ==
                        ASNBER_OK);
        asnber_type_desc_t set_type =
            make_type("BadSet", ASNBER_TYPE_KIND_SET, ASNBER_TAG_UNIVERSAL, 17,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &set_type, &set_id) ==
                        ASNBER_OK);
        asnber_field_desc_t any_field = make_field("anyValue", any_id);
        ASNBER_TEST_CHECK(asnber_schema_add_field(schema, set_id, &any_field) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_E_SCHEMA_TYPE);
        asnber_schema_destroy(schema);
    }

    /* ===== 1c. EXPLICIT ANY：节点即外层包装，content 为内层原始 TLV ===== */
    {
        asnber_schema_t *schema = NULL;
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        uint32_t oid_id = 0;
        uint32_t any_id = 0;
        uint32_t seq_id = 0;
        asnber_type_desc_t oid_type =
            make_type("Oid", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 6,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &oid_type, &oid_id) ==
                        ASNBER_OK);
        asnber_type_desc_t any_type =
            make_type("ExplicitAny", ASNBER_TYPE_KIND_ANY, ASNBER_TAG_CONTEXT, 1,
                      ASNBER_TAG_MODE_EXPLICIT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &any_type, &any_id) ==
                        ASNBER_OK);
        asnber_type_desc_t seq_type =
            make_type("SecurityCategory", ASNBER_TYPE_KIND_SEQUENCE,
                      ASNBER_TAG_UNIVERSAL, 16, ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &seq_type, &seq_id) ==
                        ASNBER_OK);
        asnber_field_desc_t oid_field = make_field("type", oid_id);
        ASNBER_TEST_CHECK(asnber_schema_add_field(schema, seq_id, &oid_field) ==
                        ASNBER_OK);
        asnber_field_desc_t any_field = make_field("value", any_id);
        any_field.flags = ASNBER_FIELD_OPTIONAL;
        ASNBER_TEST_CHECK(asnber_schema_add_field(schema, seq_id, &any_field) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_set_root(schema, seq_id) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);

        static const uint8_t kInnerSeq[5] = {0x30, 0x03, 0x02, 0x01, 0x05};
        static const uint8_t kOuterSeq[12] = {0x30, 0x0A, 0x06, 0x01, 0x2A,
                                             0xA1, 0x05, 0x30, 0x03,
                                             0x02, 0x01, 0x05};
        static const uint8_t kInnerOctets[4] = {0x04, 0x02, 0xAA, 0xBB};
        static const uint8_t kOuterOctets[11] = {0x30, 0x09, 0x06, 0x01, 0x2A,
                                                0xA1, 0x04, 0x04, 0x02,
                                                0xAA, 0xBB};
        static const uint8_t kOuterContextZero[11] = {
            0x30, 0x09, 0x06, 0x01, 0x2A, 0xA0, 0x04, 0x04, 0x02, 0xAA, 0xBB};

        asnber_decode_options_t options;
        asnber_decode_options_init(&options);
        options.encoding = ASNBER_ENCODING_BER;

        asnber_doc_t *doc = NULL;
        size_t consumed = 0;
        ASNBER_TEST_CHECK(asnber_decode_buffer_with_schema(
                            ctx, kOuterSeq, sizeof(kOuterSeq), schema,
                            &options, &doc, &consumed) == ASNBER_OK);
        const asnber_node_t *any_node =
            asnber_node_child_by_name(asnber_doc_root(doc), "value");
        ASNBER_TEST_CHECK(any_node != NULL);
        ASNBER_TEST_CHECK(asnber_node_child_count(any_node) == 0);
        size_t tlv_size = 0;
        const uint8_t *tlv = asnber_node_tlv(any_node, &tlv_size);
        ASNBER_TEST_CHECK(tlv_size == 7);
        ASNBER_TEST_CHECK(bytes_equal(tlv, tlv_size, kOuterSeq + 5, 7));
        const uint8_t *content = NULL;
        size_t content_size = 0;
        ASNBER_TEST_CHECK(asnber_node_content(any_node, &content, &content_size) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(content_size == sizeof(kInnerSeq));
        ASNBER_TEST_CHECK(bytes_equal(content, content_size, kInnerSeq,
                                    sizeof(kInnerSeq)));
        asnber_doc_destroy(doc);

        ASNBER_TEST_CHECK(asnber_decode_buffer_with_schema(
                            ctx, kOuterOctets, sizeof(kOuterOctets), schema,
                            &options, &doc, &consumed) == ASNBER_OK);
        any_node = asnber_node_child_by_name(asnber_doc_root(doc), "value");
        ASNBER_TEST_CHECK(any_node != NULL);
        tlv = asnber_node_tlv(any_node, &tlv_size);
        ASNBER_TEST_CHECK(tlv_size == 6);
        ASNBER_TEST_CHECK(bytes_equal(tlv, tlv_size, kOuterOctets + 5, 6));
        ASNBER_TEST_CHECK(asnber_node_content(any_node, &content, &content_size) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(content_size == sizeof(kInnerOctets));
        ASNBER_TEST_CHECK(bytes_equal(content, content_size, kInnerOctets,
                                    sizeof(kInnerOctets)));
        asnber_doc_destroy(doc);

        /* 描述表路径：kind = 6 + EXPLICIT + CONTEXT 0 也能注册。 */
        asnber_schema_destroy(schema);
        asnber_schema_t *zero_schema = NULL;
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &zero_schema) == ASNBER_OK);
        uint32_t zero_any = 0;
        uint32_t zero_seq = 0;
        asnber_type_desc_t zero_type =
            make_type("ExplicitAnyZero", ASNBER_TYPE_KIND_ANY,
                      ASNBER_TAG_CONTEXT, 0, ASNBER_TAG_MODE_EXPLICIT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(zero_schema, &zero_type,
                                             &zero_any) == ASNBER_OK);
        asnber_type_desc_t zero_seq_type =
            make_type("OtherName", ASNBER_TYPE_KIND_SEQUENCE,
                      ASNBER_TAG_UNIVERSAL, 16, ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(zero_schema, &zero_seq_type,
                                             &zero_seq) == ASNBER_OK);
        uint32_t zero_oid = 0;
        asnber_type_desc_t zero_oid_type =
            make_type("Oid", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 6,
                      ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(zero_schema, &zero_oid_type,
                                             &zero_oid) == ASNBER_OK);
        asnber_field_desc_t oid_zero_field = make_field("type-id", zero_oid);
        ASNBER_TEST_CHECK(asnber_schema_add_field(zero_schema, zero_seq,
                                              &oid_zero_field) == ASNBER_OK);
        asnber_field_desc_t any_zero_field = make_field("value", zero_any);
        ASNBER_TEST_CHECK(asnber_schema_add_field(zero_schema, zero_seq,
                                              &any_zero_field) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_set_root(zero_schema, zero_seq) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_seal(zero_schema) == ASNBER_OK);
        asnber_err_t zero_rc = asnber_decode_buffer_with_schema(
                            ctx, kOuterContextZero, sizeof(kOuterContextZero),
                            zero_schema, &options, &doc, &consumed);
        ASNBER_TEST_CHECK(zero_rc == ASNBER_OK);
        any_node = asnber_node_child_by_name(asnber_doc_root(doc), "value");
        ASNBER_TEST_CHECK(any_node != NULL);
        tlv = asnber_node_tlv(any_node, &tlv_size);
        ASNBER_TEST_CHECK(tlv_size == 6);
        ASNBER_TEST_CHECK(bytes_equal(tlv, tlv_size, kOuterContextZero + 5, 6));
        asnber_doc_destroy(doc);
        asnber_schema_destroy(zero_schema);
    }

    /* ===== 1d. SET OF ANY：注册、封存与异构解码 ===== */
    {
        asnber_schema_t *schema = NULL;
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        uint32_t any_id = 0;
        uint32_t set_of_id = 0;
        asnber_type_desc_t any_type = make_any("AttributeValue");
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &any_type, &any_id) ==
                        ASNBER_OK);
        asnber_type_desc_t set_of_type =
            make_type("AttributeSet", ASNBER_TYPE_KIND_SET_OF,
                      ASNBER_TAG_UNIVERSAL, 17, ASNBER_TAG_MODE_DEFAULT, any_id);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &set_of_type,
                                             &set_of_id) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_set_root(schema, set_of_id) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);

        static const uint8_t kSetOfAny[13] = {
            0x31, 0x0B, 0x05, 0x00, 0x02, 0x01, 0x05, 0x04, 0x02,
            0xAA, 0xBB, 0x30, 0x00};
        asnber_decode_options_t options;
        asnber_decode_options_init(&options);
        options.encoding = ASNBER_ENCODING_BER;
        asnber_doc_t *doc = NULL;
        size_t consumed = 0;
        ASNBER_TEST_CHECK(asnber_decode_buffer_with_schema(
                            ctx, kSetOfAny, sizeof(kSetOfAny), schema, &options,
                            &doc, &consumed) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_child_count(asnber_doc_root(doc)) == 4);
        const asnber_node_t *element = asnber_node_child_at(asnber_doc_root(doc), 0);
        ASNBER_TEST_CHECK(element != NULL);
        ASNBER_TEST_CHECK(asnber_node_child_count(element) == 0);
        asnber_doc_destroy(doc);
        asnber_schema_destroy(schema);
    }


    /* ===== 2. 描述表 kind = 6 ===== */
    {
        uint8_t table_bytes[160];
        build_any_table(table_bytes, sizeof(table_bytes));

        asnber_schema_table_t table;
        memset(&table, 0, sizeof(table));
        table.struct_size = sizeof(table);
        table.data = table_bytes;
        table.size = sizeof(table_bytes);
        table.format_version = 1u << 16;

        asnber_schema_t *schema = NULL;
        ASNBER_TEST_CHECK(asnber_schema_load(ctx, &table, &schema) == ASNBER_OK);
        asnber_test_type_info info;
        ASNBER_TEST_CHECK(asnber_test_schema_type_info(schema, 1, &info) == 1);
        ASNBER_TEST_CHECK(info.kind == 6);
        ASNBER_TEST_CHECK(info.tag_number == 0);
        ASNBER_TEST_CHECK(info.element_type_id == 0);
        asnber_schema_destroy(schema);
    }

    /* ===== 3. ANY 节点语义与编码回写 ===== */
    {
        static const uint8_t kNullTlv[2] = {0x05, 0x00};
        ASNBER_TEST_CHECK(roundtrip_any(ctx, kNullTlv, sizeof(kNullTlv), 0, 0) ==
                        0);

        static const uint8_t kConstructedTlv[5] = {0x30, 0x03, 0x02, 0x01,
                                                   0x05};
        ASNBER_TEST_CHECK(roundtrip_any(ctx, kConstructedTlv,
                                      sizeof(kConstructedTlv), 1, 3) == 0);

        /* 未知 OID 的任意 TLV：OID 1.2.3.4 与一段 OCTET STRING。 */
        static const uint8_t kUnknownOidTlv[10] = {
            0x30, 0x08, 0x06, 0x03, 0x2A, 0x03, 0x04, 0x04, 0x01, 0x00};
        ASNBER_TEST_CHECK(roundtrip_any(ctx, kUnknownOidTlv,
                                      sizeof(kUnknownOidTlv), 1, 8) == 0);

        /* 无 schema 的通用编码路径：BER 不定长原始 TLV 按原样保留与回写。
           schema 感知 DER 编码会对此类源返回 ASNBER_E_NON_CANONICAL。 */
        static const uint8_t kIndefiniteExact[7] = {0x30, 0x80, 0x02, 0x01,
                                                    0x05, 0x00, 0x00};
        ASNBER_TEST_CHECK(roundtrip_any(ctx, kIndefiniteExact,
                                      sizeof(kIndefiniteExact), 1, 3) == 0);

        /* 注释中的承诺落到断言：BER 不定长保留 TLV 在 schema 感知 DER
           编码时返回 NON_CANONICAL，且不产出字节。 */
        asnber_schema_t *schema = NULL;
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        asnber_type_desc_t any_type = make_any("AnyRoot");
        uint32_t any_id = 0;
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &any_type, &any_id) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_set_root(schema, any_id) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);

        asnber_decode_options_t decode_options;
        asnber_decode_options_init(&decode_options);
        decode_options.encoding = ASNBER_ENCODING_BER;
        asnber_doc_t *doc = NULL;
        size_t consumed = 0;
        ASNBER_TEST_CHECK(asnber_decode_buffer_with_schema(
                            ctx, kIndefiniteExact, sizeof(kIndefiniteExact),
                            schema, &decode_options, &doc, &consumed) ==
                        ASNBER_OK);

        asnber_encode_options_t encode_options;
        asnber_encode_options_init(&encode_options);
        encode_options.schema = schema;
        asnber_buf_t buf;
        memset(&buf, 0, sizeof(buf));
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, &encode_options, &buf) ==
                        ASNBER_E_NON_CANONICAL);
        ASNBER_TEST_CHECK(buf.data == NULL && buf.size == 0);
        asnber_doc_destroy(doc);
        asnber_schema_destroy(schema);
    }

    /* ===== 4. ANY 作为构造父节点的子节点（schema-aware 等价用例）===== */
    {
        asnber_schema_t *schema = NULL;
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        uint32_t any_id = 0;
        uint32_t seq_id = 0;
        asnber_type_desc_t any_type = make_any("Value");
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &any_type, &any_id) ==
                        ASNBER_OK);
        asnber_type_desc_t seq_type =
            make_type("Wrapper", ASNBER_TYPE_KIND_SEQUENCE, ASNBER_TAG_UNIVERSAL,
                      16, ASNBER_TAG_MODE_DEFAULT, 0);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &seq_type, &seq_id) ==
                        ASNBER_OK);
        asnber_field_desc_t value_field = make_field("value", any_id);
        ASNBER_TEST_CHECK(asnber_schema_add_field(schema, seq_id, &value_field) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_set_root(schema, seq_id) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);

        static const uint8_t kSeqNull[4] = {0x30, 0x02, 0x05, 0x00};
        asnber_decode_options_t options;
        asnber_decode_options_init(&options);
        options.encoding = ASNBER_ENCODING_BER;
        asnber_doc_t *doc = NULL;
        size_t consumed = 0;
        ASNBER_TEST_CHECK(asnber_decode_buffer_with_schema(
                            ctx, kSeqNull, sizeof(kSeqNull), schema, &options,
                            &doc, &consumed) == ASNBER_OK);
        const asnber_node_t *root = asnber_doc_root(doc);
        ASNBER_TEST_CHECK(root != NULL);
        ASNBER_TEST_CHECK(asnber_node_child_count(root) == 1);
        const asnber_node_t *any_node = asnber_node_child_by_name(root, "value");
        ASNBER_TEST_CHECK(any_node != NULL);
        ASNBER_TEST_CHECK(asnber_node_child_count(any_node) == 0);

        asnber_buf_t buf;
        memset(&buf, 0, sizeof(buf));
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, NULL, &buf) == ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(buf.data, buf.size, kSeqNull,
                                    sizeof(kSeqNull)));
        ASNBER_TEST_CHECK(asnber_buf_release(ctx, &buf) == ASNBER_OK);
        asnber_doc_destroy(doc);
        asnber_schema_destroy(schema);
    }

    /* ===== 5. 真实证书 AlgorithmIdentifier.parameters ===== */
    {
        asnber_decode_options_t options;
        asnber_decode_options_init(&options);
        options.encoding = ASNBER_ENCODING_BER;

        /* RSA：parameters = NULL (05 00)。 */
        asnber_doc_t *doc = NULL;
        size_t consumed = 0;
        ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, kCertRsaSelfsigned,
                                           kCertRsaSelfsignedSize, &options,
                                           &doc, &consumed) == ASNBER_OK);
        size_t param_size = 0;
        const uint8_t *param = cert_parameters_tlv(doc, &param_size);
        ASNBER_TEST_CHECK(param != NULL);
        ASNBER_TEST_CHECK(param_size == 2);
        ASNBER_TEST_CHECK(param[0] == 0x05 && param[1] == 0x00);
        ASNBER_TEST_CHECK(roundtrip_any(ctx, param, param_size, 0, 0) == 0);
        asnber_doc_destroy(doc);

        /* RSA-PSS：parameters = SEQUENCE。 */
        doc = NULL;
        consumed = 0;
        ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, kCertRsaPssSelfsigned,
                                           kCertRsaPssSelfsignedSize,
                                           &options, &doc, &consumed) ==
                        ASNBER_OK);
        param = cert_parameters_tlv(doc, &param_size);
        ASNBER_TEST_CHECK(param != NULL);
        ASNBER_TEST_CHECK(param_size > 2);
        ASNBER_TEST_CHECK(param[0] == 0x30);
        ASNBER_TEST_CHECK(roundtrip_any(ctx, param, param_size, 1,
                                      param_size - 2) == 0);
        asnber_doc_destroy(doc);

        /* EC：ecdsa-with-SHA256 的 AlgorithmIdentifier 参数缺省（无子节点）。 */
        doc = NULL;
        consumed = 0;
        ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, kCertEcSelfsigned,
                                           kCertEcSelfsignedSize, &options,
                                           &doc, &consumed) == ASNBER_OK);
        param = cert_parameters_tlv(doc, &param_size);
        ASNBER_TEST_CHECK(param == NULL);
        asnber_doc_destroy(doc);
    }

    asnber_ctx_destroy(ctx);
    return 0;
}
