/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * asnberc 端到端测试：加载构建期生成的 PKIX 描述表，校验描述表语义、
 * .bin 头部自检、真证书 schema 解码/编码往返，以及与手工运行时树的等价性。
 */

#include <asnber/asnber.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "check.h"
#include "cert_ec_selfsigned.h"
#include "cert_rsa_selfsigned.h"
#include "schema_compare.h"
#include "schema_probe.h"

#ifndef ASNBERC_PKIX_BIN
#error "ASNBERC_PKIX_BIN must be defined by the build system"
#endif
#ifndef ASNBERC_EQUIV_BIN
#error "ASNBERC_EQUIV_BIN must be defined by the build system"
#endif

#define PKIX_TYPE_COUNT 173u
#define PKIX_NAMED_COUNT 69u
#define PKIX_ROOT_TYPE_ID 20u
#define PKIX_NAME_COUNT 31u
#define PKIX_NAME_KEYUSAGE 9u
#define PKIX_NAME_REASONFLAGS 9u
#define PKIX_NAME_CRLREASON 10u
#define PKIX_NAME_VERSION 3u

static uint32_t read_u32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint16_t read_u16le(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint64_t read_u64le(const uint8_t *p)
{
    return (uint64_t)read_u32le(p) | ((uint64_t)read_u32le(p + 4) << 32);
}

static uint8_t *read_file(const char *path, size_t *out_size)
{
    FILE *f = fopen(path, "rb");
    size_t size;
    uint8_t *data;

    if (f == NULL) {
        fprintf(stderr, "cannot open %s\n", path);
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    size = (size_t)ftell(f);
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }
    data = (uint8_t *)malloc(size == 0 ? 1 : size);
    if (data == NULL) {
        fclose(f);
        return NULL;
    }
    if (size != 0 && fread(data, 1, size, f) != size) {
        free(data);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *out_size = size;
    return data;
}

static int load_schema(asnber_ctx_t *ctx, const uint8_t *data, size_t size,
                       asnber_schema_t **out_schema)
{
    asnber_schema_table_t table;

    memset(&table, 0, sizeof(table));
    table.struct_size = sizeof(table);
    table.data = data;
    table.size = size;
    table.format_version = (1u << 16) | 0u;
    return asnber_schema_load(ctx, &table, out_schema) == ASNBER_OK ? 0 : 1;
}

static uint32_t find_type(const asnber_schema_t *schema, const char *name,
                          asnber_test_type_info *out_info)
{
    uint32_t count = asnber_test_schema_type_count(schema);
    uint32_t id;

    for (id = 1; id <= count; ++id) {
        asnber_test_type_info info;
        if (!asnber_test_schema_type_info(schema, id, &info)) {
            continue;
        }
        if (strcmp(info.name, name) == 0) {
            if (out_info != NULL) {
                *out_info = info;
            }
            return id;
        }
    }
    return 0;
}

static int find_field(const asnber_schema_t *schema, uint32_t type_id,
                      const char *name, uint32_t *out_index,
                      asnber_test_field_info *out_info)
{
    asnber_test_type_info type;
    uint32_t index;

    if (!asnber_test_schema_type_info(schema, type_id, &type)) {
        return 1;
    }
    for (index = 0; index < type.field_count; ++index) {
        asnber_test_field_info field;
        if (!asnber_test_schema_field_info(schema, type_id, index, &field)) {
            continue;
        }
        if (strcmp(field.name, name) == 0) {
            if (out_index != NULL) {
                *out_index = index;
            }
            if (out_info != NULL) {
                *out_info = field;
            }
            return 0;
        }
    }
    return 1;
}

/* 校验一处 ANY 字段的类型记录 tag 语义。 */
static int check_any_field(const asnber_schema_t *schema, const char *type_name,
                           const char *field_name, uint32_t tag_mode,
                           uint32_t tag_class, uint32_t tag_number)
{
    uint32_t type_id = find_type(schema, type_name, NULL);
    asnber_test_field_info field;
    asnber_test_type_info any_type;

    ASNBER_TEST_CHECK(type_id != 0);
    ASNBER_TEST_CHECK(find_field(schema, type_id, field_name, NULL, &field) == 0);
    ASNBER_TEST_CHECK(
        asnber_test_schema_type_info(schema, field.type_id, &any_type));
    ASNBER_TEST_CHECK(any_type.kind == ASNBER_TYPE_KIND_ANY);
    ASNBER_TEST_CHECK(any_type.tag_mode == tag_mode);
    ASNBER_TEST_CHECK(any_type.tag_class == tag_class);
    ASNBER_TEST_CHECK(any_type.tag_number == tag_number);
    ASNBER_TEST_CHECK(any_type.element_type_id == 0u);
    ASNBER_TEST_CHECK(any_type.constraint_count == 0u);
    return 0;
}

static int test_bin_header(void)
{
    static const uint8_t kMagic[8] = {0x41, 0x53, 0x4E, 0x31,
                                      0x53, 0x43, 0x48, 0x1A};
    size_t size = 0;
    uint8_t *data = read_file(ASNBERC_PKIX_BIN, &size);
    uint32_t spans[6][2];
    uint32_t i;
    uint32_t j;
    uint8_t *copy;
    uint32_t computed;
    uint32_t stored_checksum;
    uint32_t type_count;
    uint32_t field_count;
    uint32_t constraint_count;
    uint32_t default_count;
    uint32_t name_count;
    uint32_t name_offset;
    uint64_t total_size;

    ASNBER_TEST_CHECK(data != NULL);
    ASNBER_TEST_CHECK(size >= 108u);
    ASNBER_TEST_CHECK(memcmp(data, kMagic, sizeof(kMagic)) == 0);
    ASNBER_TEST_CHECK(read_u32le(data + 8) == ((1u << 16) | 0u));
    ASNBER_TEST_CHECK(read_u32le(data + 12) == 108u);
    ASNBER_TEST_CHECK(read_u32le(data + 16) == 0x01020304u);
    ASNBER_TEST_CHECK(read_u32le(data + 24) == 1u);
    ASNBER_TEST_CHECK(read_u32le(data + 28) == 1u);
    total_size = read_u64le(data + 32);
    ASNBER_TEST_CHECK(total_size == (uint64_t)size);

    /* 六张表：字符串池、类型、字段、约束、默认值、名称。 */
    type_count = read_u32le(data + 52);
    field_count = read_u32le(data + 60);
    constraint_count = read_u32le(data + 68);
    default_count = read_u32le(data + 76);
    name_offset = read_u32le(data + 100);
    name_count = read_u32le(data + 104);
    ASNBER_TEST_CHECK(type_count == PKIX_TYPE_COUNT);
    ASNBER_TEST_CHECK(name_count == PKIX_NAME_COUNT);
    ASNBER_TEST_CHECK(name_offset != 0u);
    spans[0][0] = read_u32le(data + 40);
    spans[0][1] = read_u32le(data + 44);
    spans[1][0] = read_u32le(data + 48);
    spans[1][1] = type_count * 48u;
    spans[2][0] = read_u32le(data + 56);
    spans[2][1] = field_count * 32u;
    spans[3][0] = read_u32le(data + 64);
    spans[3][1] = constraint_count * 48u;
    spans[4][0] = read_u32le(data + 72);
    spans[4][1] = default_count * 8u;
    spans[5][0] = name_offset;
    spans[5][1] = name_count * 24u;

    for (i = 0; i < 6u; ++i) {
        ASNBER_TEST_CHECK(spans[i][0] >= 108u);
        ASNBER_TEST_CHECK((uint64_t)spans[i][0] + spans[i][1] <= total_size);
    }
    for (i = 0; i < 6u; ++i) {
        for (j = i + 1u; j < 6u; ++j) {
            const uint64_t start_a = spans[i][0];
            const uint64_t end_a = (uint64_t)spans[i][0] + spans[i][1];
            const uint64_t start_b = spans[j][0];
            const uint64_t end_b = (uint64_t)spans[j][0] + spans[j][1];
            ASNBER_TEST_CHECK(end_a <= start_b || end_b <= start_a);
        }
    }

    /* 名称记录逐条自洽：type_id 在范围内、name_off 指向字符串池。 */
    for (i = 0; i < name_count; ++i) {
        const size_t rec = (size_t)name_offset + (size_t)i * 24u;
        const uint32_t type_id = read_u32le(data + rec);
        const uint32_t name_off = read_u32le(data + rec + 4);
        ASNBER_TEST_CHECK(type_id >= 1u && type_id <= type_count);
        ASNBER_TEST_CHECK(name_off != 0u);
        ASNBER_TEST_CHECK(name_off >= spans[0][0]);
        ASNBER_TEST_CHECK((uint64_t)name_off <
                        (uint64_t)spans[0][0] + spans[0][1]);
        ASNBER_TEST_CHECK(read_u16le(data + rec + 8) <= 1u);
        ASNBER_TEST_CHECK((read_u16le(data + rec + 10) & ~1u) == 0u);
        ASNBER_TEST_CHECK(read_u32le(data + rec + 12) == 0u);
    }

    /* CRC32C：整表覆盖，checksum 字段（偏移 80）按 0 参与计算。 */
    stored_checksum = read_u32le(data + 80);
    copy = (uint8_t *)malloc(size);
    ASNBER_TEST_CHECK(copy != NULL);
    memcpy(copy, data, size);
    memset(copy + 80, 0, 4);
    {
        const uint8_t *p = copy;
        size_t left = size;
        computed = 0xFFFFFFFFu;
        while (left > 0) {
            int bit;
            computed ^= (uint32_t)p[0];
            for (bit = 0; bit < 8; ++bit) {
                computed = (computed >> 1) ^
                           (0x82F63B78u &
                            (uint32_t)(-(int32_t)(computed & 1u)));
            }
            ++p;
            --left;
        }
        computed ^= 0xFFFFFFFFu;
    }
    ASNBER_TEST_CHECK(computed == stored_checksum);
    free(copy);

    /* CRC32C 已知答案：标准测试向量 "123456789"。 */
    {
        static const uint8_t kVector[9] = {'1', '2', '3', '4', '5',
                                           '6', '7', '8', '9'};
        const uint8_t *p = kVector;
        size_t left = sizeof(kVector);
        uint32_t crc = 0xFFFFFFFFu;
        while (left > 0) {
            int bit;
            crc ^= (uint32_t)p[0];
            for (bit = 0; bit < 8; ++bit) {
                crc = (crc >> 1) ^
                      (0x82F63B78u & (uint32_t)(-(int32_t)(crc & 1u)));
            }
            ++p;
            --left;
        }
        crc ^= 0xFFFFFFFFu;
        ASNBER_TEST_CHECK(crc == 0xE3069283u);
    }

    free(data);
    return 0;
}

static int test_table_shape(const asnber_schema_t *schema)
{
    uint32_t count = asnber_test_schema_type_count(schema);
    uint32_t id;
    uint32_t named = 0;
    asnber_test_type_info info;

    ASNBER_TEST_CHECK(count == PKIX_TYPE_COUNT);
    ASNBER_TEST_CHECK(asnber_test_schema_sealed(schema) == 1);
    ASNBER_TEST_CHECK(asnber_test_schema_module_tag_mode(schema) == 2u);

    for (id = 1; id <= count; ++id) {
        ASNBER_TEST_CHECK(asnber_test_schema_type_info(schema, id, &info));
        if (info.name[0] != '$') {
            ++named;
            ASNBER_TEST_CHECK(id <= PKIX_NAMED_COUNT);
        } else {
            ASNBER_TEST_CHECK(id > PKIX_NAMED_COUNT);
        }
    }
    ASNBER_TEST_CHECK(named == PKIX_NAMED_COUNT);

    ASNBER_TEST_CHECK(asnber_test_schema_root_type_id(schema) ==
                    PKIX_ROOT_TYPE_ID);
    ASNBER_TEST_CHECK(
        asnber_test_schema_type_info(schema, PKIX_ROOT_TYPE_ID, &info));
    ASNBER_TEST_CHECK(strcmp(info.name, "Certificate") == 0);
    return 0;
}

static int expect_bit_name(const asnber_schema_t *schema, uint32_t type_id,
                           uint32_t bit, const char *expected)
{
    const char *name = (const char *)(void *)0x1;
    int64_t value = -1;
    int found = -1;

    ASNBER_TEST_CHECK(asnber_schema_name_for_bit(schema, type_id, bit, &name) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(name != NULL && strcmp(name, expected) == 0);
    ASNBER_TEST_CHECK(asnber_schema_value_for_name(schema, type_id, expected,
                                               &value, &found) == ASNBER_OK);
    ASNBER_TEST_CHECK(found == 1 && value == (int64_t)bit);
    return 0;
}

static int expect_number_name(const asnber_schema_t *schema, uint32_t type_id,
                              int64_t value, const char *expected)
{
    const char *name = (const char *)(void *)0x1;
    int64_t found_value = -1;
    int found = -1;

    ASNBER_TEST_CHECK(asnber_schema_name_for_value(schema, type_id, value, &name) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(name != NULL && strcmp(name, expected) == 0);
    ASNBER_TEST_CHECK(asnber_schema_value_for_name(schema, type_id, expected,
                                               &found_value, &found) == ASNBER_OK);
    ASNBER_TEST_CHECK(found == 1 && found_value == value);
    return 0;
}

static int test_names(const asnber_schema_t *schema)
{
    static const struct {
        uint32_t bit;
        const char *name;
    } kKeyUsage[] = {
        {0u, "digitalSignature"}, {1u, "nonRepudiation"},
        {2u, "keyEncipherment"},  {3u, "dataEncipherment"},
        {4u, "keyAgreement"},     {5u, "keyCertSign"},
        {6u, "cRLSign"},          {7u, "encipherOnly"},
        {8u, "decipherOnly"}};
    static const struct {
        uint32_t bit;
        const char *name;
    } kReasonFlags[] = {
        {0u, "unused"}, {1u, "keyCompromise"}, {8u, "aACompromise"}};
    static const struct {
        int64_t value;
        const char *name;
    } kCrlReason[] = {
        {0, "unspecified"},          {1, "keyCompromise"},
        {2, "cACompromise"},         {3, "affiliationChanged"},
        {4, "superseded"},           {5, "cessationOfOperation"},
        {6, "certificateHold"},      {8, "removeFromCRL"},
        {9, "privilegeWithdrawn"},   {10, "aACompromise"}};
    uint32_t key_usage = find_type(schema, "KeyUsage", NULL);
    uint32_t reason_flags = find_type(schema, "ReasonFlags", NULL);
    uint32_t crl_reason = find_type(schema, "CRLReason", NULL);
    uint32_t version = find_type(schema, "Version", NULL);
    const char *name = NULL;
    uint32_t count = 0;
    uint32_t i;

    ASNBER_TEST_CHECK(key_usage != 0u);
    ASNBER_TEST_CHECK(reason_flags != 0u);
    ASNBER_TEST_CHECK(crl_reason != 0u);
    ASNBER_TEST_CHECK(version != 0u);

    ASNBER_TEST_CHECK(asnber_schema_name_count(schema, key_usage, &count) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(count == PKIX_NAME_KEYUSAGE);
    ASNBER_TEST_CHECK(asnber_schema_name_count(schema, reason_flags, &count) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(count == PKIX_NAME_REASONFLAGS);
    ASNBER_TEST_CHECK(asnber_schema_name_count(schema, crl_reason, &count) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(count == PKIX_NAME_CRLREASON);
    ASNBER_TEST_CHECK(asnber_schema_name_count(schema, version, &count) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(count == PKIX_NAME_VERSION);

    for (i = 0; i < sizeof(kKeyUsage) / sizeof(kKeyUsage[0]); ++i) {
        ASNBER_TEST_CHECK(expect_bit_name(schema, key_usage, kKeyUsage[i].bit,
                                        kKeyUsage[i].name) == 0);
    }
    ASNBER_TEST_CHECK(asnber_schema_name_for_bit(schema, key_usage, 20u, &name) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(name == NULL);

    for (i = 0; i < sizeof(kReasonFlags) / sizeof(kReasonFlags[0]); ++i) {
        ASNBER_TEST_CHECK(expect_bit_name(schema, reason_flags,
                                        kReasonFlags[i].bit,
                                        kReasonFlags[i].name) == 0);
    }

    for (i = 0; i < sizeof(kCrlReason) / sizeof(kCrlReason[0]); ++i) {
        ASNBER_TEST_CHECK(expect_number_name(schema, crl_reason,
                                           kCrlReason[i].value,
                                           kCrlReason[i].name) == 0);
    }
    ASNBER_TEST_CHECK(asnber_schema_name_for_value(schema, crl_reason, 7, &name) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(name == NULL);

    ASNBER_TEST_CHECK(expect_number_name(schema, version, 0, "v1") == 0);
    ASNBER_TEST_CHECK(expect_number_name(schema, version, 1, "v2") == 0);
    ASNBER_TEST_CHECK(expect_number_name(schema, version, 2, "v3") == 0);

    /* BIT_NAME 与 NUMBER_NAME 不跨 kind 命中。 */
    ASNBER_TEST_CHECK(asnber_schema_name_for_value(schema, key_usage, 0, &name) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(name == NULL);
    ASNBER_TEST_CHECK(asnber_schema_name_for_bit(schema, crl_reason, 0u, &name) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(name == NULL);
    ASNBER_TEST_CHECK(asnber_schema_name_for_bit(schema, version, 0u, &name) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(name == NULL);
    return 0;
}

static int test_any_fields(const asnber_schema_t *schema)
{
    uint32_t count = asnber_test_schema_type_count(schema);
    uint32_t id;
    uint32_t any_count = 0;
    uint32_t type_id;
    uint32_t field_index = 0;
    asnber_test_field_info field;
    asnber_test_type_info type;
    asnber_test_type_info element;
    uint32_t i;
    int found_size = 0;

    for (id = 1; id <= count; ++id) {
        if (asnber_test_schema_type_info(schema, id, &type) &&
            type.kind == ASNBER_TYPE_KIND_ANY) {
            ++any_count;
        }
    }
    ASNBER_TEST_CHECK(any_count == 3u);

    ASNBER_TEST_CHECK(check_any_field(schema, "AlgorithmIdentifier",
                                    "parameters", ASNBER_TAG_MODE_DEFAULT,
                                    ASNBER_TAG_UNIVERSAL, 0u) == 0);
    ASNBER_TEST_CHECK(check_any_field(schema, "SingleAttribute", "value",
                                    ASNBER_TAG_MODE_DEFAULT, ASNBER_TAG_UNIVERSAL,
                                    0u) == 0);
    ASNBER_TEST_CHECK(check_any_field(schema, "CERT-POLICY-QUALIFIER",
                                    "qualifier", ASNBER_TAG_MODE_DEFAULT,
                                    ASNBER_TAG_UNIVERSAL, 0u) == 0);
    ASNBER_TEST_CHECK(check_any_field(schema, "SECURITY-CATEGORY", "value",
                                    ASNBER_TAG_MODE_EXPLICIT, ASNBER_TAG_CONTEXT,
                                    1u) == 0);
    ASNBER_TEST_CHECK(check_any_field(schema, "OTHER-NAME", "value",
                                    ASNBER_TAG_MODE_EXPLICIT, ASNBER_TAG_CONTEXT,
                                    0u) == 0);

    type_id = find_type(schema, "AttributeSet", NULL);
    ASNBER_TEST_CHECK(type_id != 0);
    ASNBER_TEST_CHECK(find_field(schema, type_id, "values", &field_index,
                               &field) == 0);
    ASNBER_TEST_CHECK(
        asnber_test_schema_type_info(schema, field.type_id, &type));
    ASNBER_TEST_CHECK(type.kind == ASNBER_TYPE_KIND_SET_OF);
    ASNBER_TEST_CHECK(
        asnber_test_schema_type_info(schema, type.element_type_id, &element));
    ASNBER_TEST_CHECK(element.kind == ASNBER_TYPE_KIND_ANY);
    /* asnberc 把 `SET SIZE (1..MAX) OF ANY` 的 SIZE 约束记在 SET OF
       类型本身（而不是字段）上。 */
    ASNBER_TEST_CHECK(field.constraint_count == 0u);
    ASNBER_TEST_CHECK(type.constraint_count >= 1u);
    for (i = 0; i < type.constraint_count; ++i) {
        asnber_test_constraint_info constraint;
        ASNBER_TEST_CHECK(asnber_test_schema_type_constraint(
                            schema, field.type_id, i, &constraint) == 1);
        if (constraint.kind == ASNBER_CONSTRAINT_SIZE) {
            found_size = 1;
            ASNBER_TEST_CHECK(constraint.lower_unbounded == 0);
            ASNBER_TEST_CHECK(constraint.lower.value == 1);
            ASNBER_TEST_CHECK(constraint.upper_unbounded == 1);
        }
    }
    ASNBER_TEST_CHECK(found_size == 1);
    return 0;
}

static int expect_default(const asnber_schema_t *schema, const char *type_name,
                          const char *field_name, const uint8_t *expected,
                          size_t expected_size)
{
    uint32_t type_id = find_type(schema, type_name, NULL);
    uint32_t index = 0;
    asnber_test_field_info field;
    const uint8_t *bytes;
    size_t size = 0;

    ASNBER_TEST_CHECK(type_id != 0);
    ASNBER_TEST_CHECK(find_field(schema, type_id, field_name, &index, &field) ==
                    0);
    bytes = asnber_test_schema_field_default(schema, type_id, index, &size);
    ASNBER_TEST_CHECK(bytes != NULL);
    ASNBER_TEST_CHECK(size == expected_size);
    ASNBER_TEST_CHECK(memcmp(bytes, expected, expected_size) == 0);
    return 0;
}

static int test_structure_and_defaults(const asnber_schema_t *schema)
{
    uint32_t type_id;
    asnber_test_field_info field;
    asnber_test_type_info type;
    uint32_t i;
    int found_enum = 0;
    int found_size = 0;
    static const uint8_t kVersionDefault[5] = {0xA0, 0x03, 0x02, 0x01, 0x00};
    static const uint8_t kBooleanDefault[3] = {0x01, 0x01, 0x00};
    static const uint8_t kMinimumDefault[3] = {0x80, 0x01, 0x00};

    type_id = find_type(schema, "TBSCertificate", &type);
    ASNBER_TEST_CHECK(type_id != 0);
    ASNBER_TEST_CHECK((type.flags & ASNBER_TYPE_EXTENSIBLE) != 0u);

    ASNBER_TEST_CHECK(
        find_field(schema, type_id, "extensions", NULL, &field) == 0);
    ASNBER_TEST_CHECK((field.flags & ASNBER_FIELD_OPTIONAL) != 0u);
    ASNBER_TEST_CHECK((field.flags & ASNBER_FIELD_EXTENSION) != 0u);

    type_id = find_type(schema, "Version", &type);
    ASNBER_TEST_CHECK(type_id != 0);
    ASNBER_TEST_CHECK(type.constraint_count >= 1u);
    for (i = 0; i < type.constraint_count; ++i) {
        asnber_test_constraint_info constraint;
        ASNBER_TEST_CHECK(
            asnber_test_schema_type_constraint(schema, type_id, i, &constraint) ==
            1);
        if (constraint.kind == ASNBER_CONSTRAINT_ENUM) {
            found_enum = 1;
            ASNBER_TEST_CHECK(constraint.enum_count == 3u);
            ASNBER_TEST_CHECK(constraint.enum_values[0] == 0);
            ASNBER_TEST_CHECK(constraint.enum_values[1] == 1);
            ASNBER_TEST_CHECK(constraint.enum_values[2] == 2);
        }
    }
    ASNBER_TEST_CHECK(found_enum == 1);

    type_id = find_type(schema, "RelativeDistinguishedName", &type);
    ASNBER_TEST_CHECK(type_id != 0);
    ASNBER_TEST_CHECK(type.constraint_count >= 1u);
    for (i = 0; i < type.constraint_count; ++i) {
        asnber_test_constraint_info constraint;
        ASNBER_TEST_CHECK(
            asnber_test_schema_type_constraint(schema, type_id, i, &constraint) ==
            1);
        if (constraint.kind == ASNBER_CONSTRAINT_SIZE) {
            found_size = 1;
            ASNBER_TEST_CHECK(constraint.lower_unbounded == 0);
            ASNBER_TEST_CHECK(constraint.lower.value == 1);
            ASNBER_TEST_CHECK(constraint.upper_unbounded == 1);
        }
    }
    ASNBER_TEST_CHECK(found_size == 1);

    ASNBER_TEST_CHECK(expect_default(schema, "TBSCertificate", "version",
                                   kVersionDefault,
                                   sizeof(kVersionDefault)) == 0);
    ASNBER_TEST_CHECK(expect_default(schema, "BasicConstraints", "cA",
                                   kBooleanDefault,
                                   sizeof(kBooleanDefault)) == 0);
    ASNBER_TEST_CHECK(expect_default(schema, "GeneralSubtree", "minimum",
                                   kMinimumDefault,
                                   sizeof(kMinimumDefault)) == 0);
    return 0;
}

static int check_certificate(asnber_ctx_t *ctx, const asnber_schema_t *schema,
                             const char *label, const uint8_t *data,
                             size_t size)
{
    asnber_decode_options_t options;
    asnber_doc_t *doc = NULL;
    size_t consumed = 0;
    const asnber_node_t *root;
    const asnber_node_t *tbs;
    const asnber_node_t *subject;
    const asnber_node_t *issuer;
    const asnber_node_t *validity;
    const asnber_node_t *not_before;
    const asnber_node_t *not_after;
    const asnber_node_t *extensions;
    const asnber_node_t *ext_sequence;
    const asnber_node_t *extension;
    const asnber_node_t *extn_id;
    const asnber_node_t *extn_value;
    asnber_encode_options_t encode_options;
    asnber_buf_t encoded;
    asnber_err_t rc;

    asnber_decode_options_init(&options);
    options.encoding = ASNBER_ENCODING_BER;
    rc = asnber_decode_buffer_with_schema(ctx, data, size, schema, &options, &doc,
                                        &consumed);
    if (rc != ASNBER_OK) {
        fprintf(stderr, "%s: schema decode failed: %d\n", label, (int)rc);
        ASNBER_TEST_CHECK(rc == ASNBER_OK);
    }
    ASNBER_TEST_CHECK(consumed == size);

    root = asnber_doc_root(doc);
    ASNBER_TEST_CHECK(root != NULL);
    ASNBER_TEST_CHECK(asnber_node_tag_class(root) == ASNBER_TAG_UNIVERSAL);
    ASNBER_TEST_CHECK(asnber_node_tag_number(root) == 16u);

    tbs = asnber_node_child_by_name(root, "toBeSigned");
    ASNBER_TEST_CHECK(tbs != NULL);
    ASNBER_TEST_CHECK(asnber_node_tag_number(tbs) == 16u);
    ASNBER_TEST_CHECK(asnber_node_child_count(tbs) >= 7u);

    subject = asnber_node_child_by_name(tbs, "subject");
    issuer = asnber_node_child_by_name(tbs, "issuer");
    validity = asnber_node_child_by_name(tbs, "validity");
    ASNBER_TEST_CHECK(subject != NULL);
    ASNBER_TEST_CHECK(issuer != NULL);
    ASNBER_TEST_CHECK(validity != NULL);
    ASNBER_TEST_CHECK(asnber_node_tag_number(subject) == 16u);
    ASNBER_TEST_CHECK(asnber_node_tag_number(issuer) == 16u);
    ASNBER_TEST_CHECK(asnber_node_tag_number(validity) == 16u);

    not_before = asnber_node_child_by_name(validity, "notBefore");
    not_after = asnber_node_child_by_name(validity, "notAfter");
    ASNBER_TEST_CHECK(not_before != NULL);
    ASNBER_TEST_CHECK(not_after != NULL);
    ASNBER_TEST_CHECK(asnber_node_tag_class(not_before) == ASNBER_TAG_UNIVERSAL);
    ASNBER_TEST_CHECK(asnber_node_tag_class(not_after) == ASNBER_TAG_UNIVERSAL);

    extensions = asnber_node_child_by_name(tbs, "extensions");
    ASNBER_TEST_CHECK(extensions != NULL);
    ASNBER_TEST_CHECK(asnber_node_tag_class(extensions) == ASNBER_TAG_CONTEXT);
    ASNBER_TEST_CHECK(asnber_node_tag_number(extensions) == 3u);
    ASNBER_TEST_CHECK(asnber_node_child_count(extensions) == 1u);
    ext_sequence = asnber_node_child_at(extensions, 0);
    ASNBER_TEST_CHECK(ext_sequence != NULL);
    ASNBER_TEST_CHECK(asnber_node_tag_number(ext_sequence) == 16u);
    ASNBER_TEST_CHECK(asnber_node_child_count(ext_sequence) >= 1u);
    extension = asnber_node_child_at(ext_sequence, 0);
    ASNBER_TEST_CHECK(extension != NULL);
    extn_id = asnber_node_child_by_name(extension, "extnID");
    extn_value = asnber_node_child_by_name(extension, "extnValue");
    ASNBER_TEST_CHECK(extn_id != NULL);
    ASNBER_TEST_CHECK(extn_value != NULL);
    ASNBER_TEST_CHECK(asnber_node_tag_class(extn_id) == ASNBER_TAG_UNIVERSAL);
    ASNBER_TEST_CHECK(asnber_node_tag_number(extn_id) == 6u);
    ASNBER_TEST_CHECK(asnber_node_tag_class(extn_value) == ASNBER_TAG_UNIVERSAL);
    ASNBER_TEST_CHECK(asnber_node_tag_number(extn_value) == 4u);

    asnber_encode_options_init(&encode_options);
    encode_options.schema = schema;
    memset(&encoded, 0, sizeof(encoded));
    rc = asnber_encode_buffer(ctx, doc, &encode_options, &encoded);
    if (rc != ASNBER_OK) {
        fprintf(stderr, "%s: schema encode failed: %d\n", label, (int)rc);
        ASNBER_TEST_CHECK(rc == ASNBER_OK);
    }
    ASNBER_TEST_CHECK(encoded.size == size);
    ASNBER_TEST_CHECK(memcmp(encoded.data, data, size) == 0);
    asnber_buf_release(ctx, &encoded);

    asnber_doc_destroy(doc);
    return 0;
}

static int test_certificates(asnber_ctx_t *ctx, const asnber_schema_t *schema)
{
    ASNBER_TEST_CHECK(check_certificate(ctx, schema, "rsa", kCertRsaSelfsigned,
                                      kCertRsaSelfsignedSize) == 0);
    ASNBER_TEST_CHECK(check_certificate(ctx, schema, "ec", kCertEcSelfsigned,
                                      kCertEcSelfsignedSize) == 0);
    return 0;
}

static int add_type_desc(asnber_schema_t *schema,
                         const asnber_type_desc_t *desc, uint32_t expected_id)
{
    uint32_t type_id = 0;
    ASNBER_TEST_CHECK(asnber_schema_add_type(schema, desc, &type_id) == ASNBER_OK);
    ASNBER_TEST_CHECK(type_id == expected_id);
    return 0;
}

static int add_field_desc(asnber_schema_t *schema, uint32_t parent_type_id,
                          const char *name, uint32_t type_id,
                          uint32_t flags, const uint8_t *default_value,
                          size_t default_size,
                          const asnber_constraint_t *constraints,
                          uint32_t constraint_count)
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
    field.field_constraint_count = constraint_count;
    ASNBER_TEST_CHECK(asnber_schema_add_field(schema, parent_type_id, &field) ==
                    ASNBER_OK);
    return 0;
}

static int add_type_from(asnber_schema_t *schema, const char *name,
                         asnber_type_kind_t kind, uint32_t tag_number,
                         uint32_t element_type_id,
                         const asnber_constraint_t *constraints,
                         uint32_t constraint_count, uint32_t expected_id)
{
    asnber_type_desc_t type;

    memset(&type, 0, sizeof(type));
    type.struct_size = sizeof(type);
    type.name = name;
    type.kind = kind;
    type.tag_class = ASNBER_TAG_UNIVERSAL;
    type.tag_number = tag_number;
    type.tag_mode = ASNBER_TAG_MODE_DEFAULT;
    type.element_type_id = element_type_id;
    type.flags = 0u;
    type.constraints = constraints;
    type.constraint_count = constraint_count;
    return add_type_desc(schema, &type, expected_id);
}

static asnber_constraint_t make_range_constraint(asnber_constraint_kind_t kind)
{
    asnber_constraint_t constraint;

    memset(&constraint, 0, sizeof(constraint));
    constraint.struct_size = sizeof(constraint);
    constraint.kind = kind;
    constraint.lower.struct_size = sizeof(constraint.lower);
    constraint.upper.struct_size = sizeof(constraint.upper);
    constraint.lower.is_unbounded = 1;
    constraint.upper.is_unbounded = 1;
    return constraint;
}

/* 手工构建的等价运行时树（与 equiv_sample.asn1 的 asnberc 确定性输出一致）。 */
static int build_equiv_schema(asnber_ctx_t *ctx, asnber_schema_t **out_schema)
{
    static const uint8_t kBooleanDefault[3] = {0x01, 0x01, 0x00};
    asnber_schema_t *schema = NULL;
    asnber_constraint_t count_constraint;
    asnber_constraint_t kind_constraint;
    asnber_constraint_t any_set_constraint;
    asnber_constraint_t item_set_constraint;
    int64_t enum_values[2];

    ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_IMPLICIT, &schema) ==
                    ASNBER_OK);

    /* 1..4：基本类型。 */
    ASNBER_TEST_CHECK(add_type_from(schema, "Flag", ASNBER_TYPE_KIND_SIMPLE, 1u,
                                  0u, NULL, 0u, 1u) == 0);
    count_constraint = make_range_constraint(ASNBER_CONSTRAINT_MAX);
    count_constraint.lower.is_unbounded = 0;
    count_constraint.lower.value = 0;
    ASNBER_TEST_CHECK(add_type_from(schema, "Count", ASNBER_TYPE_KIND_SIMPLE, 2u,
                                  0u, &count_constraint, 1u, 2u) == 0);
    kind_constraint = make_range_constraint(ASNBER_CONSTRAINT_ENUM);
    kind_constraint.lower.is_unbounded = 0;
    kind_constraint.upper.is_unbounded = 0;
    enum_values[0] = 0;
    enum_values[1] = 1;
    kind_constraint.enum_values = enum_values;
    kind_constraint.enum_count = 2u;
    ASNBER_TEST_CHECK(add_type_from(schema, "Kind", ASNBER_TYPE_KIND_SIMPLE, 10u,
                                  0u, &kind_constraint, 1u, 3u) == 0);
    ASNBER_TEST_CHECK(add_type_from(schema, "Text", ASNBER_TYPE_KIND_SIMPLE, 12u,
                                  0u, NULL, 0u, 4u) == 0);

    /* 5..10：具名复合类型。 */
    ASNBER_TEST_CHECK(add_type_from(schema, "Item", ASNBER_TYPE_KIND_SEQUENCE, 0u,
                                  0u, NULL, 0u, 5u) == 0);
    ASNBER_TEST_CHECK(add_type_from(schema, "Pick", ASNBER_TYPE_KIND_CHOICE, 0u,
                                  0u, NULL, 0u, 6u) == 0);
    any_set_constraint = make_range_constraint(ASNBER_CONSTRAINT_SIZE);
    any_set_constraint.lower.is_unbounded = 0;
    any_set_constraint.lower.value = 1;
    any_set_constraint.upper.is_unbounded = 0;
    any_set_constraint.upper.value = 4;
    ASNBER_TEST_CHECK(add_type_from(schema, "AnySet", ASNBER_TYPE_KIND_SET_OF, 0u,
                                  5u, &any_set_constraint, 1u, 7u) == 0);
    item_set_constraint = make_range_constraint(ASNBER_CONSTRAINT_SIZE);
    item_set_constraint.lower.is_unbounded = 0;
    item_set_constraint.lower.value = 1;
    item_set_constraint.upper.is_unbounded = 0;
    item_set_constraint.upper.value = 10;
    ASNBER_TEST_CHECK(add_type_from(schema, "ItemSet", ASNBER_TYPE_KIND_SET_OF, 0u,
                                  5u, &item_set_constraint, 1u, 8u) == 0);
    ASNBER_TEST_CHECK(add_type_from(schema, "Alias", ASNBER_TYPE_KIND_SEQUENCE, 0u,
                                  0u, NULL, 0u, 9u) == 0);
    ASNBER_TEST_CHECK(add_type_from(schema, "Container",
                                  ASNBER_TYPE_KIND_SEQUENCE, 0u, 0u, NULL, 0u,
                                  10u) == 0);

    /* 11：共享裸 ANY 合成类型。 */
    ASNBER_TEST_CHECK(add_type_from(schema, "$ANY_0", ASNBER_TYPE_KIND_ANY, 0u,
                                  0u, NULL, 0u, 11u) == 0);

    /* Item / Alias / Pick / Container 的字段（所有类型已注册）。 */
    ASNBER_TEST_CHECK(add_field_desc(schema, 5u, "flag", 1u, 0u, kBooleanDefault,
                                   sizeof(kBooleanDefault), NULL, 0u) == 0);
    ASNBER_TEST_CHECK(add_field_desc(schema, 5u, "count", 2u, 0u, NULL, 0u, NULL,
                                   0u) == 0);
    ASNBER_TEST_CHECK(add_field_desc(schema, 5u, "kind", 3u, 0u, NULL, 0u, NULL,
                                   0u) == 0);
    ASNBER_TEST_CHECK(add_field_desc(schema, 5u, "label", 4u,
                                   ASNBER_FIELD_OPTIONAL, NULL, 0u, NULL, 0u) ==
                    0);
    ASNBER_TEST_CHECK(add_field_desc(schema, 5u, "extra", 11u, 0u, NULL, 0u, NULL,
                                   0u) == 0);

    ASNBER_TEST_CHECK(add_field_desc(schema, 6u, "item", 5u, 0u, NULL, 0u, NULL,
                                   0u) == 0);
    ASNBER_TEST_CHECK(add_field_desc(schema, 6u, "text", 4u, 0u, NULL, 0u, NULL,
                                   0u) == 0);

    ASNBER_TEST_CHECK(add_field_desc(schema, 9u, "flag", 1u, 0u, kBooleanDefault,
                                   sizeof(kBooleanDefault), NULL, 0u) == 0);
    ASNBER_TEST_CHECK(add_field_desc(schema, 9u, "count", 2u, 0u, NULL, 0u, NULL,
                                   0u) == 0);
    ASNBER_TEST_CHECK(add_field_desc(schema, 9u, "kind", 3u, 0u, NULL, 0u, NULL,
                                   0u) == 0);
    ASNBER_TEST_CHECK(add_field_desc(schema, 9u, "label", 4u,
                                   ASNBER_FIELD_OPTIONAL, NULL, 0u, NULL, 0u) ==
                    0);
    ASNBER_TEST_CHECK(add_field_desc(schema, 9u, "extra", 11u, 0u, NULL, 0u, NULL,
                                   0u) == 0);

    ASNBER_TEST_CHECK(add_field_desc(schema, 10u, "pick", 6u, 0u, NULL, 0u, NULL,
                                   0u) == 0);
    ASNBER_TEST_CHECK(add_field_desc(schema, 10u, "anySet", 7u, 0u, NULL, 0u,
                                   NULL, 0u) == 0);
    ASNBER_TEST_CHECK(add_field_desc(schema, 10u, "itemSet", 8u, 0u, NULL, 0u,
                                   NULL, 0u) == 0);

    ASNBER_TEST_CHECK(asnber_schema_set_root(schema, 10u) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);

    *out_schema = schema;
    return 0;
}

static int test_equivalence(asnber_ctx_t *ctx)
{
    size_t size = 0;
    uint8_t *data = read_file(ASNBERC_EQUIV_BIN, &size);
    asnber_schema_t *loaded = NULL;
    asnber_schema_t *manual = NULL;

    ASNBER_TEST_CHECK(data != NULL);
    ASNBER_TEST_CHECK(load_schema(ctx, data, size, &loaded) == 0);
    ASNBER_TEST_CHECK(asnber_test_schema_type_count(loaded) == 11u);
    ASNBER_TEST_CHECK(asnber_test_schema_root_type_id(loaded) == 10u);

    ASNBER_TEST_CHECK(build_equiv_schema(ctx, &manual) == 0);
    ASNBER_TEST_CHECK(asnber_test_compare_schemas(loaded, manual) == 0);

    asnber_schema_destroy(manual);
    asnber_schema_destroy(loaded);
    free(data);
    return 0;
}

int main(void)
{
    asnber_ctx_config_t config;
    asnber_ctx_t *ctx = NULL;
    size_t size = 0;
    uint8_t *data;
    asnber_schema_t *schema = NULL;

    ASNBER_TEST_CHECK(test_bin_header() == 0);

    asnber_ctx_config_init(&config);
    ASNBER_TEST_CHECK(asnber_ctx_create(&config, &ctx) == ASNBER_OK);

    data = read_file(ASNBERC_PKIX_BIN, &size);
    ASNBER_TEST_CHECK(data != NULL);
    ASNBER_TEST_CHECK(load_schema(ctx, data, size, &schema) == 0);

    ASNBER_TEST_CHECK(test_table_shape(schema) == 0);
    ASNBER_TEST_CHECK(test_names(schema) == 0);
    ASNBER_TEST_CHECK(test_any_fields(schema) == 0);
    ASNBER_TEST_CHECK(test_structure_and_defaults(schema) == 0);
    ASNBER_TEST_CHECK(test_certificates(ctx, schema) == 0);
    ASNBER_TEST_CHECK(test_equivalence(ctx) == 0);

    asnber_schema_destroy(schema);
    asnber_ctx_destroy(ctx);
    free(data);
    return 0;
}
