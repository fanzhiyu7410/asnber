/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * 共享构造层 X.509 编码原语：Name/RDN、UTCTime/GeneralizedTime 选择、
 * BIT STRING 未用位。
 *
 * Name 期望字节来自 OpenSSL 3.5.9 实测（openssl req -subj ... 后
 * openssl asn1parse），用于把字符串类型选择与 SET OF 排序规则钉死。
 */

#include <asnber/asnber.h>

#include "detail/x509_primitives.h"

#include <cstdint>
#include <cstring>

#include "check.h"

using asnber::module_detail::createBitStringNode;
using asnber::module_detail::createNameNode;
using asnber::module_detail::createTimeNode;
using asnber::module_detail::name_attribute;
using asnber::module_detail::name_rdn;

static asnber_ctx_t *make_ctx(void)
{
    asnber_ctx_config_t config;
    asnber_ctx_config_init(&config);
    asnber_ctx_t *ctx = nullptr;
    if (asnber_ctx_create(&config, &ctx) != ASNBER_OK) {
        return nullptr;
    }
    return ctx;
}

static bool bytes_match(const uint8_t *actual, size_t actual_size,
                        const void *expected, size_t expected_size)
{
    return actual_size == expected_size &&
           (actual_size == 0 || std::memcmp(actual, expected, actual_size) == 0);
}

static name_attribute make_attr(const char *oid, const char *text,
                                uint32_t string_tag = 0)
{
    name_attribute attribute;
    attribute.oid = oid;
    attribute.value = reinterpret_cast<const uint8_t *>(text);
    attribute.value_size = std::strlen(text);
    attribute.string_tag = string_tag;
    return attribute;
}

/* 通用 DER 编码（无 schema）：用于直接观察构树产出的规范字节。 */
static asnber_err_t encode_root(asnber_ctx_t *ctx, asnber_doc_t *doc,
                              asnber_buf_t *buf)
{
    asnber_encode_options_t options;
    asnber_encode_options_init(&options);
    return asnber_encode_buffer(ctx, doc, &options, buf);
}

static asnber_err_t decode_root(asnber_ctx_t *ctx, const uint8_t *der, size_t size,
                              asnber_doc_t **doc)
{
    asnber_decode_options_t options;
    asnber_decode_options_init(&options);
    options.encoding = ASNBER_ENCODING_DER;
    size_t consumed = 0;
    asnber_err_t rc = asnber_decode_buffer(ctx, der, size, &options, doc, &consumed);
    if (rc == ASNBER_OK && consumed != size) {
        asnber_doc_destroy(*doc);
        *doc = nullptr;
        return ASNBER_E_TRAILING_DATA;
    }
    return rc;
}

/* 把单个 Name 编码成独立文档，返回编码结果。 */
static int encode_name(asnber_ctx_t *ctx, const name_rdn *rdns, size_t count,
                       asnber_buf_t *out)
{
    asnber_doc_t *doc = nullptr;
    asnber_node_t *name = nullptr;
    if (asnber_doc_create(ctx, &doc) != ASNBER_OK) {
        return 1;
    }
    asnber_err_t rc = createNameNode(doc, nullptr, rdns, count, &name);
    if (rc == ASNBER_OK) {
        rc = asnber_doc_seal(doc);
    }
    if (rc == ASNBER_OK) {
        rc = encode_root(ctx, doc, out);
    }
    asnber_doc_destroy(doc);
    return rc == ASNBER_OK ? 0 : 1;
}

/* OpenSSL CSR subject：C/ST/L/O/OU/CN/emailAddress/serialNumber/DC。 */
static const uint8_t kOpensslName[] = {
    0x30, 0x81, 0xAA, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06,
    0x13, 0x02, 0x43, 0x4E, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04,
    0x08, 0x0C, 0x07, 0x42, 0x65, 0x69, 0x6A, 0x69, 0x6E, 0x67, 0x31, 0x10,
    0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0C, 0x07, 0x48, 0x61, 0x69,
    0x64, 0x69, 0x61, 0x6E, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04,
    0x0A, 0x0C, 0x0C, 0x45, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x20, 0x43,
    0x6F, 0x72, 0x70, 0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04, 0x0B,
    0x0C, 0x04, 0x54, 0x65, 0x73, 0x74, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x0C, 0x0B, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65,
    0x2E, 0x63, 0x6F, 0x6D, 0x31, 0x16, 0x30, 0x14, 0x06, 0x09, 0x2A, 0x86,
    0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01, 0x16, 0x07, 0x61, 0x40, 0x62,
    0x2E, 0x63, 0x6F, 0x6D, 0x31, 0x0E, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x04,
    0x05, 0x13, 0x05, 0x31, 0x32, 0x33, 0x34, 0x35, 0x31, 0x13, 0x30, 0x11,
    0x06, 0x0A, 0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x19,
    0x16, 0x03, 0x63, 0x6F, 0x6D};

/* OpenSSL /O=a+CN=b：SET OF 排序后 CN（2.5.4.3）在前，O（2.5.4.10）在后。 */
static const uint8_t kOpensslMultiRdn[] = {
    0x30, 0x16, 0x31, 0x14, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C,
    0x01, 0x62, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x01, 0x61};

static int test_name_openssl_fixture(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_buf_t encoded;
    name_attribute attributes[9];
    name_rdn rdns[9];

    std::memset(&encoded, 0, sizeof(encoded));
    ASNBER_TEST_CHECK(ctx != nullptr);

    attributes[0] = make_attr("2.5.4.6", "CN");
    attributes[1] = make_attr("2.5.4.8", "Beijing");
    attributes[2] = make_attr("2.5.4.7", "Haidian");
    attributes[3] = make_attr("2.5.4.10", "Example Corp");
    attributes[4] = make_attr("2.5.4.11", "Test");
    attributes[5] = make_attr("2.5.4.3", "example.com");
    attributes[6] = make_attr("1.2.840.113549.1.9.1", "a@b.com");
    attributes[7] = make_attr("2.5.4.5", "12345");
    attributes[8] = make_attr("0.9.2342.19200300.100.1.25", "com");
    for (size_t i = 0; i < 9; ++i) {
        rdns[i].attributes = &attributes[i];
        rdns[i].count = 1;
    }

    ASNBER_TEST_CHECK(encode_name(ctx, rdns, 9, &encoded) == 0);
    ASNBER_TEST_CHECK(bytes_match(encoded.data, encoded.size, kOpensslName,
                                sizeof(kOpensslName)));
    asnber_buf_release(ctx, &encoded);
    asnber_ctx_destroy(ctx);
    return 0;
}

static int test_name_multi_rdn_sorting(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_buf_t encoded;
    name_attribute attributes[2];
    name_rdn rdn;

    std::memset(&encoded, 0, sizeof(encoded));
    ASNBER_TEST_CHECK(ctx != nullptr);

    /* 输入顺序与 DER 顺序相反，验证排序仍由核心 DER 编码完成。 */
    attributes[0] = make_attr("2.5.4.10", "a");
    attributes[1] = make_attr("2.5.4.3", "b");
    rdn.attributes = attributes;
    rdn.count = 2;

    ASNBER_TEST_CHECK(encode_name(ctx, &rdn, 1, &encoded) == 0);
    ASNBER_TEST_CHECK(bytes_match(encoded.data, encoded.size, kOpensslMultiRdn,
                                sizeof(kOpensslMultiRdn)));
    asnber_buf_release(ctx, &encoded);
    asnber_ctx_destroy(ctx);
    return 0;
}

static int test_name_empty(void)
{
    static const uint8_t kEmptyName[] = {0x30, 0x00};
    asnber_ctx_t *ctx = make_ctx();
    asnber_buf_t encoded;

    std::memset(&encoded, 0, sizeof(encoded));
    ASNBER_TEST_CHECK(ctx != nullptr);
    ASNBER_TEST_CHECK(encode_name(ctx, nullptr, 0, &encoded) == 0);
    ASNBER_TEST_CHECK(bytes_match(encoded.data, encoded.size, kEmptyName,
                                sizeof(kEmptyName)));
    asnber_buf_release(ctx, &encoded);
    asnber_ctx_destroy(ctx);
    return 0;
}

static int test_name_string_tags(void)
{
    /* C=CN -> PrintableString 19。 */
    static const uint8_t kCountry[] = {
        0x30, 0x0D, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03,
        0x55, 0x04, 0x06, 0x13, 0x02, 0x43, 0x4E};
    /* CN=ab -> UTF8String 12。 */
    static const uint8_t kCommonName[] = {
        0x30, 0x0D, 0x31, 0x0B, 0x30, 0x09, 0x06,
        0x03, 0x55, 0x04, 0x03, 0x0C, 0x02, 0x61, 0x62};
    /* DC=com -> IA5String 22。 */
    static const uint8_t kDomainComponent[] = {
        0x30, 0x15, 0x31, 0x13, 0x30, 0x11, 0x06, 0x0A, 0x09, 0x92,
        0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x19, 0x16, 0x03,
        0x63, 0x6F, 0x6D};
    /* dnQualifier=DQ -> PrintableString 19。 */
    static const uint8_t kDnQualifier[] = {
        0x30, 0x0D, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03,
        0x55, 0x04, 0x2E, 0x13, 0x02, 0x44, 0x51};
    /* CN=ab + 显式 19 -> 覆盖默认的 UTF8String。 */
    static const uint8_t kCommonNamePrintable[] = {
        0x30, 0x0D, 0x31, 0x0B, 0x30, 0x09, 0x06,
        0x03, 0x55, 0x04, 0x03, 0x13, 0x02, 0x61, 0x62};
    asnber_ctx_t *ctx = make_ctx();
    asnber_buf_t encoded;
    name_attribute attribute;
    name_rdn rdn;

    std::memset(&encoded, 0, sizeof(encoded));
    ASNBER_TEST_CHECK(ctx != nullptr);
    rdn.attributes = &attribute;
    rdn.count = 1;

    attribute = make_attr("2.5.4.6", "CN");
    ASNBER_TEST_CHECK(encode_name(ctx, &rdn, 1, &encoded) == 0);
    ASNBER_TEST_CHECK(bytes_match(encoded.data, encoded.size, kCountry,
                                sizeof(kCountry)));
    asnber_buf_release(ctx, &encoded);

    attribute = make_attr("2.5.4.3", "ab");
    ASNBER_TEST_CHECK(encode_name(ctx, &rdn, 1, &encoded) == 0);
    ASNBER_TEST_CHECK(bytes_match(encoded.data, encoded.size, kCommonName,
                                sizeof(kCommonName)));
    asnber_buf_release(ctx, &encoded);

    attribute = make_attr("0.9.2342.19200300.100.1.25", "com");
    ASNBER_TEST_CHECK(encode_name(ctx, &rdn, 1, &encoded) == 0);
    ASNBER_TEST_CHECK(bytes_match(encoded.data, encoded.size, kDomainComponent,
                                sizeof(kDomainComponent)));
    asnber_buf_release(ctx, &encoded);

    attribute = make_attr("2.5.4.46", "DQ");
    ASNBER_TEST_CHECK(encode_name(ctx, &rdn, 1, &encoded) == 0);
    ASNBER_TEST_CHECK(bytes_match(encoded.data, encoded.size, kDnQualifier,
                                sizeof(kDnQualifier)));
    asnber_buf_release(ctx, &encoded);

    attribute = make_attr("2.5.4.3", "ab", 19);
    ASNBER_TEST_CHECK(encode_name(ctx, &rdn, 1, &encoded) == 0);
    ASNBER_TEST_CHECK(bytes_match(encoded.data, encoded.size,
                                kCommonNamePrintable,
                                sizeof(kCommonNamePrintable)));
    asnber_buf_release(ctx, &encoded);

    asnber_ctx_destroy(ctx);
    return 0;
}

/* 每次失败都会在文档里留下部分树，因此每个负例使用独立文档。 */
static asnber_err_t name_error(asnber_ctx_t *ctx, const name_rdn *rdns,
                            size_t count)
{
    asnber_doc_t *doc = nullptr;
    asnber_node_t *name = nullptr;
    if (asnber_doc_create(ctx, &doc) != ASNBER_OK) {
        return ASNBER_E_NOMEM;
    }
    asnber_err_t rc = createNameNode(doc, nullptr, rdns, count, &name);
    asnber_doc_destroy(doc);
    return rc;
}

static int test_name_negative(void)
{
    asnber_ctx_t *ctx = make_ctx();
    name_attribute attribute;
    name_rdn rdn;

    ASNBER_TEST_CHECK(ctx != nullptr);
    rdn.attributes = &attribute;
    rdn.count = 1;

    /* C 的非 PrintableString 字符。 */
    attribute = make_attr("2.5.4.6", "\xE4\xB8\xAD");
    ASNBER_TEST_CHECK(name_error(ctx, &rdn, 1) == ASNBER_E_INVALID_VALUE);
    /* DC 的非 IA5 字符。 */
    attribute = make_attr("0.9.2342.19200300.100.1.25", "caf\xC3\xA9");
    ASNBER_TEST_CHECK(name_error(ctx, &rdn, 1) == ASNBER_E_INVALID_VALUE);
    /* 空值与空 OID。 */
    attribute = make_attr("2.5.4.3", "");
    ASNBER_TEST_CHECK(name_error(ctx, &rdn, 1) == ASNBER_E_INVALID_VALUE);
    attribute = make_attr(nullptr, "x");
    ASNBER_TEST_CHECK(name_error(ctx, &rdn, 1) == ASNBER_E_INVALID_ARG);
    /* 显式标签不在 12/19/22 内。 */
    attribute = make_attr("2.5.4.3", "x", 16);
    ASNBER_TEST_CHECK(name_error(ctx, &rdn, 1) == ASNBER_E_INVALID_ARG);

    /* 指针/计数组合非法。 */
    ASNBER_TEST_CHECK(name_error(ctx, nullptr, 1) == ASNBER_E_INVALID_ARG);
    rdn.attributes = nullptr;
    rdn.count = 0;
    ASNBER_TEST_CHECK(name_error(ctx, &rdn, 1) == ASNBER_E_INVALID_ARG);

    asnber_ctx_destroy(ctx);
    return 0;
}

static int setup_time(asnber_time_t *time, int32_t year, uint8_t month,
                      uint8_t day, uint8_t hour, uint8_t minute,
                      uint8_t second)
{
    std::memset(time, 0, sizeof(*time));
    time->struct_size = sizeof(asnber_time_t);
    time->year = year;
    time->month = month;
    time->day = day;
    time->hour = hour;
    time->minute = minute;
    time->second = second;
    return 0;
}

static int encode_time(asnber_ctx_t *ctx, const asnber_time_t *time,
                       asnber_buf_t *out)
{
    asnber_doc_t *doc = nullptr;
    asnber_node_t *node = nullptr;
    if (asnber_doc_create(ctx, &doc) != ASNBER_OK) {
        return 1;
    }
    asnber_err_t rc = createTimeNode(doc, nullptr, time, &node);
    if (rc == ASNBER_OK) {
        rc = asnber_doc_seal(doc);
    }
    if (rc == ASNBER_OK) {
        rc = encode_root(ctx, doc, out);
    }
    asnber_doc_destroy(doc);
    return rc == ASNBER_OK ? 0 : 1;
}

/* 编码后再解码，读回时间六元组与来源标志。 */
static int expect_time(asnber_ctx_t *ctx, const asnber_time_t *time,
                       const char *text, size_t text_size, uint32_t flag)
{
    asnber_buf_t encoded;
    asnber_doc_t *doc = nullptr;
    asnber_time_t got;

    std::memset(&encoded, 0, sizeof(encoded));
    ASNBER_TEST_CHECK(encode_time(ctx, time, &encoded) == 0);
    ASNBER_TEST_CHECK(encoded.size == text_size + 2);
    ASNBER_TEST_CHECK(encoded.data[0] ==
                    (flag == ASNBER_TIME_UTC ? 0x17 : 0x18));
    ASNBER_TEST_CHECK(encoded.data[1] == static_cast<uint8_t>(text_size));
    ASNBER_TEST_CHECK(std::memcmp(encoded.data + 2, text, text_size) == 0);
    ASNBER_TEST_CHECK(decode_root(ctx, encoded.data, encoded.size, &doc) ==
                    ASNBER_OK);
    std::memset(&got, 0, sizeof(got));
    got.struct_size = sizeof(asnber_time_t);
    ASNBER_TEST_CHECK(asnber_node_get_time(asnber_doc_root(doc), &got) == ASNBER_OK);
    ASNBER_TEST_CHECK(got.struct_size == sizeof(asnber_time_t));
    ASNBER_TEST_CHECK(got.year == time->year && got.month == time->month &&
                    got.day == time->day && got.hour == time->hour &&
                    got.minute == time->minute && got.second == time->second);
    ASNBER_TEST_CHECK((got.flags & ASNBER_TIME_UTC) != 0 ||
                    (got.flags & ASNBER_TIME_GENERALIZED) != 0);
    ASNBER_TEST_CHECK((got.flags & flag) != 0);
    asnber_doc_destroy(doc);
    asnber_buf_release(ctx, &encoded);
    return 0;
}

static int test_time_selection(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_time_t time;

    ASNBER_TEST_CHECK(ctx != nullptr);

    setup_time(&time, 2026, 11, 10, 12, 34, 56);
    ASNBER_TEST_CHECK(expect_time(ctx, &time, "261110123456Z", 13,
                                ASNBER_TIME_UTC) == 0);

    setup_time(&time, 2049, 12, 31, 23, 59, 59);
    ASNBER_TEST_CHECK(expect_time(ctx, &time, "491231235959Z", 13,
                                ASNBER_TIME_UTC) == 0);

    setup_time(&time, 2050, 1, 1, 0, 0, 0);
    ASNBER_TEST_CHECK(expect_time(ctx, &time, "20500101000000Z", 15,
                                ASNBER_TIME_GENERALIZED) == 0);

    setup_time(&time, 1949, 12, 31, 0, 0, 0);
    ASNBER_TEST_CHECK(expect_time(ctx, &time, "19491231000000Z", 15,
                                ASNBER_TIME_GENERALIZED) == 0);

    /* 2000 年是闰年。 */
    setup_time(&time, 2000, 2, 29, 1, 2, 3);
    ASNBER_TEST_CHECK(expect_time(ctx, &time, "000229010203Z", 13,
                                ASNBER_TIME_UTC) == 0);

    asnber_ctx_destroy(ctx);
    return 0;
}

static int test_time_negative(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_doc_t *doc = nullptr;
    asnber_time_t time;
    asnber_node_t *node = nullptr;

    ASNBER_TEST_CHECK(ctx != nullptr);

    ASNBER_TEST_CHECK(asnber_doc_create(ctx, &doc) == ASNBER_OK);
    setup_time(&time, 2026, 11, 10, 12, 34, 56);
    time.struct_size = 0;
    ASNBER_TEST_CHECK(createTimeNode(doc, nullptr, &time, &node) ==
                    ASNBER_E_INVALID_ARG);
    setup_time(&time, 2026, 11, 10, 12, 34, 56);
    time.reserved_flags = 1;
    ASNBER_TEST_CHECK(createTimeNode(doc, nullptr, &time, &node) ==
                    ASNBER_E_INVALID_ARG);
    setup_time(&time, 2026, 11, 10, 12, 34, 56);
    time.flags = ASNBER_TIME_HAS_OFFSET;
    ASNBER_TEST_CHECK(createTimeNode(doc, nullptr, &time, &node) ==
                    ASNBER_E_INVALID_VALUE);
    setup_time(&time, 2026, 11, 10, 12, 34, 56);
    time.flags = ASNBER_TIME_FRACTIONAL;
    ASNBER_TEST_CHECK(createTimeNode(doc, nullptr, &time, &node) ==
                    ASNBER_E_INVALID_VALUE);
    setup_time(&time, 2026, 13, 1, 0, 0, 0);
    ASNBER_TEST_CHECK(createTimeNode(doc, nullptr, &time, &node) ==
                    ASNBER_E_INVALID_VALUE);
    setup_time(&time, 2026, 2, 29, 0, 0, 0);
    ASNBER_TEST_CHECK(createTimeNode(doc, nullptr, &time, &node) ==
                    ASNBER_E_INVALID_VALUE);
    setup_time(&time, 10000, 1, 1, 0, 0, 0);
    ASNBER_TEST_CHECK(createTimeNode(doc, nullptr, &time, &node) ==
                    ASNBER_E_INVALID_VALUE);
    setup_time(&time, 2026, 1, 1, 24, 0, 0);
    ASNBER_TEST_CHECK(createTimeNode(doc, nullptr, &time, &node) ==
                    ASNBER_E_INVALID_VALUE);
    asnber_doc_destroy(doc);

    asnber_ctx_destroy(ctx);
    return 0;
}

static int encode_bits(asnber_ctx_t *ctx, const uint8_t *bits, size_t size,
                       uint8_t unused_bits, asnber_buf_t *out)
{
    asnber_doc_t *doc = nullptr;
    asnber_node_t *node = nullptr;
    if (asnber_doc_create(ctx, &doc) != ASNBER_OK) {
        return 1;
    }
    asnber_err_t rc = createBitStringNode(doc, nullptr, bits, size, unused_bits,
                                        &node);
    if (rc == ASNBER_OK) {
        rc = asnber_doc_seal(doc);
    }
    if (rc == ASNBER_OK) {
        rc = encode_root(ctx, doc, out);
    }
    asnber_doc_destroy(doc);
    return rc == ASNBER_OK ? 0 : 1;
}

static int test_bit_string(void)
{
    static const uint8_t kBits[] = {0xDE, 0xAD, 0xA0};
    static const uint8_t kExpected[] = {0x03, 0x04, 0x04, 0xDE, 0xAD, 0xA0};
    static const uint8_t kEmptyExpected[] = {0x03, 0x01, 0x00};
    asnber_ctx_t *ctx = make_ctx();
    asnber_buf_t encoded;
    asnber_doc_t *doc = nullptr;
    const uint8_t *data = nullptr;
    size_t size = 0;
    size_t bit_length = 0;
    uint8_t unused = 0;

    std::memset(&encoded, 0, sizeof(encoded));
    ASNBER_TEST_CHECK(ctx != nullptr);

    ASNBER_TEST_CHECK(encode_bits(ctx, kBits, sizeof(kBits), 4, &encoded) == 0);
    ASNBER_TEST_CHECK(bytes_match(encoded.data, encoded.size, kExpected,
                                sizeof(kExpected)));
    ASNBER_TEST_CHECK(decode_root(ctx, encoded.data, encoded.size, &doc) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_node_get_bits(asnber_doc_root(doc), &data, &size,
                                       &bit_length, &unused) == ASNBER_OK);
    ASNBER_TEST_CHECK(size == 3 && data != nullptr);
    ASNBER_TEST_CHECK(unused == 4 && bit_length == 20);
    ASNBER_TEST_CHECK(std::memcmp(data, kBits, sizeof(kBits)) == 0);
    asnber_doc_destroy(doc);
    asnber_buf_release(ctx, &encoded);

    ASNBER_TEST_CHECK(encode_bits(ctx, nullptr, 0, 0, &encoded) == 0);
    ASNBER_TEST_CHECK(bytes_match(encoded.data, encoded.size, kEmptyExpected,
                                sizeof(kEmptyExpected)));
    ASNBER_TEST_CHECK(decode_root(ctx, encoded.data, encoded.size, &doc) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_node_get_bits(asnber_doc_root(doc), &data, &size,
                                       &bit_length, &unused) == ASNBER_OK);
    ASNBER_TEST_CHECK(data == nullptr && size == 0 && bit_length == 0 &&
                    unused == 0);
    asnber_doc_destroy(doc);
    asnber_buf_release(ctx, &encoded);

    /* 负例：未用位数越界、空输入带未用位、填充位非零。 */
    ASNBER_TEST_CHECK(encode_bits(ctx, kBits, sizeof(kBits), 8, &encoded) != 0);
    ASNBER_TEST_CHECK(encode_bits(ctx, nullptr, 0, 3, &encoded) != 0);
    {
        static const uint8_t kBadFill[] = {0xA1};
        ASNBER_TEST_CHECK(encode_bits(ctx, kBadFill, sizeof(kBadFill), 4,
                                    &encoded) != 0);
    }

    asnber_ctx_destroy(ctx);
    return 0;
}

int main(void)
{
    if (test_name_openssl_fixture() != 0) {
        return 1;
    }
    if (test_name_multi_rdn_sorting() != 0) {
        return 1;
    }
    if (test_name_empty() != 0) {
        return 1;
    }
    if (test_name_string_tags() != 0) {
        return 1;
    }
    if (test_name_negative() != 0) {
        return 1;
    }
    if (test_time_selection() != 0) {
        return 1;
    }
    if (test_time_negative() != 0) {
        return 1;
    }
    if (test_bit_string() != 0) {
        return 1;
    }
    return 0;
}
