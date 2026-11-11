/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * asnber-pkix Certificate builder：OpenSSL 夹具全字节对拍、便捷扩展、
 * v1 缺省、唯一标识与负例。夹具为 tests/data/cert_rsa_selfsigned.der。
 */

#include <asnber/asnber.h>
#include <asnber/pkix/pkix.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "../data/cert_rsa_selfsigned.h"
#include "check.h"
#include "test_compare.h"

/* ---------- 夹具常量 ---------- */

static const uint8_t kSerialMagnitude[] = {
    0x72, 0x12, 0xAF, 0x38, 0x15, 0x28, 0xA1, 0x36, 0x6D, 0x0B,
    0xFC, 0x55, 0x0F, 0xBA, 0x9B, 0x5D, 0x7E, 0x90, 0xF6, 0x35,
};

static const uint8_t kNullParameters[] = {0x05, 0x00};

static const uint8_t kSanExtnValue[] = {
    0x30, 0x12, 0x82, 0x10, 0x61, 0x73, 0x6E, 0x31, 0x2D,
    0x72, 0x73, 0x61, 0x2E, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65,
};

static const uint8_t kSkiExtnValue[] = {
    0x04, 0x14, 0xA8, 0x4A, 0xEF, 0xD4, 0x3E, 0x3A, 0x5A, 0x12, 0x4F,
    0x28, 0xFA, 0x95, 0x0E, 0xC3, 0x7B, 0xFB, 0x0F, 0xDC, 0xA6, 0xD4,
};

static const asnber_pkix_name_attribute_t kNameAttributes[] = {
    {"2.5.4.6", (const uint8_t *)"CN", 2, 0},
    {"2.5.4.10", (const uint8_t *)"ASN1 Test", 9, 0},
    {"2.5.4.3", (const uint8_t *)"ASN1 RSA Self Signed", 20, 0},
};

static const asnber_pkix_name_rdn_t kNameRdns[] = {
    {&kNameAttributes[0], 1},
    {&kNameAttributes[1], 1},
    {&kNameAttributes[2], 1},
};

/* ---------- 辅助 ---------- */

static asnber_ctx_t *make_ctx(void)
{
    asnber_ctx_config_t config;
    asnber_ctx_config_init(&config);
    asnber_ctx_t *ctx = NULL;
    if (asnber_ctx_create(&config, &ctx) != ASNBER_OK) {
        return NULL;
    }
    return ctx;
}

static void make_time(asnber_time_t *time, int32_t year, uint8_t month,
                      uint8_t day, uint8_t hour, uint8_t minute,
                      uint8_t second)
{
    memset(time, 0, sizeof(*time));
    time->struct_size = sizeof(*time);
    time->year = year;
    time->month = month;
    time->day = day;
    time->hour = hour;
    time->minute = minute;
    time->second = second;
}

/* 从夹具读回 SPKI 公钥位串与签名值，避免在测试里内嵌 500+ 字节。 */
static int load_fixture_bits(asnber_ctx_t *ctx, uint8_t **spki, size_t *spki_size,
                             uint8_t **signature, size_t *signature_size)
{
    asnber_pkix_certificate_t *cert = NULL;
    const asnber_node_t *node = NULL;
    const uint8_t *data = NULL;
    size_t size = 0;
    size_t bit_length = 0;
    uint8_t unused = 0;

    *spki = NULL;
    *signature = NULL;
    ASNBER_TEST_CHECK(asnber_pkix_certificate_open(
                        ctx, kCertRsaSelfsigned, kCertRsaSelfsignedSize,
                        &cert) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_find(
                        cert, "tbsCertificate.subjectPublicKeyInfo.subjectPublicKey",
                        &node) == ASNBER_OK);
    ASNBER_TEST_CHECK(node != NULL);
    ASNBER_TEST_CHECK(asnber_node_get_bits(node, &data, &size, &bit_length,
                                       &unused) == ASNBER_OK);
    ASNBER_TEST_CHECK(unused == 0 && size != 0);
    *spki = (uint8_t *)malloc(size);
    ASNBER_TEST_CHECK(*spki != NULL);
    memcpy(*spki, data, size);
    *spki_size = size;

    ASNBER_TEST_CHECK(asnber_pkix_certificate_signature_value(
                        cert, &data, &size, &bit_length, &unused) == ASNBER_OK);
    ASNBER_TEST_CHECK(unused == 0 && size != 0);
    *signature = (uint8_t *)malloc(size);
    ASNBER_TEST_CHECK(*signature != NULL);
    memcpy(*signature, data, size);
    *signature_size = size;

    asnber_pkix_certificate_close(cert);
    return 0;
}

/* 设置与夹具一致的除签名值与扩展外的全部字段。 */
static int setup_base(asnber_ctx_t *ctx,
                      asnber_pkix_certificate_builder_t *builder,
                      const uint8_t *spki, size_t spki_size)
{
    asnber_time_t not_before;
    asnber_time_t not_after;

    make_time(&not_before, 2026, 11, 4, 6, 40, 49);
    make_time(&not_after, 2036, 11, 1, 6, 40, 49);

    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_set_version(builder, 2) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_set_serial_number(
                        builder, kSerialMagnitude,
                        sizeof(kSerialMagnitude)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_set_signature_algorithm(
                        builder, "1.2.840.113549.1.1.11", kNullParameters,
                        sizeof(kNullParameters)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_set_issuer(
                        builder, kNameRdns, 3) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_set_validity(
                        builder, &not_before, &not_after) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_set_subject(
                        builder, kNameRdns, 3) == ASNBER_OK);
    ASNBER_TEST_CHECK(
        asnber_pkix_certificate_builder_set_subject_public_key_algorithm(
            builder, "1.2.840.113549.1.1.1", kNullParameters,
            sizeof(kNullParameters)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_set_subject_public_key(
                        builder, spki, spki_size, 0) == ASNBER_OK);
    (void)ctx;
    return 0;
}

/* 在 Extensions 中按 OID 找 Extension；extensions 允许是 [3] 外层包装。 */
static const asnber_node_t *find_extension(const asnber_node_t *extensions,
                                         const char *oid)
{
    size_t count = 0;
    size_t i;

    if (extensions == NULL) {
        return NULL;
    }
    if (asnber_node_tag_class(extensions) == ASNBER_TAG_CONTEXT &&
        asnber_node_child_count(extensions) == 1) {
        extensions = asnber_node_child_at(extensions, 0);
    }
    count = asnber_node_child_count(extensions);
    for (i = 0; i < count; ++i) {
        const asnber_node_t *extension = asnber_node_child_at(extensions, i);
        const asnber_node_t *type = asnber_node_child_at(extension, 0);
        const char *dotted = NULL;
        size_t size = 0;
        if (type == NULL ||
            asnber_node_get_oid(type, &dotted, &size) != ASNBER_OK) {
            continue;
        }
        if (size == strlen(oid) && memcmp(dotted, oid, size) == 0) {
            return extension;
        }
    }
    return NULL;
}

static int extension_value_equals(const asnber_node_t *extension,
                                  const uint8_t *expected, size_t expected_size)
{
    const asnber_node_t *value = NULL;
    const uint8_t *content = NULL;
    size_t size = 0;
    size_t count = asnber_node_child_count(extension);

    ASNBER_TEST_CHECK(count >= 2);
    value = asnber_node_child_at(extension, count - 1);
    ASNBER_TEST_CHECK(asnber_node_tag_number(value) == 4);
    ASNBER_TEST_CHECK(asnber_node_content(value, &content, &size) == ASNBER_OK);
    return bytes_equal(content, size, expected, expected_size);
}

/* ---------- 正例：与 OpenSSL 证书逐字节一致 ---------- */

static int test_openssl_certificate(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_pkix_certificate_builder_t *builder = NULL;
    asnber_buf_t encoded;
    uint8_t *spki = NULL;
    uint8_t *signature = NULL;
    size_t spki_size = 0;
    size_t signature_size = 0;

    ASNBER_TEST_CHECK(ctx != NULL);
    memset(&encoded, 0, sizeof(encoded));
    ASNBER_TEST_CHECK(load_fixture_bits(ctx, &spki, &spki_size, &signature,
                                      &signature_size) == 0);

    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_create(ctx, &builder) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(setup_base(ctx, builder, spki, spki_size) == 0);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_add_basic_constraints(
                        builder, 1, 1, 0, 0) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_add_extension(
                        builder, "2.5.29.17", 0, kSanExtnValue,
                        sizeof(kSanExtnValue)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_add_extension(
                        builder, "2.5.29.14", 0, kSkiExtnValue,
                        sizeof(kSkiExtnValue)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_set_signature_value(
                        builder, signature, signature_size, 0) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_encode(builder, &encoded) ==
                    ASNBER_OK);

    ASNBER_TEST_CHECK(encoded.size == kCertRsaSelfsignedSize);
    ASNBER_TEST_CHECK(bytes_equal(encoded.data, encoded.size,
                                kCertRsaSelfsigned,
                                kCertRsaSelfsignedSize));

    asnber_buf_release(ctx, &encoded);
    asnber_pkix_certificate_builder_destroy(builder);
    free(spki);
    free(signature);
    asnber_ctx_destroy(ctx);
    return 0;
}

/* ---------- v1 缺省：不设置 version 时完全省略 [0] ---------- */

static int test_v1_default(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_pkix_certificate_builder_t *builder = NULL;
    asnber_pkix_certificate_t *cert = NULL;
    asnber_buf_t encoded;
    uint8_t *spki = NULL;
    uint8_t *signature = NULL;
    size_t spki_size = 0;
    size_t signature_size = 0;

    ASNBER_TEST_CHECK(ctx != NULL);
    memset(&encoded, 0, sizeof(encoded));
    ASNBER_TEST_CHECK(load_fixture_bits(ctx, &spki, &spki_size, &signature,
                                      &signature_size) == 0);

    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_create(ctx, &builder) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_set_serial_number(
                        builder, kSerialMagnitude,
                        sizeof(kSerialMagnitude)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_set_signature_algorithm(
                        builder, "1.2.840.113549.1.1.11", kNullParameters,
                        sizeof(kNullParameters)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_set_issuer(
                        builder, kNameRdns, 3) == ASNBER_OK);
    {
        asnber_time_t not_before;
        asnber_time_t not_after;
        make_time(&not_before, 2026, 11, 4, 6, 40, 49);
        make_time(&not_after, 2036, 11, 1, 6, 40, 49);
        ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_set_validity(
                            builder, &not_before, &not_after) == ASNBER_OK);
    }
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_set_subject(
                        builder, kNameRdns, 3) == ASNBER_OK);
    ASNBER_TEST_CHECK(
        asnber_pkix_certificate_builder_set_subject_public_key_algorithm(
            builder, "1.2.840.113549.1.1.1", kNullParameters,
            sizeof(kNullParameters)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_set_subject_public_key(
                        builder, spki, spki_size, 0) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_set_signature_value(
                        builder, signature, signature_size, 0) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_encode(builder, &encoded) ==
                    ASNBER_OK);

    ASNBER_TEST_CHECK(asnber_pkix_certificate_open(ctx, encoded.data,
                                               encoded.size, &cert) == ASNBER_OK);
    {
        uint32_t version = 99;
        const asnber_node_t *version_node = NULL;
        ASNBER_TEST_CHECK(asnber_pkix_certificate_version(cert, &version) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(version == 0);
        ASNBER_TEST_CHECK(asnber_pkix_certificate_find(
                            cert, "tbsCertificate.version", &version_node) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(version_node == NULL);
    }
    asnber_pkix_certificate_close(cert);

    asnber_buf_release(ctx, &encoded);
    asnber_pkix_certificate_builder_destroy(builder);
    free(spki);
    free(signature);
    asnber_ctx_destroy(ctx);
    return 0;
}

/* ---------- 便捷扩展 ---------- */

static int test_convenience_extensions(void)
{
    static const uint8_t kKeyUsageBits[] = {0x86};
    static const uint8_t kExpectedKeyUsage[] = {0x03, 0x02, 0x01, 0x86};
    static const uint8_t kExpectedBasicConstraints[] = {0x30, 0x06, 0x01,
                                                        0x01, 0xFF, 0x02,
                                                        0x01, 0x03};
    static const uint8_t kExpectedEku[] = {
        0x30, 0x14, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05,
        0x05, 0x07, 0x03, 0x01, 0x06, 0x08, 0x2B, 0x06,
        0x01, 0x05, 0x05, 0x07, 0x03, 0x02,
    };
    static const char *const kEkuOids[] = {
        "1.3.6.1.5.5.7.3.1",
        "1.3.6.1.5.5.7.3.2",
    };
    asnber_ctx_t *ctx = make_ctx();
    asnber_pkix_certificate_builder_t *builder = NULL;
    asnber_pkix_certificate_t *cert = NULL;
    asnber_buf_t encoded;
    uint8_t *spki = NULL;
    uint8_t *signature = NULL;
    size_t spki_size = 0;
    size_t signature_size = 0;

    ASNBER_TEST_CHECK(ctx != NULL);
    memset(&encoded, 0, sizeof(encoded));
    ASNBER_TEST_CHECK(load_fixture_bits(ctx, &spki, &spki_size, &signature,
                                      &signature_size) == 0);

    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_create(ctx, &builder) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(setup_base(ctx, builder, spki, spki_size) == 0);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_add_basic_constraints(
                        builder, 1, 1, 1, 3) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_add_key_usage(
                        builder, 1, kKeyUsageBits, sizeof(kKeyUsageBits),
                        1) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_add_extended_key_usage(
                        builder, 0, kEkuOids, 2) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_set_signature_value(
                        builder, signature, signature_size, 0) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_encode(builder, &encoded) ==
                    ASNBER_OK);

    ASNBER_TEST_CHECK(asnber_pkix_certificate_open(ctx, encoded.data,
                                               encoded.size, &cert) == ASNBER_OK);
    {
        const asnber_node_t *extensions = NULL;
        const asnber_node_t *extension = NULL;
        ASNBER_TEST_CHECK(asnber_pkix_certificate_find(
                            cert, "tbsCertificate.extensions", &extensions) ==
                        ASNBER_OK);

        extension = find_extension(extensions, "2.5.29.19");
        ASNBER_TEST_CHECK(extension != NULL);
        ASNBER_TEST_CHECK(extension_value_equals(
                            extension, kExpectedBasicConstraints,
                            sizeof(kExpectedBasicConstraints)));
        {
            /* critical 为 TRUE 时应写出 BOOLEAN TRUE。 */
            const asnber_node_t *critical = asnber_node_child_at(extension, 1);
            int value = 0;
            ASNBER_TEST_CHECK(critical != NULL);
            ASNBER_TEST_CHECK(asnber_node_tag_number(critical) == 1);
            ASNBER_TEST_CHECK(asnber_node_get_bool(critical, &value) == ASNBER_OK);
            ASNBER_TEST_CHECK(value != 0);
        }

        extension = find_extension(extensions, "2.5.29.15");
        ASNBER_TEST_CHECK(extension != NULL);
        ASNBER_TEST_CHECK(extension_value_equals(
                            extension, kExpectedKeyUsage,
                            sizeof(kExpectedKeyUsage)));

        extension = find_extension(extensions, "2.5.29.37");
        ASNBER_TEST_CHECK(extension != NULL);
        ASNBER_TEST_CHECK(extension_value_equals(extension, kExpectedEku,
                                               sizeof(kExpectedEku)));
        {
            /* critical 为 0 时 BOOLEAN 完全省略：critical 位置直接是 OCTET STRING。 */
            ASNBER_TEST_CHECK(asnber_node_child_count(extension) == 2);
            ASNBER_TEST_CHECK(asnber_node_tag_number(
                                asnber_node_child_at(extension, 1)) == 4);
        }
    }
    asnber_pkix_certificate_close(cert);

    asnber_buf_release(ctx, &encoded);
    asnber_pkix_certificate_builder_destroy(builder);
    free(spki);
    free(signature);
    asnber_ctx_destroy(ctx);
    return 0;
}

/* ---------- issuerUniqueID / subjectUniqueID ---------- */

static int test_unique_ids(void)
{
    static const uint8_t kIssuerId[] = {0xAA, 0x55};
    static const uint8_t kSubjectId[] = {0x80};
    asnber_ctx_t *ctx = make_ctx();
    asnber_pkix_certificate_builder_t *builder = NULL;
    asnber_pkix_certificate_t *cert = NULL;
    asnber_buf_t encoded;
    uint8_t *spki = NULL;
    uint8_t *signature = NULL;
    size_t spki_size = 0;
    size_t signature_size = 0;

    ASNBER_TEST_CHECK(ctx != NULL);
    memset(&encoded, 0, sizeof(encoded));
    ASNBER_TEST_CHECK(load_fixture_bits(ctx, &spki, &spki_size, &signature,
                                      &signature_size) == 0);

    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_create(ctx, &builder) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(setup_base(ctx, builder, spki, spki_size) == 0);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_set_issuer_unique_id(
                        builder, kIssuerId, sizeof(kIssuerId), 0) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_set_subject_unique_id(
                        builder, kSubjectId, sizeof(kSubjectId), 7) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_set_signature_value(
                        builder, signature, signature_size, 0) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_encode(builder, &encoded) ==
                    ASNBER_OK);

    ASNBER_TEST_CHECK(asnber_pkix_certificate_open(ctx, encoded.data,
                                               encoded.size, &cert) == ASNBER_OK);
    {
        static const uint8_t kIssuerContent[] = {0x00, 0xAA, 0x55};
        static const uint8_t kSubjectContent[] = {0x07, 0x80};
        const asnber_node_t *node = NULL;
        const uint8_t *content = NULL;
        size_t size = 0;

        ASNBER_TEST_CHECK(asnber_pkix_certificate_find(
                            cert, "tbsCertificate.issuerUniqueID", &node) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(node != NULL);
        ASNBER_TEST_CHECK(asnber_node_tag_class(node) == ASNBER_TAG_CONTEXT);
        ASNBER_TEST_CHECK(asnber_node_tag_number(node) == 1);
        ASNBER_TEST_CHECK(asnber_node_content(node, &content, &size) == ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(content, size, kIssuerContent,
                                    sizeof(kIssuerContent)));

        ASNBER_TEST_CHECK(asnber_pkix_certificate_find(
                            cert, "tbsCertificate.subjectUniqueID", &node) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(node != NULL);
        ASNBER_TEST_CHECK(asnber_node_tag_class(node) == ASNBER_TAG_CONTEXT);
        ASNBER_TEST_CHECK(asnber_node_tag_number(node) == 2);
        ASNBER_TEST_CHECK(asnber_node_content(node, &content, &size) == ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(content, size, kSubjectContent,
                                    sizeof(kSubjectContent)));
    }
    asnber_pkix_certificate_close(cert);

    asnber_buf_release(ctx, &encoded);
    asnber_pkix_certificate_builder_destroy(builder);
    free(spki);
    free(signature);
    asnber_ctx_destroy(ctx);
    return 0;
}

/* ---------- 负例 ---------- */

static int test_negative(void)
{
    static const uint8_t kBadOid[] = "not-an-oid";
    static const uint8_t kTruncatedValue[] = {0x02, 0x05};
    static const uint8_t kBadFillBits[] = {0x01};
    static const uint8_t kBits[] = {0xAA};
    static const char *const kEkuOids[] = {"1.3.6.1.5.5.7.3.1"};
    asnber_ctx_t *ctx = make_ctx();
    asnber_pkix_certificate_builder_t *builder = NULL;
    asnber_buf_t encoded;
    asnber_time_t not_before;
    asnber_time_t not_after;

    ASNBER_TEST_CHECK(ctx != NULL);
    memset(&encoded, 0, sizeof(encoded));

    /* 生命周期与空参。 */
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_create(NULL, &builder) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_create(ctx, NULL) ==
                    ASNBER_E_INVALID_ARG);
    asnber_pkix_certificate_builder_destroy(NULL);

    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_create(ctx, &builder) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_encode(builder, &encoded) ==
                    ASNBER_E_INVALID_STATE);
    ASNBER_TEST_CHECK(encoded.data == NULL);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_encode(builder, NULL) ==
                    ASNBER_E_INVALID_ARG);

    /* version 越界与重复设置。 */
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_set_version(builder, -1) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_set_version(builder, 3) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_set_version(builder, 1) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_set_version(builder, 2) ==
                    ASNBER_E_INVALID_STATE);

    /* serial 空参。 */
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_set_serial_number(
                        builder, NULL, 4) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_set_serial_number(
                        builder, kBits, 0) == ASNBER_E_INVALID_ARG);

    /* 签名算法：非法 OID 与残缺参数。 */
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_set_signature_algorithm(
                        builder, (const char *)kBadOid, NULL, 0) != ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_set_signature_algorithm(
                        builder, "1.2.840.113549.1.1.11", kTruncatedValue,
                        sizeof(kTruncatedValue)) != ASNBER_OK);

    /* Name 负例。 */
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_set_issuer(builder, NULL,
                                                             1) ==
                    ASNBER_E_INVALID_ARG);
    {
        static const asnber_pkix_name_rdn_t kEmptyRdn = {NULL, 0};
        ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_set_issuer(
                            builder, &kEmptyRdn, 1) == ASNBER_E_INVALID_ARG);
    }

    /* 时间负例：偏移与非法日期。 */
    make_time(&not_before, 2026, 11, 4, 6, 40, 49);
    make_time(&not_after, 2036, 11, 1, 6, 40, 49);
    not_before.flags = ASNBER_TIME_HAS_OFFSET;
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_set_validity(
                        builder, &not_before, &not_after) ==
                    ASNBER_E_INVALID_VALUE);
    not_before.flags = 0;
    not_before.day = 31;
    not_before.month = 4;
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_set_validity(
                        builder, &not_before, &not_after) ==
                    ASNBER_E_INVALID_VALUE);
    not_before.struct_size = 0;
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_set_validity(
                        builder, &not_before, &not_after) ==
                    ASNBER_E_INVALID_ARG);

    /* 位串负例：未用位越界与填充位非零。 */
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_set_subject_public_key(
                        builder, kBits, sizeof(kBits), 8) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_set_subject_public_key(
                        builder, kBadFillBits, sizeof(kBadFillBits), 4) ==
                    ASNBER_E_INVALID_VALUE);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_set_signature_value(
                        builder, kBadFillBits, sizeof(kBadFillBits), 4) ==
                    ASNBER_E_INVALID_VALUE);

    /* 扩展负例：pathLen 无 cA、重复 OID、非法值、空 EKU。 */
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_add_basic_constraints(
                        builder, 0, 0, 1, 1) == ASNBER_E_INVALID_VALUE);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_add_extension(
                        builder, "2.5.29.17", 0, kSanExtnValue,
                        sizeof(kSanExtnValue)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_add_extension(
                        builder, "2.5.29.17", 0, kSanExtnValue,
                        sizeof(kSanExtnValue)) == ASNBER_E_INVALID_VALUE);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_add_extension(
                        builder, "2.5.29.19", 1, kTruncatedValue,
                        sizeof(kTruncatedValue)) != ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_add_extension(
                        builder, (const char *)kBadOid, 0, kSanExtnValue,
                        sizeof(kSanExtnValue)) != ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_add_extended_key_usage(
                        builder, 0, kEkuOids, 0) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_add_basic_constraints(
                        builder, 0, 0, 0, 0) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_builder_add_basic_constraints(
                        builder, 0, 0, 0, 0) == ASNBER_E_INVALID_VALUE);

    asnber_pkix_certificate_builder_destroy(builder);
    asnber_ctx_destroy(ctx);
    return 0;
}

int main(void)
{
    if (test_openssl_certificate() != 0) {
        return 1;
    }
    if (test_v1_default() != 0) {
        return 1;
    }
    if (test_convenience_extensions() != 0) {
        return 1;
    }
    if (test_unique_ids() != 0) {
        return 1;
    }
    if (test_negative() != 0) {
        return 1;
    }
    return 0;
}
