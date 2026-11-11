/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * asnber-pkix 模块：真实证书字段访问、ANY 三形态、句柄隔离与负例。
 */

#include <asnber/asnber.h>
#include <asnber/pkix/pkix.h>

#include <stddef.h>
#include <string.h>

#include "../data/cert_ec_selfsigned.h"
#include "../data/cert_rsa_pss_selfsigned.h"
#include "../data/cert_rsa_selfsigned.h"
#include "../data/key_rsa_pkcs8.h"
#include "check.h"
#include "test_compare.h"

/* ---------- 辅助 ---------- */

/* 版本同源：CMake 生成头宏、模块运行时字符串与核心运行时字符串一致。 */
static int test_module_version(void)
{
    const char *runtime = asnber_pkix_version_string();
    asnber_version_info_t info;

    memset(&info, 0, sizeof(info));
    info.struct_size = sizeof(info);
    ASNBER_TEST_CHECK(runtime != NULL);
    ASNBER_TEST_CHECK(strcmp(runtime, ASNBER_PKIX_VERSION_STRING) == 0);
    ASNBER_TEST_CHECK(asnber_version(&info) == ASNBER_OK);
    ASNBER_TEST_CHECK(info.string != NULL);
    ASNBER_TEST_CHECK(strcmp(runtime, info.string) == 0);
    return 0;
}

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

/* 在 RDNSequence 中查找与 expected 完全相等的文本（本测试用它定位 CN）。 */
static int find_text(const asnber_node_t *name, const char *expected)
{
    size_t sets = asnber_node_child_count(name);
    size_t i;
    for (i = 0; i < sets; ++i) {
        const asnber_node_t *set = asnber_node_child_at(name, i);
        size_t j;
        for (j = 0; j < asnber_node_child_count(set); ++j) {
            const asnber_node_t *pair = asnber_node_child_at(set, j);
            const char *text = NULL;
            size_t text_size = 0;
            if (asnber_node_child_count(pair) != 2) {
                continue;
            }
            if (asnber_node_get_utf8(asnber_node_child_at(pair, 1), &text,
                                   &text_size) != ASNBER_OK) {
                continue;
            }
            if (text_size == strlen(expected) &&
                memcmp(text, expected, text_size) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

/* [n] EXPLICIT 包装内的 SEQUENCE 元素数，否则直接返回子节点数。 */
static size_t sequence_item_count(const asnber_node_t *node)
{
    if (asnber_node_tag_class(node) == ASNBER_TAG_CONTEXT &&
        asnber_node_child_count(node) == 1) {
        node = asnber_node_child_at(node, 0);
    }
    return asnber_node_child_count(node);
}

typedef struct cert_expectation {
    const uint8_t *der;
    size_t der_size;
    const char *signature_oid;
    const char *serial_decimal;
    const char *cn;
    int32_t not_before_year;
    uint8_t not_before_month;
    uint8_t not_before_day;
    uint8_t not_before_second;
    int32_t not_after_year;
    uint8_t not_after_month;
    uint8_t not_after_day;
    uint8_t not_after_second;
} cert_expectation_t;

static int check_certificate(const cert_expectation_t *expected,
                             int check_any_shapes)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_pkix_certificate_t *cert = NULL;
    asnber_err_t status;

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_open(ctx, expected->der,
                                               expected->der_size,
                                               &cert) == ASNBER_OK);
    ASNBER_TEST_CHECK(cert != NULL);

    {
        uint32_t version = 0;
        ASNBER_TEST_CHECK(asnber_pkix_certificate_version(cert, &version) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(version == 2);
    }

    {
        const char *serial = NULL;
        size_t size = 0;
        ASNBER_TEST_CHECK(asnber_pkix_certificate_serial_number(cert, &serial,
                                                            &size) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(serial != NULL);
        ASNBER_TEST_CHECK(size == strlen(expected->serial_decimal));
        ASNBER_TEST_CHECK(memcmp(serial, expected->serial_decimal, size) == 0);
    }

    {
        const char *oid = NULL;
        size_t size = 0;
        ASNBER_TEST_CHECK(asnber_pkix_certificate_signature_algorithm_oid(
                            cert, &oid, &size) == ASNBER_OK);
        ASNBER_TEST_CHECK(oid != NULL);
        ASNBER_TEST_CHECK(size == strlen(expected->signature_oid));
        ASNBER_TEST_CHECK(memcmp(oid, expected->signature_oid, size) == 0);
    }

    {
        const uint8_t *bits = NULL;
        size_t size = 0;
        size_t bit_length = 0;
        uint8_t unused = 0;
        ASNBER_TEST_CHECK(asnber_pkix_certificate_signature_value(
                            cert, &bits, &size, &bit_length, &unused) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(bits != NULL);
        ASNBER_TEST_CHECK(size > 0);
        ASNBER_TEST_CHECK(unused <= 7);
        ASNBER_TEST_CHECK(bit_length == size * 8 - unused);
    }

    {
        const uint8_t *subject = NULL;
        const uint8_t *issuer = NULL;
        size_t subject_size = 0;
        size_t issuer_size = 0;
        ASNBER_TEST_CHECK(asnber_pkix_certificate_subject_der(
                            cert, &subject, &subject_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_pkix_certificate_issuer_der(
                            cert, &issuer, &issuer_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(subject != NULL && issuer != NULL);
        ASNBER_TEST_CHECK(subject_size == issuer_size);
        ASNBER_TEST_CHECK(bytes_equal(subject, subject_size, issuer,
                                    issuer_size));
    }

    {
        asnber_time_t before;
        asnber_time_t after;
        memset(&before, 0, sizeof(before));
        memset(&after, 0, sizeof(after));
        before.struct_size = sizeof(before);
        after.struct_size = sizeof(after);
        ASNBER_TEST_CHECK(asnber_pkix_certificate_validity(cert, &before,
                                                       &after) == ASNBER_OK);
        ASNBER_TEST_CHECK(before.year == expected->not_before_year);
        ASNBER_TEST_CHECK(before.month == expected->not_before_month);
        ASNBER_TEST_CHECK(before.day == expected->not_before_day);
        ASNBER_TEST_CHECK(before.second == expected->not_before_second);
        ASNBER_TEST_CHECK((before.flags & ASNBER_TIME_UTC) != 0);
        ASNBER_TEST_CHECK((before.flags & ASNBER_TIME_HAS_OFFSET) == 0);
        ASNBER_TEST_CHECK((before.flags & ASNBER_TIME_LOCAL) == 0);
        ASNBER_TEST_CHECK(after.year == expected->not_after_year);
        ASNBER_TEST_CHECK(after.month == expected->not_after_month);
        ASNBER_TEST_CHECK(after.day == expected->not_after_day);
        ASNBER_TEST_CHECK(after.second == expected->not_after_second);
        ASNBER_TEST_CHECK((after.flags & ASNBER_TIME_UTC) != 0);
    }

    {
        const asnber_node_t *node = NULL;
        ASNBER_TEST_CHECK(asnber_pkix_certificate_find(
                            cert, "tbsCertificate.subject", &node) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(node != NULL);
        ASNBER_TEST_CHECK(find_text(node, expected->cn));

        ASNBER_TEST_CHECK(asnber_pkix_certificate_find(
                            cert, "tbsCertificate.issuer", &node) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(node != NULL);
        ASNBER_TEST_CHECK(find_text(node, expected->cn));

        ASNBER_TEST_CHECK(asnber_pkix_certificate_find(
                            cert, "tbsCertificate.validity", &node) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(node != NULL);
        ASNBER_TEST_CHECK(asnber_node_child_count(node) == 2);

        ASNBER_TEST_CHECK(asnber_pkix_certificate_find(
                            cert, "tbsCertificate.extensions", &node) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(node != NULL);
        ASNBER_TEST_CHECK(sequence_item_count(node) == 3);
    }

    if (check_any_shapes) {
        const asnber_node_t *any_node = NULL;
        size_t size = 0;
        const uint8_t *tlv = NULL;
        ASNBER_TEST_CHECK(asnber_pkix_certificate_find(
                            cert, "signatureAlgorithm.parameters",
                            &any_node) == ASNBER_OK);

        if (strcmp(expected->signature_oid, "1.2.840.113549.1.1.11") == 0) {
            /* RSA：parameters 为 NULL，完整 TLV 05 00。 */
            ASNBER_TEST_CHECK(any_node != NULL);
            ASNBER_TEST_CHECK(asnber_node_child_count(any_node) == 0);
            tlv = asnber_node_tlv(any_node, &size);
            ASNBER_TEST_CHECK(tlv != NULL && size == 2);
            ASNBER_TEST_CHECK(tlv[0] == 0x05 && tlv[1] == 0x00);
        } else if (strcmp(expected->signature_oid,
                          "1.2.840.113549.1.1.10") == 0) {
            /* RSA-PSS：parameters 为内层 SEQUENCE，ANY 只给完整 TLV。 */
            ASNBER_TEST_CHECK(any_node != NULL);
            ASNBER_TEST_CHECK(asnber_node_child_count(any_node) == 0);
            tlv = asnber_node_tlv(any_node, &size);
            ASNBER_TEST_CHECK(tlv != NULL && size > 2);
            ASNBER_TEST_CHECK(tlv[0] == 0x30);
        } else {
            /* EC：parameters 缺省，find 返回无节点且不报错。 */
            ASNBER_TEST_CHECK(any_node == NULL);
        }
    }

    asnber_pkix_certificate_close(cert);
    asnber_ctx_destroy(ctx);
    return 0;
}

/* ---------- 正例：三张真实证书 ---------- */

static int test_real_certificates(void)
{
    const cert_expectation_t rsa = {
        kCertRsaSelfsigned, kCertRsaSelfsignedSize,
        "1.2.840.113549.1.1.11",
        "651241625021466612160683104114604757680343021109",
        "ASN1 RSA Self Signed", 2026, 11, 4, 49, 2036, 11, 1, 49};
    const cert_expectation_t pss = {
        kCertRsaPssSelfsigned, kCertRsaPssSelfsignedSize,
        "1.2.840.113549.1.1.10",
        "191865463882548997427553112368273144303752527720",
        "ASN1 RSA-PSS Self Signed", 2026, 11, 4, 50, 2036, 11, 1, 50};
    const cert_expectation_t ec = {
        kCertEcSelfsigned, kCertEcSelfsignedSize,
        "1.2.840.10045.4.3.2",
        "638742892805164721513090762070971563210776089362",
        "ASN1 EC Self Signed", 2026, 11, 4, 50, 2036, 11, 1, 50};

    ASNBER_TEST_CHECK(check_certificate(&rsa, 1) == 0);
    ASNBER_TEST_CHECK(check_certificate(&pss, 1) == 0);
    ASNBER_TEST_CHECK(check_certificate(&ec, 1) == 0);
    return 0;
}

/* ---------- 句柄隔离：两个上下文同时持有一份 ---------- */

static int test_handle_isolation(void)
{
    asnber_ctx_t *ctx_a = make_ctx();
    asnber_ctx_t *ctx_b = make_ctx();
    asnber_pkix_certificate_t *cert_a = NULL;
    asnber_pkix_certificate_t *cert_b = NULL;

    ASNBER_TEST_CHECK(ctx_a != NULL && ctx_b != NULL);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_open(ctx_a, kCertRsaSelfsigned,
                                               kCertRsaSelfsignedSize,
                                               &cert_a) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_open(ctx_b, kCertEcSelfsigned,
                                               kCertEcSelfsignedSize,
                                               &cert_b) == ASNBER_OK);

    {
        const char *serial = NULL;
        size_t size = 0;
        ASNBER_TEST_CHECK(asnber_pkix_certificate_serial_number(cert_a, &serial,
                                                            &size) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(size ==
                        strlen("651241625021466612160683104114604757680343021109"));
        ASNBER_TEST_CHECK(memcmp(serial,
                               "651241625021466612160683104114604757680343021109",
                               size) == 0);
        ASNBER_TEST_CHECK(asnber_pkix_certificate_serial_number(cert_b, &serial,
                                                            &size) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(size ==
                        strlen("638742892805164721513090762070971563210776089362"));
        ASNBER_TEST_CHECK(memcmp(serial,
                               "638742892805164721513090762070971563210776089362",
                               size) == 0);
    }

    asnber_pkix_certificate_close(cert_a);

    {
        const char *serial = NULL;
        size_t size = 0;
        ASNBER_TEST_CHECK(asnber_pkix_certificate_serial_number(cert_b, &serial,
                                                            &size) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(memcmp(serial,
                               "638742892805164721513090762070971563210776089362",
                               size) == 0);
    }

    asnber_pkix_certificate_close(cert_b);
    asnber_ctx_destroy(ctx_b);
    asnber_ctx_destroy(ctx_a);
    return 0;
}

/* ---------- 负例 ---------- */

static int test_negative(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_pkix_certificate_t *cert = NULL;
    const asnber_node_t *node_out = NULL;

    ASNBER_TEST_CHECK(ctx != NULL);

    /* 空参与空句柄。 */
    ASNBER_TEST_CHECK(asnber_pkix_certificate_open(NULL, kCertRsaSelfsigned,
                                               kCertRsaSelfsignedSize,
                                               &cert) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_open(ctx, NULL,
                                               kCertRsaSelfsignedSize,
                                               &cert) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_open(ctx, kCertRsaSelfsigned, 0,
                                               &cert) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_open(ctx, kCertRsaSelfsigned,
                                               kCertRsaSelfsignedSize,
                                               NULL) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_find(NULL,
                                               "tbsCertificate.subject",
                                               &node_out) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_find(cert, NULL, &node_out) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkix_certificate_version(NULL, NULL) ==
                    ASNBER_E_INVALID_ARG);
    asnber_pkix_certificate_close(NULL);

    /* 非证书 DER：PKCS#8 私钥。 */
    ASNBER_TEST_CHECK(asnber_pkix_certificate_open(ctx, kKeyRsaPkcs8,
                                               kKeyRsaPkcs8Size, &cert) !=
                    ASNBER_OK);
    ASNBER_TEST_CHECK(cert == NULL);

    /* 截断的证书。 */
    ASNBER_TEST_CHECK(asnber_pkix_certificate_open(
                        ctx, kCertRsaSelfsigned,
                        kCertRsaSelfsignedSize - 10, &cert) != ASNBER_OK);
    ASNBER_TEST_CHECK(cert == NULL);

    /* 合法 DER 后附加尾随字节。 */
    {
        static uint8_t trailing[kCertRsaSelfsignedSize + 1];
        memcpy(trailing, kCertRsaSelfsigned, kCertRsaSelfsignedSize);
        trailing[kCertRsaSelfsignedSize] = 0x00;
        ASNBER_TEST_CHECK(asnber_pkix_certificate_open(
                            ctx, trailing, kCertRsaSelfsignedSize + 1,
                            &cert) != ASNBER_OK);
        ASNBER_TEST_CHECK(cert == NULL);
    }

    /* 合法证书上的路径/参数负例。 */
    ASNBER_TEST_CHECK(asnber_pkix_certificate_open(ctx, kCertRsaSelfsigned,
                                               kCertRsaSelfsignedSize,
                                               &cert) == ASNBER_OK);
    {
        const asnber_node_t *found = NULL;

        ASNBER_TEST_CHECK(asnber_pkix_certificate_find(
                            cert, "tbsCertificate..subject", &found) ==
                        ASNBER_E_INVALID_ARG);
        ASNBER_TEST_CHECK(asnber_pkix_certificate_find(cert, "noSuchField",
                                                   &found) == ASNBER_OK);
        ASNBER_TEST_CHECK(found == NULL);
        ASNBER_TEST_CHECK(asnber_pkix_certificate_find(cert, "", &found) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(found != NULL);

        ASNBER_TEST_CHECK(asnber_pkix_certificate_signature_algorithm_oid(
                            cert, NULL, NULL) == ASNBER_E_INVALID_ARG);
        ASNBER_TEST_CHECK(asnber_pkix_certificate_signature_value(
                            cert, NULL, NULL, NULL, NULL) ==
                        ASNBER_E_INVALID_ARG);
        ASNBER_TEST_CHECK(asnber_pkix_certificate_serial_number(cert, NULL,
                                                            NULL) ==
                        ASNBER_E_INVALID_ARG);
        ASNBER_TEST_CHECK(asnber_pkix_certificate_issuer_der(cert, NULL, NULL) ==
                        ASNBER_E_INVALID_ARG);
        ASNBER_TEST_CHECK(asnber_pkix_certificate_subject_der(cert, NULL, NULL) ==
                        ASNBER_E_INVALID_ARG);
        ASNBER_TEST_CHECK(asnber_pkix_certificate_validity(cert, NULL, NULL) ==
                        ASNBER_E_INVALID_ARG);
    }
    asnber_pkix_certificate_close(cert);

    asnber_ctx_destroy(ctx);
    return 0;
}

int main(void)
{
    if (test_module_version() != 0) {
        return 1;
    }
    if (test_real_certificates() != 0) {
        return 1;
    }
    if (test_handle_isolation() != 0) {
        return 1;
    }
    if (test_negative() != 0) {
        return 1;
    }
    return 0;
}
