/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * DER 严格解码校验：每条规则的合法/非法样本、BER 模式保持宽松、多字节
 * 标签支持，以及“解码→编码”对真实证书/密钥/CSR 的逐字节往返。
 */
#include <asnber/asnber.h>

#include <stddef.h>
#include <string.h>

#include "../data/cert_ec_selfsigned.h"
#include "../data/cert_rsa_selfsigned.h"
#include "../data/csr_ec.h"
#include "../data/csr_rsa.h"
#include "../data/key_ec_pkcs8.h"
#include "../data/key_rsa_pkcs8.h"
#include "check.h"

static asnber_err_t decode_with(asnber_ctx_t *ctx, const uint8_t *data, size_t size,
                              asnber_encoding_t encoding, asnber_doc_t **out_doc)
{
    asnber_decode_options_t options;
    asnber_decode_options_init(&options);
    options.encoding = encoding;
    size_t consumed = 0;
    *out_doc = NULL;
    return asnber_decode_buffer(ctx, data, size, &options, out_doc, &consumed);
}

/* 断言 DER 解码结果；期望成功时验证文档非空，期望失败时验证无文档。 */
static int expect_der(asnber_ctx_t *ctx, const uint8_t *data, size_t size,
                      asnber_err_t expected)
{
    asnber_doc_t *doc = NULL;
    const asnber_err_t rc =
        decode_with(ctx, data, size, ASNBER_ENCODING_DER, &doc);
    if (rc != expected) {
        asnber_doc_destroy(doc);
        return 1;
    }
    if (expected == ASNBER_OK) {
        if (doc == NULL) {
            return 1;
        }
        asnber_doc_destroy(doc);
    } else if (doc != NULL) {
        asnber_doc_destroy(doc);
        return 1;
    }
    return 0;
}

/* BER 模式同一字节应按宽松规则解码成功。 */
static int expect_ber_ok(asnber_ctx_t *ctx, const uint8_t *data, size_t size)
{
    asnber_doc_t *doc = NULL;
    const asnber_err_t rc =
        decode_with(ctx, data, size, ASNBER_ENCODING_BER, &doc);
    if (rc != ASNBER_OK || doc == NULL) {
        asnber_doc_destroy(doc);
        return 1;
    }
    asnber_doc_destroy(doc);
    return 0;
}

/* DER 解码后再编码，要求与原始字节逐字节一致。 */
static int roundtrip(asnber_ctx_t *ctx, const uint8_t *der, size_t size)
{
    asnber_doc_t *doc = NULL;
    if (decode_with(ctx, der, size, ASNBER_ENCODING_DER, &doc) != ASNBER_OK) {
        return 1;
    }
    asnber_buf_t buf;
    buf.data = NULL;
    buf.size = 0;
    buf.capacity = 0;
    const asnber_err_t rc = asnber_encode_buffer(ctx, doc, NULL, &buf);
    asnber_doc_destroy(doc);
    if (rc != ASNBER_OK) {
        return 1;
    }
    const int equal = buf.size == size && memcmp(buf.data, der, size) == 0;
    asnber_buf_release(ctx, &buf);
    return equal ? 0 : 1;
}

int main(void)
{
    asnber_ctx_config_t config;
    asnber_ctx_config_init(&config);
    asnber_ctx_t *ctx = NULL;
    ASNBER_TEST_CHECK(asnber_ctx_create(&config, &ctx) == ASNBER_OK);

    /* ---------- 长度：最短形式 / 禁不定长 ---------- */
    {
        static const uint8_t ok[] = {0x30, 0x03, 0x02, 0x01, 0x05};
        static const uint8_t non_minimal[] = {0x30, 0x81, 0x03, 0x02, 0x01,
                                              0x05};
        static const uint8_t indefinite[] = {0x30, 0x80, 0x00, 0x00};
        ASNBER_TEST_CHECK(expect_der(ctx, ok, sizeof(ok), ASNBER_OK) == 0);
        ASNBER_TEST_CHECK(expect_der(ctx, non_minimal, sizeof(non_minimal),
                                   ASNBER_E_NON_CANONICAL) == 0);
        ASNBER_TEST_CHECK(expect_ber_ok(ctx, non_minimal,
                                      sizeof(non_minimal)) == 0);
        ASNBER_TEST_CHECK(expect_der(ctx, indefinite, sizeof(indefinite),
                                   ASNBER_E_INDEFINITE_NOT_ALLOWED) == 0);
        /* BER 支持不定长与 EOC。 */
        ASNBER_TEST_CHECK(expect_ber_ok(ctx, indefinite,
                                      sizeof(indefinite)) == 0);
        /* DER 的定长构造内容中出现 EOC：3005；顶层裸 EOC：MALFORMED_TAG。 */
        static const uint8_t eoc_inside[] = {0x30, 0x02, 0x00, 0x00};
        ASNBER_TEST_CHECK(expect_der(ctx, eoc_inside, sizeof(eoc_inside),
                                   ASNBER_E_INDEFINITE_NOT_ALLOWED) == 0);
        static const uint8_t eoc[] = {0x00};
        ASNBER_TEST_CHECK(expect_der(ctx, eoc, sizeof(eoc),
                                   ASNBER_E_MALFORMED_TAG) == 0);
    }

    /* 长形式长度：128 字节内容必须用 0x81 0x80；0x82 0x00 0x80 非最短。 */
    {
        static uint8_t canonical[3 + 128];
        static uint8_t leading_zero[4 + 128];
        memset(canonical, 0xAA, sizeof(canonical));
        canonical[0] = 0x04;
        canonical[1] = 0x81;
        canonical[2] = 0x80;
        memset(leading_zero, 0xAA, sizeof(leading_zero));
        leading_zero[0] = 0x04;
        leading_zero[1] = 0x82;
        leading_zero[2] = 0x00;
        leading_zero[3] = 0x80;
        ASNBER_TEST_CHECK(expect_der(ctx, canonical, sizeof(canonical),
                                   ASNBER_OK) == 0);
        ASNBER_TEST_CHECK(expect_der(ctx, leading_zero, sizeof(leading_zero),
                                   ASNBER_E_NON_CANONICAL) == 0);
        ASNBER_TEST_CHECK(expect_ber_ok(ctx, leading_zero,
                                      sizeof(leading_zero)) == 0);
    }

    /* ---------- BOOLEAN ---------- */
    {
        static const uint8_t false_ok[] = {0x01, 0x01, 0x00};
        static const uint8_t true_ok[] = {0x01, 0x01, 0xFF};
        static const uint8_t bad_value[] = {0x01, 0x01, 0x01};
        static const uint8_t bad_size[] = {0x01, 0x02, 0x00, 0x00};
        ASNBER_TEST_CHECK(expect_der(ctx, false_ok, sizeof(false_ok),
                                   ASNBER_OK) == 0);
        ASNBER_TEST_CHECK(expect_der(ctx, true_ok, sizeof(true_ok),
                                   ASNBER_OK) == 0);
        ASNBER_TEST_CHECK(expect_der(ctx, bad_value, sizeof(bad_value),
                                   ASNBER_E_NON_CANONICAL) == 0);
        ASNBER_TEST_CHECK(expect_ber_ok(ctx, bad_value,
                                      sizeof(bad_value)) == 0);
        ASNBER_TEST_CHECK(expect_der(ctx, bad_size, sizeof(bad_size),
                                   ASNBER_E_NON_CANONICAL) == 0);
    }

    /* ---------- INTEGER / ENUMERATED ---------- */
    {
        static const uint8_t int_ok[] = {0x02, 0x01, 0x05};
        static const uint8_t int_required_zero[] = {0x02, 0x02, 0x00, 0x80};
        static const uint8_t int_leading_zero[] = {0x02, 0x02, 0x00, 0x05};
        static const uint8_t int_required_ff[] = {0x02, 0x01, 0x80};
        static const uint8_t int_leading_ff[] = {0x02, 0x02, 0xFF, 0x80};
        static const uint8_t int_empty[] = {0x02, 0x00};
        static const uint8_t enum_leading_zero[] = {0x0A, 0x02, 0x00, 0x05};
        ASNBER_TEST_CHECK(expect_der(ctx, int_ok, sizeof(int_ok), ASNBER_OK) == 0);
        ASNBER_TEST_CHECK(expect_der(ctx, int_required_zero,
                                   sizeof(int_required_zero), ASNBER_OK) == 0);
        ASNBER_TEST_CHECK(expect_der(ctx, int_leading_zero,
                                   sizeof(int_leading_zero),
                                   ASNBER_E_NON_CANONICAL) == 0);
        ASNBER_TEST_CHECK(expect_ber_ok(ctx, int_leading_zero,
                                      sizeof(int_leading_zero)) == 0);
        ASNBER_TEST_CHECK(expect_der(ctx, int_required_ff,
                                   sizeof(int_required_ff), ASNBER_OK) == 0);
        ASNBER_TEST_CHECK(expect_der(ctx, int_leading_ff, sizeof(int_leading_ff),
                                   ASNBER_E_NON_CANONICAL) == 0);
        ASNBER_TEST_CHECK(expect_der(ctx, int_empty, sizeof(int_empty),
                                   ASNBER_E_MALFORMED_VALUE) == 0);
        ASNBER_TEST_CHECK(expect_der(ctx, enum_leading_zero,
                                   sizeof(enum_leading_zero),
                                   ASNBER_E_NON_CANONICAL) == 0);
    }

    /* ---------- BIT STRING ---------- */
    {
        static const uint8_t ok[] = {0x03, 0x02, 0x04, 0xA0};
        static const uint8_t zero_ok[] = {0x03, 0x01, 0x00};
        static const uint8_t empty[] = {0x03, 0x00};
        static const uint8_t unused_too_large[] = {0x03, 0x02, 0x08, 0x00};
        static const uint8_t zero_with_unused[] = {0x03, 0x01, 0x01};
        ASNBER_TEST_CHECK(expect_der(ctx, ok, sizeof(ok), ASNBER_OK) == 0);
        ASNBER_TEST_CHECK(expect_der(ctx, zero_ok, sizeof(zero_ok),
                                   ASNBER_OK) == 0);
        ASNBER_TEST_CHECK(expect_der(ctx, empty, sizeof(empty),
                                   ASNBER_E_NON_CANONICAL) == 0);
        ASNBER_TEST_CHECK(expect_der(ctx, unused_too_large,
                                   sizeof(unused_too_large),
                                   ASNBER_E_NON_CANONICAL) == 0);
        ASNBER_TEST_CHECK(expect_der(ctx, zero_with_unused,
                                   sizeof(zero_with_unused),
                                   ASNBER_E_NON_CANONICAL) == 0);
        ASNBER_TEST_CHECK(expect_ber_ok(ctx, unused_too_large,
                                      sizeof(unused_too_large)) == 0);
    }

    /* ---------- OCTET STRING / 字符串禁构造形式 ---------- */
    {
        static const uint8_t octet_ok[] = {0x04, 0x02, 0x41, 0x42};
        static const uint8_t octet_constructed[] = {0x24, 0x03, 0x04, 0x01,
                                                    0x41};
        static const uint8_t printable_ok[] = {0x13, 0x01, 0x41};
        static const uint8_t printable_constructed[] = {0x33, 0x03, 0x13,
                                                        0x01, 0x41};
        ASNBER_TEST_CHECK(expect_der(ctx, octet_ok, sizeof(octet_ok),
                                   ASNBER_OK) == 0);
        ASNBER_TEST_CHECK(expect_der(ctx, octet_constructed,
                                   sizeof(octet_constructed),
                                   ASNBER_E_NON_CANONICAL) == 0);
        ASNBER_TEST_CHECK(expect_ber_ok(ctx, octet_constructed,
                                      sizeof(octet_constructed)) == 0);
        ASNBER_TEST_CHECK(expect_der(ctx, printable_ok, sizeof(printable_ok),
                                   ASNBER_OK) == 0);
        ASNBER_TEST_CHECK(expect_der(ctx, printable_constructed,
                                   sizeof(printable_constructed),
                                   ASNBER_E_NON_CANONICAL) == 0);
    }

    /* ---------- SET / SET OF 排序 ---------- */
    {
        static const uint8_t set_ok[] = {0x31, 0x06, 0x01, 0x01, 0xFF, 0x02,
                                         0x01, 0x05};
        static const uint8_t set_unordered[] = {0x31, 0x06, 0x02, 0x01,
                                                0x05, 0x01, 0x01, 0xFF};
        static const uint8_t set_of_ok[] = {0x31, 0x06, 0x04, 0x01, 0x61,
                                            0x04, 0x01, 0x62};
        static const uint8_t set_of_unordered[] = {
            0x31, 0x06, 0x04, 0x01, 0x62, 0x04, 0x01, 0x61};
        ASNBER_TEST_CHECK(expect_der(ctx, set_ok, sizeof(set_ok), ASNBER_OK) == 0);
        ASNBER_TEST_CHECK(expect_der(ctx, set_unordered, sizeof(set_unordered),
                                   ASNBER_E_NON_CANONICAL) == 0);
        ASNBER_TEST_CHECK(expect_ber_ok(ctx, set_unordered,
                                      sizeof(set_unordered)) == 0);
        ASNBER_TEST_CHECK(expect_der(ctx, set_of_ok, sizeof(set_of_ok),
                                   ASNBER_OK) == 0);
        ASNBER_TEST_CHECK(expect_der(ctx, set_of_unordered,
                                   sizeof(set_of_unordered),
                                   ASNBER_E_NON_CANONICAL) == 0);
    }

    /* ---------- 时间 ---------- */
    {
        static const uint8_t utc_ok[] = {
            0x17, 0x0D, '9', '9', '0', '1', '0', '1',
            '0', '0', '0', '0', '0', '0', 'Z'};
        static const uint8_t utc_no_seconds[] = {
            0x17, 0x0B, '9', '9', '0', '1', '0', '1',
            '0', '0', '0', '0', 'Z'};
        static const uint8_t utc_local[] = {
            0x17, 0x0A, '9', '9', '0', '1', '0', '1', '0', '0', '0', '0'};
        static const uint8_t utc_offset[] = {
            0x17, 0x11, '9', '9', '0', '1', '0', '1', '0', '0',
            '0', '0', '0', '0', '+', '0', '1', '0', '0'};
        static const uint8_t utc_plus_zero[] = {
            0x17, 0x11, '9', '9', '0', '1', '0', '1', '0', '0',
            '0', '0', '0', '0', '+', '0', '0', '0', '0'};
        static const uint8_t utc_minus_zero[] = {
            0x17, 0x11, '9', '9', '0', '1', '0', '1', '0', '0',
            '0', '0', '0', '0', '-', '0', '0', '0', '0'};
        static const uint8_t utc_leap_second[] = {
            0x17, 0x0D, '9', '9', '0', '1', '0', '1',
            '0', '0', '0', '0', '6', '0', 'Z'};
        static const uint8_t gen_ok[] = {
            0x18, 0x0F, '2', '0', '2', '4', '0', '1',
            '0', '1', '0', '0', '0', '0', '0', '0', 'Z'};
        static const uint8_t gen_fraction[] = {
            0x18, 0x11, '2', '0', '2', '4', '0', '1', '0', '1', '0',
            '0', '0', '0', '0', '0', '.', '5', 'Z'};
        static const uint8_t gen_fraction_trailing_zero[] = {
            0x18, 0x12, '2', '0', '2', '4', '0', '1', '0', '1', '0',
            '0', '0', '0', '0', '0', '.', '5', '0', 'Z'};
        static const uint8_t gen_no_seconds[] = {
            0x18, 0x0D, '2', '0', '2', '4', '0', '1', '0',
            '1', '0', '0', '0', '0', 'Z'};
        static const uint8_t gen_comma_fraction[] = {
            0x18, 0x11, '2', '0', '2', '4', '0', '1', '0', '1', '0',
            '0', '0', '0', '0', '0', ',', '5', 'Z'};
        static const uint8_t gen_local[] = {
            0x18, 0x0E, '2', '0', '2', '4', '0', '1', '0',
            '1', '0', '0', '0', '0', '0', '0'};
        ASNBER_TEST_CHECK(expect_der(ctx, utc_ok, sizeof(utc_ok), ASNBER_OK) == 0);
        ASNBER_TEST_CHECK(expect_der(ctx, utc_no_seconds,
                                   sizeof(utc_no_seconds),
                                   ASNBER_E_NON_CANONICAL) == 0);
        ASNBER_TEST_CHECK(expect_der(ctx, utc_local, sizeof(utc_local),
                                   ASNBER_E_NON_CANONICAL) == 0);
        ASNBER_TEST_CHECK(expect_der(ctx, utc_offset, sizeof(utc_offset),
                                   ASNBER_E_NON_CANONICAL) == 0);
        ASNBER_TEST_CHECK(expect_der(ctx, utc_plus_zero, sizeof(utc_plus_zero),
                                   ASNBER_E_NON_CANONICAL) == 0);
        ASNBER_TEST_CHECK(expect_der(ctx, utc_minus_zero, sizeof(utc_minus_zero),
                                   ASNBER_E_NON_CANONICAL) == 0);
        ASNBER_TEST_CHECK(expect_der(ctx, utc_leap_second,
                                   sizeof(utc_leap_second),
                                   ASNBER_E_NON_CANONICAL) == 0);
        ASNBER_TEST_CHECK(expect_ber_ok(ctx, utc_local, sizeof(utc_local)) == 0);
        ASNBER_TEST_CHECK(expect_ber_ok(ctx, utc_offset, sizeof(utc_offset)) == 0);
        ASNBER_TEST_CHECK(expect_ber_ok(ctx, utc_plus_zero,
                                      sizeof(utc_plus_zero)) == 0);
        ASNBER_TEST_CHECK(expect_ber_ok(ctx, utc_minus_zero,
                                      sizeof(utc_minus_zero)) == 0);
        ASNBER_TEST_CHECK(expect_ber_ok(ctx, utc_leap_second,
                                      sizeof(utc_leap_second)) == 0);
        ASNBER_TEST_CHECK(expect_der(ctx, gen_ok, sizeof(gen_ok), ASNBER_OK) == 0);
        ASNBER_TEST_CHECK(expect_der(ctx, gen_fraction, sizeof(gen_fraction),
                                   ASNBER_OK) == 0);
        ASNBER_TEST_CHECK(expect_der(ctx, gen_fraction_trailing_zero,
                                   sizeof(gen_fraction_trailing_zero),
                                   ASNBER_E_NON_CANONICAL) == 0);
        ASNBER_TEST_CHECK(expect_der(ctx, gen_no_seconds,
                                   sizeof(gen_no_seconds),
                                   ASNBER_E_NON_CANONICAL) == 0);
        ASNBER_TEST_CHECK(expect_der(ctx, gen_local, sizeof(gen_local),
                                   ASNBER_E_NON_CANONICAL) == 0);
        ASNBER_TEST_CHECK(expect_der(ctx, gen_comma_fraction,
                                   sizeof(gen_comma_fraction),
                                   ASNBER_E_NON_CANONICAL) == 0);
        ASNBER_TEST_CHECK(expect_ber_ok(ctx, gen_local, sizeof(gen_local)) == 0);
        ASNBER_TEST_CHECK(expect_ber_ok(ctx, gen_comma_fraction,
                                      sizeof(gen_comma_fraction)) == 0);
        ASNBER_TEST_CHECK(expect_ber_ok(ctx, gen_fraction_trailing_zero,
                                      sizeof(gen_fraction_trailing_zero)) == 0);
    }

    /* ---------- OID 最短 base128 ---------- */
    {
        static const uint8_t ok[] = {0x06, 0x03, 0x55, 0x04, 0x03};
        static const uint8_t non_minimal[] = {0x06, 0x03, 0x80, 0x00, 0x01};
        static const uint8_t unterminated[] = {0x06, 0x02, 0x55, 0x84};
        ASNBER_TEST_CHECK(expect_der(ctx, ok, sizeof(ok), ASNBER_OK) == 0);
        ASNBER_TEST_CHECK(expect_der(ctx, non_minimal, sizeof(non_minimal),
                                   ASNBER_E_NON_CANONICAL) == 0);
        ASNBER_TEST_CHECK(expect_der(ctx, unterminated, sizeof(unterminated),
                                   ASNBER_E_NON_CANONICAL) == 0);
        ASNBER_TEST_CHECK(expect_ber_ok(ctx, non_minimal,
                                      sizeof(non_minimal)) == 0);
    }

    /* ---------- 多字节标签 ---------- */
    {
        static const uint8_t canonical[] = {0x9F, 0x28, 0x00};
        static const uint8_t long_form_of_short[] = {0x9F, 0x01, 0x00};
        ASNBER_TEST_CHECK(expect_der(ctx, canonical, sizeof(canonical),
                                   ASNBER_OK) == 0);
        ASNBER_TEST_CHECK(roundtrip(ctx, canonical, sizeof(canonical)) == 0);
        ASNBER_TEST_CHECK(expect_der(ctx, long_form_of_short,
                                   sizeof(long_form_of_short),
                                   ASNBER_E_NON_CANONICAL) == 0);
        ASNBER_TEST_CHECK(expect_ber_ok(ctx, long_form_of_short,
                                      sizeof(long_form_of_short)) == 0);
        /* EOC 在任何模式都非法。 */
        static const uint8_t eoc[] = {0x00};
        ASNBER_TEST_CHECK(expect_der(ctx, eoc, sizeof(eoc),
                                   ASNBER_E_MALFORMED_TAG) == 0);
    }

    /* ---------- 真实材料：解码→编码逐字节一致 ---------- */
    {
        ASNBER_TEST_CHECK(roundtrip(ctx, kCertRsaSelfsigned,
                                  kCertRsaSelfsignedSize) == 0);
        ASNBER_TEST_CHECK(roundtrip(ctx, kCertEcSelfsigned,
                                  kCertEcSelfsignedSize) == 0);
        ASNBER_TEST_CHECK(roundtrip(ctx, kKeyRsaPkcs8,
                                  kKeyRsaPkcs8Size) == 0);
        ASNBER_TEST_CHECK(roundtrip(ctx, kKeyEcPkcs8, kKeyEcPkcs8Size) == 0);
        ASNBER_TEST_CHECK(roundtrip(ctx, kCsrRsa, kCsrRsaSize) == 0);
        ASNBER_TEST_CHECK(roundtrip(ctx, kCsrEc, kCsrEcSize) == 0);
    }

    asnber_ctx_destroy(ctx);
    return 0;
}
