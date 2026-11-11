/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * asnber-pkcs1 RSAPublicKey / RSAPrivateKey builder：正例往返、大整数规整
 * 与负例。
 */

#include <asnber/asnber.h>
#include <asnber/pkcs1/pkcs1.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "../data/key_rsa_pkcs1_private.h"
#include "../data/key_rsa_pkcs1_public.h"
#include "check.h"
#include "test_compare.h"

#define kBigIntegerLimit ((size_t)8192u)
#define kPrivateFieldCount ((size_t)8u)

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

/*
 * 从 DER fixture 的第 index 个顶层子节点取 INTEGER 内容，去掉符号前导
 * 0x00 后复制为大端无符号幅值。返回 0 表示成功。
 */
static int read_fixture_bigint(asnber_ctx_t *ctx, const uint8_t *der,
                               size_t der_size, size_t index,
                               uint8_t **out_magnitude, size_t *out_size)
{
    asnber_decode_options_t options;
    asnber_doc_t *doc = NULL;
    const asnber_node_t *root = NULL;
    const asnber_node_t *child = NULL;
    const uint8_t *content = NULL;
    size_t content_size = 0;
    size_t consumed = 0;
    uint8_t *copy = NULL;

    asnber_decode_options_init(&options);
    options.encoding = ASNBER_ENCODING_DER;
    options.flags = ASNBER_DECODE_COPY_INPUT;
    if (asnber_decode_buffer(ctx, der, der_size, &options, &doc, &consumed) !=
        ASNBER_OK) {
        return 1;
    }
    root = asnber_doc_root(doc);
    child = asnber_node_child_at(root, index);
    if (child == NULL ||
        asnber_node_content(child, &content, &content_size) != ASNBER_OK ||
        content == NULL || content_size == 0) {
        asnber_doc_destroy(doc);
        return 1;
    }
    while (content_size > 1 && content[0] == 0x00u) {
        ++content;
        --content_size;
    }
    copy = (uint8_t *)malloc(content_size);
    if (copy == NULL) {
        asnber_doc_destroy(doc);
        return 1;
    }
    memcpy(copy, content, content_size);
    asnber_doc_destroy(doc);

    *out_magnitude = copy;
    *out_size = content_size;
    return 0;
}

/* 两份 DER 的 modulus 与 publicExponent 十进制文本必须逐字符一致。 */
static int compare_public_decimal(asnber_ctx_t *ctx, const uint8_t *left,
                                  size_t left_size, const uint8_t *right,
                                  size_t right_size)
{
    asnber_pkcs_rsa_public_key_t *left_key = NULL;
    asnber_pkcs_rsa_public_key_t *right_key = NULL;
    const char *left_text = NULL;
    const char *right_text = NULL;
    size_t left_text_size = 0;
    size_t right_text_size = 0;
    int failed = 1;

    if (asnber_pkcs_rsa_public_key_open(ctx, left, left_size, &left_key) !=
            ASNBER_OK ||
        asnber_pkcs_rsa_public_key_open(ctx, right, right_size, &right_key) !=
            ASNBER_OK) {
        goto done;
    }
    if (asnber_pkcs_rsa_public_key_modulus(left_key, &left_text,
                                         &left_text_size) != ASNBER_OK ||
        asnber_pkcs_rsa_public_key_modulus(right_key, &right_text,
                                         &right_text_size) != ASNBER_OK) {
        goto done;
    }
    if (left_text_size != right_text_size ||
        memcmp(left_text, right_text, left_text_size) != 0) {
        goto done;
    }
    if (asnber_pkcs_rsa_public_key_public_exponent(left_key, &left_text,
                                                  &left_text_size) !=
            ASNBER_OK ||
        asnber_pkcs_rsa_public_key_public_exponent(right_key, &right_text,
                                                  &right_text_size) !=
            ASNBER_OK) {
        goto done;
    }
    if (left_text_size != right_text_size ||
        memcmp(left_text, right_text, left_text_size) != 0) {
        goto done;
    }
    failed = 0;

done:
    asnber_pkcs_rsa_public_key_close(right_key);
    asnber_pkcs_rsa_public_key_close(left_key);
    return failed;
}

/*
 * fixture 往返：DOM 取出两段幅值 → builder 重建 → 与 fixture 逐字节一致，
 * 且读侧十进制与原始 fixture 一致（对拍编码侧的长度与符号位）。
 */
static int test_roundtrip_fixture(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_pkcs_rsa_public_key_builder_t *builder = NULL;
    asnber_buf_t encoded;
    uint8_t *modulus = NULL;
    uint8_t *exponent = NULL;
    size_t modulus_size = 0;
    size_t exponent_size = 0;
    int failed = 1;

    memset(&encoded, 0, sizeof(encoded));
    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(read_fixture_bigint(ctx, kKeyRsaPkcs1Public,
                                        kKeyRsaPkcs1PublicSize, 0, &modulus,
                                        &modulus_size) == 0);
    ASNBER_TEST_CHECK(read_fixture_bigint(ctx, kKeyRsaPkcs1Public,
                                        kKeyRsaPkcs1PublicSize, 1, &exponent,
                                        &exponent_size) == 0);

    ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_builder_create(ctx, &builder) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_builder_set_modulus(
                        builder, modulus, modulus_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_builder_set_public_exponent(
                        builder, exponent, exponent_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_builder_encode(builder,
                                                            &encoded) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(encoded.data != NULL);
    ASNBER_TEST_CHECK(encoded.size == kKeyRsaPkcs1PublicSize);
    ASNBER_TEST_CHECK(bytes_equal(encoded.data, encoded.size,
                                kKeyRsaPkcs1Public, kKeyRsaPkcs1PublicSize));
    ASNBER_TEST_CHECK(compare_public_decimal(ctx, kKeyRsaPkcs1Public,
                                           kKeyRsaPkcs1PublicSize,
                                           encoded.data, encoded.size) == 0);

    failed = 0;

    asnber_buf_release(ctx, &encoded);
    asnber_pkcs_rsa_public_key_builder_destroy(builder);
    free(exponent);
    free(modulus);
    asnber_ctx_destroy(ctx);
    return failed;
}

/*
 * 用给定 modulus 幅值与固定 publicExponent = 1 编码，期望输出 expected。
 */
static int expect_public_key(const uint8_t *modulus, size_t modulus_size,
                             const uint8_t *expected, size_t expected_size)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_pkcs_rsa_public_key_builder_t *builder = NULL;
    asnber_buf_t encoded;
    static const uint8_t exponent[] = {0x01};
    int failed = 1;

    memset(&encoded, 0, sizeof(encoded));
    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_builder_create(ctx, &builder) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_builder_set_modulus(
                        builder, modulus, modulus_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_builder_set_public_exponent(
                        builder, exponent, sizeof(exponent)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_builder_encode(builder,
                                                            &encoded) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(bytes_equal(encoded.data, encoded.size, expected,
                                expected_size));

    failed = 0;

    asnber_buf_release(ctx, &encoded);
    asnber_pkcs_rsa_public_key_builder_destroy(builder);
    asnber_ctx_destroy(ctx);
    return failed;
}

/* 零值：内容为单字节 0x00，读侧十进制为 "0"。 */
static int test_zero_magnitude(void)
{
    static const uint8_t zero[] = {0x00};
    static const uint8_t expected[] = {0x30, 0x06, 0x02, 0x01,
                                       0x00, 0x02, 0x01, 0x01};
    asnber_ctx_t *ctx = make_ctx();
    asnber_pkcs_rsa_public_key_t *key = NULL;
    const char *text = NULL;
    size_t text_size = 0;
    int failed = 1;

    ASNBER_TEST_CHECK(expect_public_key(zero, sizeof(zero), expected,
                                      sizeof(expected)) == 0);

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_open(ctx, expected,
                                                  sizeof(expected),
                                                  &key) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_modulus(key, &text,
                                                      &text_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(text_equals(text, text_size, "0"));

    failed = 0;

    asnber_pkcs_rsa_public_key_close(key);
    asnber_ctx_destroy(ctx);
    return failed;
}

/* 冗余前导零：{00,00,01} 规整后与 {01} 完全一致。 */
static int test_redundant_leading_zeros(void)
{
    static const uint8_t padded[] = {0x00, 0x00, 0x01};
    static const uint8_t expected[] = {0x30, 0x06, 0x02, 0x01,
                                       0x01, 0x02, 0x01, 0x01};

    return expect_public_key(padded, sizeof(padded), expected,
                             sizeof(expected));
}

/* 最高位为 1：内容补前导 0x00，读侧十进制为 "128"。 */
static int test_high_bit_magnitude(void)
{
    static const uint8_t high_bit[] = {0x80};
    static const uint8_t expected[] = {0x30, 0x07, 0x02, 0x02,
                                       0x00, 0x80, 0x02, 0x01, 0x01};
    asnber_ctx_t *ctx = make_ctx();
    asnber_pkcs_rsa_public_key_t *key = NULL;
    const char *text = NULL;
    size_t text_size = 0;
    int failed = 1;

    ASNBER_TEST_CHECK(expect_public_key(high_bit, sizeof(high_bit), expected,
                                      sizeof(expected)) == 0);

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_open(ctx, expected,
                                                  sizeof(expected),
                                                  &key) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_modulus(key, &text,
                                                      &text_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(text_equals(text, text_size, "128"));

    failed = 0;

    asnber_pkcs_rsa_public_key_close(key);
    asnber_ctx_destroy(ctx);
    return failed;
}

/* 上限 8192 字节可编码，8193 字节按输入上限拒绝。 */
static int test_input_limit(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_pkcs_rsa_public_key_builder_t *builder = NULL;
    asnber_buf_t encoded;
    uint8_t *buffer = NULL;
    int failed = 1;

    memset(&encoded, 0, sizeof(encoded));
    ASNBER_TEST_CHECK(ctx != NULL);
    buffer = (uint8_t *)malloc(kBigIntegerLimit + 1);
    ASNBER_TEST_CHECK(buffer != NULL);
    memset(buffer, 0x01, kBigIntegerLimit + 1);

    ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_builder_create(ctx, &builder) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_builder_set_modulus(
                        builder, buffer, kBigIntegerLimit + 1) ==
                    ASNBER_E_INPUT_LIMIT);
    ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_builder_set_modulus(
                        builder, buffer, kBigIntegerLimit) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_builder_set_public_exponent(
                        builder, buffer, 1) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_builder_encode(builder,
                                                            &encoded) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(encoded.data != NULL && encoded.size > kBigIntegerLimit);

    failed = 0;

    asnber_buf_release(ctx, &encoded);
    asnber_pkcs_rsa_public_key_builder_destroy(builder);
    free(buffer);
    asnber_ctx_destroy(ctx);
    return failed;
}

static int test_negative_arguments(void)
{
    static const uint8_t one[] = {0x01};
    asnber_ctx_t *ctx = make_ctx();
    asnber_pkcs_rsa_public_key_builder_t *builder = NULL;
    asnber_buf_t encoded;

    memset(&encoded, 0, sizeof(encoded));
    ASNBER_TEST_CHECK(ctx != NULL);

    ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_builder_create(NULL, &builder) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(builder == NULL);
    ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_builder_create(ctx, NULL) ==
                    ASNBER_E_INVALID_ARG);
    asnber_pkcs_rsa_public_key_builder_destroy(NULL);

    ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_builder_set_modulus(
                        NULL, one, sizeof(one)) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_builder_set_public_exponent(
                        NULL, one, sizeof(one)) == ASNBER_E_INVALID_ARG);

    ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_builder_create(ctx, &builder) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_builder_set_modulus(
                        builder, NULL, 0) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_builder_set_modulus(
                        builder, one, 0) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_builder_set_public_exponent(
                        builder, NULL, 1) == ASNBER_E_INVALID_ARG);

    /* 必填缺失：先缺两个、再补一个、最后齐全。失败时 out_buf 清零。 */
    {
        asnber_buf_t buf;
        buf.data = (uint8_t *)(uintptr_t)1;
        buf.size = 1;
        buf.capacity = 1;

        ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_builder_encode(
                            builder, &buf) == ASNBER_E_INVALID_STATE);
        ASNBER_TEST_CHECK(buf.data == NULL && buf.size == 0 &&
                        buf.capacity == 0);
        ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_builder_set_modulus(
                            builder, one, sizeof(one)) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_builder_encode(
                            builder, &buf) == ASNBER_E_INVALID_STATE);
        ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_builder_set_public_exponent(
                            builder, one, sizeof(one)) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_builder_encode(builder,
                                                                &buf) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(buf.data != NULL && buf.size > 0);
        asnber_buf_release(ctx, &buf);
    }

    ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_builder_set_modulus(
                        builder, one, sizeof(one)) == ASNBER_E_INVALID_STATE);
    ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_builder_set_public_exponent(
                        builder, one, sizeof(one)) == ASNBER_E_INVALID_STATE);

    ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_builder_encode(NULL, &encoded) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_builder_encode(builder, NULL) ==
                    ASNBER_E_INVALID_ARG);

    asnber_pkcs_rsa_public_key_builder_destroy(builder);
    asnber_ctx_destroy(ctx);
    return 0;
}

typedef asnber_err_t (*private_setter_fn)(asnber_pkcs_rsa_private_key_builder_t *,
                                        const uint8_t *, size_t);
typedef asnber_err_t (*private_getter_fn)(const asnber_pkcs_rsa_private_key_t *,
                                        const char **, size_t *);

/* 与 RSAPrivateKey 的字段顺序一致（version 之后）。 */
static const private_setter_fn kPrivateSetters[kPrivateFieldCount] = {
    asnber_pkcs_rsa_private_key_builder_set_modulus,
    asnber_pkcs_rsa_private_key_builder_set_public_exponent,
    asnber_pkcs_rsa_private_key_builder_set_private_exponent,
    asnber_pkcs_rsa_private_key_builder_set_prime1,
    asnber_pkcs_rsa_private_key_builder_set_prime2,
    asnber_pkcs_rsa_private_key_builder_set_exponent1,
    asnber_pkcs_rsa_private_key_builder_set_exponent2,
    asnber_pkcs_rsa_private_key_builder_set_coefficient};

static const private_getter_fn kPrivateGetters[kPrivateFieldCount] = {
    asnber_pkcs_rsa_private_key_modulus,
    asnber_pkcs_rsa_private_key_public_exponent,
    asnber_pkcs_rsa_private_key_private_exponent,
    asnber_pkcs_rsa_private_key_prime1,
    asnber_pkcs_rsa_private_key_prime2,
    asnber_pkcs_rsa_private_key_exponent1,
    asnber_pkcs_rsa_private_key_exponent2,
    asnber_pkcs_rsa_private_key_coefficient};

/* 两份 DER 的 8 个十进制字段与 version 必须逐字符一致。 */
static int compare_private_decimal(asnber_ctx_t *ctx, const uint8_t *left,
                                   size_t left_size, const uint8_t *right,
                                   size_t right_size)
{
    asnber_pkcs_rsa_private_key_t *left_key = NULL;
    asnber_pkcs_rsa_private_key_t *right_key = NULL;
    int64_t left_version = -1;
    int64_t right_version = -1;
    int failed = 1;

    if (asnber_pkcs_rsa_private_key_open(ctx, left, left_size, &left_key) !=
            ASNBER_OK ||
        asnber_pkcs_rsa_private_key_open(ctx, right, right_size, &right_key) !=
            ASNBER_OK) {
        goto done;
    }
    if (asnber_pkcs_rsa_private_key_version(left_key, &left_version) !=
            ASNBER_OK ||
        asnber_pkcs_rsa_private_key_version(right_key, &right_version) !=
            ASNBER_OK ||
        left_version != right_version) {
        goto done;
    }
    for (size_t i = 0; i < kPrivateFieldCount; ++i) {
        const char *left_text = NULL;
        const char *right_text = NULL;
        size_t left_text_size = 0;
        size_t right_text_size = 0;

        if (kPrivateGetters[i](left_key, &left_text, &left_text_size) !=
                ASNBER_OK ||
            kPrivateGetters[i](right_key, &right_text, &right_text_size) !=
                ASNBER_OK ||
            left_text_size != right_text_size ||
            memcmp(left_text, right_text, left_text_size) != 0) {
            goto done;
        }
    }
    failed = 0;

done:
    asnber_pkcs_rsa_private_key_close(right_key);
    asnber_pkcs_rsa_private_key_close(left_key);
    return failed;
}

/*
 * 私钥 fixture 往返：取 8 段幅值 → builder 重建（version 由模块写 0）→
 * 与 fixture 逐字节一致，且十进制字段与原始 fixture 一致。
 */
static int test_private_roundtrip_fixture(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_pkcs_rsa_private_key_builder_t *builder = NULL;
    asnber_buf_t encoded;
    uint8_t *magnitude[kPrivateFieldCount];
    size_t magnitude_size[kPrivateFieldCount];
    int failed = 1;

    memset(&encoded, 0, sizeof(encoded));
    memset(magnitude, 0, sizeof(magnitude));
    memset(magnitude_size, 0, sizeof(magnitude_size));
    ASNBER_TEST_CHECK(ctx != NULL);

    for (size_t i = 0; i < kPrivateFieldCount; ++i) {
        /* 顶层第 0 个节点是 version，其余按字段顺序排列。 */
        ASNBER_TEST_CHECK(read_fixture_bigint(ctx, kKeyRsaPkcs1Private,
                                            kKeyRsaPkcs1PrivateSize, i + 1,
                                            &magnitude[i],
                                            &magnitude_size[i]) == 0);
    }

    ASNBER_TEST_CHECK(asnber_pkcs_rsa_private_key_builder_create(ctx, &builder) ==
                    ASNBER_OK);
    for (size_t i = 0; i < kPrivateFieldCount; ++i) {
        ASNBER_TEST_CHECK(kPrivateSetters[i](builder, magnitude[i],
                                           magnitude_size[i]) == ASNBER_OK);
    }
    ASNBER_TEST_CHECK(asnber_pkcs_rsa_private_key_builder_encode(builder,
                                                             &encoded) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(encoded.data != NULL);
    ASNBER_TEST_CHECK(encoded.size == kKeyRsaPkcs1PrivateSize);
    ASNBER_TEST_CHECK(bytes_equal(encoded.data, encoded.size,
                                kKeyRsaPkcs1Private, kKeyRsaPkcs1PrivateSize));
    ASNBER_TEST_CHECK(compare_private_decimal(ctx, kKeyRsaPkcs1Private,
                                            kKeyRsaPkcs1PrivateSize,
                                            encoded.data, encoded.size) == 0);

    failed = 0;

    asnber_buf_release(ctx, &encoded);
    asnber_pkcs_rsa_private_key_builder_destroy(builder);
    for (size_t i = 0; i < kPrivateFieldCount; ++i) {
        free(magnitude[i]);
    }
    asnber_ctx_destroy(ctx);
    return failed;
}

/* 逐一缺 8 个必填字段之一：encode 返回 INVALID_STATE 并清零 out_buf。 */
static int test_private_missing_field(void)
{
    static const uint8_t one[] = {0x01};
    asnber_ctx_t *ctx = make_ctx();

    ASNBER_TEST_CHECK(ctx != NULL);
    for (size_t skip = 0; skip < kPrivateFieldCount; ++skip) {
        asnber_pkcs_rsa_private_key_builder_t *builder = NULL;
        asnber_buf_t buf;
        buf.data = (uint8_t *)(uintptr_t)1;
        buf.size = 1;
        buf.capacity = 1;

        ASNBER_TEST_CHECK(asnber_pkcs_rsa_private_key_builder_create(
                            ctx, &builder) == ASNBER_OK);
        for (size_t i = 0; i < kPrivateFieldCount; ++i) {
            if (i != skip) {
                ASNBER_TEST_CHECK(kPrivateSetters[i](builder, one,
                                                   sizeof(one)) == ASNBER_OK);
            }
        }
        ASNBER_TEST_CHECK(asnber_pkcs_rsa_private_key_builder_encode(builder,
                                                                 &buf) ==
                        ASNBER_E_INVALID_STATE);
        ASNBER_TEST_CHECK(buf.data == NULL && buf.size == 0 &&
                        buf.capacity == 0);
        asnber_pkcs_rsa_private_key_builder_destroy(builder);
    }

    asnber_ctx_destroy(ctx);
    return 0;
}

static int test_private_negative_arguments(void)
{
    static const uint8_t one[] = {0x01};
    asnber_ctx_t *ctx = make_ctx();
    asnber_pkcs_rsa_private_key_builder_t *builder = NULL;
    asnber_buf_t encoded;

    memset(&encoded, 0, sizeof(encoded));
    ASNBER_TEST_CHECK(ctx != NULL);

    ASNBER_TEST_CHECK(asnber_pkcs_rsa_private_key_builder_create(NULL, &builder) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(builder == NULL);
    ASNBER_TEST_CHECK(asnber_pkcs_rsa_private_key_builder_create(ctx, NULL) ==
                    ASNBER_E_INVALID_ARG);
    asnber_pkcs_rsa_private_key_builder_destroy(NULL);

    ASNBER_TEST_CHECK(asnber_pkcs_rsa_private_key_builder_set_modulus(
                        NULL, one, sizeof(one)) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkcs_rsa_private_key_builder_encode(NULL, &encoded) ==
                    ASNBER_E_INVALID_ARG);

    ASNBER_TEST_CHECK(asnber_pkcs_rsa_private_key_builder_create(ctx, &builder) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs_rsa_private_key_builder_set_modulus(
                        builder, NULL, 0) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkcs_rsa_private_key_builder_set_modulus(
                        builder, one, 0) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkcs_rsa_private_key_builder_encode(builder, NULL) ==
                    ASNBER_E_INVALID_ARG);

    ASNBER_TEST_CHECK(asnber_pkcs_rsa_private_key_builder_set_modulus(
                        builder, one, sizeof(one)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs_rsa_private_key_builder_set_modulus(
                        builder, one, sizeof(one)) == ASNBER_E_INVALID_STATE);

    asnber_pkcs_rsa_private_key_builder_destroy(builder);
    asnber_ctx_destroy(ctx);
    return 0;
}

int main(void)
{
    if (test_roundtrip_fixture() != 0) {
        return 1;
    }
    if (test_zero_magnitude() != 0) {
        return 1;
    }
    if (test_redundant_leading_zeros() != 0) {
        return 1;
    }
    if (test_high_bit_magnitude() != 0) {
        return 1;
    }
    if (test_input_limit() != 0) {
        return 1;
    }
    if (test_negative_arguments() != 0) {
        return 1;
    }
    if (test_private_roundtrip_fixture() != 0) {
        return 1;
    }
    if (test_private_missing_field() != 0) {
        return 1;
    }
    if (test_private_negative_arguments() != 0) {
        return 1;
    }
    return 0;
}
