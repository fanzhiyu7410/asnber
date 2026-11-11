/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * PKCS#1 参考集成。每步单独创建上下文，用完 asnber_ctx_destroy，
 * 下一步再复用同一块静态池：
 *   1. 打开样例 RSAPublicKey，读公开指数
 *   2. 编一把最小公钥并读回
 *   3. 打开样例 RSAPrivateKey，读 version
 *   4. 编一把最小私钥并读回
 *
 * 库不做 RSA 运算。大整数按大端无符号幅值传入。
 */
#include <asnber/asnber.h>
#include <asnber/pkcs1/pkcs1.h>

#include <stdio.h>
#include <string.h>

#include "key_rsa_pkcs1_private.h"
#include "key_rsa_pkcs1_public.h"

#define STEP_POOL ((size_t)256u * 1024u)
#define DER_CAP ((size_t)4096u)

static const uint8_t kOne[] = {0x01};
static const uint8_t kExponent[] = {0x01, 0x00, 0x01}; /* 65537 */

static union {
    long double align_ld;
    void *align_ptr;
    unsigned char bytes[STEP_POOL];
} g_pool;

static asnber_ctx_t *create_ctx(void)
{
    asnber_ctx_config_t config;
    asnber_ctx_t *ctx = NULL;

    asnber_ctx_config_init(&config);
    config.static_pool = g_pool.bytes;
    config.static_pool_size = sizeof(g_pool.bytes);
    if (asnber_ctx_create(&config, &ctx) != ASNBER_OK) {
        return NULL;
    }
    return ctx;
}

static int copy_out(const asnber_buf_t *encoded, unsigned char *dest,
                    size_t *dest_size)
{
    if (encoded->data == NULL || encoded->size == 0 ||
        encoded->size > DER_CAP) {
        return 1;
    }
    memcpy(dest, encoded->data, encoded->size);
    *dest_size = encoded->size;
    return 0;
}

static int text_is(const char *text, size_t size, const char *expected)
{
    const size_t expected_size = strlen(expected);
    return text != NULL && size == expected_size &&
           memcmp(text, expected, expected_size) == 0;
}

static int open_public_sample(void)
{
    asnber_ctx_t *ctx = create_ctx();
    asnber_pkcs_rsa_public_key_t *key = NULL;
    const char *exponent = NULL;
    size_t exponent_size = 0;
    asnber_err_t err;

    if (ctx == NULL) {
        fprintf(stderr, "public sample: asnber_ctx_create failed\n");
        return 1;
    }
    err = asnber_pkcs_rsa_public_key_open(ctx, kKeyRsaPkcs1Public,
                                        kKeyRsaPkcs1PublicSize, &key);
    if (err == ASNBER_OK) {
        err = asnber_pkcs_rsa_public_key_public_exponent(key, &exponent,
                                                       &exponent_size);
    }
    if (err == ASNBER_OK && !text_is(exponent, exponent_size, "65537")) {
        err = ASNBER_E_INVALID_VALUE;
    }
    asnber_pkcs_rsa_public_key_close(key);
    asnber_ctx_destroy(ctx);
    if (err != ASNBER_OK) {
        fprintf(stderr, "public sample: %d\n", (int)err);
        return 1;
    }
    return 0;
}

static int encode_public(size_t *out_size)
{
    asnber_ctx_t *ctx = create_ctx();
    asnber_pkcs_rsa_public_key_builder_t *builder = NULL;
    asnber_buf_t encoded;
    unsigned char der[DER_CAP];
    size_t der_size = 0;
    asnber_err_t err = ASNBER_OK;
    int failed = 0;

    memset(&encoded, 0, sizeof(encoded));
    if (ctx == NULL) {
        fprintf(stderr, "public encode: asnber_ctx_create failed\n");
        return 1;
    }
    err = asnber_pkcs_rsa_public_key_builder_create(ctx, &builder);
    if (err == ASNBER_OK) {
        err = asnber_pkcs_rsa_public_key_builder_set_modulus(builder, kOne,
                                                           sizeof(kOne));
    }
    if (err == ASNBER_OK) {
        err = asnber_pkcs_rsa_public_key_builder_set_public_exponent(
            builder, kExponent, sizeof(kExponent));
    }
    if (err == ASNBER_OK) {
        err = asnber_pkcs_rsa_public_key_builder_encode(builder, &encoded);
    }
    if (err == ASNBER_OK && copy_out(&encoded, der, &der_size) != 0) {
        failed = 1;
    }
    asnber_pkcs_rsa_public_key_builder_destroy(builder);
    (void)asnber_buf_release(ctx, &encoded);
    asnber_ctx_destroy(ctx);
    if (failed || err != ASNBER_OK) {
        fprintf(stderr, "public encode: %d\n", (int)err);
        return 1;
    }

    ctx = create_ctx();
    if (ctx == NULL) {
        fprintf(stderr, "public readback: asnber_ctx_create failed\n");
        return 1;
    }
    {
        asnber_pkcs_rsa_public_key_t *key = NULL;
        const char *exponent = NULL;
        size_t exponent_size = 0;

        err = asnber_pkcs_rsa_public_key_open(ctx, der, der_size, &key);
        if (err == ASNBER_OK) {
            err = asnber_pkcs_rsa_public_key_public_exponent(key, &exponent,
                                                           &exponent_size);
        }
        if (err == ASNBER_OK && !text_is(exponent, exponent_size, "65537")) {
            err = ASNBER_E_INVALID_VALUE;
        }
        asnber_pkcs_rsa_public_key_close(key);
        asnber_ctx_destroy(ctx);
    }
    if (err != ASNBER_OK) {
        fprintf(stderr, "public readback: %d\n", (int)err);
        return 1;
    }
    *out_size = der_size;
    return 0;
}

static int open_private_sample(int64_t *out_version)
{
    asnber_ctx_t *ctx = create_ctx();
    asnber_pkcs_rsa_private_key_t *key = NULL;
    asnber_err_t err;

    if (ctx == NULL) {
        fprintf(stderr, "private sample: asnber_ctx_create failed\n");
        return 1;
    }
    err = asnber_pkcs_rsa_private_key_open(ctx, kKeyRsaPkcs1Private,
                                         kKeyRsaPkcs1PrivateSize, &key);
    if (err == ASNBER_OK) {
        err = asnber_pkcs_rsa_private_key_version(key, out_version);
    }
    asnber_pkcs_rsa_private_key_close(key);
    asnber_ctx_destroy(ctx);
    if (err != ASNBER_OK) {
        fprintf(stderr, "private sample: %d\n", (int)err);
        return 1;
    }
    return 0;
}

static int encode_private(size_t *out_size)
{
    asnber_ctx_t *ctx = create_ctx();
    asnber_pkcs_rsa_private_key_builder_t *builder = NULL;
    asnber_buf_t encoded;
    unsigned char der[DER_CAP];
    size_t der_size = 0;
    asnber_err_t err = ASNBER_OK;
    int failed = 0;

    memset(&encoded, 0, sizeof(encoded));
    if (ctx == NULL) {
        fprintf(stderr, "private encode: asnber_ctx_create failed\n");
        return 1;
    }
    err = asnber_pkcs_rsa_private_key_builder_create(ctx, &builder);
    if (err == ASNBER_OK) {
        err = asnber_pkcs_rsa_private_key_builder_set_modulus(builder, kOne,
                                                            sizeof(kOne));
    }
    if (err == ASNBER_OK) {
        err = asnber_pkcs_rsa_private_key_builder_set_public_exponent(
            builder, kExponent, sizeof(kExponent));
    }
    if (err == ASNBER_OK) {
        err = asnber_pkcs_rsa_private_key_builder_set_private_exponent(
            builder, kOne, sizeof(kOne));
    }
    if (err == ASNBER_OK) {
        err = asnber_pkcs_rsa_private_key_builder_set_prime1(builder, kOne,
                                                           sizeof(kOne));
    }
    if (err == ASNBER_OK) {
        err = asnber_pkcs_rsa_private_key_builder_set_prime2(builder, kOne,
                                                           sizeof(kOne));
    }
    if (err == ASNBER_OK) {
        err = asnber_pkcs_rsa_private_key_builder_set_exponent1(builder, kOne,
                                                              sizeof(kOne));
    }
    if (err == ASNBER_OK) {
        err = asnber_pkcs_rsa_private_key_builder_set_exponent2(builder, kOne,
                                                              sizeof(kOne));
    }
    if (err == ASNBER_OK) {
        err = asnber_pkcs_rsa_private_key_builder_set_coefficient(builder, kOne,
                                                                sizeof(kOne));
    }
    if (err == ASNBER_OK) {
        err = asnber_pkcs_rsa_private_key_builder_encode(builder, &encoded);
    }
    if (err == ASNBER_OK && copy_out(&encoded, der, &der_size) != 0) {
        failed = 1;
    }
    asnber_pkcs_rsa_private_key_builder_destroy(builder);
    (void)asnber_buf_release(ctx, &encoded);
    asnber_ctx_destroy(ctx);
    if (failed || err != ASNBER_OK) {
        fprintf(stderr, "private encode: %d\n", (int)err);
        return 1;
    }

    ctx = create_ctx();
    if (ctx == NULL) {
        fprintf(stderr, "private readback: asnber_ctx_create failed\n");
        return 1;
    }
    {
        asnber_pkcs_rsa_private_key_t *key = NULL;
        int64_t version = -1;

        err = asnber_pkcs_rsa_private_key_open(ctx, der, der_size, &key);
        if (err == ASNBER_OK) {
            err = asnber_pkcs_rsa_private_key_version(key, &version);
        }
        if (err == ASNBER_OK && version != 0) {
            err = ASNBER_E_INVALID_VALUE;
        }
        asnber_pkcs_rsa_private_key_close(key);
        asnber_ctx_destroy(ctx);
    }
    if (err != ASNBER_OK) {
        fprintf(stderr, "private readback: %d\n", (int)err);
        return 1;
    }
    *out_size = der_size;
    return 0;
}

int main(void)
{
    int64_t private_version = -1;
    size_t public_size = 0;
    size_t private_size = 0;

    if (open_public_sample() != 0 || encode_public(&public_size) != 0 ||
        open_private_sample(&private_version) != 0 ||
        encode_private(&private_size) != 0) {
        return 1;
    }
    printf("sample private version=%lld\n", (long long)private_version);
    printf("encoded public=%zu bytes, encoded private=%zu bytes\n",
           public_size, private_size);
    return 0;
}
