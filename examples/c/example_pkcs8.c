/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * PKCS#8 参考集成。每步单独创建上下文，用完 asnber_ctx_destroy：
 *   1. 打开样例 PrivateKeyInfo
 *   2. 打开样例 EncryptedPrivateKeyInfo（不解密）
 *   3. 编一条最小 PrivateKeyInfo 并读回
 *
 * privateKey 是调用方给的字节，库不解析密钥。
 */
#include <asnber/asnber.h>
#include <asnber/pkcs8/pkcs8.h>

#include <stdio.h>
#include <string.h>

#include "key_rsa_pkcs8.h"
#include "key_rsa_pkcs8_encrypted.h"

#define STEP_POOL ((size_t)256u * 1024u)
#define DER_CAP ((size_t)4096u)

static const uint8_t kNullParams[] = {0x05, 0x00};
static const uint8_t kKeyBytes[] = {0x01};
static const char kRsaOid[] = "1.2.840.113549.1.1.1";

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

static int text_is(const char *text, size_t size, const char *expected)
{
    const size_t expected_size = strlen(expected);
    return text != NULL && size == expected_size &&
           memcmp(text, expected, expected_size) == 0;
}

static int open_info_sample(int64_t *out_version)
{
    asnber_ctx_t *ctx = create_ctx();
    asnber_pkcs_private_key_info_t *info = NULL;
    const char *oid = NULL;
    size_t oid_size = 0;
    asnber_err_t err;

    if (ctx == NULL) {
        fprintf(stderr, "pkcs8 sample: asnber_ctx_create failed\n");
        return 1;
    }
    err = asnber_pkcs_private_key_info_open(ctx, kKeyRsaPkcs8, kKeyRsaPkcs8Size,
                                          &info);
    if (err == ASNBER_OK) {
        err = asnber_pkcs_private_key_info_version(info, out_version);
    }
    if (err == ASNBER_OK) {
        err = asnber_pkcs_private_key_info_algorithm_oid(info, &oid, &oid_size);
    }
    if (err == ASNBER_OK && !text_is(oid, oid_size, kRsaOid)) {
        err = ASNBER_E_INVALID_VALUE;
    }
    asnber_pkcs_private_key_info_close(info);
    asnber_ctx_destroy(ctx);
    if (err != ASNBER_OK) {
        fprintf(stderr, "pkcs8 sample: %d\n", (int)err);
        return 1;
    }
    return 0;
}

static int open_encrypted_sample(void)
{
    asnber_ctx_t *ctx = create_ctx();
    asnber_pkcs_encrypted_private_key_info_t *info = NULL;
    const char *oid = NULL;
    size_t oid_size = 0;
    const uint8_t *encrypted = NULL;
    size_t encrypted_size = 0;
    asnber_err_t err;

    if (ctx == NULL) {
        fprintf(stderr, "pkcs8 encrypted: asnber_ctx_create failed\n");
        return 1;
    }
    err = asnber_pkcs_encrypted_private_key_info_open(
        ctx, kKeyRsaPkcs8Encrypted, kKeyRsaPkcs8EncryptedSize, &info);
    if (err == ASNBER_OK) {
        err = asnber_pkcs_encrypted_private_key_info_algorithm_oid(info, &oid,
                                                                &oid_size);
    }
    if (err == ASNBER_OK) {
        err = asnber_pkcs_encrypted_private_key_info_encrypted_data(
            info, &encrypted, &encrypted_size);
    }
    if (err == ASNBER_OK && (oid == NULL || oid_size == 0 || encrypted == NULL ||
                           encrypted_size == 0)) {
        err = ASNBER_E_INVALID_VALUE;
    }
    asnber_pkcs_encrypted_private_key_info_close(info);
    asnber_ctx_destroy(ctx);
    if (err != ASNBER_OK) {
        fprintf(stderr, "pkcs8 encrypted: %d\n", (int)err);
        return 1;
    }
    return 0;
}

static int encode_info(size_t *out_size)
{
    asnber_ctx_t *ctx = create_ctx();
    asnber_pkcs_private_key_info_builder_t *builder = NULL;
    asnber_buf_t encoded;
    unsigned char der[DER_CAP];
    size_t der_size = 0;
    asnber_err_t err = ASNBER_OK;
    int failed = 0;

    memset(&encoded, 0, sizeof(encoded));
    if (ctx == NULL) {
        fprintf(stderr, "pkcs8 encode: asnber_ctx_create failed\n");
        return 1;
    }
    err = asnber_pkcs_private_key_info_builder_create(ctx, &builder);
    if (err == ASNBER_OK) {
        err = asnber_pkcs_private_key_info_builder_set_version(builder, 0);
    }
    if (err == ASNBER_OK) {
        err = asnber_pkcs_private_key_info_builder_set_algorithm(
            builder, kRsaOid, kNullParams, sizeof(kNullParams));
    }
    if (err == ASNBER_OK) {
        err = asnber_pkcs_private_key_info_builder_set_private_key(
            builder, kKeyBytes, sizeof(kKeyBytes));
    }
    if (err == ASNBER_OK) {
        err = asnber_pkcs_private_key_info_builder_encode(builder, &encoded);
    }
    if (err == ASNBER_OK &&
        (encoded.data == NULL || encoded.size == 0 || encoded.size > DER_CAP)) {
        failed = 1;
    }
    if (err == ASNBER_OK && !failed) {
        memcpy(der, encoded.data, encoded.size);
        der_size = encoded.size;
    }
    asnber_pkcs_private_key_info_builder_destroy(builder);
    (void)asnber_buf_release(ctx, &encoded);
    asnber_ctx_destroy(ctx);
    if (failed || err != ASNBER_OK) {
        fprintf(stderr, "pkcs8 encode: %d\n", (int)err);
        return 1;
    }

    ctx = create_ctx();
    if (ctx == NULL) {
        fprintf(stderr, "pkcs8 readback: asnber_ctx_create failed\n");
        return 1;
    }
    {
        asnber_pkcs_private_key_info_t *info = NULL;
        int64_t version = -1;
        const char *oid = NULL;
        size_t oid_size = 0;

        err = asnber_pkcs_private_key_info_open(ctx, der, der_size, &info);
        if (err == ASNBER_OK) {
            err = asnber_pkcs_private_key_info_version(info, &version);
        }
        if (err == ASNBER_OK) {
            err = asnber_pkcs_private_key_info_algorithm_oid(info, &oid, &oid_size);
        }
        if (err == ASNBER_OK &&
            (version != 0 || !text_is(oid, oid_size, kRsaOid))) {
            err = ASNBER_E_INVALID_VALUE;
        }
        asnber_pkcs_private_key_info_close(info);
        asnber_ctx_destroy(ctx);
    }
    if (err != ASNBER_OK) {
        fprintf(stderr, "pkcs8 readback: %d\n", (int)err);
        return 1;
    }
    *out_size = der_size;
    return 0;
}

int main(void)
{
    int64_t version = -1;
    size_t encoded_size = 0;

    if (open_info_sample(&version) != 0 || open_encrypted_sample() != 0 ||
        encode_info(&encoded_size) != 0) {
        return 1;
    }
    printf("sample PrivateKeyInfo version=%lld\n", (long long)version);
    printf("encoded PrivateKeyInfo=%zu bytes\n", encoded_size);
    return 0;
}
