/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * CMS 参考集成。每步单独创建上下文，用完 asnber_ctx_destroy：
 *   1. 打开样例 SignedData：先开 ContentInfo，再用 content 的内层 TLV
 *      打开 SignedData。内层指针借用外层句柄，两步必须留在同一上下文。
 *   2. 编一条 data ContentInfo 并读回
 *   3. 编一条带一条 ktri 的 EnvelopedData（外层仍是 ContentInfo）并读回
 *
 * 库不签名、不加密、不解密。密钥、IV 和密文都是占位字节。
 */
#include <asnber/asnber.h>
#include <asnber/cms/cms.h>

#include <stdio.h>
#include <string.h>

#include "cms_rsa_minimal.h"

#define STEP_POOL ((size_t)1024u * 1024u)
#define DER_CAP ((size_t)4096u)

static const char kSignedDataOid[] = "1.2.840.113549.1.7.2";
static const char kEnvelopedDataOid[] = "1.2.840.113549.1.7.3";
static const char kDataOid[] = "1.2.840.113549.1.7.1";
static const char kAes256WrapOid[] = "2.16.840.1.101.3.4.1.45";
static const char kAes256CbcOid[] = "2.16.840.1.101.3.4.1.42";

static const uint8_t kPayload[] = {0x01, 0x02, 0x03};
static const uint8_t kSki[] = {0xDE, 0xAD, 0xBE, 0xEF};
static const uint8_t kEncryptedKey[] = {0x11, 0x22};
static const uint8_t kEncryptedContent[] = {0x33, 0x44};
static const uint8_t kIv[] = {
    0x04, 0x10, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

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

static int copy_der(const asnber_buf_t *encoded, unsigned char *dest,
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

static int open_signed_sample(int64_t *out_version)
{
    asnber_ctx_t *ctx = create_ctx();
    asnber_cms_content_info_t *info = NULL;
    asnber_cms_signed_data_t *signed_data = NULL;
    const char *oid = NULL;
    size_t oid_size = 0;
    const uint8_t *content = NULL;
    size_t content_size = 0;
    asnber_err_t err;

    if (ctx == NULL) {
        fprintf(stderr, "signed sample: asnber_ctx_create failed\n");
        return 1;
    }
    err = asnber_cms_content_info_open(ctx, kCmsRsaMinimal, kCmsRsaMinimalSize,
                                     &info);
    if (err == ASNBER_OK) {
        err = asnber_cms_content_info_content_type(info, &oid, &oid_size);
    }
    if (err == ASNBER_OK && !text_is(oid, oid_size, kSignedDataOid)) {
        err = ASNBER_E_INVALID_VALUE;
    }
    if (err == ASNBER_OK) {
        err = asnber_cms_content_info_content(info, &content, &content_size);
    }
    if (err == ASNBER_OK) {
        err = asnber_cms_signed_data_open(ctx, content, content_size,
                                        &signed_data);
    }
    if (err == ASNBER_OK) {
        err = asnber_cms_signed_data_version(signed_data, out_version);
    }
    asnber_cms_signed_data_close(signed_data);
    asnber_cms_content_info_close(info);
    asnber_ctx_destroy(ctx);
    if (err != ASNBER_OK) {
        fprintf(stderr, "signed sample: %d\n", (int)err);
        return 1;
    }
    return 0;
}

static int encode_data(size_t *out_size)
{
    asnber_ctx_t *ctx = create_ctx();
    asnber_cms_content_info_builder_t *builder = NULL;
    asnber_buf_t encoded;
    unsigned char der[DER_CAP];
    size_t der_size = 0;
    asnber_err_t err = ASNBER_OK;
    int failed = 0;

    memset(&encoded, 0, sizeof(encoded));
    if (ctx == NULL) {
        fprintf(stderr, "data encode: asnber_ctx_create failed\n");
        return 1;
    }
    err = asnber_cms_content_info_builder_create(ctx, &builder);
    if (err == ASNBER_OK) {
        err = asnber_cms_content_info_builder_set_content_type(builder, kDataOid);
    }
    if (err == ASNBER_OK) {
        err = asnber_cms_content_info_builder_set_content_octets(
            builder, kPayload, sizeof(kPayload));
    }
    if (err == ASNBER_OK) {
        err = asnber_cms_content_info_builder_encode(builder, &encoded);
    }
    if (err == ASNBER_OK && copy_der(&encoded, der, &der_size) != 0) {
        failed = 1;
    }
    asnber_cms_content_info_builder_destroy(builder);
    (void)asnber_buf_release(ctx, &encoded);
    asnber_ctx_destroy(ctx);
    if (failed || err != ASNBER_OK) {
        fprintf(stderr, "data encode: %d\n", (int)err);
        return 1;
    }

    ctx = create_ctx();
    if (ctx == NULL) {
        fprintf(stderr, "data readback: asnber_ctx_create failed\n");
        return 1;
    }
    {
        asnber_cms_content_info_t *info = NULL;
        const char *oid = NULL;
        size_t oid_size = 0;

        err = asnber_cms_content_info_open(ctx, der, der_size, &info);
        if (err == ASNBER_OK) {
            err = asnber_cms_content_info_content_type(info, &oid, &oid_size);
        }
        if (err == ASNBER_OK && !text_is(oid, oid_size, kDataOid)) {
            err = ASNBER_E_INVALID_VALUE;
        }
        asnber_cms_content_info_close(info);
        asnber_ctx_destroy(ctx);
    }
    if (err != ASNBER_OK) {
        fprintf(stderr, "data readback: %d\n", (int)err);
        return 1;
    }
    *out_size = der_size;
    return 0;
}

static int encode_enveloped(size_t *out_size)
{
    asnber_ctx_t *ctx = create_ctx();
    asnber_cms_enveloped_builder_t *builder = NULL;
    asnber_buf_t encoded;
    unsigned char der[DER_CAP];
    size_t der_size = 0;
    asnber_err_t err = ASNBER_OK;
    int failed = 0;

    memset(&encoded, 0, sizeof(encoded));
    if (ctx == NULL) {
        fprintf(stderr, "enveloped encode: asnber_ctx_create failed\n");
        return 1;
    }
    err = asnber_cms_enveloped_builder_create(ctx, &builder);
    if (err == ASNBER_OK) {
        err = asnber_cms_enveloped_builder_set_version(builder, 2);
    }
    if (err == ASNBER_OK) {
        err = asnber_cms_enveloped_builder_add_ktri(
            builder, 2, ASNBER_CMS_RID_SUBJECT_KEY_IDENTIFIER, kSki, sizeof(kSki),
            NULL, 0, kAes256WrapOid, NULL, 0, kEncryptedKey,
            sizeof(kEncryptedKey));
    }
    if (err == ASNBER_OK) {
        err = asnber_cms_enveloped_builder_set_content_type(builder, kDataOid);
    }
    if (err == ASNBER_OK) {
        err = asnber_cms_enveloped_builder_set_content_encryption_algorithm(
            builder, kAes256CbcOid, kIv, sizeof(kIv));
    }
    if (err == ASNBER_OK) {
        err = asnber_cms_enveloped_builder_set_encrypted_content(
            builder, kEncryptedContent, sizeof(kEncryptedContent));
    }
    if (err == ASNBER_OK) {
        err = asnber_cms_enveloped_builder_encode(builder, &encoded);
    }
    if (err == ASNBER_OK && copy_der(&encoded, der, &der_size) != 0) {
        failed = 1;
    }
    asnber_cms_enveloped_builder_destroy(builder);
    (void)asnber_buf_release(ctx, &encoded);
    asnber_ctx_destroy(ctx);
    if (failed || err != ASNBER_OK) {
        fprintf(stderr, "enveloped encode: %d\n", (int)err);
        return 1;
    }

    ctx = create_ctx();
    if (ctx == NULL) {
        fprintf(stderr, "enveloped readback: asnber_ctx_create failed\n");
        return 1;
    }
    {
        asnber_cms_content_info_t *info = NULL;
        asnber_cms_enveloped_data_t *env = NULL;
        const char *oid = NULL;
        size_t oid_size = 0;
        const uint8_t *content = NULL;
        size_t content_size = 0;
        size_t recipients = 0;

        err = asnber_cms_content_info_open(ctx, der, der_size, &info);
        if (err == ASNBER_OK) {
            err = asnber_cms_content_info_content_type(info, &oid, &oid_size);
        }
        if (err == ASNBER_OK && !text_is(oid, oid_size, kEnvelopedDataOid)) {
            err = ASNBER_E_INVALID_VALUE;
        }
        if (err == ASNBER_OK) {
            err = asnber_cms_content_info_content(info, &content, &content_size);
        }
        if (err == ASNBER_OK) {
            err = asnber_cms_enveloped_data_open(ctx, content, content_size, &env);
        }
        if (err == ASNBER_OK) {
            err = asnber_cms_enveloped_data_recipient_count(env, &recipients);
        }
        if (err == ASNBER_OK && recipients != 1) {
            err = ASNBER_E_INVALID_VALUE;
        }
        asnber_cms_enveloped_data_close(env);
        asnber_cms_content_info_close(info);
        asnber_ctx_destroy(ctx);
    }
    if (err != ASNBER_OK) {
        fprintf(stderr, "enveloped readback: %d\n", (int)err);
        return 1;
    }
    *out_size = der_size;
    return 0;
}

int main(void)
{
    int64_t signed_version = -1;
    size_t data_size = 0;
    size_t enveloped_size = 0;

    if (open_signed_sample(&signed_version) != 0 ||
        encode_data(&data_size) != 0 ||
        encode_enveloped(&enveloped_size) != 0) {
        return 1;
    }
    printf("sample SignedData version=%lld\n", (long long)signed_version);
    printf("encoded data ContentInfo=%zu bytes\n", data_size);
    printf("encoded EnvelopedData ContentInfo=%zu bytes\n", enveloped_size);
    return 0;
}
