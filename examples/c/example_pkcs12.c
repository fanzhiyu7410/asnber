/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * PKCS#12 参考集成。每步单独创建上下文，用完 asnber_ctx_destroy：
 *   1. 打开样例 PFX，读 version
 *   2. 编一个最小 PFX：空 SafeContents 放进 AuthenticatedSafe，
 *      再包成 data ContentInfo。不计算 MAC、不加密。
 *   3. 读回编出的 PFX
 */
#include <asnber/asnber.h>
#include <asnber/pkcs12/pkcs12.h>

#include <stdio.h>
#include <string.h>

#include "pfx_rsa_unencrypted.h"

#define STEP_POOL ((size_t)256u * 1024u)
#define DER_CAP ((size_t)4096u)

static const char kDataOid[] = "1.2.840.113549.1.7.1";
static const uint8_t kEmptySafeContents[] = {0x30, 0x00};

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

static int wrap_octet_string(const uint8_t *data, size_t size, uint8_t *out,
                             size_t cap, size_t *out_size)
{
    if (size >= 0x80u || 2u + size > cap) {
        return 1;
    }
    out[0] = 0x04;
    out[1] = (uint8_t)size;
    if (size != 0) {
        memcpy(out + 2, data, size);
    }
    *out_size = 2u + size;
    return 0;
}

static int open_sample(int64_t *out_version)
{
    asnber_ctx_t *ctx = create_ctx();
    asnber_pkcs12_pfx_t *pfx = NULL;
    asnber_err_t err;

    if (ctx == NULL) {
        fprintf(stderr, "pfx sample: asnber_ctx_create failed\n");
        return 1;
    }
    err = asnber_pkcs12_pfx_open(ctx, kPfxRsaUnencrypted, kPfxRsaUnencryptedSize,
                               &pfx);
    if (err == ASNBER_OK) {
        err = asnber_pkcs12_pfx_version(pfx, out_version);
    }
    asnber_pkcs12_pfx_close(pfx);
    asnber_ctx_destroy(ctx);
    if (err != ASNBER_OK) {
        fprintf(stderr, "pfx sample: %d\n", (int)err);
        return 1;
    }
    return 0;
}

static int encode_pfx(unsigned char *der, size_t *der_size)
{
    asnber_ctx_t *ctx = create_ctx();
    asnber_pkcs12_authenticated_safe_builder_t *safe_builder = NULL;
    asnber_pkcs12_pfx_builder_t *pfx_builder = NULL;
    asnber_buf_t safe_der;
    asnber_buf_t pfx_der;
    uint8_t content_tlv[DER_CAP];
    size_t content_size = 0;
    asnber_err_t err = ASNBER_OK;
    int failed = 0;

    memset(&safe_der, 0, sizeof(safe_der));
    memset(&pfx_der, 0, sizeof(pfx_der));
    if (ctx == NULL) {
        fprintf(stderr, "pfx encode: asnber_ctx_create failed\n");
        return 1;
    }
    err = asnber_pkcs12_authenticated_safe_builder_create(ctx, &safe_builder);
    if (err == ASNBER_OK) {
        err = asnber_pkcs12_authenticated_safe_builder_add_data(
            safe_builder, kEmptySafeContents, sizeof(kEmptySafeContents));
    }
    if (err == ASNBER_OK) {
        err = asnber_pkcs12_authenticated_safe_builder_encode(safe_builder,
                                                            &safe_der);
    }
    if (err == ASNBER_OK &&
        wrap_octet_string(safe_der.data, safe_der.size, content_tlv,
                          sizeof(content_tlv), &content_size) != 0) {
        failed = 1;
    }
    if (err == ASNBER_OK && !failed) {
        err = asnber_pkcs12_pfx_builder_create(ctx, &pfx_builder);
    }
    if (err == ASNBER_OK && !failed) {
        err = asnber_pkcs12_pfx_builder_set_version(pfx_builder, 3);
    }
    if (err == ASNBER_OK && !failed) {
        err = asnber_pkcs12_pfx_builder_set_auth_safe(pfx_builder, kDataOid,
                                                    content_tlv, content_size);
    }
    if (err == ASNBER_OK && !failed) {
        err = asnber_pkcs12_pfx_builder_encode(pfx_builder, &pfx_der);
    }
    if (err == ASNBER_OK && !failed &&
        (pfx_der.data == NULL || pfx_der.size == 0 || pfx_der.size > DER_CAP)) {
        failed = 1;
    }
    if (err == ASNBER_OK && !failed) {
        memcpy(der, pfx_der.data, pfx_der.size);
        *der_size = pfx_der.size;
    }
    asnber_pkcs12_pfx_builder_destroy(pfx_builder);
    asnber_pkcs12_authenticated_safe_builder_destroy(safe_builder);
    (void)asnber_buf_release(ctx, &pfx_der);
    (void)asnber_buf_release(ctx, &safe_der);
    asnber_ctx_destroy(ctx);
    if (failed || err != ASNBER_OK) {
        fprintf(stderr, "pfx encode: %d\n", (int)err);
        return 1;
    }
    return 0;
}

static int open_encoded(const unsigned char *der, size_t der_size,
                        int64_t *out_version)
{
    asnber_ctx_t *ctx = create_ctx();
    asnber_pkcs12_pfx_t *pfx = NULL;
    int mac_present = -1;
    asnber_err_t err;

    if (ctx == NULL) {
        fprintf(stderr, "pfx readback: asnber_ctx_create failed\n");
        return 1;
    }
    err = asnber_pkcs12_pfx_open(ctx, der, der_size, &pfx);
    if (err == ASNBER_OK) {
        err = asnber_pkcs12_pfx_version(pfx, out_version);
    }
    if (err == ASNBER_OK) {
        err = asnber_pkcs12_pfx_mac_present(pfx, &mac_present);
    }
    if (err == ASNBER_OK && (*out_version != 3 || mac_present != 0)) {
        err = ASNBER_E_INVALID_VALUE;
    }
    asnber_pkcs12_pfx_close(pfx);
    asnber_ctx_destroy(ctx);
    if (err != ASNBER_OK) {
        fprintf(stderr, "pfx readback: %d\n", (int)err);
        return 1;
    }
    return 0;
}

int main(void)
{
    int64_t sample_version = -1;
    int64_t encoded_version = -1;
    unsigned char der[DER_CAP];
    size_t der_size = 0;

    if (open_sample(&sample_version) != 0 || encode_pfx(der, &der_size) != 0 ||
        open_encoded(der, der_size, &encoded_version) != 0) {
        return 1;
    }
    printf("sample PFX version=%lld\n", (long long)sample_version);
    printf("encoded PFX=%zu bytes, version=%lld\n", der_size,
           (long long)encoded_version);
    return 0;
}
