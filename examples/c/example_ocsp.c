/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * OCSP 参考集成。每步单独创建上下文，用完 asnber_ctx_destroy：
 *   1. 打开样例 OCSPRequest，读 version 与 request 条数
 *   2. 编一条最小未签名请求
 *   3. 读回编出的请求
 *
 * 库不签名、不验签、不判断证书状态。散列和序列号是样例字节。
 */
#include <asnber/asnber.h>
#include <asnber/ocsp/ocsp_builder.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ocsp_request.h"

#define STEP_POOL ((size_t)256u * 1024u)
#define DER_CAP ((size_t)512u)

static const char kSha1[] = "1.3.14.3.2.26";
static const uint8_t kNullParams[] = {0x05, 0x00};
static const uint8_t kNameHash[20] = {
    0xE3, 0x20, 0x0D, 0xBB, 0xE8, 0x5E, 0xD9, 0x2E, 0x30, 0x5C,
    0x17, 0x42, 0xA5, 0x82, 0x49, 0x68, 0x23, 0x7B, 0x9D, 0xFB,
};
static const uint8_t kKeyHash[20] = {
    0xA8, 0x4A, 0xEF, 0xD4, 0x3E, 0x3A, 0x5A, 0x12, 0x4F, 0x28,
    0xFA, 0x95, 0x0E, 0xC3, 0x7B, 0xFB, 0x0F, 0xDC, 0xA6, 0xD4,
};
static const uint8_t kSerial[20] = {
    0x72, 0x12, 0xAF, 0x38, 0x15, 0x28, 0xA1, 0x36, 0x6D, 0x0B,
    0xFC, 0x55, 0x0F, 0xBA, 0x9B, 0x5D, 0x7E, 0x90, 0xF6, 0x35,
};

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

static int open_sample(uint32_t *out_version, size_t *out_count)
{
    asnber_ctx_t *ctx = create_ctx();
    asnber_ocsp_request_t *request = NULL;
    asnber_err_t err;

    if (ctx == NULL) {
        fprintf(stderr, "ocsp sample: asnber_ctx_create failed\n");
        return 1;
    }
    err = asnber_ocsp_request_open(ctx, kOcspRequest, kOcspRequestSize, &request);
    if (err == ASNBER_OK) {
        err = asnber_ocsp_request_version(request, out_version);
    }
    if (err == ASNBER_OK) {
        err = asnber_ocsp_request_count(request, out_count);
    }
    asnber_ocsp_request_close(request);
    asnber_ctx_destroy(ctx);
    if (err != ASNBER_OK) {
        fprintf(stderr, "ocsp sample: %d\n", (int)err);
        return 1;
    }
    return 0;
}

static int encode_request(unsigned char *der, size_t *der_size)
{
    asnber_ctx_t *ctx = create_ctx();
    asnber_ocsp_request_builder_t *builder = NULL;
    asnber_buf_t encoded;
    asnber_err_t err = ASNBER_OK;

    memset(&encoded, 0, sizeof(encoded));
    if (ctx == NULL) {
        fprintf(stderr, "ocsp encode: asnber_ctx_create failed\n");
        return 1;
    }
    err = asnber_ocsp_request_builder_create(ctx, &builder);
    if (err == ASNBER_OK) {
        err = asnber_ocsp_request_builder_set_version(builder, 0);
    }
    if (err == ASNBER_OK) {
        err = asnber_ocsp_request_builder_add_request(
            builder, kSha1, kNullParams, sizeof(kNullParams), kNameHash,
            sizeof(kNameHash), kKeyHash, sizeof(kKeyHash), kSerial,
            sizeof(kSerial));
    }
    if (err == ASNBER_OK) {
        err = asnber_ocsp_request_builder_encode(builder, &encoded);
    }
    if (err == ASNBER_OK &&
        (encoded.data == NULL || encoded.size == 0 || encoded.size > DER_CAP)) {
        err = ASNBER_E_INVALID_VALUE;
    }
    if (err == ASNBER_OK) {
        memcpy(der, encoded.data, encoded.size);
        *der_size = encoded.size;
    }
    asnber_ocsp_request_builder_destroy(builder);
    (void)asnber_buf_release(ctx, &encoded);
    asnber_ctx_destroy(ctx);
    if (err != ASNBER_OK) {
        fprintf(stderr, "ocsp encode: %d\n", (int)err);
        return 1;
    }
    return 0;
}

static int open_encoded(const unsigned char *der, size_t der_size,
                        uint32_t *out_version, size_t *out_count)
{
    asnber_ctx_t *ctx = create_ctx();
    asnber_ocsp_request_t *request = NULL;
    const char *hash_oid = NULL;
    size_t hash_oid_size = 0;
    const uint8_t *hash_params = NULL;
    size_t hash_params_size = 0;
    int hash_params_present = 0;
    const uint8_t *name_hash = NULL;
    size_t name_hash_size = 0;
    const uint8_t *key_hash = NULL;
    size_t key_hash_size = 0;
    const char *serial = NULL;
    size_t serial_size = 0;
    asnber_err_t err;

    if (ctx == NULL) {
        fprintf(stderr, "ocsp readback: asnber_ctx_create failed\n");
        return 1;
    }
    err = asnber_ocsp_request_open(ctx, der, der_size, &request);
    if (err == ASNBER_OK) {
        err = asnber_ocsp_request_version(request, out_version);
    }
    if (err == ASNBER_OK) {
        err = asnber_ocsp_request_count(request, out_count);
    }
    if (err == ASNBER_OK) {
        err = asnber_ocsp_request_cert_id(
            request, 0, &hash_oid, &hash_oid_size, &hash_params, &hash_params_size,
            &hash_params_present, &name_hash, &name_hash_size, &key_hash,
            &key_hash_size, &serial, &serial_size);
    }
    if (err == ASNBER_OK &&
        (*out_version != 0 || *out_count != 1 || hash_oid == NULL ||
         hash_oid_size != strlen(kSha1) ||
         memcmp(hash_oid, kSha1, hash_oid_size) != 0)) {
        err = ASNBER_E_INVALID_VALUE;
    }
    asnber_ocsp_request_close(request);
    asnber_ctx_destroy(ctx);
    if (err != ASNBER_OK) {
        fprintf(stderr, "ocsp readback: %d\n", (int)err);
        return 1;
    }
    return 0;
}

int main(void)
{
    uint32_t sample_version = 99;
    size_t sample_count = 0;
    uint32_t encoded_version = 99;
    size_t encoded_count = 0;
    unsigned char der[DER_CAP];
    size_t der_size = 0;

    if (open_sample(&sample_version, &sample_count) != 0 ||
        encode_request(der, &der_size) != 0 ||
        open_encoded(der, der_size, &encoded_version, &encoded_count) != 0) {
        return 1;
    }
    printf("sample OCSPRequest version=%u count=%zu\n",
           (unsigned)sample_version, sample_count);
    printf("encoded OCSPRequest=%zu bytes, version=%u count=%zu\n", der_size,
           (unsigned)encoded_version, encoded_count);
    return 0;
}
