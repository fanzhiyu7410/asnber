/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * cert-decode 裁剪构建：只读访问器断言 + 最小静态池测量。
 * 宿主运行二分测量；交叉编译只构建与链接。
 */
#include <asnber/asnber.h>
#include <asnber/pkix/pkix.h>

#include <stdio.h>

#include "cert_rsa_selfsigned.h"

#if defined(__arm__)
#define MAX_POOL ((size_t)4096u)
#else
#define MAX_POOL ((size_t)1u << 20)
#endif

static union align_pool {
    long double align_ld;
    void *align_ptr;
    unsigned char bytes[MAX_POOL];
} g_pool;

static int check_accessors(asnber_pkix_certificate_t *cert)
{
    const char *text = NULL;
    size_t text_size = 0;
    const uint8_t *bytes = NULL;
    size_t byte_size = 0;
    size_t bit_length = 0;
    uint8_t unused_bits = 0;
    uint32_t version = 0;
    asnber_time_t not_before;
    asnber_time_t not_after;
    const asnber_node_t *node = NULL;

    not_before.struct_size = sizeof(not_before);
    not_after.struct_size = sizeof(not_after);

    if (asnber_pkix_certificate_version(cert, &version) != ASNBER_OK ||
        version > 2u) {
        return 0;
    }
    if (asnber_pkix_certificate_signature_algorithm_oid(
            cert, &text, &text_size) != ASNBER_OK ||
        text == NULL || text_size == 0) {
        return 0;
    }
    if (asnber_pkix_certificate_signature_value(
            cert, &bytes, &byte_size, &bit_length, &unused_bits) != ASNBER_OK ||
        bytes == NULL || byte_size == 0) {
        return 0;
    }
    if (asnber_pkix_certificate_serial_number(cert, &text, &text_size) !=
            ASNBER_OK ||
        text == NULL || text_size == 0) {
        return 0;
    }
    if (asnber_pkix_certificate_issuer_der(cert, &bytes, &byte_size) != ASNBER_OK ||
        bytes == NULL || byte_size == 0) {
        return 0;
    }
    if (asnber_pkix_certificate_subject_der(cert, &bytes, &byte_size) != ASNBER_OK ||
        bytes == NULL || byte_size == 0) {
        return 0;
    }
    if (asnber_pkix_certificate_validity(cert, &not_before, &not_after) !=
        ASNBER_OK) {
        return 0;
    }
    if (asnber_pkix_certificate_find(cert, "tbsCertificate.subject", &node) !=
            ASNBER_OK ||
        node == NULL) {
        return 0;
    }
    return 1;
}

static int try_pool(size_t pool_size)
{
    asnber_ctx_config_t config;
    asnber_ctx_t *ctx = NULL;
    asnber_pkix_certificate_t *cert = NULL;
    int ok = 0;

    asnber_ctx_config_init(&config);
    config.static_pool = g_pool.bytes;
    config.static_pool_size = pool_size;
    if (asnber_ctx_create(&config, &ctx) != ASNBER_OK) {
        return 0;
    }
    if (asnber_pkix_certificate_open(ctx, kCertRsaSelfsigned,
                                   kCertRsaSelfsignedSize, &cert) != ASNBER_OK) {
        goto done;
    }
    if (!check_accessors(cert)) {
        goto done;
    }
    ok = 1;

done:
    asnber_pkix_certificate_close(cert);
    asnber_ctx_destroy(ctx);
    return ok;
}

int main(void)
{
#if defined(__arm__)
    (void)try_pool(MAX_POOL);
    return 0;
#else
    asnber_ctx_config_t config;
    size_t ctx_floor = 0;
    size_t lo = 1;
    size_t hi = MAX_POOL;

    if (asnber_has_capability(ASNBER_CAP_ENCODE_SCHEMA_AWARE) != 0) {
        fprintf(stderr, "FAIL: encode 能力位未清除\n");
        return 1;
    }
    if (asnber_has_capability(ASNBER_CAP_SCHEMA_RUNTIME_REGISTER) != 0) {
        fprintf(stderr, "FAIL: schema 运行时注册能力位未清除\n");
        return 1;
    }
    if (asnber_has_capability(ASNBER_CAP_SCHEMA_TABLE_LOAD) != 1) {
        fprintf(stderr, "FAIL: 描述表加载能力位缺失\n");
        return 1;
    }
    if (!try_pool(MAX_POOL)) {
        fprintf(stderr, "FAIL: %zu 字节池仍无法完成证书打开\n", MAX_POOL);
        return 1;
    }

    asnber_ctx_config_init(&config);
    (void)asnber_ctx_size_for_config(&config, &ctx_floor);
    while (lo < hi) {
        const size_t mid = lo + (hi - lo) / 2;
        if (try_pool(mid)) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    printf("asnber_ctx_size_for_config = %zu bytes\n", ctx_floor);
    printf("min_static_pool_size(PKIX certificate table + cert open) = %zu bytes\n",
           lo);
    if (lo < ctx_floor) {
        fprintf(stderr, "FAIL: 最小池小于 ctx 固定开销\n");
        return 1;
    }
    printf("OK\n");
    return 0;
#endif
}
