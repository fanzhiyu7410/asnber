/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * cert-decode 参考集成：在静态池上打开一张证书，读出版本后销毁上下文。
 *
 * 链接 asnber::pkix::static。certificate 变体上打开本示例自带的 RSA 自签
 * 证书，宿主实测最小静态池为 21,744 字节（已含上下文固定开销）。这里留
 * 32 KiB。换成设备上的证书时按那张证书重新测量。
 */
#include <asnber/asnber.h>
#include <asnber/pkix/pkix.h>

#include <stdio.h>

#include "cert_rsa_selfsigned.h"

#define CERT_OPEN_POOL ((size_t)32u * 1024u)

static union {
    long double align_ld;
    void *align_ptr;
    unsigned char bytes[CERT_OPEN_POOL];
} g_pool;

static int open_certificate(uint32_t *out_version)
{
    asnber_ctx_config_t config;
    asnber_ctx_t *ctx = NULL;
    asnber_pkix_certificate_t *cert = NULL;
    asnber_err_t err;

    asnber_ctx_config_init(&config);
    config.static_pool = g_pool.bytes;
    config.static_pool_size = sizeof(g_pool.bytes);
    err = asnber_ctx_create(&config, &ctx);
    if (err != ASNBER_OK) {
        fprintf(stderr, "asnber_ctx_create: %d\n", (int)err);
        return 1;
    }

    err = asnber_pkix_certificate_open(ctx, kCertRsaSelfsigned,
                                     kCertRsaSelfsignedSize, &cert);
    if (err != ASNBER_OK) {
        fprintf(stderr, "asnber_pkix_certificate_open: %d\n", (int)err);
        asnber_ctx_destroy(ctx);
        return 1;
    }

    err = asnber_pkix_certificate_version(cert, out_version);
    asnber_pkix_certificate_close(cert);
    asnber_ctx_destroy(ctx);
    if (err != ASNBER_OK) {
        fprintf(stderr, "asnber_pkix_certificate_version: %d\n", (int)err);
        return 1;
    }
    return 0;
}

int main(void)
{
    uint32_t version = 0;

    if (open_certificate(&version) != 0) {
        return 1;
    }
    printf("certificate version=%u\n", (unsigned)version);
    return 0;
}
