/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * cert-and-csr 裁剪构建：打开真实证书、编一张最小证书与一张最小 CSR、
 * 再读回 CSR version，并二分测量最小静态池。
 * 宿主运行二分测量；交叉编译只构建与链接。
 *
 * Builder 内部用 malloc 深拷贝输入，不占用静态池；池只覆盖上下文、
 * 描述表、文档与编码缓冲。
 */
#include <asnber/asnber.h>
#include <asnber/pkcs10/pkcs10.h>
#include <asnber/pkix/pkix.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cert_rsa_selfsigned.h"

#if defined(__arm__)
#define MAX_POOL ((size_t)4096u)
#else
#define MAX_POOL ((size_t)1u << 20)
#endif

static const uint8_t kNullParams[] = {0x05, 0x00};
static const uint8_t kOne[] = {0x01};
static const uint8_t kCn[] = {'a'};

static const char kRsaOid[] = "1.2.840.113549.1.1.1";
static const char kCnOid[] = "2.5.4.3";

static const asnber_pkix_name_attribute_t kPkixCn = {
    kCnOid, kCn, sizeof(kCn), 0};
static const asnber_pkix_name_rdn_t kPkixRdn = {&kPkixCn, 1};

static const asnber_pkcs_name_attribute_t kPkcsCn = {
    kCnOid, kCn, sizeof(kCn), 0};
static const asnber_pkcs_name_rdn_t kPkcsRdn = {&kPkcsCn, 1};

static uint8_t *g_csr_der = NULL;
static size_t g_csr_der_size = 0;

static union align_pool {
    long double align_ld;
    void *align_ptr;
    unsigned char bytes[MAX_POOL];
} g_pool;

static void set_time(asnber_time_t *time, int32_t year, uint8_t month,
                     uint8_t day)
{
    memset(time, 0, sizeof(*time));
    time->struct_size = sizeof(asnber_time_t);
    time->year = year;
    time->month = month;
    time->day = day;
}

static asnber_err_t encode_min_certificate(
    asnber_ctx_t *ctx, asnber_pkix_certificate_builder_t **out_builder,
    asnber_buf_t *out_buf)
{
    asnber_pkix_certificate_builder_t *builder = NULL;
    asnber_time_t not_before;
    asnber_time_t not_after;
    asnber_err_t err;

    *out_builder = NULL;
    memset(out_buf, 0, sizeof(*out_buf));
    set_time(&not_before, 2026, 1, 1);
    set_time(&not_after, 2027, 1, 1);

    err = asnber_pkix_certificate_builder_create(ctx, &builder);
    if (err != ASNBER_OK) {
        return err;
    }
    *out_builder = builder;

    err = asnber_pkix_certificate_builder_set_serial_number(
        builder, kOne, sizeof(kOne));
    if (err != ASNBER_OK) {
        return err;
    }
    err = asnber_pkix_certificate_builder_set_signature_algorithm(
        builder, kRsaOid, kNullParams, sizeof(kNullParams));
    if (err != ASNBER_OK) {
        return err;
    }
    err = asnber_pkix_certificate_builder_set_issuer(builder, &kPkixRdn, 1);
    if (err != ASNBER_OK) {
        return err;
    }
    err = asnber_pkix_certificate_builder_set_validity(builder, &not_before,
                                                     &not_after);
    if (err != ASNBER_OK) {
        return err;
    }
    err = asnber_pkix_certificate_builder_set_subject(builder, &kPkixRdn, 1);
    if (err != ASNBER_OK) {
        return err;
    }
    err = asnber_pkix_certificate_builder_set_subject_public_key_algorithm(
        builder, kRsaOid, kNullParams, sizeof(kNullParams));
    if (err != ASNBER_OK) {
        return err;
    }
    err = asnber_pkix_certificate_builder_set_subject_public_key(
        builder, kOne, sizeof(kOne), 0);
    if (err != ASNBER_OK) {
        return err;
    }
    err = asnber_pkix_certificate_builder_set_signature_value(
        builder, kOne, sizeof(kOne), 0);
    if (err != ASNBER_OK) {
        return err;
    }
    return asnber_pkix_certificate_builder_encode(builder, out_buf);
}

static asnber_err_t encode_min_csr(
    asnber_ctx_t *ctx, asnber_pkcs_certification_request_builder_t **out_builder,
    asnber_buf_t *out_buf)
{
    asnber_pkcs_certification_request_builder_t *builder = NULL;
    asnber_err_t err;

    *out_builder = NULL;
    memset(out_buf, 0, sizeof(*out_buf));

    err = asnber_pkcs_certification_request_builder_create(ctx, &builder);
    if (err != ASNBER_OK) {
        return err;
    }
    *out_builder = builder;

    err = asnber_pkcs_certification_request_builder_set_version(builder, 0);
    if (err != ASNBER_OK) {
        return err;
    }
    err = asnber_pkcs_certification_request_builder_set_subject(builder,
                                                              &kPkcsRdn, 1);
    if (err != ASNBER_OK) {
        return err;
    }
    err = asnber_pkcs_certification_request_builder_set_subject_public_key_algorithm(
        builder, kRsaOid, kNullParams, sizeof(kNullParams));
    if (err != ASNBER_OK) {
        return err;
    }
    err = asnber_pkcs_certification_request_builder_set_subject_public_key(
        builder, kOne, sizeof(kOne), 0);
    if (err != ASNBER_OK) {
        return err;
    }
    err = asnber_pkcs_certification_request_builder_set_signature_algorithm(
        builder, kRsaOid, kNullParams, sizeof(kNullParams));
    if (err != ASNBER_OK) {
        return err;
    }
    err = asnber_pkcs_certification_request_builder_set_signature(
        builder, kOne, sizeof(kOne), 0);
    if (err != ASNBER_OK) {
        return err;
    }
    return asnber_pkcs_certification_request_builder_encode(builder, out_buf);
}

static int try_pool(size_t pool_size, asnber_err_t *out_err, const char **out_step)
{
    asnber_ctx_config_t config;
    asnber_ctx_t *ctx = NULL;
    asnber_pkix_certificate_t *cert = NULL;
    asnber_pkix_certificate_builder_t *cert_builder = NULL;
    asnber_pkcs_certification_request_builder_t *csr_builder = NULL;
    asnber_pkcs_certification_request_t *csr = NULL;
    asnber_buf_t encoded_cert;
    asnber_buf_t encoded_csr;
    asnber_err_t err = ASNBER_OK;
    const char *step = NULL;
    uint32_t cert_version = 0;
    int64_t csr_version = -1;
    int ok = 0;

    memset(&encoded_cert, 0, sizeof(encoded_cert));
    memset(&encoded_csr, 0, sizeof(encoded_csr));
    if (out_err != NULL) {
        *out_err = ASNBER_OK;
    }
    if (out_step != NULL) {
        *out_step = NULL;
    }

    asnber_ctx_config_init(&config);
    config.static_pool = g_pool.bytes;
    config.static_pool_size = pool_size;

    step = "asnber_ctx_create";
    err = asnber_ctx_create(&config, &ctx);
    if (err != ASNBER_OK) {
        goto done;
    }

    step = "asnber_pkix_certificate_open";
    err = asnber_pkix_certificate_open(ctx, kCertRsaSelfsigned,
                                     kCertRsaSelfsignedSize, &cert);
    if (err != ASNBER_OK) {
        goto done;
    }
    step = "asnber_pkix_certificate_version";
    err = asnber_pkix_certificate_version(cert, &cert_version);
    if (err != ASNBER_OK) {
        goto done;
    }
    (void)cert_version;

    step = "asnber_pkix_certificate_builder_encode";
    err = encode_min_certificate(ctx, &cert_builder, &encoded_cert);
    if (err != ASNBER_OK) {
        goto done;
    }
    if (encoded_cert.size == 0) {
        err = ASNBER_E_INVALID_VALUE;
        goto done;
    }

    step = "asnber_pkcs_certification_request_builder_encode";
    err = encode_min_csr(ctx, &csr_builder, &encoded_csr);
    if (err != ASNBER_OK) {
        goto done;
    }
    if (encoded_csr.size == 0) {
        err = ASNBER_E_INVALID_VALUE;
        goto done;
    }

    step = "asnber_pkcs_certification_request_open";
    err = asnber_pkcs_certification_request_open(
        ctx, encoded_csr.data, encoded_csr.size, &csr);
    if (err != ASNBER_OK) {
        goto done;
    }
    step = "asnber_pkcs_certification_request_version";
    err = asnber_pkcs_certification_request_version(csr, &csr_version);
    if (err != ASNBER_OK || csr_version != 0) {
        if (err == ASNBER_OK) {
            err = ASNBER_E_INVALID_VALUE;
        }
        goto done;
    }

    ok = 1;

done:
    if (!ok) {
        if (out_err != NULL) {
            *out_err = err;
        }
        if (out_step != NULL) {
            *out_step = step;
        }
    }
    asnber_pkix_certificate_close(cert);
    asnber_pkcs_certification_request_close(csr);
    asnber_pkix_certificate_builder_destroy(cert_builder);
    asnber_pkcs_certification_request_builder_destroy(csr_builder);
    if (ctx != NULL) {
        (void)asnber_buf_release(ctx, &encoded_cert);
        (void)asnber_buf_release(ctx, &encoded_csr);
        asnber_ctx_destroy(ctx);
    }
    return ok;
}

static asnber_ctx_t *create_pool_ctx(size_t pool_size)
{
    asnber_ctx_config_t config;
    asnber_ctx_t *ctx = NULL;

    asnber_ctx_config_init(&config);
    config.static_pool = g_pool.bytes;
    config.static_pool_size = pool_size;
    if (asnber_ctx_create(&config, &ctx) != ASNBER_OK) {
        return NULL;
    }
    return ctx;
}

static int open_cert_only(size_t pool_size)
{
    asnber_ctx_t *ctx = create_pool_ctx(pool_size);
    asnber_pkix_certificate_t *cert = NULL;
    uint32_t version = 0;
    int ok = 0;

    if (ctx == NULL) {
        return 0;
    }
    if (asnber_pkix_certificate_open(ctx, kCertRsaSelfsigned, kCertRsaSelfsignedSize,
                                   &cert) == ASNBER_OK &&
        asnber_pkix_certificate_version(cert, &version) == ASNBER_OK) {
        ok = 1;
    }
    asnber_pkix_certificate_close(cert);
    asnber_ctx_destroy(ctx);
    return ok;
}

static int encode_cert_only(size_t pool_size)
{
    asnber_ctx_t *ctx = create_pool_ctx(pool_size);
    asnber_pkix_certificate_builder_t *builder = NULL;
    asnber_buf_t encoded;
    int ok = 0;

    memset(&encoded, 0, sizeof(encoded));
    if (ctx == NULL) {
        return 0;
    }
    if (encode_min_certificate(ctx, &builder, &encoded) == ASNBER_OK &&
        encoded.size > 0) {
        ok = 1;
    }
    asnber_pkix_certificate_builder_destroy(builder);
    (void)asnber_buf_release(ctx, &encoded);
    asnber_ctx_destroy(ctx);
    return ok;
}

static int encode_csr_only(size_t pool_size)
{
    asnber_ctx_t *ctx = create_pool_ctx(pool_size);
    asnber_pkcs_certification_request_builder_t *builder = NULL;
    asnber_buf_t encoded;
    int ok = 0;

    memset(&encoded, 0, sizeof(encoded));
    if (ctx == NULL) {
        return 0;
    }
    if (encode_min_csr(ctx, &builder, &encoded) == ASNBER_OK && encoded.size > 0) {
        ok = 1;
    }
    asnber_pkcs_certification_request_builder_destroy(builder);
    (void)asnber_buf_release(ctx, &encoded);
    asnber_ctx_destroy(ctx);
    return ok;
}

static int open_csr_only(size_t pool_size)
{
    asnber_ctx_t *ctx = create_pool_ctx(pool_size);
    asnber_pkcs_certification_request_t *csr = NULL;
    int64_t version = -1;
    int ok = 0;

    if (ctx == NULL || g_csr_der == NULL) {
        asnber_ctx_destroy(ctx);
        return 0;
    }
    if (asnber_pkcs_certification_request_open(ctx, g_csr_der, g_csr_der_size,
                                             &csr) == ASNBER_OK &&
        asnber_pkcs_certification_request_version(csr, &version) == ASNBER_OK &&
        version == 0) {
        ok = 1;
    }
    asnber_pkcs_certification_request_close(csr);
    asnber_ctx_destroy(ctx);
    return ok;
}

static int capture_csr_der(void)
{
    asnber_ctx_config_t config;
    asnber_ctx_t *ctx = NULL;
    asnber_pkcs_certification_request_builder_t *builder = NULL;
    asnber_buf_t encoded;
    uint8_t *copy = NULL;

    memset(&encoded, 0, sizeof(encoded));
    asnber_ctx_config_init(&config);
    if (asnber_ctx_create(&config, &ctx) != ASNBER_OK) {
        return 0;
    }
    if (encode_min_csr(ctx, &builder, &encoded) != ASNBER_OK || encoded.size == 0) {
        asnber_pkcs_certification_request_builder_destroy(builder);
        (void)asnber_buf_release(ctx, &encoded);
        asnber_ctx_destroy(ctx);
        return 0;
    }
    copy = (uint8_t *)malloc(encoded.size);
    if (copy == NULL) {
        asnber_pkcs_certification_request_builder_destroy(builder);
        (void)asnber_buf_release(ctx, &encoded);
        asnber_ctx_destroy(ctx);
        return 0;
    }
    memcpy(copy, encoded.data, encoded.size);
    g_csr_der = copy;
    g_csr_der_size = encoded.size;
    asnber_pkcs_certification_request_builder_destroy(builder);
    (void)asnber_buf_release(ctx, &encoded);
    asnber_ctx_destroy(ctx);
    return 1;
}

static size_t minimum_pool(int (*probe)(size_t))
{
    size_t lo = 1;
    size_t hi = MAX_POOL;

    if (!probe(MAX_POOL)) {
        return 0;
    }
    while (lo < hi) {
        const size_t mid = lo + (hi - lo) / 2;
        if (probe(mid)) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    return lo;
}

int main(void)
{
#if defined(__arm__)
    (void)try_pool(4096u, NULL, NULL);
    return 0;
#else
    asnber_ctx_config_t config;
    asnber_err_t err = ASNBER_OK;
    const char *step = NULL;
    size_t ctx_floor = 0;
    size_t lo = 1;
    size_t hi = MAX_POOL;

    if (asnber_has_capability(ASNBER_CAP_ENCODE_SCHEMA_AWARE) != 1) {
        fprintf(stderr, "FAIL: encode 能力位缺失\n");
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
    if (!capture_csr_der()) {
        fprintf(stderr, "FAIL: 无法在堆上编出供读回的 CSR\n");
        return 1;
    }
    {
        const size_t cert_open = minimum_pool(open_cert_only);
        const size_t cert_encode = minimum_pool(encode_cert_only);
        const size_t csr_encode = minimum_pool(encode_csr_only);
        const size_t csr_open = minimum_pool(open_csr_only);
        if (cert_open == 0 || cert_encode == 0 || csr_encode == 0 ||
            csr_open == 0) {
            fprintf(stderr, "FAIL: 单步静态池测量失败\n");
            free(g_csr_der);
            return 1;
        }
        printf("min_static_pool_size(cert open, fresh ctx) = %zu bytes\n",
               cert_open);
        printf("min_static_pool_size(cert encode, fresh ctx) = %zu bytes\n",
               cert_encode);
        printf("min_static_pool_size(csr encode, fresh ctx) = %zu bytes\n",
               csr_encode);
        printf("min_static_pool_size(csr open, fresh ctx) = %zu bytes\n",
               csr_open);
    }
    if (!try_pool(MAX_POOL, &err, &step)) {
        fprintf(stderr,
                "FAIL: %zu 字节池仍无法完成证书与 CSR 编解码 (%s, asnber_err=%ld)\n",
                MAX_POOL, step != NULL ? step : "?", (long)err);
        return 1;
    }

    asnber_ctx_config_init(&config);
    (void)asnber_ctx_size_for_config(&config, &ctx_floor);
    while (lo < hi) {
        const size_t mid = lo + (hi - lo) / 2;
        if (try_pool(mid, NULL, NULL)) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    printf("asnber_ctx_size_for_config = %zu bytes\n", ctx_floor);
    printf("min_static_pool_size(certificate table + CSR table + cert/csr codec) = %zu bytes\n",
           lo);
    if (lo < ctx_floor) {
        fprintf(stderr, "FAIL: 最小池小于 ctx 固定开销\n");
        return 1;
    }
    printf("OK\n");
    free(g_csr_der);
    return 0;
#endif
}
