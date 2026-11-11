/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * cert-and-csr 参考集成。四步各用一个上下文，用完 asnber_ctx_destroy，
 * 下一步再在同一块静态池上创建：
 *   1. 打开样例证书
 *   2. 编一张最小证书，并把 DER 拷出池外
 *   3. 编一张最小 CSR，并把 DER 拷出池外
 *   4. 读回这张 CSR
 *
 * 库不签名。公钥和签名位串是占位字节，集成方换成自己的密钥和签名。
 * builder 拷贝主体、公钥和签名时使用 malloc，这块堆不在静态池里。
 *
 * 宿主实测单步最小静态池（2026-11-11，已含上下文固定开销）：
 *   打开样例证书 21,744；编最小证书 241,952；
 *   编最小 CSR 179,904；读回 CSR 11,040。
 * 本示例用 256 KiB 覆盖单步最大值，四步复用同一块池。
 */
#include <asnber/asnber.h>
#include <asnber/pkcs10/pkcs10.h>
#include <asnber/pkix/pkix.h>

#include <stdio.h>
#include <string.h>

#include "cert_rsa_selfsigned.h"

#define STEP_POOL ((size_t)256u * 1024u)
#define DER_CAP ((size_t)4096u)

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

static union {
    long double align_ld;
    void *align_ptr;
    unsigned char bytes[STEP_POOL];
} g_pool;

static unsigned char g_cert_der[DER_CAP];
static size_t g_cert_der_size = 0;
static unsigned char g_csr_der[DER_CAP];
static size_t g_csr_der_size = 0;

static void set_time(asnber_time_t *time, int32_t year, uint8_t month,
                     uint8_t day)
{
    memset(time, 0, sizeof(*time));
    time->struct_size = sizeof(asnber_time_t);
    time->year = year;
    time->month = month;
    time->day = day;
}

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

static int open_sample_cert(uint32_t *out_version)
{
    asnber_ctx_t *ctx = create_ctx();
    asnber_pkix_certificate_t *cert = NULL;
    asnber_err_t err;

    if (ctx == NULL) {
        fprintf(stderr, "cert open: asnber_ctx_create failed\n");
        return 1;
    }
    err = asnber_pkix_certificate_open(ctx, kCertRsaSelfsigned,
                                     kCertRsaSelfsignedSize, &cert);
    if (err == ASNBER_OK) {
        err = asnber_pkix_certificate_version(cert, out_version);
    }
    asnber_pkix_certificate_close(cert);
    asnber_ctx_destroy(ctx);
    if (err != ASNBER_OK) {
        fprintf(stderr, "cert open: %d\n", (int)err);
        return 1;
    }
    return 0;
}

static int encode_certificate(void)
{
    asnber_ctx_t *ctx = create_ctx();
    asnber_pkix_certificate_builder_t *builder = NULL;
    asnber_buf_t encoded;
    asnber_time_t not_before;
    asnber_time_t not_after;
    asnber_err_t err = ASNBER_OK;
    int failed = 0;

    memset(&encoded, 0, sizeof(encoded));
    if (ctx == NULL) {
        fprintf(stderr, "cert encode: asnber_ctx_create failed\n");
        return 1;
    }
    set_time(&not_before, 2026, 1, 1);
    set_time(&not_after, 2027, 1, 1);

    err = asnber_pkix_certificate_builder_create(ctx, &builder);
    if (err == ASNBER_OK) {
        err = asnber_pkix_certificate_builder_set_serial_number(
            builder, kOne, sizeof(kOne));
    }
    if (err == ASNBER_OK) {
        err = asnber_pkix_certificate_builder_set_signature_algorithm(
            builder, kRsaOid, kNullParams, sizeof(kNullParams));
    }
    if (err == ASNBER_OK) {
        err = asnber_pkix_certificate_builder_set_issuer(builder, &kPkixRdn, 1);
    }
    if (err == ASNBER_OK) {
        err = asnber_pkix_certificate_builder_set_validity(builder, &not_before,
                                                         &not_after);
    }
    if (err == ASNBER_OK) {
        err = asnber_pkix_certificate_builder_set_subject(builder, &kPkixRdn, 1);
    }
    if (err == ASNBER_OK) {
        err = asnber_pkix_certificate_builder_set_subject_public_key_algorithm(
            builder, kRsaOid, kNullParams, sizeof(kNullParams));
    }
    if (err == ASNBER_OK) {
        err = asnber_pkix_certificate_builder_set_subject_public_key(
            builder, kOne, sizeof(kOne), 0);
    }
    if (err == ASNBER_OK) {
        err = asnber_pkix_certificate_builder_set_signature_value(
            builder, kOne, sizeof(kOne), 0);
    }
    if (err == ASNBER_OK) {
        err = asnber_pkix_certificate_builder_encode(builder, &encoded);
    }
    if (err == ASNBER_OK && copy_out(&encoded, g_cert_der, &g_cert_der_size) != 0) {
        failed = 1;
    }
    asnber_pkix_certificate_builder_destroy(builder);
    (void)asnber_buf_release(ctx, &encoded);
    asnber_ctx_destroy(ctx);
    if (failed) {
        fprintf(stderr, "cert encode: DER 超出 %zu 字节\n", DER_CAP);
        return 1;
    }
    if (err != ASNBER_OK) {
        fprintf(stderr, "cert encode: %d\n", (int)err);
        return 1;
    }
    return 0;
}

static int encode_csr(void)
{
    asnber_ctx_t *ctx = create_ctx();
    asnber_pkcs_certification_request_builder_t *builder = NULL;
    asnber_buf_t encoded;
    asnber_err_t err = ASNBER_OK;
    int failed = 0;

    memset(&encoded, 0, sizeof(encoded));
    if (ctx == NULL) {
        fprintf(stderr, "csr encode: asnber_ctx_create failed\n");
        return 1;
    }

    err = asnber_pkcs_certification_request_builder_create(ctx, &builder);
    if (err == ASNBER_OK) {
        err = asnber_pkcs_certification_request_builder_set_version(builder, 0);
    }
    if (err == ASNBER_OK) {
        err = asnber_pkcs_certification_request_builder_set_subject(
            builder, &kPkcsRdn, 1);
    }
    if (err == ASNBER_OK) {
        err = asnber_pkcs_certification_request_builder_set_subject_public_key_algorithm(
            builder, kRsaOid, kNullParams, sizeof(kNullParams));
    }
    if (err == ASNBER_OK) {
        err = asnber_pkcs_certification_request_builder_set_subject_public_key(
            builder, kOne, sizeof(kOne), 0);
    }
    if (err == ASNBER_OK) {
        err = asnber_pkcs_certification_request_builder_set_signature_algorithm(
            builder, kRsaOid, kNullParams, sizeof(kNullParams));
    }
    if (err == ASNBER_OK) {
        err = asnber_pkcs_certification_request_builder_set_signature(
            builder, kOne, sizeof(kOne), 0);
    }
    if (err == ASNBER_OK) {
        err = asnber_pkcs_certification_request_builder_encode(builder, &encoded);
    }
    if (err == ASNBER_OK && copy_out(&encoded, g_csr_der, &g_csr_der_size) != 0) {
        failed = 1;
    }
    asnber_pkcs_certification_request_builder_destroy(builder);
    (void)asnber_buf_release(ctx, &encoded);
    asnber_ctx_destroy(ctx);
    if (failed) {
        fprintf(stderr, "csr encode: DER 超出 %zu 字节\n", DER_CAP);
        return 1;
    }
    if (err != ASNBER_OK) {
        fprintf(stderr, "csr encode: %d\n", (int)err);
        return 1;
    }
    return 0;
}

static int open_csr(int64_t *out_version)
{
    asnber_ctx_t *ctx = create_ctx();
    asnber_pkcs_certification_request_t *csr = NULL;
    asnber_err_t err;

    if (ctx == NULL) {
        fprintf(stderr, "csr open: asnber_ctx_create failed\n");
        return 1;
    }
    err = asnber_pkcs_certification_request_open(ctx, g_csr_der, g_csr_der_size,
                                               &csr);
    if (err == ASNBER_OK) {
        err = asnber_pkcs_certification_request_version(csr, out_version);
    }
    asnber_pkcs_certification_request_close(csr);
    asnber_ctx_destroy(ctx);
    if (err != ASNBER_OK) {
        fprintf(stderr, "csr open: %d\n", (int)err);
        return 1;
    }
    return 0;
}

int main(void)
{
    uint32_t cert_version = 0;
    int64_t csr_version = -1;

    if (open_sample_cert(&cert_version) != 0 || encode_certificate() != 0 ||
        encode_csr() != 0 || open_csr(&csr_version) != 0) {
        return 1;
    }
    printf("sample certificate version=%u\n", (unsigned)cert_version);
    printf("encoded certificate=%zu bytes\n", g_cert_der_size);
    printf("encoded csr=%zu bytes, version=%lld\n", g_csr_der_size,
           (long long)csr_version);
    return csr_version == 0 ? 0 : 1;
}
