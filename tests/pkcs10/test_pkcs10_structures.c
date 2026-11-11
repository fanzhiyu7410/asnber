/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * asnber-pkcs10 只读结构访问：CertificationRequest 字段、非 0 版本与负例。
 */

#include <asnber/asnber.h>
#include <asnber/pkcs10/pkcs10.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "../data/csr_ec.h"
#include "../data/csr_rsa.h"
#include "../data/key_rsa_pkcs8.h"
#include "check.h"
#include "test_compare.h"

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

/* ---------- PKCS#10 CSR 正例：RSA 与 EC ---------- */

static int test_certification_request(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_pkcs_certification_request_t *csr = NULL;

    ASNBER_TEST_CHECK(ctx != NULL);

    /* RSA CSR：sha256WithRSAEncryption、rsaEncryption + NULL、空 attributes。 */
    ASNBER_TEST_CHECK(asnber_pkcs_certification_request_open(
                        ctx, kCsrRsa, kCsrRsaSize, &csr) == ASNBER_OK);
    ASNBER_TEST_CHECK(csr != NULL);

    {
        int64_t version = -1;
        ASNBER_TEST_CHECK(asnber_pkcs_certification_request_version(csr, &version) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(version == 0);
    }

    {
        const uint8_t *subject = NULL;
        size_t size = 0;
        ASNBER_TEST_CHECK(asnber_pkcs_certification_request_subject_der(
                            csr, &subject, &size) == ASNBER_OK);
        ASNBER_TEST_CHECK(subject != NULL && size == 58);
        ASNBER_TEST_CHECK(subject[0] == 0x30);
    }

    {
        const char *oid = NULL;
        size_t size = 0;
        const uint8_t *params = NULL;
        size_t params_size = 0;
        ASNBER_TEST_CHECK(
            asnber_pkcs_certification_request_subject_public_key_algorithm_oid(
                csr, &oid, &size) == ASNBER_OK);
        ASNBER_TEST_CHECK(text_equals(oid, size, "1.2.840.113549.1.1.1"));
        ASNBER_TEST_CHECK(
            asnber_pkcs_certification_request_subject_public_key_algorithm_parameters(
                csr, &params, &params_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(params != NULL && params_size == 2);
        ASNBER_TEST_CHECK(params[0] == 0x05 && params[1] == 0x00);
    }

    {
        const uint8_t *key = NULL;
        size_t size = 0;
        const uint8_t *tlv = NULL;
        size_t tlv_size = 0;
        ASNBER_TEST_CHECK(asnber_pkcs_certification_request_subject_public_key(
                            csr, &key, &size) == ASNBER_OK);
        ASNBER_TEST_CHECK(key != NULL && size == 270);
        ASNBER_TEST_CHECK(key[0] == 0x30);
        ASNBER_TEST_CHECK(
            asnber_pkcs_certification_request_subject_public_key_tlv(
                csr, &tlv, &tlv_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(tlv != NULL && tlv_size == 275);
        ASNBER_TEST_CHECK(tlv[0] == 0x03);
    }

    {
        size_t count = 1;
        const char *oid = NULL;
        size_t oid_size = 0;
        const asnber_node_t *values = NULL;
        ASNBER_TEST_CHECK(
            asnber_pkcs_certification_request_attribute_count(csr, &count) ==
            ASNBER_OK);
        ASNBER_TEST_CHECK(count == 0);
        ASNBER_TEST_CHECK(
            asnber_pkcs_certification_request_attribute_at(
                csr, 0, &oid, &oid_size, &values) == ASNBER_E_INVALID_ARG);
    }

    {
        const char *oid = NULL;
        size_t size = 0;
        const uint8_t *params = NULL;
        size_t params_size = 0;
        const uint8_t *signature = NULL;
        size_t signature_size = 0;
        const uint8_t *tlv = NULL;
        size_t tlv_size = 0;
        ASNBER_TEST_CHECK(
            asnber_pkcs_certification_request_signature_algorithm_oid(
                csr, &oid, &size) == ASNBER_OK);
        ASNBER_TEST_CHECK(text_equals(oid, size, "1.2.840.113549.1.1.11"));
        ASNBER_TEST_CHECK(
            asnber_pkcs_certification_request_signature_algorithm_parameters(
                csr, &params, &params_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(params != NULL && params_size == 2);
        ASNBER_TEST_CHECK(params[0] == 0x05 && params[1] == 0x00);
        ASNBER_TEST_CHECK(asnber_pkcs_certification_request_signature_value(
                            csr, &signature, &signature_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(signature != NULL && signature_size == 256);
        ASNBER_TEST_CHECK(
            asnber_pkcs_certification_request_signature_value_tlv(
                csr, &tlv, &tlv_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(tlv != NULL && tlv_size == 261);
        ASNBER_TEST_CHECK(tlv[0] == 0x03);
    }

    asnber_pkcs_certification_request_close(csr);
    csr = NULL;

    /* EC CSR：参数为 curve OID，公钥为未压缩点。 */
    ASNBER_TEST_CHECK(asnber_pkcs_certification_request_open(
                        ctx, kCsrEc, kCsrEcSize, &csr) == ASNBER_OK);
    ASNBER_TEST_CHECK(csr != NULL);

    {
        const uint8_t *subject = NULL;
        size_t size = 0;
        ASNBER_TEST_CHECK(asnber_pkcs_certification_request_subject_der(
                            csr, &subject, &size) == ASNBER_OK);
        ASNBER_TEST_CHECK(subject != NULL && size == 57);
    }

    {
        const char *oid = NULL;
        size_t size = 0;
        const uint8_t *params = NULL;
        size_t params_size = 0;
        const uint8_t *key = NULL;
        size_t key_size = 0;
        ASNBER_TEST_CHECK(
            asnber_pkcs_certification_request_subject_public_key_algorithm_oid(
                csr, &oid, &size) == ASNBER_OK);
        ASNBER_TEST_CHECK(text_equals(oid, size, "1.2.840.10045.2.1"));
        ASNBER_TEST_CHECK(
            asnber_pkcs_certification_request_subject_public_key_algorithm_parameters(
                csr, &params, &params_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(params != NULL && params_size == 10);
        ASNBER_TEST_CHECK(params[0] == 0x06);
        ASNBER_TEST_CHECK(asnber_pkcs_certification_request_subject_public_key(
                            csr, &key, &key_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(key != NULL && key_size == 65);
        ASNBER_TEST_CHECK(key[0] == 0x04);
    }

    {
        const char *oid = NULL;
        size_t size = 0;
        ASNBER_TEST_CHECK(
            asnber_pkcs_certification_request_signature_algorithm_oid(
                csr, &oid, &size) == ASNBER_OK);
        ASNBER_TEST_CHECK(text_equals(oid, size, "1.2.840.10045.4.3.2"));
    }

    asnber_pkcs_certification_request_close(csr);
    asnber_ctx_destroy(ctx);
    return 0;
}

/* ---------- PKCS#10 非 0 版本：原样给出值 ---------- */

static int test_certification_request_nonzero_version(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_pkcs_certification_request_t *csr = NULL;
    uint8_t *patched = NULL;

    ASNBER_TEST_CHECK(ctx != NULL);

    /*
     * CSR DER：0 SEQUENCE，4 certificationRequestInfo，8 INTEGER 0；
     * 内容字节位于偏移 10。改为 1，构造“非 v1”的不常见输入。
     */
    patched = (uint8_t *)malloc(kCsrRsaSize);
    ASNBER_TEST_CHECK(patched != NULL);
    memcpy(patched, kCsrRsa, kCsrRsaSize);
    patched[10] = 0x01;

    ASNBER_TEST_CHECK(asnber_pkcs_certification_request_open(
                        ctx, patched, kCsrRsaSize, &csr) == ASNBER_OK);
    ASNBER_TEST_CHECK(csr != NULL);

    {
        int64_t version = -1;
        ASNBER_TEST_CHECK(asnber_pkcs_certification_request_version(csr, &version) ==
                        ASNBER_OK);
        /* 不做范围校验、不静默改写为 0。 */
        ASNBER_TEST_CHECK(version == 1);
    }

    /* 其余字段不受版本影响，仍可正常读取。 */
    {
        const char *oid = NULL;
        size_t size = 0;
        ASNBER_TEST_CHECK(
            asnber_pkcs_certification_request_signature_algorithm_oid(
                csr, &oid, &size) == ASNBER_OK);
        ASNBER_TEST_CHECK(text_equals(oid, size, "1.2.840.113549.1.1.11"));
    }

    asnber_pkcs_certification_request_close(csr);
    free(patched);
    asnber_ctx_destroy(ctx);
    return 0;
}

/* ---------- PKCS#10 负例 ---------- */

static int test_certification_request_negative(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_pkcs_certification_request_t *csr = NULL;
    uint8_t *trailing = NULL;

    ASNBER_TEST_CHECK(ctx != NULL);

    ASNBER_TEST_CHECK(asnber_pkcs_certification_request_open(
                        NULL, kCsrRsa, kCsrRsaSize, &csr) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkcs_certification_request_open(
                        ctx, NULL, kCsrRsaSize, &csr) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkcs_certification_request_open(
                        ctx, kCsrRsa, kCsrRsaSize, NULL) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkcs_certification_request_version(NULL, NULL) ==
                    ASNBER_E_INVALID_ARG);
    asnber_pkcs_certification_request_close(NULL);

    /* 非 CSR 输入（PKCS#8 私钥）必须失败。 */
    ASNBER_TEST_CHECK(asnber_pkcs_certification_request_open(
                        ctx, kKeyRsaPkcs8, kKeyRsaPkcs8Size, &csr) != ASNBER_OK);
    ASNBER_TEST_CHECK(csr == NULL);

    /* 截断 CSR。 */
    ASNBER_TEST_CHECK(asnber_pkcs_certification_request_open(
                        ctx, kCsrRsa, kCsrRsaSize - 20, &csr) != ASNBER_OK);
    ASNBER_TEST_CHECK(csr == NULL);

    /* 合法 DER 后附加尾随字节。 */
    trailing = (uint8_t *)malloc(kCsrRsaSize + 1);
    ASNBER_TEST_CHECK(trailing != NULL);
    memcpy(trailing, kCsrRsa, kCsrRsaSize);
    trailing[kCsrRsaSize] = 0x00;
    ASNBER_TEST_CHECK(asnber_pkcs_certification_request_open(
                        ctx, trailing, kCsrRsaSize + 1, &csr) != ASNBER_OK);
    ASNBER_TEST_CHECK(csr == NULL);
    free(trailing);

    asnber_ctx_destroy(ctx);
    return 0;
}

int main(void)
{
    if (test_certification_request() != 0) {
        return 1;
    }
    if (test_certification_request_nonzero_version() != 0) {
        return 1;
    }
    if (test_certification_request_negative() != 0) {
        return 1;
    }
    return 0;
}
