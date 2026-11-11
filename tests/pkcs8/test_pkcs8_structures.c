/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * asnber-pkcs8 只读结构访问：PrivateKeyInfo / EncryptedPrivateKeyInfo。
 * 覆盖明文与加密结构、RSA-PSS 参数缺省与负例。
 */

#include <asnber/asnber.h>
#include <asnber/pkcs8/pkcs8.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "../data/key_rsa_pkcs8.h"
#include "../data/key_rsa_pkcs8_encrypted.h"
#include "../data/key_rsa_pss_pkcs8.h"
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

static int tlv_is(const uint8_t *tlv, size_t size, const uint8_t *expected,
                  size_t expected_size)
{
    if (tlv == NULL || size != expected_size) {
        return 0;
    }
    return memcmp(tlv, expected, expected_size) == 0;
}

/* ---------- PKCS#8 明文 PrivateKeyInfo ---------- */

static int test_private_key_info_clear(void)
{
    static const uint8_t null_parameters[] = {0x05, 0x00};
    asnber_ctx_t *ctx = make_ctx();
    asnber_pkcs_private_key_info_t *info = NULL;

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_open(
                        ctx, kKeyRsaPkcs8, kKeyRsaPkcs8Size, &info) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(info != NULL);

    {
        int64_t version = -1;
        ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_version(info, &version) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(version == 0);
    }

    {
        const char *oid = NULL;
        size_t size = 0;
        ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_algorithm_oid(
                            info, &oid, &size) == ASNBER_OK);
        ASNBER_TEST_CHECK(text_equals(oid, size, "1.2.840.113549.1.1.1"));
    }

    {
        /* RSA 的 parameters 是 NULL，ANY 只给完整原始 TLV 05 00。 */
        const uint8_t *tlv = NULL;
        size_t size = 0;
        ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_algorithm_parameters(
                            info, &tlv, &size) == ASNBER_OK);
        ASNBER_TEST_CHECK(tlv_is(tlv, size, null_parameters,
                               sizeof(null_parameters)));
    }

    {
        const uint8_t *data = NULL;
        const uint8_t *tlv = NULL;
        size_t size = 0;
        size_t tlv_size = 0;
        ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_private_key(
                            info, &data, &size) == ASNBER_OK);
        ASNBER_TEST_CHECK(data != NULL && size > 0);
        ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_private_key_tlv(
                            info, &tlv, &tlv_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(tlv != NULL && tlv_size > size);
        ASNBER_TEST_CHECK(tlv[0] == 0x04);
        /* privateKey 内容是 PKCS#1 RSAPrivateKey 的完整 DER，交给 asnber-pkcs1。 */
        ASNBER_TEST_CHECK(data[0] == 0x30);
    }

    {
        size_t count = 99;
        ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_attribute_count(
                            info, &count) == ASNBER_OK);
        ASNBER_TEST_CHECK(count == 0);
        ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_attribute_at(
                            info, 0, NULL, NULL, NULL) ==
                        ASNBER_E_INVALID_ARG);
    }

    asnber_pkcs_private_key_info_close(info);
    asnber_ctx_destroy(ctx);
    return 0;
}

/* ---------- PKCS#8 RSA-PSS：parameters 缺省 ---------- */

static int test_private_key_info_pss(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_pkcs_private_key_info_t *info = NULL;

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_open(
                        ctx, kKeyRsaPssPkcs8, kKeyRsaPssPkcs8Size, &info) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(info != NULL);

    {
        const char *oid = NULL;
        size_t size = 0;
        ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_algorithm_oid(
                            info, &oid, &size) == ASNBER_OK);
        ASNBER_TEST_CHECK(text_equals(oid, size, "1.2.840.113549.1.1.10"));
    }

    {
        /* 该样本的 AlgorithmIdentifier 只含 algorithm OID，parameters 缺省。 */
        const uint8_t *tlv = NULL;
        size_t size = 0;
        ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_algorithm_parameters(
                            info, &tlv, &size) == ASNBER_OK);
        ASNBER_TEST_CHECK(tlv == NULL);
        ASNBER_TEST_CHECK(size == 0);
    }

    asnber_pkcs_private_key_info_close(info);
    asnber_ctx_destroy(ctx);
    return 0;
}

/* ---------- PKCS#8 EncryptedPrivateKeyInfo ---------- */

static int test_encrypted_private_key_info(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_pkcs_encrypted_private_key_info_t *info = NULL;

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(asnber_pkcs_encrypted_private_key_info_open(
                        ctx, kKeyRsaPkcs8Encrypted,
                        kKeyRsaPkcs8EncryptedSize, &info) == ASNBER_OK);
    ASNBER_TEST_CHECK(info != NULL);

    {
        const char *oid = NULL;
        size_t size = 0;
        ASNBER_TEST_CHECK(asnber_pkcs_encrypted_private_key_info_algorithm_oid(
                            info, &oid, &size) == ASNBER_OK);
        ASNBER_TEST_CHECK(text_equals(oid, size, "1.2.840.113549.1.5.13"));
    }

    {
        const uint8_t *tlv = NULL;
        size_t size = 0;
        ASNBER_TEST_CHECK(
            asnber_pkcs_encrypted_private_key_info_algorithm_parameters(
                info, &tlv, &size) == ASNBER_OK);
        ASNBER_TEST_CHECK(tlv != NULL && size > 2);
        ASNBER_TEST_CHECK(tlv[0] == 0x30);
    }

    {
        const uint8_t *data = NULL;
        const uint8_t *tlv = NULL;
        size_t size = 0;
        size_t tlv_size = 0;
        ASNBER_TEST_CHECK(
            asnber_pkcs_encrypted_private_key_info_encrypted_data(
                info, &data, &size) == ASNBER_OK);
        ASNBER_TEST_CHECK(data != NULL && size > 0);
        ASNBER_TEST_CHECK(
            asnber_pkcs_encrypted_private_key_info_encrypted_data_tlv(
                info, &tlv, &tlv_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(tlv != NULL && tlv_size > size);
        ASNBER_TEST_CHECK(tlv[0] == 0x04);
    }

    asnber_pkcs_encrypted_private_key_info_close(info);
    asnber_ctx_destroy(ctx);
    return 0;
}

/* ---------- PKCS#8 负例 ---------- */

static int test_negative(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_pkcs_private_key_info_t *info = NULL;
    uint8_t *trailing = NULL;

    ASNBER_TEST_CHECK(ctx != NULL);

    ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_open(NULL, kKeyRsaPkcs8,
                                                    kKeyRsaPkcs8Size,
                                                    &info) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_open(ctx, NULL,
                                                    kKeyRsaPkcs8Size,
                                                    &info) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_open(ctx, kKeyRsaPkcs8, 0,
                                                    &info) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_open(ctx, kKeyRsaPkcs8,
                                                    kKeyRsaPkcs8Size,
                                                    NULL) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_version(NULL, NULL) ==
                    ASNBER_E_INVALID_ARG);
    asnber_pkcs_private_key_info_close(NULL);
    asnber_pkcs_encrypted_private_key_info_close(NULL);

    /* 合法 DER 后附加尾随字节。 */
    trailing = (uint8_t *)malloc(kKeyRsaPkcs8Size + 1);
    ASNBER_TEST_CHECK(trailing != NULL);
    memcpy(trailing, kKeyRsaPkcs8, kKeyRsaPkcs8Size);
    trailing[kKeyRsaPkcs8Size] = 0x00;
    ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_open(
                        ctx, trailing, kKeyRsaPkcs8Size + 1, &info) !=
                    ASNBER_OK);
    ASNBER_TEST_CHECK(info == NULL);
    free(trailing);

    asnber_ctx_destroy(ctx);
    return 0;
}

int main(void)
{
    if (test_private_key_info_clear() != 0) {
        return 1;
    }
    if (test_private_key_info_pss() != 0) {
        return 1;
    }
    if (test_encrypted_private_key_info() != 0) {
        return 1;
    }
    if (test_negative() != 0) {
        return 1;
    }
    return 0;
}
