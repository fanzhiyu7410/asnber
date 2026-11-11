/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * asnber-pkcs1 只读结构访问：RSAPublicKey / RSAPrivateKey 与负例。
 */

#include <asnber/asnber.h>
#include <asnber/pkcs1/pkcs1.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "../data/key_rsa_pkcs1_private.h"
#include "../data/key_rsa_pkcs1_public.h"
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

/* ---------- PKCS#1 公私钥 ---------- */

static int test_rsa_keys(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_pkcs_rsa_public_key_t *pub = NULL;
    asnber_pkcs_rsa_private_key_t *priv = NULL;
    const char *pub_modulus = NULL;
    const char *priv_modulus = NULL;
    size_t pub_size = 0;
    size_t priv_size = 0;

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_open(
                        ctx, kKeyRsaPkcs1Public, kKeyRsaPkcs1PublicSize,
                        &pub) == ASNBER_OK);
    ASNBER_TEST_CHECK(pub != NULL);

    {
        const char *exponent = NULL;
        size_t size = 0;
        ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_modulus(
                            pub, &pub_modulus, &pub_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(pub_modulus != NULL && pub_size > 0);
        ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_public_exponent(
                            pub, &exponent, &size) == ASNBER_OK);
        ASNBER_TEST_CHECK(text_equals(exponent, size, "65537"));
    }

    ASNBER_TEST_CHECK(asnber_pkcs_rsa_private_key_open(
                        ctx, kKeyRsaPkcs1Private, kKeyRsaPkcs1PrivateSize,
                        &priv) == ASNBER_OK);
    ASNBER_TEST_CHECK(priv != NULL);

    {
        int64_t version = -1;
        const char *exponent = NULL;
        size_t size = 0;
        ASNBER_TEST_CHECK(asnber_pkcs_rsa_private_key_version(priv, &version) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(version == 0);
        ASNBER_TEST_CHECK(asnber_pkcs_rsa_private_key_modulus(
                            priv, &priv_modulus, &priv_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(priv_size == pub_size);
        ASNBER_TEST_CHECK(memcmp(priv_modulus, pub_modulus, pub_size) == 0);
        ASNBER_TEST_CHECK(asnber_pkcs_rsa_private_key_public_exponent(
                            priv, &exponent, &size) == ASNBER_OK);
        ASNBER_TEST_CHECK(text_equals(exponent, size, "65537"));
    }

    {
        const char *field = NULL;
        size_t field_size = 0;
        const char *prime2 = NULL;
        size_t prime2_size = 0;

        ASNBER_TEST_CHECK(asnber_pkcs_rsa_private_key_private_exponent(
                            priv, &field, &field_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(field != NULL && field_size > 0);

        ASNBER_TEST_CHECK(asnber_pkcs_rsa_private_key_prime1(
                            priv, &field, &field_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(field != NULL && field_size > 0);
        ASNBER_TEST_CHECK(asnber_pkcs_rsa_private_key_prime2(
                            priv, &prime2, &prime2_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(prime2 != NULL && prime2_size > 0);
        ASNBER_TEST_CHECK(field_size != prime2_size ||
                        memcmp(field, prime2, field_size) != 0);

        ASNBER_TEST_CHECK(asnber_pkcs_rsa_private_key_exponent1(
                            priv, &field, &field_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(field != NULL && field_size > 0);
        ASNBER_TEST_CHECK(asnber_pkcs_rsa_private_key_exponent2(
                            priv, &field, &field_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(field != NULL && field_size > 0);
        ASNBER_TEST_CHECK(asnber_pkcs_rsa_private_key_coefficient(
                            priv, &field, &field_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(field != NULL && field_size > 0);
    }

    asnber_pkcs_rsa_private_key_close(priv);
    asnber_pkcs_rsa_public_key_close(pub);
    asnber_ctx_destroy(ctx);
    return 0;
}

/* ---------- PKCS#1 负例 ---------- */

static int test_negative(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_pkcs_rsa_public_key_t *pub = NULL;
    asnber_pkcs_rsa_private_key_t *priv = NULL;
    uint8_t *trailing = NULL;

    ASNBER_TEST_CHECK(ctx != NULL);

    ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_open(
                        NULL, kKeyRsaPkcs1Public, kKeyRsaPkcs1PublicSize,
                        &pub) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_open(
                        ctx, NULL, kKeyRsaPkcs1PublicSize, &pub) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_open(
                        ctx, kKeyRsaPkcs1Public, 0, &pub) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_modulus(NULL, NULL, NULL) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkcs_rsa_private_key_version(NULL, NULL) ==
                    ASNBER_E_INVALID_ARG);
    asnber_pkcs_rsa_public_key_close(NULL);
    asnber_pkcs_rsa_private_key_close(NULL);

    /* 用 PKCS#8 私钥去打开 RSAPublicKey 必须失败。 */
    ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_open(
                        ctx, kKeyRsaPkcs8, kKeyRsaPkcs8Size, &pub) != ASNBER_OK);
    ASNBER_TEST_CHECK(pub == NULL);

    /* 截断的 PKCS#1 私钥。 */
    ASNBER_TEST_CHECK(asnber_pkcs_rsa_private_key_open(
                        ctx, kKeyRsaPkcs1Private,
                        kKeyRsaPkcs1PrivateSize - 8, &priv) != ASNBER_OK);
    ASNBER_TEST_CHECK(priv == NULL);

    /* 合法 DER 后附加尾随字节。 */
    trailing = (uint8_t *)malloc(kKeyRsaPkcs1PublicSize + 1);
    ASNBER_TEST_CHECK(trailing != NULL);
    memcpy(trailing, kKeyRsaPkcs1Public, kKeyRsaPkcs1PublicSize);
    trailing[kKeyRsaPkcs1PublicSize] = 0x00;
    ASNBER_TEST_CHECK(asnber_pkcs_rsa_public_key_open(
                        ctx, trailing, kKeyRsaPkcs1PublicSize + 1, &pub) !=
                    ASNBER_OK);
    ASNBER_TEST_CHECK(pub == NULL);
    free(trailing);

    asnber_ctx_destroy(ctx);
    return 0;
}

int main(void)
{
    if (test_rsa_keys() != 0) {
        return 1;
    }
    if (test_negative() != 0) {
        return 1;
    }
    return 0;
}
