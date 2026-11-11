/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * asnber-pkcs8 PrivateKeyInfo builder：正例往返与负例。
 * 正例覆盖 RSA（NULL 参数）、EC（命名曲线 OID 参数）、RSA-PSS（参数缺省）
 * 与 attributes 改写；负例覆盖参数、重复设置、必填缺失与非法 TLV。
 */

#include <asnber/asnber.h>
#include <asnber/pkcs8/pkcs8.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "../data/key_rsa_pkcs8.h"
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

static char *dup_text(const char *text, size_t size)
{
    char *copy = (char *)malloc(size + 1);
    if (copy == NULL) {
        return NULL;
    }
    memcpy(copy, text, size);
    copy[size] = '\0';
    return copy;
}

/*
 * 读取 fixture 的四个字段并经 builder 重建，要求与 fixture 逐字节一致。
 * has_parameters 为 0 时要求参数缺省。
 */
static int roundtrip_fixture(const uint8_t *der, size_t der_size,
                             int has_parameters)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_pkcs_private_key_info_t *info = NULL;
    asnber_pkcs_private_key_info_builder_t *builder = NULL;
    asnber_buf_t encoded;
    char *oid_copy = NULL;
    int failed = 1;

    memset(&encoded, 0, sizeof(encoded));
    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_open(ctx, der, der_size,
                                                    &info) == ASNBER_OK);

    {
        int64_t version = -1;
        const char *oid = NULL;
        size_t oid_size = 0;
        const uint8_t *parameters = NULL;
        size_t parameters_size = 0;
        const uint8_t *key = NULL;
        size_t key_size = 0;

        ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_version(info, &version) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_algorithm_oid(
                            info, &oid, &oid_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(oid != NULL && oid_size > 0);
        ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_algorithm_parameters(
                            info, &parameters, &parameters_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(has_parameters ? (parameters != NULL &&
                                          parameters_size > 0)
                                       : (parameters == NULL &&
                                          parameters_size == 0));
        ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_private_key(
                            info, &key, &key_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(key != NULL);

        oid_copy = dup_text(oid, oid_size);
        ASNBER_TEST_CHECK(oid_copy != NULL);

        ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_create(
                            ctx, &builder) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_set_version(
                            builder, version) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_set_algorithm(
                            builder, oid_copy, parameters,
                            parameters_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_set_private_key(
                            builder, key, key_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_encode(
                            builder, &encoded) == ASNBER_OK);
        ASNBER_TEST_CHECK(encoded.data != NULL);
        ASNBER_TEST_CHECK(encoded.size == der_size);
        ASNBER_TEST_CHECK(memcmp(encoded.data, der, der_size) == 0);
    }

    failed = 0;

    asnber_buf_release(ctx, &encoded);
    asnber_pkcs_private_key_info_builder_destroy(builder);
    free(oid_copy);
    asnber_pkcs_private_key_info_close(info);
    asnber_ctx_destroy(ctx);
    return failed;
}

static int test_roundtrip_rsa(void)
{
    return roundtrip_fixture(kKeyRsaPkcs8, kKeyRsaPkcs8Size, 1);
}

/*
 * parameters 为命名曲线 OID 的 EC PrivateKeyInfo（手工构造的最小样本）：
 * ecPublicKey 1.2.840.10045.2.1 + prime256v1 1.2.840.10045.3.1.7。
 */
static const uint8_t kEcPrivateKeyInfo[] = {
    0x30, 0x1E, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06,
    0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03,
    0x01, 0x07, 0x04, 0x04, 0xDE, 0xAD, 0xBE, 0xEF};

static int test_roundtrip_ec(void)
{
    return roundtrip_fixture(kEcPrivateKeyInfo, sizeof(kEcPrivateKeyInfo), 1);
}

static int test_roundtrip_pss_without_parameters(void)
{
    return roundtrip_fixture(kKeyRsaPssPkcs8, kKeyRsaPssPkcs8Size, 0);
}

/* Attribute ::= SEQUENCE { type 2.5.29.15, values SET { BIT STRING 05 A0 } } */
static const uint8_t kAttributesSet[] = {
    0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x1D,
    0x0F, 0x31, 0x04, 0x03, 0x02, 0x05, 0xA0};

static int test_attributes(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_pkcs_private_key_info_t *info = NULL;
    asnber_pkcs_private_key_info_builder_t *builder = NULL;
    asnber_buf_t encoded;
    const uint8_t *key = NULL;
    size_t key_size = 0;
    int failed = 1;

    memset(&encoded, 0, sizeof(encoded));
    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_open(
                        ctx, kKeyRsaPkcs8, kKeyRsaPkcs8Size, &info) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_private_key(
                        info, &key, &key_size) == ASNBER_OK);

    ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_create(
                        ctx, &builder) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_set_version(
                        builder, 0) == ASNBER_OK);
    {
        static const uint8_t null_parameters[] = {0x05, 0x00};
        ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_set_algorithm(
                            builder, "1.2.840.113549.1.1.1", null_parameters,
                            sizeof(null_parameters)) == ASNBER_OK);
    }
    ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_set_private_key(
                        builder, key, key_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_set_attributes(
                        builder, kAttributesSet, sizeof(kAttributesSet)) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_encode(
                        builder, &encoded) == ASNBER_OK);

    /* [0] IMPLICIT 改写：SET 的 0x31 变为 0xA0，内容不变。 */
    {
        size_t i = 0;
        int found = 0;
        for (i = 0; i + sizeof(kAttributesSet) <= encoded.size; ++i) {
            if (encoded.data[i] == 0xA0 &&
                memcmp(encoded.data + i + 1, kAttributesSet + 1,
                       sizeof(kAttributesSet) - 1) == 0) {
                found = 1;
                break;
            }
        }
        ASNBER_TEST_CHECK(found);
    }

    /* 读回验证 attributes 可被只读侧识别。 */
    {
        asnber_pkcs_private_key_info_t *reopened = NULL;
        size_t count = 0;
        const char *type_oid = NULL;
        size_t type_oid_size = 0;
        const asnber_node_t *values = NULL;
        const uint8_t *values_tlv = NULL;
        size_t values_tlv_size = 0;

        ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_open(
                            ctx, encoded.data, encoded.size, &reopened) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_attribute_count(
                            reopened, &count) == ASNBER_OK);
        ASNBER_TEST_CHECK(count == 1);
        ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_attribute_at(
                            reopened, 0, &type_oid, &type_oid_size,
                            &values) == ASNBER_OK);
        ASNBER_TEST_CHECK(text_equals(type_oid, type_oid_size, "2.5.29.15"));
        ASNBER_TEST_CHECK(values != NULL);
        values_tlv = asnber_node_tlv(values, &values_tlv_size);
        ASNBER_TEST_CHECK(values_tlv != NULL);
        ASNBER_TEST_CHECK(values_tlv_size == 6);
        ASNBER_TEST_CHECK(memcmp(values_tlv, kAttributesSet + 9, 6) == 0);
        asnber_pkcs_private_key_info_close(reopened);
    }

    failed = 0;

    asnber_buf_release(ctx, &encoded);
    asnber_pkcs_private_key_info_builder_destroy(builder);
    asnber_pkcs_private_key_info_close(info);
    asnber_ctx_destroy(ctx);
    return failed;
}

static int test_negative_arguments(void)
{
    static const uint8_t two_tlvs[] = {0x05, 0x00, 0x05, 0x00};
    static const uint8_t not_a_set[] = {0x30, 0x00};
    static const uint8_t empty_set[] = {0x31, 0x00};
    static const uint8_t bad_member[] = {0x31, 0x05, 0x04, 0x03, 0x00, 0x01,
                                         0x02};
    static const uint8_t key[] = {0x30, 0x00};
    asnber_ctx_t *ctx = make_ctx();
    asnber_pkcs_private_key_info_builder_t *builder = NULL;
    asnber_buf_t encoded;

    memset(&encoded, 0, sizeof(encoded));
    ASNBER_TEST_CHECK(ctx != NULL);

    ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_create(
                        NULL, &builder) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(builder == NULL);
    ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_create(ctx, NULL) ==
                    ASNBER_E_INVALID_ARG);
    asnber_pkcs_private_key_info_builder_destroy(NULL);

    ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_set_version(
                        NULL, 0) == ASNBER_E_INVALID_ARG);

    /* 每次失败都不应把字段置为已设置，随后可用合法值重试。 */
    ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_create(
                        ctx, &builder) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_set_algorithm(
                        builder, NULL, NULL, 0) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_set_algorithm(
                        builder, "1.2.3.", NULL, 0) != ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_set_algorithm(
                        builder, "1.2.3", NULL, 1) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_set_algorithm(
                        builder, "1.2.3", two_tlvs, sizeof(two_tlvs)) !=
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_set_algorithm(
                        builder, "1.2.840.113549.1.1.1", NULL, 0) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_set_algorithm(
                        builder, "1.2.3", NULL, 0) ==
                    ASNBER_E_INVALID_STATE);

    ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_set_private_key(
                        builder, NULL, 1) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_set_private_key(
                        builder, key, sizeof(key)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_set_private_key(
                        builder, key, sizeof(key)) ==
                    ASNBER_E_INVALID_STATE);

    ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_set_attributes(
                        builder, NULL, 1) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_set_attributes(
                        builder, kAttributesSet, 0) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_set_attributes(
                        builder, not_a_set, sizeof(not_a_set)) != ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_set_attributes(
                        builder, empty_set, sizeof(empty_set)) != ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_set_attributes(
                        builder, bad_member, sizeof(bad_member)) != ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_set_attributes(
                        builder, kAttributesSet, sizeof(kAttributesSet)) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_set_attributes(
                        builder, kAttributesSet, sizeof(kAttributesSet)) ==
                    ASNBER_E_INVALID_STATE);

    ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_encode(
                        NULL, &encoded) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_encode(
                        builder, NULL) == ASNBER_E_INVALID_ARG);

    asnber_pkcs_private_key_info_builder_destroy(builder);
    builder = NULL;

    /* 必填字段缺失：version / algorithm / privateKey 三档。 */
    ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_set_algorithm(
                        builder, NULL, NULL, 0) == ASNBER_E_INVALID_ARG);

    {
        asnber_buf_t buf;
        buf.data = (uint8_t *)(uintptr_t)1;
        buf.size = 1;
        buf.capacity = 1;

        ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_create(
                            ctx, &builder) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_set_version(
                            builder, 0) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_encode(
                            builder, &buf) == ASNBER_E_INVALID_STATE);
        ASNBER_TEST_CHECK(buf.data == NULL && buf.size == 0 &&
                        buf.capacity == 0);
        ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_set_algorithm(
                            builder, "1.2.840.113549.1.1.1", NULL, 0) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_encode(
                            builder, &buf) == ASNBER_E_INVALID_STATE);
        ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_set_private_key(
                            builder, key, sizeof(key)) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_pkcs_private_key_info_builder_encode(
                            builder, &buf) == ASNBER_OK);
        ASNBER_TEST_CHECK(buf.data != NULL && buf.size > 0);
        asnber_buf_release(ctx, &buf);
        asnber_pkcs_private_key_info_builder_destroy(builder);
    }

    asnber_ctx_destroy(ctx);
    return 0;
}

static int test_encrypted_builder(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_pkcs_encrypted_private_key_info_builder_t *builder = NULL;
    asnber_pkcs_encrypted_private_key_info_t *info = NULL;
    asnber_buf_t encoded;
    const uint8_t ciphertext[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    const uint8_t null_params[2] = {0x05, 0x00};
    const char *oid = NULL;
    size_t oid_size = 0;
    const uint8_t *params = NULL;
    size_t params_size = 0;
    const uint8_t *data = NULL;
    size_t data_size = 0;

    ASNBER_TEST_CHECK(ctx != NULL);
    memset(&encoded, 0, sizeof(encoded));
    ASNBER_TEST_CHECK(asnber_pkcs_encrypted_private_key_info_builder_create(
                        ctx, &builder) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs_encrypted_private_key_info_builder_encode(
                        builder, &encoded) == ASNBER_E_INVALID_STATE);
    ASNBER_TEST_CHECK(asnber_pkcs_encrypted_private_key_info_builder_set_algorithm(
                        builder, "1.2.840.113549.1.5.13", null_params,
                        sizeof(null_params)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs_encrypted_private_key_info_builder_set_algorithm(
                        builder, "1.2.840.113549.1.5.13", NULL, 0) ==
                    ASNBER_E_INVALID_STATE);
    ASNBER_TEST_CHECK(
        asnber_pkcs_encrypted_private_key_info_builder_set_encrypted_data(
            builder, ciphertext, sizeof(ciphertext)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs_encrypted_private_key_info_builder_encode(
                        builder, &encoded) == ASNBER_OK);

    ASNBER_TEST_CHECK(asnber_pkcs_encrypted_private_key_info_open(
                        ctx, encoded.data, encoded.size, &info) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs_encrypted_private_key_info_algorithm_oid(
                        info, &oid, &oid_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(oid != NULL && strcmp(oid, "1.2.840.113549.1.5.13") == 0);
    ASNBER_TEST_CHECK(asnber_pkcs_encrypted_private_key_info_algorithm_parameters(
                        info, &params, &params_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(params != NULL && params_size == sizeof(null_params));
    ASNBER_TEST_CHECK(memcmp(params, null_params, sizeof(null_params)) == 0);
    ASNBER_TEST_CHECK(asnber_pkcs_encrypted_private_key_info_encrypted_data(
                        info, &data, &data_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(data != NULL && data_size == sizeof(ciphertext));
    ASNBER_TEST_CHECK(memcmp(data, ciphertext, sizeof(ciphertext)) == 0);

    asnber_pkcs_encrypted_private_key_info_close(info);
    asnber_buf_release(ctx, &encoded);
    asnber_pkcs_encrypted_private_key_info_builder_destroy(builder);
    asnber_pkcs_encrypted_private_key_info_builder_destroy(NULL);
    asnber_ctx_destroy(ctx);
    return 0;
}

int main(void)
{
    if (test_encrypted_builder() != 0) {
        return 1;
    }
    if (test_roundtrip_rsa() != 0) {
        return 1;
    }
    if (test_roundtrip_ec() != 0) {
        return 1;
    }
    if (test_roundtrip_pss_without_parameters() != 0) {
        return 1;
    }
    if (test_attributes() != 0) {
        return 1;
    }
    if (test_negative_arguments() != 0) {
        return 1;
    }
    return 0;
}
