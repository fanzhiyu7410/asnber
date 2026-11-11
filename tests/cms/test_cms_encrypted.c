/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * asnber-cms 只读结构访问：EncryptedData。
 * 覆盖 version 0 detached、version 0 空 encryptedContent（`80 00`）、
 * version 2 + unprotectedAttrs，以及空参数、截断、缺字段等负例。
 */

#include <asnber/asnber.h>
#include <asnber/cms/cms.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../data/cms_encrypted_data.h"
#include "../support/check.h"
#include "../support/test_compare.h"

static const char kDataOid[] = "1.2.840.113549.1.7.1";
static const char kAes256CbcOid[] = "2.16.840.1.101.3.4.1.42";

/*
 * EncryptedData {
 *   version 0,
 *   encryptedContentInfo { data, aes-256-cbc } }   -- encryptedContent 缺省
 */
static const uint8_t kDetached[] = {
    0x30, 0x1D,
    0x02, 0x01, 0x00,
    0x30, 0x18,
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
    0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
    0x01, 0x2A,
};

/* 同上，但 encryptedContent 为空 OCTET STRING：`80 00`。 */
static const uint8_t kEmptyContent[] = {
    0x30, 0x1F,
    0x02, 0x01, 0x00,
    0x30, 0x1A,
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
    0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
    0x01, 0x2A,
    0x80, 0x00,
};

/*
 * version 2 + unprotectedAttrs:
 *   [1] IMPLICIT SET { Attribute { 1.2.3.4, SET { INTEGER 1 } } }
 * 空 encryptedContent 同时保留，验证两个可选/尾部字段可共存。
 */
static const uint8_t kVersion2Attrs[] = {
    0x30, 0x2D,
    0x02, 0x01, 0x02,
    0x30, 0x1A,
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
    0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
    0x01, 0x2A,
    0x80, 0x00,
    0xA1, 0x0C,
    0x30, 0x0A,
    0x06, 0x03, 0x2A, 0x03, 0x04,
    0x31, 0x03, 0x02, 0x01, 0x01,
};

/* 缺 encryptedContentInfo（version 后直接结束）。 */
static const uint8_t kMissingContentInfo[] = {0x30, 0x03, 0x02, 0x01, 0x00};

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

static int check_content_info(asnber_cms_encrypted_data_t *encrypted)
{
    const char *oid = NULL;
    size_t oid_size = 0;
    ASNBER_TEST_CHECK(asnber_cms_encrypted_data_content_type(
                        encrypted, &oid, &oid_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(text_equals(oid, oid_size, kDataOid));

    const uint8_t *parameters = NULL;
    size_t parameters_size = 0;
    ASNBER_TEST_CHECK(
        asnber_cms_encrypted_data_content_encryption_algorithm(
            encrypted, &oid, &oid_size, &parameters, &parameters_size) ==
        ASNBER_OK);
    ASNBER_TEST_CHECK(text_equals(oid, oid_size, kAes256CbcOid));
    ASNBER_TEST_CHECK(parameters == NULL);
    ASNBER_TEST_CHECK(parameters_size == 0);
    return 0;
}

static int check_detached(asnber_ctx_t *ctx)
{
    asnber_cms_encrypted_data_t *encrypted = NULL;
    ASNBER_TEST_CHECK(asnber_cms_encrypted_data_open(
                        ctx, kDetached, sizeof(kDetached), &encrypted) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(encrypted != NULL);

    int64_t version = -1;
    ASNBER_TEST_CHECK(asnber_cms_encrypted_data_version(encrypted, &version) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(version == 0);

    ASNBER_TEST_CHECK(check_content_info(encrypted) == 0);

    const uint8_t *data = NULL;
    size_t data_size = 0;
    ASNBER_TEST_CHECK(asnber_cms_encrypted_data_encrypted_content(
                        encrypted, &data, &data_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(data == NULL);
    ASNBER_TEST_CHECK(data_size == 0);

    const uint8_t *tlv = NULL;
    size_t tlv_size = 0;
    ASNBER_TEST_CHECK(asnber_cms_encrypted_data_encrypted_content_tlv(
                        encrypted, &tlv, &tlv_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(tlv == NULL);
    ASNBER_TEST_CHECK(tlv_size == 0);

    ASNBER_TEST_CHECK(asnber_cms_encrypted_data_unprotected_attrs_tlv(
                        encrypted, &tlv, &tlv_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(tlv == NULL);
    ASNBER_TEST_CHECK(tlv_size == 0);

    asnber_cms_encrypted_data_close(encrypted);
    asnber_cms_encrypted_data_close(NULL);
    return 0;
}

static int check_empty_content(asnber_ctx_t *ctx)
{
    asnber_cms_encrypted_data_t *encrypted = NULL;
    ASNBER_TEST_CHECK(asnber_cms_encrypted_data_open(
                        ctx, kEmptyContent, sizeof(kEmptyContent),
                        &encrypted) == ASNBER_OK);
    ASNBER_TEST_CHECK(check_content_info(encrypted) == 0);

    const uint8_t *data = NULL;
    size_t data_size = 1;
    ASNBER_TEST_CHECK(asnber_cms_encrypted_data_encrypted_content(
                        encrypted, &data, &data_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(data != NULL);
    ASNBER_TEST_CHECK(data_size == 0);

    const uint8_t *tlv = NULL;
    size_t tlv_size = 0;
    ASNBER_TEST_CHECK(asnber_cms_encrypted_data_encrypted_content_tlv(
                        encrypted, &tlv, &tlv_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(tlv != NULL);
    ASNBER_TEST_CHECK(tlv_size == 2);
    ASNBER_TEST_CHECK(tlv[0] == 0x80 && tlv[1] == 0x00);

    asnber_cms_encrypted_data_close(encrypted);
    return 0;
}

static int check_version2_attrs(asnber_ctx_t *ctx)
{
    asnber_cms_encrypted_data_t *encrypted = NULL;
    ASNBER_TEST_CHECK(asnber_cms_encrypted_data_open(
                        ctx, kVersion2Attrs, sizeof(kVersion2Attrs),
                        &encrypted) == ASNBER_OK);

    int64_t version = -1;
    ASNBER_TEST_CHECK(asnber_cms_encrypted_data_version(encrypted, &version) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(version == 2);

    const uint8_t *tlv = NULL;
    size_t tlv_size = 0;
    ASNBER_TEST_CHECK(asnber_cms_encrypted_data_unprotected_attrs_tlv(
                        encrypted, &tlv, &tlv_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(tlv != NULL);
    ASNBER_TEST_CHECK(tlv_size == 14);
    ASNBER_TEST_CHECK(tlv[0] == 0xA1);
    static const uint8_t kExpectedAttrs[14] = {
        0xA1, 0x0C, 0x30, 0x0A, 0x06, 0x03, 0x2A,
        0x03, 0x04, 0x31, 0x03, 0x02, 0x01, 0x01};
    ASNBER_TEST_CHECK(memcmp(tlv, kExpectedAttrs, sizeof(kExpectedAttrs)) == 0);

    const uint8_t *data = NULL;
    size_t data_size = 1;
    ASNBER_TEST_CHECK(asnber_cms_encrypted_data_encrypted_content(
                        encrypted, &data, &data_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(data != NULL);
    ASNBER_TEST_CHECK(data_size == 0);

    asnber_cms_encrypted_data_close(encrypted);
    return 0;
}

/* openssl 真实产物：ContentInfo(EncryptedData)，version 0，AES-256-CBC。 */
static int check_openssl_sample(asnber_ctx_t *ctx)
{
    asnber_cms_content_info_t *info = NULL;
    const char *oid = NULL;
    size_t oid_size = 0;
    const uint8_t *content = NULL;
    size_t content_size = 0;
    asnber_cms_encrypted_data_t *encrypted = NULL;
    int64_t version = -1;
    const uint8_t *parameters = NULL;
    size_t parameters_size = 0;
    const uint8_t *data = NULL;
    size_t data_size = 0;
    const uint8_t *tlv = NULL;
    size_t tlv_size = 0;

    ASNBER_TEST_CHECK(asnber_cms_content_info_open(ctx, kCmsEncryptedData,
                                               kCmsEncryptedDataSize,
                                               &info) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_content_info_content_type(info, &oid,
                                                       &oid_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(text_equals(oid, oid_size, "1.2.840.113549.1.7.6"));
    ASNBER_TEST_CHECK(asnber_cms_content_info_content(info, &content,
                                                  &content_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_encrypted_data_open(ctx, content, content_size,
                                                 &encrypted) == ASNBER_OK);

    ASNBER_TEST_CHECK(asnber_cms_encrypted_data_version(encrypted, &version) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(version == 0);
    ASNBER_TEST_CHECK(asnber_cms_encrypted_data_content_type(encrypted, &oid,
                                                         &oid_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(text_equals(oid, oid_size, kDataOid));
    ASNBER_TEST_CHECK(
        asnber_cms_encrypted_data_content_encryption_algorithm(
            encrypted, &oid, &oid_size, &parameters, &parameters_size) ==
        ASNBER_OK);
    ASNBER_TEST_CHECK(text_equals(oid, oid_size, kAes256CbcOid));
    /* AES-CBC 的 IV 以 OCTET STRING 作为 AlgorithmIdentifier.parameters。 */
    ASNBER_TEST_CHECK(parameters != NULL);
    ASNBER_TEST_CHECK(parameters_size == 18);
    ASNBER_TEST_CHECK(parameters[0] == 0x04 && parameters[1] == 0x10);

    ASNBER_TEST_CHECK(asnber_cms_encrypted_data_encrypted_content(
                        encrypted, &data, &data_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(data != NULL);
    ASNBER_TEST_CHECK(data_size != 0);
    ASNBER_TEST_CHECK(data_size % 16u == 0);
    ASNBER_TEST_CHECK(asnber_cms_encrypted_data_encrypted_content_tlv(
                        encrypted, &tlv, &tlv_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(tlv != NULL);
    ASNBER_TEST_CHECK(tlv_size == data_size + 2);
    ASNBER_TEST_CHECK(tlv[0] == 0x80 &&
                    tlv[1] == (uint8_t)data_size);
    ASNBER_TEST_CHECK(asnber_cms_encrypted_data_unprotected_attrs_tlv(
                        encrypted, &tlv, &tlv_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(tlv == NULL && tlv_size == 0);

    asnber_cms_encrypted_data_close(encrypted);
    asnber_cms_content_info_close(info);
    return 0;
}

static int open_encoded(asnber_ctx_t *ctx, const asnber_buf_t *encoded,
                        asnber_cms_content_info_t **out_info,
                        asnber_cms_encrypted_data_t **out_encrypted)
{
    const uint8_t *content = NULL;
    size_t content_size = 0;
    ASNBER_TEST_CHECK(asnber_cms_content_info_open(ctx, encoded->data,
                                               encoded->size, out_info) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_content_info_content(*out_info, &content,
                                                  &content_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_encrypted_data_open(ctx, content, content_size,
                                                 out_encrypted) == ASNBER_OK);
    return 0;
}

/* 完整 ContentInfo（id-encryptedData）+ detached EncryptedData。 */
static int check_builder_detached(asnber_ctx_t *ctx)
{
    static const uint8_t kExpected[] = {
        0x30, 0x2C,
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x06,
        0xA0, 0x1F,
        0x30, 0x1D,
        0x02, 0x01, 0x00,
        0x30, 0x18,
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
        0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
        0x01, 0x2A,
    };
    asnber_cms_encrypted_builder_t *builder = NULL;
    asnber_buf_t encoded;
    memset(&encoded, 0, sizeof(encoded));

    ASNBER_TEST_CHECK(asnber_cms_encrypted_builder_create(ctx, &builder) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_encrypted_builder_set_version(builder, 0) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_encrypted_builder_set_content_type(
                        builder, kDataOid) == ASNBER_OK);
    ASNBER_TEST_CHECK(
        asnber_cms_encrypted_builder_set_content_encryption_algorithm(
            builder, kAes256CbcOid, NULL, 0) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_encrypted_builder_encode(builder, &encoded) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(bytes_equal(encoded.data, encoded.size, kExpected,
                                sizeof(kExpected)));

    {
        asnber_cms_content_info_t *info = NULL;
        asnber_cms_encrypted_data_t *encrypted = NULL;
        const char *oid = NULL;
        size_t oid_size = 0;
        const uint8_t *data = NULL;
        size_t data_size = 1;
        const uint8_t *tlv = NULL;
        size_t tlv_size = 1;

        ASNBER_TEST_CHECK(open_encoded(ctx, &encoded, &info, &encrypted) == 0);
        ASNBER_TEST_CHECK(asnber_cms_content_info_content_type(
                            info, &oid, &oid_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(text_equals(oid, oid_size,
                                    "1.2.840.113549.1.7.6"));
        ASNBER_TEST_CHECK(check_content_info(encrypted) == 0);
        ASNBER_TEST_CHECK(asnber_cms_encrypted_data_encrypted_content(
                            encrypted, &data, &data_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(data == NULL);
        ASNBER_TEST_CHECK(data_size == 0);
        ASNBER_TEST_CHECK(asnber_cms_encrypted_data_encrypted_content_tlv(
                            encrypted, &tlv, &tlv_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(tlv == NULL);
        ASNBER_TEST_CHECK(tlv_size == 0);

        asnber_cms_encrypted_data_close(encrypted);
        asnber_cms_content_info_close(info);
    }

    asnber_buf_release(ctx, &encoded);
    asnber_cms_encrypted_builder_destroy(builder);
    return 0;
}

/* 空 encryptedContent（`80 00`）与 unprotectedAttrs（0x31 → 0xA1）。 */
static int check_builder_empty_content_and_attrs(asnber_ctx_t *ctx)
{
    static const uint8_t kAttrsSet[14] = {
        0x31, 0x0C, 0x30, 0x0A, 0x06, 0x03, 0x2A,
        0x03, 0x04, 0x31, 0x03, 0x02, 0x01, 0x01};
    static const uint8_t kExpectedAttrs[14] = {
        0xA1, 0x0C, 0x30, 0x0A, 0x06, 0x03, 0x2A,
        0x03, 0x04, 0x31, 0x03, 0x02, 0x01, 0x01};
    static const uint8_t kExpected[] = {
        0x30, 0x3C,
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x06,
        0xA0, 0x2F,
        0x30, 0x2D,
        0x02, 0x01, 0x02,
        0x30, 0x1A,
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
        0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
        0x01, 0x2A,
        0x80, 0x00,
        0xA1, 0x0C,
        0x30, 0x0A,
        0x06, 0x03, 0x2A, 0x03, 0x04,
        0x31, 0x03, 0x02, 0x01, 0x01,
    };
    asnber_cms_encrypted_builder_t *builder = NULL;
    asnber_buf_t encoded;
    memset(&encoded, 0, sizeof(encoded));

    ASNBER_TEST_CHECK(asnber_cms_encrypted_builder_create(ctx, &builder) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_encrypted_builder_set_version(builder, 2) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_encrypted_builder_set_content_type(
                        builder, kDataOid) == ASNBER_OK);
    ASNBER_TEST_CHECK(
        asnber_cms_encrypted_builder_set_content_encryption_algorithm(
            builder, kAes256CbcOid, NULL, 0) == ASNBER_OK);
    /* NULL/0 合法：显式设置空内容，区别于未设置（detached）。 */
    ASNBER_TEST_CHECK(asnber_cms_encrypted_builder_set_encrypted_content(
                        builder, NULL, 0) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_encrypted_builder_set_unprotected_attrs(
                        builder, kAttrsSet, sizeof(kAttrsSet)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_encrypted_builder_encode(builder, &encoded) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(bytes_equal(encoded.data, encoded.size, kExpected,
                                sizeof(kExpected)));

    {
        asnber_cms_content_info_t *info = NULL;
        asnber_cms_encrypted_data_t *encrypted = NULL;
        int64_t version = -1;
        const uint8_t *data = NULL;
        size_t data_size = 1;
        const uint8_t *tlv = NULL;
        size_t tlv_size = 0;

        ASNBER_TEST_CHECK(open_encoded(ctx, &encoded, &info, &encrypted) == 0);
        ASNBER_TEST_CHECK(asnber_cms_encrypted_data_version(encrypted, &version) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(version == 2);
        ASNBER_TEST_CHECK(asnber_cms_encrypted_data_encrypted_content(
                            encrypted, &data, &data_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(data != NULL);
        ASNBER_TEST_CHECK(data_size == 0);
        static const uint8_t kEmptyContentTlv[2] = {0x80, 0x00};
        ASNBER_TEST_CHECK(asnber_cms_encrypted_data_encrypted_content_tlv(
                            encrypted, &tlv, &tlv_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(tlv, tlv_size, kEmptyContentTlv, 2));
        ASNBER_TEST_CHECK(asnber_cms_encrypted_data_unprotected_attrs_tlv(
                            encrypted, &tlv, &tlv_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(tlv, tlv_size, kExpectedAttrs,
                                    sizeof(kExpectedAttrs)));

        asnber_cms_encrypted_data_close(encrypted);
        asnber_cms_content_info_close(info);
    }

    asnber_buf_release(ctx, &encoded);
    asnber_cms_encrypted_builder_destroy(builder);
    return 0;
}

/* 非空 encryptedContent 的 builder → reader 往返。 */
static int check_builder_content_roundtrip(asnber_ctx_t *ctx)
{
    static const uint8_t kContent[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    asnber_cms_encrypted_builder_t *builder = NULL;
    asnber_buf_t encoded;
    memset(&encoded, 0, sizeof(encoded));

    ASNBER_TEST_CHECK(asnber_cms_encrypted_builder_create(ctx, &builder) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_encrypted_builder_set_version(builder, 0) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_encrypted_builder_set_content_type(
                        builder, kDataOid) == ASNBER_OK);
    ASNBER_TEST_CHECK(
        asnber_cms_encrypted_builder_set_content_encryption_algorithm(
            builder, kAes256CbcOid, NULL, 0) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_encrypted_builder_set_encrypted_content(
                        builder, kContent, sizeof(kContent)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_encrypted_builder_encode(builder, &encoded) ==
                    ASNBER_OK);

    {
        asnber_cms_content_info_t *info = NULL;
        asnber_cms_encrypted_data_t *encrypted = NULL;
        const uint8_t *data = NULL;
        size_t data_size = 0;
        const uint8_t *tlv = NULL;
        size_t tlv_size = 0;

        ASNBER_TEST_CHECK(open_encoded(ctx, &encoded, &info, &encrypted) == 0);
        ASNBER_TEST_CHECK(asnber_cms_encrypted_data_encrypted_content(
                            encrypted, &data, &data_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(data, data_size, kContent,
                                    sizeof(kContent)));
        ASNBER_TEST_CHECK(asnber_cms_encrypted_data_encrypted_content_tlv(
                            encrypted, &tlv, &tlv_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(tlv_size == 6);
        ASNBER_TEST_CHECK(tlv[0] == 0x80 && tlv[1] == 0x04);
        ASNBER_TEST_CHECK(memcmp(tlv + 2, kContent, sizeof(kContent)) == 0);

        asnber_cms_encrypted_data_close(encrypted);
        asnber_cms_content_info_close(info);
    }

    asnber_buf_release(ctx, &encoded);
    asnber_cms_encrypted_builder_destroy(builder);
    return 0;
}

static int check_builder_errors(asnber_ctx_t *ctx)
{
    asnber_buf_t encoded;
    memset(&encoded, 0, sizeof(encoded));

    ASNBER_TEST_CHECK(asnber_cms_encrypted_builder_create(NULL, NULL) ==
                    ASNBER_E_INVALID_ARG);
    {
        asnber_cms_encrypted_builder_t *builder = NULL;
        ASNBER_TEST_CHECK(asnber_cms_encrypted_builder_create(ctx, &builder) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_encrypted_builder_encode(builder, &encoded) ==
                        ASNBER_E_INVALID_STATE);
        ASNBER_TEST_CHECK(encoded.data == NULL && encoded.size == 0);
        ASNBER_TEST_CHECK(asnber_cms_encrypted_builder_set_version(NULL, 0) ==
                        ASNBER_E_INVALID_ARG);
        ASNBER_TEST_CHECK(asnber_cms_encrypted_builder_set_version(builder, 0) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_encrypted_builder_set_version(builder, 0) ==
                        ASNBER_E_INVALID_STATE);
        ASNBER_TEST_CHECK(asnber_cms_encrypted_builder_set_content_type(
                            builder, kDataOid) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_encrypted_builder_set_content_type(
                            builder, kDataOid) == ASNBER_E_INVALID_STATE);
        ASNBER_TEST_CHECK(
            asnber_cms_encrypted_builder_set_content_encryption_algorithm(
                builder, kAes256CbcOid, NULL, 0) == ASNBER_OK);
        ASNBER_TEST_CHECK(
            asnber_cms_encrypted_builder_set_content_encryption_algorithm(
                builder, kAes256CbcOid, NULL, 0) == ASNBER_E_INVALID_STATE);
        ASNBER_TEST_CHECK(asnber_cms_encrypted_builder_set_encrypted_content(
                            builder, NULL, 1) == ASNBER_E_INVALID_ARG);
        ASNBER_TEST_CHECK(asnber_cms_encrypted_builder_set_encrypted_content(
                            builder, NULL, 0) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_encrypted_builder_set_encrypted_content(
                            builder, NULL, 0) == ASNBER_E_INVALID_STATE);
        ASNBER_TEST_CHECK(asnber_cms_encrypted_builder_set_unprotected_attrs(
                            builder, NULL, 0) == ASNBER_E_INVALID_ARG);
        /* version 0 与 unprotectedAttrs 不能共存。 */
        {
            static const uint8_t kAttrsSet[14] = {
                0x31, 0x0C, 0x30, 0x0A, 0x06, 0x03, 0x2A,
                0x03, 0x04, 0x31, 0x03, 0x02, 0x01, 0x01};
            ASNBER_TEST_CHECK(asnber_cms_encrypted_builder_set_unprotected_attrs(
                                builder, kAttrsSet,
                                sizeof(kAttrsSet)) == ASNBER_OK);
            ASNBER_TEST_CHECK(asnber_cms_encrypted_builder_set_unprotected_attrs(
                                builder, kAttrsSet,
                                sizeof(kAttrsSet)) == ASNBER_E_INVALID_STATE);
            ASNBER_TEST_CHECK(
                asnber_cms_encrypted_builder_encode(builder, &encoded) ==
                ASNBER_E_INVALID_VALUE);
            ASNBER_TEST_CHECK(encoded.data == NULL && encoded.size == 0);
        }
        asnber_cms_encrypted_builder_destroy(builder);
    }

    /* version 2 但没有 unprotectedAttrs。 */
    {
        asnber_cms_encrypted_builder_t *builder = NULL;
        ASNBER_TEST_CHECK(asnber_cms_encrypted_builder_create(ctx, &builder) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_encrypted_builder_set_version(builder, 2) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_encrypted_builder_set_content_type(
                            builder, kDataOid) == ASNBER_OK);
        ASNBER_TEST_CHECK(
            asnber_cms_encrypted_builder_set_content_encryption_algorithm(
                builder, kAes256CbcOid, NULL, 0) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_encrypted_builder_encode(builder, &encoded) ==
                        ASNBER_E_INVALID_VALUE);
        ASNBER_TEST_CHECK(encoded.data == NULL && encoded.size == 0);
        asnber_cms_encrypted_builder_destroy(builder);
    }

    /* 非 0/2 的 version：setter 立即拒绝，且失败不改变 builder 状态。 */
    {
        asnber_cms_encrypted_builder_t *builder = NULL;
        ASNBER_TEST_CHECK(asnber_cms_encrypted_builder_create(ctx, &builder) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_encrypted_builder_set_version(builder, 1) ==
                        ASNBER_E_INVALID_VALUE);
        ASNBER_TEST_CHECK(asnber_cms_encrypted_builder_set_version(builder, 3) ==
                        ASNBER_E_INVALID_VALUE);
        /* setter 拒绝后仍未设置版本，可补设 0 并正常编码。 */
        ASNBER_TEST_CHECK(asnber_cms_encrypted_builder_set_version(builder, 0) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_encrypted_builder_set_content_type(
                            builder, kDataOid) == ASNBER_OK);
        ASNBER_TEST_CHECK(
            asnber_cms_encrypted_builder_set_content_encryption_algorithm(
                builder, kAes256CbcOid, NULL, 0) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_encrypted_builder_encode(builder, &encoded) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(encoded.data != NULL && encoded.size != 0);
        asnber_buf_release(ctx, &encoded);
        asnber_cms_encrypted_builder_destroy(builder);
    }

    asnber_cms_encrypted_builder_destroy(NULL);
    return 0;
}

static int check_errors(asnber_ctx_t *ctx)
{
    asnber_cms_encrypted_data_t *encrypted = NULL;
    ASNBER_TEST_CHECK(asnber_cms_encrypted_data_open(
                        ctx, NULL, 0, &encrypted) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(encrypted == NULL);
    ASNBER_TEST_CHECK(asnber_cms_encrypted_data_open(
                        ctx, kDetached, sizeof(kDetached), NULL) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_encrypted_data_open(
                        ctx, kMissingContentInfo,
                        sizeof(kMissingContentInfo), &encrypted) != ASNBER_OK);
    ASNBER_TEST_CHECK(encrypted == NULL);
    ASNBER_TEST_CHECK(asnber_cms_encrypted_data_open(
                        ctx, kDetached, sizeof(kDetached) - 1, &encrypted) !=
                    ASNBER_OK);
    ASNBER_TEST_CHECK(encrypted == NULL);

    ASNBER_TEST_CHECK(asnber_cms_encrypted_data_open(
                        ctx, kDetached, sizeof(kDetached), &encrypted) ==
                    ASNBER_OK);
    int64_t version = 0;
    const uint8_t *data = NULL;
    size_t data_size = 0;
    ASNBER_TEST_CHECK(asnber_cms_encrypted_data_version(NULL, &version) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_encrypted_data_version(encrypted, NULL) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_encrypted_data_encrypted_content(
                        NULL, &data, &data_size) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_encrypted_data_encrypted_content(
                        encrypted, NULL, &data_size) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_encrypted_data_unprotected_attrs_tlv(
                        NULL, &data, &data_size) == ASNBER_E_INVALID_ARG);
    asnber_cms_encrypted_data_close(encrypted);
    return 0;
}

int main(void)
{
    asnber_ctx_t *ctx = make_ctx();
    ASNBER_TEST_CHECK(ctx != NULL);

    ASNBER_TEST_CHECK(check_openssl_sample(ctx) == 0);
    ASNBER_TEST_CHECK(check_detached(ctx) == 0);
    ASNBER_TEST_CHECK(check_empty_content(ctx) == 0);
    ASNBER_TEST_CHECK(check_version2_attrs(ctx) == 0);
    ASNBER_TEST_CHECK(check_errors(ctx) == 0);
    ASNBER_TEST_CHECK(check_builder_detached(ctx) == 0);
    ASNBER_TEST_CHECK(check_builder_empty_content_and_attrs(ctx) == 0);
    ASNBER_TEST_CHECK(check_builder_content_roundtrip(ctx) == 0);
    ASNBER_TEST_CHECK(check_builder_errors(ctx) == 0);

    asnber_ctx_destroy(ctx);
    return 0;
}
