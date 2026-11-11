/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * asnber-cms ContentInfo builder：正例（TLV / OCTET STRING / 缺省 content）、
 * 负例（必填缺失、重复设置、两种 content 互斥、非法 TLV）与编码后回读。
 */

#include <asnber/asnber.h>
#include <asnber/cms/cms.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "check.h"
#include "test_compare.h"

static const char kDataOid[] = "1.2.840.113549.1.7.1";

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

/* content 以原始字节设置：内层应为补出的 OCTET STRING。 */
static int test_octets_content(void)
{
    static const uint8_t kPayload[] = {0x01, 0x02, 0x03};
    /* 期望内层完整 TLV：OCTET STRING(3) + payload。 */
    static const uint8_t kExpected[] = {0x04, 0x03, 0x01, 0x02, 0x03};

    asnber_ctx_t *ctx = make_ctx();
    asnber_cms_content_info_builder_t *builder = NULL;
    asnber_buf_t encoded;
    asnber_cms_content_info_t *info = NULL;
    const char *oid = NULL;
    size_t oid_size = 0;
    const uint8_t *content = NULL;
    size_t content_size = 0;
    memset(&encoded, 0, sizeof(encoded));

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(asnber_cms_content_info_builder_create(ctx, &builder) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_content_info_builder_set_content_type(
                        builder, kDataOid) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_content_info_builder_set_content_octets(
                        builder, kPayload, sizeof(kPayload)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_content_info_builder_encode(builder, &encoded) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(encoded.data != NULL && encoded.size > 0);

    ASNBER_TEST_CHECK(asnber_cms_content_info_open(ctx, encoded.data, encoded.size,
                                               &info) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_content_info_content_type(info, &oid,
                                                       &oid_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(text_equals(oid, oid_size, kDataOid));
    ASNBER_TEST_CHECK(asnber_cms_content_info_content(info, &content,
                                                  &content_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(content_size == sizeof(kExpected));
    ASNBER_TEST_CHECK(memcmp(content, kExpected, sizeof(kExpected)) == 0);

    asnber_cms_content_info_close(info);
    asnber_buf_release(ctx, &encoded);
    asnber_cms_content_info_builder_destroy(builder);
    asnber_ctx_destroy(ctx);
    return 0;
}

/* content 以完整 TLV 设置：内层应逐字节保留。 */
static int test_tlv_content(void)
{
    static const uint8_t kInner[] = {0x02, 0x01, 0x2A}; /* INTEGER 42 */

    asnber_ctx_t *ctx = make_ctx();
    asnber_cms_content_info_builder_t *builder = NULL;
    asnber_buf_t encoded;
    asnber_cms_content_info_t *info = NULL;
    const char *oid = NULL;
    size_t oid_size = 0;
    const uint8_t *content = NULL;
    size_t content_size = 0;
    memset(&encoded, 0, sizeof(encoded));

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(asnber_cms_content_info_builder_create(ctx, &builder) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_content_info_builder_set_content_type(
                        builder, kDataOid) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_content_info_builder_set_content_tlv(
                        builder, kInner, sizeof(kInner)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_content_info_builder_encode(builder, &encoded) ==
                    ASNBER_OK);

    ASNBER_TEST_CHECK(asnber_cms_content_info_open(ctx, encoded.data, encoded.size,
                                               &info) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_content_info_content_type(info, &oid,
                                                       &oid_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(text_equals(oid, oid_size, kDataOid));
    ASNBER_TEST_CHECK(asnber_cms_content_info_content(info, &content,
                                                  &content_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(content_size == sizeof(kInner));
    ASNBER_TEST_CHECK(memcmp(content, kInner, sizeof(kInner)) == 0);

    asnber_cms_content_info_close(info);
    asnber_buf_release(ctx, &encoded);
    asnber_cms_content_info_builder_destroy(builder);
    asnber_ctx_destroy(ctx);
    return 0;
}

/* content 必填：只设置 contentType 时编码失败且不产出半成品。 */
static int test_missing_content(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_cms_content_info_builder_t *builder = NULL;
    asnber_buf_t encoded;

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(asnber_cms_content_info_builder_create(ctx, &builder) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_content_info_builder_set_content_type(
                        builder, kDataOid) == ASNBER_OK);
    memset(&encoded, 0xFF, sizeof(encoded));
    ASNBER_TEST_CHECK(asnber_cms_content_info_builder_encode(builder, &encoded) ==
                    ASNBER_E_SCHEMA_FIELD);
    ASNBER_TEST_CHECK(encoded.data == NULL && encoded.size == 0 &&
                    encoded.capacity == 0);

    asnber_cms_content_info_builder_destroy(builder);
    asnber_ctx_destroy(ctx);
    return 0;
}

static int test_negative(void)
{
    static const uint8_t kInvalid[] = {0x02};
    static const uint8_t kValid[] = {0x02, 0x01, 0x01};

    asnber_ctx_t *ctx = make_ctx();
    asnber_cms_content_info_builder_t *builder = NULL;
    asnber_buf_t encoded;

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(asnber_cms_content_info_builder_create(NULL, &builder) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_content_info_builder_create(ctx, NULL) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_content_info_builder_create(ctx, &builder) ==
                    ASNBER_OK);

    ASNBER_TEST_CHECK(asnber_cms_content_info_builder_set_content_type(NULL,
                                                                   kDataOid) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_content_info_builder_set_content_type(builder,
                                                                   NULL) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_content_info_builder_set_content_type(
                        builder, "1.2.") != ASNBER_OK);

    /* contentType 必填：缺失时 encode 拒绝。 */
    memset(&encoded, 0xFF, sizeof(encoded));
    ASNBER_TEST_CHECK(asnber_cms_content_info_builder_encode(builder, &encoded) ==
                    ASNBER_E_INVALID_STATE);
    ASNBER_TEST_CHECK(encoded.data == NULL && encoded.size == 0 &&
                    encoded.capacity == 0);

    ASNBER_TEST_CHECK(asnber_cms_content_info_builder_set_content_type(
                        builder, kDataOid) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_content_info_builder_set_content_type(
                        builder, kDataOid) == ASNBER_E_INVALID_STATE);

    ASNBER_TEST_CHECK(asnber_cms_content_info_builder_set_content_tlv(
                        builder, NULL, 3) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_content_info_builder_set_content_tlv(
                        builder, kValid, 0) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_content_info_builder_set_content_tlv(
                        builder, kInvalid, sizeof(kInvalid)) != ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_content_info_builder_set_content_tlv(
                        builder, kValid, sizeof(kValid)) == ASNBER_OK);
    /* 两种 content 互斥；同一种重复设置同样拒绝。 */
    ASNBER_TEST_CHECK(asnber_cms_content_info_builder_set_content_octets(
                        builder, kValid, sizeof(kValid)) ==
                    ASNBER_E_INVALID_STATE);
    ASNBER_TEST_CHECK(asnber_cms_content_info_builder_set_content_tlv(
                        builder, kValid, sizeof(kValid)) ==
                    ASNBER_E_INVALID_STATE);

    ASNBER_TEST_CHECK(asnber_cms_content_info_builder_encode(NULL, &encoded) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_content_info_builder_encode(builder, NULL) ==
                    ASNBER_E_INVALID_ARG);

    asnber_cms_content_info_builder_destroy(builder);
    asnber_cms_content_info_builder_destroy(NULL);
    asnber_ctx_destroy(ctx);
    return 0;
}

int main(void)
{
    if (test_octets_content() != 0) {
        return 1;
    }
    if (test_tlv_content() != 0) {
        return 1;
    }
    if (test_missing_content() != 0) {
        return 1;
    }
    if (test_negative() != 0) {
        return 1;
    }
    return 0;
}
