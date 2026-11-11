/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * asnber-cms 只读结构访问与构造：CompressedData（RFC 3274 第 2 节）。
 * 覆盖 OpenSSL `cms -compress` 真实样本、builder 逐字节往返、detached
 * 形态，以及参数/状态负例。open 不校验 version 必须为 0，builder 只做
 * 结构组装，不解压也不校验压缩数据。
 */

#include <asnber/asnber.h>
#include <asnber/cms/cms.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../data/cms_compressed_data.h"
#include "check.h"
#include "test_compare.h"

static const char kCompressedDataOid[] = "1.2.840.113549.1.9.16.1.9";
static const char kDataOid[] = "1.2.840.113549.1.7.1";
static const char kZlibOid[] = "1.2.840.113549.1.9.16.3.8";

/*
 * CompressedData {
 *   version 1（语义非法，但 open 只做结构解码，用于固定边界）,
 *   compressionAlgorithm zlib,
 *   encapContentInfo { id-data } }
 */
static const uint8_t kVersion1[] = {
    0x30, 0x1F,
    0x02, 0x01, 0x01,
    0x30, 0x0D, 0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01,
    0x09, 0x10, 0x03, 0x08,
    0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01,
    0x07, 0x01,
};

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

/* 打开真实样本：ContentInfo(CompressedData) -> 裸 CompressedData。 */
static int open_sample(asnber_ctx_t *ctx, asnber_cms_content_info_t **out_info,
                       asnber_cms_compressed_data_t **out_data)
{
    const uint8_t *content = NULL;
    size_t content_size = 0;

    ASNBER_TEST_CHECK(asnber_cms_content_info_open(ctx, kCmsCompressedData,
                                               kCmsCompressedDataSize,
                                               out_info) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_content_info_content(*out_info, &content,
                                                  &content_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(content != NULL && content_size > 0);
    ASNBER_TEST_CHECK(asnber_cms_compressed_data_open(ctx, content, content_size,
                                                  out_data) == ASNBER_OK);
    return 0;
}

/* ---------- OpenSSL 真实样本 ---------- */

static int test_openssl_sample(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_cms_content_info_t *info = NULL;
    asnber_cms_compressed_data_t *compressed = NULL;
    const char *oid = NULL;
    size_t oid_size = 0;
    int64_t version = -1;
    const uint8_t *parameters = NULL;
    size_t parameters_size = 0;
    const uint8_t *data = NULL;
    size_t data_size = 0;
    const uint8_t *tlv = NULL;
    size_t tlv_size = 0;

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(open_sample(ctx, &info, &compressed) == 0);
    ASNBER_TEST_CHECK(asnber_cms_content_info_content_type(info, &oid,
                                                       &oid_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(text_equals(oid, oid_size, kCompressedDataOid));

    ASNBER_TEST_CHECK(asnber_cms_compressed_data_version(compressed, &version) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(version == 0);

    ASNBER_TEST_CHECK(
        asnber_cms_compressed_data_compression_algorithm(
            compressed, &oid, &oid_size, &parameters, &parameters_size) ==
        ASNBER_OK);
    ASNBER_TEST_CHECK(text_equals(oid, oid_size, kZlibOid));
    /* zlib 的 AlgorithmIdentifier 省略 parameters。 */
    ASNBER_TEST_CHECK(parameters == NULL && parameters_size == 0);

    ASNBER_TEST_CHECK(asnber_cms_compressed_data_econtent_type(
                        compressed, &oid, &oid_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(text_equals(oid, oid_size, kDataOid));

    ASNBER_TEST_CHECK(asnber_cms_compressed_data_econtent(
                        compressed, &data, &data_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(data != NULL && data_size > 0);
    ASNBER_TEST_CHECK(asnber_cms_compressed_data_econtent_tlv(
                        compressed, &tlv, &tlv_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(tlv != NULL);
    ASNBER_TEST_CHECK(tlv_size == data_size + 2);
    ASNBER_TEST_CHECK(tlv[0] == 0x04);
    ASNBER_TEST_CHECK(memcmp(tlv + 2, data, data_size) == 0);

    asnber_cms_compressed_data_close(compressed);
    asnber_cms_content_info_close(info);
    asnber_ctx_destroy(ctx);
    return 0;
}

/*
 * builder 往返：从真实样本读出压缩数据字节，按相同字段重新组装，要求与
 * OpenSSL 产物逐字节相同（样本不含随机成分）。
 */
static int test_builder_roundtrip(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_cms_content_info_t *info = NULL;
    asnber_cms_compressed_data_t *compressed = NULL;
    const uint8_t *data = NULL;
    size_t data_size = 0;
    asnber_cms_compressed_builder_t *builder = NULL;
    asnber_buf_t encoded;
    memset(&encoded, 0, sizeof(encoded));

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(open_sample(ctx, &info, &compressed) == 0);
    ASNBER_TEST_CHECK(asnber_cms_compressed_data_econtent(
                        compressed, &data, &data_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(data != NULL && data_size > 0);

    ASNBER_TEST_CHECK(asnber_cms_compressed_builder_create(ctx, &builder) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_compressed_builder_set_version(builder, 0) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(
        asnber_cms_compressed_builder_set_compression_algorithm(
            builder, kZlibOid, NULL, 0) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_compressed_builder_set_econtent_type(
                        builder, kDataOid) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_compressed_builder_set_econtent(
                        builder, data, data_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_compressed_builder_encode(builder, &encoded) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(bytes_equal(encoded.data, encoded.size, kCmsCompressedData,
                                kCmsCompressedDataSize));

    asnber_buf_release(ctx, &encoded);
    asnber_cms_compressed_builder_destroy(builder);
    asnber_cms_compressed_data_close(compressed);
    asnber_cms_content_info_close(info);
    asnber_ctx_destroy(ctx);
    return 0;
}

/* detached：不设置 eContent，编码后 encapContentInfo 只有 eContentType。 */
static int test_builder_detached(void)
{
    static const uint8_t kExpected[] = {
        0x30, 0x30,
        0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10,
        0x01, 0x09,
        0xA0, 0x21,
        0x30, 0x1F,
        0x02, 0x01, 0x00,
        0x30, 0x0D, 0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01,
        0x09, 0x10, 0x03, 0x08,
        0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01,
        0x07, 0x01,
    };
    asnber_ctx_t *ctx = make_ctx();
    asnber_cms_compressed_builder_t *builder = NULL;
    asnber_buf_t encoded;
    memset(&encoded, 0, sizeof(encoded));

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(asnber_cms_compressed_builder_create(ctx, &builder) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_compressed_builder_set_version(builder, 0) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(
        asnber_cms_compressed_builder_set_compression_algorithm(
            builder, kZlibOid, NULL, 0) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_compressed_builder_set_econtent_type(
                        builder, kDataOid) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_compressed_builder_encode(builder, &encoded) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(bytes_equal(encoded.data, encoded.size, kExpected,
                                sizeof(kExpected)));

    {
        const uint8_t *inner = NULL;
        size_t inner_size = 0;
        asnber_cms_content_info_t *info = NULL;
        asnber_cms_compressed_data_t *compressed = NULL;
        const uint8_t *data = NULL;
        size_t data_size = 1;

        ASNBER_TEST_CHECK(asnber_cms_content_info_open(ctx, encoded.data,
                                                   encoded.size, &info) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_content_info_content(info, &inner,
                                                      &inner_size) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_compressed_data_open(ctx, inner, inner_size,
                                                      &compressed) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_compressed_data_econtent(
                            compressed, &data, &data_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(data == NULL && data_size == 0);
        asnber_cms_compressed_data_close(compressed);
        asnber_cms_content_info_close(info);
    }

    asnber_buf_release(ctx, &encoded);
    asnber_cms_compressed_builder_destroy(builder);
    asnber_ctx_destroy(ctx);
    return 0;
}

/* open 不校验语义：version 1 仍按结构接受。 */
static int test_open_accepts_nonzero_version(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_cms_compressed_data_t *compressed = NULL;
    int64_t version = -1;

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(asnber_cms_compressed_data_open(
                        ctx, kVersion1, sizeof(kVersion1), &compressed) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_compressed_data_version(compressed, &version) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(version == 1);
    asnber_cms_compressed_data_close(compressed);
    asnber_ctx_destroy(ctx);
    return 0;
}

/* ---------- 负例 ---------- */

static int test_read_negative(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_cms_compressed_data_t *compressed = NULL;
    int64_t version = 0;
    const char *oid = NULL;
    size_t oid_size = 0;
    const uint8_t *data = NULL;
    size_t data_size = 0;

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(asnber_cms_compressed_data_open(
                        NULL, kCmsCompressedData, kCmsCompressedDataSize,
                        &compressed) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_compressed_data_open(
                        ctx, NULL, 0, &compressed) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_compressed_data_open(
                        ctx, kCmsCompressedData, kCmsCompressedDataSize,
                        NULL) == ASNBER_E_INVALID_ARG);
    /* 整段 ContentInfo 不是裸 CompressedData。 */
    ASNBER_TEST_CHECK(asnber_cms_compressed_data_open(
                        ctx, kCmsCompressedData, kCmsCompressedDataSize,
                        &compressed) != ASNBER_OK);
    /* 截断。 */
    ASNBER_TEST_CHECK(asnber_cms_compressed_data_open(
                        ctx, kVersion1, sizeof(kVersion1) - 1,
                        &compressed) != ASNBER_OK);

    ASNBER_TEST_CHECK(asnber_cms_compressed_data_version(NULL, &version) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_compressed_data_version(NULL, NULL) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_compressed_data_compression_algorithm(
                        NULL, &oid, &oid_size, &data, &data_size) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_compressed_data_econtent_type(
                        NULL, &oid, &oid_size) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_compressed_data_econtent(
                        NULL, &data, &data_size) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_compressed_data_econtent_tlv(
                        NULL, &data, &data_size) == ASNBER_E_INVALID_ARG);
    asnber_cms_compressed_data_close(NULL);

    asnber_ctx_destroy(ctx);
    return 0;
}

static int test_builder_negative(void)
{
    static const uint8_t kBadParams[1] = {0x00};
    asnber_ctx_t *ctx = make_ctx();
    asnber_cms_compressed_builder_t *builder = NULL;
    asnber_buf_t encoded;
    memset(&encoded, 0, sizeof(encoded));

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(asnber_cms_compressed_builder_create(NULL, &builder) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_compressed_builder_create(ctx, NULL) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_compressed_builder_create(ctx, &builder) ==
                    ASNBER_OK);

    /* 尚未设置必填字段：encode 返回状态错误。 */
    ASNBER_TEST_CHECK(asnber_cms_compressed_builder_encode(builder, &encoded) ==
                    ASNBER_E_INVALID_STATE);
    ASNBER_TEST_CHECK(asnber_cms_compressed_builder_encode(builder, NULL) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_compressed_builder_encode(NULL, &encoded) ==
                    ASNBER_E_INVALID_ARG);

    ASNBER_TEST_CHECK(asnber_cms_compressed_builder_set_version(NULL, 0) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_compressed_builder_set_version(builder, 1) ==
                    ASNBER_E_INVALID_VALUE);
    ASNBER_TEST_CHECK(asnber_cms_compressed_builder_set_version(builder, 0) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_compressed_builder_set_version(builder, 0) ==
                    ASNBER_E_INVALID_STATE);

    ASNBER_TEST_CHECK(
        asnber_cms_compressed_builder_set_compression_algorithm(
            builder, NULL, NULL, 0) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(
        asnber_cms_compressed_builder_set_compression_algorithm(
            builder, kZlibOid, NULL, 1) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(
        asnber_cms_compressed_builder_set_compression_algorithm(
            builder, "1.2.840.113549..1", NULL, 0) ==
        ASNBER_E_INVALID_VALUE);
    ASNBER_TEST_CHECK(
        asnber_cms_compressed_builder_set_compression_algorithm(
            builder, kZlibOid, kBadParams, sizeof(kBadParams)) != ASNBER_OK);
    ASNBER_TEST_CHECK(
        asnber_cms_compressed_builder_set_compression_algorithm(
            builder, kZlibOid, NULL, 0) == ASNBER_OK);
    ASNBER_TEST_CHECK(
        asnber_cms_compressed_builder_set_compression_algorithm(
            builder, kZlibOid, NULL, 0) == ASNBER_E_INVALID_STATE);

    ASNBER_TEST_CHECK(asnber_cms_compressed_builder_set_econtent_type(
                        builder, NULL) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_compressed_builder_set_econtent_type(
                        builder, "1.2.840.113549..1") != ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_compressed_builder_set_econtent_type(
                        builder, kDataOid) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_compressed_builder_set_econtent_type(
                        builder, kDataOid) == ASNBER_E_INVALID_STATE);

    ASNBER_TEST_CHECK(asnber_cms_compressed_builder_set_econtent(
                        builder, NULL, 1) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_compressed_builder_set_econtent(
                        builder, NULL, 0) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_compressed_builder_set_econtent(
                        builder, NULL, 0) == ASNBER_E_INVALID_STATE);

    /* 必填字段齐备，空内容显式存在：编码成功，DER 为 `A0 02 04 00`。 */
    ASNBER_TEST_CHECK(asnber_cms_compressed_builder_encode(builder, &encoded) ==
                    ASNBER_OK);
    {
        asnber_cms_content_info_t *info = NULL;
        const uint8_t *inner = NULL;
        size_t inner_size = 0;

        ASNBER_TEST_CHECK(asnber_cms_content_info_open(ctx, encoded.data,
                                                   encoded.size, &info) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_content_info_content(info, &inner,
                                                      &inner_size) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(inner != NULL && inner_size >= 4);
        ASNBER_TEST_CHECK(memcmp(inner + inner_size - 4, "\xA0\x02\x04\x00",
                               4) == 0);
        asnber_cms_content_info_close(info);
    }

    asnber_buf_release(ctx, &encoded);
    asnber_cms_compressed_builder_destroy(builder);
    asnber_cms_compressed_builder_destroy(NULL);
    asnber_ctx_destroy(ctx);
    return 0;
}

int main(void)
{
    if (test_openssl_sample() != 0) {
        return 1;
    }
    if (test_builder_roundtrip() != 0) {
        return 1;
    }
    if (test_builder_detached() != 0) {
        return 1;
    }
    if (test_open_accepts_nonzero_version() != 0) {
        return 1;
    }
    if (test_read_negative() != 0) {
        return 1;
    }
    if (test_builder_negative() != 0) {
        return 1;
    }
    return 0;
}
