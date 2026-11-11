/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * asnber-pkcs12 PFX / AuthenticatedSafe builder：与 OpenSSL 夹具逐字节对拍
 * （data 与 encryptedData 两种形态）、authSafe content octets、macData
 * DEFAULT 1 省略与负例。
 */

#include <asnber/asnber.h>
#include <asnber/pkcs12/pkcs12.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "../data/pfx_certs_only.h"
#include "../data/pfx_rsa_unencrypted.h"
#include "check.h"
#include "test_compare.h"

static const char *const kDataOid = "1.2.840.113549.1.7.1";
static const char *const kEncryptedDataOid = "1.2.840.113549.1.7.6";
static const char *const kSha256Oid = "2.16.840.1.101.3.4.2.1";

/* ---------- DER 辅助 ---------- */

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

/* 解析单个 DER TLV 的头部，返回内容起点偏移；失败返回 0。 */
static size_t tlv_content_offset(const uint8_t *tlv, size_t size)
{
    size_t header = 2;
    size_t length = 0;
    size_t i = 0;

    if (tlv == NULL || size < 2) {
        return 0;
    }
    length = tlv[1];
    if ((length & 0x80u) != 0) {
        const size_t count = length & 0x7Fu;
        if (count == 0 || count > sizeof(size_t) || size < 2 + count) {
            return 0;
        }
        length = 0;
        for (i = 0; i < count; ++i) {
            length = (length << 8) | tlv[2 + i];
        }
        header = 2 + count;
    }
    if (length != size - header) {
        return 0;
    }
    return header;
}

/* 用完整内容构造单字节标签的 DER TLV（长度支持长形式）。 */
static uint8_t *make_tlv(uint8_t tag, const uint8_t *content, size_t size,
                         size_t *out_size)
{
    size_t header = 2;
    size_t length_bytes = 0;
    size_t value = size;

    if (size >= 0x80) {
        while (value != 0) {
            ++length_bytes;
            value >>= 8;
        }
        header += length_bytes;
    }
    uint8_t *tlv = (uint8_t *)malloc(header + size);
    if (tlv == NULL) {
        return NULL;
    }
    tlv[0] = tag;
    if (size < 0x80) {
        tlv[1] = (uint8_t)size;
    } else {
        tlv[1] = (uint8_t)(0x80 | length_bytes);
        for (size_t i = 0; i < length_bytes; ++i) {
            tlv[2 + i] = (uint8_t)(size >> (8 * (length_bytes - 1 - i)));
        }
    }
    if (size != 0) {
        memcpy(tlv + header, content, size);
    }
    *out_size = header + size;
    return tlv;
}

/* ---------- data 形态：pfx_rsa_unencrypted ---------- */

static int test_pfx_data_form(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_pkcs12_pfx_t *pfx = NULL;
    asnber_pkcs12_authenticated_safe_t *safe = NULL;
    asnber_pkcs12_authenticated_safe_builder_t *safe_builder = NULL;
    asnber_pkcs12_pfx_builder_t *pfx_builder = NULL;
    asnber_buf_t encoded;
    asnber_buf_t whole;
    const char *type = NULL;
    size_t type_size = 0;
    const uint8_t *content = NULL;
    size_t content_size = 0;
    const uint8_t *as_der = NULL;
    size_t as_der_size = 0;
    const uint8_t *safe_contents[2] = {NULL, NULL};
    size_t safe_contents_size[2] = {0, 0};
    size_t count = 0;
    int present = -1;
    int64_t version = 0;

    ASNBER_TEST_CHECK(ctx != NULL);
    memset(&encoded, 0, sizeof(encoded));
    memset(&whole, 0, sizeof(whole));

    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_open(ctx, kPfxRsaUnencrypted,
                                         kPfxRsaUnencryptedSize,
                                         &pfx) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_version(pfx, &version) == ASNBER_OK);
    ASNBER_TEST_CHECK(version == 3);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_mac_present(pfx, &present) == ASNBER_OK);
    ASNBER_TEST_CHECK(present == 0);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_auth_safe_content_type(
                        pfx, &type, &type_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(type_size == strlen(kDataOid));
    ASNBER_TEST_CHECK(memcmp(type, kDataOid, type_size) == 0);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_auth_safe_content_tlv(
                        pfx, &content, &content_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(tlv_content_offset(content, content_size) != 0);
    as_der = content + tlv_content_offset(content, content_size);
    as_der_size = content_size - tlv_content_offset(content, content_size);

    ASNBER_TEST_CHECK(asnber_pkcs12_authenticated_safe_open(ctx, as_der, as_der_size,
                                                        &safe) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs12_authenticated_safe_content_count(safe, &count) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(count == 2);
    for (size_t i = 0; i < count; ++i) {
        const uint8_t *item = NULL;
        size_t item_size = 0;
        size_t offset = 0;
        ASNBER_TEST_CHECK(asnber_pkcs12_authenticated_safe_content_at(
                            safe, i, &type, &type_size, &item,
                            &item_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(type_size == strlen(kDataOid));
        ASNBER_TEST_CHECK(memcmp(type, kDataOid, type_size) == 0);
        offset = tlv_content_offset(item, item_size);
        ASNBER_TEST_CHECK(offset != 0);
        safe_contents[i] = item + offset;
        safe_contents_size[i] = item_size - offset;
    }

    /* AuthenticatedSafe builder：两个 data 条目。 */
    ASNBER_TEST_CHECK(asnber_pkcs12_authenticated_safe_builder_create(
                        ctx, &safe_builder) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs12_authenticated_safe_builder_add_data(
                        safe_builder, safe_contents[0],
                        safe_contents_size[0]) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs12_authenticated_safe_builder_add_data(
                        safe_builder, safe_contents[1],
                        safe_contents_size[1]) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs12_authenticated_safe_builder_encode(
                        safe_builder, &encoded) == ASNBER_OK);
    ASNBER_TEST_CHECK(bytes_equal(encoded.data, encoded.size, as_der,
                                as_der_size));
    asnber_buf_release(ctx, &encoded);
    asnber_pkcs12_authenticated_safe_close(safe);

    /* PFX builder：data ContentInfo + 无 macData。 */
    {
        size_t octet_size = 0;
        uint8_t *octet_tlv = make_tlv(0x04, as_der, as_der_size, &octet_size);
        ASNBER_TEST_CHECK(octet_tlv != NULL);
        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_create(ctx, &pfx_builder) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_set_version(pfx_builder, 3) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_set_auth_safe(
                            pfx_builder, kDataOid, octet_tlv,
                            octet_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_encode(pfx_builder,
                                                       &whole) == ASNBER_OK);
        ASNBER_TEST_CHECK(whole.size == kPfxRsaUnencryptedSize);
        ASNBER_TEST_CHECK(bytes_equal(whole.data, whole.size,
                                    kPfxRsaUnencrypted,
                                    kPfxRsaUnencryptedSize));
        asnber_buf_release(ctx, &whole);
        free(octet_tlv);
    }

    /* authSafe content octets 供 macData 计算。 */
    {
        const uint8_t *octets = NULL;
        size_t octets_size = 0;
        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_auth_safe_content_octets(
                            pfx_builder, &octets, &octets_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(octets, octets_size, as_der, as_der_size));
    }

    asnber_pkcs12_pfx_builder_destroy(pfx_builder);
    asnber_pkcs12_authenticated_safe_builder_destroy(safe_builder);
    asnber_pkcs12_pfx_close(pfx);
    asnber_ctx_destroy(ctx);
    return 0;
}

/* ---------- encryptedData 形态：pfx_certs_only ---------- */

static int test_pfx_encrypted_form(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_pkcs12_pfx_t *pfx = NULL;
    asnber_pkcs12_authenticated_safe_t *safe = NULL;
    asnber_pkcs12_authenticated_safe_builder_t *safe_builder = NULL;
    asnber_pkcs12_pfx_builder_t *pfx_builder = NULL;
    asnber_buf_t encoded;
    asnber_buf_t whole;
    const char *type = NULL;
    size_t type_size = 0;
    const char *digest_oid = NULL;
    size_t digest_oid_size = 0;
    const uint8_t *content = NULL;
    size_t content_size = 0;
    const uint8_t *params = NULL;
    size_t params_size = 0;
    const uint8_t *digest = NULL;
    size_t digest_size = 0;
    const uint8_t *salt = NULL;
    size_t salt_size = 0;
    const uint8_t *as_der = NULL;
    size_t as_der_size = 0;
    const uint8_t *encrypted = NULL;
    size_t encrypted_size = 0;
    size_t count = 0;
    int present = -1;
    int64_t iterations = 0;
    int64_t version = 0;

    ASNBER_TEST_CHECK(ctx != NULL);
    memset(&encoded, 0, sizeof(encoded));
    memset(&whole, 0, sizeof(whole));

    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_open(ctx, kPfxCertsOnly, kPfxCertsOnlySize,
                                         &pfx) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_version(pfx, &version) == ASNBER_OK);
    ASNBER_TEST_CHECK(version == 3);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_mac_present(pfx, &present) == ASNBER_OK);
    ASNBER_TEST_CHECK(present == 1);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_mac_digest_algorithm_oid(
                        pfx, &digest_oid, &digest_oid_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(digest_oid_size == strlen(kSha256Oid));
    ASNBER_TEST_CHECK(memcmp(digest_oid, kSha256Oid, digest_oid_size) == 0);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_mac_digest_algorithm_parameters(
                        pfx, &params, &params_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(params != NULL && params_size == 2);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_mac_digest(pfx, &digest, &digest_size) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(digest_size == 32);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_mac_salt(pfx, &salt, &salt_size) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(salt_size != 0);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_mac_iterations(pfx, &iterations) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(iterations == 2048);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_auth_safe_content_type(
                        pfx, &type, &type_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(type_size == strlen(kDataOid));
    ASNBER_TEST_CHECK(memcmp(type, kDataOid, type_size) == 0);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_auth_safe_content_tlv(
                        pfx, &content, &content_size) == ASNBER_OK);
    as_der = content + tlv_content_offset(content, content_size);
    as_der_size = content_size - tlv_content_offset(content, content_size);

    ASNBER_TEST_CHECK(asnber_pkcs12_authenticated_safe_open(ctx, as_der, as_der_size,
                                                        &safe) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs12_authenticated_safe_content_count(safe, &count) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(count == 1);
    ASNBER_TEST_CHECK(asnber_pkcs12_authenticated_safe_content_at(
                        safe, 0, &type, &type_size, &encrypted,
                        &encrypted_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(type_size == strlen(kEncryptedDataOid));
    ASNBER_TEST_CHECK(memcmp(type, kEncryptedDataOid, type_size) == 0);
    ASNBER_TEST_CHECK(encrypted != NULL && encrypted_size != 0);

    /* AuthenticatedSafe builder：encryptedData 原样。 */
    ASNBER_TEST_CHECK(asnber_pkcs12_authenticated_safe_builder_create(
                        ctx, &safe_builder) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs12_authenticated_safe_builder_add_encrypted_data(
                        safe_builder, encrypted, encrypted_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs12_authenticated_safe_builder_encode(
                        safe_builder, &encoded) == ASNBER_OK);
    ASNBER_TEST_CHECK(bytes_equal(encoded.data, encoded.size, as_der,
                                as_der_size));
    asnber_buf_release(ctx, &encoded);
    asnber_pkcs12_authenticated_safe_close(safe);

    /* PFX builder：data ContentInfo + macData（iterations = 2048）。 */
    {
        size_t octet_size = 0;
        uint8_t *octet_tlv = make_tlv(0x04, as_der, as_der_size, &octet_size);
        ASNBER_TEST_CHECK(octet_tlv != NULL);
        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_create(ctx, &pfx_builder) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_set_version(pfx_builder, 3) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_set_auth_safe(
                            pfx_builder, kDataOid, octet_tlv,
                            octet_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_set_mac_data(
                            pfx_builder, kSha256Oid, params, params_size,
                            digest, digest_size, salt, salt_size,
                            iterations) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_encode(pfx_builder,
                                                       &whole) == ASNBER_OK);
        ASNBER_TEST_CHECK(whole.size == kPfxCertsOnlySize);
        ASNBER_TEST_CHECK(bytes_equal(whole.data, whole.size, kPfxCertsOnly,
                                    kPfxCertsOnlySize));
        asnber_buf_release(ctx, &whole);
        free(octet_tlv);
    }

    {
        const uint8_t *octets = NULL;
        size_t octets_size = 0;
        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_auth_safe_content_octets(
                            pfx_builder, &octets, &octets_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(octets, octets_size, as_der, as_der_size));
    }

    asnber_pkcs12_pfx_builder_destroy(pfx_builder);
    asnber_pkcs12_authenticated_safe_builder_destroy(safe_builder);
    asnber_pkcs12_pfx_close(pfx);
    asnber_ctx_destroy(ctx);
    return 0;
}

/* ---------- macData iterations DEFAULT 1 省略 ---------- */

static int test_mac_default_iterations(void)
{
    static const uint8_t kDigest[] = {0xAA, 0xBB};
    static const uint8_t kSalt[] = {0x01, 0x02, 0x03, 0x04};
    static const uint8_t kSafeContents[] = {0x30, 0x00};
    asnber_ctx_t *ctx = make_ctx();
    asnber_pkcs12_pfx_builder_t *builder = NULL;
    asnber_pkcs12_pfx_t *pfx = NULL;
    asnber_buf_t with_default;
    asnber_buf_t with_two;
    uint8_t *octet_tlv = NULL;
    size_t octet_size = 0;
    int64_t iterations = 0;
    int present = 0;

    ASNBER_TEST_CHECK(ctx != NULL);
    memset(&with_default, 0, sizeof(with_default));
    memset(&with_two, 0, sizeof(with_two));
    octet_tlv = make_tlv(0x04, kSafeContents, sizeof(kSafeContents),
                         &octet_size);
    ASNBER_TEST_CHECK(octet_tlv != NULL);

    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_create(ctx, &builder) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_set_auth_safe(
                        builder, kDataOid, octet_tlv, octet_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_set_mac_data(
                        builder, kSha256Oid, NULL, 0, kDigest,
                        sizeof(kDigest), kSalt, sizeof(kSalt),
                        1) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_encode(builder, &with_default) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_open(ctx, with_default.data,
                                         with_default.size, &pfx) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_mac_present(pfx, &present) == ASNBER_OK);
    ASNBER_TEST_CHECK(present == 1);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_mac_iterations(pfx, &iterations) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(iterations == 1);
    asnber_pkcs12_pfx_close(pfx);
    asnber_pkcs12_pfx_builder_destroy(builder);

    /* iterations = 2 时多出 INTEGER 3 字节；反证 1 时完全省略。 */
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_create(ctx, &builder) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_set_auth_safe(
                        builder, kDataOid, octet_tlv, octet_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_set_mac_data(
                        builder, kSha256Oid, NULL, 0, kDigest,
                        sizeof(kDigest), kSalt, sizeof(kSalt),
                        2) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_encode(builder, &with_two) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(with_two.size == with_default.size + 3);

    asnber_pkcs12_pfx_builder_destroy(builder);
    asnber_buf_release(ctx, &with_two);
    asnber_buf_release(ctx, &with_default);
    free(octet_tlv);
    asnber_ctx_destroy(ctx);
    return 0;
}

/* ---------- 负例 ---------- */

static int test_negative(void)
{
    static const uint8_t kTruncated[] = {0x30, 0x05, 0x02};
    static const uint8_t kBadOid[] = "not-an-oid";
    static const uint8_t kDigest[] = {0xAA};
    static const uint8_t kSalt[] = {0x01};
    static const uint8_t kOctet[] = {0x04, 0x02, 0x30, 0x00};
    static const uint8_t kSequence[] = {0x30, 0x00};
    asnber_ctx_t *ctx = make_ctx();
    asnber_pkcs12_pfx_builder_t *pfx_builder = NULL;
    asnber_pkcs12_authenticated_safe_builder_t *safe_builder = NULL;
    asnber_buf_t out;

    ASNBER_TEST_CHECK(ctx != NULL);
    memset(&out, 0, sizeof(out));

    /* 生命周期。 */
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_create(NULL, &pfx_builder) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_create(ctx, NULL) ==
                    ASNBER_E_INVALID_ARG);
    asnber_pkcs12_pfx_builder_destroy(NULL);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_create(ctx, &pfx_builder) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_encode(pfx_builder, &out) ==
                    ASNBER_E_INVALID_STATE);
    ASNBER_TEST_CHECK(out.data == NULL);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_encode(pfx_builder, NULL) ==
                    ASNBER_E_INVALID_ARG);

    /* version。 */
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_set_version(pfx_builder, -1) ==
                    ASNBER_E_INVALID_VALUE);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_set_version(pfx_builder, 3) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_set_version(pfx_builder, 3) ==
                    ASNBER_E_INVALID_STATE);

    /* authSafe。 */
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_auth_safe_content_octets(
                        pfx_builder, NULL, NULL) == ASNBER_E_INVALID_ARG);
    {
        const uint8_t *octets = NULL;
        size_t octets_size = 0;
        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_auth_safe_content_octets(
                            pfx_builder, &octets, &octets_size) ==
                        ASNBER_E_INVALID_STATE);
    }
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_set_auth_safe(
                        pfx_builder, kDataOid, NULL, 0) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_set_auth_safe(
                        pfx_builder, (const char *)kBadOid, kOctet,
                        sizeof(kOctet)) != ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_set_auth_safe(
                        pfx_builder, kDataOid, kTruncated,
                        sizeof(kTruncated)) != ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_set_auth_safe(
                        pfx_builder, kDataOid, kOctet, sizeof(kOctet)) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_set_auth_safe(
                        pfx_builder, kDataOid, kOctet, sizeof(kOctet)) ==
                    ASNBER_E_INVALID_STATE);

    /* 非 data ContentInfo 取不到内容 octets。 */
    {
        const uint8_t *octets = NULL;
        size_t octets_size = 0;
        asnber_pkcs12_pfx_builder_t *other = NULL;
        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_create(ctx, &other) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_set_auth_safe(
                            other, kEncryptedDataOid, kSequence,
                            sizeof(kSequence)) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_auth_safe_content_octets(
                            other, &octets, &octets_size) ==
                        ASNBER_E_INVALID_STATE);
        {
            /* data 但内层不是 OCTET STRING。 */
            asnber_pkcs12_pfx_builder_t *third = NULL;
            ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_create(ctx, &third) ==
                            ASNBER_OK);
            ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_set_auth_safe(
                                third, kDataOid, kSequence,
                                sizeof(kSequence)) == ASNBER_OK);
            ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_auth_safe_content_octets(
                                third, &octets, &octets_size) ==
                            ASNBER_E_INVALID_STATE);
            asnber_pkcs12_pfx_builder_destroy(third);
        }
        asnber_pkcs12_pfx_builder_destroy(other);
    }

    /* macData。 */
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_set_mac_data(
                        pfx_builder, NULL, NULL, 0, kDigest, sizeof(kDigest),
                        kSalt, sizeof(kSalt), 1) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_set_mac_data(
                        pfx_builder, kSha256Oid, NULL, 0, kDigest,
                        sizeof(kDigest), kSalt, sizeof(kSalt),
                        0) == ASNBER_E_INVALID_VALUE);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_set_mac_data(
                        pfx_builder, kSha256Oid, NULL, 0, NULL, 0, kSalt,
                        sizeof(kSalt), 1) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_set_mac_data(
                        pfx_builder, kSha256Oid, NULL, 0, kDigest,
                        sizeof(kDigest), NULL, 0, 1) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_set_mac_data(
                        pfx_builder, (const char *)kBadOid, NULL, 0, kDigest,
                        sizeof(kDigest), kSalt, sizeof(kSalt),
                        1) != ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_set_mac_data(
                        pfx_builder, kSha256Oid, kTruncated,
                        sizeof(kTruncated), kDigest, sizeof(kDigest), kSalt,
                        sizeof(kSalt), 1) != ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_set_mac_data(
                        pfx_builder, kSha256Oid, NULL, 0, kDigest,
                        sizeof(kDigest), kSalt, sizeof(kSalt),
                        1) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_builder_set_mac_data(
                        pfx_builder, kSha256Oid, NULL, 0, kDigest,
                        sizeof(kDigest), kSalt, sizeof(kSalt),
                        1) == ASNBER_E_INVALID_STATE);
    asnber_pkcs12_pfx_builder_destroy(pfx_builder);

    /* AuthenticatedSafe builder。 */
    ASNBER_TEST_CHECK(asnber_pkcs12_authenticated_safe_builder_create(
                        NULL, &safe_builder) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkcs12_authenticated_safe_builder_create(
                        ctx, NULL) == ASNBER_E_INVALID_ARG);
    asnber_pkcs12_authenticated_safe_builder_destroy(NULL);
    ASNBER_TEST_CHECK(asnber_pkcs12_authenticated_safe_builder_create(
                        ctx, &safe_builder) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkcs12_authenticated_safe_builder_encode(
                        safe_builder, NULL) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkcs12_authenticated_safe_builder_add_data(
                        safe_builder, NULL, 0) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkcs12_authenticated_safe_builder_add_data(
                        safe_builder, kTruncated, sizeof(kTruncated)) !=
                    ASNBER_OK);
    ASNBER_TEST_CHECK(
        asnber_pkcs12_authenticated_safe_builder_add_encrypted_data(
            safe_builder, NULL, 0) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(
        asnber_pkcs12_authenticated_safe_builder_add_encrypted_data(
            safe_builder, kTruncated, sizeof(kTruncated)) != ASNBER_OK);

    /* 空 AuthenticatedSafe 编成 30 00。 */
    ASNBER_TEST_CHECK(asnber_pkcs12_authenticated_safe_builder_encode(
                        safe_builder, &out) == ASNBER_OK);
    {
        static const uint8_t kEmpty[] = {0x30, 0x00};
        ASNBER_TEST_CHECK(bytes_equal(out.data, out.size, kEmpty,
                                    sizeof(kEmpty)));
    }
    asnber_buf_release(ctx, &out);
    asnber_pkcs12_authenticated_safe_builder_destroy(safe_builder);

    asnber_ctx_destroy(ctx);
    return 0;
}

int main(void)
{
    if (test_pfx_data_form() != 0) {
        return 1;
    }
    if (test_pfx_encrypted_form() != 0) {
        return 1;
    }
    if (test_mac_default_iterations() != 0) {
        return 1;
    }
    if (test_negative() != 0) {
        return 1;
    }
    return 0;
}
