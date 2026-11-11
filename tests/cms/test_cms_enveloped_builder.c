/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * asnber-cms EnvelopedData builder：样本 decode → 重建 → 编码逐字节往返，
 * 合成 kari / ori 分支、originatorInfo / unprotectedAttrs，以及负例。
 */

#include <asnber/asnber.h>
#include <asnber/cms/cms.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "../data/cms_enveloped_kari.h"
#include "../data/cms_enveloped_kekri.h"
#include "../data/cms_enveloped_ktri.h"
#include "../data/cms_enveloped_ktri_keyid.h"
#include "../data/cms_enveloped_ktri_multi.h"
#include "../data/cms_enveloped_pwri.h"
#include "check.h"
#include "test_compare.h"

static const char kEnvelopedDataOid[] = "1.2.840.113549.1.7.3";
static const char kDataOid[] = "1.2.840.113549.1.7.1";
static const char kAes256CbcOid[] = "2.16.840.1.101.3.4.1.42";
static const char kAes256WrapOid[] = "2.16.840.1.101.3.4.1.45";

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

/* ---------- 最小 DER 头解析（仅用于测试里从完整 TLV 中取子节点） ---------- */

static size_t der_total_length(const uint8_t *tlv, size_t avail,
                               size_t *out_content_offset,
                               size_t *out_content_size)
{
    size_t offset = 2;
    size_t length;
    if (avail < 2) {
        return 0;
    }
    length = tlv[1];
    if ((tlv[1] & 0x80u) != 0) {
        const size_t count = tlv[1] & 0x7Fu;
        if (count == 0 || count > 4 || avail < 2 + count) {
            return 0;
        }
        length = 0;
        for (size_t i = 0; i < count; ++i) {
            length = (length << 8) | tlv[2 + i];
        }
        offset = 2 + count;
    }
    if (length > avail - offset) {
        return 0;
    }
    *out_content_offset = offset;
    *out_content_size = length;
    return offset + length;
}

/* 取构造 TLV 的最后一个直接子节点的完整 TLV。 */
static int last_child_tlv(const uint8_t *tlv, size_t size,
                          const uint8_t **out_data, size_t *out_size)
{
    size_t content_offset = 0;
    size_t content_size = 0;
    size_t total = der_total_length(tlv, size, &content_offset, &content_size);
    const uint8_t *last = NULL;
    size_t last_size = 0;
    size_t pos;
    if (total == 0 || total != size) {
        return 0;
    }
    pos = content_offset;
    while (pos < total) {
        size_t child_offset = 0;
        size_t child_content = 0;
        size_t child_total = der_total_length(tlv + pos, total - pos,
                                              &child_offset, &child_content);
        if (child_total == 0) {
            return 0;
        }
        last = tlv + pos;
        last_size = child_total;
        pos += child_total;
    }
    if (last == NULL) {
        return 0;
    }
    *out_data = last;
    *out_size = last_size;
    return 1;
}

static size_t encode_length(uint8_t *dst, size_t length)
{
    if (length < 128) {
        dst[0] = (uint8_t)length;
        return 1;
    }
    if (length < 256) {
        dst[0] = 0x81;
        dst[1] = (uint8_t)length;
        return 2;
    }
    dst[0] = 0x82;
    dst[1] = (uint8_t)((length >> 8) & 0xFFu);
    dst[2] = (uint8_t)(length & 0xFFu);
    return 3;
}

/* KEKIdentifier ::= SEQUENCE { keyIdentifier OCTET STRING, ... }，仅 keyId。 */
static int build_kek_identifier(const uint8_t *key_id, size_t key_id_size,
                                uint8_t *buffer, size_t buffer_size,
                                size_t *out_size)
{
    const size_t octets_length = 2 + key_id_size;
    const size_t sequence_length = 2 + octets_length;
    size_t pos = 0;
    if (buffer_size < sequence_length) {
        return 0;
    }
    buffer[pos++] = 0x30;
    pos += encode_length(buffer + pos, octets_length);
    buffer[pos++] = 0x04;
    pos += encode_length(buffer + pos, key_id_size);
    memcpy(buffer + pos, key_id, key_id_size);
    pos += key_id_size;
    *out_size = pos;
    return 1;
}

/* ---------- 样本重建 ---------- */

static int add_sample_recipient(asnber_cms_enveloped_builder_t *builder,
                                asnber_cms_enveloped_data_t *env, size_t index)
{
    int choice = -1;
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_choice(env, index,
                                                             &choice) ==
                    ASNBER_OK);

    switch (choice) {
    case ASNBER_CMS_RECIPIENT_KTRI: {
        int64_t version = -1;
        int rid_choice = -1;
        const uint8_t *rid1 = NULL;
        size_t rid1_size = 0;
        const uint8_t *rid2 = NULL;
        size_t rid2_size = 0;
        const char *oid = NULL;
        size_t oid_size = 0;
        const uint8_t *params = NULL;
        size_t params_size = 0;
        const uint8_t *key = NULL;
        size_t key_size = 0;

        ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_version(
                            env, index, &version) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_rid_choice(
                            env, index, &rid_choice) == ASNBER_OK);
        if (rid_choice == ASNBER_CMS_RID_ISSUER_AND_SERIAL) {
            ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_rid_issuer_tlv(
                                env, index, &rid1, &rid1_size) == ASNBER_OK);
            ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_rid_serial_tlv(
                                env, index, &rid2, &rid2_size) == ASNBER_OK);
        } else {
            ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_rid_subject_key_id(
                                env, index, &rid1, &rid1_size) == ASNBER_OK);
        }
        ASNBER_TEST_CHECK(
            asnber_cms_enveloped_data_recipient_key_encryption_algorithm(
                env, index, &oid, &oid_size, &params, &params_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_encrypted_key(
                            env, index, &key, &key_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_add_ktri(
                            builder, version, rid_choice, rid1, rid1_size, rid2,
                            rid2_size, oid, params, params_size, key,
                            key_size) == ASNBER_OK);
        break;
    }
    case ASNBER_CMS_RECIPIENT_KARI: {
        int64_t version = -1;
        const uint8_t *originator = NULL;
        size_t originator_size = 0;
        const uint8_t *recipient_tlv = NULL;
        size_t recipient_tlv_size = 0;
        const uint8_t *reks = NULL;
        size_t reks_size = 0;
        const char *oid = NULL;
        size_t oid_size = 0;
        const uint8_t *params = NULL;
        size_t params_size = 0;

        ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_version(
                            env, index, &version) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_originator_tlv(
                            env, index, &originator, &originator_size) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_tlv(
                            env, index, &recipient_tlv,
                            &recipient_tlv_size) == ASNBER_OK);
        /* 样本无 ukm；recipientEncryptedKeys 是 kari 的最后一个字段。 */
        ASNBER_TEST_CHECK(last_child_tlv(recipient_tlv, recipient_tlv_size,
                                       &reks, &reks_size) == 1);
        ASNBER_TEST_CHECK(
            asnber_cms_enveloped_data_recipient_key_encryption_algorithm(
                env, index, &oid, &oid_size, &params, &params_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_add_kari(
                            builder, version, originator, originator_size, NULL,
                            0, reks, reks_size, oid, params,
                            params_size) == ASNBER_OK);
        break;
    }
    case ASNBER_CMS_RECIPIENT_KEKRI: {
        int64_t version = -1;
        const uint8_t *key_id = NULL;
        size_t key_id_size = 0;
        const char *oid = NULL;
        size_t oid_size = 0;
        const uint8_t *params = NULL;
        size_t params_size = 0;
        const uint8_t *key = NULL;
        size_t key_size = 0;
        uint8_t kekid[64];
        size_t kekid_size = 0;

        ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_version(
                            env, index, &version) == ASNBER_OK);
        ASNBER_TEST_CHECK(
            asnber_cms_enveloped_data_recipient_kekri_key_identifier(
                env, index, &key_id, &key_id_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(build_kek_identifier(key_id, key_id_size, kekid,
                                            sizeof(kekid), &kekid_size) == 1);
        ASNBER_TEST_CHECK(
            asnber_cms_enveloped_data_recipient_key_encryption_algorithm(
                env, index, &oid, &oid_size, &params, &params_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_encrypted_key(
                            env, index, &key, &key_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_add_kekri(
                            builder, version, kekid, kekid_size, oid, params,
                            params_size, key, key_size) == ASNBER_OK);
        break;
    }
    case ASNBER_CMS_RECIPIENT_PWRI: {
        int64_t version = -1;
        const uint8_t *kdf = NULL;
        size_t kdf_size = 0;
        const char *oid = NULL;
        size_t oid_size = 0;
        const uint8_t *params = NULL;
        size_t params_size = 0;
        const uint8_t *key = NULL;
        size_t key_size = 0;

        ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_version(
                            env, index, &version) == ASNBER_OK);
        ASNBER_TEST_CHECK(
            asnber_cms_enveloped_data_recipient_pwri_key_derivation_algorithm_tlv(
                env, index, &kdf, &kdf_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(
            asnber_cms_enveloped_data_recipient_key_encryption_algorithm(
                env, index, &oid, &oid_size, &params, &params_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_encrypted_key(
                            env, index, &key, &key_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_add_pwri(
                            builder, version, kdf, kdf_size, oid, params,
                            params_size, key, key_size) == ASNBER_OK);
        break;
    }
    case ASNBER_CMS_RECIPIENT_ORI: {
        const char *oid = NULL;
        size_t oid_size = 0;
        const uint8_t *value = NULL;
        size_t value_size = 0;

        ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_ori_type(
                            env, index, &oid, &oid_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_ori_value_tlv(
                            env, index, &value, &value_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_add_ori(
                            builder, oid, value, value_size) == ASNBER_OK);
        break;
    }
    default:
        return 1;
    }
    return 0;
}

static int rebuild_sample(asnber_ctx_t *ctx, const uint8_t *der,
                          size_t der_size)
{
    asnber_cms_content_info_t *info = NULL;
    asnber_cms_enveloped_data_t *env = NULL;
    asnber_cms_enveloped_builder_t *builder = NULL;
    asnber_buf_t encoded;
    memset(&encoded, 0, sizeof(encoded));

    ASNBER_TEST_CHECK(asnber_cms_content_info_open(ctx, der, der_size, &info) ==
                    ASNBER_OK);
    {
        const char *oid = NULL;
        size_t oid_size = 0;
        const uint8_t *content = NULL;
        size_t content_size = 0;
        ASNBER_TEST_CHECK(asnber_cms_content_info_content_type(info, &oid,
                                                           &oid_size) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(text_equals(oid, oid_size, kEnvelopedDataOid));
        ASNBER_TEST_CHECK(asnber_cms_content_info_content(info, &content,
                                                      &content_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_enveloped_data_open(ctx, content, content_size,
                                                     &env) == ASNBER_OK);
    }

    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_create(ctx, &builder) == ASNBER_OK);

    {
        int64_t version = -1;
        ASNBER_TEST_CHECK(asnber_cms_enveloped_data_version(env, &version) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_version(builder,
                                                               version) ==
                        ASNBER_OK);
    }

    {
        const uint8_t *originator_info = NULL;
        size_t originator_info_size = 0;
        ASNBER_TEST_CHECK(asnber_cms_enveloped_data_originator_info_tlv(
                            env, &originator_info, &originator_info_size) ==
                        ASNBER_OK);
        if (originator_info != NULL) {
            ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_originator_info(
                                builder, originator_info,
                                originator_info_size) == ASNBER_OK);
        }
    }

    {
        size_t count = 0;
        ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_count(env, &count) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(count > 0);
        for (size_t i = 0; i < count; ++i) {
            ASNBER_TEST_CHECK(add_sample_recipient(builder, env, i) == 0);
        }
    }

    {
        const char *oid = NULL;
        size_t oid_size = 0;
        const uint8_t *params = NULL;
        size_t params_size = 0;
        ASNBER_TEST_CHECK(asnber_cms_enveloped_data_content_type(env, &oid,
                                                             &oid_size) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_content_type(builder,
                                                                    oid) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(
            asnber_cms_enveloped_data_content_encryption_algorithm(
                env, &oid, &oid_size, &params, &params_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(
            asnber_cms_enveloped_builder_set_content_encryption_algorithm(
                builder, oid, params, params_size) == ASNBER_OK);
    }

    {
        const uint8_t *tlv = NULL;
        size_t tlv_size = 0;
        const uint8_t *bytes = NULL;
        size_t bytes_size = 0;
        ASNBER_TEST_CHECK(asnber_cms_enveloped_data_encrypted_content_tlv(
                            env, &tlv, &tlv_size) == ASNBER_OK);
        if (tlv != NULL) {
            ASNBER_TEST_CHECK(asnber_cms_enveloped_data_encrypted_content(
                                env, &bytes, &bytes_size) == ASNBER_OK);
            ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_encrypted_content(
                                builder, bytes, bytes_size) == ASNBER_OK);
        }
    }

    {
        const uint8_t *attrs = NULL;
        size_t attrs_size = 0;
        uint8_t *attrs_in = NULL;
        size_t attrs_in_size = 0;
        ASNBER_TEST_CHECK(asnber_cms_enveloped_data_unprotected_attrs_tlv(
                            env, &attrs, &attrs_size) == ASNBER_OK);
        if (attrs != NULL) {
            ASNBER_TEST_CHECK(rewrite_outer_tag(attrs, attrs_size, 0x31, &attrs_in,
                                              &attrs_in_size) == ASNBER_OK);
            ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_unprotected_attrs(
                                builder, attrs_in, attrs_in_size) == ASNBER_OK);
            free(attrs_in);
        }
    }

    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_encode(builder, &encoded) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(bytes_equal(encoded.data, encoded.size, der, der_size));

    asnber_buf_release(ctx, &encoded);
    asnber_cms_enveloped_builder_destroy(builder);
    asnber_cms_enveloped_data_close(env);
    asnber_cms_content_info_close(info);
    return 0;
}

static int roundtrip_all_samples(asnber_ctx_t *ctx)
{
    ASNBER_TEST_CHECK(rebuild_sample(ctx, kCmsEnvelopedKtri,
                                   kCmsEnvelopedKtriSize) == 0);
    ASNBER_TEST_CHECK(rebuild_sample(ctx, kCmsEnvelopedKtriMulti,
                                   kCmsEnvelopedKtriMultiSize) == 0);
    ASNBER_TEST_CHECK(rebuild_sample(ctx, kCmsEnvelopedKtriKeyid,
                                   kCmsEnvelopedKtriKeyidSize) == 0);
    ASNBER_TEST_CHECK(rebuild_sample(ctx, kCmsEnvelopedKari,
                                   kCmsEnvelopedKariSize) == 0);
    ASNBER_TEST_CHECK(rebuild_sample(ctx, kCmsEnvelopedKekri,
                                   kCmsEnvelopedKekriSize) == 0);
    ASNBER_TEST_CHECK(rebuild_sample(ctx, kCmsEnvelopedPwri,
                                   kCmsEnvelopedPwriSize) == 0);
    return 0;
}

/* ---------- 合成分支 ---------- */

/* originatorKey：outer [0] EXPLICIT 包 [1] IMPLICIT OriginatorPublicKey。 */
static const uint8_t kOriginatorKey[14] = {
    0xA0, 0x0C, 0xA1, 0x0A, 0x30, 0x05, 0x06, 0x03,
    0x2A, 0x03, 0x04, 0x03, 0x01, 0x00};

/* RecipientEncryptedKeys：一个 rKeyId + encryptedKey。 */
static const uint8_t kRecipientEncryptedKeys[14] = {
    0x30, 0x0C, 0x30, 0x0A, 0xA0, 0x05, 0x04,
    0x03, 0x01, 0x02, 0x03, 0x04, 0x01, 0xAA};

static const uint8_t kIv16[18] = {
    0x04, 0x10, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

static int open_encoded(asnber_ctx_t *ctx, const asnber_buf_t *encoded,
                        asnber_cms_content_info_t **out_info,
                        asnber_cms_enveloped_data_t **out_env)
{
    const uint8_t *content = NULL;
    size_t content_size = 0;
    ASNBER_TEST_CHECK(asnber_cms_content_info_open(ctx, encoded->data,
                                               encoded->size, out_info) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_content_info_content(*out_info, &content,
                                                  &content_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_open(ctx, content, content_size,
                                                 out_env) == ASNBER_OK);
    return 0;
}

static int build_kari(asnber_ctx_t *ctx)
{
    static const uint8_t kEncryptedContent[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    asnber_cms_enveloped_builder_t *builder = NULL;
    asnber_buf_t encoded;
    memset(&encoded, 0, sizeof(encoded));

    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_create(ctx, &builder) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_version(builder, 3) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_add_kari(
                        builder, 3, kOriginatorKey, sizeof(kOriginatorKey),
                        NULL, 0, kRecipientEncryptedKeys,
                        sizeof(kRecipientEncryptedKeys), kAes256WrapOid, NULL,
                        0) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_content_type(
                        builder, kDataOid) == ASNBER_OK);
    ASNBER_TEST_CHECK(
        asnber_cms_enveloped_builder_set_content_encryption_algorithm(
            builder, kAes256CbcOid, kIv16, sizeof(kIv16)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_encrypted_content(
                        builder, kEncryptedContent,
                        sizeof(kEncryptedContent)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_encode(builder, &encoded) ==
                    ASNBER_OK);

    {
        asnber_cms_content_info_t *info = NULL;
        asnber_cms_enveloped_data_t *env = NULL;
        int choice = -1;
        int originator_choice = -1;
        int64_t version = -1;
        const uint8_t *originator = NULL;
        size_t originator_size = 0;
        size_t count = 0;
        const char *oid = NULL;
        size_t oid_size = 0;
        const uint8_t *params = NULL;
        size_t params_size = 0;

        ASNBER_TEST_CHECK(open_encoded(ctx, &encoded, &info, &env) == 0);
        ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_count(env, &count) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(count == 1);
        ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_choice(
                            env, 0, &choice) == ASNBER_OK);
        ASNBER_TEST_CHECK(choice == ASNBER_CMS_RECIPIENT_KARI);
        ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_version(
                            env, 0, &version) == ASNBER_OK);
        ASNBER_TEST_CHECK(version == 3);
        ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_originator_choice(
                            env, 0, &originator_choice) == ASNBER_OK);
        ASNBER_TEST_CHECK(originator_choice == ASNBER_CMS_ORIGINATOR_KEY);
        ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_originator_tlv(
                            env, 0, &originator, &originator_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(originator, originator_size, kOriginatorKey,
                                    sizeof(kOriginatorKey)));
        ASNBER_TEST_CHECK(
            asnber_cms_enveloped_data_recipient_kari_encrypted_key_count(
                env, 0, &count) == ASNBER_OK);
        ASNBER_TEST_CHECK(count == 1);
        ASNBER_TEST_CHECK(
            asnber_cms_enveloped_data_recipient_key_encryption_algorithm(
                env, 0, &oid, &oid_size, &params, &params_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(text_equals(oid, oid_size, kAes256WrapOid));

        asnber_cms_enveloped_data_close(env);
        asnber_cms_content_info_close(info);
    }

    asnber_buf_release(ctx, &encoded);
    asnber_cms_enveloped_builder_destroy(builder);
    return 0;
}

static int build_ori(asnber_ctx_t *ctx)
{
    static const uint8_t kOriValue[4] = {0x04, 0x02, 0xAA, 0xBB};
    static const uint8_t kEncryptedContent[3] = {0x01, 0x02, 0x03};
    asnber_cms_enveloped_builder_t *builder = NULL;
    asnber_buf_t encoded;
    memset(&encoded, 0, sizeof(encoded));

    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_create(ctx, &builder) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_version(builder, 0) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_add_ori(
                        builder, "1.2.3.4", kOriValue,
                        sizeof(kOriValue)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_content_type(
                        builder, kDataOid) == ASNBER_OK);
    ASNBER_TEST_CHECK(
        asnber_cms_enveloped_builder_set_content_encryption_algorithm(
            builder, kAes256CbcOid, kIv16, sizeof(kIv16)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_encrypted_content(
                        builder, kEncryptedContent,
                        sizeof(kEncryptedContent)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_encode(builder, &encoded) ==
                    ASNBER_OK);

    {
        asnber_cms_content_info_t *info = NULL;
        asnber_cms_enveloped_data_t *env = NULL;
        int choice = -1;
        const char *oid = NULL;
        size_t oid_size = 0;
        const uint8_t *value = NULL;
        size_t value_size = 0;

        ASNBER_TEST_CHECK(open_encoded(ctx, &encoded, &info, &env) == 0);
        ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_choice(
                            env, 0, &choice) == ASNBER_OK);
        ASNBER_TEST_CHECK(choice == ASNBER_CMS_RECIPIENT_ORI);
        ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_ori_type(
                            env, 0, &oid, &oid_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(text_equals(oid, oid_size, "1.2.3.4"));
        ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_ori_value_tlv(
                            env, 0, &value, &value_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(value, value_size, kOriValue,
                                    sizeof(kOriValue)));

        asnber_cms_enveloped_data_close(env);
        asnber_cms_content_info_close(info);
    }

    asnber_buf_release(ctx, &encoded);
    asnber_cms_enveloped_builder_destroy(builder);
    return 0;
}

/* originatorInfo + unprotectedAttrs 原样承载，unprotectedAttrs 改写成 0xA1。 */
static int build_optional_fields(asnber_ctx_t *ctx)
{
    static const uint8_t kOriginatorInfo[2] = {0xA0, 0x00};
    /* SET OF Attribute：Attribute 的 attrValues 是必填 SET，编码为 31 02 05 00。 */
    static const uint8_t kAttrs[13] = {
        0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x2A, 0x03,
        0x04, 0x31, 0x02, 0x05, 0x00};
    static const uint8_t kSki[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    static const uint8_t kEncryptedKey[2] = {0x11, 0x22};
    static const uint8_t kEncryptedContent[2] = {0x33, 0x44};
    asnber_cms_enveloped_builder_t *builder = NULL;
    asnber_buf_t encoded;
    memset(&encoded, 0, sizeof(encoded));

    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_create(ctx, &builder) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_version(builder, 2) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_originator_info(
                        builder, kOriginatorInfo,
                        sizeof(kOriginatorInfo)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_add_ktri(
                        builder, 2, ASNBER_CMS_RID_SUBJECT_KEY_IDENTIFIER, kSki,
                        sizeof(kSki), NULL, 0, kAes256WrapOid, NULL, 0,
                        kEncryptedKey, sizeof(kEncryptedKey)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_content_type(
                        builder, kDataOid) == ASNBER_OK);
    ASNBER_TEST_CHECK(
        asnber_cms_enveloped_builder_set_content_encryption_algorithm(
            builder, kAes256CbcOid, kIv16, sizeof(kIv16)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_encrypted_content(
                        builder, kEncryptedContent,
                        sizeof(kEncryptedContent)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_unprotected_attrs(
                        builder, kAttrs, sizeof(kAttrs)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_encode(builder, &encoded) ==
                    ASNBER_OK);

    {
        asnber_cms_content_info_t *info = NULL;
        asnber_cms_enveloped_data_t *env = NULL;
        const uint8_t *originator_info = NULL;
        size_t originator_info_size = 0;
        const uint8_t *attrs = NULL;
        size_t attrs_size = 0;

        ASNBER_TEST_CHECK(open_encoded(ctx, &encoded, &info, &env) == 0);
        ASNBER_TEST_CHECK(asnber_cms_enveloped_data_originator_info_tlv(
                            env, &originator_info, &originator_info_size) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(originator_info, originator_info_size,
                                    kOriginatorInfo,
                                    sizeof(kOriginatorInfo)));
        ASNBER_TEST_CHECK(asnber_cms_enveloped_data_unprotected_attrs_tlv(
                            env, &attrs, &attrs_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(attrs != NULL && attrs_size == sizeof(kAttrs));
        ASNBER_TEST_CHECK(attrs[0] == 0xA1);
        ASNBER_TEST_CHECK(memcmp(attrs + 1, kAttrs + 1, attrs_size - 1) == 0);

        asnber_cms_enveloped_data_close(env);
        asnber_cms_content_info_close(info);
    }

    asnber_buf_release(ctx, &encoded);
    asnber_cms_enveloped_builder_destroy(builder);
    return 0;
}

/* ---------- 形状正例 ---------- */

/*
 * 校验器不是“只拒绝”：下列输入都应按合法形状接受。
 * originatorInfo 的 certs/crls 内部语义不由 builder 展开，这里只验证
 * 外层形状与可选成员顺序。
 */
static int build_shape_positive_cases(asnber_ctx_t *ctx)
{
    static const uint8_t kOriginatorInfoBoth[10] = {
        0xA0, 0x08, 0xA0, 0x02, 0x30, 0x00, 0xA1, 0x02, 0x30, 0x00};
    static const uint8_t kKekIdFull[29] = {
        0x30, 0x1B, 0x04, 0x03, 0x01, 0x02, 0x03, 0x18, 0x0F, 0x32,
        0x30, 0x32, 0x34, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x5A, 0x30, 0x03, 0x06, 0x01, 0x2A};
    static const uint8_t kEmptyRekeys[2] = {0x30, 0x00};
    static const uint8_t kSkiOriginator[4] = {0xA0, 0x02, 0x80, 0x00};
    static const uint8_t kUkm[5] = {0xA1, 0x03, 0x04, 0x01, 0xAA};
    static const uint8_t kSki[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    static const uint8_t kKekKeyId[3] = {0x01, 0x02, 0x03};
    static const uint8_t kEncryptedKey[2] = {0x11, 0x22};
    static const uint8_t kEncryptedContent[2] = {0x33, 0x44};
    asnber_cms_enveloped_builder_t *builder = NULL;
    asnber_buf_t encoded;
    memset(&encoded, 0, sizeof(encoded));

    /* originatorInfo 同时带 certs 与 crls。 */
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_create(ctx, &builder) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_version(builder, 2) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_originator_info(
                        builder, kOriginatorInfoBoth,
                        sizeof(kOriginatorInfoBoth)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_add_ktri(
                        builder, 2, ASNBER_CMS_RID_SUBJECT_KEY_IDENTIFIER, kSki,
                        sizeof(kSki), NULL, 0, kAes256WrapOid, NULL, 0,
                        kEncryptedKey, sizeof(kEncryptedKey)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_content_type(
                        builder, kDataOid) == ASNBER_OK);
    ASNBER_TEST_CHECK(
        asnber_cms_enveloped_builder_set_content_encryption_algorithm(
            builder, kAes256CbcOid, kIv16, sizeof(kIv16)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_encrypted_content(
                        builder, kEncryptedContent,
                        sizeof(kEncryptedContent)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_encode(builder, &encoded) ==
                    ASNBER_OK);
    asnber_buf_release(ctx, &encoded);
    asnber_cms_enveloped_builder_destroy(builder);

    /* KEKIdentifier 同时带 date 和 other；编码后读回 keyIdentifier。 */
    memset(&encoded, 0, sizeof(encoded));
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_create(ctx, &builder) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_version(builder, 4) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_add_kekri(
                        builder, 4, kKekIdFull, sizeof(kKekIdFull),
                        kAes256WrapOid, NULL, 0, kEncryptedKey,
                        sizeof(kEncryptedKey)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_content_type(
                        builder, kDataOid) == ASNBER_OK);
    ASNBER_TEST_CHECK(
        asnber_cms_enveloped_builder_set_content_encryption_algorithm(
            builder, kAes256CbcOid, kIv16, sizeof(kIv16)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_encode(builder, &encoded) ==
                    ASNBER_OK);

    {
        asnber_cms_content_info_t *info = NULL;
        asnber_cms_enveloped_data_t *env = NULL;
        int choice = -1;
        const uint8_t *key_id = NULL;
        size_t key_id_size = 0;

        ASNBER_TEST_CHECK(open_encoded(ctx, &encoded, &info, &env) == 0);
        ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_choice(
                            env, 0, &choice) == ASNBER_OK);
        ASNBER_TEST_CHECK(choice == ASNBER_CMS_RECIPIENT_KEKRI);
        ASNBER_TEST_CHECK(
            asnber_cms_enveloped_data_recipient_kekri_key_identifier(
                env, 0, &key_id, &key_id_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(key_id, key_id_size, kKekKeyId,
                                    sizeof(kKekKeyId)));
        asnber_cms_enveloped_data_close(env);
        asnber_cms_content_info_close(info);
    }
    asnber_buf_release(ctx, &encoded);
    asnber_cms_enveloped_builder_destroy(builder);

    /* kari：originator 的 [0] primitive + ukm + 空 RecipientEncryptedKeys。 */
    memset(&encoded, 0, sizeof(encoded));
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_create(ctx, &builder) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_version(builder, 3) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_add_kari(
                        builder, 3, kSkiOriginator, sizeof(kSkiOriginator),
                        kUkm, sizeof(kUkm), kEmptyRekeys,
                        sizeof(kEmptyRekeys), kAes256WrapOid, NULL,
                        0) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_content_type(
                        builder, kDataOid) == ASNBER_OK);
    ASNBER_TEST_CHECK(
        asnber_cms_enveloped_builder_set_content_encryption_algorithm(
            builder, kAes256CbcOid, kIv16, sizeof(kIv16)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_encode(builder, &encoded) ==
                    ASNBER_OK);

    {
        asnber_cms_content_info_t *info = NULL;
        asnber_cms_enveloped_data_t *env = NULL;
        int choice = -1;
        int originator_choice = -1;
        size_t rekey_count = 99;

        ASNBER_TEST_CHECK(open_encoded(ctx, &encoded, &info, &env) == 0);
        ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_choice(
                            env, 0, &choice) == ASNBER_OK);
        ASNBER_TEST_CHECK(choice == ASNBER_CMS_RECIPIENT_KARI);
        ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_originator_choice(
                            env, 0, &originator_choice) == ASNBER_OK);
        ASNBER_TEST_CHECK(originator_choice ==
                        ASNBER_CMS_ORIGINATOR_SUBJECT_KEY_IDENTIFIER);
        ASNBER_TEST_CHECK(
            asnber_cms_enveloped_data_recipient_kari_encrypted_key_count(
                env, 0, &rekey_count) == ASNBER_OK);
        ASNBER_TEST_CHECK(rekey_count == 0);
        asnber_cms_enveloped_data_close(env);
        asnber_cms_content_info_close(info);
    }
    asnber_buf_release(ctx, &encoded);
    asnber_cms_enveloped_builder_destroy(builder);
    return 0;
}

/* ---------- 空内容 / detached ---------- */

/* 最小 builder：version 2 + 一条 ktri(SKI) + contentType + 内容加密算法。 */
static int prepare_minimal_builder(asnber_ctx_t *ctx,
                                   asnber_cms_enveloped_builder_t **out_builder)
{
    static const uint8_t kSki[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    static const uint8_t kEncryptedKey[2] = {0x11, 0x22};
    asnber_cms_enveloped_builder_t *builder = NULL;

    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_create(ctx, &builder) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_version(builder, 2) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_add_ktri(
                        builder, 2, ASNBER_CMS_RID_SUBJECT_KEY_IDENTIFIER, kSki,
                        sizeof(kSki), NULL, 0, kAes256WrapOid, NULL, 0,
                        kEncryptedKey, sizeof(kEncryptedKey)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_content_type(
                        builder, kDataOid) == ASNBER_OK);
    ASNBER_TEST_CHECK(
        asnber_cms_enveloped_builder_set_content_encryption_algorithm(
            builder, kAes256CbcOid, kIv16, sizeof(kIv16)) == ASNBER_OK);
    *out_builder = builder;
    return 0;
}

/*
 * 空内容：显式设置 NULL,0 后 encryptedContent 字段存在，DER 为 `80 00`
 * （`[0] IMPLICIT OCTET STRING` 的 primitive 空编码；`04 00` 属于显式/包装
 * 层，本 builder 不产生），与“字段缺失”明确区分。
 */
static int build_empty_content(asnber_ctx_t *ctx)
{
    asnber_cms_enveloped_builder_t *builder = NULL;
    asnber_buf_t encoded;
    memset(&encoded, 0, sizeof(encoded));

    ASNBER_TEST_CHECK(prepare_minimal_builder(ctx, &builder) == 0);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_encrypted_content(
                        builder, NULL, 0) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_encode(builder, &encoded) ==
                    ASNBER_OK);

    {
        asnber_cms_content_info_t *info = NULL;
        asnber_cms_enveloped_data_t *env = NULL;
        const uint8_t *tlv = NULL;
        size_t tlv_size = 0;
        const uint8_t *content = NULL;
        size_t content_size = 7;

        ASNBER_TEST_CHECK(open_encoded(ctx, &encoded, &info, &env) == 0);
        ASNBER_TEST_CHECK(asnber_cms_enveloped_data_encrypted_content_tlv(
                            env, &tlv, &tlv_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(tlv != NULL && tlv_size == 2);
        ASNBER_TEST_CHECK(tlv[0] == 0x80 && tlv[1] == 0x00);
        ASNBER_TEST_CHECK(asnber_cms_enveloped_data_encrypted_content(
                            env, &content, &content_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(content_size == 0);

        asnber_cms_enveloped_data_close(env);
        asnber_cms_content_info_close(info);
    }

    asnber_buf_release(ctx, &encoded);
    asnber_cms_enveloped_builder_destroy(builder);
    return 0;
}

/*
 * detached：完全不调用 set_encrypted_content，编码后 encryptedContent 字段
 * 不存在（读回 NULL/0），而不是零长度字段。
 */
static int build_detached_content(asnber_ctx_t *ctx)
{
    asnber_cms_enveloped_builder_t *builder = NULL;
    asnber_buf_t encoded;
    memset(&encoded, 0, sizeof(encoded));

    ASNBER_TEST_CHECK(prepare_minimal_builder(ctx, &builder) == 0);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_encode(builder, &encoded) ==
                    ASNBER_OK);

    {
        asnber_cms_content_info_t *info = NULL;
        asnber_cms_enveloped_data_t *env = NULL;
        const uint8_t *tlv = NULL;
        size_t tlv_size = 1;
        const uint8_t *content = NULL;
        size_t content_size = 1;

        ASNBER_TEST_CHECK(open_encoded(ctx, &encoded, &info, &env) == 0);
        ASNBER_TEST_CHECK(asnber_cms_enveloped_data_encrypted_content_tlv(
                            env, &tlv, &tlv_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(tlv == NULL && tlv_size == 0);
        ASNBER_TEST_CHECK(asnber_cms_enveloped_data_encrypted_content(
                            env, &content, &content_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(content == NULL && content_size == 0);

        asnber_cms_enveloped_data_close(env);
        asnber_cms_content_info_close(info);
    }

    asnber_buf_release(ctx, &encoded);
    asnber_cms_enveloped_builder_destroy(builder);
    return 0;
}

/* ---------- 负例 ---------- */

static int builder_negative_cases(asnber_ctx_t *ctx)
{
    static const uint8_t kIssuer[2] = {0x30, 0x00};
    static const uint8_t kSerial[3] = {0x02, 0x01, 0x01};
    static const uint8_t kOctets[2] = {0x04, 0x00};
    static const uint8_t kTruncated[3] = {0x30, 0x02, 0x02};
    static const uint8_t kTrailing[4] = {0x05, 0x00, 0xAA, 0xBB};
    static const uint8_t kEmptySet[2] = {0x31, 0x00};
    static const uint8_t kKey[2] = {0x01, 0x02};
    /* [0] 包装内 3 个 SEQUENCE 子节点，超过 OriginatorInfo 的 2 个可选成员。 */
    static const uint8_t kOriginatorInfoTooMany[8] = {
        0xA0, 0x06, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00};
    /* 形状错误：originatorInfo / kari originator 的 [0] 里放 INTEGER。 */
    static const uint8_t kContext0Integer[5] = {0xA0, 0x03, 0x02, 0x01, 0x00};
    /* 形状错误：ukm 的 [1] 里放 INTEGER，而不是 OCTET STRING。 */
    static const uint8_t kUkmInteger[5] = {0xA1, 0x03, 0x02, 0x01, 0x00};
    /* 形状错误：KEKIdentifier 缺少必填 keyIdentifier / 首子节点类型错误。 */
    static const uint8_t kEmptyKekIdentifier[2] = {0x30, 0x00};
    static const uint8_t kBadKekIdentifier[5] = {0x30, 0x03, 0x02, 0x01, 0x00};
    /* 形状错误：keyDerivationAlgorithm 为空或只有 INTEGER，缺少 OID。 */
    static const uint8_t kEmptyKdf[2] = {0xA0, 0x00};
    static const uint8_t kKdfIntegerOnly[5] = {0xA0, 0x03, 0x02, 0x01, 0x00};
    /* 形状错误：RecipientEncryptedKeys 元素里的 rid 是 OCTET STRING。 */
    static const uint8_t kBadRecipientEncryptedKeys[8] = {
        0x30, 0x06, 0x30, 0x04, 0x04, 0x02, 0xAA, 0xBB};
    /* RFC 允许空的 RecipientEncryptedKeys；这里放非 SEQUENCE 元素。 */
    static const uint8_t kBadRecipientEncryptedKeysElement[4] = {
        0x30, 0x02, 0x04, 0x00};

    asnber_cms_enveloped_builder_t *builder = NULL;
    asnber_buf_t encoded;
    memset(&encoded, 0, sizeof(encoded));

    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_create(ctx, &builder) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_encode(builder, &encoded) ==
                    ASNBER_E_INVALID_STATE);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_version(builder, 0) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_version(builder, 1) ==
                    ASNBER_E_INVALID_STATE);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_encode(builder, &encoded) ==
                    ASNBER_E_INVALID_STATE);

    /* 无 recipient。 */
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_content_type(
                        builder, kDataOid) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_content_type(
                        builder, kDataOid) == ASNBER_E_INVALID_STATE);
    ASNBER_TEST_CHECK(
        asnber_cms_enveloped_builder_set_content_encryption_algorithm(
            builder, kAes256CbcOid, kIv16, sizeof(kIv16)) == ASNBER_OK);
    ASNBER_TEST_CHECK(
        asnber_cms_enveloped_builder_set_content_encryption_algorithm(
            builder, kAes256CbcOid, NULL, 0) == ASNBER_E_INVALID_STATE);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_encode(builder, &encoded) ==
                    ASNBER_E_INVALID_STATE);

    /* 非法 OID / TLV。 */
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_content_type(
                        builder, "1.2.3.4.") == ASNBER_E_INVALID_STATE);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_add_ktri(
                        builder, 0, 7, kIssuer, sizeof(kIssuer), kSerial,
                        sizeof(kSerial), kAes256WrapOid, NULL, 0, kKey,
                        sizeof(kKey)) == ASNBER_E_INVALID_VALUE);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_add_ktri(
                        builder, 0, ASNBER_CMS_RID_ISSUER_AND_SERIAL, kOctets,
                        sizeof(kOctets), kSerial, sizeof(kSerial),
                        kAes256WrapOid, NULL, 0, kKey,
                        sizeof(kKey)) == ASNBER_E_INVALID_VALUE);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_add_ktri(
                        builder, 0, ASNBER_CMS_RID_ISSUER_AND_SERIAL, kTruncated,
                        sizeof(kTruncated), kSerial, sizeof(kSerial),
                        kAes256WrapOid, NULL, 0, kKey,
                        sizeof(kKey)) == ASNBER_E_TRUNCATED);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_add_ktri(
                        builder, 0, ASNBER_CMS_RID_ISSUER_AND_SERIAL, kIssuer,
                        sizeof(kIssuer), kSerial, sizeof(kSerial),
                        kAes256WrapOid, kTrailing,
                        sizeof(kTrailing), kKey,
                        sizeof(kKey)) == ASNBER_E_TRAILING_DATA);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_add_ktri(
                        builder, 0, ASNBER_CMS_RID_SUBJECT_KEY_IDENTIFIER, kOctets,
                        sizeof(kOctets), kSerial, sizeof(kSerial),
                        kAes256WrapOid, NULL, 0, kKey,
                        sizeof(kKey)) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_add_ktri(
                        builder, 0, ASNBER_CMS_RID_SUBJECT_KEY_IDENTIFIER, kOctets,
                        sizeof(kOctets), NULL, 0, "1.2.3.4.", NULL, 0, kKey,
                        sizeof(kKey)) == ASNBER_E_INVALID_VALUE);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_add_ktri(
                        builder, 0, ASNBER_CMS_RID_SUBJECT_KEY_IDENTIFIER, kOctets,
                        sizeof(kOctets), NULL, 0, kAes256WrapOid, kTruncated,
                        sizeof(kTruncated), kKey,
                        sizeof(kKey)) == ASNBER_E_TRUNCATED);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_add_ktri(
                        builder, 0, ASNBER_CMS_RID_SUBJECT_KEY_IDENTIFIER, kOctets,
                        sizeof(kOctets), NULL, 0, kAes256WrapOid, NULL, 0, NULL,
                        1) == ASNBER_E_INVALID_ARG);

    /* kari / kekri / pwri / ori 结构负例。 */
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_add_kari(
                        builder, 3, kOctets, sizeof(kOctets), NULL, 0,
                        kRecipientEncryptedKeys,
                        sizeof(kRecipientEncryptedKeys), kAes256WrapOid, NULL,
                        0) == ASNBER_E_INVALID_VALUE);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_add_kari(
                        builder, 3, kOriginatorKey, sizeof(kOriginatorKey),
                        kOctets, sizeof(kOctets), kRecipientEncryptedKeys,
                        sizeof(kRecipientEncryptedKeys), kAes256WrapOid, NULL,
                        0) == ASNBER_E_INVALID_VALUE);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_add_kari(
                        builder, 3, kOriginatorKey, sizeof(kOriginatorKey),
                        NULL, 0, kBadRecipientEncryptedKeysElement,
                        sizeof(kBadRecipientEncryptedKeysElement),
                        kAes256WrapOid, NULL, 0) == ASNBER_E_INVALID_VALUE);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_add_kari(
                        builder, 3, kContext0Integer, sizeof(kContext0Integer),
                        NULL, 0, kRecipientEncryptedKeys,
                        sizeof(kRecipientEncryptedKeys), kAes256WrapOid, NULL,
                        0) == ASNBER_E_INVALID_VALUE);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_add_kari(
                        builder, 3, kOriginatorKey, sizeof(kOriginatorKey),
                        kUkmInteger, sizeof(kUkmInteger),
                        kRecipientEncryptedKeys,
                        sizeof(kRecipientEncryptedKeys), kAes256WrapOid, NULL,
                        0) == ASNBER_E_INVALID_VALUE);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_add_kari(
                        builder, 3, kOriginatorKey, sizeof(kOriginatorKey),
                        NULL, 0, kBadRecipientEncryptedKeys,
                        sizeof(kBadRecipientEncryptedKeys), kAes256WrapOid,
                        NULL, 0) == ASNBER_E_INVALID_VALUE);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_add_kekri(
                        builder, 4, kOctets, sizeof(kOctets), kAes256WrapOid,
                        NULL, 0, kKey, sizeof(kKey)) == ASNBER_E_INVALID_VALUE);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_add_kekri(
                        builder, 4, kEmptyKekIdentifier,
                        sizeof(kEmptyKekIdentifier), kAes256WrapOid, NULL, 0,
                        kKey, sizeof(kKey)) == ASNBER_E_INVALID_VALUE);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_add_kekri(
                        builder, 4, kBadKekIdentifier,
                        sizeof(kBadKekIdentifier), kAes256WrapOid, NULL, 0,
                        kKey, sizeof(kKey)) == ASNBER_E_INVALID_VALUE);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_add_pwri(
                        builder, 0, kIssuer, sizeof(kIssuer), kAes256WrapOid,
                        NULL, 0, kKey, sizeof(kKey)) == ASNBER_E_INVALID_VALUE);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_add_pwri(
                        builder, 0, kEmptyKdf, sizeof(kEmptyKdf),
                        kAes256WrapOid, NULL, 0, kKey,
                        sizeof(kKey)) == ASNBER_E_INVALID_VALUE);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_add_pwri(
                        builder, 0, kKdfIntegerOnly, sizeof(kKdfIntegerOnly),
                        kAes256WrapOid, NULL, 0, kKey,
                        sizeof(kKey)) == ASNBER_E_INVALID_VALUE);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_add_ori(
                        builder, "1.2.3.4.", kOctets,
                        sizeof(kOctets)) == ASNBER_E_INVALID_VALUE);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_add_ori(
                        builder, "1.2.3.4", kTruncated,
                        sizeof(kTruncated)) == ASNBER_E_TRUNCATED);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_add_ori(
                        builder, "1.2.3.4", NULL, 0) == ASNBER_E_INVALID_ARG);

    /* originatorInfo / unprotectedAttrs / encryptedContent 校验。 */
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_originator_info(
                        builder, kIssuer, sizeof(kIssuer)) ==
                    ASNBER_E_INVALID_VALUE);
    /* OriginatorInfo 至多 2 个子 TLV（certs、crls 均可选）；3 个拒绝。 */
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_originator_info(
                        builder, kOriginatorInfoTooMany,
                        sizeof(kOriginatorInfoTooMany)) == ASNBER_E_INVALID_VALUE);
    /* 子节点必须是 certs [0] / crls [1]，不能是 INTEGER。 */
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_originator_info(
                        builder, kContext0Integer,
                        sizeof(kContext0Integer)) == ASNBER_E_INVALID_VALUE);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_unprotected_attrs(
                        builder, kEmptySet, sizeof(kEmptySet)) ==
                    ASNBER_E_INVALID_VALUE);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_unprotected_attrs(
                        builder, kOctets, sizeof(kOctets)) ==
                    ASNBER_E_INVALID_VALUE);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_encrypted_content(
                        builder, NULL, 1) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_encrypted_content(
                        builder, NULL, 0) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_encrypted_content(
                        builder, kKey, sizeof(kKey)) == ASNBER_E_INVALID_STATE);

    /* 前面所有失败调用都未落入状态；补齐 recipient 后可以正常编码。 */
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_add_ktri(
                        builder, 0, ASNBER_CMS_RID_ISSUER_AND_SERIAL, kIssuer,
                        sizeof(kIssuer), kSerial, sizeof(kSerial),
                        kAes256WrapOid, NULL, 0, kKey,
                        sizeof(kKey)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_encode(builder, &encoded) ==
                    ASNBER_OK);
    asnber_buf_release(ctx, &encoded);

    asnber_cms_enveloped_builder_destroy(builder);
    asnber_cms_enveloped_builder_destroy(NULL);

    /* 缺少 contentEncryptionAlgorithm。 */
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_create(ctx, &builder) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_version(builder, 0) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_add_ktri(
                        builder, 0, ASNBER_CMS_RID_ISSUER_AND_SERIAL, kIssuer,
                        sizeof(kIssuer), kSerial, sizeof(kSerial),
                        kAes256WrapOid, NULL, 0, kKey,
                        sizeof(kKey)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_content_type(
                        builder, kDataOid) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_encode(builder, &encoded) ==
                    ASNBER_E_INVALID_STATE);
    asnber_cms_enveloped_builder_destroy(builder);

    /* 缺少 contentType。 */
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_create(ctx, &builder) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_set_version(builder, 0) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_add_ktri(
                        builder, 0, ASNBER_CMS_RID_ISSUER_AND_SERIAL, kIssuer,
                        sizeof(kIssuer), kSerial, sizeof(kSerial),
                        kAes256WrapOid, NULL, 0, kKey,
                        sizeof(kKey)) == ASNBER_OK);
    ASNBER_TEST_CHECK(
        asnber_cms_enveloped_builder_set_content_encryption_algorithm(
            builder, kAes256CbcOid, kIv16, sizeof(kIv16)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_builder_encode(builder, &encoded) ==
                    ASNBER_E_INVALID_STATE);
    asnber_cms_enveloped_builder_destroy(builder);
    return 0;
}

int main(void)
{
    asnber_ctx_t *ctx = make_ctx();
    ASNBER_TEST_CHECK(ctx != NULL);

    ASNBER_TEST_CHECK(roundtrip_all_samples(ctx) == 0);
    ASNBER_TEST_CHECK(build_kari(ctx) == 0);
    ASNBER_TEST_CHECK(build_ori(ctx) == 0);
    ASNBER_TEST_CHECK(build_optional_fields(ctx) == 0);
    ASNBER_TEST_CHECK(build_shape_positive_cases(ctx) == 0);
    ASNBER_TEST_CHECK(build_empty_content(ctx) == 0);
    ASNBER_TEST_CHECK(build_detached_content(ctx) == 0);
    ASNBER_TEST_CHECK(builder_negative_cases(ctx) == 0);

    asnber_ctx_destroy(ctx);
    return 0;
}
