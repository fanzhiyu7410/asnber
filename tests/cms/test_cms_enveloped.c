/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * asnber-cms 只读结构访问：EnvelopedData。
 * 覆盖 ktri（单/多收件人）、kari、kekri、pwri 的真实 openssl 样本，构造级
 * ori 样本，以及空 recipientInfos、截断、误用访问器等负例。
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
static const char kRsaEncryptionOid[] = "1.2.840.113549.1.1.1";
static const char kAes256CbcOid[] = "2.16.840.1.101.3.4.1.42";
static const char kAes256WrapOid[] = "2.16.840.1.101.3.4.1.45";
static const char kDhSsha1Oid[] = "1.3.133.16.840.63.0.2";
static const char kPwriKekOid[] = "1.2.840.113549.1.9.16.3.9";

/*
 * Repo 内 ktri 样本的证书序列号。样本由已提交的 cert_rsa_selfsigned.pem
 * 生成，序列号稳定（密文随机不影响 rid）。
 */
static const char kKtriSerialDecimal[] =
    "651241625021466612160683104114604757680343021109";

/*
 * 构造级 ori 样本：仅验证结构，不是 openssl 产物。
 *
 * EnvelopedData ::= SEQUENCE {
 *   version 0,
 *   recipientInfos SET { [4] { oriType 1.2.3.4.5, oriValue INTEGER 1 } },
 *   encryptedContentInfo { data, aes-256-cbc } }
 */
static const uint8_t kOriEnveloped[] = {
    0x30, 0x2A,
    0x02, 0x01, 0x00,
    0x31, 0x0B,
    0xA4, 0x09,
    0x06, 0x04, 0x2A, 0x03, 0x04, 0x05,
    0x02, 0x01, 0x01,
    0x30, 0x18,
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
    0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
    0x01, 0x2A,
};

/* 空 recipientInfos：`SET SIZE (1..MAX)` 应由 schema 约束拒绝。 */
static const uint8_t kEmptyRecipients[] = {
    0x30, 0x1F,
    0x02, 0x01, 0x00,
    0x31, 0x00,
    0x30, 0x18,
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
    0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
    0x01, 0x2A,
};

/*
 * BER 构造形式 encryptedContent：`[0]` 为构造形式（0xA0），内含两个
 * OCTET STRING 段 "abc" + "def"。用于验证模块按核心合并规则给出
 * "abcdef" 与完整构造 TLV，而不是只支持基本形式。
 *
 * EnvelopedData { version 0, recipientInfos SET{ktri}, EncryptedContentInfo }
 * ktri: version 0, rid issuerAndSerialNumber{空 Name, serial 1},
 *       rsaEncryption + NULL, encryptedKey 01 02
 */
static const uint8_t kBerSegmentedContent[] = {
    0x30, 0x4C,
    0x02, 0x01, 0x00,
    0x31, 0x1F,
    0x30, 0x1D,
    0x02, 0x01, 0x00,
    0x30, 0x05, 0x30, 0x00, 0x02, 0x01, 0x01,
    0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01,
    0x01, 0x01, 0x05, 0x00,
    0x04, 0x02, 0x01, 0x02,
    0x30, 0x26,
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
    0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
    0x01, 0x2A, 0x05, 0x00,
    0xA0, 0x0A, 0x04, 0x03, 0x61, 0x62, 0x63, 0x04, 0x03, 0x64, 0x65, 0x66,
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

/* 经 ContentInfo 剥壳后打开裸 EnvelopedData。 */
static int open_env(asnber_ctx_t *ctx, const uint8_t *der, size_t size,
                    asnber_cms_enveloped_data_t **out)
{
    asnber_cms_content_info_t *info = NULL;
    const uint8_t *inner = NULL;
    size_t inner_size = 0;
    asnber_err_t status = ASNBER_OK;

    *out = NULL;
    ASNBER_TEST_CHECK(asnber_cms_content_info_open(ctx, der, size, &info) ==
                    ASNBER_OK);
    status = asnber_cms_content_info_content(info, &inner, &inner_size);
    if (status == ASNBER_OK) {
        status = asnber_cms_enveloped_data_open(ctx, inner, inner_size, out);
    }
    asnber_cms_content_info_close(info);
    ASNBER_TEST_CHECK(status == ASNBER_OK);
    return 0;
}

static int test_ktri(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_cms_content_info_t *info = NULL;
    asnber_cms_enveloped_data_t *env = NULL;
    const char *oid = NULL;
    size_t oid_size = 0;
    const uint8_t *data = NULL;
    size_t size = 0;
    int64_t version = -1;
    size_t count = 0;
    int choice = -1;
    char decimal[64];
    size_t decimal_size = 0;

    ASNBER_TEST_CHECK(ctx != NULL);

    /* ContentInfo 层的 contentType 与内层 TLV。 */
    ASNBER_TEST_CHECK(asnber_cms_content_info_open(ctx, kCmsEnvelopedKtri,
                                               kCmsEnvelopedKtriSize,
                                               &info) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_content_info_content_type(info, &oid,
                                                       &oid_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(text_equals(oid, oid_size, kEnvelopedDataOid));
    ASNBER_TEST_CHECK(asnber_cms_content_info_content(info, &data, &size) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(data != NULL && size > 0);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_open(ctx, data, size, &env) ==
                    ASNBER_OK);
    asnber_cms_content_info_close(info);
    info = NULL;

    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_version(env, &version) == ASNBER_OK);
    ASNBER_TEST_CHECK(version == 0);

    /* 可选字段缺省。 */
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_originator_info_tlv(
                        env, &data, &size) == ASNBER_OK);
    ASNBER_TEST_CHECK(data == NULL && size == 0);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_unprotected_attrs_tlv(
                        env, &data, &size) == ASNBER_OK);
    ASNBER_TEST_CHECK(data == NULL && size == 0);

    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_count(env, &count) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(count == 1);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_choice(env, 0,
                                                             &choice) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(choice == ASNBER_CMS_RECIPIENT_KTRI);

    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_tlv(env, 0, &data,
                                                          &size) == ASNBER_OK);
    ASNBER_TEST_CHECK(data != NULL && size > 0 && data[0] == 0x30);

    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_version(
                        env, 0, &version) == ASNBER_OK);
    ASNBER_TEST_CHECK(version == 0);

    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_key_encryption_algorithm(
                        env, 0, &oid, &oid_size, &data, &size) == ASNBER_OK);
    ASNBER_TEST_CHECK(text_equals(oid, oid_size, kRsaEncryptionOid));
    /* openssl 的 rsaEncryption 参数为显式 NULL（05 00）。 */
    ASNBER_TEST_CHECK(data != NULL && size == 2 && data[0] == 0x05);

    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_encrypted_key(
                        env, 0, &data, &size) == ASNBER_OK);
    ASNBER_TEST_CHECK(data != NULL && size > 0);

    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_rid_choice(env, 0,
                                                                 &choice) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(choice == ASNBER_CMS_RID_ISSUER_AND_SERIAL);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_rid_issuer_tlv(
                        env, 0, &data, &size) == ASNBER_OK);
    ASNBER_TEST_CHECK(data != NULL && size > 0);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_rid_serial_tlv(
                        env, 0, &data, &size) == ASNBER_OK);
    ASNBER_TEST_CHECK(data != NULL && size > 0);

    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_rid_serial_decimal(
                        env, 0, decimal, sizeof(decimal), &decimal_size) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(decimal_size == strlen(kKtriSerialDecimal));
    ASNBER_TEST_CHECK(strcmp(decimal, kKtriSerialDecimal) == 0);

    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_content_type(env, &oid,
                                                         &oid_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(text_equals(oid, oid_size, kDataOid));

    ASNBER_TEST_CHECK(
        asnber_cms_enveloped_data_content_encryption_algorithm(
            env, &oid, &oid_size, &data, &size) == ASNBER_OK);
    ASNBER_TEST_CHECK(text_equals(oid, oid_size, kAes256CbcOid));
    ASNBER_TEST_CHECK(data != NULL && size > 0);

    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_encrypted_content(env, &data,
                                                             &size) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(data != NULL && size > 0);
    {
        const uint8_t *content = data;
        size_t content_size = size;
        ASNBER_TEST_CHECK(asnber_cms_enveloped_data_encrypted_content_tlv(
                            env, &data, &size) == ASNBER_OK);
        /* 隐式 OCTET STRING：openssl 用基本形式，标签为 0x80（非构造）。 */
        ASNBER_TEST_CHECK(data != NULL && size == content_size + 2);
        ASNBER_TEST_CHECK(data[0] == 0x80);
        ASNBER_TEST_CHECK(memcmp(data + 2, content, content_size) == 0);
    }

    asnber_cms_enveloped_data_close(env);
    asnber_ctx_destroy(ctx);
    return 0;
}

static int test_ktri_multi(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_cms_enveloped_data_t *env = NULL;
    size_t count = 0;
    int choice = -1;
    const uint8_t *first = NULL;
    size_t first_size = 0;
    const uint8_t *second = NULL;
    size_t second_size = 0;
    char d0[64];
    char d1[64];
    size_t d0_size = 0;
    size_t d1_size = 0;

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(open_env(ctx, kCmsEnvelopedKtriMulti,
                             kCmsEnvelopedKtriMultiSize, &env) == 0);

    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_count(env, &count) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(count == 2);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_choice(env, 0,
                                                             &choice) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(choice == ASNBER_CMS_RECIPIENT_KTRI);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_choice(env, 1,
                                                             &choice) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(choice == ASNBER_CMS_RECIPIENT_KTRI);

    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_rid_serial_decimal(
                        env, 0, d0, sizeof(d0), &d0_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_rid_serial_decimal(
                        env, 1, d1, sizeof(d1), &d1_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(d0_size == d1_size && memcmp(d0, d1, d0_size) == 0);

    /* 同一证书、两次加密的 encryptedKey 不同，分支 TLV 必须不同。 */
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_tlv(
                        env, 0, &first, &first_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_tlv(
                        env, 1, &second, &second_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(first_size != second_size ||
                    memcmp(first, second, first_size) != 0);

    asnber_cms_enveloped_data_close(env);
    asnber_ctx_destroy(ctx);
    return 0;
}

static int test_ktri_keyid(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_cms_enveloped_data_t *env = NULL;
    const char *oid = NULL;
    size_t oid_size = 0;
    const uint8_t *data = NULL;
    size_t size = 0;
    int64_t version = -1;
    size_t count = 0;
    int choice = -1;
    char decimal[64];
    size_t decimal_size = 0;

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(open_env(ctx, kCmsEnvelopedKtriKeyid,
                             kCmsEnvelopedKtriKeyidSize, &env) == 0);

    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_version(env, &version) == ASNBER_OK);
    ASNBER_TEST_CHECK(version == 2);

    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_count(env, &count) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(count == 1);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_choice(env, 0,
                                                             &choice) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(choice == ASNBER_CMS_RECIPIENT_KTRI);

    /* rid 为 subjectKeyIdentifier 时 ktri 的版本按 RFC 5652 §6.2.1 为 2。 */
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_version(
                        env, 0, &version) == ASNBER_OK);
    ASNBER_TEST_CHECK(version == 2);

    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_key_encryption_algorithm(
                        env, 0, &oid, &oid_size, &data, &size) == ASNBER_OK);
    ASNBER_TEST_CHECK(text_equals(oid, oid_size, kRsaEncryptionOid));
    /* 实测：-keyid 样本的 rsaEncryption 仍带显式 NULL（05 00）。 */
    ASNBER_TEST_CHECK(data != NULL && size == 2 && data[0] == 0x05 &&
                    data[1] == 0x00);

    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_encrypted_key(
                        env, 0, &data, &size) == ASNBER_OK);
    ASNBER_TEST_CHECK(data != NULL && size > 0);

    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_rid_choice(env, 0,
                                                                 &choice) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(choice == ASNBER_CMS_RID_SUBJECT_KEY_IDENTIFIER);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_rid_subject_key_id(
                        env, 0, &data, &size) == ASNBER_OK);
    ASNBER_TEST_CHECK(data != NULL && size == 20);

    /* issuer/serial 只属于第一分支，此处应统一返回 ASNBER_E_UNSUPPORTED。 */
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_rid_issuer_tlv(
                        env, 0, &data, &size) == ASNBER_E_UNSUPPORTED);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_rid_serial_tlv(
                        env, 0, &data, &size) == ASNBER_E_UNSUPPORTED);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_rid_serial_decimal(
                        env, 0, decimal, sizeof(decimal), &decimal_size) ==
                    ASNBER_E_UNSUPPORTED);

    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_content_type(env, &oid,
                                                         &oid_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(text_equals(oid, oid_size, kDataOid));
    ASNBER_TEST_CHECK(
        asnber_cms_enveloped_data_content_encryption_algorithm(
            env, &oid, &oid_size, &data, &size) == ASNBER_OK);
    ASNBER_TEST_CHECK(text_equals(oid, oid_size, kAes256CbcOid));
    ASNBER_TEST_CHECK(data != NULL && size > 0);

    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_encrypted_content(env, &data,
                                                             &size) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(data != NULL && size > 0);
    {
        const uint8_t *content = data;
        size_t content_size = size;
        ASNBER_TEST_CHECK(asnber_cms_enveloped_data_encrypted_content_tlv(
                            env, &data, &size) == ASNBER_OK);
        ASNBER_TEST_CHECK(data != NULL && size == content_size + 2);
        ASNBER_TEST_CHECK(data[0] == 0x80);
        ASNBER_TEST_CHECK(memcmp(data + 2, content, content_size) == 0);
    }

    asnber_cms_enveloped_data_close(env);
    asnber_ctx_destroy(ctx);
    return 0;
}

static int test_kari(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_cms_enveloped_data_t *env = NULL;
    const char *oid = NULL;
    size_t oid_size = 0;
    const uint8_t *data = NULL;
    size_t size = 0;
    int64_t version = -1;
    int choice = -1;
    size_t keys = 0;

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(open_env(ctx, kCmsEnvelopedKari, kCmsEnvelopedKariSize,
                             &env) == 0);

    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_version(env, &version) == ASNBER_OK);
    ASNBER_TEST_CHECK(version == 2);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_count(env, &keys) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(keys == 1);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_choice(env, 0,
                                                             &choice) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(choice == ASNBER_CMS_RECIPIENT_KARI);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_version(env, 0,
                                                              &version) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(version == 3);

    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_key_encryption_algorithm(
                        env, 0, &oid, &oid_size, &data, &size) == ASNBER_OK);
    ASNBER_TEST_CHECK(text_equals(oid, oid_size, kDhSsha1Oid));

    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_originator_choice(
                        env, 0, &choice) == ASNBER_OK);
    ASNBER_TEST_CHECK(choice == ASNBER_CMS_ORIGINATOR_KEY);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_originator_tlv(
                        env, 0, &data, &size) == ASNBER_OK);
    ASNBER_TEST_CHECK(data != NULL && size > 0 && data[0] == 0xA0);

    ASNBER_TEST_CHECK(
        asnber_cms_enveloped_data_recipient_kari_encrypted_key_count(
            env, 0, &keys) == ASNBER_OK);
    ASNBER_TEST_CHECK(keys == 1);

    /* 分支专属访问器在 kari 上不适用。 */
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_encrypted_key(
                        env, 0, &data, &size) == ASNBER_E_UNSUPPORTED);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_rid_choice(env, 0,
                                                                 &choice) ==
                    ASNBER_E_UNSUPPORTED);

    asnber_cms_enveloped_data_close(env);
    asnber_ctx_destroy(ctx);
    return 0;
}

static int test_kekri(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_cms_enveloped_data_t *env = NULL;
    const char *oid = NULL;
    size_t oid_size = 0;
    const uint8_t *data = NULL;
    size_t size = 0;
    int64_t version = -1;
    int choice = -1;
    static const uint8_t kKeyId[8] = {1, 2, 3, 4, 5, 6, 7, 8};

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(open_env(ctx, kCmsEnvelopedKekri, kCmsEnvelopedKekriSize,
                             &env) == 0);

    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_version(env, &version) == ASNBER_OK);
    ASNBER_TEST_CHECK(version == 2);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_choice(env, 0,
                                                             &choice) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(choice == ASNBER_CMS_RECIPIENT_KEKRI);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_version(env, 0,
                                                              &version) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(version == 4);

    ASNBER_TEST_CHECK(
        asnber_cms_enveloped_data_recipient_kekri_key_identifier(
            env, 0, &data, &size) == ASNBER_OK);
    ASNBER_TEST_CHECK(size == sizeof(kKeyId) && memcmp(data, kKeyId, size) == 0);

    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_key_encryption_algorithm(
                        env, 0, &oid, &oid_size, &data, &size) == ASNBER_OK);
    ASNBER_TEST_CHECK(text_equals(oid, oid_size, kAes256WrapOid));

    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_encrypted_key(
                        env, 0, &data, &size) == ASNBER_OK);
    ASNBER_TEST_CHECK(data != NULL && size > 0);

    asnber_cms_enveloped_data_close(env);
    asnber_ctx_destroy(ctx);
    return 0;
}

static int test_pwri(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_cms_enveloped_data_t *env = NULL;
    const char *oid = NULL;
    size_t oid_size = 0;
    const uint8_t *data = NULL;
    size_t size = 0;
    int64_t version = -1;
    int choice = -1;

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(open_env(ctx, kCmsEnvelopedPwri, kCmsEnvelopedPwriSize,
                             &env) == 0);

    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_version(env, &version) == ASNBER_OK);
    ASNBER_TEST_CHECK(version == 3);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_choice(env, 0,
                                                             &choice) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(choice == ASNBER_CMS_RECIPIENT_PWRI);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_version(env, 0,
                                                              &version) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(version == 0);

    ASNBER_TEST_CHECK(
        asnber_cms_enveloped_data_recipient_pwri_key_derivation_algorithm_tlv(
            env, 0, &data, &size) == ASNBER_OK);
    ASNBER_TEST_CHECK(data != NULL && size > 0 && data[0] == 0xA0);

    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_key_encryption_algorithm(
                        env, 0, &oid, &oid_size, &data, &size) == ASNBER_OK);
    ASNBER_TEST_CHECK(text_equals(oid, oid_size, kPwriKekOid));
    ASNBER_TEST_CHECK(data != NULL && size > 0);

    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_encrypted_key(
                        env, 0, &data, &size) == ASNBER_OK);
    ASNBER_TEST_CHECK(data != NULL && size > 0);

    asnber_cms_enveloped_data_close(env);
    asnber_ctx_destroy(ctx);
    return 0;
}

static int test_ber_encrypted_content(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_cms_enveloped_data_t *env = NULL;
    const uint8_t *data = NULL;
    size_t size = 0;
    size_t count = 0;
    int choice = -1;

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_open(
                        ctx, kBerSegmentedContent,
                        sizeof(kBerSegmentedContent), &env) == ASNBER_OK);

    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_count(env, &count) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(count == 1);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_choice(env, 0,
                                                             &choice) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(choice == ASNBER_CMS_RECIPIENT_KTRI);

    /* 合并后的内容字节：两个段按顺序拼接。 */
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_encrypted_content(env, &data,
                                                             &size) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(data != NULL && size == 6);
    ASNBER_TEST_CHECK(memcmp(data, "abcdef", 6) == 0);

    /* 完整 TLV 保留构造形式：A0 0A 04 03 "abc" 04 03 "def"，共 12 字节。 */
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_encrypted_content_tlv(
                        env, &data, &size) == ASNBER_OK);
    ASNBER_TEST_CHECK(data != NULL && size == 12);
    ASNBER_TEST_CHECK(data[0] == 0xA0);
    ASNBER_TEST_CHECK(data[1] == 0x0A);
    ASNBER_TEST_CHECK(memcmp(data + 2, "\x04\x03" "abc", 5) == 0);
    ASNBER_TEST_CHECK(memcmp(data + 7, "\x04\x03" "def", 5) == 0);
    /* 两段内容在 TLV 中的位置与合并字节对应。 */
    ASNBER_TEST_CHECK(data[4] == 'a');
    ASNBER_TEST_CHECK(data[11] == 'f');

    asnber_cms_enveloped_data_close(env);
    asnber_ctx_destroy(ctx);
    return 0;
}

static int test_ori_constructed(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_cms_enveloped_data_t *env = NULL;
    const char *oid = NULL;
    size_t oid_size = 0;
    const uint8_t *data = NULL;
    size_t size = 0;
    int64_t version = -1;
    int choice = -1;

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_open(
                        ctx, kOriEnveloped, sizeof(kOriEnveloped), &env) ==
                    ASNBER_OK);

    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_count(env, &size) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(size == 1);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_choice(env, 0,
                                                             &choice) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(choice == ASNBER_CMS_RECIPIENT_ORI);

    /* ori 分支没有 version / keyEncryptionAlgorithm / encryptedKey。 */
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_version(
                        env, 0, &version) == ASNBER_E_UNSUPPORTED);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_key_encryption_algorithm(
                        env, 0, &oid, &oid_size, &data, &size) ==
                    ASNBER_E_UNSUPPORTED);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_encrypted_key(
                        env, 0, &data, &size) == ASNBER_E_UNSUPPORTED);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_rid_choice(env, 0,
                                                                 &choice) ==
                    ASNBER_E_UNSUPPORTED);

    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_ori_type(
                        env, 0, &oid, &oid_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(text_equals(oid, oid_size, "1.2.3.4.5"));
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_ori_value_tlv(
                        env, 0, &data, &size) == ASNBER_OK);
    ASNBER_TEST_CHECK(data != NULL && size == 3 && data[0] == 0x02);

    asnber_cms_enveloped_data_close(env);
    asnber_ctx_destroy(ctx);
    return 0;
}

static int test_negative(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_cms_enveloped_data_t *env = NULL;
    asnber_cms_content_info_t *info = NULL;
    const uint8_t *data = NULL;
    size_t size = 0;
    int64_t version = 0;
    int choice = 0;
    char decimal[16];

    ASNBER_TEST_CHECK(ctx != NULL);

    /* 空参。 */
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_open(ctx, NULL, 1, &env) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_open(ctx, kOriEnveloped, 0,
                                                 &env) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_open(ctx, kOriEnveloped,
                                                 sizeof(kOriEnveloped),
                                                 NULL) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_version(NULL, &version) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_count(NULL, &size) ==
                    ASNBER_E_INVALID_ARG);

    /* 整段 ContentInfo 不是裸 EnvelopedData：根 SEQUENCE 可解析，但第一个
     * 必需字段版本之后接的是 OID 而非 recipientInfos，实测返回
     * ASNBER_E_SCHEMA_FIELD。 */
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_open(
                        ctx, kCmsEnvelopedKtri, kCmsEnvelopedKtriSize,
                        &env) == ASNBER_E_SCHEMA_FIELD);
    ASNBER_TEST_CHECK(env == NULL);

    /* 截断：保留外层 TLV 头与 version，丢掉 recipientInfos；实测解码器
     * 在外层长度不足时返回 ASNBER_E_TRUNCATED。 */
    ASNBER_TEST_CHECK(asnber_cms_content_info_open(ctx, kCmsEnvelopedKtri,
                                               kCmsEnvelopedKtriSize,
                                               &info) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_content_info_content(info, &data, &size) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_open(ctx, data, 8, &env) ==
                    ASNBER_E_TRUNCATED);
    asnber_cms_content_info_close(info);
    info = NULL;

    /* 空 recipientInfos 由 schema 的 SIZE 约束拒绝。 */
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_open(ctx, kEmptyRecipients,
                                                 sizeof(kEmptyRecipients),
                                                 &env) ==
                    ASNBER_E_SCHEMA_CONSTRAINT);
    ASNBER_TEST_CHECK(env == NULL);

    /* 越界与缓冲不足。 */
    ASNBER_TEST_CHECK(open_env(ctx, kCmsEnvelopedKtri, kCmsEnvelopedKtriSize,
                             &env) == 0);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_choice(env, 1,
                                                             &choice) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_tlv(env, 1, &data,
                                                         &size) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_rid_serial_decimal(
                        env, 0, decimal, sizeof(decimal), &size) ==
                    ASNBER_E_INVALID_ARG);

    /* kari 专属访问器在 ktri 上不适用，反之亦然。 */
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_originator_choice(
                        env, 0, &choice) == ASNBER_E_UNSUPPORTED);
    ASNBER_TEST_CHECK(
        asnber_cms_enveloped_data_recipient_kari_encrypted_key_count(
            env, 0, &size) == ASNBER_E_UNSUPPORTED);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_ori_type(
                        env, 0, NULL, NULL) == ASNBER_E_INVALID_ARG);

    asnber_cms_enveloped_data_close(env);
    asnber_ctx_destroy(ctx);
    return 0;
}

int main(void)
{
    if (test_ktri() != 0) {
        return 1;
    }
    if (test_ktri_multi() != 0) {
        return 1;
    }
    if (test_ktri_keyid() != 0) {
        return 1;
    }
    if (test_kari() != 0) {
        return 1;
    }
    if (test_kekri() != 0) {
        return 1;
    }
    if (test_pwri() != 0) {
        return 1;
    }
    if (test_ori_constructed() != 0) {
        return 1;
    }
    if (test_ber_encrypted_content() != 0) {
        return 1;
    }
    if (test_negative() != 0) {
        return 1;
    }
    return 0;
}
