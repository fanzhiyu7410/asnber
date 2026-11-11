/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * asnber-cms 只读结构访问：ContentInfo / SignedData。
 * 覆盖 attached/detached、多证书、无证书最小样本、SignerInfo 字段（含
 * subjectKeyIdentifier 形式的 sid）与负例。
 */

#include <asnber/asnber.h>
#include <asnber/cms/cms.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "../data/cms_rsa_attached.h"
#include "../data/cms_rsa_detached.h"
#include "../data/cms_rsa_ec_multicert.h"
#include "../data/cms_rsa_keyid.h"
#include "../data/cms_rsa_minimal.h"
#include "../data/cert_rsa_selfsigned.h"
#include "check.h"
#include "test_compare.h"

static const char kSignedDataOid[] = "1.2.840.113549.1.7.2";
static const char kDataOid[] = "1.2.840.113549.1.7.1";
static const char kSha256Oid[] = "2.16.840.1.101.3.4.2.1";
static const char kRsaEncryptionOid[] = "1.2.840.113549.1.1.1";

/* 版本同源：CMake 生成头宏、模块运行时字符串与核心运行时字符串一致。 */
static int test_module_version(void)
{
    const char *runtime = asnber_cms_version_string();
    asnber_version_info_t info;

    memset(&info, 0, sizeof(info));
    info.struct_size = sizeof(info);
    ASNBER_TEST_CHECK(runtime != NULL);
    ASNBER_TEST_CHECK(strcmp(runtime, ASNBER_CMS_VERSION_STRING) == 0);
    ASNBER_TEST_CHECK(asnber_version(&info) == ASNBER_OK);
    ASNBER_TEST_CHECK(info.string != NULL);
    ASNBER_TEST_CHECK(strcmp(runtime, info.string) == 0);
    return 0;
}

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

/* ContentInfo -> SignedData；两者由调用方 close。 */
static int open_signed_data(asnber_ctx_t *ctx, const unsigned char *der,
                            size_t der_size,
                            asnber_cms_content_info_t **out_info,
                            asnber_cms_signed_data_t **out_signed)
{
    const uint8_t *content = NULL;
    size_t content_size = 0;

    ASNBER_TEST_CHECK(asnber_cms_content_info_open(ctx, der, der_size, out_info) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_content_info_content(*out_info, &content,
                                                  &content_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(content != NULL && content_size > 0);
    ASNBER_TEST_CHECK(asnber_cms_signed_data_open(ctx, content, content_size,
                                              out_signed) == ASNBER_OK);
    return 0;
}

/* ---------- attached：完整内容 + 单证书 ---------- */

static int test_attached(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_cms_content_info_t *info = NULL;
    asnber_cms_signed_data_t *signed_data = NULL;

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(open_signed_data(ctx, kCmsRsaAttached,
                                     kCmsRsaAttachedSize, &info,
                                     &signed_data) == 0);

    {
        const char *oid = NULL;
        size_t size = 0;
        ASNBER_TEST_CHECK(asnber_cms_content_info_content_type(info, &oid,
                                                           &size) == ASNBER_OK);
        ASNBER_TEST_CHECK(text_equals(oid, size, kSignedDataOid));
    }

    {
        int64_t version = -1;
        ASNBER_TEST_CHECK(asnber_cms_signed_data_version(
                            signed_data, &version) == ASNBER_OK);
        ASNBER_TEST_CHECK(version == 1);
    }

    {
        size_t count = 0;
        const char *oid = NULL;
        size_t oid_size = 0;
        const uint8_t *params = NULL;
        size_t params_size = 0;

        ASNBER_TEST_CHECK(asnber_cms_signed_data_digest_algorithm_count(
                            signed_data, &count) == ASNBER_OK);
        ASNBER_TEST_CHECK(count == 1);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_digest_algorithm_at(
                            signed_data, 0, &oid, &oid_size, &params,
                            &params_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(text_equals(oid, oid_size, kSha256Oid));
        /* 本样本的摘要算法省略 parameters，缺省返回 NULL/0。 */
        ASNBER_TEST_CHECK(params == NULL && params_size == 0);
    }

    {
        const char *oid = NULL;
        size_t size = 0;
        const uint8_t *data = NULL;
        const uint8_t *tlv = NULL;
        size_t data_size = 0;
        size_t tlv_size = 0;

        ASNBER_TEST_CHECK(asnber_cms_signed_data_encap_content_type(
                            signed_data, &oid, &size) == ASNBER_OK);
        ASNBER_TEST_CHECK(text_equals(oid, size, kDataOid));
        ASNBER_TEST_CHECK(asnber_cms_signed_data_encap_content(
                            signed_data, &data, &data_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(data != NULL && data_size > 0);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_encap_content_tlv(
                            signed_data, &tlv, &tlv_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(tlv != NULL && tlv_size > data_size);
        ASNBER_TEST_CHECK(tlv[0] == 0x04);
    }

    {
        size_t count = 0;
        int choice = -1;
        const uint8_t *tlv = NULL;
        size_t tlv_size = 0;
        const uint8_t *subject = NULL;
        const uint8_t *issuer = NULL;
        size_t subject_size = 0;
        size_t issuer_size = 0;
        const char *serial = NULL;
        size_t serial_size = 0;

        ASNBER_TEST_CHECK(asnber_cms_signed_data_certificate_count(
                            signed_data, &count) == ASNBER_OK);
        ASNBER_TEST_CHECK(count == 1);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_certificate_at(
                            signed_data, 0, &choice, &tlv, &tlv_size) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(choice == ASNBER_CMS_CERT_CHOICE_CERTIFICATE);
        ASNBER_TEST_CHECK(tlv != NULL && tlv_size > 0 && tlv[0] == 0x30);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_certificate_subject(
                            signed_data, 0, &subject, &subject_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(subject != NULL && subject_size > 0);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_certificate_issuer(
                            signed_data, 0, &issuer, &issuer_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(issuer != NULL && issuer_size > 0);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_certificate_serial(
                            signed_data, 0, &serial, &serial_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(serial != NULL && serial_size > 0);
    }

    {
        size_t count = 99;
        ASNBER_TEST_CHECK(asnber_cms_signed_data_crl_count(signed_data, &count) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(count == 0);
    }

    {
        size_t count = 0;
        int64_t version = -1;
        int sid_choice = -1;
        const uint8_t *issuer = NULL;
        size_t issuer_size = 0;
        const char *serial = NULL;
        size_t serial_size = 0;
        const char *oid = NULL;
        size_t oid_size = 0;
        const uint8_t *params = NULL;
        size_t params_size = 0;
        const uint8_t *attrs = NULL;
        size_t attrs_size = 0;
        const uint8_t *signature = NULL;
        size_t signature_size = 0;

        ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_count(
                            signed_data, &count) == ASNBER_OK);
        ASNBER_TEST_CHECK(count == 1);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_version(
                            signed_data, 0, &version) == ASNBER_OK);
        ASNBER_TEST_CHECK(version == 1);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_sid_choice(
                            signed_data, 0, &sid_choice) == ASNBER_OK);
        ASNBER_TEST_CHECK(sid_choice == ASNBER_CMS_SID_ISSUER_AND_SERIAL);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_sid_issuer(
                            signed_data, 0, &issuer, &issuer_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(issuer != NULL && issuer_size > 0);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_sid_serial(
                            signed_data, 0, &serial, &serial_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(serial != NULL && serial_size > 0);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_digest_algorithm(
                            signed_data, 0, &oid, &oid_size, &params,
                            &params_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(text_equals(oid, oid_size, kSha256Oid));
        ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_signed_attrs(
                            signed_data, 0, &attrs, &attrs_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(attrs != NULL && attrs_size > 0 && attrs[0] == 0xA0);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_signature_algorithm(
                            signed_data, 0, &oid, &oid_size, &params,
                            &params_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(text_equals(oid, oid_size, kRsaEncryptionOid));
        ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_signature(
                            signed_data, 0, &signature,
                            &signature_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(signature != NULL && signature_size > 0);
        /* OpenSSL 默认不写 unsignedAttrs。 */
        ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_unsigned_attrs(
                            signed_data, 0, &attrs, &attrs_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(attrs == NULL && attrs_size == 0);
    }

    /* 越界与错误分支判别。 */
    {
        int choice = -1;
        const uint8_t *tlv = NULL;
        size_t tlv_size = 0;
        const uint8_t *subject = NULL;
        size_t subject_size = 0;
        ASNBER_TEST_CHECK(asnber_cms_signed_data_certificate_at(
                            signed_data, 99, &choice, &tlv, &tlv_size) ==
                        ASNBER_E_INVALID_ARG);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_certificate_subject(
                            signed_data, 99, &subject, &subject_size) ==
                        ASNBER_E_INVALID_ARG);
        int64_t out_of_range_version = -1;
        ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_version(
                            signed_data, 99, &out_of_range_version) ==
                        ASNBER_E_INVALID_ARG);
    }

    asnber_cms_signed_data_close(signed_data);
    asnber_cms_content_info_close(info);
    asnber_ctx_destroy(ctx);
    return 0;
}

/* ---------- detached：无 eContent，仍有证书与 signedAttrs ---------- */

static int test_detached(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_cms_content_info_t *info = NULL;
    asnber_cms_signed_data_t *signed_data = NULL;

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(open_signed_data(ctx, kCmsRsaDetached,
                                     kCmsRsaDetachedSize, &info,
                                     &signed_data) == 0);

    {
        const char *oid = NULL;
        size_t oid_size = 0;
        const uint8_t *data = NULL;
        const uint8_t *tlv = NULL;
        size_t data_size = 99;
        size_t tlv_size = 99;

        ASNBER_TEST_CHECK(asnber_cms_signed_data_encap_content_type(
                            signed_data, &oid, &oid_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(text_equals(oid, oid_size, kDataOid));
        ASNBER_TEST_CHECK(asnber_cms_signed_data_encap_content(
                            signed_data, &data, &data_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(data == NULL && data_size == 0);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_encap_content_tlv(
                            signed_data, &tlv, &tlv_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(tlv == NULL && tlv_size == 0);
    }

    {
        size_t count = 0;
        const uint8_t *attrs = NULL;
        size_t attrs_size = 0;
        ASNBER_TEST_CHECK(asnber_cms_signed_data_certificate_count(
                            signed_data, &count) == ASNBER_OK);
        ASNBER_TEST_CHECK(count == 1);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_count(
                            signed_data, &count) == ASNBER_OK);
        ASNBER_TEST_CHECK(count == 1);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_signed_attrs(
                            signed_data, 0, &attrs, &attrs_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(attrs != NULL && attrs_size > 0 && attrs[0] == 0xA0);
    }

    asnber_cms_signed_data_close(signed_data);
    asnber_cms_content_info_close(info);
    asnber_ctx_destroy(ctx);
    return 0;
}

/* ---------- 最小样本：无证书、无 signedAttrs ---------- */

static int test_minimal(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_cms_content_info_t *info = NULL;
    asnber_cms_signed_data_t *signed_data = NULL;

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(open_signed_data(ctx, kCmsRsaMinimal,
                                     kCmsRsaMinimalSize, &info,
                                     &signed_data) == 0);

    {
        size_t count = 99;
        ASNBER_TEST_CHECK(asnber_cms_signed_data_certificate_count(
                            signed_data, &count) == ASNBER_OK);
        ASNBER_TEST_CHECK(count == 0);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_crl_count(signed_data, &count) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(count == 0);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_count(signed_data,
                                                          &count) == ASNBER_OK);
        ASNBER_TEST_CHECK(count == 1);
    }

    {
        const uint8_t *data = NULL;
        size_t data_size = 99;
        const uint8_t *attrs = NULL;
        size_t attrs_size = 99;
        const uint8_t *signature = NULL;
        size_t signature_size = 0;
        int sid_choice = -1;

        ASNBER_TEST_CHECK(asnber_cms_signed_data_encap_content(
                            signed_data, &data, &data_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(data == NULL && data_size == 0);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_signed_attrs(
                            signed_data, 0, &attrs, &attrs_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(attrs == NULL && attrs_size == 0);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_sid_choice(
                            signed_data, 0, &sid_choice) == ASNBER_OK);
        ASNBER_TEST_CHECK(sid_choice == ASNBER_CMS_SID_ISSUER_AND_SERIAL);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_signature(
                            signed_data, 0, &signature,
                            &signature_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(signature != NULL && signature_size > 0);
    }

    asnber_cms_signed_data_close(signed_data);
    asnber_cms_content_info_close(info);
    asnber_ctx_destroy(ctx);
    return 0;
}

/* ---------- 多证书：逐项访问两个证书与两个 SignerInfo ---------- */

static int test_multicert(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_cms_content_info_t *info = NULL;
    asnber_cms_signed_data_t *signed_data = NULL;

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(open_signed_data(ctx, kCmsRsaEcMulticert,
                                     kCmsRsaEcMulticertSize, &info,
                                     &signed_data) == 0);

    {
        size_t count = 0;
        ASNBER_TEST_CHECK(asnber_cms_signed_data_certificate_count(
                            signed_data, &count) == ASNBER_OK);
        ASNBER_TEST_CHECK(count == 2);

        for (size_t i = 0; i < count; ++i) {
            int choice = -1;
            const uint8_t *tlv = NULL;
            size_t tlv_size = 0;
            const uint8_t *subject = NULL;
            const uint8_t *issuer = NULL;
            size_t subject_size = 0;
            size_t issuer_size = 0;
            const char *serial = NULL;
            size_t serial_size = 0;

            ASNBER_TEST_CHECK(asnber_cms_signed_data_certificate_at(
                                signed_data, i, &choice, &tlv,
                                &tlv_size) == ASNBER_OK);
            ASNBER_TEST_CHECK(choice == ASNBER_CMS_CERT_CHOICE_CERTIFICATE);
            ASNBER_TEST_CHECK(tlv != NULL && tlv_size > 0 && tlv[0] == 0x30);
            ASNBER_TEST_CHECK(asnber_cms_signed_data_certificate_subject(
                                signed_data, i, &subject, &subject_size) ==
                            ASNBER_OK);
            ASNBER_TEST_CHECK(subject != NULL && subject_size > 0);
            ASNBER_TEST_CHECK(asnber_cms_signed_data_certificate_issuer(
                                signed_data, i, &issuer, &issuer_size) ==
                            ASNBER_OK);
            ASNBER_TEST_CHECK(issuer != NULL && issuer_size > 0);
            ASNBER_TEST_CHECK(asnber_cms_signed_data_certificate_serial(
                                signed_data, i, &serial, &serial_size) ==
                            ASNBER_OK);
            ASNBER_TEST_CHECK(serial != NULL && serial_size > 0);
        }
    }

    {
        size_t count = 0;
        ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_count(signed_data,
                                                          &count) == ASNBER_OK);
        ASNBER_TEST_CHECK(count == 2);
        for (size_t i = 0; i < count; ++i) {
            int sid_choice = -1;
            const uint8_t *signature = NULL;
            size_t signature_size = 0;
            const char *oid = NULL;
            size_t oid_size = 0;
            const uint8_t *params = NULL;
            size_t params_size = 0;

            ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_sid_choice(
                                signed_data, i, &sid_choice) == ASNBER_OK);
            ASNBER_TEST_CHECK(sid_choice == ASNBER_CMS_SID_ISSUER_AND_SERIAL);
            ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_signature_algorithm(
                                signed_data, i, &oid, &oid_size, &params,
                                &params_size) == ASNBER_OK);
            ASNBER_TEST_CHECK(oid != NULL && oid_size > 0);
            ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_signature(
                                signed_data, i, &signature,
                                &signature_size) == ASNBER_OK);
            ASNBER_TEST_CHECK(signature != NULL && signature_size > 0);
        }
    }

    asnber_cms_signed_data_close(signed_data);
    asnber_cms_content_info_close(info);
    asnber_ctx_destroy(ctx);
    return 0;
}

/* ---------- subjectKeyIdentifier 形式的 sid ---------- */

static int test_keyid(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_cms_content_info_t *info = NULL;
    asnber_cms_signed_data_t *signed_data = NULL;

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(open_signed_data(ctx, kCmsRsaKeyid, kCmsRsaKeyidSize, &info,
                                     &signed_data) == 0);

    {
        int sid_choice = -1;
        const uint8_t *key_id = NULL;
        size_t key_id_size = 0;
        const uint8_t *issuer = NULL;
        size_t issuer_size = 0;
        const char *serial = NULL;
        size_t serial_size = 0;

        ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_sid_choice(
                            signed_data, 0, &sid_choice) == ASNBER_OK);
        ASNBER_TEST_CHECK(sid_choice == ASNBER_CMS_SID_SUBJECT_KEY_IDENTIFIER);
        ASNBER_TEST_CHECK(
            asnber_cms_signed_data_signer_sid_subject_key_identifier(
                signed_data, 0, &key_id, &key_id_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(key_id != NULL && key_id_size > 0);
        /* 两种 issuerAndSerialNumber 访问器在该分支必须拒绝。 */
        ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_sid_issuer(
                            signed_data, 0, &issuer, &issuer_size) ==
                        ASNBER_E_INVALID_ARG);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_sid_serial(
                            signed_data, 0, &serial, &serial_size) ==
                        ASNBER_E_INVALID_ARG);
    }

    {
        int64_t version = -1;
        ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_version(
                            signed_data, 0, &version) == ASNBER_OK);
        /* subjectKeyIdentifier 形式的 sid 对应 CMSVersion v3。 */
        ASNBER_TEST_CHECK(version == 3);
    }

    asnber_cms_signed_data_close(signed_data);
    asnber_cms_content_info_close(info);
    asnber_ctx_destroy(ctx);
    return 0;
}

/* ---------- 负例 ---------- */

static int test_negative(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_cms_content_info_t *info = NULL;
    asnber_cms_signed_data_t *signed_data = NULL;
    uint8_t *truncated = NULL;

    ASNBER_TEST_CHECK(ctx != NULL);

    /* 空参。 */
    ASNBER_TEST_CHECK(asnber_cms_content_info_open(ctx, NULL, 1, &info) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_content_info_open(ctx, kCmsRsaAttached, 0,
                                               &info) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_content_info_open(ctx, kCmsRsaAttached,
                                               kCmsRsaAttachedSize,
                                               NULL) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_signed_data_open(ctx, NULL, 1, &signed_data) ==
                    ASNBER_E_INVALID_ARG);

    /* 非 CMS 输入（X.509 证书 DER）。 */
    ASNBER_TEST_CHECK(asnber_cms_content_info_open(ctx, kCertRsaSelfsigned,
                                               kCertRsaSelfsignedSize,
                                               &info) != ASNBER_OK);
    ASNBER_TEST_CHECK(info == NULL);

    /* 用 ContentInfo 整段喂给 SignedData：根结构不符。 */
    ASNBER_TEST_CHECK(asnber_cms_signed_data_open(ctx, kCmsRsaAttached,
                                              kCmsRsaAttachedSize,
                                              &signed_data) != ASNBER_OK);
    ASNBER_TEST_CHECK(signed_data == NULL);

    /* 截断（保留外层头与 contentType，丢掉 content）。 */
    truncated = (uint8_t *)malloc(40);
    ASNBER_TEST_CHECK(truncated != NULL);
    memcpy(truncated, kCmsRsaAttached, 40);
    ASNBER_TEST_CHECK(asnber_cms_content_info_open(ctx, truncated, 40, &info) !=
                    ASNBER_OK);
    ASNBER_TEST_CHECK(info == NULL);
    free(truncated);

    /* 访问器空参。 */
    ASNBER_TEST_CHECK(asnber_cms_content_info_content_type(NULL, NULL, NULL) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_content_info_content(NULL, NULL, NULL) ==
                    ASNBER_E_INVALID_ARG);

    asnber_ctx_destroy(ctx);
    return 0;
}

int main(void)
{
    if (test_module_version() != 0) {
        return 1;
    }
    if (test_attached() != 0) {
        return 1;
    }
    if (test_detached() != 0) {
        return 1;
    }
    if (test_minimal() != 0) {
        return 1;
    }
    if (test_multicert() != 0) {
        return 1;
    }
    if (test_keyid() != 0) {
        return 1;
    }
    if (test_negative() != 0) {
        return 1;
    }
    return 0;
}
