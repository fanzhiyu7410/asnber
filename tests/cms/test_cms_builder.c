/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * asnber-cms 结构构造：builder 正例、负例与 5 份既有样本的
 * decode → 重建 → 编码逐字节往返。
 */

#include <asnber/asnber.h>
#include <asnber/cms/cms.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "../data/cert_rsa_selfsigned.h"
#include "../data/cms_rsa_attached.h"
#include "../data/cms_rsa_detached.h"
#include "../data/cms_rsa_ec_multicert.h"
#include "../data/cms_rsa_keyid.h"
#include "../data/cms_rsa_minimal.h"
#include "check.h"
#include "test_compare.h"

static const char kSignedDataOid[] = "1.2.840.113549.1.7.2";
static const char kDataOid[] = "1.2.840.113549.1.7.1";
static const char kSha256Oid[] = "2.16.840.1.101.3.4.2.1";
static const char kRsaEncryptionOid[] = "1.2.840.113549.1.1.1";

static const uint8_t kNullParams[2] = {0x05, 0x00};

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

/* 从既有样本读取全部字段并交给 builder 重建，编码后与原字节比较。 */
static int rebuild_sample(asnber_ctx_t *ctx, const uint8_t *der,
                          size_t der_size)
{
    asnber_cms_content_info_t *info = NULL;
    asnber_cms_signed_data_t *signed_data = NULL;
    asnber_cms_builder_t *builder = NULL;
    asnber_buf_t encoded;
    memset(&encoded, 0, sizeof(encoded));

    ASNBER_TEST_CHECK(asnber_cms_content_info_open(ctx, der, der_size, &info) ==
                    ASNBER_OK);

    {
        const char *oid = NULL;
        size_t oid_size = 0;
        ASNBER_TEST_CHECK(asnber_cms_content_info_content_type(info, &oid,
                                                           &oid_size) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(text_equals(oid, oid_size, kSignedDataOid));
    }

    {
        const uint8_t *content = NULL;
        size_t content_size = 0;
        ASNBER_TEST_CHECK(asnber_cms_content_info_content(info, &content,
                                                      &content_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(content != NULL && content_size > 0);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_open(ctx, content, content_size,
                                                  &signed_data) == ASNBER_OK);
    }

    ASNBER_TEST_CHECK(asnber_cms_builder_create(ctx, &builder) == ASNBER_OK);

    {
        int64_t version = -1;
        ASNBER_TEST_CHECK(asnber_cms_signed_data_version(signed_data, &version) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_builder_set_version(builder, version) ==
                        ASNBER_OK);
    }

    {
        size_t count = 0;
        ASNBER_TEST_CHECK(asnber_cms_signed_data_digest_algorithm_count(
                            signed_data, &count) == ASNBER_OK);
        ASNBER_TEST_CHECK(count > 0);
        for (size_t i = 0; i < count; ++i) {
            const char *oid = NULL;
            size_t oid_size = 0;
            const uint8_t *params = NULL;
            size_t params_size = 0;
            ASNBER_TEST_CHECK(asnber_cms_signed_data_digest_algorithm_at(
                                signed_data, i, &oid, &oid_size, &params,
                                &params_size) == ASNBER_OK);
            ASNBER_TEST_CHECK(asnber_cms_builder_add_digest_algorithm(
                                builder, oid, params, params_size) == ASNBER_OK);
        }
    }

    {
        const char *oid = NULL;
        size_t oid_size = 0;
        const uint8_t *octets = NULL;
        size_t octets_size = 0;
        const uint8_t *tlv = NULL;
        size_t tlv_size = 0;

        ASNBER_TEST_CHECK(asnber_cms_signed_data_encap_content_type(
                            signed_data, &oid, &oid_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_builder_set_econtent_type(builder, oid) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_encap_content(
                            signed_data, &octets, &octets_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_encap_content_tlv(
                            signed_data, &tlv, &tlv_size) == ASNBER_OK);
        if (tlv != NULL) {
            ASNBER_TEST_CHECK(octets != NULL);
            ASNBER_TEST_CHECK(asnber_cms_builder_set_econtent(builder, tlv,
                                                          tlv_size) == ASNBER_OK);
        } else {
            ASNBER_TEST_CHECK(octets == NULL && octets_size == 0);
        }
    }

    {
        size_t count = 0;
        ASNBER_TEST_CHECK(asnber_cms_signed_data_certificate_count(signed_data,
                                                               &count) ==
                        ASNBER_OK);
        for (size_t i = 0; i < count; ++i) {
            int choice = -1;
            const uint8_t *tlv = NULL;
            size_t tlv_size = 0;
            ASNBER_TEST_CHECK(asnber_cms_signed_data_certificate_at(
                                signed_data, i, &choice, &tlv, &tlv_size) ==
                            ASNBER_OK);
            ASNBER_TEST_CHECK(choice == ASNBER_CMS_CERT_CHOICE_CERTIFICATE);
            ASNBER_TEST_CHECK(asnber_cms_builder_add_certificate(builder, tlv,
                                                             tlv_size) ==
                            ASNBER_OK);
        }
    }

    {
        size_t count = 0;
        ASNBER_TEST_CHECK(asnber_cms_signed_data_crl_count(signed_data, &count) ==
                        ASNBER_OK);
        for (size_t i = 0; i < count; ++i) {
            int choice = -1;
            const uint8_t *tlv = NULL;
            size_t tlv_size = 0;
            ASNBER_TEST_CHECK(asnber_cms_signed_data_crl_at(signed_data, i, &choice,
                                                        &tlv, &tlv_size) ==
                            ASNBER_OK);
            ASNBER_TEST_CHECK(choice == ASNBER_CMS_REVOCATION_CHOICE_CRL);
            ASNBER_TEST_CHECK(asnber_cms_builder_add_crl(builder, tlv, tlv_size) ==
                            ASNBER_OK);
        }
    }

    {
        size_t count = 0;
        ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_count(signed_data, &count) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(count > 0);
        for (size_t i = 0; i < count; ++i) {
            int64_t version = -1;
            int sid_choice = -1;
            const uint8_t *sid1 = NULL;
            size_t sid1_size = 0;
            const uint8_t *sid2 = NULL;
            size_t sid2_size = 0;
            const char *digest_oid = NULL;
            size_t digest_oid_size = 0;
            const uint8_t *digest_params = NULL;
            size_t digest_params_size = 0;
            const uint8_t *signed_attrs = NULL;
            size_t signed_attrs_size = 0;
            const char *sig_oid = NULL;
            size_t sig_oid_size = 0;
            const uint8_t *sig_params = NULL;
            size_t sig_params_size = 0;
            const uint8_t *signature = NULL;
            size_t signature_size = 0;
            const uint8_t *unsigned_attrs = NULL;
            size_t unsigned_attrs_size = 0;
            uint8_t *signed_attrs_in = NULL;
            uint8_t *unsigned_attrs_in = NULL;

            ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_version(
                                signed_data, i, &version) == ASNBER_OK);
            ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_sid_choice(
                                signed_data, i, &sid_choice) == ASNBER_OK);
            if (sid_choice == ASNBER_CMS_SID_ISSUER_AND_SERIAL) {
                ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_sid_issuer(
                                    signed_data, i, &sid1, &sid1_size) ==
                                ASNBER_OK);
                ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_sid_serial_tlv(
                                    signed_data, i, &sid2, &sid2_size) ==
                                ASNBER_OK);
            } else {
                ASNBER_TEST_CHECK(
                    asnber_cms_signed_data_signer_sid_subject_key_identifier(
                        signed_data, i, &sid1, &sid1_size) == ASNBER_OK);
                sid2 = NULL;
                sid2_size = 0;
            }

            ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_digest_algorithm(
                                signed_data, i, &digest_oid, &digest_oid_size,
                                &digest_params, &digest_params_size) == ASNBER_OK);
            ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_signed_attrs(
                                signed_data, i, &signed_attrs,
                                &signed_attrs_size) == ASNBER_OK);
            ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_signature_algorithm(
                                signed_data, i, &sig_oid, &sig_oid_size,
                                &sig_params, &sig_params_size) == ASNBER_OK);
            ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_signature(
                                signed_data, i, &signature, &signature_size) ==
                            ASNBER_OK);
            ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_unsigned_attrs(
                                signed_data, i, &unsigned_attrs,
                                &unsigned_attrs_size) == ASNBER_OK);

            if (signed_attrs != NULL) {
                ASNBER_TEST_CHECK(rewrite_outer_tag(signed_attrs,
                                                  signed_attrs_size, 0x31,
                                                  &signed_attrs_in,
                                                  &signed_attrs_size) == ASNBER_OK);
            }
            if (unsigned_attrs != NULL) {
                ASNBER_TEST_CHECK(rewrite_outer_tag(unsigned_attrs,
                                                  unsigned_attrs_size, 0x31,
                                                  &unsigned_attrs_in,
                                                  &unsigned_attrs_size) ==
                                ASNBER_OK);
            }

            ASNBER_TEST_CHECK(asnber_cms_builder_add_signer(
                                builder, version, sid_choice, sid1, sid1_size,
                                sid2, sid2_size, digest_oid, digest_params,
                                digest_params_size, signed_attrs_in,
                                signed_attrs_size, sig_oid, sig_params,
                                sig_params_size, signature, signature_size,
                                unsigned_attrs_in, unsigned_attrs_size) ==
                            ASNBER_OK);
            free(signed_attrs_in);
            free(unsigned_attrs_in);
        }
    }

    ASNBER_TEST_CHECK(asnber_cms_builder_encode(builder, &encoded) == ASNBER_OK);
    ASNBER_TEST_CHECK(bytes_equal(encoded.data, encoded.size, der, der_size));

    asnber_buf_release(ctx, &encoded);
    asnber_cms_builder_destroy(builder);
    asnber_cms_signed_data_close(signed_data);
    asnber_cms_content_info_close(info);
    return 0;
}

static int roundtrip_all_samples(asnber_ctx_t *ctx)
{
    ASNBER_TEST_CHECK(rebuild_sample(ctx, kCmsRsaAttached, kCmsRsaAttachedSize) ==
                    0);
    ASNBER_TEST_CHECK(rebuild_sample(ctx, kCmsRsaDetached, kCmsRsaDetachedSize) ==
                    0);
    ASNBER_TEST_CHECK(rebuild_sample(ctx, kCmsRsaEcMulticert,
                                   kCmsRsaEcMulticertSize) == 0);
    ASNBER_TEST_CHECK(rebuild_sample(ctx, kCmsRsaKeyid, kCmsRsaKeyidSize) == 0);
    ASNBER_TEST_CHECK(rebuild_sample(ctx, kCmsRsaMinimal, kCmsRsaMinimalSize) ==
                    0);
    return 0;
}

/* 构造一份最小 attached SignedData：无证书、issuerAndSerialNumber、无属性。 */
static int build_attached_minimal(asnber_ctx_t *ctx)
{
    static const uint8_t kEcontent[7] = {0x04, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F};
    static const uint8_t kIssuer[2] = {0x30, 0x00};
    static const uint8_t kSerial[3] = {0x02, 0x01, 0x01};
    static const uint8_t kSignature[3] = {0x01, 0x02, 0x03};

    asnber_cms_builder_t *builder = NULL;
    asnber_buf_t encoded;
    memset(&encoded, 0, sizeof(encoded));
    ASNBER_TEST_CHECK(asnber_cms_builder_create(ctx, &builder) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_builder_set_version(builder, 1) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_builder_add_digest_algorithm(
                        builder, kSha256Oid, NULL, 0) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_builder_set_econtent_type(builder, kDataOid) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_builder_set_econtent(builder, kEcontent,
                                                  sizeof(kEcontent)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_builder_add_signer(
                        builder, 1, ASNBER_CMS_SID_ISSUER_AND_SERIAL, kIssuer,
                        sizeof(kIssuer), kSerial, sizeof(kSerial), kSha256Oid,
                        NULL, 0, NULL, 0, kRsaEncryptionOid, kNullParams,
                        sizeof(kNullParams), kSignature, sizeof(kSignature),
                        NULL, 0) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_builder_encode(builder, &encoded) == ASNBER_OK);

    /* 回读结构字段。 */
    asnber_cms_content_info_t *info = NULL;
    asnber_cms_signed_data_t *signed_data = NULL;
    ASNBER_TEST_CHECK(asnber_cms_content_info_open(ctx, encoded.data, encoded.size,
                                               &info) == ASNBER_OK);
    {
        const uint8_t *content = NULL;
        size_t content_size = 0;
        ASNBER_TEST_CHECK(asnber_cms_content_info_content(info, &content,
                                                      &content_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_open(ctx, content, content_size,
                                                  &signed_data) == ASNBER_OK);
    }
    {
        const uint8_t *octets = NULL;
        size_t octets_size = 0;
        ASNBER_TEST_CHECK(asnber_cms_signed_data_encap_content(
                            signed_data, &octets, &octets_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(octets != NULL && octets_size == 5);
        ASNBER_TEST_CHECK(memcmp(octets, "hello", 5) == 0);
    }
    {
        size_t count = 0;
        ASNBER_TEST_CHECK(asnber_cms_signed_data_certificate_count(signed_data,
                                                               &count) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(count == 0);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_count(signed_data,
                                                          &count) == ASNBER_OK);
        ASNBER_TEST_CHECK(count == 1);
    }
    {
        const uint8_t *signature = NULL;
        size_t signature_size = 0;
        ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_signature(
                            signed_data, 0, &signature, &signature_size) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(signature, signature_size, kSignature,
                                    sizeof(kSignature)));
    }

    asnber_cms_signed_data_close(signed_data);
    asnber_cms_content_info_close(info);
    asnber_buf_release(ctx, &encoded);
    asnber_cms_builder_destroy(builder);
    return 0;
}

/* 构造 detached：不设置 eContent。 */
static int build_detached(asnber_ctx_t *ctx)
{
    static const uint8_t kIssuer[2] = {0x30, 0x00};
    static const uint8_t kSerial[3] = {0x02, 0x01, 0x01};
    static const uint8_t kSignature[2] = {0xAA, 0xBB};

    asnber_cms_builder_t *builder = NULL;
    asnber_buf_t encoded;
    memset(&encoded, 0, sizeof(encoded));
    ASNBER_TEST_CHECK(asnber_cms_builder_create(ctx, &builder) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_builder_set_version(builder, 1) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_builder_add_digest_algorithm(
                        builder, kSha256Oid, NULL, 0) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_builder_set_econtent_type(builder, kDataOid) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_builder_add_signer(
                        builder, 1, ASNBER_CMS_SID_ISSUER_AND_SERIAL, kIssuer,
                        sizeof(kIssuer), kSerial, sizeof(kSerial), kSha256Oid,
                        NULL, 0, NULL, 0, kRsaEncryptionOid, kNullParams,
                        sizeof(kNullParams), kSignature, sizeof(kSignature),
                        NULL, 0) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_builder_encode(builder, &encoded) == ASNBER_OK);

    asnber_cms_content_info_t *info = NULL;
    asnber_cms_signed_data_t *signed_data = NULL;
    ASNBER_TEST_CHECK(asnber_cms_content_info_open(ctx, encoded.data, encoded.size,
                                               &info) == ASNBER_OK);
    {
        const uint8_t *content = NULL;
        size_t content_size = 0;
        ASNBER_TEST_CHECK(asnber_cms_content_info_content(info, &content,
                                                      &content_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_open(ctx, content, content_size,
                                                  &signed_data) == ASNBER_OK);
    }
    {
        const uint8_t *octets = NULL;
        size_t octets_size = 0;
        ASNBER_TEST_CHECK(asnber_cms_signed_data_encap_content(
                            signed_data, &octets, &octets_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(octets == NULL && octets_size == 0);
    }
    asnber_cms_signed_data_close(signed_data);
    asnber_cms_content_info_close(info);
    asnber_buf_release(ctx, &encoded);
    asnber_cms_builder_destroy(builder);
    return 0;
}

/* 多证书：逆序追加，输出按 DER SET OF 排序。 */
static int build_multicert(asnber_ctx_t *ctx)
{
    asnber_cms_content_info_t *source_info = NULL;
    asnber_cms_signed_data_t *source_signed = NULL;
    const uint8_t *cert0 = NULL;
    const uint8_t *cert1 = NULL;
    size_t cert0_size = 0;
    size_t cert1_size = 0;

    ASNBER_TEST_CHECK(asnber_cms_content_info_open(ctx, kCmsRsaEcMulticert,
                                               kCmsRsaEcMulticertSize,
                                               &source_info) == ASNBER_OK);
    {
        const uint8_t *content = NULL;
        size_t content_size = 0;
        ASNBER_TEST_CHECK(asnber_cms_content_info_content(source_info, &content,
                                                      &content_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_open(ctx, content, content_size,
                                                  &source_signed) == ASNBER_OK);
    }
    {
        int choice = -1;
        ASNBER_TEST_CHECK(asnber_cms_signed_data_certificate_at(
                            source_signed, 0, &choice, &cert0, &cert0_size) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_certificate_at(
                            source_signed, 1, &choice, &cert1, &cert1_size) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(choice == ASNBER_CMS_CERT_CHOICE_CERTIFICATE);
    }

    asnber_cms_builder_t *builder = NULL;
    asnber_buf_t encoded;
    memset(&encoded, 0, sizeof(encoded));
    ASNBER_TEST_CHECK(asnber_cms_builder_create(ctx, &builder) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_builder_set_version(builder, 1) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_builder_add_digest_algorithm(
                        builder, kSha256Oid, NULL, 0) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_builder_set_econtent_type(builder, kDataOid) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_builder_add_certificate(builder, cert1,
                                                     cert1_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_builder_add_certificate(builder, cert0,
                                                     cert0_size) == ASNBER_OK);
    {
        static const uint8_t kIssuer[2] = {0x30, 0x00};
        static const uint8_t kSerial[3] = {0x02, 0x01, 0x01};
        static const uint8_t kSignature[2] = {0xCC, 0xDD};
        ASNBER_TEST_CHECK(asnber_cms_builder_add_signer(
                            builder, 1, ASNBER_CMS_SID_ISSUER_AND_SERIAL, kIssuer,
                            sizeof(kIssuer), kSerial, sizeof(kSerial),
                            kSha256Oid, NULL, 0, NULL, 0, kRsaEncryptionOid,
                            kNullParams, sizeof(kNullParams), kSignature,
                            sizeof(kSignature), NULL, 0) == ASNBER_OK);
    }
    ASNBER_TEST_CHECK(asnber_cms_builder_encode(builder, &encoded) == ASNBER_OK);

    asnber_cms_content_info_t *info = NULL;
    asnber_cms_signed_data_t *signed_data = NULL;
    ASNBER_TEST_CHECK(asnber_cms_content_info_open(ctx, encoded.data, encoded.size,
                                               &info) == ASNBER_OK);
    {
        const uint8_t *content = NULL;
        size_t content_size = 0;
        const uint8_t *actual = NULL;
        size_t actual_size = 0;
        int choice = -1;
        ASNBER_TEST_CHECK(asnber_cms_content_info_content(info, &content,
                                                      &content_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_open(ctx, content, content_size,
                                                  &signed_data) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_certificate_at(
                            signed_data, 0, &choice, &actual, &actual_size) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(actual, actual_size, cert0, cert0_size));
        ASNBER_TEST_CHECK(asnber_cms_signed_data_certificate_at(
                            signed_data, 1, &choice, &actual, &actual_size) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(actual, actual_size, cert1, cert1_size));
    }
    asnber_cms_signed_data_close(signed_data);
    asnber_cms_content_info_close(info);
    asnber_buf_release(ctx, &encoded);
    asnber_cms_builder_destroy(builder);
    asnber_cms_signed_data_close(source_signed);
    asnber_cms_content_info_close(source_info);
    return 0;
}

/* subjectKeyIdentifier 形式 sid + signedAttrs 原样承载。 */
static int build_keyid_with_attrs(asnber_ctx_t *ctx)
{
    static const uint8_t kSki[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    static const uint8_t kSignature[2] = {0x11, 0x22};
    /* Attribute ::= SEQUENCE { attrType contentType OID,
       attrValues SET OF OID data }。 */
    static const uint8_t kSignedAttrs[28] = {
        0x31, 0x1A, 0x30, 0x18, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
        0xF7, 0x0D, 0x01, 0x09, 0x03, 0x31, 0x0B, 0x06, 0x09, 0x2A,
        0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01};

    asnber_cms_builder_t *builder = NULL;
    asnber_buf_t encoded;
    memset(&encoded, 0, sizeof(encoded));
    ASNBER_TEST_CHECK(asnber_cms_builder_create(ctx, &builder) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_builder_set_version(builder, 3) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_builder_add_digest_algorithm(
                        builder, kSha256Oid, NULL, 0) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_builder_set_econtent_type(builder, kDataOid) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_builder_add_signer(
                        builder, 1, ASNBER_CMS_SID_SUBJECT_KEY_IDENTIFIER, kSki,
                        sizeof(kSki), NULL, 0, kSha256Oid, NULL, 0,
                        kSignedAttrs, sizeof(kSignedAttrs), kRsaEncryptionOid,
                        kNullParams, sizeof(kNullParams), kSignature,
                        sizeof(kSignature), kSignedAttrs,
                        sizeof(kSignedAttrs)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_builder_encode(builder, &encoded) == ASNBER_OK);

    asnber_cms_content_info_t *info = NULL;
    asnber_cms_signed_data_t *signed_data = NULL;
    ASNBER_TEST_CHECK(asnber_cms_content_info_open(ctx, encoded.data, encoded.size,
                                               &info) == ASNBER_OK);
    {
        const uint8_t *content = NULL;
        size_t content_size = 0;
        int sid_choice = -1;
        const uint8_t *ski = NULL;
        size_t ski_size = 0;
        const uint8_t *attrs = NULL;
        size_t attrs_size = 0;
        int64_t version = -1;
        ASNBER_TEST_CHECK(asnber_cms_content_info_content(info, &content,
                                                      &content_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_open(ctx, content, content_size,
                                                  &signed_data) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_version(signed_data, &version) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(version == 3);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_sid_choice(
                            signed_data, 0, &sid_choice) == ASNBER_OK);
        ASNBER_TEST_CHECK(sid_choice == ASNBER_CMS_SID_SUBJECT_KEY_IDENTIFIER);
        ASNBER_TEST_CHECK(
            asnber_cms_signed_data_signer_sid_subject_key_identifier(
                signed_data, 0, &ski, &ski_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(ski, ski_size, kSki, sizeof(kSki)));
        ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_signed_attrs(
                            signed_data, 0, &attrs, &attrs_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(attrs != NULL && attrs_size == sizeof(kSignedAttrs));
        ASNBER_TEST_CHECK(attrs[0] == 0xA0);
        ASNBER_TEST_CHECK(memcmp(attrs + 1, kSignedAttrs + 1,
                               attrs_size - 1) == 0);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_unsigned_attrs(
                            signed_data, 0, &attrs, &attrs_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(attrs != NULL && attrs_size == sizeof(kSignedAttrs));
        ASNBER_TEST_CHECK(attrs[0] == 0xA1);
        ASNBER_TEST_CHECK(memcmp(attrs + 1, kSignedAttrs + 1,
                               attrs_size - 1) == 0);
    }
    asnber_cms_signed_data_close(signed_data);
    asnber_cms_content_info_close(info);
    asnber_buf_release(ctx, &encoded);
    asnber_cms_builder_destroy(builder);
    return 0;
}

/* v1/v2 AttributeCertificate 分支：certificate_at 保留 kind + 原始 TLV，
 * 结构化访问器返回 UNSUPPORTED。 */
static int build_attribute_cert_choice(asnber_ctx_t *ctx)
{
    static const uint8_t kSki[4] = {0x01, 0x02, 0x03, 0x04};
    static const uint8_t kSignature[2] = {0xAA, 0xBB};
    /* 本切片的 AttributeCertificateV1/V2 为不透明扩展 SEQUENCE：
     * [1]/[2] IMPLICIT，内容非空以同时验证原始 TLV 逐字节保留。 */
    static const uint8_t kV1AttrCert[5] = {0xA1, 0x03, 0x02, 0x01, 0x01};
    static const uint8_t kV2AttrCert[5] = {0xA2, 0x03, 0x02, 0x01, 0x02};

    asnber_cms_builder_t *builder = NULL;
    asnber_buf_t encoded;
    memset(&encoded, 0, sizeof(encoded));
    ASNBER_TEST_CHECK(asnber_cms_builder_create(ctx, &builder) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_builder_set_version(builder, 3) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_builder_add_digest_algorithm(
                        builder, kSha256Oid, NULL, 0) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_builder_set_econtent_type(builder, kDataOid) ==
                    ASNBER_OK);
    /* 逆序输入（先 [2] 后 [1]），输出必须按 DER SET OF 排成 [1]、[2]。 */
    ASNBER_TEST_CHECK(asnber_cms_builder_add_certificate(
                        builder, kV2AttrCert, sizeof(kV2AttrCert)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_builder_add_certificate(
                        builder, kV1AttrCert, sizeof(kV1AttrCert)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_builder_add_signer(
                        builder, 1, ASNBER_CMS_SID_SUBJECT_KEY_IDENTIFIER, kSki,
                        sizeof(kSki), NULL, 0, kSha256Oid, NULL, 0, NULL, 0,
                        kRsaEncryptionOid, kNullParams, sizeof(kNullParams),
                        kSignature, sizeof(kSignature), NULL, 0) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_builder_encode(builder, &encoded) == ASNBER_OK);

    {
        asnber_cms_content_info_t *info = NULL;
        asnber_cms_signed_data_t *signed_data = NULL;
        const uint8_t *content = NULL;
        size_t content_size = 0;
        const uint8_t *tlv = NULL;
        size_t tlv_size = 0;
        const uint8_t *bytes = NULL;
        size_t bytes_size = 0;
        const char *text = NULL;
        size_t text_size = 0;
        int choice = -1;
        size_t count = 0;

        ASNBER_TEST_CHECK(asnber_cms_content_info_open(ctx, encoded.data,
                                                   encoded.size, &info) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_content_info_content(info, &content,
                                                      &content_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_open(ctx, content, content_size,
                                                  &signed_data) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_certificate_count(
                            signed_data, &count) == ASNBER_OK);
        ASNBER_TEST_CHECK(count == 2);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_certificate_at(
                            signed_data, 0, &choice, &tlv, &tlv_size) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(choice == ASNBER_CMS_CERT_CHOICE_V1_ATTR_CERT);
        ASNBER_TEST_CHECK(
            bytes_equal(tlv, tlv_size, kV1AttrCert, sizeof(kV1AttrCert)));
        ASNBER_TEST_CHECK(asnber_cms_signed_data_certificate_at(
                            signed_data, 1, &choice, &tlv, &tlv_size) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(choice == ASNBER_CMS_CERT_CHOICE_V2_ATTR_CERT);
        ASNBER_TEST_CHECK(
            bytes_equal(tlv, tlv_size, kV2AttrCert, sizeof(kV2AttrCert)));
        ASNBER_TEST_CHECK(asnber_cms_signed_data_certificate_subject(
                            signed_data, 0, &bytes, &bytes_size) ==
                        ASNBER_E_UNSUPPORTED);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_certificate_subject(
                            signed_data, 1, &bytes, &bytes_size) ==
                        ASNBER_E_UNSUPPORTED);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_certificate_issuer(
                            signed_data, 0, &bytes, &bytes_size) ==
                        ASNBER_E_UNSUPPORTED);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_certificate_issuer(
                            signed_data, 1, &bytes, &bytes_size) ==
                        ASNBER_E_UNSUPPORTED);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_certificate_serial(
                            signed_data, 0, &text, &text_size) ==
                        ASNBER_E_UNSUPPORTED);
        ASNBER_TEST_CHECK(asnber_cms_signed_data_certificate_serial(
                            signed_data, 1, &text, &text_size) ==
                        ASNBER_E_UNSUPPORTED);

        asnber_cms_signed_data_close(signed_data);
        asnber_cms_content_info_close(info);
    }
    asnber_buf_release(ctx, &encoded);
    asnber_cms_builder_destroy(builder);
    return 0;
}

/* certificates-only：没有签名者，digestAlgorithms 也为空。 */
static int build_certificates_only(asnber_ctx_t *ctx)
{
    asnber_cms_builder_t *builder = NULL;
    asnber_buf_t encoded;
    asnber_cms_content_info_t *info = NULL;
    asnber_cms_signed_data_t *signed_data = NULL;
    const uint8_t *content = NULL;
    size_t content_size = 0;
    size_t count = 99;

    memset(&encoded, 0, sizeof(encoded));
    ASNBER_TEST_CHECK(asnber_cms_builder_create(ctx, &builder) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_builder_set_version(builder, 1) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_builder_set_econtent_type(builder, kDataOid) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_builder_add_certificate(
                        builder, kCertRsaSelfsigned, kCertRsaSelfsignedSize) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_builder_encode(builder, &encoded) == ASNBER_OK);

    ASNBER_TEST_CHECK(asnber_cms_content_info_open(ctx, encoded.data, encoded.size,
                                               &info) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_content_info_content(info, &content,
                                                  &content_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_signed_data_open(ctx, content, content_size,
                                              &signed_data) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_signed_data_signer_count(signed_data, &count) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(count == 0);
    ASNBER_TEST_CHECK(asnber_cms_signed_data_digest_algorithm_count(
                        signed_data, &count) == ASNBER_OK);
    ASNBER_TEST_CHECK(count == 0);
    ASNBER_TEST_CHECK(asnber_cms_signed_data_certificate_count(signed_data,
                                                           &count) == ASNBER_OK);
    ASNBER_TEST_CHECK(count == 1);

    asnber_cms_signed_data_close(signed_data);
    asnber_cms_content_info_close(info);
    asnber_buf_release(ctx, &encoded);
    asnber_cms_builder_destroy(builder);
    return 0;
}

/* 负例：必填缺失、重复设置、非法 OID / TLV / 属性集合。 */
static int builder_negative_cases(asnber_ctx_t *ctx)
{
    asnber_cms_builder_t *builder = NULL;
    asnber_buf_t encoded;
    memset(&encoded, 0, sizeof(encoded));
    ASNBER_TEST_CHECK(asnber_cms_builder_create(ctx, &builder) == ASNBER_OK);

    /* 必填缺失。 */
    ASNBER_TEST_CHECK(asnber_cms_builder_encode(builder, &encoded) ==
                    ASNBER_E_INVALID_STATE);

    ASNBER_TEST_CHECK(asnber_cms_builder_set_version(builder, 1) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_builder_set_version(builder, 2) ==
                    ASNBER_E_INVALID_STATE);
    ASNBER_TEST_CHECK(asnber_cms_builder_set_econtent_type(builder, kDataOid) ==
                    ASNBER_OK);
    /* 只有 version 与 eContentType，没有证书、CRL 或签名者。 */
    ASNBER_TEST_CHECK(asnber_cms_builder_encode(builder, &encoded) ==
                    ASNBER_E_INVALID_STATE);
    ASNBER_TEST_CHECK(asnber_cms_builder_set_econtent_type(builder, kDataOid) ==
                    ASNBER_E_INVALID_STATE);
    ASNBER_TEST_CHECK(asnber_cms_builder_add_digest_algorithm(
                        builder, "1.2.3.4.5.", NULL, 0) == ASNBER_E_INVALID_VALUE);
    ASNBER_TEST_CHECK(asnber_cms_builder_add_digest_algorithm(
                        builder, kSha256Oid, kNullParams, sizeof(kNullParams)) ==
                    ASNBER_OK);

    {
        static const uint8_t kTruncated[3] = {0x30, 0x02, 0x02};
        static const uint8_t kTrailing[4] = {0x05, 0x00, 0xAA, 0xBB};
        static const uint8_t kNotOctets[2] = {0x05, 0x00};
        /* 两个 Attribute 逆序排列，违反 DER SET OF 排序规则。 */
        static const uint8_t kUnorderedSet[24] = {
            0x31, 0x16, 0x30, 0x09, 0x06, 0x02, 0x2A, 0x04, 0x31, 0x03,
            0x02, 0x01, 0x01, 0x30, 0x09, 0x06, 0x02, 0x2A, 0x03, 0x31,
            0x03, 0x02, 0x01, 0x01};

        ASNBER_TEST_CHECK(asnber_cms_builder_add_certificate(
                            builder, kTruncated, sizeof(kTruncated)) ==
                        ASNBER_E_TRUNCATED);
        ASNBER_TEST_CHECK(asnber_cms_builder_add_certificate(
                            builder, kTrailing, sizeof(kTrailing)) ==
                        ASNBER_E_TRAILING_DATA);
        ASNBER_TEST_CHECK(asnber_cms_builder_set_econtent(builder, kNotOctets,
                                                      sizeof(kNotOctets)) ==
                        ASNBER_E_INVALID_VALUE);
        ASNBER_TEST_CHECK(asnber_cms_builder_set_econtent(builder, kTruncated,
                                                      sizeof(kTruncated)) ==
                        ASNBER_E_TRUNCATED);
        /* 非法 sid_kind。 */
        ASNBER_TEST_CHECK(asnber_cms_builder_add_signer(
                            builder, 1, 7, kNotOctets, sizeof(kNotOctets), NULL,
                            0, kSha256Oid, NULL, 0, NULL, 0, kRsaEncryptionOid,
                            kNullParams, sizeof(kNullParams), kNotOctets,
                            sizeof(kNotOctets), NULL, 0) == ASNBER_E_INVALID_VALUE);
        /* subjectKeyIdentifier 形态不接受 sid2。 */
        ASNBER_TEST_CHECK(asnber_cms_builder_add_signer(
                            builder, 1, ASNBER_CMS_SID_SUBJECT_KEY_IDENTIFIER,
                            kNotOctets, sizeof(kNotOctets), kNotOctets,
                            sizeof(kNotOctets), kSha256Oid, NULL, 0, NULL, 0,
                            kRsaEncryptionOid, kNullParams,
                            sizeof(kNullParams), kNotOctets,
                            sizeof(kNotOctets), NULL, 0) == ASNBER_E_INVALID_ARG);
        /* signedAttrs 必须是 SET，非 SET 标签被拒。 */
        ASNBER_TEST_CHECK(asnber_cms_builder_add_signer(
                            builder, 1, ASNBER_CMS_SID_SUBJECT_KEY_IDENTIFIER,
                            kNotOctets, sizeof(kNotOctets), NULL, 0,
                            kSha256Oid, NULL, 0, kNotOctets, sizeof(kNotOctets),
                            kRsaEncryptionOid, kNullParams,
                            sizeof(kNullParams), kNotOctets,
                            sizeof(kNotOctets), NULL, 0) == ASNBER_E_INVALID_VALUE);
        /* 非规范（未排序）SET OF 被拒。 */
        ASNBER_TEST_CHECK(asnber_cms_builder_add_signer(
                            builder, 1, ASNBER_CMS_SID_SUBJECT_KEY_IDENTIFIER,
                            kNotOctets, sizeof(kNotOctets), NULL, 0,
                            kSha256Oid, NULL, 0, kUnorderedSet,
                            sizeof(kUnorderedSet), kRsaEncryptionOid,
                            kNullParams, sizeof(kNullParams), kNotOctets,
                            sizeof(kNotOctets), NULL, 0) ==
                        ASNBER_E_NON_CANONICAL);
    }

    {
        /* CertificateChoices / RevocationInfoChoice 根标签校验。 */
        static const uint8_t kName[2] = {0x30, 0x00};
        static const uint8_t kSerial[3] = {0x02, 0x01, 0x01};
        static const uint8_t kOctets[2] = {0x04, 0x00};
        static const uint8_t kCertAlt[4] = {0xA0, 0x02, 0x30, 0x00};
        static const uint8_t kCrlOther[4] = {0xA1, 0x02, 0x30, 0x00};
        static const uint8_t kEmptySet[2] = {0x31, 0x00};
        static const uint8_t kIntSet[5] = {0x31, 0x03, 0x02, 0x01, 0x01};
        static const uint8_t kAttributeSet[9] = {
            0x31, 0x07, 0x30, 0x05, 0x06, 0x03, 0x2A, 0x03, 0x04};

        ASNBER_TEST_CHECK(asnber_cms_builder_add_certificate(
                            builder, kOctets, sizeof(kOctets)) ==
                        ASNBER_E_INVALID_VALUE);
        ASNBER_TEST_CHECK(asnber_cms_builder_add_certificate(
                            builder, kCertAlt, sizeof(kCertAlt)) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_builder_add_crl(builder, kOctets,
                                                 sizeof(kOctets)) ==
                        ASNBER_E_INVALID_VALUE);
        ASNBER_TEST_CHECK(asnber_cms_builder_add_crl(builder, kCrlOther,
                                                 sizeof(kCrlOther)) == ASNBER_OK);

        /* issuer 必须是 SEQUENCE，serialNumber 必须是 INTEGER。 */
        ASNBER_TEST_CHECK(asnber_cms_builder_add_signer(
                            builder, 1, ASNBER_CMS_SID_ISSUER_AND_SERIAL, kOctets,
                            sizeof(kOctets), kSerial, sizeof(kSerial),
                            kSha256Oid, NULL, 0, NULL, 0, kRsaEncryptionOid,
                            kNullParams, sizeof(kNullParams), kOctets,
                            sizeof(kOctets), NULL, 0) == ASNBER_E_INVALID_VALUE);
        ASNBER_TEST_CHECK(asnber_cms_builder_add_signer(
                            builder, 1, ASNBER_CMS_SID_ISSUER_AND_SERIAL, kName,
                            sizeof(kName), kOctets, sizeof(kOctets), kSha256Oid,
                            NULL, 0, NULL, 0, kRsaEncryptionOid, kNullParams,
                            sizeof(kNullParams), kOctets, sizeof(kOctets), NULL,
                            0) == ASNBER_E_INVALID_VALUE);
        ASNBER_TEST_CHECK(asnber_cms_builder_add_signer(
                            builder, 1, ASNBER_CMS_SID_ISSUER_AND_SERIAL, kName,
                            sizeof(kName), kSerial, sizeof(kSerial), kSha256Oid,
                            NULL, 0, NULL, 0, kRsaEncryptionOid, kNullParams,
                            sizeof(kNullParams), kOctets, sizeof(kOctets), NULL,
                            0) == ASNBER_OK);

        /* signedAttrs / unsignedAttrs 必须是非空 SET OF Attribute。 */
        ASNBER_TEST_CHECK(asnber_cms_builder_add_signer(
                            builder, 1, ASNBER_CMS_SID_SUBJECT_KEY_IDENTIFIER,
                            kOctets, sizeof(kOctets), NULL, 0,
                            kSha256Oid, NULL, 0, kEmptySet, sizeof(kEmptySet),
                            kRsaEncryptionOid, kNullParams,
                            sizeof(kNullParams), kOctets, sizeof(kOctets), NULL,
                            0) == ASNBER_E_INVALID_VALUE);
        ASNBER_TEST_CHECK(asnber_cms_builder_add_signer(
                            builder, 1, ASNBER_CMS_SID_SUBJECT_KEY_IDENTIFIER,
                            kOctets, sizeof(kOctets), NULL, 0,
                            kSha256Oid, NULL, 0, kIntSet, sizeof(kIntSet),
                            kRsaEncryptionOid, kNullParams,
                            sizeof(kNullParams), kOctets, sizeof(kOctets), NULL,
                            0) == ASNBER_E_INVALID_VALUE);
        ASNBER_TEST_CHECK(asnber_cms_builder_add_signer(
                            builder, 1, ASNBER_CMS_SID_SUBJECT_KEY_IDENTIFIER,
                            kOctets, sizeof(kOctets), NULL, 0,
                            kSha256Oid, NULL, 0, kAttributeSet,
                            sizeof(kAttributeSet), kRsaEncryptionOid,
                            kNullParams, sizeof(kNullParams), kOctets,
                            sizeof(kOctets), kEmptySet,
                            sizeof(kEmptySet)) == ASNBER_E_INVALID_VALUE);
        ASNBER_TEST_CHECK(asnber_cms_builder_add_signer(
                            builder, 1, ASNBER_CMS_SID_SUBJECT_KEY_IDENTIFIER,
                            kOctets, sizeof(kOctets), NULL, 0,
                            kSha256Oid, NULL, 0, kAttributeSet,
                            sizeof(kAttributeSet), kRsaEncryptionOid,
                            kNullParams, sizeof(kNullParams), kOctets,
                            sizeof(kOctets), kAttributeSet,
                            sizeof(kAttributeSet)) == ASNBER_OK);
    }

    asnber_cms_builder_destroy(builder);
    asnber_cms_builder_destroy(NULL);
    return 0;
}

int main(void)
{
    asnber_ctx_t *ctx = make_ctx();
    ASNBER_TEST_CHECK(ctx != NULL);

    ASNBER_TEST_CHECK(roundtrip_all_samples(ctx) == 0);
    ASNBER_TEST_CHECK(build_attached_minimal(ctx) == 0);
    ASNBER_TEST_CHECK(build_detached(ctx) == 0);
    ASNBER_TEST_CHECK(build_multicert(ctx) == 0);
    ASNBER_TEST_CHECK(build_keyid_with_attrs(ctx) == 0);
    ASNBER_TEST_CHECK(build_attribute_cert_choice(ctx) == 0);
    ASNBER_TEST_CHECK(build_certificates_only(ctx) == 0);
    ASNBER_TEST_CHECK(builder_negative_cases(ctx) == 0);

    asnber_ctx_destroy(ctx);
    return 0;
}
