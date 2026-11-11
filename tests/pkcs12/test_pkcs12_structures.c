/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * asnber-pkcs12 PKCS#12 只读结构访问。
 * 覆盖明文/加密 PFX、AuthenticatedSafe、SafeContents/SafeBag 属性、
 * CertBag 的 X.509 与 SDSI 分支、MacData（含 iterations DEFAULT）与负例。
 */

#include <asnber/asnber.h>
#include <asnber/pkcs12/pkcs12.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "../data/cert_rsa_selfsigned.h"
#include "../data/pfx_certs_only.h"
#include "../data/pfx_rsa_encrypted.h"
#include "../data/pfx_rsa_unencrypted.h"
#include "check.h"
#include "test_compare.h"

#define kDataOid "1.2.840.113549.1.7.1"
#define kEncryptedDataOid "1.2.840.113549.1.7.6"
#define kCertBagOid "1.2.840.113549.1.12.10.1.3"
#define kKeyBagOid "1.2.840.113549.1.12.10.1.1"
#define kShroudedKeyBagOid "1.2.840.113549.1.12.10.1.2"
#define kX509CertificateOid "1.2.840.113549.1.9.22.1"
#define kFriendlyNameOid "1.2.840.113549.1.9.20"
#define kLocalKeyIdOid "1.2.840.113549.1.9.21"

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

static int tlv_starts_with(const uint8_t *tlv, size_t size, uint8_t tag)
{
    return tlv != NULL && size > 0 && tlv[0] == tag;
}

/* 把完整 OCTET STRING TLV 解成节点并取出内容字节；文档需由调用方销毁。 */
static int octets_of(asnber_ctx_t *ctx, const uint8_t *tlv, size_t tlv_size,
                     asnber_doc_t **out_doc, const uint8_t **out_data,
                     size_t *out_size)
{
    asnber_decode_options_t options;
    asnber_decode_options_init(&options);
    size_t consumed = 0;
    if (asnber_decode_buffer(ctx, tlv, tlv_size, &options, out_doc,
                           &consumed) != ASNBER_OK) {
        return 1;
    }
    if (consumed != tlv_size) {
        return 1;
    }
    return asnber_node_get_octets(asnber_doc_root(*out_doc), out_data,
                                out_size) == ASNBER_OK
               ? 0
               : 1;
}

/* 在 bag 的属性中按 OID 查找下标；找不到返回 (size_t)-1。 */
static size_t attribute_index(const asnber_pkcs12_safe_contents_t *contents,
                              size_t bag_index, size_t count,
                              const char *oid)
{
    for (size_t i = 0; i < count; ++i) {
        const char *dotted = NULL;
        size_t dotted_size = 0;
        const asnber_node_t *values = NULL;
        if (asnber_pkcs12_safe_contents_bag_attribute_at(
                contents, bag_index, i, &dotted, &dotted_size,
                &values) != ASNBER_OK) {
            return (size_t)-1;
        }
        if (text_equals(dotted, dotted_size, oid)) {
            return i;
        }
    }
    return (size_t)-1;
}

/* 短格式 TLV 追加（本文件构造的样本总长与各层长度均小于 128）。 */
static size_t append_tlv(uint8_t *out, uint8_t tag, const uint8_t *content,
                         size_t size)
{
    out[0] = tag;
    out[1] = (uint8_t)size;
    if (size != 0) {
        memcpy(out + 2, content, size);
    }
    return size + 2;
}

/* ---------- 明文 PFX：完整遍历到证书与私钥 ---------- */

static int test_pfx_unencrypted(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_pkcs12_pfx_t *pfx = NULL;

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_open(ctx, kPfxRsaUnencrypted,
                                         kPfxRsaUnencryptedSize,
                                         &pfx) == ASNBER_OK);
    ASNBER_TEST_CHECK(pfx != NULL);

    {
        int64_t version = -1;
        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_version(pfx, &version) == ASNBER_OK);
        ASNBER_TEST_CHECK(version == 3);
    }

    {
        const char *oid = NULL;
        size_t oid_size = 0;
        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_auth_safe_content_type(
                            pfx, &oid, &oid_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(text_equals(oid, oid_size, kDataOid));

        int present = -1;
        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_mac_present(pfx, &present) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(present == 0);
        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_mac_digest(pfx, NULL, NULL) ==
                        ASNBER_E_INVALID_ARG);
    }

    {
        /* 无 MAC：所有 macData 访问器按字段缺省报错。 */
        const char *oid = NULL;
        size_t oid_size = 0;
        const uint8_t *data = NULL;
        size_t size = 0;
        int64_t iterations = 0;
        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_mac_digest_algorithm_oid(
                            pfx, &oid, &oid_size) == ASNBER_E_SCHEMA_FIELD);
        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_mac_digest_algorithm_parameters(
                            pfx, &data, &size) == ASNBER_E_SCHEMA_FIELD);
        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_mac_digest(pfx, &data, &size) ==
                        ASNBER_E_SCHEMA_FIELD);
        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_mac_salt(pfx, &data, &size) ==
                        ASNBER_E_SCHEMA_FIELD);
        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_mac_iterations(pfx, &iterations) ==
                        ASNBER_E_SCHEMA_FIELD);
    }

    {
        const uint8_t *content = NULL;
        size_t content_size = 0;
        asnber_doc_t *content_doc = NULL;
        const uint8_t *auth_der = NULL;
        size_t auth_der_size = 0;
        asnber_pkcs12_authenticated_safe_t *safe = NULL;

        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_auth_safe_content_tlv(
                            pfx, &content, &content_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(tlv_starts_with(content, content_size, 0x04));
        ASNBER_TEST_CHECK(octets_of(ctx, content, content_size, &content_doc,
                                  &auth_der, &auth_der_size) == 0);
        ASNBER_TEST_CHECK(asnber_pkcs12_authenticated_safe_open(
                            ctx, auth_der, auth_der_size, &safe) == ASNBER_OK);
        ASNBER_TEST_CHECK(safe != NULL);

        {
            size_t count = 0;
            ASNBER_TEST_CHECK(
                asnber_pkcs12_authenticated_safe_content_count(safe, &count) ==
                ASNBER_OK);
            ASNBER_TEST_CHECK(count == 2);
        }

        /* 第 0 个 ContentInfo：data，内含证书 bag。 */
        {
            const char *oid = NULL;
            size_t oid_size = 0;
            const uint8_t *inner = NULL;
            size_t inner_size = 0;
            asnber_doc_t *inner_doc = NULL;
            const uint8_t *safe_der = NULL;
            size_t safe_der_size = 0;
            asnber_pkcs12_safe_contents_t *contents = NULL;

            ASNBER_TEST_CHECK(asnber_pkcs12_authenticated_safe_content_at(
                                safe, 0, &oid, &oid_size, &inner,
                                &inner_size) == ASNBER_OK);
            ASNBER_TEST_CHECK(text_equals(oid, oid_size, kDataOid));
            ASNBER_TEST_CHECK(tlv_starts_with(inner, inner_size, 0x04));
            ASNBER_TEST_CHECK(octets_of(ctx, inner, inner_size, &inner_doc,
                                      &safe_der, &safe_der_size) == 0);
            ASNBER_TEST_CHECK(asnber_pkcs12_safe_contents_open(
                                ctx, safe_der, safe_der_size,
                                &contents) == ASNBER_OK);

            {
                size_t bag_count = 0;
                const char *bag_id = NULL;
                size_t bag_id_size = 0;
                const uint8_t *value = NULL;
                size_t value_size = 0;
                size_t attributes = 0;

                ASNBER_TEST_CHECK(asnber_pkcs12_safe_contents_bag_count(
                                    contents, &bag_count) == ASNBER_OK);
                ASNBER_TEST_CHECK(bag_count == 1);
                ASNBER_TEST_CHECK(asnber_pkcs12_safe_contents_bag_at(
                                    contents, 0, &bag_id, &bag_id_size,
                                    &value, &value_size,
                                    &attributes) == ASNBER_OK);
                ASNBER_TEST_CHECK(text_equals(bag_id, bag_id_size,
                                            kCertBagOid));
                ASNBER_TEST_CHECK(tlv_starts_with(value, value_size, 0x30));
                ASNBER_TEST_CHECK(attributes == 2);

                {
                    size_t index = attribute_index(contents, 0, attributes,
                                                   kFriendlyNameOid);
                    const char *attr_id = NULL;
                    size_t attr_id_size = 0;
                    const asnber_node_t *values = NULL;
                    ASNBER_TEST_CHECK(index != (size_t)-1);
                    ASNBER_TEST_CHECK(
                        asnber_pkcs12_safe_contents_bag_attribute_at(
                            contents, 0, index, &attr_id, &attr_id_size,
                            &values) == ASNBER_OK);
                    ASNBER_TEST_CHECK(text_equals(attr_id, attr_id_size,
                                                kFriendlyNameOid));
                    ASNBER_TEST_CHECK(asnber_node_child_count(values) == 1);
                }
                {
                    size_t index = attribute_index(contents, 0, attributes,
                                                   kLocalKeyIdOid);
                    ASNBER_TEST_CHECK(index != (size_t)-1);
                }

                /* CertBag 内层证书与独立证书样本逐字节一致。 */
                {
                    asnber_pkcs12_cert_bag_t *bag = NULL;
                    const char *cert_id = NULL;
                    size_t cert_id_size = 0;
                    const uint8_t *cert_value = NULL;
                    size_t cert_value_size = 0;
                    const uint8_t *certificate = NULL;
                    size_t certificate_size = 0;

                    ASNBER_TEST_CHECK(asnber_pkcs12_cert_bag_open(
                                        ctx, value, value_size, &bag) ==
                                    ASNBER_OK);
                    ASNBER_TEST_CHECK(asnber_pkcs12_cert_bag_cert_id(
                                        bag, &cert_id, &cert_id_size) ==
                                    ASNBER_OK);
                    ASNBER_TEST_CHECK(text_equals(cert_id, cert_id_size,
                                                kX509CertificateOid));
                    ASNBER_TEST_CHECK(
                        asnber_pkcs12_cert_bag_cert_value_tlv(
                            bag, &cert_value, &cert_value_size) == ASNBER_OK);
                    ASNBER_TEST_CHECK(tlv_starts_with(cert_value,
                                                    cert_value_size, 0x04));
                    ASNBER_TEST_CHECK(asnber_pkcs12_cert_bag_certificate(
                                        bag, &certificate,
                                        &certificate_size) == ASNBER_OK);
                    ASNBER_TEST_CHECK(certificate_size == kCertRsaSelfsignedSize);
                    ASNBER_TEST_CHECK(memcmp(certificate, kCertRsaSelfsigned,
                                           certificate_size) == 0);
                    asnber_pkcs12_cert_bag_close(bag);
                }
            }

            asnber_pkcs12_safe_contents_close(contents);
            asnber_doc_destroy(inner_doc);
        }

        /* 第 1 个 ContentInfo：data，内含 keyBag（PKCS#8 PrivateKeyInfo）。 */
        {
            const char *oid = NULL;
            size_t oid_size = 0;
            const uint8_t *inner = NULL;
            size_t inner_size = 0;
            asnber_doc_t *inner_doc = NULL;
            const uint8_t *safe_der = NULL;
            size_t safe_der_size = 0;
            asnber_pkcs12_safe_contents_t *contents = NULL;

            ASNBER_TEST_CHECK(asnber_pkcs12_authenticated_safe_content_at(
                                safe, 1, &oid, &oid_size, &inner,
                                &inner_size) == ASNBER_OK);
            ASNBER_TEST_CHECK(text_equals(oid, oid_size, kDataOid));
            ASNBER_TEST_CHECK(octets_of(ctx, inner, inner_size, &inner_doc,
                                      &safe_der, &safe_der_size) == 0);
            ASNBER_TEST_CHECK(asnber_pkcs12_safe_contents_open(
                                ctx, safe_der, safe_der_size,
                                &contents) == ASNBER_OK);

            {
                size_t bag_count = 0;
                const char *bag_id = NULL;
                size_t bag_id_size = 0;
                const uint8_t *value = NULL;
                size_t value_size = 0;
                size_t attributes = 0;

                ASNBER_TEST_CHECK(asnber_pkcs12_safe_contents_bag_count(
                                    contents, &bag_count) == ASNBER_OK);
                ASNBER_TEST_CHECK(bag_count == 1);
                ASNBER_TEST_CHECK(asnber_pkcs12_safe_contents_bag_at(
                                    contents, 0, &bag_id, &bag_id_size,
                                    &value, &value_size,
                                    &attributes) == ASNBER_OK);
                ASNBER_TEST_CHECK(text_equals(bag_id, bag_id_size,
                                            kKeyBagOid));
                /* keyBag 的 bagValue 是 PrivateKeyInfo 的原始 SEQUENCE TLV。 */
                ASNBER_TEST_CHECK(value_size > 0 && value[0] == 0x30);
            }

            asnber_pkcs12_safe_contents_close(contents);
            asnber_doc_destroy(inner_doc);
        }

        asnber_pkcs12_authenticated_safe_close(safe);
        asnber_doc_destroy(content_doc);
    }

    asnber_pkcs12_pfx_close(pfx);
    asnber_ctx_destroy(ctx);
    return 0;
}

/* ---------- 加密 PFX：只读结构与 MacData ---------- */

static int test_pfx_encrypted(void)
{
    static const uint8_t null_parameters[] = {0x05, 0x00};
    asnber_ctx_t *ctx = make_ctx();
    asnber_pkcs12_pfx_t *pfx = NULL;

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_open(ctx, kPfxRsaEncrypted,
                                         kPfxRsaEncryptedSize,
                                         &pfx) == ASNBER_OK);
    ASNBER_TEST_CHECK(pfx != NULL);

    {
        int64_t version = -1;
        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_version(pfx, &version) == ASNBER_OK);
        ASNBER_TEST_CHECK(version == 3);
    }

    {
        int present = -1;
        const char *oid = NULL;
        size_t oid_size = 0;
        const uint8_t *parameters = NULL;
        size_t parameters_size = 0;
        const uint8_t *digest = NULL;
        size_t digest_size = 0;
        const uint8_t *salt = NULL;
        size_t salt_size = 0;
        int64_t iterations = -1;

        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_mac_present(pfx, &present) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(present == 1);
        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_mac_digest_algorithm_oid(
                            pfx, &oid, &oid_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(text_equals(oid, oid_size, "2.16.840.1.101.3.4.2.1"));
        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_mac_digest_algorithm_parameters(
                            pfx, &parameters, &parameters_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(parameters_size == sizeof(null_parameters));
        ASNBER_TEST_CHECK(memcmp(parameters, null_parameters,
                               parameters_size) == 0);
        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_mac_digest(pfx, &digest,
                                                   &digest_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(digest_size == 32);
        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_mac_salt(pfx, &salt, &salt_size) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(salt_size == 8);
        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_mac_iterations(
                            pfx, &iterations) == ASNBER_OK);
        ASNBER_TEST_CHECK(iterations == 2048);
    }

    {
        const uint8_t *content = NULL;
        size_t content_size = 0;
        asnber_doc_t *content_doc = NULL;
        const uint8_t *auth_der = NULL;
        size_t auth_der_size = 0;
        asnber_pkcs12_authenticated_safe_t *safe = NULL;
        size_t count = 0;

        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_auth_safe_content_tlv(
                            pfx, &content, &content_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(octets_of(ctx, content, content_size, &content_doc,
                                  &auth_der, &auth_der_size) == 0);
        ASNBER_TEST_CHECK(asnber_pkcs12_authenticated_safe_open(
                            ctx, auth_der, auth_der_size, &safe) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_pkcs12_authenticated_safe_content_count(
                            safe, &count) == ASNBER_OK);
        ASNBER_TEST_CHECK(count == 2);

        /* 第 0 个：EncryptedData，内容不解密。 */
        {
            const char *oid = NULL;
            size_t oid_size = 0;
            const uint8_t *inner = NULL;
            size_t inner_size = 0;
            ASNBER_TEST_CHECK(asnber_pkcs12_authenticated_safe_content_at(
                                safe, 0, &oid, &oid_size, &inner,
                                &inner_size) == ASNBER_OK);
            ASNBER_TEST_CHECK(text_equals(oid, oid_size, kEncryptedDataOid));
            ASNBER_TEST_CHECK(tlv_starts_with(inner, inner_size, 0x30));
        }

        /* 第 1 个：data，SafeContents 里是 pkcs8ShroudedKeyBag。 */
        {
            const char *oid = NULL;
            size_t oid_size = 0;
            const uint8_t *inner = NULL;
            size_t inner_size = 0;
            asnber_doc_t *inner_doc = NULL;
            const uint8_t *safe_der = NULL;
            size_t safe_der_size = 0;
            asnber_pkcs12_safe_contents_t *contents = NULL;
            const char *bag_id = NULL;
            size_t bag_id_size = 0;
            const uint8_t *value = NULL;
            size_t value_size = 0;
            size_t attributes = 0;

            ASNBER_TEST_CHECK(asnber_pkcs12_authenticated_safe_content_at(
                                safe, 1, &oid, &oid_size, &inner,
                                &inner_size) == ASNBER_OK);
            ASNBER_TEST_CHECK(text_equals(oid, oid_size, kDataOid));
            ASNBER_TEST_CHECK(octets_of(ctx, inner, inner_size, &inner_doc,
                                      &safe_der, &safe_der_size) == 0);
            ASNBER_TEST_CHECK(asnber_pkcs12_safe_contents_open(
                                ctx, safe_der, safe_der_size,
                                &contents) == ASNBER_OK);
            ASNBER_TEST_CHECK(asnber_pkcs12_safe_contents_bag_at(
                                contents, 0, &bag_id, &bag_id_size, &value,
                                &value_size, &attributes) == ASNBER_OK);
            ASNBER_TEST_CHECK(text_equals(bag_id, bag_id_size,
                                        kShroudedKeyBagOid));
            /*
             * bagValue 按原始 TLV 暴露：EncryptedPrivateKeyInfo 是 SEQUENCE。
             * 内层 PKCS#8 语义由调用方交给 asnber-pkcs8 解析，本模块不建立
             * 对 asnber-pkcs8 的依赖。
             */
            ASNBER_TEST_CHECK(value_size > 0 && value[0] == 0x30);
            asnber_pkcs12_safe_contents_close(contents);
            asnber_doc_destroy(inner_doc);
        }

        asnber_pkcs12_authenticated_safe_close(safe);
        asnber_doc_destroy(content_doc);
    }

    asnber_pkcs12_pfx_close(pfx);
    asnber_ctx_destroy(ctx);
    return 0;
}

/* ---------- 仅证书 PFX ---------- */

static int test_pfx_certs_only(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_pkcs12_pfx_t *pfx = NULL;

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_open(ctx, kPfxCertsOnly,
                                         kPfxCertsOnlySize,
                                         &pfx) == ASNBER_OK);

    {
        const uint8_t *content = NULL;
        size_t content_size = 0;
        asnber_doc_t *content_doc = NULL;
        const uint8_t *auth_der = NULL;
        size_t auth_der_size = 0;
        asnber_pkcs12_authenticated_safe_t *safe = NULL;
        size_t count = 0;

        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_auth_safe_content_tlv(
                            pfx, &content, &content_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(octets_of(ctx, content, content_size, &content_doc,
                                  &auth_der, &auth_der_size) == 0);
        ASNBER_TEST_CHECK(asnber_pkcs12_authenticated_safe_open(
                            ctx, auth_der, auth_der_size, &safe) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_pkcs12_authenticated_safe_content_count(
                            safe, &count) == ASNBER_OK);
        ASNBER_TEST_CHECK(count == 1);

        {
            const char *oid = NULL;
            size_t oid_size = 0;
            const uint8_t *inner = NULL;
            size_t inner_size = 0;
            ASNBER_TEST_CHECK(asnber_pkcs12_authenticated_safe_content_at(
                                safe, 0, &oid, &oid_size, &inner,
                                &inner_size) == ASNBER_OK);
            ASNBER_TEST_CHECK(text_equals(oid, oid_size, kEncryptedDataOid));
        }

        asnber_pkcs12_authenticated_safe_close(safe);
        asnber_doc_destroy(content_doc);
    }

    asnber_pkcs12_pfx_close(pfx);
    asnber_ctx_destroy(ctx);
    return 0;
}

/* ---------- version 原样返回与 MacData iterations DEFAULT ---------- */

static int test_version_and_default_iterations(void)
{
    /* 手写最小 PFX：version 3、空 AuthenticatedSafe、macData 省略 iterations。 */
    static const uint8_t version_three[] = {0x02, 0x01, 0x03};
    static const uint8_t digest_algorithm[] = {0x30, 0x0D, 0x06, 0x09, 0x60,
                                               0x86, 0x48, 0x01, 0x65, 0x03,
                                               0x04, 0x02, 0x01, 0x05, 0x00};
    static const uint8_t data_oid_tlv[] = {0x06, 0x09, 0x2A, 0x86, 0x48,
                                           0x86, 0xF7, 0x0D, 0x01, 0x07,
                                           0x01};
    static const uint8_t empty_authenticated_safe[] = {0x30, 0x00};
    static const uint8_t digest_value[32] = {0};
    static const uint8_t salt_value[8] = {0};
    uint8_t digest_info_content[64];
    uint8_t digest_info[64];
    uint8_t octet_string[16];
    uint8_t content_wrapper[24];
    uint8_t content_info_content[40];
    uint8_t content_info[40];
    uint8_t mac_data_content[80];
    uint8_t mac_data[80];
    uint8_t pfx_content[128];
    uint8_t pfx_der[128];
    size_t digest_info_content_size = 0;
    size_t digest_info_size = 0;
    size_t octet_string_size = 0;
    size_t wrapper_size = 0;
    size_t content_info_content_size = 0;
    size_t content_info_size = 0;
    size_t mac_data_content_size = 0;
    size_t mac_data_size = 0;
    size_t pfx_content_size = 0;
    size_t pfx_size = 0;

    asnber_ctx_t *ctx = make_ctx();
    asnber_pkcs12_pfx_t *pfx = NULL;

    ASNBER_TEST_CHECK(ctx != NULL);

    memcpy(digest_info_content, digest_algorithm, sizeof(digest_algorithm));
    digest_info_content_size = sizeof(digest_algorithm);
    digest_info_content_size += append_tlv(
        digest_info_content + digest_info_content_size, 0x04, digest_value,
        sizeof(digest_value));
    digest_info_size = append_tlv(digest_info, 0x30, digest_info_content,
                                  digest_info_content_size);

    octet_string_size = append_tlv(octet_string, 0x04,
                                   empty_authenticated_safe,
                                   sizeof(empty_authenticated_safe));
    wrapper_size = append_tlv(content_wrapper, 0xA0, octet_string,
                              octet_string_size);

    memcpy(content_info_content, data_oid_tlv, sizeof(data_oid_tlv));
    content_info_content_size = sizeof(data_oid_tlv);
    memcpy(content_info_content + content_info_content_size,
           content_wrapper, wrapper_size);
    content_info_content_size += wrapper_size;
    content_info_size = append_tlv(content_info, 0x30,
                                   content_info_content,
                                   content_info_content_size);

    memcpy(mac_data_content, digest_info, digest_info_size);
    mac_data_content_size = digest_info_size;
    mac_data_content_size += append_tlv(mac_data_content +
                                            mac_data_content_size,
                                        0x04, salt_value,
                                        sizeof(salt_value));
    mac_data_size = append_tlv(mac_data, 0x30, mac_data_content,
                               mac_data_content_size);

    memcpy(pfx_content, version_three, sizeof(version_three));
    pfx_content_size = sizeof(version_three);
    memcpy(pfx_content + pfx_content_size, content_info, content_info_size);
    pfx_content_size += content_info_size;
    memcpy(pfx_content + pfx_content_size, mac_data, mac_data_size);
    pfx_content_size += mac_data_size;
    pfx_size = append_tlv(pfx_der, 0x30, pfx_content, pfx_content_size);

    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_open(ctx, pfx_der, pfx_size, &pfx) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(pfx != NULL);

    {
        int64_t version = -1;
        int present = 0;
        int64_t iterations = -1;
        const uint8_t *digest = NULL;
        size_t digest_size = 0;
        const uint8_t *salt = NULL;
        size_t salt_size = 0;
        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_version(pfx, &version) == ASNBER_OK);
        ASNBER_TEST_CHECK(version == 3);
        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_mac_present(pfx, &present) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(present == 1);
        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_mac_iterations(pfx, &iterations) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(iterations == 1);
        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_mac_digest(pfx, &digest,
                                                   &digest_size) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(digest_size == sizeof(digest_value));
        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_mac_salt(pfx, &salt, &salt_size) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(salt_size == sizeof(salt_value));
    }

    {
        /* authSafe 的 OCTET STRING 内容就是空 AuthenticatedSafe。 */
        const uint8_t *content = NULL;
        size_t content_size = 0;
        asnber_doc_t *doc = NULL;
        const uint8_t *auth_der = NULL;
        size_t auth_der_size = 0;
        asnber_pkcs12_authenticated_safe_t *safe = NULL;
        size_t count = 1;

        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_auth_safe_content_tlv(
                            pfx, &content, &content_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(octets_of(ctx, content, content_size, &doc,
                                  &auth_der, &auth_der_size) == 0);
        ASNBER_TEST_CHECK(auth_der_size == sizeof(empty_authenticated_safe));
        ASNBER_TEST_CHECK(memcmp(auth_der, empty_authenticated_safe,
                               auth_der_size) == 0);
        ASNBER_TEST_CHECK(asnber_pkcs12_authenticated_safe_open(
                            ctx, auth_der, auth_der_size, &safe) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_pkcs12_authenticated_safe_content_count(
                            safe, &count) == ASNBER_OK);
        ASNBER_TEST_CHECK(count == 0);
        asnber_pkcs12_authenticated_safe_close(safe);
        asnber_doc_destroy(doc);
    }

    asnber_pkcs12_pfx_close(pfx);

    /* 非 3 的 version：原样返回，不做范围校验。 */
    {
        uint8_t *patched = (uint8_t *)malloc(kPfxRsaUnencryptedSize);
        ASNBER_TEST_CHECK(patched != NULL);
        memcpy(patched, kPfxRsaUnencrypted, kPfxRsaUnencryptedSize);
        ASNBER_TEST_CHECK(patched[4] == 0x02 && patched[5] == 0x01);
        patched[6] = 0x02;
        pfx = NULL;
        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_open(
                            ctx, patched, kPfxRsaUnencryptedSize,
                            &pfx) == ASNBER_OK);
        {
            int64_t version = -1;
            ASNBER_TEST_CHECK(asnber_pkcs12_pfx_version(pfx, &version) ==
                            ASNBER_OK);
            ASNBER_TEST_CHECK(version == 2);
        }
        asnber_pkcs12_pfx_close(pfx);
        free(patched);
    }

    asnber_ctx_destroy(ctx);
    return 0;
}

/* ---------- CertBag 的 SDSI 分支 ---------- */

static int test_cert_bag_sdsi(void)
{
    /* CertBag { certId sdsiCertificate, certValue [0] { IA5String } } */
    static const uint8_t sdsi_cert_bag[] = {
        0x30, 0x14, 0x06, 0x0A, 0x2A, 0x86, 0x48, 0x86,
        0xF7, 0x0D, 0x01, 0x09, 0x16, 0x02, 0xA0, 0x06,
        0x16, 0x04, 0x74, 0x65, 0x73, 0x74,
    };
    asnber_ctx_t *ctx = make_ctx();
    asnber_pkcs12_cert_bag_t *bag = NULL;

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(asnber_pkcs12_cert_bag_open(ctx, sdsi_cert_bag,
                                              sizeof(sdsi_cert_bag),
                                              &bag) == ASNBER_OK);

    {
        const char *oid = NULL;
        size_t oid_size = 0;
        const uint8_t *value = NULL;
        size_t value_size = 0;
        const uint8_t *certificate = NULL;
        size_t certificate_size = 0;

        ASNBER_TEST_CHECK(asnber_pkcs12_cert_bag_cert_id(bag, &oid, &oid_size) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(text_equals(oid, oid_size,
                                    "1.2.840.113549.1.9.22.2"));
        ASNBER_TEST_CHECK(asnber_pkcs12_cert_bag_cert_value_tlv(
                            bag, &value, &value_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(tlv_starts_with(value, value_size, 0x16));
        /* 非 X.509 分支：结构化证书访问返回 UNSUPPORTED。 */
        ASNBER_TEST_CHECK(certificate == NULL);
        ASNBER_TEST_CHECK(asnber_pkcs12_cert_bag_certificate(
                            bag, &certificate, &certificate_size) ==
                        ASNBER_E_UNSUPPORTED);
        ASNBER_TEST_CHECK(certificate == NULL && certificate_size == 0);
    }

    asnber_pkcs12_cert_bag_close(bag);
    asnber_ctx_destroy(ctx);
    return 0;
}

/* ---------- 负例：空参、错误结构、越界 ---------- */

static int test_negative(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_pkcs12_pfx_t *pfx = NULL;
    asnber_pkcs12_authenticated_safe_t *safe = NULL;
    asnber_pkcs12_safe_contents_t *contents = NULL;
    asnber_pkcs12_cert_bag_t *bag = NULL;
    uint8_t *trailing = NULL;

    ASNBER_TEST_CHECK(ctx != NULL);

    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_open(NULL, kPfxRsaUnencrypted,
                                         kPfxRsaUnencryptedSize,
                                         &pfx) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_open(ctx, NULL, 1, &pfx) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_open(ctx, kPfxRsaUnencrypted, 0, &pfx) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_open(ctx, kPfxRsaUnencrypted,
                                         kPfxRsaUnencryptedSize,
                                         NULL) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_version(NULL, NULL) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_mac_present(NULL, NULL) ==
                    ASNBER_E_INVALID_ARG);
    asnber_pkcs12_pfx_close(NULL);
    asnber_pkcs12_authenticated_safe_close(NULL);
    asnber_pkcs12_safe_contents_close(NULL);
    asnber_pkcs12_cert_bag_close(NULL);

    /* 非 PFX 输入。 */
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_open(ctx, kCertRsaSelfsigned,
                                         kCertRsaSelfsignedSize,
                                         &pfx) != ASNBER_OK);
    ASNBER_TEST_CHECK(pfx == NULL);

    /* 截断与尾随字节。 */
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_open(
                        ctx, kPfxRsaUnencrypted,
                        kPfxRsaUnencryptedSize - 8, &pfx) != ASNBER_OK);
    trailing = (uint8_t *)malloc(kPfxRsaUnencryptedSize + 1);
    ASNBER_TEST_CHECK(trailing != NULL);
    memcpy(trailing, kPfxRsaUnencrypted, kPfxRsaUnencryptedSize);
    trailing[kPfxRsaUnencryptedSize] = 0x00;
    ASNBER_TEST_CHECK(asnber_pkcs12_pfx_open(
                        ctx, trailing, kPfxRsaUnencryptedSize + 1,
                        &pfx) != ASNBER_OK);
    ASNBER_TEST_CHECK(pfx == NULL);
    free(trailing);

    /* AuthenticatedSafe 不接受 PFX 根结构。 */
    ASNBER_TEST_CHECK(asnber_pkcs12_authenticated_safe_open(
                        ctx, kPfxRsaUnencrypted, kPfxRsaUnencryptedSize,
                        &safe) != ASNBER_OK);
    ASNBER_TEST_CHECK(safe == NULL);

    /* 打开明文 PFX 取 AuthenticatedSafe，再测下标越界。 */
    {
        const uint8_t *content = NULL;
        size_t content_size = 0;
        asnber_doc_t *doc = NULL;
        const uint8_t *auth_der = NULL;
        size_t auth_der_size = 0;

        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_open(ctx, kPfxRsaUnencrypted,
                                             kPfxRsaUnencryptedSize,
                                             &pfx) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_pkcs12_pfx_auth_safe_content_tlv(
                            pfx, &content, &content_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(octets_of(ctx, content, content_size, &doc,
                                  &auth_der, &auth_der_size) == 0);
        ASNBER_TEST_CHECK(asnber_pkcs12_authenticated_safe_open(
                            ctx, auth_der, auth_der_size, &safe) == ASNBER_OK);

        {
            const char *oid = NULL;
            size_t oid_size = 0;
            const uint8_t *inner = NULL;
            size_t inner_size = 0;
            ASNBER_TEST_CHECK(asnber_pkcs12_authenticated_safe_content_at(
                                safe, 2, &oid, &oid_size, &inner,
                                &inner_size) == ASNBER_E_INVALID_ARG);
            ASNBER_TEST_CHECK(oid == NULL && inner == NULL);
        }

        {
            asnber_doc_t *inner_doc = NULL;
            const uint8_t *safe_der = NULL;
            size_t safe_der_size = 0;
            const char *oid = NULL;
            size_t oid_size = 0;
            const uint8_t *inner = NULL;
            size_t inner_size = 0;
            const char *bag_id = NULL;
            size_t bag_id_size = 0;
            const uint8_t *value = NULL;
            size_t value_size = 0;
            size_t attributes = 0;
            const char *attr_id = NULL;
            size_t attr_id_size = 0;
            const asnber_node_t *values = NULL;

            ASNBER_TEST_CHECK(asnber_pkcs12_authenticated_safe_content_at(
                                safe, 0, &oid, &oid_size, &inner,
                                &inner_size) == ASNBER_OK);
            ASNBER_TEST_CHECK(octets_of(ctx, inner, inner_size, &inner_doc,
                                      &safe_der, &safe_der_size) == 0);
            ASNBER_TEST_CHECK(asnber_pkcs12_safe_contents_open(
                                ctx, safe_der, safe_der_size,
                                &contents) == ASNBER_OK);
            ASNBER_TEST_CHECK(asnber_pkcs12_safe_contents_bag_at(
                                contents, 1, &bag_id, &bag_id_size, &value,
                                &value_size, &attributes) ==
                            ASNBER_E_INVALID_ARG);
            ASNBER_TEST_CHECK(asnber_pkcs12_safe_contents_bag_at(
                                contents, 0, &bag_id, &bag_id_size, &value,
                                &value_size, &attributes) == ASNBER_OK);
            ASNBER_TEST_CHECK(asnber_pkcs12_safe_contents_bag_attribute_at(
                                contents, 0, attributes, &attr_id,
                                &attr_id_size, &values) ==
                            ASNBER_E_INVALID_ARG);
            asnber_pkcs12_safe_contents_close(contents);
            asnber_doc_destroy(inner_doc);
        }

        asnber_pkcs12_authenticated_safe_close(safe);
        asnber_doc_destroy(doc);
        asnber_pkcs12_pfx_close(pfx);
    }

    /* CertBag 不接受 PFX 根结构。 */
    ASNBER_TEST_CHECK(asnber_pkcs12_cert_bag_open(
                        ctx, kPfxRsaUnencrypted, kPfxRsaUnencryptedSize,
                        &bag) != ASNBER_OK);
    ASNBER_TEST_CHECK(bag == NULL);

    asnber_ctx_destroy(ctx);
    return 0;
}

int main(void)
{
    if (test_pfx_unencrypted() != 0) {
        return 1;
    }
    if (test_pfx_encrypted() != 0) {
        return 1;
    }
    if (test_pfx_certs_only() != 0) {
        return 1;
    }
    if (test_version_and_default_iterations() != 0) {
        return 1;
    }
    if (test_cert_bag_sdsi() != 0) {
        return 1;
    }
    if (test_negative() != 0) {
        return 1;
    }
    return 0;
}
