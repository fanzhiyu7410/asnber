/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * libFuzzer harness：asnber-cms ContentInfo / SignedData / EnvelopedData /
 * EncryptedData 只读访问面与 builder 写路径。
 *
 * 输入先按 ContentInfo 打开；成功后把 content 字段的内层 TLV 再交给
 * SignedData、EnvelopedData 与 EncryptedData open，覆盖两级结构（内层
 * 命中哪个只看输入字节）。所有带下标的访问器按 0 / count / SIZE_MAX
 * 探测，并对 NULL 输出参数做边界调用。随后用同一份输入驱动 builder 的
 * 单 TLV 入口与 signer 路径并尝试编码，覆盖写侧校验与组装。
 */
#include <asnber/cms/cms.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "fuzz_common.h"
#include "fuzz_module_common.h"

static const char kSha256Oid[] = "2.16.840.1.101.3.4.2.1";
static const char kDataOid[] = "1.2.840.113549.1.7.1";
static const char kRsaEncryptionOid[] = "1.2.840.113549.1.1.1";
static const char kAes256CbcOid[] = "2.16.840.1.101.3.4.1.42";
static const char kHmacSha256Oid[] = "1.2.840.113549.2.9";
static const char kZlibOid[] = "1.2.840.113549.1.9.16.3.8";
static const uint8_t kNullParams[2] = {0x05, 0x00};
/* 最小合法 ktri，供 AuthenticatedData builder 骨架使用。 */
static const uint8_t kFuzzKtri[] = {
    0x30, 0x2C, 0x02, 0x01, 0x00, 0x30, 0x14, 0x30, 0x0F, 0x31, 0x0D,
    0x30, 0x0B, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x04, 0x74, 0x65,
    0x73, 0x74, 0x02, 0x01, 0x01, 0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86,
    0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x04, 0x04, 0x01, 0x02,
    0x03, 0x04,
};

/* 属性集合必须以 SET OF Attribute（0x31）给入，builder 会改写为 [1]。 */
static const uint8_t kUnprotectedAttrs[] = {
    0x31, 0x0C, 0x30, 0x0A, 0x06, 0x03, 0x2A, 0x03, 0x04,
    0x31, 0x03, 0x02, 0x01, 0x01,
};

static void scan_signer(const asnber_cms_signed_data_t *signed_data,
                        size_t index)
{
    int64_t version = 0;
    int choice = -1;
    const char *text = NULL;
    size_t text_size = 0;
    const uint8_t *bytes = NULL;
    size_t bytes_size = 0;
    const uint8_t *params = NULL;
    size_t params_size = 0;

    (void)asnber_cms_signed_data_signer_version(signed_data, index, &version);
    (void)asnber_cms_signed_data_signer_version(signed_data, index, NULL);

    (void)asnber_cms_signed_data_signer_sid_choice(signed_data, index, &choice);
    (void)asnber_cms_signed_data_signer_sid_choice(signed_data, index, NULL);

    (void)asnber_cms_signed_data_signer_sid_issuer(signed_data, index, &bytes,
                                                 &bytes_size);
    (void)asnber_cms_signed_data_signer_sid_issuer(signed_data, index, NULL,
                                                 &bytes_size);
    (void)asnber_cms_signed_data_signer_sid_issuer(signed_data, index, &bytes,
                                                 NULL);

    (void)asnber_cms_signed_data_signer_sid_serial(signed_data, index, &text,
                                                 &text_size);
    (void)asnber_cms_signed_data_signer_sid_serial(signed_data, index, NULL,
                                                 &text_size);
    (void)asnber_cms_signed_data_signer_sid_serial(signed_data, index, &text,
                                                 NULL);

    (void)asnber_cms_signed_data_signer_sid_serial_tlv(
        signed_data, index, &bytes, &bytes_size);
    (void)asnber_cms_signed_data_signer_sid_serial_tlv(
        signed_data, index, NULL, &bytes_size);
    (void)asnber_cms_signed_data_signer_sid_serial_tlv(
        signed_data, index, &bytes, NULL);

    (void)asnber_cms_signed_data_signer_sid_subject_key_identifier(
        signed_data, index, &bytes, &bytes_size);
    (void)asnber_cms_signed_data_signer_sid_subject_key_identifier(
        signed_data, index, NULL, &bytes_size);
    (void)asnber_cms_signed_data_signer_sid_subject_key_identifier(
        signed_data, index, &bytes, NULL);

    (void)asnber_cms_signed_data_signer_digest_algorithm(
        signed_data, index, &text, &text_size, &params, &params_size);
    (void)asnber_cms_signed_data_signer_digest_algorithm(
        signed_data, index, NULL, &text_size, &params, &params_size);
    (void)asnber_cms_signed_data_signer_digest_algorithm(
        signed_data, index, &text, NULL, &params, &params_size);
    (void)asnber_cms_signed_data_signer_digest_algorithm(
        signed_data, index, &text, &text_size, NULL, &params_size);
    (void)asnber_cms_signed_data_signer_digest_algorithm(
        signed_data, index, &text, &text_size, &params, NULL);

    (void)asnber_cms_signed_data_signer_signed_attrs(signed_data, index, &bytes,
                                                   &bytes_size);
    (void)asnber_cms_signed_data_signer_signed_attrs(signed_data, index, NULL,
                                                   &bytes_size);
    (void)asnber_cms_signed_data_signer_signed_attrs(signed_data, index, &bytes,
                                                   NULL);

    (void)asnber_cms_signed_data_signer_signature_algorithm(
        signed_data, index, &text, &text_size, &params, &params_size);
    (void)asnber_cms_signed_data_signer_signature_algorithm(
        signed_data, index, NULL, &text_size, &params, &params_size);
    (void)asnber_cms_signed_data_signer_signature_algorithm(
        signed_data, index, &text, NULL, &params, &params_size);
    (void)asnber_cms_signed_data_signer_signature_algorithm(
        signed_data, index, &text, &text_size, NULL, &params_size);
    (void)asnber_cms_signed_data_signer_signature_algorithm(
        signed_data, index, &text, &text_size, &params, NULL);

    (void)asnber_cms_signed_data_signer_signature(signed_data, index, &bytes,
                                                &bytes_size);
    (void)asnber_cms_signed_data_signer_signature(signed_data, index, NULL,
                                                &bytes_size);
    (void)asnber_cms_signed_data_signer_signature(signed_data, index, &bytes,
                                                NULL);

    (void)asnber_cms_signed_data_signer_signature_tlv(
        signed_data, index, &bytes, &bytes_size);
    (void)asnber_cms_signed_data_signer_signature_tlv(
        signed_data, index, NULL, &bytes_size);
    (void)asnber_cms_signed_data_signer_signature_tlv(
        signed_data, index, &bytes, NULL);

    (void)asnber_cms_signed_data_signer_unsigned_attrs(
        signed_data, index, &bytes, &bytes_size);
    (void)asnber_cms_signed_data_signer_unsigned_attrs(
        signed_data, index, NULL, &bytes_size);
    (void)asnber_cms_signed_data_signer_unsigned_attrs(
        signed_data, index, &bytes, NULL);
}

static void scan_signed_data(const asnber_cms_signed_data_t *signed_data)
{
    int64_t version = 0;
    const char *text = NULL;
    size_t text_size = 0;
    const uint8_t *bytes = NULL;
    size_t bytes_size = 0;
    size_t count = 0;
    int probe;

    (void)asnber_cms_signed_data_version(signed_data, &version);
    (void)asnber_cms_signed_data_version(signed_data, NULL);

    if (asnber_cms_signed_data_digest_algorithm_count(signed_data, &count) ==
        ASNBER_OK) {
        for (probe = 0; probe < FUZZ_INDEX_PROBES; ++probe) {
            const uint8_t *params = NULL;
            size_t params_size = 0;
            size_t index = fuzz_probe_index(count, probe);
            (void)asnber_cms_signed_data_digest_algorithm_at(
                signed_data, index, &text, &text_size, &params,
                &params_size);
        }
    }
    (void)asnber_cms_signed_data_digest_algorithm_count(signed_data, NULL);

    (void)asnber_cms_signed_data_encap_content_type(signed_data, &text,
                                                  &text_size);
    (void)asnber_cms_signed_data_encap_content_type(signed_data, NULL,
                                                  &text_size);
    (void)asnber_cms_signed_data_encap_content_type(signed_data, &text, NULL);

    (void)asnber_cms_signed_data_encap_content(signed_data, &bytes,
                                             &bytes_size);
    (void)asnber_cms_signed_data_encap_content(signed_data, NULL, &bytes_size);
    (void)asnber_cms_signed_data_encap_content(signed_data, &bytes, NULL);

    (void)asnber_cms_signed_data_encap_content_tlv(signed_data, &bytes,
                                                 &bytes_size);
    (void)asnber_cms_signed_data_encap_content_tlv(signed_data, NULL,
                                                 &bytes_size);
    (void)asnber_cms_signed_data_encap_content_tlv(signed_data, &bytes, NULL);

    if (asnber_cms_signed_data_certificate_count(signed_data, &count) ==
        ASNBER_OK) {
        for (probe = 0; probe < FUZZ_INDEX_PROBES; ++probe) {
            int choice = -1;
            size_t index = fuzz_probe_index(count, probe);
            (void)asnber_cms_signed_data_certificate_at(
                signed_data, index, &choice, &bytes, &bytes_size);
            (void)asnber_cms_signed_data_certificate_subject(
                signed_data, index, &bytes, &bytes_size);
            (void)asnber_cms_signed_data_certificate_issuer(
                signed_data, index, &bytes, &bytes_size);
            (void)asnber_cms_signed_data_certificate_serial(
                signed_data, index, &text, &text_size);
        }
    }
    (void)asnber_cms_signed_data_certificate_count(signed_data, NULL);

    if (asnber_cms_signed_data_crl_count(signed_data, &count) == ASNBER_OK) {
        for (probe = 0; probe < FUZZ_INDEX_PROBES; ++probe) {
            int choice = -1;
            size_t index = fuzz_probe_index(count, probe);
            (void)asnber_cms_signed_data_crl_at(signed_data, index, &choice,
                                              &bytes, &bytes_size);
        }
    }
    (void)asnber_cms_signed_data_crl_count(signed_data, NULL);

    if (asnber_cms_signed_data_signer_count(signed_data, &count) == ASNBER_OK) {
        for (probe = 0; probe < FUZZ_INDEX_PROBES; ++probe) {
            scan_signer(signed_data, fuzz_probe_index(count, probe));
        }
    }
    (void)asnber_cms_signed_data_signer_count(signed_data, NULL);
}

static void scan_recipient(const asnber_cms_enveloped_data_t *enveloped,
                           size_t index)
{
    int choice = -1;
    int64_t version = 0;
    const char *text = NULL;
    size_t text_size = 0;
    const uint8_t *bytes = NULL;
    size_t bytes_size = 0;
    const uint8_t *params = NULL;
    size_t params_size = 0;
    char decimal[64];
    size_t decimal_size = 0;
    size_t count = 0;

    (void)asnber_cms_enveloped_data_recipient_choice(enveloped, index, &choice);
    (void)asnber_cms_enveloped_data_recipient_choice(enveloped, index, NULL);

    (void)asnber_cms_enveloped_data_recipient_tlv(enveloped, index, &bytes,
                                                &bytes_size);
    (void)asnber_cms_enveloped_data_recipient_tlv(enveloped, index, NULL,
                                                &bytes_size);
    (void)asnber_cms_enveloped_data_recipient_tlv(enveloped, index, &bytes,
                                                NULL);

    (void)asnber_cms_enveloped_data_recipient_version(enveloped, index,
                                                    &version);
    (void)asnber_cms_enveloped_data_recipient_version(enveloped, index, NULL);

    (void)asnber_cms_enveloped_data_recipient_key_encryption_algorithm(
        enveloped, index, &text, &text_size, &params, &params_size);
    (void)asnber_cms_enveloped_data_recipient_key_encryption_algorithm(
        enveloped, index, NULL, &text_size, &params, &params_size);
    (void)asnber_cms_enveloped_data_recipient_key_encryption_algorithm(
        enveloped, index, &text, NULL, &params, &params_size);
    (void)asnber_cms_enveloped_data_recipient_key_encryption_algorithm(
        enveloped, index, &text, &text_size, NULL, &params_size);
    (void)asnber_cms_enveloped_data_recipient_key_encryption_algorithm(
        enveloped, index, &text, &text_size, &params, NULL);

    (void)asnber_cms_enveloped_data_recipient_encrypted_key(enveloped, index,
                                                          &bytes,
                                                          &bytes_size);
    (void)asnber_cms_enveloped_data_recipient_encrypted_key(enveloped, index,
                                                          NULL,
                                                          &bytes_size);
    (void)asnber_cms_enveloped_data_recipient_encrypted_key(enveloped, index,
                                                          &bytes, NULL);

    (void)asnber_cms_enveloped_data_recipient_kekri_key_identifier(
        enveloped, index, &bytes, &bytes_size);
    (void)asnber_cms_enveloped_data_recipient_kekri_key_identifier(
        enveloped, index, NULL, &bytes_size);
    (void)asnber_cms_enveloped_data_recipient_kekri_key_identifier(
        enveloped, index, &bytes, NULL);

    (void)asnber_cms_enveloped_data_recipient_pwri_key_derivation_algorithm_tlv(
        enveloped, index, &bytes, &bytes_size);
    (void)asnber_cms_enveloped_data_recipient_pwri_key_derivation_algorithm_tlv(
        enveloped, index, NULL, &bytes_size);
    (void)asnber_cms_enveloped_data_recipient_pwri_key_derivation_algorithm_tlv(
        enveloped, index, &bytes, NULL);

    (void)asnber_cms_enveloped_data_recipient_ori_type(enveloped, index, &text,
                                                     &text_size);
    (void)asnber_cms_enveloped_data_recipient_ori_type(enveloped, index, NULL,
                                                     &text_size);
    (void)asnber_cms_enveloped_data_recipient_ori_type(enveloped, index, &text,
                                                     NULL);

    (void)asnber_cms_enveloped_data_recipient_ori_value_tlv(
        enveloped, index, &bytes, &bytes_size);
    (void)asnber_cms_enveloped_data_recipient_ori_value_tlv(
        enveloped, index, NULL, &bytes_size);
    (void)asnber_cms_enveloped_data_recipient_ori_value_tlv(
        enveloped, index, &bytes, NULL);

    (void)asnber_cms_enveloped_data_recipient_rid_choice(enveloped, index,
                                                        &choice);
    (void)asnber_cms_enveloped_data_recipient_rid_choice(enveloped, index,
                                                        NULL);

    (void)asnber_cms_enveloped_data_recipient_rid_issuer_tlv(
        enveloped, index, &bytes, &bytes_size);
    (void)asnber_cms_enveloped_data_recipient_rid_issuer_tlv(
        enveloped, index, NULL, &bytes_size);
    (void)asnber_cms_enveloped_data_recipient_rid_issuer_tlv(
        enveloped, index, &bytes, NULL);

    (void)asnber_cms_enveloped_data_recipient_rid_serial_tlv(
        enveloped, index, &bytes, &bytes_size);
    (void)asnber_cms_enveloped_data_recipient_rid_serial_tlv(
        enveloped, index, NULL, &bytes_size);
    (void)asnber_cms_enveloped_data_recipient_rid_serial_tlv(
        enveloped, index, &bytes, NULL);

    (void)asnber_cms_enveloped_data_recipient_rid_serial_decimal(
        enveloped, index, decimal, sizeof(decimal), &decimal_size);
    (void)asnber_cms_enveloped_data_recipient_rid_serial_decimal(
        enveloped, index, decimal, sizeof(decimal), NULL);
    (void)asnber_cms_enveloped_data_recipient_rid_serial_decimal(
        enveloped, index, NULL, sizeof(decimal), &decimal_size);
    (void)asnber_cms_enveloped_data_recipient_rid_serial_decimal(
        enveloped, index, decimal, 0, &decimal_size);
    (void)asnber_cms_enveloped_data_recipient_rid_serial_decimal(
        enveloped, index, decimal, 1, &decimal_size);

    (void)asnber_cms_enveloped_data_recipient_rid_subject_key_id(
        enveloped, index, &bytes, &bytes_size);
    (void)asnber_cms_enveloped_data_recipient_rid_subject_key_id(
        enveloped, index, NULL, &bytes_size);
    (void)asnber_cms_enveloped_data_recipient_rid_subject_key_id(
        enveloped, index, &bytes, NULL);

    (void)asnber_cms_enveloped_data_recipient_originator_choice(
        enveloped, index, &choice);
    (void)asnber_cms_enveloped_data_recipient_originator_choice(
        enveloped, index, NULL);

    (void)asnber_cms_enveloped_data_recipient_originator_tlv(
        enveloped, index, &bytes, &bytes_size);
    (void)asnber_cms_enveloped_data_recipient_originator_tlv(
        enveloped, index, NULL, &bytes_size);
    (void)asnber_cms_enveloped_data_recipient_originator_tlv(
        enveloped, index, &bytes, NULL);

    (void)asnber_cms_enveloped_data_recipient_kari_encrypted_key_count(
        enveloped, index, &count);
    (void)asnber_cms_enveloped_data_recipient_kari_encrypted_key_count(
        enveloped, index, NULL);
}

static void scan_enveloped_data(const asnber_cms_enveloped_data_t *enveloped)
{
    int64_t version = 0;
    const char *text = NULL;
    size_t text_size = 0;
    const uint8_t *bytes = NULL;
    size_t bytes_size = 0;
    const uint8_t *params = NULL;
    size_t params_size = 0;
    size_t count = 0;
    int probe;

    (void)asnber_cms_enveloped_data_version(enveloped, &version);
    (void)asnber_cms_enveloped_data_version(enveloped, NULL);

    (void)asnber_cms_enveloped_data_originator_info_tlv(enveloped, &bytes,
                                                      &bytes_size);
    (void)asnber_cms_enveloped_data_originator_info_tlv(enveloped, NULL,
                                                      &bytes_size);
    (void)asnber_cms_enveloped_data_originator_info_tlv(enveloped, &bytes,
                                                      NULL);

    if (asnber_cms_enveloped_data_recipient_count(enveloped, &count) == ASNBER_OK) {
        for (probe = 0; probe < FUZZ_INDEX_PROBES; ++probe) {
            scan_recipient(enveloped, fuzz_probe_index(count, probe));
        }
    }
    (void)asnber_cms_enveloped_data_recipient_count(enveloped, NULL);

    (void)asnber_cms_enveloped_data_content_type(enveloped, &text, &text_size);
    (void)asnber_cms_enveloped_data_content_type(enveloped, NULL, &text_size);
    (void)asnber_cms_enveloped_data_content_type(enveloped, &text, NULL);

    (void)asnber_cms_enveloped_data_content_encryption_algorithm(
        enveloped, &text, &text_size, &params, &params_size);
    (void)asnber_cms_enveloped_data_content_encryption_algorithm(
        enveloped, NULL, &text_size, &params, &params_size);
    (void)asnber_cms_enveloped_data_content_encryption_algorithm(
        enveloped, &text, NULL, &params, &params_size);
    (void)asnber_cms_enveloped_data_content_encryption_algorithm(
        enveloped, &text, &text_size, NULL, &params_size);
    (void)asnber_cms_enveloped_data_content_encryption_algorithm(
        enveloped, &text, &text_size, &params, NULL);

    (void)asnber_cms_enveloped_data_encrypted_content(enveloped, &bytes,
                                                    &bytes_size);
    (void)asnber_cms_enveloped_data_encrypted_content(enveloped, NULL,
                                                    &bytes_size);
    (void)asnber_cms_enveloped_data_encrypted_content(enveloped, &bytes, NULL);

    (void)asnber_cms_enveloped_data_encrypted_content_tlv(enveloped, &bytes,
                                                        &bytes_size);
    (void)asnber_cms_enveloped_data_encrypted_content_tlv(enveloped, NULL,
                                                        &bytes_size);
    (void)asnber_cms_enveloped_data_encrypted_content_tlv(enveloped, &bytes,
                                                        NULL);

    (void)asnber_cms_enveloped_data_unprotected_attrs_tlv(enveloped, &bytes,
                                                        &bytes_size);
    (void)asnber_cms_enveloped_data_unprotected_attrs_tlv(enveloped, NULL,
                                                        &bytes_size);
    (void)asnber_cms_enveloped_data_unprotected_attrs_tlv(enveloped, &bytes,
                                                        NULL);
}

static void scan_encrypted_data(const asnber_cms_encrypted_data_t *encrypted)
{
    int64_t version = 0;
    const char *text = NULL;
    size_t text_size = 0;
    const uint8_t *bytes = NULL;
    size_t bytes_size = 0;
    const uint8_t *params = NULL;
    size_t params_size = 0;

    (void)asnber_cms_encrypted_data_version(encrypted, &version);
    (void)asnber_cms_encrypted_data_version(encrypted, NULL);

    (void)asnber_cms_encrypted_data_content_type(encrypted, &text, &text_size);
    (void)asnber_cms_encrypted_data_content_type(encrypted, NULL, &text_size);
    (void)asnber_cms_encrypted_data_content_type(encrypted, &text, NULL);

    (void)asnber_cms_encrypted_data_content_encryption_algorithm(
        encrypted, &text, &text_size, &params, &params_size);
    (void)asnber_cms_encrypted_data_content_encryption_algorithm(
        encrypted, NULL, &text_size, &params, &params_size);
    (void)asnber_cms_encrypted_data_content_encryption_algorithm(
        encrypted, &text, NULL, &params, &params_size);
    (void)asnber_cms_encrypted_data_content_encryption_algorithm(
        encrypted, &text, &text_size, NULL, &params_size);
    (void)asnber_cms_encrypted_data_content_encryption_algorithm(
        encrypted, &text, &text_size, &params, NULL);

    (void)asnber_cms_encrypted_data_encrypted_content(encrypted, &bytes,
                                                    &bytes_size);
    (void)asnber_cms_encrypted_data_encrypted_content(encrypted, NULL,
                                                    &bytes_size);
    (void)asnber_cms_encrypted_data_encrypted_content(encrypted, &bytes, NULL);

    (void)asnber_cms_encrypted_data_encrypted_content_tlv(encrypted, &bytes,
                                                        &bytes_size);
    (void)asnber_cms_encrypted_data_encrypted_content_tlv(encrypted, NULL,
                                                        &bytes_size);
    (void)asnber_cms_encrypted_data_encrypted_content_tlv(encrypted, &bytes,
                                                        NULL);

    (void)asnber_cms_encrypted_data_unprotected_attrs_tlv(encrypted, &bytes,
                                                        &bytes_size);
    (void)asnber_cms_encrypted_data_unprotected_attrs_tlv(encrypted, NULL,
                                                        &bytes_size);
    (void)asnber_cms_encrypted_data_unprotected_attrs_tlv(encrypted, &bytes,
                                                        NULL);
}

static void scan_compressed_data(
    const asnber_cms_compressed_data_t *compressed_data)
{
    int64_t version = 0;
    const char *text = NULL;
    size_t text_size = 0;
    const uint8_t *bytes = NULL;
    size_t bytes_size = 0;
    const uint8_t *params = NULL;
    size_t params_size = 0;

    (void)asnber_cms_compressed_data_version(compressed_data, &version);
    (void)asnber_cms_compressed_data_version(compressed_data, NULL);

    (void)asnber_cms_compressed_data_compression_algorithm(
        compressed_data, &text, &text_size, &params, &params_size);
    (void)asnber_cms_compressed_data_compression_algorithm(
        compressed_data, NULL, &text_size, &params, &params_size);
    (void)asnber_cms_compressed_data_compression_algorithm(
        compressed_data, &text, NULL, &params, &params_size);
    (void)asnber_cms_compressed_data_compression_algorithm(
        compressed_data, &text, &text_size, NULL, &params_size);
    (void)asnber_cms_compressed_data_compression_algorithm(
        compressed_data, &text, &text_size, &params, NULL);

    (void)asnber_cms_compressed_data_econtent_type(compressed_data, &text,
                                                 &text_size);
    (void)asnber_cms_compressed_data_econtent_type(compressed_data, NULL,
                                                 &text_size);
    (void)asnber_cms_compressed_data_econtent_type(compressed_data, &text, NULL);

    (void)asnber_cms_compressed_data_econtent(compressed_data, &bytes,
                                            &bytes_size);
    (void)asnber_cms_compressed_data_econtent(compressed_data, NULL,
                                            &bytes_size);
    (void)asnber_cms_compressed_data_econtent(compressed_data, &bytes, NULL);

    (void)asnber_cms_compressed_data_econtent_tlv(compressed_data, &bytes,
                                                &bytes_size);
    (void)asnber_cms_compressed_data_econtent_tlv(compressed_data, NULL,
                                                &bytes_size);
    (void)asnber_cms_compressed_data_econtent_tlv(compressed_data, &bytes, NULL);
}

static void scan_authenticated_data(
    const asnber_cms_authenticated_data_t *authenticated_data)
{
    int64_t version = 0;
    const char *text = NULL;
    size_t text_size = 0;
    const uint8_t *bytes = NULL;
    size_t bytes_size = 0;
    const uint8_t *params = NULL;
    size_t params_size = 0;
    size_t count = 0;
    int probe;

    (void)asnber_cms_authenticated_data_version(authenticated_data, &version);
    (void)asnber_cms_authenticated_data_version(authenticated_data, NULL);

    (void)asnber_cms_authenticated_data_originator_info_tlv(
        authenticated_data, &bytes, &bytes_size);
    (void)asnber_cms_authenticated_data_originator_info_tlv(
        authenticated_data, NULL, &bytes_size);
    (void)asnber_cms_authenticated_data_originator_info_tlv(
        authenticated_data, &bytes, NULL);

    if (asnber_cms_authenticated_data_recipient_count(authenticated_data,
                                                    &count) == ASNBER_OK) {
        for (probe = 0; probe < FUZZ_INDEX_PROBES; ++probe) {
            int kind = -1;
            size_t index = fuzz_probe_index(count, probe);
            (void)asnber_cms_authenticated_data_recipient_at(
                authenticated_data, index, &kind, &bytes, &bytes_size);
            (void)asnber_cms_authenticated_data_recipient_at(
                authenticated_data, index, NULL, &bytes, &bytes_size);
            (void)asnber_cms_authenticated_data_recipient_at(
                authenticated_data, index, &kind, NULL, &bytes_size);
            (void)asnber_cms_authenticated_data_recipient_at(
                authenticated_data, index, &kind, &bytes, NULL);
        }
    }
    (void)asnber_cms_authenticated_data_recipient_count(authenticated_data,
                                                      NULL);

    (void)asnber_cms_authenticated_data_mac_algorithm(
        authenticated_data, &text, &text_size, &params, &params_size);
    (void)asnber_cms_authenticated_data_mac_algorithm(
        authenticated_data, NULL, &text_size, &params, &params_size);
    (void)asnber_cms_authenticated_data_mac_algorithm(
        authenticated_data, &text, NULL, &params, &params_size);
    (void)asnber_cms_authenticated_data_mac_algorithm(
        authenticated_data, &text, &text_size, NULL, &params_size);
    (void)asnber_cms_authenticated_data_mac_algorithm(
        authenticated_data, &text, &text_size, &params, NULL);

    (void)asnber_cms_authenticated_data_digest_algorithm(
        authenticated_data, &text, &text_size, &params, &params_size);
    (void)asnber_cms_authenticated_data_digest_algorithm(
        authenticated_data, NULL, &text_size, &params, &params_size);
    (void)asnber_cms_authenticated_data_digest_algorithm(
        authenticated_data, &text, NULL, &params, &params_size);
    (void)asnber_cms_authenticated_data_digest_algorithm(
        authenticated_data, &text, &text_size, NULL, &params_size);
    (void)asnber_cms_authenticated_data_digest_algorithm(
        authenticated_data, &text, &text_size, &params, NULL);

    (void)asnber_cms_authenticated_data_econtent_type(authenticated_data, &text,
                                                    &text_size);
    (void)asnber_cms_authenticated_data_econtent_type(authenticated_data, NULL,
                                                    &text_size);
    (void)asnber_cms_authenticated_data_econtent_type(authenticated_data, &text,
                                                    NULL);

    (void)asnber_cms_authenticated_data_econtent(authenticated_data, &bytes,
                                               &bytes_size);
    (void)asnber_cms_authenticated_data_econtent(authenticated_data, NULL,
                                               &bytes_size);
    (void)asnber_cms_authenticated_data_econtent(authenticated_data, &bytes,
                                               NULL);

    (void)asnber_cms_authenticated_data_econtent_tlv(authenticated_data, &bytes,
                                                   &bytes_size);
    (void)asnber_cms_authenticated_data_econtent_tlv(authenticated_data, NULL,
                                                   &bytes_size);
    (void)asnber_cms_authenticated_data_econtent_tlv(authenticated_data, &bytes,
                                                   NULL);

    (void)asnber_cms_authenticated_data_auth_attrs_tlv(authenticated_data,
                                                     &bytes, &bytes_size);
    (void)asnber_cms_authenticated_data_auth_attrs_tlv(authenticated_data, NULL,
                                                     &bytes_size);
    (void)asnber_cms_authenticated_data_auth_attrs_tlv(authenticated_data,
                                                     &bytes, NULL);

    (void)asnber_cms_authenticated_data_mac(authenticated_data, &bytes,
                                          &bytes_size);
    (void)asnber_cms_authenticated_data_mac(authenticated_data, NULL,
                                          &bytes_size);
    (void)asnber_cms_authenticated_data_mac(authenticated_data, &bytes, NULL);

    (void)asnber_cms_authenticated_data_mac_tlv(authenticated_data, &bytes,
                                              &bytes_size);
    (void)asnber_cms_authenticated_data_mac_tlv(authenticated_data, NULL,
                                              &bytes_size);
    (void)asnber_cms_authenticated_data_mac_tlv(authenticated_data, &bytes,
                                              NULL);

    (void)asnber_cms_authenticated_data_unauth_attrs_tlv(authenticated_data,
                                                       &bytes, &bytes_size);
    (void)asnber_cms_authenticated_data_unauth_attrs_tlv(authenticated_data,
                                                       NULL, &bytes_size);
    (void)asnber_cms_authenticated_data_unauth_attrs_tlv(authenticated_data,
                                                       &bytes, NULL);
}

static void scan_content_info(asnber_ctx_t *ctx,
                              const asnber_cms_content_info_t *info)
{
    const char *text = NULL;
    size_t text_size = 0;
    const uint8_t *bytes = NULL;
    size_t bytes_size = 0;

    (void)asnber_cms_content_info_content_type(info, &text, &text_size);
    (void)asnber_cms_content_info_content_type(info, NULL, &text_size);
    (void)asnber_cms_content_info_content_type(info, &text, NULL);

    (void)asnber_cms_content_info_content(info, &bytes, &bytes_size);
    (void)asnber_cms_content_info_content(info, NULL, &bytes_size);
    (void)asnber_cms_content_info_content(info, &bytes, NULL);

    if (bytes != NULL && bytes_size != 0) {
        asnber_cms_signed_data_t *signed_data = NULL;
        if (asnber_cms_signed_data_open(ctx, bytes, bytes_size, &signed_data) ==
                ASNBER_OK &&
            signed_data != NULL) {
            scan_signed_data(signed_data);
        }
        asnber_cms_signed_data_close(signed_data);
        signed_data = NULL;
        asnber_cms_signed_data_close(signed_data);

        /* ContentInfo 内容也可能是 EnvelopedData：无论 contentType 是否匹配
         * 都按 EnvelopedData 再试一次，覆盖“标签不匹配即失败”的路径。 */
        asnber_cms_enveloped_data_t *enveloped = NULL;
        if (asnber_cms_enveloped_data_open(ctx, bytes, bytes_size, &enveloped) ==
                ASNBER_OK &&
            enveloped != NULL) {
            scan_enveloped_data(enveloped);
        }
        asnber_cms_enveloped_data_close(enveloped);
        enveloped = NULL;
        asnber_cms_enveloped_data_close(enveloped);

        /* 内层也可能是 EncryptedData，同样无条件尝试。 */
        asnber_cms_encrypted_data_t *encrypted = NULL;
        if (asnber_cms_encrypted_data_open(ctx, bytes, bytes_size, &encrypted) ==
                ASNBER_OK &&
            encrypted != NULL) {
            scan_encrypted_data(encrypted);
        }
        asnber_cms_encrypted_data_close(encrypted);
        encrypted = NULL;
        asnber_cms_encrypted_data_close(encrypted);

        /* 内层也可能是 CompressedData / AuthenticatedData。 */
        asnber_cms_compressed_data_t *compressed = NULL;
        if (asnber_cms_compressed_data_open(ctx, bytes, bytes_size,
                                          &compressed) == ASNBER_OK &&
            compressed != NULL) {
            scan_compressed_data(compressed);
        }
        asnber_cms_compressed_data_close(compressed);
        compressed = NULL;
        asnber_cms_compressed_data_close(compressed);

        asnber_cms_authenticated_data_t *authenticated = NULL;
        if (asnber_cms_authenticated_data_open(ctx, bytes, bytes_size,
                                             &authenticated) == ASNBER_OK &&
            authenticated != NULL) {
            scan_authenticated_data(authenticated);
        }
        asnber_cms_authenticated_data_close(authenticated);
        authenticated = NULL;
        asnber_cms_authenticated_data_close(authenticated);
    }
}

/*
 * 写路径：固定合法骨架保证 encode 可达，模糊输入只进入单 TLV 校验入口
 * （eContent / 证书 / CRL / 参数 / sid / 属性集合 / 签名内容）。
 */
static void scan_builder(asnber_ctx_t *ctx, const uint8_t *data, size_t size)
{
    asnber_cms_builder_t *builder = NULL;
    if (asnber_cms_builder_create(ctx, &builder) != ASNBER_OK) {
        return;
    }

    (void)asnber_cms_builder_set_version(builder, (int64_t)size);
    (void)asnber_cms_builder_add_digest_algorithm(builder, kSha256Oid, NULL, 0);
    (void)asnber_cms_builder_set_econtent_type(builder, kDataOid);

    if (size != 0) {
        (void)asnber_cms_builder_set_econtent(builder, data, size);
        (void)asnber_cms_builder_add_certificate(builder, data, size);
        (void)asnber_cms_builder_add_crl(builder, data, size);
        (void)asnber_cms_builder_add_digest_algorithm(builder, kSha256Oid, data,
                                                   size);
        (void)asnber_cms_builder_add_signer(
            builder, 1, ASNBER_CMS_SID_SUBJECT_KEY_IDENTIFIER, data, size, NULL,
            0, kSha256Oid, NULL, 0, data, size, kRsaEncryptionOid,
            kNullParams, sizeof(kNullParams), data, size, data, size);
        (void)asnber_cms_builder_add_signer(
            builder, 1, ASNBER_CMS_SID_ISSUER_AND_SERIAL, data, size, data, size,
            kSha256Oid, NULL, 0, NULL, 0, kRsaEncryptionOid, kNullParams,
            sizeof(kNullParams), data, size, NULL, 0);
    }

    {
        asnber_buf_t encoded;
        memset(&encoded, 0, sizeof(encoded));
        (void)asnber_cms_builder_encode(builder, &encoded);
        (void)asnber_buf_release(ctx, &encoded);
    }
    asnber_cms_builder_destroy(builder);
    asnber_cms_builder_destroy(NULL);
}

/*
 * EncryptedData 写路径：固定 version 2 + 合法属性集合保证 encode 可达，
 * 模糊输入进入加密内容入口与（重复设置的）属性入口。
 */
static void scan_encrypted_builder(asnber_ctx_t *ctx, const uint8_t *data,
                                   size_t size)
{
    asnber_cms_encrypted_builder_t *builder = NULL;
    if (asnber_cms_encrypted_builder_create(ctx, &builder) != ASNBER_OK) {
        return;
    }

    (void)asnber_cms_encrypted_builder_set_version(builder, 2);
    (void)asnber_cms_encrypted_builder_set_content_type(builder, kDataOid);
    (void)asnber_cms_encrypted_builder_set_content_encryption_algorithm(
        builder, kAes256CbcOid, kNullParams, sizeof(kNullParams));
    (void)asnber_cms_encrypted_builder_set_unprotected_attrs(
        builder, kUnprotectedAttrs, sizeof(kUnprotectedAttrs));

    if (size != 0) {
        (void)asnber_cms_encrypted_builder_set_encrypted_content(builder, data,
                                                               size);
        (void)asnber_cms_encrypted_builder_set_unprotected_attrs(builder, data,
                                                               size);
    }

    {
        asnber_buf_t encoded;
        memset(&encoded, 0, sizeof(encoded));
        (void)asnber_cms_encrypted_builder_encode(builder, &encoded);
        (void)asnber_buf_release(ctx, &encoded);
    }
    asnber_cms_encrypted_builder_destroy(builder);
    asnber_cms_encrypted_builder_destroy(NULL);
}

/*
 * CompressedData 写路径：固定 version 0 + 合法算法保证 encode 可达，
 * 模糊输入进入压缩算法参数与 eContent 入口。
 */
static void scan_compressed_builder(asnber_ctx_t *ctx, const uint8_t *data,
                                    size_t size)
{
    asnber_cms_compressed_builder_t *builder = NULL;
    if (asnber_cms_compressed_builder_create(ctx, &builder) != ASNBER_OK) {
        return;
    }

    (void)asnber_cms_compressed_builder_set_version(builder, 0);
    (void)asnber_cms_compressed_builder_set_compression_algorithm(
        builder, kZlibOid, kNullParams, sizeof(kNullParams));
    (void)asnber_cms_compressed_builder_set_econtent_type(builder, kDataOid);

    if (size != 0) {
        (void)asnber_cms_compressed_builder_set_compression_algorithm(
            builder, kZlibOid, data, size);
        (void)asnber_cms_compressed_builder_set_econtent(builder, data, size);
    }

    {
        asnber_buf_t encoded;
        memset(&encoded, 0, sizeof(encoded));
        (void)asnber_cms_compressed_builder_encode(builder, &encoded);
        (void)asnber_buf_release(ctx, &encoded);
    }
    asnber_cms_compressed_builder_destroy(builder);
    asnber_cms_compressed_builder_destroy(NULL);
}

/*
 * AuthenticatedData 写路径：固定 version 0 + 合法 ktri 骨架保证 encode
 * 可达，模糊输入进入收件人 TLV、算法参数、属性与 MAC 入口。
 */
static void scan_authenticated_builder(asnber_ctx_t *ctx, const uint8_t *data,
                                       size_t size)
{
    asnber_cms_authenticated_builder_t *builder = NULL;
    if (asnber_cms_authenticated_builder_create(ctx, &builder) != ASNBER_OK) {
        return;
    }

    (void)asnber_cms_authenticated_builder_set_version(builder, 0);
    (void)asnber_cms_authenticated_builder_add_recipient(
        builder, kFuzzKtri, sizeof(kFuzzKtri));
    (void)asnber_cms_authenticated_builder_set_mac_algorithm(
        builder, kHmacSha256Oid, NULL, 0);
    (void)asnber_cms_authenticated_builder_set_econtent_type(builder, kDataOid);
    (void)asnber_cms_authenticated_builder_set_mac(
        builder, kNullParams, sizeof(kNullParams));

    if (size != 0) {
        (void)asnber_cms_authenticated_builder_add_recipient(builder, data,
                                                           size);
        (void)asnber_cms_authenticated_builder_set_mac_algorithm(
            builder, kHmacSha256Oid, data, size);
        (void)asnber_cms_authenticated_builder_set_originator_info(builder,
                                                                 data, size);
        (void)asnber_cms_authenticated_builder_set_digest_algorithm(builder,
                                                                  data, size);
        (void)asnber_cms_authenticated_builder_set_econtent(builder, data,
                                                          size);
        (void)asnber_cms_authenticated_builder_set_auth_attrs(builder, data,
                                                            size);
        (void)asnber_cms_authenticated_builder_set_mac(builder, data, size);
        (void)asnber_cms_authenticated_builder_set_unauth_attrs(builder, data,
                                                              size);
    }

    {
        asnber_buf_t encoded;
        memset(&encoded, 0, sizeof(encoded));
        (void)asnber_cms_authenticated_builder_encode(builder, &encoded);
        (void)asnber_buf_release(ctx, &encoded);
    }
    asnber_cms_authenticated_builder_destroy(builder);
    asnber_cms_authenticated_builder_destroy(NULL);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    asnber_ctx_t *ctx = fuzz_ctx_create();
    if (ctx == NULL) {
        return 0;
    }

    /* ContentInfo open 参数边界。 */
    {
        asnber_cms_content_info_t *probe = NULL;
        (void)asnber_cms_content_info_open(NULL, data, size, &probe);
        probe = NULL;
        (void)asnber_cms_content_info_open(ctx, NULL, size, &probe);
        probe = NULL;
        (void)asnber_cms_content_info_open(ctx, data, 0, &probe);
        probe = NULL;
        (void)asnber_cms_content_info_open(ctx, data, size, NULL);
        probe = NULL;
        (void)asnber_cms_content_info_open(ctx, data, SIZE_MAX, &probe);
    }

    /* SignedData open 参数边界（输入既可来自 ContentInfo，也可独立给入）。 */
    {
        asnber_cms_signed_data_t *probe = NULL;
        (void)asnber_cms_signed_data_open(NULL, data, size, &probe);
        probe = NULL;
        (void)asnber_cms_signed_data_open(ctx, NULL, size, &probe);
        probe = NULL;
        (void)asnber_cms_signed_data_open(ctx, data, 0, &probe);
        probe = NULL;
        (void)asnber_cms_signed_data_open(ctx, data, size, NULL);
        probe = NULL;
        (void)asnber_cms_signed_data_open(ctx, data, SIZE_MAX, &probe);
    }

    /* EnvelopedData open 参数边界（裸 EnvelopedData，不含 ContentInfo）。 */
    {
        asnber_cms_enveloped_data_t *probe = NULL;
        (void)asnber_cms_enveloped_data_open(NULL, data, size, &probe);
        probe = NULL;
        (void)asnber_cms_enveloped_data_open(ctx, NULL, size, &probe);
        probe = NULL;
        (void)asnber_cms_enveloped_data_open(ctx, data, 0, &probe);
        probe = NULL;
        (void)asnber_cms_enveloped_data_open(ctx, data, size, NULL);
        probe = NULL;
        (void)asnber_cms_enveloped_data_open(ctx, data, SIZE_MAX, &probe);
    }

    /* EncryptedData open 参数边界（裸 EncryptedData，不含 ContentInfo）。 */
    {
        asnber_cms_encrypted_data_t *probe = NULL;
        (void)asnber_cms_encrypted_data_open(NULL, data, size, &probe);
        probe = NULL;
        (void)asnber_cms_encrypted_data_open(ctx, NULL, size, &probe);
        probe = NULL;
        (void)asnber_cms_encrypted_data_open(ctx, data, 0, &probe);
        probe = NULL;
        (void)asnber_cms_encrypted_data_open(ctx, data, size, NULL);
        probe = NULL;
        (void)asnber_cms_encrypted_data_open(ctx, data, SIZE_MAX, &probe);
    }

    /* CompressedData open 参数边界（裸 CompressedData）。 */
    {
        asnber_cms_compressed_data_t *probe = NULL;
        (void)asnber_cms_compressed_data_open(NULL, data, size, &probe);
        probe = NULL;
        (void)asnber_cms_compressed_data_open(ctx, NULL, size, &probe);
        probe = NULL;
        (void)asnber_cms_compressed_data_open(ctx, data, 0, &probe);
        probe = NULL;
        (void)asnber_cms_compressed_data_open(ctx, data, size, NULL);
        probe = NULL;
        (void)asnber_cms_compressed_data_open(ctx, data, SIZE_MAX, &probe);
    }

    /* AuthenticatedData open 参数边界（裸 AuthenticatedData）。 */
    {
        asnber_cms_authenticated_data_t *probe = NULL;
        (void)asnber_cms_authenticated_data_open(NULL, data, size, &probe);
        probe = NULL;
        (void)asnber_cms_authenticated_data_open(ctx, NULL, size, &probe);
        probe = NULL;
        (void)asnber_cms_authenticated_data_open(ctx, data, 0, &probe);
        probe = NULL;
        (void)asnber_cms_authenticated_data_open(ctx, data, size, NULL);
        probe = NULL;
        (void)asnber_cms_authenticated_data_open(ctx, data, SIZE_MAX, &probe);
    }

    {
        asnber_cms_content_info_t *info = NULL;
        if (asnber_cms_content_info_open(ctx, data, size, &info) == ASNBER_OK &&
            info != NULL) {
            scan_content_info(ctx, info);
        }
        /* 置空后再 close 覆盖 close(NULL) 重复调用；同一非空指针的重复
         * close 不在契约内，不在此构造。 */
        asnber_cms_content_info_close(info);
        info = NULL;
        asnber_cms_content_info_close(info);
    }

    /* 独立 SignedData 输入：部分语料直接给 SignedData，不带 ContentInfo。 */
    {
        asnber_cms_signed_data_t *signed_data = NULL;
        if (asnber_cms_signed_data_open(ctx, data, size, &signed_data) ==
                ASNBER_OK &&
            signed_data != NULL) {
            scan_signed_data(signed_data);
        }
        asnber_cms_signed_data_close(signed_data);
        signed_data = NULL;
        asnber_cms_signed_data_close(signed_data);
    }

    scan_builder(ctx, data, size);
    scan_encrypted_builder(ctx, data, size);
    scan_compressed_builder(ctx, data, size);
    scan_authenticated_builder(ctx, data, size);

    /* 独立 EnvelopedData 输入：部分语料直接给内层 TLV，不带 ContentInfo。 */
    {
        asnber_cms_enveloped_data_t *enveloped = NULL;
        if (asnber_cms_enveloped_data_open(ctx, data, size, &enveloped) ==
                ASNBER_OK &&
            enveloped != NULL) {
            scan_enveloped_data(enveloped);
        }
        asnber_cms_enveloped_data_close(enveloped);
        enveloped = NULL;
        asnber_cms_enveloped_data_close(enveloped);
    }

    /* 独立 EncryptedData 输入：同上级结构，可能不带 ContentInfo。 */
    {
        asnber_cms_encrypted_data_t *encrypted = NULL;
        if (asnber_cms_encrypted_data_open(ctx, data, size, &encrypted) ==
                ASNBER_OK &&
            encrypted != NULL) {
            scan_encrypted_data(encrypted);
        }
        asnber_cms_encrypted_data_close(encrypted);
        encrypted = NULL;
        asnber_cms_encrypted_data_close(encrypted);
    }

    /* 独立 CompressedData 输入：语料可能直接给内层 TLV。 */
    {
        asnber_cms_compressed_data_t *compressed = NULL;
        if (asnber_cms_compressed_data_open(ctx, data, size, &compressed) ==
                ASNBER_OK &&
            compressed != NULL) {
            scan_compressed_data(compressed);
        }
        asnber_cms_compressed_data_close(compressed);
        compressed = NULL;
        asnber_cms_compressed_data_close(compressed);
    }

    /* 独立 AuthenticatedData 输入：同上。 */
    {
        asnber_cms_authenticated_data_t *authenticated = NULL;
        if (asnber_cms_authenticated_data_open(ctx, data, size,
                                             &authenticated) == ASNBER_OK &&
            authenticated != NULL) {
            scan_authenticated_data(authenticated);
        }
        asnber_cms_authenticated_data_close(authenticated);
        authenticated = NULL;
        asnber_cms_authenticated_data_close(authenticated);
    }

    asnber_ctx_destroy(ctx);
    return 0;
}
