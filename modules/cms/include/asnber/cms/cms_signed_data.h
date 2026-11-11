/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-cms 公共子头文件：SignedData（RFC 5652 第 5 节）只读访问。
 */

#ifndef ASNBER_CMS_SIGNED_DATA_H_INCLUDED
#define ASNBER_CMS_SIGNED_DATA_H_INCLUDED

#include <asnber/cms/cms_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* SignedData（RFC 5652 第 5 节）                                              */
/* ------------------------------------------------------------------------- */

/* 打开 DER 编码的 SignedData（不含外层 ContentInfo）。只读结构。 */
ASNBER_CMS_API asnber_err_t asnber_cms_signed_data_open(
    asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asnber_cms_signed_data_t **out_signed_data);

ASNBER_CMS_API void asnber_cms_signed_data_close(
    asnber_cms_signed_data_t *signed_data);

/* version：原样返回 CMSVersion 整数值，不做范围校验。 */
ASNBER_CMS_API asnber_err_t asnber_cms_signed_data_version(
    const asnber_cms_signed_data_t *signed_data, int64_t *out_version);

/* digestAlgorithms（SET OF AlgorithmIdentifier）条目数。 */
ASNBER_CMS_API asnber_err_t asnber_cms_signed_data_digest_algorithm_count(
    const asnber_cms_signed_data_t *signed_data, size_t *out_count);

/*
 * 按下标访问 digestAlgorithms 条目：algorithm OID 点分十进制 + parameters
 * 完整原始 TLV。parameters 缺省时返回 ASNBER_OK 且 *out_parameters = NULL、
 * *out_parameters_size = 0。index 越界返回 ASNBER_E_INVALID_ARG。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_signed_data_digest_algorithm_at(
    const asnber_cms_signed_data_t *signed_data, size_t index,
    const char **out_oid, size_t *out_oid_size,
    const uint8_t **out_parameters, size_t *out_parameters_size);

/* encapContentInfo.eContentType：OID 点分十进制文本（借用句柄）。 */
ASNBER_CMS_API asnber_err_t asnber_cms_signed_data_encap_content_type(
    const asnber_cms_signed_data_t *signed_data, const char **out_dotted,
    size_t *out_size);

/*
 * encapContentInfo.eContent：OCTET STRING 内容字节（不含 tag/len）。
 * detached 场景字段缺省：返回 ASNBER_OK 且 NULL/0。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_signed_data_encap_content(
    const asnber_cms_signed_data_t *signed_data, const uint8_t **out_data,
    size_t *out_size);

/* eContent 字段完整 TLV（OCTET STRING，含 tag/len）；缺省 NULL/0。 */
ASNBER_CMS_API asnber_err_t asnber_cms_signed_data_encap_content_tlv(
    const asnber_cms_signed_data_t *signed_data, const uint8_t **out_data,
    size_t *out_size);

/* certificates（CertificateSet）条目数；字段缺省时为 0。 */
ASNBER_CMS_API asnber_err_t asnber_cms_signed_data_certificate_count(
    const asnber_cms_signed_data_t *signed_data, size_t *out_count);

/*
 * 按下标判别并返回证书条目：
 * - *out_choice 为 ASNBER_CMS_CERT_CHOICE_*；
 * - *out_tlv 为该分支的完整原始 TLV（含 tag/len），借用句柄；
 * - index 越界返回 ASNBER_E_INVALID_ARG。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_signed_data_certificate_at(
    const asnber_cms_signed_data_t *signed_data, size_t index,
    int *out_choice, const uint8_t **out_tlv, size_t *out_tlv_size);

/*
 * 仅对 ASNBER_CMS_CERT_CHOICE_CERTIFICATE 分支有效：返回 TBSCertificate
 * 中 subject / issuer 的完整原始 TLV。扩展证书、v1/v2 AttributeCertificate
 * 与 other 分支返回 ASNBER_E_UNSUPPORTED（其完整原始 TLV 仍由
 * certificate_at 返回）；下标越界返回 ASNBER_E_INVALID_ARG。不做链校验，
 * 也不解析 RDN 内容。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_signed_data_certificate_subject(
    const asnber_cms_signed_data_t *signed_data, size_t index,
    const uint8_t **out_data, size_t *out_size);

ASNBER_CMS_API asnber_err_t asnber_cms_signed_data_certificate_issuer(
    const asnber_cms_signed_data_t *signed_data, size_t index,
    const uint8_t **out_data, size_t *out_size);

/* 仅证书分支：serialNumber 大整数严格十进制文本（借用句柄）。 */
ASNBER_CMS_API asnber_err_t asnber_cms_signed_data_certificate_serial(
    const asnber_cms_signed_data_t *signed_data, size_t index,
    const char **out_decimal, size_t *out_size);

/* crls（RevocationInfoChoices）条目数；字段缺省时为 0。 */
ASNBER_CMS_API asnber_err_t asnber_cms_signed_data_crl_count(
    const asnber_cms_signed_data_t *signed_data, size_t *out_count);

/*
 * 按下标判别并返回 crls 条目：*out_choice 为
 * ASNBER_CMS_REVOCATION_CHOICE_CRL 或 ASNBER_CMS_REVOCATION_CHOICE_OTHER；
 * *out_tlv 为完整原始 TLV。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_signed_data_crl_at(
    const asnber_cms_signed_data_t *signed_data, size_t index,
    int *out_choice, const uint8_t **out_tlv, size_t *out_tlv_size);

/* signerInfos 条目数。 */
ASNBER_CMS_API asnber_err_t asnber_cms_signed_data_signer_count(
    const asnber_cms_signed_data_t *signed_data, size_t *out_count);

/* SignerInfo.version：原样返回整数值。 */
ASNBER_CMS_API asnber_err_t asnber_cms_signed_data_signer_version(
    const asnber_cms_signed_data_t *signed_data, size_t index,
    int64_t *out_version);

/*
 * signerInfos[index].sid 分支判别：ASNBER_CMS_SID_ISSUER_AND_SERIAL 或
 * ASNBER_CMS_SID_SUBJECT_KEY_IDENTIFIER。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_signed_data_signer_sid_choice(
    const asnber_cms_signed_data_t *signed_data, size_t index,
    int *out_choice);

/* sid 为 issuerAndSerialNumber 时的 issuer 完整原始 TLV。 */
ASNBER_CMS_API asnber_err_t asnber_cms_signed_data_signer_sid_issuer(
    const asnber_cms_signed_data_t *signed_data, size_t index,
    const uint8_t **out_data, size_t *out_size);

/* sid 为 issuerAndSerialNumber 时的 serialNumber 十进制文本。 */
ASNBER_CMS_API asnber_err_t asnber_cms_signed_data_signer_sid_serial(
    const asnber_cms_signed_data_t *signed_data, size_t index,
    const char **out_decimal, size_t *out_size);

/* sid 为 issuerAndSerialNumber 时的 serialNumber 完整原始 TLV。 */
ASNBER_CMS_API asnber_err_t asnber_cms_signed_data_signer_sid_serial_tlv(
    const asnber_cms_signed_data_t *signed_data, size_t index,
    const uint8_t **out_data, size_t *out_size);

/* sid 为 subjectKeyIdentifier 时的内容字节（不含 tag/len）。 */
ASNBER_CMS_API asnber_err_t
asnber_cms_signed_data_signer_sid_subject_key_identifier(
    const asnber_cms_signed_data_t *signed_data, size_t index,
    const uint8_t **out_data, size_t *out_size);

/* SignerInfo.digestAlgorithm：OID 与 parameters（ANY 原始 TLV）。 */
ASNBER_CMS_API asnber_err_t asnber_cms_signed_data_signer_digest_algorithm(
    const asnber_cms_signed_data_t *signed_data, size_t index,
    const char **out_oid, size_t *out_oid_size,
    const uint8_t **out_parameters, size_t *out_parameters_size);

/*
 * SignerInfo.signedAttrs：`[0] IMPLICIT SET OF Attribute` 的完整原始 TLV
 * （含 [0] 标签）；缺省时返回 ASNBER_OK 且 NULL/0。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_signed_data_signer_signed_attrs(
    const asnber_cms_signed_data_t *signed_data, size_t index,
    const uint8_t **out_data, size_t *out_size);

/* SignerInfo.signatureAlgorithm：OID 与 parameters（ANY 原始 TLV）。 */
ASNBER_CMS_API asnber_err_t asnber_cms_signed_data_signer_signature_algorithm(
    const asnber_cms_signed_data_t *signed_data, size_t index,
    const char **out_oid, size_t *out_oid_size,
    const uint8_t **out_parameters, size_t *out_parameters_size);

/* SignerInfo.signature：OCTET STRING 内容字节（不含 tag/len）。 */
ASNBER_CMS_API asnber_err_t asnber_cms_signed_data_signer_signature(
    const asnber_cms_signed_data_t *signed_data, size_t index,
    const uint8_t **out_data, size_t *out_size);

/* SignerInfo.signature：OCTET STRING 完整 TLV。 */
ASNBER_CMS_API asnber_err_t asnber_cms_signed_data_signer_signature_tlv(
    const asnber_cms_signed_data_t *signed_data, size_t index,
    const uint8_t **out_data, size_t *out_size);

/*
 * SignerInfo.unsignedAttrs：`[1] IMPLICIT SET OF Attribute` 的完整原始
 * TLV（含 [1] 标签）；缺省时返回 ASNBER_OK 且 NULL/0。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_signed_data_signer_unsigned_attrs(
    const asnber_cms_signed_data_t *signed_data, size_t index,
    const uint8_t **out_data, size_t *out_size);


#ifdef __cplusplus
}
#endif

#endif /* ASNBER_CMS_SIGNED_DATA_H_INCLUDED */
