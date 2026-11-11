/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-cms 公共子头文件：EnvelopedData（RFC 5652 第 6 节）只读访问。
 */

#ifndef ASNBER_CMS_ENVELOPED_DATA_H_INCLUDED
#define ASNBER_CMS_ENVELOPED_DATA_H_INCLUDED

#include <asnber/cms/cms_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* EnvelopedData（RFC 5652 第 6 节，只读）                                     */
/* ------------------------------------------------------------------------- */

/*
 * RecipientInfo 分支判别值，数值与 RFC 5652 §6.2 备选顺序一致：ktri 无标签，
 * kari..ori 的数值等于各自的 `[n]` 标签。
 */
#define ASNBER_CMS_RECIPIENT_KTRI 0
#define ASNBER_CMS_RECIPIENT_KARI 1
#define ASNBER_CMS_RECIPIENT_KEKRI 2
#define ASNBER_CMS_RECIPIENT_PWRI 3
#define ASNBER_CMS_RECIPIENT_ORI 4

/* RecipientIdentifier（ktri.rid）分支判别值。 */
#define ASNBER_CMS_RID_ISSUER_AND_SERIAL 0
#define ASNBER_CMS_RID_SUBJECT_KEY_IDENTIFIER 1

/* OriginatorIdentifierOrKey（kari.originator）分支判别值。 */
#define ASNBER_CMS_ORIGINATOR_ISSUER_AND_SERIAL 0
#define ASNBER_CMS_ORIGINATOR_SUBJECT_KEY_IDENTIFIER 1
#define ASNBER_CMS_ORIGINATOR_KEY 2

/*
 * 打开 DER 编码的 EnvelopedData（**不含外层 ContentInfo**）。调用方先用
 * asnber_cms_content_info_open + asnber_cms_content_info_content 取 `[0]` 内层
 * TLV，再传入本函数；模块不提供自动剥壳入口。
 *
 * 只读结构访问：不解密、不做密钥协商、不做 KEK/口令派生、不校验 MAC、
 * 不展开 encryptedKey / oriValue / keyAttr 的内部语义。
 *
 * recipientInfos 的 `SET SIZE (1..MAX) OF` 约束由描述表生效；空集合在
 * open 阶段返回 ASNBER_E_SCHEMA_CONSTRAINT，不会出现“解码成功但语义非法”。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_data_open(
    asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asnber_cms_enveloped_data_t **out_enveloped_data);

ASNBER_CMS_API void asnber_cms_enveloped_data_close(
    asnber_cms_enveloped_data_t *enveloped_data);

/* version：原样返回 CMSVersion 整数值，不做范围校验。 */
ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_data_version(
    const asnber_cms_enveloped_data_t *enveloped_data, int64_t *out_version);

/* originatorInfo：`[0] IMPLICIT OriginatorInfo` 完整原始 TLV；缺省 NULL/0。 */
ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_data_originator_info_tlv(
    const asnber_cms_enveloped_data_t *enveloped_data, const uint8_t **out_data,
    size_t *out_size);

/* recipientInfos 条目数（schema 已保证至少 1 条）。 */
ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_data_recipient_count(
    const asnber_cms_enveloped_data_t *enveloped_data, size_t *out_count);

/* 按下标返回 RecipientInfo 分支判别值 ASNBER_CMS_RECIPIENT_*。 */
ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_data_recipient_choice(
    const asnber_cms_enveloped_data_t *enveloped_data, size_t index,
    int *out_choice);

/*
 * 按下标返回该分支的完整原始 TLV（ktri 为 SEQUENCE，kari..ori 为 `[n]`）。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_data_recipient_tlv(
    const asnber_cms_enveloped_data_t *enveloped_data, size_t index,
    const uint8_t **out_data, size_t *out_size);

/* ktri / kari / kekri / pwri 的 version；ori 返回 ASNBER_E_UNSUPPORTED。 */
ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_data_recipient_version(
    const asnber_cms_enveloped_data_t *enveloped_data, size_t index,
    int64_t *out_version);

/*
 * ktri / kari / kekri / pwri 的 keyEncryptionAlgorithm：OID 点分文本 +
 * parameters 完整原始 TLV（缺省 NULL/0）；ori 返回 ASNBER_E_UNSUPPORTED。
 */
ASNBER_CMS_API asnber_err_t
asnber_cms_enveloped_data_recipient_key_encryption_algorithm(
    const asnber_cms_enveloped_data_t *enveloped_data, size_t index,
    const char **out_oid, size_t *out_oid_size,
    const uint8_t **out_parameters, size_t *out_parameters_size);

/*
 * ktri / kekri / pwri 的 encryptedKey 内容字节（不含 tag/len）；kari 与
 * ori 返回 ASNBER_E_UNSUPPORTED。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_data_recipient_encrypted_key(
    const asnber_cms_enveloped_data_t *enveloped_data, size_t index,
    const uint8_t **out_data, size_t *out_size);

/* kekri.kekid.keyIdentifier 内容字节（不含 tag/len）；非 kekri 返回 UNSUPPORTED。 */
ASNBER_CMS_API asnber_err_t
asnber_cms_enveloped_data_recipient_kekri_key_identifier(
    const asnber_cms_enveloped_data_t *enveloped_data, size_t index,
    const uint8_t **out_data, size_t *out_size);

/*
 * pwri.keyDerivationAlgorithm：`[0] IMPLICIT AlgorithmIdentifier` 完整原始
 * TLV；字段缺省返回 ASNBER_OK 且 NULL/0。非 pwri 返回 UNSUPPORTED。
 */
ASNBER_CMS_API asnber_err_t
asnber_cms_enveloped_data_recipient_pwri_key_derivation_algorithm_tlv(
    const asnber_cms_enveloped_data_t *enveloped_data, size_t index,
    const uint8_t **out_data, size_t *out_size);

/* ori.oriType：OID 点分文本；非 ori 返回 UNSUPPORTED。 */
ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_data_recipient_ori_type(
    const asnber_cms_enveloped_data_t *enveloped_data, size_t index,
    const char **out_oid, size_t *out_oid_size);

/* ori.oriValue：ANY 完整原始 TLV；非 ori 返回 UNSUPPORTED。 */
ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_data_recipient_ori_value_tlv(
    const asnber_cms_enveloped_data_t *enveloped_data, size_t index,
    const uint8_t **out_data, size_t *out_size);

/* ktri.rid 分支判别值 ASNBER_CMS_RID_*；非 ktri 分支返回 UNSUPPORTED。 */
ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_data_recipient_rid_choice(
    const asnber_cms_enveloped_data_t *enveloped_data, size_t index,
    int *out_choice);

/*
 * ktri.rid.issuerAndSerialNumber 的 issuer / serialNumber 完整原始 TLV。
 * issuer 不解析 RDN。rid 不是该分支时返回 ASNBER_E_UNSUPPORTED。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_data_recipient_rid_issuer_tlv(
    const asnber_cms_enveloped_data_t *enveloped_data, size_t index,
    const uint8_t **out_data, size_t *out_size);

ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_data_recipient_rid_serial_tlv(
    const asnber_cms_enveloped_data_t *enveloped_data, size_t index,
    const uint8_t **out_data, size_t *out_size);

/*
 * serialNumber 严格十进制文本写入调用方缓冲（以 NUL 结尾）。buf_size 不足
 * （需要 out_size + 1 字节）返回 ASNBER_E_INVALID_ARG；rid 不是该分支返回
 * ASNBER_E_UNSUPPORTED。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_data_recipient_rid_serial_decimal(
    const asnber_cms_enveloped_data_t *enveloped_data, size_t index, char *buf,
    size_t buf_size, size_t *out_size);

/* ktri.rid.subjectKeyIdentifier 内容字节（不含 tag/len）。 */
ASNBER_CMS_API asnber_err_t
asnber_cms_enveloped_data_recipient_rid_subject_key_id(
    const asnber_cms_enveloped_data_t *enveloped_data, size_t index,
    const uint8_t **out_data, size_t *out_size);

/* kari.originator 分支判别值 ASNBER_CMS_ORIGINATOR_*；非 kari 返回 UNSUPPORTED。 */
ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_data_recipient_originator_choice(
    const asnber_cms_enveloped_data_t *enveloped_data, size_t index,
    int *out_choice);

/* kari.originator `[0] EXPLICIT` 包装的完整原始 TLV。 */
ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_data_recipient_originator_tlv(
    const asnber_cms_enveloped_data_t *enveloped_data, size_t index,
    const uint8_t **out_data, size_t *out_size);

/* kari.recipientEncryptedKeys 元素个数；非 kari 返回 UNSUPPORTED。 */
ASNBER_CMS_API asnber_err_t
asnber_cms_enveloped_data_recipient_kari_encrypted_key_count(
    const asnber_cms_enveloped_data_t *enveloped_data, size_t index,
    size_t *out_count);

/* EncryptedContentInfo.contentType：OID 点分文本（借用句柄）。 */
ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_data_content_type(
    const asnber_cms_enveloped_data_t *enveloped_data, const char **out_oid,
    size_t *out_oid_size);

/* EncryptedContentInfo.contentEncryptionAlgorithm：OID + parameters TLV。 */
ASNBER_CMS_API asnber_err_t
asnber_cms_enveloped_data_content_encryption_algorithm(
    const asnber_cms_enveloped_data_t *enveloped_data, const char **out_oid,
    size_t *out_oid_size, const uint8_t **out_parameters,
    size_t *out_parameters_size);

/*
 * encryptedContent 内容字节（不含 tag/len）。`[0] IMPLICIT OCTET STRING` 的
 * BER 构造形式按核心既有 OCTET STRING 合并规则展平；字段缺省时 NULL/0。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_data_encrypted_content(
    const asnber_cms_enveloped_data_t *enveloped_data, const uint8_t **out_data,
    size_t *out_size);

/* encryptedContent 完整原始 TLV（含 `[0]` 标签）；缺省 NULL/0。 */
ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_data_encrypted_content_tlv(
    const asnber_cms_enveloped_data_t *enveloped_data, const uint8_t **out_data,
    size_t *out_size);

/*
 * unprotectedAttrs：`[1] IMPLICIT SET OF Attribute` 完整原始 TLV；缺省
 * 返回 ASNBER_OK 且 NULL/0。不解析属性内容。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_data_unprotected_attrs_tlv(
    const asnber_cms_enveloped_data_t *enveloped_data, const uint8_t **out_data,
    size_t *out_size);


#ifdef __cplusplus
}
#endif

#endif /* ASNBER_CMS_ENVELOPED_DATA_H_INCLUDED */
