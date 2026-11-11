/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-cms 公共子头文件：EnvelopedData 构造（写）。
 */

#ifndef ASNBER_CMS_ENVELOPED_BUILDER_H_INCLUDED
#define ASNBER_CMS_ENVELOPED_BUILDER_H_INCLUDED

#include <asnber/cms/cms_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* 结构构造（写）：EnvelopedData builder                                       */
/* ------------------------------------------------------------------------- */

/*
 * 只做结构构造与 DER 编码：recipientInfos 各分支、算法 OID、加密后的内容与
 * 属性集合全部由调用方给值，模块原样承载。不做密钥协商、密钥派生、内容
 * 加密/解密、MAC 计算、证书链校验、时间与随机数生成。
 *
 * 与 SignedData builder 相同：
 * - CMSVersion 由调用方显式给出，模块不推导、不校验范围；
 * - 算法 parameters 为空表示缺省，否则必须是完整规范 DER TLV；
 * - 所有输入字节在调用返回时已复制，调用方可立即释放原缓冲。
 *
 * 组合约束（encode 时检查）：
 * - version / contentType / contentEncryptionAlgorithm 必填；
 * - recipientInfos 至少一条（跨全部 add_* 调用累计）；
 * - encryptedContent 可缺省，表示 detached 形式；
 * - 每个单值字段只允许设置一次，重复设置返回 ASNBER_E_INVALID_STATE。
 *
 * 生命周期：create 建立句柄，逐项设置/追加，encode 编码到调用方缓冲，
 * destroy 释放。destroy(NULL) 为空操作；同一句柄只能 destroy 一次，重复
 * destroy 或使用已销毁指针为未定义行为（句柄指针归调用方所有，库无法置空）。
 * 句柄借用调用方的 asnber_ctx_t，必须在其 ctx 销毁前 destroy；跨 ctx 使用
 * 行为未定义。
 */

typedef struct asnber_cms_enveloped_builder asnber_cms_enveloped_builder_t;

ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_builder_create(
    asnber_ctx_t *ctx, asnber_cms_enveloped_builder_t **out_builder);

ASNBER_CMS_API void asnber_cms_enveloped_builder_destroy(
    asnber_cms_enveloped_builder_t *builder);

/* EnvelopedData.version。必填，重复设置返回 ASNBER_E_INVALID_STATE。 */
ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_builder_set_version(
    asnber_cms_enveloped_builder_t *builder, int64_t version);

/*
 * originatorInfo：完整 `[0] IMPLICIT OriginatorInfo` DER TLV（外层 0xA0，
 * 构造形式）。直接子节点只能是可选的 `certs [0]`（0xA0，构造形式）与
 * `crls [1]`（0xA1，构造形式），顺序固定、各至多一次；内部语义不展开。
 * 可选，重复设置返回 ASNBER_E_INVALID_STATE。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_builder_set_originator_info(
    asnber_cms_enveloped_builder_t *builder, const uint8_t *tlv,
    size_t tlv_size);

/*
 * 追加一条 ktri（KeyTransRecipientInfo）。
 *
 * rid_kind = ASNBER_CMS_RID_ISSUER_AND_SERIAL：
 *   rid1 = issuer Name 完整 DER TLV（SEQUENCE），rid2 = serialNumber
 *   完整 DER TLV（INTEGER）。
 * rid_kind = ASNBER_CMS_RID_SUBJECT_KEY_IDENTIFIER：
 *   rid1 = subjectKeyIdentifier 内容字节（不含 tag/len），rid2 必须为空。
 *
 * key_encryption_params 为空表示 parameters 缺省；encrypted_key 为 OCTET
 * STRING 内容字节（可为空，但 encrypted_key_size != 0 时不得为 NULL）。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_builder_add_ktri(
    asnber_cms_enveloped_builder_t *builder, int64_t version, int32_t rid_kind,
    const uint8_t *rid1, size_t rid1_size, const uint8_t *rid2,
    size_t rid2_size, const char *key_encryption_oid,
    const uint8_t *key_encryption_params, size_t key_encryption_params_size,
    const uint8_t *encrypted_key, size_t encrypted_key_size);

/*
 * 追加一条 kari（KeyAgreeRecipientInfo），字段以预构造 TLV 传入：
 * - originator_tlv：完整 `[0] EXPLICIT OriginatorIdentifierOrKey`（0xA0，
 *   构造形式），子节点须为 `issuerAndSerialNumber`（0x30）、
 *   `subjectKeyIdentifier`（0x80，primitive）或 `originatorKey`
 *   （0xA1，constructed）三支之一；
 * - ukm_tlv：可选，完整 `[1] EXPLICIT UserKeyingMaterial`（0xA1），子节点
 *   须为一个 OCTET STRING；NULL/0 表示缺省；
 * - recipient_encrypted_keys_tlv：完整 `RecipientEncryptedKeys`（0x30）。
 *   RFC 5652 未规定下界，允许空序列；每个元素须为 SEQUENCE，且依次为
 *   `rid`（SEQUENCE 或 `[0]` constructed）与 `encryptedKey`（OCTET STRING）。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_builder_add_kari(
    asnber_cms_enveloped_builder_t *builder, int64_t version,
    const uint8_t *originator_tlv, size_t originator_size,
    const uint8_t *ukm_tlv, size_t ukm_size,
    const uint8_t *recipient_encrypted_keys_tlv,
    size_t recipient_encrypted_keys_size, const char *key_encryption_oid,
    const uint8_t *key_encryption_params, size_t key_encryption_params_size);

/*
 * 追加一条 kekri（KEKRecipientInfo）。kekid_tlv 为完整 `KEKIdentifier`
 * （SEQUENCE）：首子节点必须是 OCTET STRING（keyIdentifier），其后可选
 * GeneralizedTime（date）与 SEQUENCE（other），顺序固定；内部语义不展开。
 * encrypted_key 为 OCTET STRING 内容字节。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_builder_add_kekri(
    asnber_cms_enveloped_builder_t *builder, int64_t version,
    const uint8_t *kekid_tlv, size_t kekid_size,
    const char *key_encryption_oid,
    const uint8_t *key_encryption_params, size_t key_encryption_params_size,
    const uint8_t *encrypted_key, size_t encrypted_key_size);

/*
 * 追加一条 pwri（PasswordRecipientInfo）。key_derivation_algorithm_tlv
 * 可选，为完整 `[0] IMPLICIT AlgorithmIdentifier`（0xA0）：子节点为
 * algorithm OID（必填）加可选 parameters（任意单 TLV）；NULL/0 表示缺省。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_builder_add_pwri(
    asnber_cms_enveloped_builder_t *builder, int64_t version,
    const uint8_t *key_derivation_algorithm_tlv,
    size_t key_derivation_algorithm_size, const char *key_encryption_oid,
    const uint8_t *key_encryption_params, size_t key_encryption_params_size,
    const uint8_t *encrypted_key, size_t encrypted_key_size);

/*
 * 追加一条 ori（OtherRecipientInfo）。ori_type 为点分十进制 OID；
 * ori_value_tlv 为 ANY 的完整规范 DER TLV。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_builder_add_ori(
    asnber_cms_enveloped_builder_t *builder, const char *ori_type,
    const uint8_t *ori_value_tlv, size_t ori_value_size);

/* EncryptedContentInfo.contentType。必填，重复设置返回 INVALID_STATE。 */
ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_builder_set_content_type(
    asnber_cms_enveloped_builder_t *builder, const char *oid);

/* EncryptedContentInfo.contentEncryptionAlgorithm。必填，重复设置 INVALID_STATE。 */
ASNBER_CMS_API asnber_err_t
asnber_cms_enveloped_builder_set_content_encryption_algorithm(
    asnber_cms_enveloped_builder_t *builder, const char *oid,
    const uint8_t *params, size_t params_size);

/*
 * EncryptedContentInfo.encryptedContent：OCTET STRING 内容字节（不含
 * tag/len）。可选；不设置即 detached。允许空内容，重复设置返回
 * ASNBER_E_INVALID_STATE。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_builder_set_encrypted_content(
    asnber_cms_enveloped_builder_t *builder, const uint8_t *data, size_t size);

/*
 * unprotectedAttrs：完整、非空 `SET OF Attribute`（外层 0x31，元素为
 * SEQUENCE）。模块把外层标签改写为 0xA1（`[1] IMPLICIT`），长度与内容
 * 逐字节不变。
 * 可选，重复设置返回 ASNBER_E_INVALID_STATE。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_builder_set_unprotected_attrs(
    asnber_cms_enveloped_builder_t *builder, const uint8_t *tlv,
    size_t tlv_size);

/*
 * 组装并编码 ContentInfo（contentType = id-envelopedData）。
 * 成功时 out_buf 由上下文分配，调用方用 asnber_buf_release 归还；失败时
 * out_buf 清零且不产出半成品。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_builder_encode(
    const asnber_cms_enveloped_builder_t *builder, asnber_buf_t *out_buf);


#ifdef __cplusplus
}
#endif

#endif /* ASNBER_CMS_ENVELOPED_BUILDER_H_INCLUDED */
