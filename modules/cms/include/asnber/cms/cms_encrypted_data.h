/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-cms 公共子头文件：EncryptedData（RFC 5652 第 8 节）只读访问。
 */

#ifndef ASNBER_CMS_ENCRYPTED_DATA_H_INCLUDED
#define ASNBER_CMS_ENCRYPTED_DATA_H_INCLUDED

#include <asnber/cms/cms_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* EncryptedData（RFC 5652 第 8 节，只读）                                     */
/* ------------------------------------------------------------------------- */

/*
 * 打开 DER 编码的 EncryptedData（**不含外层 ContentInfo**）。调用方先用
 * asnber_cms_content_info_open + asnber_cms_content_info_content 取 `[0]` 内层
 * TLV，再传入本函数；模块不提供自动剥壳入口。
 *
 * 只读结构访问：不解密、不派生密钥、不校验 MAC、不展开算法参数或属性
 * 内容。version 原样返回，不在此处校验 0/2 语义。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_encrypted_data_open(
    asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asnber_cms_encrypted_data_t **out_encrypted_data);

ASNBER_CMS_API void asnber_cms_encrypted_data_close(
    asnber_cms_encrypted_data_t *encrypted_data);

/* version：原样返回 CMSVersion 整数值，不做范围校验。 */
ASNBER_CMS_API asnber_err_t asnber_cms_encrypted_data_version(
    const asnber_cms_encrypted_data_t *encrypted_data, int64_t *out_version);

/* EncryptedContentInfo.contentType：OID 点分文本（借用句柄）。 */
ASNBER_CMS_API asnber_err_t asnber_cms_encrypted_data_content_type(
    const asnber_cms_encrypted_data_t *encrypted_data, const char **out_oid,
    size_t *out_oid_size);

/* EncryptedContentInfo.contentEncryptionAlgorithm：OID + parameters TLV。 */
ASNBER_CMS_API asnber_err_t asnber_cms_encrypted_data_content_encryption_algorithm(
    const asnber_cms_encrypted_data_t *encrypted_data, const char **out_oid,
    size_t *out_oid_size, const uint8_t **out_parameters,
    size_t *out_parameters_size);

/*
 * encryptedContent 内容字节（不含 tag/len）。`[0] IMPLICIT OCTET STRING` 的
 * BER 构造形式按核心既有 OCTET STRING 合并规则展平；字段缺省（detached）
 * 返回 ASNBER_OK 且 NULL/0。空内容 `80 00` 返回非 NULL、size 0。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_encrypted_data_encrypted_content(
    const asnber_cms_encrypted_data_t *encrypted_data, const uint8_t **out_data,
    size_t *out_size);

/* encryptedContent 完整原始 TLV（含 `[0]` 标签）；字段缺省返回 NULL/0。 */
ASNBER_CMS_API asnber_err_t asnber_cms_encrypted_data_encrypted_content_tlv(
    const asnber_cms_encrypted_data_t *encrypted_data, const uint8_t **out_data,
    size_t *out_size);

/*
 * unprotectedAttrs：`[1] IMPLICIT SET OF Attribute` 完整原始 TLV；缺省
 * 返回 ASNBER_OK 且 NULL/0。不解析属性内容。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_encrypted_data_unprotected_attrs_tlv(
    const asnber_cms_encrypted_data_t *encrypted_data, const uint8_t **out_data,
    size_t *out_size);


#ifdef __cplusplus
}
#endif

#endif /* ASNBER_CMS_ENCRYPTED_DATA_H_INCLUDED */
