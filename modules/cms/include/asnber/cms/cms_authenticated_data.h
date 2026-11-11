/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-cms 公共子头文件：AuthenticatedData（RFC 5652 第 9 节）只读访问。
 */

#ifndef ASNBER_CMS_AUTHENTICATED_DATA_H_INCLUDED
#define ASNBER_CMS_AUTHENTICATED_DATA_H_INCLUDED

#include <asnber/cms/cms_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* AuthenticatedData（RFC 5652 第 9 节，只读）                                 */
/* ------------------------------------------------------------------------- */

/*
 * 打开 DER 编码的 AuthenticatedData（**不含外层 ContentInfo**）。调用方先用
 * asnber_cms_content_info_open + asnber_cms_content_info_content 取 `[0]` 内层
 * TLV，再传入本函数；模块不提供自动剥壳入口。
 *
 * 只读结构访问：不校验 MAC、不计算摘要、不做密钥派生/解密、不展开
 * recipientInfo 分支内部字段。**不校验 `authAttrs` 与 `digestAlgorithm`
 * 的耦合**：RFC 5652 要求二者成对出现，但本模块的读侧只做结构投影，
 * 两个方向的缺失（`authAttrs` 有而 `digestAlgorithm` 无、`digestAlgorithm`
 * 有而 `authAttrs` 无）都照常返回 ASNBER_OK。
 * recipientInfos 的 `SET SIZE (1..MAX) OF` 约束由描述表生效；空集合在
 * open 阶段返回 ASNBER_E_SCHEMA_CONSTRAINT（`authAttrs`/`unauthAttrs`
 * 的空 SET 同样由 `SET SIZE (1..MAX)` 拒绝）。
 * version 原样返回，不在此处校验 0/1/3 语义。
 *
 * 未知字段策略：**不启用** `ASNBER_DECODE_STRICT_SCHEMA`。与任何字段都不
 * 匹配的错标签 TLV 按未知字段静默忽略，不报错、不影响其余字段投影；
 * 但根 SEQUENCE 之后的尾随数据仍返回 ASNBER_E_TRAILING_DATA。
 *
 * 指针所有权：所有 `*_tlv` / 字符串 / 字节访问器返回的指针都**借用**
 * 句柄内部的输入缓冲区，不复制、不需释放；`close` 后一律失效。
 * 对同一句柄重复调用 `close` 属未定义行为。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_authenticated_data_open(
    asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asnber_cms_authenticated_data_t **out_authenticated_data);

ASNBER_CMS_API void asnber_cms_authenticated_data_close(
    asnber_cms_authenticated_data_t *authenticated_data);

/* version：原样返回 CMSVersion 整数值，不做范围校验。 */
ASNBER_CMS_API asnber_err_t asnber_cms_authenticated_data_version(
    const asnber_cms_authenticated_data_t *authenticated_data,
    int64_t *out_version);

/*
 * originatorInfo：`[0] IMPLICIT OriginatorInfo` 完整原始 TLV；缺省返回
 * ASNBER_OK 且 NULL/0。不展开 certs/crls 内容。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_authenticated_data_originator_info_tlv(
    const asnber_cms_authenticated_data_t *authenticated_data,
    const uint8_t **out_data, size_t *out_size);

/* recipientInfos 条目数；描述表保证至少 1 条。 */
ASNBER_CMS_API asnber_err_t asnber_cms_authenticated_data_recipient_count(
    const asnber_cms_authenticated_data_t *authenticated_data,
    size_t *out_count);

/*
 * 按下标返回一条 RecipientInfo：分支判别值 ASNBER_CMS_RECIPIENT_* 与完整
 * 原始 TLV。分支内部字段不在此展开，调用方可按分支自行二次解析。
 * `index` 越界（含等于条目数）返回 ASNBER_E_INVALID_ARG，并把 out 参数
 * 复位为 -1 / NULL / 0；越界调用不影响句柄后续读取。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_authenticated_data_recipient_at(
    const asnber_cms_authenticated_data_t *authenticated_data, size_t index,
    int *out_kind, const uint8_t **out_tlv, size_t *out_tlv_size);

/* macAlgorithm：OID + parameters TLV（缺省时 NULL/0）。 */
ASNBER_CMS_API asnber_err_t asnber_cms_authenticated_data_mac_algorithm(
    const asnber_cms_authenticated_data_t *authenticated_data,
    const char **out_oid, size_t *out_oid_size,
    const uint8_t **out_parameters, size_t *out_parameters_size);

/*
 * digestAlgorithm：`[1] IMPLICIT DigestAlgorithmIdentifier` 的 OID +
 * parameters TLV；字段缺省返回 ASNBER_OK 且 NULL/0。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_authenticated_data_digest_algorithm(
    const asnber_cms_authenticated_data_t *authenticated_data,
    const char **out_oid, size_t *out_oid_size,
    const uint8_t **out_parameters, size_t *out_parameters_size);

/* EncapsulatedContentInfo.eContentType：OID 点分文本。 */
ASNBER_CMS_API asnber_err_t asnber_cms_authenticated_data_econtent_type(
    const asnber_cms_authenticated_data_t *authenticated_data,
    const char **out_oid, size_t *out_oid_size);

/*
 * eContent 内容字节（不含 tag/len）。字段缺省（detached）返回 ASNBER_OK 且
 * NULL/0；空内容返回非 NULL、size 0。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_authenticated_data_econtent(
    const asnber_cms_authenticated_data_t *authenticated_data,
    const uint8_t **out_data, size_t *out_size);

/* eContent 内层 OCTET STRING 的完整原始 TLV（不含外层 `[0]` 包装）；缺省 NULL/0。 */
ASNBER_CMS_API asnber_err_t asnber_cms_authenticated_data_econtent_tlv(
    const asnber_cms_authenticated_data_t *authenticated_data,
    const uint8_t **out_data, size_t *out_size);

/*
 * authAttrs：`[2] IMPLICIT SET OF Attribute` 完整原始 TLV；缺省返回
 * ASNBER_OK 且 NULL/0。不解析属性内容。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_authenticated_data_auth_attrs_tlv(
    const asnber_cms_authenticated_data_t *authenticated_data,
    const uint8_t **out_data, size_t *out_size);

/* mac：OCTET STRING 内容字节（不含 tag/len）；空 MAC 返回非 NULL、size 0。 */
ASNBER_CMS_API asnber_err_t asnber_cms_authenticated_data_mac(
    const asnber_cms_authenticated_data_t *authenticated_data,
    const uint8_t **out_data, size_t *out_size);

/* mac：完整原始 TLV。 */
ASNBER_CMS_API asnber_err_t asnber_cms_authenticated_data_mac_tlv(
    const asnber_cms_authenticated_data_t *authenticated_data,
    const uint8_t **out_data, size_t *out_size);

/*
 * unauthAttrs：`[3] IMPLICIT SET OF Attribute` 完整原始 TLV；缺省返回
 * ASNBER_OK 且 NULL/0。不解析属性内容。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_authenticated_data_unauth_attrs_tlv(
    const asnber_cms_authenticated_data_t *authenticated_data,
    const uint8_t **out_data, size_t *out_size);


#ifdef __cplusplus
}
#endif

#endif /* ASNBER_CMS_AUTHENTICATED_DATA_H_INCLUDED */
