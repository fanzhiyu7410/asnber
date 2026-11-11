/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-cms 公共子头文件：AuthenticatedData 构造（写）。
 */

#ifndef ASNBER_CMS_AUTHENTICATED_BUILDER_H_INCLUDED
#define ASNBER_CMS_AUTHENTICATED_BUILDER_H_INCLUDED

#include <asnber/cms/cms_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* 结构构造（写）：AuthenticatedData builder                                   */
/* ------------------------------------------------------------------------- */

/*
 * 只做结构构造与 DER 编码：recipientInfos 以预编码 TLV 传入，MAC 算法、
 * 摘要算法、认证属性、MAC 值与内容全部由调用方给值，模块原样承载。不做
 * MAC 计算/校验、不计算摘要、不做密钥派生或解密。
 *
 * 组合约束：
 * - version / recipientInfos / macAlgorithm / eContentType / mac 必填；
 * - set_version 只接受 0 / 1 / 3，其他值立即返回 ASNBER_E_INVALID_VALUE；
 *   version 与 originatorInfo 内部证书类型的配对由调用方负责，encode 只
 *   检查非 0 version 必须带 originatorInfo；
 * - digestAlgorithm 与 authAttrs 必须同时出现或同时缺省；eContentType
 *   不是 id-data 时 authAttrs 必填；
 * - originatorInfo 输入为已带 `[0]` 标签的完整 TLV；digestAlgorithm 输入
 *   为已带 `[1]` 标签的完整 TLV；authAttrs/unauthAttrs 输入外层 0x31，
 *   模块分别改写为 0xA2/0xA3；
 * - eContent 可缺省，表示 detached 形式；
 * - 每个单值字段只允许设置一次，重复设置返回 ASNBER_E_INVALID_STATE。
 */

typedef struct asnber_cms_authenticated_builder asnber_cms_authenticated_builder_t;

ASNBER_CMS_API asnber_err_t asnber_cms_authenticated_builder_create(
    asnber_ctx_t *ctx, asnber_cms_authenticated_builder_t **out_builder);

ASNBER_CMS_API void asnber_cms_authenticated_builder_destroy(
    asnber_cms_authenticated_builder_t *builder);

/* AuthenticatedData.version。必填；只接受 0 / 1 / 3。 */
ASNBER_CMS_API asnber_err_t asnber_cms_authenticated_builder_set_version(
    asnber_cms_authenticated_builder_t *builder, int64_t version);

/*
 * originatorInfo：完整 `[0] IMPLICIT OriginatorInfo` TLV（外层 0xA0）。
 * 可选，重复设置返回 INVALID_STATE。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_authenticated_builder_set_originator_info(
    asnber_cms_authenticated_builder_t *builder, const uint8_t *tlv,
    size_t tlv_size);

/*
 * 追加一条 RecipientInfo。输入为完整、规范 DER TLV：ktri 为 SEQUENCE，
 * kari..ori 为 `[1]`..`[4]` 构造标签；模块只校验分支根标签，内部字段由
 * 调用方保证。至少添加一条才能 encode。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_authenticated_builder_add_recipient(
    asnber_cms_authenticated_builder_t *builder, const uint8_t *tlv,
    size_t tlv_size);

/* macAlgorithm。必填，重复设置返回 INVALID_STATE。 */
ASNBER_CMS_API asnber_err_t asnber_cms_authenticated_builder_set_mac_algorithm(
    asnber_cms_authenticated_builder_t *builder, const char *oid,
    const uint8_t *params, size_t params_size);

/*
 * digestAlgorithm：完整 `[1] IMPLICIT AlgorithmIdentifier` TLV（外层 0xA1）。
 * 可选；设置时 authAttrs 也必须设置。重复设置返回 INVALID_STATE。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_authenticated_builder_set_digest_algorithm(
    asnber_cms_authenticated_builder_t *builder, const uint8_t *tlv,
    size_t tlv_size);

/* EncapsulatedContentInfo.eContentType。必填，重复设置 INVALID_STATE。 */
ASNBER_CMS_API asnber_err_t asnber_cms_authenticated_builder_set_econtent_type(
    asnber_cms_authenticated_builder_t *builder, const char *oid);

/*
 * eContent：OCTET STRING 内容字节（不含 tag/len）。可选；不设置即 detached。
 * 允许空内容。重复设置返回 ASNBER_E_INVALID_STATE。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_authenticated_builder_set_econtent(
    asnber_cms_authenticated_builder_t *builder, const uint8_t *data, size_t size);

/*
 * authAttrs：完整、非空 `SET OF Attribute`（外层 0x31，元素为 SEQUENCE）。
 * 模块把外层标签改写为 0xA2，长度与内容逐字节不变。
 * 可选；设置时 digestAlgorithm 也必须设置。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_authenticated_builder_set_auth_attrs(
    asnber_cms_authenticated_builder_t *builder, const uint8_t *tlv,
    size_t tlv_size);

/* mac：OCTET STRING 内容字节（不含 tag/len）。必填，允许空 MAC。 */
ASNBER_CMS_API asnber_err_t asnber_cms_authenticated_builder_set_mac(
    asnber_cms_authenticated_builder_t *builder, const uint8_t *data,
    size_t size);

/*
 * unauthAttrs：完整、非空 `SET OF Attribute`（外层 0x31，元素为 SEQUENCE）。
 * 模块把外层标签改写为 0xA3，长度与内容逐字节不变。可选。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_authenticated_builder_set_unauth_attrs(
    asnber_cms_authenticated_builder_t *builder, const uint8_t *tlv,
    size_t tlv_size);

/*
 * 组装并编码 ContentInfo（contentType = id-ct-authData）。
 * 成功时 out_buf 由上下文分配，调用方用 asnber_buf_release 归还；失败时
 * out_buf 清零且不产出半成品。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_authenticated_builder_encode(
    const asnber_cms_authenticated_builder_t *builder, asnber_buf_t *out_buf);


#ifdef __cplusplus
}
#endif

#endif /* ASNBER_CMS_AUTHENTICATED_BUILDER_H_INCLUDED */
