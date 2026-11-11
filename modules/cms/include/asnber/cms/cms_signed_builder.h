/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-cms 公共子头文件：ContentInfo / SignedData 构造（写）。
 */

#ifndef ASNBER_CMS_SIGNED_BUILDER_H_INCLUDED
#define ASNBER_CMS_SIGNED_BUILDER_H_INCLUDED

#include <asnber/cms/cms_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* 结构构造（写）：ContentInfo / SignedData builder                            */
/* ------------------------------------------------------------------------- */

/*
 * 只做结构构造与 DER 编码：证书/CRL 原始 DER、算法 OID、eContent、签名值、
 * 属性集合等全部由调用方给值，模块原样承载。不做签名生成、摘要计算、
 * 加密/解密、证书链校验、时间与随机数生成。
 *
 * 责任边界：
 * - CMSVersion 由调用方通过 asnber_cms_builder_set_version 显式给出，模块不
 *   推导、不校验范围；
 * - signedAttrs / unsignedAttrs 原样承载：输入必须是完整、规范的
 *   `SET OF` TLV（外层 `0x31`），集合非空且每个元素为 `SEQUENCE`
 *   （Attribute）；模块只把外层标签改写为 `0xA0`（signedAttrs）或
 *   `0xA1`（unsignedAttrs），长度字节与内容逐字节不变，不重建、不排序。
 *   签名覆盖的是 SET OF 编码，调用方必须对同一份字节签名，否则验签失败；
 * - certificates / crls 校验“恰好一个完整规范 DER TLV”与分支根标签
 *   （证书 SEQUENCE 或 [0..3]；CRL SEQUENCE 或 other [1]），不解析内部、
 *   不做信任判断；输出按 DER `SET OF` 规则排序。
 *
 * 生命周期：create 建立句柄，逐项设置/追加，encode 编码到调用方缓冲，
 * destroy 释放。destroy(NULL) 为空操作；同一句柄只能 destroy 一次，重复
 * destroy 或使用已销毁指针为未定义行为（句柄指针归调用方所有，库无法置空）。
 * 句柄借用调用方的 asnber_ctx_t，必须在其 ctx 销毁前 destroy；跨 ctx 使用
 * 行为未定义。所有输入字节在调用返回时已复制进模块内存，调用方可立即释放
 * 原缓冲。
 */

typedef struct asnber_cms_builder asnber_cms_builder_t;

/* 创建/销毁 builder。create 失败时 *out_builder 置 NULL。 */
ASNBER_CMS_API asnber_err_t asnber_cms_builder_create(
    asnber_ctx_t *ctx, asnber_cms_builder_t **out_builder);

ASNBER_CMS_API void asnber_cms_builder_destroy(asnber_cms_builder_t *builder);

/*
 * 设置 CMSVersion（SignedData.version）。必填，重复设置返回
 * ASNBER_E_INVALID_STATE。值原样写入，不推导、不校验范围。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_builder_set_version(
    asnber_cms_builder_t *builder, int64_t version);

/*
 * 追加 digestAlgorithms 条目（至少一条）。oid 为点分十进制；params 为
 * 可选的完整 DER TLV（为空表示 parameters 缺省）。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_builder_add_digest_algorithm(
    asnber_cms_builder_t *builder, const char *oid, const uint8_t *params,
    size_t params_size);

/* 设置 encapContentInfo.eContentType OID。必填，重复设置返回 INVALID_STATE。 */
ASNBER_CMS_API asnber_err_t asnber_cms_builder_set_econtent_type(
    asnber_cms_builder_t *builder, const char *oid);

/*
 * 设置 encapContentInfo.eContent。econtent 必须是完整 DER OCTET STRING TLV
 * （tag 0x04）；模块取其中的内容字节。不设置即 detached。重复设置返回
 * ASNBER_E_INVALID_STATE。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_builder_set_econtent(
    asnber_cms_builder_t *builder, const uint8_t *econtent, size_t econtent_size);

/*
 * 追加证书 / CRL：各为恰好一个完整、规范的 DER TLV。除单 TLV 与规范性
 * 校验外，还检查分支根标签：证书须为 Certificate 的 SEQUENCE 或
 * CertificateChoices 的 [0..3] 备选；CRL 须为 CertificateList 的
 * SEQUENCE 或 RevocationInfoChoice 的 other [1]。模块不解析内部字段；
 * 输出按 DER SET OF 排序。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_builder_add_certificate(
    asnber_cms_builder_t *builder, const uint8_t *tlv, size_t tlv_size);

ASNBER_CMS_API asnber_err_t asnber_cms_builder_add_crl(
    asnber_cms_builder_t *builder, const uint8_t *tlv, size_t tlv_size);

/*
 * 追加 SignerInfo（至少一条）。
 *
 * sid_kind = ASNBER_CMS_SID_ISSUER_AND_SERIAL：
 *   sid1 = issuer Name 的完整 DER TLV（须为 SEQUENCE），sid2 =
 *   serialNumber 的完整 DER TLV（须为 INTEGER）；两者都必须完整规范。
 * sid_kind = ASNBER_CMS_SID_SUBJECT_KEY_IDENTIFIER：
 *   sid1 = subjectKeyIdentifier 内容字节（不含 tag/len），sid2 必须为空。
 *
 * digest_params / signature_params 为空表示 parameters 缺省，否则为完整
 * DER TLV。signed_attrs_tlv / unsigned_attrs_tlv 为空表示缺省，否则为
 * 非空 SET OF Attribute（外层 0x31，元素为 SEQUENCE），按上文规则原样
 * 承载并改写外层标签；根标签不符返回 ASNBER_E_INVALID_VALUE。
 * signature 为 OCTET STRING 内容字节。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_builder_add_signer(
    asnber_cms_builder_t *builder, int64_t version, int32_t sid_kind,
    const uint8_t *sid1, size_t sid1_size, const uint8_t *sid2,
    size_t sid2_size, const char *digest_oid, const uint8_t *digest_params,
    size_t digest_params_size, const uint8_t *signed_attrs_tlv,
    size_t signed_attrs_size, const char *signature_oid,
    const uint8_t *signature_params, size_t signature_params_size,
    const uint8_t *signature, size_t signature_size,
    const uint8_t *unsigned_attrs_tlv, size_t unsigned_attrs_size);

/*
 * 组装并编码 ContentInfo（contentType = id-signedData）。
 *
 * 成功时 out_buf 由上下文分配，调用方用 asnber_buf_release 归还；失败时
 * out_buf 清零且不产出半成品。version 与 eContentType 必填。没有签名者时
 * 必须至少有一张证书或一份 CRL（certificates-only / CRL-only，digestAlgorithms
 * 允许为空）；有签名者时必须至少有一条 digestAlgorithm。不满足时返回
 * ASNBER_E_INVALID_STATE。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_builder_encode(
    const asnber_cms_builder_t *builder, asnber_buf_t *out_buf);


#ifdef __cplusplus
}
#endif

#endif /* ASNBER_CMS_SIGNED_BUILDER_H_INCLUDED */
