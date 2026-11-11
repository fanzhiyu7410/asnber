/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-pkcs12 公共头文件（RFC 7292 只读结构访问）。
 *
 * 只读语义：不解密 SafeContents、不做口令密钥派生、不验 MAC、不验证证书；
 * content 与 bagValue 只返回完整原始 TLV，内层语义由调用方按
 * contentType / bagId 解释。
 *
 * 生命周期：句柄由 open 创建、close 销毁；内部文档与 schema 随句柄创建
 * 和销毁。句柄借用调用方的 asnber_ctx_t，ctx 必须比句柄存活更久。所有由
 * 访问器返回的指针均借用句柄，close 后立即失效。
 */

#ifndef ASNBER_PKCS12_PKCS12_H_INCLUDED
#define ASNBER_PKCS12_PKCS12_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include <asnber/asnber_build.h>
#include <asnber/asnber_node.h>

#if defined(ASNBER_PKCS12_STATIC)
#define ASNBER_PKCS12_API
#elif defined(_WIN32) || defined(__CYGWIN__)
#if defined(ASNBER_PKCS12_BUILDING_LIBRARY)
#define ASNBER_PKCS12_API __declspec(dllexport)
#else
#define ASNBER_PKCS12_API __declspec(dllimport)
#endif
#elif defined(__GNUC__) && __GNUC__ >= 4
#define ASNBER_PKCS12_API __attribute__((visibility("default")))
#else
#define ASNBER_PKCS12_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* 不透明句柄；具体布局属于模块私有实现。 */
typedef struct asnber_pkcs12_pfx asnber_pkcs12_pfx_t;
typedef struct asnber_pkcs12_authenticated_safe
    asnber_pkcs12_authenticated_safe_t;
typedef struct asnber_pkcs12_safe_contents asnber_pkcs12_safe_contents_t;
typedef struct asnber_pkcs12_cert_bag asnber_pkcs12_cert_bag_t;

/* ------------------------------------------------------------------------- */
/* PKCS#12 PFX（RFC 7292 附录 D）                                             */
/* ------------------------------------------------------------------------- */

/*
 * 打开 DER 编码的 PFX。
 *
 * 输入被复制进文档 arena，调用方可在 open 返回后释放 der；失败时
 * *out_pfx 置 NULL 并返回核心错误码。
 */
ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_pfx_open(
    asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asnber_pkcs12_pfx_t **out_pfx);

/* 关闭句柄；pfx == NULL 为空操作。 */
ASNBER_PKCS12_API void asnber_pkcs12_pfx_close(asnber_pkcs12_pfx_t *pfx);

/*
 * PFX.version。RFC 7292 只定义 v3 = 3；非 3 的输入按原值返回，不在解码期
 * 被值名约束拒绝。需要判断 v3 时由调用方比较 *out_version == 3。
 */
ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_pfx_version(
    const asnber_pkcs12_pfx_t *pfx, int64_t *out_version);

/* authSafe.contentType：OID 点分十进制文本（借用句柄）。 */
ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_pfx_auth_safe_content_type(
    const asnber_pkcs12_pfx_t *pfx, const char **out_dotted,
    size_t *out_size);

/*
 * authSafe.content 的内层完整 TLV（含 tag/len，借用句柄）。
 *
 * 常见形态：contentType = data 时为包住 AuthenticatedSafe DER 的 OCTET
 * STRING；口令加密时为 encryptedData 的 SEQUENCE。模块不递归解析，也不
 * 剥去 OCTET STRING 的 tag/len。content 缺省时返回 ASNBER_OK + NULL/0。
 */
ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_pfx_auth_safe_content_tlv(
    const asnber_pkcs12_pfx_t *pfx, const uint8_t **out_data,
    size_t *out_size);

/* macData 是否存在：1 存在、0 缺省。 */
ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_pfx_mac_present(
    const asnber_pkcs12_pfx_t *pfx, int *out_present);

/* 以下 mac* 访问器在 macData 缺省时返回 ASNBER_E_SCHEMA_FIELD。 */

/* macData.mac.digestAlgorithm.algorithm：OID 点分十进制文本（借用句柄）。 */
ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_pfx_mac_digest_algorithm_oid(
    const asnber_pkcs12_pfx_t *pfx, const char **out_dotted,
    size_t *out_size);

/* macData.mac.digestAlgorithm.parameters：ANY 原始 TLV；缺省返回 NULL/0。 */
ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_pfx_mac_digest_algorithm_parameters(
    const asnber_pkcs12_pfx_t *pfx, const uint8_t **out_data,
    size_t *out_size);

/* macData.mac.digest：OCTET STRING 内容字节（借用句柄，不验 MAC）。 */
ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_pfx_mac_digest(
    const asnber_pkcs12_pfx_t *pfx, const uint8_t **out_data,
    size_t *out_size);

/* macData.macSalt：OCTET STRING 内容字节（借用句柄）。 */
ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_pfx_mac_salt(
    const asnber_pkcs12_pfx_t *pfx, const uint8_t **out_data,
    size_t *out_size);

/* macData.iterations。字段缺省时按 DEFAULT 1 返回 1；不改变文档内容。 */
ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_pfx_mac_iterations(
    const asnber_pkcs12_pfx_t *pfx, int64_t *out_iterations);

/* ------------------------------------------------------------------------- */
/* PKCS#12 AuthenticatedSafe（RFC 7292：SEQUENCE OF ContentInfo）             */
/* ------------------------------------------------------------------------- */

/*
 * 打开 DER 编码的 AuthenticatedSafe。
 *
 * 调用方通常先从 PFX.authSafe.content 的 OCTET STRING 中取出内容字节
 *（contentType = data），或解密 encryptedData 后得到该 DER。模块只做结构
 * 解码，不区分来源。
 */
ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_authenticated_safe_open(
    asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asnber_pkcs12_authenticated_safe_t **out_safe);

ASNBER_PKCS12_API void asnber_pkcs12_authenticated_safe_close(
    asnber_pkcs12_authenticated_safe_t *safe);

/* ContentInfo 个数。 */
ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_authenticated_safe_content_count(
    const asnber_pkcs12_authenticated_safe_t *safe, size_t *out_count);

/*
 * 按下标访问 ContentInfo：contentType OID + content 内层完整 TLV。
 *
 * contentType 常见值：data（1.2.840.113549.1.7.1，明文 SafeContents 装在
 * OCTET STRING 中）、encryptedData（1.2.840.113549.1.7.6，口令加密）、
 * envelopedData（1.2.840.113549.1.7.3，公钥加密）。content 缺省时
 * *out_content 为 NULL、*out_content_size 为 0。index 越界返回
 * ASNBER_E_INVALID_ARG。
 */
ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_authenticated_safe_content_at(
    const asnber_pkcs12_authenticated_safe_t *safe, size_t index,
    const char **out_type_oid, size_t *out_type_oid_size,
    const uint8_t **out_content, size_t *out_content_size);

/* ------------------------------------------------------------------------- */
/* PKCS#12 SafeContents / SafeBag（RFC 7292）                                 */
/* ------------------------------------------------------------------------- */

/* 打开已解密的 DER 编码 SafeContents（SEQUENCE OF SafeBag）。 */
ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_safe_contents_open(
    asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asnber_pkcs12_safe_contents_t **out_contents);

ASNBER_PKCS12_API void asnber_pkcs12_safe_contents_close(
    asnber_pkcs12_safe_contents_t *contents);

/* SafeBag 个数。 */
ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_safe_contents_bag_count(
    const asnber_pkcs12_safe_contents_t *contents, size_t *out_count);

/*
 * 按下标访问 SafeBag。
 *
 * - bagId：OID 点分十进制文本（借用句柄）。常见值：
 *   keyBag 1.2.840.113549.1.12.10.1.1、
 *   pkcs8ShroudedKeyBag 1.2.840.113549.1.12.10.1.2、
 *   certBag 1.2.840.113549.1.12.10.1.3、
 *   crlBag 1.2.840.113549.1.12.10.1.4、
 *   secretBag 1.2.840.113549.1.12.10.1.5、
 *   safeContentsBag 1.2.840.113549.1.12.10.1.6。
 * - bagValue：bagValue [0] EXPLICIT 内层完整 TLV（含 tag/len）。keyBag 为
 *   PrivateKeyInfo，pkcs8ShroudedKeyBag 为 EncryptedPrivateKeyInfo，certBag
 *   为 CertBag；未知 bagId 同样原样返回。
 * - attribute_count：bagAttributes 的元素数；字段缺省时为 0。
 *
 * index 越界返回 ASNBER_E_INVALID_ARG。
 */
ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_safe_contents_bag_at(
    const asnber_pkcs12_safe_contents_t *contents, size_t index,
    const char **out_bag_id_oid, size_t *out_bag_id_oid_size,
    const uint8_t **out_bag_value_tlv, size_t *out_bag_value_tlv_size,
    size_t *out_attribute_count);

/*
 * 按下标访问 SafeBag 中的 PKCS12Attribute：attrId OID + attrValues 节点
 *（SET OF ANY，借用句柄）。bag_index 或 attribute_index 越界返回
 * ASNBER_E_INVALID_ARG。
 */
ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_safe_contents_bag_attribute_at(
    const asnber_pkcs12_safe_contents_t *contents, size_t bag_index,
    size_t attribute_index, const char **out_attr_id_oid,
    size_t *out_attr_id_oid_size, const asnber_node_t **out_values);

/* ------------------------------------------------------------------------- */
/* PKCS#12 CertBag（RFC 7292）                                                */
/* ------------------------------------------------------------------------- */

/* 打开 DER 编码的 CertBag；通常取自 SafeBag.bagValue。 */
ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_cert_bag_open(
    asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asnber_pkcs12_cert_bag_t **out_bag);

ASNBER_PKCS12_API void asnber_pkcs12_cert_bag_close(asnber_pkcs12_cert_bag_t *bag);

/* certId：OID 点分十进制文本（借用句柄）。 */
ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_cert_bag_cert_id(
    const asnber_pkcs12_cert_bag_t *bag, const char **out_dotted,
    size_t *out_size);

/* certValue [0] EXPLICIT 内层完整 TLV（含 tag/len，借用句柄）。 */
ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_cert_bag_cert_value_tlv(
    const asnber_pkcs12_cert_bag_t *bag, const uint8_t **out_data,
    size_t *out_size);

/*
 * X.509 证书字节：仅 certId = x509Certificate
 *（1.2.840.113549.1.9.22.1）且 certValue 内层为 OCTET STRING 时返回其
 * 内容字节（即证书 DER，借用句柄）。其他 certId（如 sdsiCertificate）返回
 * ASNBER_E_UNSUPPORTED，调用方仍可用 cert_value_tlv 取得原始 TLV。
 */
ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_cert_bag_certificate(
    const asnber_pkcs12_cert_bag_t *bag, const uint8_t **out_data,
    size_t *out_size);

#ifdef __cplusplus
}
#endif

/* 构造侧接口（PFX / AuthenticatedSafe）。 */
#include <asnber/pkcs12/pkcs12_builder.h>

#endif /* ASNBER_PKCS12_PKCS12_H_INCLUDED */
