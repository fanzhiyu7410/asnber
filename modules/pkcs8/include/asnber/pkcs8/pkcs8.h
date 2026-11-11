/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-pkcs8 公共头文件（RFC 5208 只读结构访问）。
 *
 * 只读语义：不解密、不做密钥解析；algorithm.parameters 与
 * attributes.values 只返回完整原始 TLV，由调用方按 OID 二次解析。
 *
 * 生命周期：句柄由 open 创建、close 销毁；内部文档与 schema 随句柄创建
 * 和销毁。句柄借用调用方的 asnber_ctx_t，ctx 必须比句柄存活更久。所有由
 * 访问器返回的指针均借用句柄，close 后立即失效。
 */

#ifndef ASNBER_PKCS8_PKCS8_H_INCLUDED
#define ASNBER_PKCS8_PKCS8_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include <asnber/asnber_build.h>
#include <asnber/asnber_node.h>

#if defined(ASNBER_PKCS8_STATIC)
#define ASNBER_PKCS8_API
#elif defined(_WIN32) || defined(__CYGWIN__)
#if defined(ASNBER_PKCS8_BUILDING_LIBRARY)
#define ASNBER_PKCS8_API __declspec(dllexport)
#else
#define ASNBER_PKCS8_API __declspec(dllimport)
#endif
#elif defined(__GNUC__) && __GNUC__ >= 4
#define ASNBER_PKCS8_API __attribute__((visibility("default")))
#else
#define ASNBER_PKCS8_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* 不透明句柄；具体布局属于模块私有实现。 */
typedef struct asnber_pkcs_private_key_info asnber_pkcs_private_key_info_t;
typedef struct asnber_pkcs_encrypted_private_key_info
    asnber_pkcs_encrypted_private_key_info_t;

/* ------------------------------------------------------------------------- */
/* PKCS#8 PrivateKeyInfo（RFC 5208 第 5 节）                                  */
/* ------------------------------------------------------------------------- */

/*
 * 打开 DER 编码的 PrivateKeyInfo。
 *
 * - 使用模块随包发布的描述表加载 schema，并以 DER 严格模式解码；
 * - 输入被复制进文档 arena，调用方可在 open 返回后释放 der；
 * - 成功时 *out_info 非 NULL；失败时置 NULL 并返回核心错误码；
 * - 空参返回 ASNBER_E_INVALID_ARG；分配失败返回 ASNBER_E_NOMEM。
 */
ASNBER_PKCS8_API asnber_err_t asnber_pkcs_private_key_info_open(
    asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asnber_pkcs_private_key_info_t **out_info);

/* 关闭句柄；info == NULL 为空操作。 */
ASNBER_PKCS8_API void asnber_pkcs_private_key_info_close(
    asnber_pkcs_private_key_info_t *info);

/* version 字段（RFC 5208 为 INTEGER；常见值 0）。 */
ASNBER_PKCS8_API asnber_err_t asnber_pkcs_private_key_info_version(
    const asnber_pkcs_private_key_info_t *info, int64_t *out_version);

/* privateKeyAlgorithm.algorithm：OID 点分十进制文本（借用句柄）。 */
ASNBER_PKCS8_API asnber_err_t asnber_pkcs_private_key_info_algorithm_oid(
    const asnber_pkcs_private_key_info_t *info, const char **out_dotted,
    size_t *out_size);

/*
 * privateKeyAlgorithm.parameters：ANY 原始 TLV（含 tag/len）。
 * 字段缺省时返回 ASNBER_OK，且 *out_data = NULL、*out_size = 0。
 */
ASNBER_PKCS8_API asnber_err_t asnber_pkcs_private_key_info_algorithm_parameters(
    const asnber_pkcs_private_key_info_t *info, const uint8_t **out_data,
    size_t *out_size);

/* privateKey：OCTET STRING 内容字节（不含 tag/len，借用句柄）。 */
ASNBER_PKCS8_API asnber_err_t asnber_pkcs_private_key_info_private_key(
    const asnber_pkcs_private_key_info_t *info, const uint8_t **out_data,
    size_t *out_size);

/* privateKey 字段完整 TLV（含 tag/len，借用句柄）。 */
ASNBER_PKCS8_API asnber_err_t asnber_pkcs_private_key_info_private_key_tlv(
    const asnber_pkcs_private_key_info_t *info, const uint8_t **out_data,
    size_t *out_size);

/* attributes 中的属性个数；字段缺省时为 0。 */
ASNBER_PKCS8_API asnber_err_t asnber_pkcs_private_key_info_attribute_count(
    const asnber_pkcs_private_key_info_t *info, size_t *out_count);

/*
 * 按下标访问 Attribute：type OID 点分十进制 + values（SET OF ANY）借用节点。
 * index 越界返回 ASNBER_E_INVALID_ARG；attributes 缺省且 count = 0。
 */
ASNBER_PKCS8_API asnber_err_t asnber_pkcs_private_key_info_attribute_at(
    const asnber_pkcs_private_key_info_t *info, size_t index,
    const char **out_type_oid, size_t *out_type_oid_size,
    const asnber_node_t **out_values);

/* ------------------------------------------------------------------------- */
/* PKCS#8 EncryptedPrivateKeyInfo（RFC 5208 附录 A）                          */
/* ------------------------------------------------------------------------- */

/* 打开 DER 编码的 EncryptedPrivateKeyInfo；只读结构，不解密。 */
ASNBER_PKCS8_API asnber_err_t asnber_pkcs_encrypted_private_key_info_open(
    asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asnber_pkcs_encrypted_private_key_info_t **out_info);

/* 关闭句柄；info == NULL 为空操作。 */
ASNBER_PKCS8_API void asnber_pkcs_encrypted_private_key_info_close(
    asnber_pkcs_encrypted_private_key_info_t *info);

/* encryptionAlgorithm.algorithm：OID 点分十进制文本（借用句柄）。 */
ASNBER_PKCS8_API asnber_err_t
asnber_pkcs_encrypted_private_key_info_algorithm_oid(
    const asnber_pkcs_encrypted_private_key_info_t *info, const char **out_dotted,
    size_t *out_size);

/* encryptionAlgorithm.parameters：ANY 原始 TLV；缺省返回 NULL/0。 */
ASNBER_PKCS8_API asnber_err_t
asnber_pkcs_encrypted_private_key_info_algorithm_parameters(
    const asnber_pkcs_encrypted_private_key_info_t *info,
    const uint8_t **out_data, size_t *out_size);

/* encryptedData：OCTET STRING 内容字节（借用句柄）。 */
ASNBER_PKCS8_API asnber_err_t
asnber_pkcs_encrypted_private_key_info_encrypted_data(
    const asnber_pkcs_encrypted_private_key_info_t *info,
    const uint8_t **out_data, size_t *out_size);

/* encryptedData 字段完整 TLV（借用句柄）。 */
ASNBER_PKCS8_API asnber_err_t
asnber_pkcs_encrypted_private_key_info_encrypted_data_tlv(
    const asnber_pkcs_encrypted_private_key_info_t *info,
    const uint8_t **out_data, size_t *out_size);

#ifdef __cplusplus
}
#endif

/* 构造接口单列一个子头，读写两侧可分别包含。 */
#include <asnber/pkcs8/pkcs8_builder.h>

#endif /* ASNBER_PKCS8_PKCS8_H_INCLUDED */
