/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-pkcs12 构造侧接口（RFC 7292 PFX 与 AuthenticatedSafe）。
 *
 * 边界与只读侧一致：不派生口令密钥、不做加密/解密、不计算或校验 MAC、
 * 不解释 SafeContents 内层语义。ContentInfo 由调用方决定：PFX builder
 * 接收完整的 contentType 与 content 内层 TLV（方案 A），AuthenticatedSafe
 * builder 只对 data 形态自动包 OCTET STRING。
 *
 * 生命周期：builder 由 create 创建、destroy 销毁；所有输入深度拷贝，
 * 调用返回后即可释放。encode 输出由 asnber_buf_release 归还。
 */

#ifndef ASNBER_PKCS12_PKCS12_BUILDER_H_INCLUDED
#define ASNBER_PKCS12_PKCS12_BUILDER_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include <asnber/asnber_build.h>
#include <asnber/asnber_encode.h>

#include "pkcs12.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct asnber_pkcs12_pfx_builder asnber_pkcs12_pfx_builder_t;
typedef struct asnber_pkcs12_authenticated_safe_builder
    asnber_pkcs12_authenticated_safe_builder_t;

/* ------------------------------------------------------------------------- */
/* PFX                                                                        */
/* ------------------------------------------------------------------------- */

ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_pfx_builder_create(
    asnber_ctx_t *ctx, asnber_pkcs12_pfx_builder_t **out_builder);

ASNBER_PKCS12_API void asnber_pkcs12_pfx_builder_destroy(
    asnber_pkcs12_pfx_builder_t *builder);

/*
 * PFX.version；未设置时按 RFC 7292 的 v3 = 3 输出。只接受非负值。
 */
ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_pfx_builder_set_version(
    asnber_pkcs12_pfx_builder_t *builder, int64_t version);

/*
 * authSafe ContentInfo（方案 A）：调用方给出 contentType OID 与 content
 * 内层完整 TLV（含 tag/len），builder 只做包装与深拷贝，不解释内容。
 *
 * 常见组合：contentType = data（1.2.840.113549.1.7.1）时 content 为包住
 * AuthenticatedSafe DER 的 OCTET STRING；contentType = encryptedData 时
 * content 为 encryptedData 的 SEQUENCE。
 */
ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_pfx_builder_set_auth_safe(
    asnber_pkcs12_pfx_builder_t *builder, const char *content_type_oid,
    const uint8_t *content_tlv, size_t content_size);

/*
 * 取 authSafe.content 的 OCTET STRING 内容字节，供调用方计算 macData。
 *
 * 仅当已设置 authSafe、contentType = data 且 content 内层为 DER OCTET
 * STRING 时成功；返回的指针借用 builder，destroy 或重新 set_auth_safe 后
 * 失效。其他形态返回 ASNBER_E_INVALID_STATE。
 */
ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_pfx_builder_auth_safe_content_octets(
    const asnber_pkcs12_pfx_builder_t *builder, const uint8_t **out_data,
    size_t *out_size);

/*
 * 设置 macData（可选）。digest_algorithm_parameters 为完整 TLV 或 NULL/0；
 * iterations 必须 >= 1，等于 1 时按 DEFAULT 省略。
 */
ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_pfx_builder_set_mac_data(
    asnber_pkcs12_pfx_builder_t *builder, const char *digest_algorithm_oid,
    const uint8_t *digest_algorithm_parameters,
    size_t digest_algorithm_parameters_size, const uint8_t *digest,
    size_t digest_size, const uint8_t *mac_salt, size_t mac_salt_size,
    int64_t iterations);

/*
 * 输出 PFX DER。authSafe 必须已设置；macData 未设置时省略。
 */
ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_pfx_builder_encode(
    asnber_pkcs12_pfx_builder_t *builder, asnber_buf_t *out_der);

/* ------------------------------------------------------------------------- */
/* AuthenticatedSafe（SEQUENCE OF ContentInfo）                               */
/* ------------------------------------------------------------------------- */

ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_authenticated_safe_builder_create(
    asnber_ctx_t *ctx, asnber_pkcs12_authenticated_safe_builder_t **out_builder);

ASNBER_PKCS12_API void asnber_pkcs12_authenticated_safe_builder_destroy(
    asnber_pkcs12_authenticated_safe_builder_t *builder);

/*
 * 追加 data 形态 ContentInfo：content 为 OCTET STRING，内容即传入的
 * SafeContents DER（builder 负责套 OCTET STRING 的 tag/len）。
 */
ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_authenticated_safe_builder_add_data(
    asnber_pkcs12_authenticated_safe_builder_t *builder,
    const uint8_t *safe_contents_der, size_t safe_contents_size);

/*
 * 追加 encryptedData 形态 ContentInfo：content 原样使用传入的完整
 * encryptedData TLV，不做任何改写。
 */
ASNBER_PKCS12_API asnber_err_t
asnber_pkcs12_authenticated_safe_builder_add_encrypted_data(
    asnber_pkcs12_authenticated_safe_builder_t *builder,
    const uint8_t *encrypted_data_tlv, size_t encrypted_data_size);

/*
 * 输出 AuthenticatedSafe DER。该字节串即 PFX authSafe 中 OCTET STRING 的
 * 内容，也是调用方计算 macData 的输入。
 */
ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_authenticated_safe_builder_encode(
    asnber_pkcs12_authenticated_safe_builder_t *builder, asnber_buf_t *out_der);

#ifdef __cplusplus
}
#endif

#endif /* ASNBER_PKCS12_PKCS12_BUILDER_H_INCLUDED */
