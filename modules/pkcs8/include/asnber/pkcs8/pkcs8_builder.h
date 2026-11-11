/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-pkcs8 构造接口：PrivateKeyInfo（RFC 5208 第 5 节）。
 *
 * PrivateKeyInfo ::= SEQUENCE {
 *     version             INTEGER,
 *     privateKeyAlgorithm AlgorithmIdentifier,
 *     privateKey          OCTET STRING,
 *     attributes      [0] IMPLICIT Attributes OPTIONAL
 * }
 *
 * 构造侧只做结构组装：不推导 version、不解析 privateKey、不解析
 * algorithm.parameters 或 attributes.values 的语义。所有输入在 set 时复制，
 * 调用方可在返回后释放原缓冲。
 */

#ifndef ASNBER_PKCS8_PKCS8_BUILDER_H_INCLUDED
#define ASNBER_PKCS8_PKCS8_BUILDER_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include <asnber/asnber_encode.h>
#include <asnber/pkcs8/pkcs8.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 不透明 builder 句柄；布局属于模块私有实现。 */
typedef struct asnber_pkcs_private_key_info_builder
    asnber_pkcs_private_key_info_builder_t;

/*
 * 创建 builder。builder 借用调用方的 ctx，ctx 必须比 builder 存活更久。
 * 空参返回 ASNBER_E_INVALID_ARG 且 *out_builder = NULL；分配失败返回
 * ASNBER_E_NOMEM。
 */
ASNBER_PKCS8_API asnber_err_t asnber_pkcs_private_key_info_builder_create(
    asnber_ctx_t *ctx, asnber_pkcs_private_key_info_builder_t **out_builder);

/* 销毁 builder；builder == NULL 为空操作。 */
ASNBER_PKCS8_API void asnber_pkcs_private_key_info_builder_destroy(
    asnber_pkcs_private_key_info_builder_t *builder);

/*
 * 设置 version（必填，只允许设置一次）。模块不推导、不改写该值。
 * 重复设置返回 ASNBER_E_INVALID_STATE。
 */
ASNBER_PKCS8_API asnber_err_t asnber_pkcs_private_key_info_builder_set_version(
    asnber_pkcs_private_key_info_builder_t *builder, int64_t version);

/*
 * 设置 privateKeyAlgorithm（必填，只允许设置一次）。
 *
 * - oid 为点分十进制文本，写入前校验；
 * - parameters_tlv 为完整 DER TLV（含 tag/len）；NULL 且 size 为 0 表示
 *   parameters 缺省；
 * - 重复设置返回 ASNBER_E_INVALID_STATE；非法 OID 或非单个规范 DER TLV 时
 *   返回对应错误码。
 */
ASNBER_PKCS8_API asnber_err_t asnber_pkcs_private_key_info_builder_set_algorithm(
    asnber_pkcs_private_key_info_builder_t *builder, const char *oid,
    const uint8_t *parameters_tlv, size_t parameters_size);

/*
 * 设置 privateKey 内容（必填，只允许设置一次）。size 可为 0；
 * data == NULL 且 size != 0 返回 ASNBER_E_INVALID_ARG。
 */
ASNBER_PKCS8_API asnber_err_t asnber_pkcs_private_key_info_builder_set_private_key(
    asnber_pkcs_private_key_info_builder_t *builder, const uint8_t *data,
    size_t size);

/*
 * 设置 attributes（可选，只允许设置一次）。
 *
 * 传入完整的 `SET OF Attribute` TLV（根为 0x31），模块改写为
 * `[0] IMPLICIT`（0xA0）。集合必须非空且元素为 SEQUENCE。
 * 重复设置返回 ASNBER_E_INVALID_STATE。
 */
ASNBER_PKCS8_API asnber_err_t asnber_pkcs_private_key_info_builder_set_attributes(
    asnber_pkcs_private_key_info_builder_t *builder, const uint8_t *set_tlv,
    size_t set_size);

/*
 * 结束并编码。version、privateKeyAlgorithm、privateKey 必须已设置，
 * 否则返回 ASNBER_E_INVALID_STATE。成功时 out_buf 由 ctx 分配，
 * 调用方用 asnber_buf_release 释放；失败时 out_buf 被清零。
 */
ASNBER_PKCS8_API asnber_err_t asnber_pkcs_private_key_info_builder_encode(
    const asnber_pkcs_private_key_info_builder_t *builder, asnber_buf_t *out_buf);

/*
 * EncryptedPrivateKeyInfo 结构组装（RFC 5208 附录 A）。
 *
 * EncryptedPrivateKeyInfo ::= SEQUENCE {
 *     encryptionAlgorithm AlgorithmIdentifier,
 *     encryptedData       OCTET STRING }
 *
 * 不加密、不派生密钥。调用方给出算法标识和密文字节，模块只按顺序写出。
 */
typedef struct asnber_pkcs_encrypted_private_key_info_builder
    asnber_pkcs_encrypted_private_key_info_builder_t;

/* 创建 builder。空参返回 ASNBER_E_INVALID_ARG；分配失败返回 ASNBER_E_NOMEM。 */
ASNBER_PKCS8_API asnber_err_t
asnber_pkcs_encrypted_private_key_info_builder_create(
    asnber_ctx_t *ctx,
    asnber_pkcs_encrypted_private_key_info_builder_t **out_builder);

/* 销毁 builder；builder == NULL 为空操作。 */
ASNBER_PKCS8_API void asnber_pkcs_encrypted_private_key_info_builder_destroy(
    asnber_pkcs_encrypted_private_key_info_builder_t *builder);

/*
 * 设置 encryptionAlgorithm（必填，只允许设置一次）。
 * parameters_tlv 为完整 DER TLV；NULL 且 size 为 0 表示 parameters 缺省。
 */
ASNBER_PKCS8_API asnber_err_t
asnber_pkcs_encrypted_private_key_info_builder_set_algorithm(
    asnber_pkcs_encrypted_private_key_info_builder_t *builder, const char *oid,
    const uint8_t *parameters_tlv, size_t parameters_size);

/*
 * 设置 encryptedData 内容字节（必填，只允许设置一次）。
 * size 可为 0；data == NULL 且 size != 0 返回 ASNBER_E_INVALID_ARG。
 */
ASNBER_PKCS8_API asnber_err_t
asnber_pkcs_encrypted_private_key_info_builder_set_encrypted_data(
    asnber_pkcs_encrypted_private_key_info_builder_t *builder,
    const uint8_t *data, size_t size);

/*
 * 结束并编码。encryptionAlgorithm 与 encryptedData 必须已设置，否则返回
 * ASNBER_E_INVALID_STATE。成功时 out_buf 由 ctx 分配。
 */
ASNBER_PKCS8_API asnber_err_t
asnber_pkcs_encrypted_private_key_info_builder_encode(
    const asnber_pkcs_encrypted_private_key_info_builder_t *builder,
    asnber_buf_t *out_buf);

#ifdef __cplusplus
}
#endif

#endif /* ASNBER_PKCS8_PKCS8_BUILDER_H_INCLUDED */
