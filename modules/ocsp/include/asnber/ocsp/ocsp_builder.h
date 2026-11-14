/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-ocsp 构造接口（RFC 6960）。
 *
 * 只组装结构，不签名、不验签、不判断证书状态、不解释扩展。version 为
 * DEFAULT v1（整数 0）时不写 [0]。扩展值是 extnValue 的内容，即一条完整
 * DER TLV。输入在设置时复制，调用方可随后释放原缓冲。
 *
 * 编码失败时 out_buf 被清零。成功时 out_buf 由 ctx 分配，调用方用
 * asnber_buf_release 释放。
 */

#ifndef ASNBER_OCSP_OCSP_BUILDER_H_INCLUDED
#define ASNBER_OCSP_OCSP_BUILDER_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include <asnber/asnber_encode.h>
#include <asnber/ocsp/ocsp.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct asnber_ocsp_request_builder asnber_ocsp_request_builder_t;

/*
 * 创建请求 builder。builder 借用 ctx，ctx 必须比 builder 存活更久。
 * 空参返回 ASNBER_E_INVALID_ARG 且 *out_builder = NULL。
 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_request_builder_create(
    asnber_ctx_t *ctx, asnber_ocsp_request_builder_t **out_builder);

/* 销毁 builder；builder == NULL 为空操作。 */
ASNBER_OCSP_API void asnber_ocsp_request_builder_destroy(
    asnber_ocsp_request_builder_t *builder);

/*
 * version。只允许设置一次，并且只接受 0（v1）。其他值返回
 * ASNBER_E_INVALID_VALUE。0 与不设置一样，编码时省略 DEFAULT。
 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_request_builder_set_version(
    asnber_ocsp_request_builder_t *builder, int64_t version);

/*
 * requestorName 的 GeneralName 完整 TLV（不含外层 [1]）。只允许设置一次。
 * 不是一条完整 DER TLV 时返回相应错误。
 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_request_builder_set_requestor(
    asnber_ocsp_request_builder_t *builder, const uint8_t *name_der,
    size_t name_size);

/*
 * 追加一条 Request。hash_params_size 为 0 时省略 parameters。
 * serial 是大端无符号幅值。返回后可用下标追加 singleRequestExtensions。
 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_request_builder_add_request(
    asnber_ocsp_request_builder_t *builder, const char *hash_oid,
    const uint8_t *hash_params, size_t hash_params_size,
    const uint8_t *name_hash, size_t name_hash_size, const uint8_t *key_hash,
    size_t key_hash_size, const uint8_t *serial, size_t serial_size);

/*
 * 给第 request_index 条 Request 追加扩展。同一条里 OID 不得重复。
 * extn_value_der 是一条完整 DER TLV。critical 非 0 时写出 BOOLEAN TRUE。
 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_request_builder_add_single_extension(
    asnber_ocsp_request_builder_t *builder, size_t request_index,
    const char *extn_oid, int critical, const uint8_t *extn_value_der,
    size_t extn_value_size);

/* 追加 requestExtensions。同一列表里 OID 不得重复。 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_request_builder_add_extension(
    asnber_ocsp_request_builder_t *builder, const char *extn_oid, int critical,
    const uint8_t *extn_value_der, size_t extn_value_size);

/*
 * optionalSignature 的算法与位串。只允许设置一次。params_size 为 0 时
 * 省略 parameters。证书用 add_signature_cert 逐张追加。
 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_request_builder_set_signature(
    asnber_ocsp_request_builder_t *builder, const char *oid,
    const uint8_t *params, size_t params_size, const uint8_t *bits, size_t bits_size,
    uint8_t unused_bits);

/* 追加一张证书的完整 DER。必须先设置签名。 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_request_builder_add_signature_cert(
    asnber_ocsp_request_builder_t *builder, const uint8_t *cert_der,
    size_t cert_size);

/*
 * 结束并编码。至少一条 Request，否则返回 ASNBER_E_INVALID_STATE。
 * 失败时 out_buf 被清零。
 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_request_builder_encode(
    const asnber_ocsp_request_builder_t *builder, asnber_buf_t *out_buf);

typedef struct asnber_ocsp_response_builder asnber_ocsp_response_builder_t;

ASNBER_OCSP_API asnber_err_t asnber_ocsp_response_builder_create(
    asnber_ctx_t *ctx, asnber_ocsp_response_builder_t **out_builder);
ASNBER_OCSP_API void asnber_ocsp_response_builder_destroy(
    asnber_ocsp_response_builder_t *builder);

/*
 * responseStatus。只允许设置一次。只接受 0、1、2、3、5、6，
 * 其他值返回 ASNBER_E_INVALID_VALUE。
 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_response_builder_set_status(
    asnber_ocsp_response_builder_t *builder, int64_t status);

/*
 * responseBytes 的 responseType 与 response 内容（不含 OCTET STRING 标签）。
 * 只允许设置一次。模块不因 status 不是 successful 而丢掉这些字节。
 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_response_builder_set_bytes(
    asnber_ocsp_response_builder_t *builder, const char *type_oid,
    const uint8_t *response, size_t response_size);

/*
 * 结束并编码。status 必须已设置，否则返回 ASNBER_E_INVALID_STATE。
 * 失败时 out_buf 被清零。
 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_response_builder_encode(
    const asnber_ocsp_response_builder_t *builder, asnber_buf_t *out_buf);

typedef struct asnber_ocsp_basic_builder asnber_ocsp_basic_builder_t;

ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_builder_create(
    asnber_ctx_t *ctx, asnber_ocsp_basic_builder_t **out_builder);
ASNBER_OCSP_API void asnber_ocsp_basic_builder_destroy(
    asnber_ocsp_basic_builder_t *builder);

/* version。语义同请求 builder：只接受 0，编码时省略 DEFAULT。 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_builder_set_version(
    asnber_ocsp_basic_builder_t *builder, int64_t version);

/*
 * responderID 的一支。byName 传入 Name 的完整 TLV（不含外层 [1]），
 * byKey 传入 KeyHash 内容字节。两支互斥，只能设置一次。
 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_builder_set_responder_name(
    asnber_ocsp_basic_builder_t *builder, const uint8_t *name_der,
    size_t name_size);
ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_builder_set_responder_key(
    asnber_ocsp_basic_builder_t *builder, const uint8_t *key_hash,
    size_t key_hash_size);

/*
 * producedAt。只允许设置一次。struct_size 必须为 sizeof(asnber_time_t)。
 * 不接受偏移、本地时间或小数秒。时间总是写成 GeneralizedTime。
 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_builder_set_produced_at(
    asnber_ocsp_basic_builder_t *builder, const asnber_time_t *produced_at);

/*
 * 追加一条 SingleResponse。CertID 参数同请求。next_update 为 NULL 时省略。
 * good 与 unknown 不带撤销时间。revoked 必须带 revocation_time。
 * reason_present 非 0 时写出 CRLReason；7 与未定义的值返回
 * ASNBER_E_INVALID_VALUE。三条状态由不同函数写入，一条记录只有一支。
 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_builder_add_good(
    asnber_ocsp_basic_builder_t *builder, const char *hash_oid,
    const uint8_t *hash_params, size_t hash_params_size,
    const uint8_t *name_hash, size_t name_hash_size, const uint8_t *key_hash,
    size_t key_hash_size, const uint8_t *serial, size_t serial_size,
    const asnber_time_t *this_update, const asnber_time_t *next_update);
ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_builder_add_unknown(
    asnber_ocsp_basic_builder_t *builder, const char *hash_oid,
    const uint8_t *hash_params, size_t hash_params_size,
    const uint8_t *name_hash, size_t name_hash_size, const uint8_t *key_hash,
    size_t key_hash_size, const uint8_t *serial, size_t serial_size,
    const asnber_time_t *this_update, const asnber_time_t *next_update);
ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_builder_add_revoked(
    asnber_ocsp_basic_builder_t *builder, const char *hash_oid,
    const uint8_t *hash_params, size_t hash_params_size,
    const uint8_t *name_hash, size_t name_hash_size, const uint8_t *key_hash,
    size_t key_hash_size, const uint8_t *serial, size_t serial_size,
    const asnber_time_t *this_update, const asnber_time_t *next_update,
    const asnber_time_t *revocation_time, int64_t reason, int reason_present);

/* 给第 response_index 条 SingleResponse 追加扩展。OID 不得在该条内重复。 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_builder_add_single_extension(
    asnber_ocsp_basic_builder_t *builder, size_t response_index,
    const char *extn_oid, int critical, const uint8_t *extn_value_der,
    size_t extn_value_size);

/* 追加 responseExtensions。同一列表里 OID 不得重复。 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_builder_add_extension(
    asnber_ocsp_basic_builder_t *builder, const char *extn_oid, int critical,
    const uint8_t *extn_value_der, size_t extn_value_size);

/* 签名算法与位串。只允许设置一次。证书用 add_signature_cert 追加。 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_builder_set_signature(
    asnber_ocsp_basic_builder_t *builder, const char *oid, const uint8_t *params,
    size_t params_size, const uint8_t *bits, size_t bits_size,
    uint8_t unused_bits);
ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_builder_add_signature_cert(
    asnber_ocsp_basic_builder_t *builder, const uint8_t *cert_der,
    size_t cert_size);

/*
 * 结束并编码。responderID、producedAt、至少一条 SingleResponse、签名算法
 * 与位串都必须已设置，否则返回 ASNBER_E_INVALID_STATE。失败时 out_buf 被清零。
 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_builder_encode(
    const asnber_ocsp_basic_builder_t *builder, asnber_buf_t *out_buf);

#ifdef __cplusplus
}
#endif

#endif /* ASNBER_OCSP_OCSP_BUILDER_H_INCLUDED */
