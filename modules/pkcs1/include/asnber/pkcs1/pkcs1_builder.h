/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-pkcs1 构造接口：RSAPublicKey 与 RSAPrivateKey（RFC 8017 附录 A.1）。
 *
 * RSAPublicKey ::= SEQUENCE {
 *     modulus           INTEGER,
 *     publicExponent    INTEGER
 * }
 *
 * RSAPrivateKey ::= SEQUENCE {
 *     version           INTEGER,  -- 恒为 0（two-prime）
 *     modulus           INTEGER,
 *     publicExponent    INTEGER,
 *     privateExponent   INTEGER,
 *     prime1            INTEGER,
 *     prime2            INTEGER,
 *     exponent1         INTEGER,
 *     exponent2         INTEGER,
 *     coefficient       INTEGER
 * }
 *
 * 大整数字段以“大端无符号幅值字节”传入，模块负责规整为规范 DER
 * INTEGER：去冗余前导 0x00、最高位为 1 时补前导 0x00、零值编码为单字节
 * 0x00，空输入按参数错误拒绝。构造侧不做 RSA 运算，也不校验
 * n = p·q 等数学关系；RSAPrivateKey.version 由模块固定写 0，不暴露
 * setter。所有输入在 set 时复制，调用方可在返回后释放原缓冲。
 */

#ifndef ASNBER_PKCS1_PKCS1_BUILDER_H_INCLUDED
#define ASNBER_PKCS1_PKCS1_BUILDER_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include <asnber/asnber_encode.h>
#include <asnber/pkcs1/pkcs1.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 不透明 builder 句柄；布局属于模块私有实现。 */
typedef struct asnber_pkcs_rsa_public_key_builder
    asnber_pkcs_rsa_public_key_builder_t;

/*
 * 创建 builder。builder 借用调用方的 ctx，ctx 必须比 builder 存活更久。
 * 空参返回 ASNBER_E_INVALID_ARG 且 *out_builder = NULL；分配失败返回
 * ASNBER_E_NOMEM。
 */
ASNBER_PKCS1_API asnber_err_t asnber_pkcs_rsa_public_key_builder_create(
    asnber_ctx_t *ctx, asnber_pkcs_rsa_public_key_builder_t **out_builder);

/* 销毁 builder；builder == NULL 为空操作。 */
ASNBER_PKCS1_API void asnber_pkcs_rsa_public_key_builder_destroy(
    asnber_pkcs_rsa_public_key_builder_t *builder);

/*
 * 设置 modulus（必填，只允许设置一次）。
 *
 * magnitude 为大端无符号幅值，size 不得为 0；空输入返回
 * ASNBER_E_INVALID_ARG，超过 8192 字节返回 ASNBER_E_INPUT_LIMIT，重复设置
 * 返回 ASNBER_E_INVALID_STATE。
 */
ASNBER_PKCS1_API asnber_err_t asnber_pkcs_rsa_public_key_builder_set_modulus(
    asnber_pkcs_rsa_public_key_builder_t *builder, const uint8_t *magnitude,
    size_t size);

/*
 * 设置 publicExponent（必填，只允许设置一次），参数与错误码同上。
 */
ASNBER_PKCS1_API asnber_err_t asnber_pkcs_rsa_public_key_builder_set_public_exponent(
    asnber_pkcs_rsa_public_key_builder_t *builder, const uint8_t *magnitude,
    size_t size);

/*
 * 结束并编码。modulus 与 publicExponent 必须已设置，否则返回
 * ASNBER_E_INVALID_STATE。成功时 out_buf 由 ctx 分配，调用方用
 * asnber_buf_release 释放；失败时 out_buf 被清零。
 */
ASNBER_PKCS1_API asnber_err_t asnber_pkcs_rsa_public_key_builder_encode(
    const asnber_pkcs_rsa_public_key_builder_t *builder, asnber_buf_t *out_buf);

/* 不透明 builder 句柄；布局属于模块私有实现。 */
typedef struct asnber_pkcs_rsa_private_key_builder
    asnber_pkcs_rsa_private_key_builder_t;

/*
 * 创建 builder。builder 借用调用方的 ctx，ctx 必须比 builder 存活更久。
 * 空参返回 ASNBER_E_INVALID_ARG 且 *out_builder = NULL；分配失败返回
 * ASNBER_E_NOMEM。
 */
ASNBER_PKCS1_API asnber_err_t asnber_pkcs_rsa_private_key_builder_create(
    asnber_ctx_t *ctx, asnber_pkcs_rsa_private_key_builder_t **out_builder);

/* 销毁 builder；builder == NULL 为空操作。 */
ASNBER_PKCS1_API void asnber_pkcs_rsa_private_key_builder_destroy(
    asnber_pkcs_rsa_private_key_builder_t *builder);

/*
 * 以下 8 个字段均为必填、只允许设置一次；magnitude 为大端无符号幅值，
 * size 不得为 0。空输入返回 ASNBER_E_INVALID_ARG，超过 8192 字节返回
 * ASNBER_E_INPUT_LIMIT，重复设置返回 ASNBER_E_INVALID_STATE。
 */
ASNBER_PKCS1_API asnber_err_t asnber_pkcs_rsa_private_key_builder_set_modulus(
    asnber_pkcs_rsa_private_key_builder_t *builder, const uint8_t *magnitude,
    size_t size);
ASNBER_PKCS1_API asnber_err_t asnber_pkcs_rsa_private_key_builder_set_public_exponent(
    asnber_pkcs_rsa_private_key_builder_t *builder, const uint8_t *magnitude,
    size_t size);
ASNBER_PKCS1_API asnber_err_t asnber_pkcs_rsa_private_key_builder_set_private_exponent(
    asnber_pkcs_rsa_private_key_builder_t *builder, const uint8_t *magnitude,
    size_t size);
ASNBER_PKCS1_API asnber_err_t asnber_pkcs_rsa_private_key_builder_set_prime1(
    asnber_pkcs_rsa_private_key_builder_t *builder, const uint8_t *magnitude,
    size_t size);
ASNBER_PKCS1_API asnber_err_t asnber_pkcs_rsa_private_key_builder_set_prime2(
    asnber_pkcs_rsa_private_key_builder_t *builder, const uint8_t *magnitude,
    size_t size);
ASNBER_PKCS1_API asnber_err_t asnber_pkcs_rsa_private_key_builder_set_exponent1(
    asnber_pkcs_rsa_private_key_builder_t *builder, const uint8_t *magnitude,
    size_t size);
ASNBER_PKCS1_API asnber_err_t asnber_pkcs_rsa_private_key_builder_set_exponent2(
    asnber_pkcs_rsa_private_key_builder_t *builder, const uint8_t *magnitude,
    size_t size);
ASNBER_PKCS1_API asnber_err_t asnber_pkcs_rsa_private_key_builder_set_coefficient(
    asnber_pkcs_rsa_private_key_builder_t *builder, const uint8_t *magnitude,
    size_t size);

/*
 * 结束并编码。version 固定写 0，其余 8 个字段必须全部设置，否则返回
 * ASNBER_E_INVALID_STATE。成功时 out_buf 由 ctx 分配，调用方用
 * asnber_buf_release 释放；失败时 out_buf 被清零。
 */
ASNBER_PKCS1_API asnber_err_t asnber_pkcs_rsa_private_key_builder_encode(
    const asnber_pkcs_rsa_private_key_builder_t *builder, asnber_buf_t *out_buf);

#ifdef __cplusplus
}
#endif

#endif /* ASNBER_PKCS1_PKCS1_BUILDER_H_INCLUDED */
