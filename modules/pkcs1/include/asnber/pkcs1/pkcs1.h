/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-pkcs1 公共头文件（RFC 8017 Appendix A 只读结构访问）。
 *
 * 只读语义：不做 RSA 运算、不做填充/签名/加密，也不解析算法参数。
 * 大整数字段按严格十进制文本返回，借用句柄。
 *
 * 生命周期：句柄由 open 创建、close 销毁；内部文档与 schema 随句柄创建
 * 和销毁。句柄借用调用方的 asnber_ctx_t，ctx 必须比句柄存活更久。所有由
 * 访问器返回的指针均借用句柄，close 后立即失效。
 */

#ifndef ASNBER_PKCS1_PKCS1_H_INCLUDED
#define ASNBER_PKCS1_PKCS1_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include <asnber/asnber_build.h>
#include <asnber/asnber_node.h>

#if defined(ASNBER_PKCS1_STATIC)
#define ASNBER_PKCS1_API
#elif defined(_WIN32) || defined(__CYGWIN__)
#if defined(ASNBER_PKCS1_BUILDING_LIBRARY)
#define ASNBER_PKCS1_API __declspec(dllexport)
#else
#define ASNBER_PKCS1_API __declspec(dllimport)
#endif
#elif defined(__GNUC__) && __GNUC__ >= 4
#define ASNBER_PKCS1_API __attribute__((visibility("default")))
#else
#define ASNBER_PKCS1_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* 不透明句柄；具体布局属于模块私有实现。 */
typedef struct asnber_pkcs_rsa_public_key asnber_pkcs_rsa_public_key_t;
typedef struct asnber_pkcs_rsa_private_key asnber_pkcs_rsa_private_key_t;

/* 打开 DER 编码的 RSAPublicKey；只读结构，不做 RSA 运算。 */
ASNBER_PKCS1_API asnber_err_t asnber_pkcs_rsa_public_key_open(
    asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asnber_pkcs_rsa_public_key_t **out_key);

/* 关闭句柄；key == NULL 为空操作。 */
ASNBER_PKCS1_API void asnber_pkcs_rsa_public_key_close(
    asnber_pkcs_rsa_public_key_t *key);

/* modulus（n）：大整数严格十进制文本（借用句柄）。 */
ASNBER_PKCS1_API asnber_err_t asnber_pkcs_rsa_public_key_modulus(
    const asnber_pkcs_rsa_public_key_t *key, const char **out_decimal,
    size_t *out_size);

/* publicExponent（e）：大整数严格十进制文本（借用句柄）。 */
ASNBER_PKCS1_API asnber_err_t asnber_pkcs_rsa_public_key_public_exponent(
    const asnber_pkcs_rsa_public_key_t *key, const char **out_decimal,
    size_t *out_size);

/* 打开 DER 编码的 RSAPrivateKey；只读结构，不做 RSA 运算。 */
ASNBER_PKCS1_API asnber_err_t asnber_pkcs_rsa_private_key_open(
    asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asnber_pkcs_rsa_private_key_t **out_key);

/* 关闭句柄；key == NULL 为空操作。 */
ASNBER_PKCS1_API void asnber_pkcs_rsa_private_key_close(
    asnber_pkcs_rsa_private_key_t *key);

/* version（two-prime = 0、multi = 1）。 */
ASNBER_PKCS1_API asnber_err_t asnber_pkcs_rsa_private_key_version(
    const asnber_pkcs_rsa_private_key_t *key, int64_t *out_version);

/* 以下均为大整数严格十进制文本（借用句柄）。 */
ASNBER_PKCS1_API asnber_err_t asnber_pkcs_rsa_private_key_modulus(
    const asnber_pkcs_rsa_private_key_t *key, const char **out_decimal,
    size_t *out_size);
ASNBER_PKCS1_API asnber_err_t asnber_pkcs_rsa_private_key_public_exponent(
    const asnber_pkcs_rsa_private_key_t *key, const char **out_decimal,
    size_t *out_size);
ASNBER_PKCS1_API asnber_err_t asnber_pkcs_rsa_private_key_private_exponent(
    const asnber_pkcs_rsa_private_key_t *key, const char **out_decimal,
    size_t *out_size);
ASNBER_PKCS1_API asnber_err_t asnber_pkcs_rsa_private_key_prime1(
    const asnber_pkcs_rsa_private_key_t *key, const char **out_decimal,
    size_t *out_size);
ASNBER_PKCS1_API asnber_err_t asnber_pkcs_rsa_private_key_prime2(
    const asnber_pkcs_rsa_private_key_t *key, const char **out_decimal,
    size_t *out_size);
ASNBER_PKCS1_API asnber_err_t asnber_pkcs_rsa_private_key_exponent1(
    const asnber_pkcs_rsa_private_key_t *key, const char **out_decimal,
    size_t *out_size);
ASNBER_PKCS1_API asnber_err_t asnber_pkcs_rsa_private_key_exponent2(
    const asnber_pkcs_rsa_private_key_t *key, const char **out_decimal,
    size_t *out_size);
ASNBER_PKCS1_API asnber_err_t asnber_pkcs_rsa_private_key_coefficient(
    const asnber_pkcs_rsa_private_key_t *key, const char **out_decimal,
    size_t *out_size);

#ifdef __cplusplus
}
#endif

/* 构造接口单列一个子头，读写两侧可分别包含。 */
#include <asnber/pkcs1/pkcs1_builder.h>

#endif /* ASNBER_PKCS1_PKCS1_H_INCLUDED */
