/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-pkcs1 只读结构访问：PKCS#1。
 *
 * 职责：用随模块发布的描述表加载 schema，按 DER 严格模式解码
 *       RSAPublicKey / RSAPrivateKey，并把结构字段投影为核心节点/值。
 * 边界：不做 RSA 运算、不做填充/签名/加密；ANY 字段只返回原始 TLV。
 * 依赖：只使用核心公共 C ABI；生成表由 asnberc 产出。
 * 所有权：句柄持有 schema 与文档，close 时逆序释放；访问器返回的指针
 *         借用句柄，close 后失效。
 */

#include "asnber/pkcs1/pkcs1.h"

#include "pkcs_handle.h"

using pkcs1_internal::bigintField;
using pkcs1_internal::closeStructure;
using pkcs1_internal::handle_base;
using pkcs1_internal::openStructure;
using pkcs1_internal::requireField;

/* ------------------------------------------------------------------------- */
/* PKCS#1 RSAPublicKey / RSAPrivateKey                                        */
/* ------------------------------------------------------------------------- */

struct asnber_pkcs_rsa_public_key : handle_base {};

extern "C" ASNBER_PKCS1_API asnber_err_t asnber_pkcs_rsa_public_key_open(
    asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asnber_pkcs_rsa_public_key_t **out_key)
{
    return openStructure(ctx, der, der_size, pkcs1SchemaTable(),
                         kPkcs1RootRsaPublicKey,
                         out_key);
}

extern "C" ASNBER_PKCS1_API void asnber_pkcs_rsa_public_key_close(
    asnber_pkcs_rsa_public_key_t *key)
{
    closeStructure(key);
}

extern "C" ASNBER_PKCS1_API asnber_err_t asnber_pkcs_rsa_public_key_modulus(
    const asnber_pkcs_rsa_public_key_t *key, const char **out_decimal,
    size_t *out_size)
{
    if (key == nullptr || out_decimal == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return bigintField(key, "modulus", out_decimal, out_size);
}

extern "C" ASNBER_PKCS1_API asnber_err_t
asnber_pkcs_rsa_public_key_public_exponent(
    const asnber_pkcs_rsa_public_key_t *key, const char **out_decimal,
    size_t *out_size)
{
    if (key == nullptr || out_decimal == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return bigintField(key, "publicExponent", out_decimal, out_size);
}

struct asnber_pkcs_rsa_private_key : handle_base {};

extern "C" ASNBER_PKCS1_API asnber_err_t asnber_pkcs_rsa_private_key_open(
    asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asnber_pkcs_rsa_private_key_t **out_key)
{
    return openStructure(ctx, der, der_size, pkcs1SchemaTable(),
                         kPkcs1RootRsaPrivateKey,
                         out_key);
}

extern "C" ASNBER_PKCS1_API void asnber_pkcs_rsa_private_key_close(
    asnber_pkcs_rsa_private_key_t *key)
{
    closeStructure(key);
}

extern "C" ASNBER_PKCS1_API asnber_err_t asnber_pkcs_rsa_private_key_version(
    const asnber_pkcs_rsa_private_key_t *key, int64_t *out_version)
{
    if (key == nullptr || out_version == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = nullptr;
    asnber_err_t status = requireField(key, "version", &node);
    if (status != ASNBER_OK) {
        return status;
    }
    return asnber_node_get_int64(node, out_version);
}

extern "C" ASNBER_PKCS1_API asnber_err_t asnber_pkcs_rsa_private_key_modulus(
    const asnber_pkcs_rsa_private_key_t *key, const char **out_decimal,
    size_t *out_size)
{
    if (key == nullptr || out_decimal == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return bigintField(key, "modulus", out_decimal, out_size);
}

extern "C" ASNBER_PKCS1_API asnber_err_t
asnber_pkcs_rsa_private_key_public_exponent(
    const asnber_pkcs_rsa_private_key_t *key, const char **out_decimal,
    size_t *out_size)
{
    if (key == nullptr || out_decimal == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return bigintField(key, "publicExponent", out_decimal, out_size);
}

extern "C" ASNBER_PKCS1_API asnber_err_t
asnber_pkcs_rsa_private_key_private_exponent(
    const asnber_pkcs_rsa_private_key_t *key, const char **out_decimal,
    size_t *out_size)
{
    if (key == nullptr || out_decimal == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return bigintField(key, "privateExponent", out_decimal, out_size);
}

extern "C" ASNBER_PKCS1_API asnber_err_t asnber_pkcs_rsa_private_key_prime1(
    const asnber_pkcs_rsa_private_key_t *key, const char **out_decimal,
    size_t *out_size)
{
    if (key == nullptr || out_decimal == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return bigintField(key, "prime1", out_decimal, out_size);
}

extern "C" ASNBER_PKCS1_API asnber_err_t asnber_pkcs_rsa_private_key_prime2(
    const asnber_pkcs_rsa_private_key_t *key, const char **out_decimal,
    size_t *out_size)
{
    if (key == nullptr || out_decimal == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return bigintField(key, "prime2", out_decimal, out_size);
}

extern "C" ASNBER_PKCS1_API asnber_err_t asnber_pkcs_rsa_private_key_exponent1(
    const asnber_pkcs_rsa_private_key_t *key, const char **out_decimal,
    size_t *out_size)
{
    if (key == nullptr || out_decimal == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return bigintField(key, "exponent1", out_decimal, out_size);
}

extern "C" ASNBER_PKCS1_API asnber_err_t asnber_pkcs_rsa_private_key_exponent2(
    const asnber_pkcs_rsa_private_key_t *key, const char **out_decimal,
    size_t *out_size)
{
    if (key == nullptr || out_decimal == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return bigintField(key, "exponent2", out_decimal, out_size);
}

extern "C" ASNBER_PKCS1_API asnber_err_t asnber_pkcs_rsa_private_key_coefficient(
    const asnber_pkcs_rsa_private_key_t *key, const char **out_decimal,
    size_t *out_size)
{
    if (key == nullptr || out_decimal == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return bigintField(key, "coefficient", out_decimal, out_size);
}
