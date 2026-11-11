/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-pkcs8 只读结构访问：PKCS#8。
 *
 * 职责：用随模块发布的描述表加载 schema，按 DER 严格模式解码
 *       PrivateKeyInfo / EncryptedPrivateKeyInfo，并把结构字段投影为
 *       核心节点/值。
 * 边界：不解密、不做密钥解析；ANY 字段只返回原始 TLV。
 * 依赖：只使用核心公共 C ABI；生成表由 asnberc 产出。
 * 所有权：句柄持有 schema 与文档，close 时逆序释放；访问器返回的指针
 *         借用句柄，close 后失效。
 */

#include "asnber/pkcs8/pkcs8.h"

#include "pkcs_handle.h"

using pkcs8_internal::algorithmOid;
using pkcs8_internal::algorithmParameters;
using pkcs8_internal::closeStructure;
using pkcs8_internal::field;
using pkcs8_internal::handle_base;
using pkcs8_internal::octetsField;
using pkcs8_internal::openStructure;
using pkcs8_internal::requireField;
using pkcs8_internal::tlvField;

/* ------------------------------------------------------------------------- */
/* PKCS#8 PrivateKeyInfo                                                      */
/* ------------------------------------------------------------------------- */

struct asnber_pkcs_private_key_info : handle_base {};

extern "C" ASNBER_PKCS8_API asnber_err_t asnber_pkcs_private_key_info_open(
    asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asnber_pkcs_private_key_info_t **out_info)
{
    return openStructure(ctx, der, der_size, pkcs8SchemaTable(),
                         kPkcs8RootPrivateKeyInfo,
                         out_info);
}

extern "C" ASNBER_PKCS8_API void asnber_pkcs_private_key_info_close(
    asnber_pkcs_private_key_info_t *info)
{
    closeStructure(info);
}

extern "C" ASNBER_PKCS8_API asnber_err_t asnber_pkcs_private_key_info_version(
    const asnber_pkcs_private_key_info_t *info, int64_t *out_version)
{
    if (info == nullptr || out_version == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = nullptr;
    asnber_err_t status = requireField(info, "version", &node);
    if (status != ASNBER_OK) {
        return status;
    }
    return asnber_node_get_int64(node, out_version);
}

extern "C" ASNBER_PKCS8_API asnber_err_t
asnber_pkcs_private_key_info_algorithm_oid(
    const asnber_pkcs_private_key_info_t *info, const char **out_dotted,
    size_t *out_size)
{
    if (info == nullptr || out_dotted == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return algorithmOid(info, "privateKeyAlgorithm", out_dotted, out_size);
}

extern "C" ASNBER_PKCS8_API asnber_err_t
asnber_pkcs_private_key_info_algorithm_parameters(
    const asnber_pkcs_private_key_info_t *info, const uint8_t **out_data,
    size_t *out_size)
{
    if (info == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return algorithmParameters(info, "privateKeyAlgorithm", out_data,
                               out_size);
}

extern "C" ASNBER_PKCS8_API asnber_err_t asnber_pkcs_private_key_info_private_key(
    const asnber_pkcs_private_key_info_t *info, const uint8_t **out_data,
    size_t *out_size)
{
    if (info == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return octetsField(info, "privateKey", out_data, out_size);
}

extern "C" ASNBER_PKCS8_API asnber_err_t
asnber_pkcs_private_key_info_private_key_tlv(
    const asnber_pkcs_private_key_info_t *info, const uint8_t **out_data,
    size_t *out_size)
{
    if (info == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return tlvField(info, "privateKey", out_data, out_size);
}

extern "C" ASNBER_PKCS8_API asnber_err_t
asnber_pkcs_private_key_info_attribute_count(
    const asnber_pkcs_private_key_info_t *info, size_t *out_count)
{
    if (info == nullptr || out_count == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *attributes = field(info, "attributes");
    *out_count = (attributes == nullptr) ? 0 : asnber_node_child_count(attributes);
    return ASNBER_OK;
}

extern "C" ASNBER_PKCS8_API asnber_err_t
asnber_pkcs_private_key_info_attribute_at(
    const asnber_pkcs_private_key_info_t *info, size_t index,
    const char **out_type_oid, size_t *out_type_oid_size,
    const asnber_node_t **out_values)
{
    if (info == nullptr || out_type_oid == nullptr ||
        out_type_oid_size == nullptr || out_values == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_type_oid = nullptr;
    *out_type_oid_size = 0;
    *out_values = nullptr;

    const asnber_node_t *attributes = field(info, "attributes");
    if (attributes == nullptr || index >= asnber_node_child_count(attributes)) {
        return ASNBER_E_INVALID_ARG;
    }

    const asnber_node_t *attribute = asnber_node_child_at(attributes, index);
    if (attribute == nullptr) {
        return ASNBER_E_INVALID_STATE;
    }

    const asnber_node_t *type = asnber_node_child_by_name(attribute, "type");
    if (type == nullptr) {
        type = asnber_node_child_at(attribute, 0);
    }
    const asnber_node_t *values = asnber_node_child_by_name(attribute, "values");
    if (values == nullptr) {
        values = asnber_node_child_at(attribute, 1);
    }
    if (type == nullptr || values == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }

    asnber_err_t status =
        asnber_node_get_oid(type, out_type_oid, out_type_oid_size);
    if (status != ASNBER_OK) {
        return status;
    }
    *out_values = values;
    return ASNBER_OK;
}

/* ------------------------------------------------------------------------- */
/* PKCS#8 EncryptedPrivateKeyInfo                                             */
/* ------------------------------------------------------------------------- */

struct asnber_pkcs_encrypted_private_key_info : handle_base {};

extern "C" ASNBER_PKCS8_API asnber_err_t
asnber_pkcs_encrypted_private_key_info_open(
    asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asnber_pkcs_encrypted_private_key_info_t **out_info)
{
    return openStructure(ctx, der, der_size,
                         pkcs8SchemaTable(), kPkcs8RootEncryptedPrivateKeyInfo,
                         out_info);
}

extern "C" ASNBER_PKCS8_API void asnber_pkcs_encrypted_private_key_info_close(
    asnber_pkcs_encrypted_private_key_info_t *info)
{
    closeStructure(info);
}

extern "C" ASNBER_PKCS8_API asnber_err_t
asnber_pkcs_encrypted_private_key_info_algorithm_oid(
    const asnber_pkcs_encrypted_private_key_info_t *info,
    const char **out_dotted, size_t *out_size)
{
    if (info == nullptr || out_dotted == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return algorithmOid(info, "encryptionAlgorithm", out_dotted, out_size);
}

extern "C" ASNBER_PKCS8_API asnber_err_t
asnber_pkcs_encrypted_private_key_info_algorithm_parameters(
    const asnber_pkcs_encrypted_private_key_info_t *info,
    const uint8_t **out_data, size_t *out_size)
{
    if (info == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return algorithmParameters(info, "encryptionAlgorithm", out_data,
                               out_size);
}

extern "C" ASNBER_PKCS8_API asnber_err_t
asnber_pkcs_encrypted_private_key_info_encrypted_data(
    const asnber_pkcs_encrypted_private_key_info_t *info,
    const uint8_t **out_data, size_t *out_size)
{
    if (info == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return octetsField(info, "encryptedData", out_data, out_size);
}

extern "C" ASNBER_PKCS8_API asnber_err_t
asnber_pkcs_encrypted_private_key_info_encrypted_data_tlv(
    const asnber_pkcs_encrypted_private_key_info_t *info,
    const uint8_t **out_data, size_t *out_size)
{
    if (info == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return tlvField(info, "encryptedData", out_data, out_size);
}
