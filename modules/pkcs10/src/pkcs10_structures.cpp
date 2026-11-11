/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-pkcs10 只读结构访问：PKCS#10。
 *
 * 职责：用随模块发布的描述表加载 schema，按 DER 严格模式解码
 *       CertificationRequest，并把结构字段投影为核心节点/值。
 * 边界：不校验签名、不解析 SPKI 内部的密钥；ANY 字段只返回原始 TLV。
 * 依赖：只使用核心公共 C ABI；生成表由 asnberc 产出。
 * 所有权：句柄持有 schema 与文档，close 时逆序释放；访问器返回的指针
 *         借用句柄，close 后失效。
 */

#include "asnber/pkcs10/pkcs10.h"

#include "pkcs_handle.h"

using pkcs10_internal::closeStructure;
using pkcs10_internal::field;
using pkcs10_internal::handle_base;
using pkcs10_internal::openStructure;
using pkcs10_internal::requireField;

/* ------------------------------------------------------------------------- */
/* PKCS#10 CertificationRequest                                               */
/* ------------------------------------------------------------------------- */

namespace {

const asnber_node_t *crInfoChild(const handle_base *request,
                               const char *name) noexcept
{
    const asnber_node_t *info = field(request, "certificationRequestInfo");
    if (info == nullptr) {
        return nullptr;
    }
    return asnber_node_child_by_name(info, name);
}

asnber_err_t requireCrInfoChild(const handle_base *request, const char *name,
                              const asnber_node_t **out_node) noexcept
{
    const asnber_node_t *node = crInfoChild(request, name);
    if (node == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    *out_node = node;
    return ASNBER_OK;
}

asnber_err_t nodeOid(const asnber_node_t *node, const char **out_dotted,
                   size_t *out_size) noexcept
{
    if (node == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    return asnber_node_get_oid(node, out_dotted, out_size);
}

/* ANY 参数缺省时按“无参数”返回 ASNBER_OK + NULL/0。 */
asnber_err_t nodeParameters(const asnber_node_t *node, const uint8_t **out_data,
                          size_t *out_size) noexcept
{
    if (node == nullptr) {
        *out_data = nullptr;
        *out_size = 0;
        return ASNBER_OK;
    }
    *out_data = asnber_node_tlv(node, out_size);
    return (*out_data == nullptr) ? ASNBER_E_INVALID_STATE : ASNBER_OK;
}

/* BIT STRING 位字节；中心只读结构，不使用 bit_length/unused 输出。 */
asnber_err_t nodeBitString(const asnber_node_t *node, const uint8_t **out_data,
                         size_t *out_size) noexcept
{
    if (node == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    size_t bit_length = 0;
    uint8_t unused_bits = 0;
    return asnber_node_get_bits(node, out_data, out_size, &bit_length,
                              &unused_bits);
}

asnber_err_t nodeTlv(const asnber_node_t *node, const uint8_t **out_data,
                   size_t *out_size) noexcept
{
    if (node == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    *out_data = asnber_node_tlv(node, out_size);
    return (*out_data == nullptr) ? ASNBER_E_INVALID_STATE : ASNBER_OK;
}

} // namespace

struct asnber_pkcs_certification_request : handle_base {};

extern "C" ASNBER_PKCS10_API asnber_err_t asnber_pkcs_certification_request_open(
    asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asnber_pkcs_certification_request_t **out_request)
{
    return openStructure(ctx, der, der_size, pkcs10SchemaTable(),
                         kPkcs10RootCertificationRequest,
                         out_request);
}

extern "C" ASNBER_PKCS10_API void asnber_pkcs_certification_request_close(
    asnber_pkcs_certification_request_t *request)
{
    closeStructure(request);
}

extern "C" ASNBER_PKCS10_API asnber_err_t asnber_pkcs_certification_request_version(
    const asnber_pkcs_certification_request_t *request, int64_t *out_version)
{
    if (request == nullptr || out_version == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = nullptr;
    asnber_err_t status = requireCrInfoChild(request, "version", &node);
    if (status != ASNBER_OK) {
        return status;
    }
    return asnber_node_get_int64(node, out_version);
}

extern "C" ASNBER_PKCS10_API asnber_err_t
asnber_pkcs_certification_request_subject_der(
    const asnber_pkcs_certification_request_t *request, const uint8_t **out_data,
    size_t *out_size)
{
    if (request == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = nullptr;
    asnber_err_t status = requireCrInfoChild(request, "subject", &node);
    if (status != ASNBER_OK) {
        return status;
    }
    return nodeTlv(node, out_data, out_size);
}

extern "C" ASNBER_PKCS10_API asnber_err_t
asnber_pkcs_certification_request_subject_public_key_algorithm_oid(
    const asnber_pkcs_certification_request_t *request, const char **out_dotted,
    size_t *out_size)
{
    if (request == nullptr || out_dotted == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *spki = nullptr;
    asnber_err_t status = requireCrInfoChild(request, "subjectPKInfo", &spki);
    if (status != ASNBER_OK) {
        return status;
    }
    const asnber_node_t *algorithm = asnber_node_child_by_name(spki, "algorithm");
    const asnber_node_t *oid =
        (algorithm == nullptr)
            ? nullptr
            : asnber_node_child_by_name(algorithm, "algorithm");
    return nodeOid(oid, out_dotted, out_size);
}

extern "C" ASNBER_PKCS10_API asnber_err_t
asnber_pkcs_certification_request_subject_public_key_algorithm_parameters(
    const asnber_pkcs_certification_request_t *request,
    const uint8_t **out_data, size_t *out_size)
{
    if (request == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *spki = nullptr;
    asnber_err_t status = requireCrInfoChild(request, "subjectPKInfo", &spki);
    if (status != ASNBER_OK) {
        return status;
    }
    const asnber_node_t *algorithm = asnber_node_child_by_name(spki, "algorithm");
    const asnber_node_t *parameters =
        (algorithm == nullptr)
            ? nullptr
            : asnber_node_child_by_name(algorithm, "parameters");
    return nodeParameters(parameters, out_data, out_size);
}

extern "C" ASNBER_PKCS10_API asnber_err_t
asnber_pkcs_certification_request_subject_public_key(
    const asnber_pkcs_certification_request_t *request,
    const uint8_t **out_data, size_t *out_size)
{
    if (request == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *spki = nullptr;
    asnber_err_t status = requireCrInfoChild(request, "subjectPKInfo", &spki);
    if (status != ASNBER_OK) {
        return status;
    }
    return nodeBitString(asnber_node_child_by_name(spki, "subjectPublicKey"),
                         out_data, out_size);
}

extern "C" ASNBER_PKCS10_API asnber_err_t
asnber_pkcs_certification_request_subject_public_key_tlv(
    const asnber_pkcs_certification_request_t *request,
    const uint8_t **out_data, size_t *out_size)
{
    if (request == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *spki = nullptr;
    asnber_err_t status = requireCrInfoChild(request, "subjectPKInfo", &spki);
    if (status != ASNBER_OK) {
        return status;
    }
    return nodeTlv(asnber_node_child_by_name(spki, "subjectPublicKey"), out_data,
                   out_size);
}

extern "C" ASNBER_PKCS10_API asnber_err_t
asnber_pkcs_certification_request_attribute_count(
    const asnber_pkcs_certification_request_t *request, size_t *out_count)
{
    if (request == nullptr || out_count == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *attributes = crInfoChild(request, "attributes");
    *out_count =
        (attributes == nullptr) ? 0 : asnber_node_child_count(attributes);
    return ASNBER_OK;
}

extern "C" ASNBER_PKCS10_API asnber_err_t
asnber_pkcs_certification_request_attribute_at(
    const asnber_pkcs_certification_request_t *request, size_t index,
    const char **out_type_oid, size_t *out_type_oid_size,
    const asnber_node_t **out_values)
{
    if (request == nullptr || out_type_oid == nullptr ||
        out_type_oid_size == nullptr || out_values == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_type_oid = nullptr;
    *out_type_oid_size = 0;
    *out_values = nullptr;

    const asnber_node_t *attributes = crInfoChild(request, "attributes");
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

extern "C" ASNBER_PKCS10_API asnber_err_t
asnber_pkcs_certification_request_signature_algorithm_oid(
    const asnber_pkcs_certification_request_t *request, const char **out_dotted,
    size_t *out_size)
{
    if (request == nullptr || out_dotted == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *algorithm = nullptr;
    asnber_err_t status =
        requireField(request, "signatureAlgorithm", &algorithm);
    if (status != ASNBER_OK) {
        return status;
    }
    return nodeOid(asnber_node_child_by_name(algorithm, "algorithm"), out_dotted,
                   out_size);
}

extern "C" ASNBER_PKCS10_API asnber_err_t
asnber_pkcs_certification_request_signature_algorithm_parameters(
    const asnber_pkcs_certification_request_t *request,
    const uint8_t **out_data, size_t *out_size)
{
    if (request == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *algorithm = nullptr;
    asnber_err_t status =
        requireField(request, "signatureAlgorithm", &algorithm);
    if (status != ASNBER_OK) {
        return status;
    }
    return nodeParameters(asnber_node_child_by_name(algorithm, "parameters"),
                          out_data, out_size);
}

extern "C" ASNBER_PKCS10_API asnber_err_t
asnber_pkcs_certification_request_signature_value(
    const asnber_pkcs_certification_request_t *request,
    const uint8_t **out_data, size_t *out_size)
{
    if (request == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = nullptr;
    asnber_err_t status = requireField(request, "signature", &node);
    if (status != ASNBER_OK) {
        return status;
    }
    return nodeBitString(node, out_data, out_size);
}

extern "C" ASNBER_PKCS10_API asnber_err_t
asnber_pkcs_certification_request_signature_value_tlv(
    const asnber_pkcs_certification_request_t *request,
    const uint8_t **out_data, size_t *out_size)
{
    if (request == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = nullptr;
    asnber_err_t status = requireField(request, "signature", &node);
    if (status != ASNBER_OK) {
        return status;
    }
    return nodeTlv(node, out_data, out_size);
}
