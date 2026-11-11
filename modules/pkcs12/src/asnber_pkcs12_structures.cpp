/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-pkcs12 只读结构访问。
 *
 * 职责：用随模块发布的描述表加载 schema，按 DER 严格模式解码 PFX /
 *       AuthenticatedSafe / SafeContents / CertBag，并把结构字段投影为
 *       核心节点/值。
 * 边界：不解密 SafeContents、不做口令密钥派生、不验 MAC、不验证证书；
 *       content 与 bagValue 只返回完整原始 TLV，内层语义由调用方按
 *       contentType / bagId 解释。
 * 依赖：只使用核心公共 C ABI；生成表由 asnberc 产出。
 * 所有权：句柄持有 schema 与文档，close 时逆序释放；访问器返回的指针
 *         借用句柄，close 后失效。
 */

#include "asnber/pkcs12/pkcs12.h"

#include "pkcs_handle.h"

#include <cstdint>
#include <string>

using pkcs12_internal::closeStructure;
using pkcs12_internal::field;
using pkcs12_internal::handle_base;
using pkcs12_internal::openStructure;

namespace {

/* x509Certificate：certValue 为包含证书 DER 的 OCTET STRING。 */
constexpr const char *kX509CertificateOid = "1.2.840.113549.1.9.22.1";

bool oidEquals(const char *dotted, size_t size,
               const char *expected) noexcept
{
    const size_t expected_size = std::char_traits<char>::length(expected);
    return size == expected_size &&
           std::char_traits<char>::compare(dotted, expected, size) == 0;
}

/*
 * [0] EXPLICIT 包装节点内的完整 TLV。
 *
 * 描述表把内层 ANY 当作不透明开放类型：解码后包装节点没有子节点，其
 * content 即内层完整 TLV（显式标签的内容只有一个 TLV）。若解码实现将来
 * 物化出子节点，则退回取子节点的 TLV。两种情况返回的指针都借用文档。
 */
asnber_err_t explicitInnerTlv(const asnber_node_t *wrapper,
                            const uint8_t **out_data,
                            size_t *out_size) noexcept
{
    if (wrapper == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    const asnber_node_t *child = asnber_node_child_at(wrapper, 0);
    if (child != nullptr) {
        *out_data = asnber_node_tlv(child, out_size);
        return (*out_data == nullptr) ? ASNBER_E_INVALID_STATE : ASNBER_OK;
    }
    asnber_err_t status = asnber_node_content(wrapper, out_data, out_size);
    if (status != ASNBER_OK) {
        return status;
    }
    if (*out_data == nullptr || *out_size == 0) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    return ASNBER_OK;
}

/* 从完整 TLV 中取 primitive OCTET STRING 的内容（DER 确定长度）。 */
asnber_err_t octetsFromTlv(const uint8_t *tlv, size_t tlv_size,
                         const uint8_t **out_data,
                         size_t *out_size) noexcept
{
    if (tlv == nullptr || tlv_size < 2 || tlv[0] != 0x04u) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    size_t header = 2;
    size_t length = tlv[1];
    if ((length & 0x80u) != 0) {
        const size_t count = length & 0x7Fu;
        if (count == 0 || count > sizeof(size_t) || tlv_size < 2 + count) {
            return ASNBER_E_SCHEMA_FIELD;
        }
        length = 0;
        for (size_t i = 0; i < count; ++i) {
            if (length > (SIZE_MAX >> 8)) {
                return ASNBER_E_SCHEMA_FIELD;
            }
            length = (length << 8) | tlv[2 + i];
        }
        header = 2 + count;
    }
    if (length != tlv_size - header) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    *out_data = tlv + header;
    *out_size = length;
    return ASNBER_OK;
}

const asnber_node_t *contentInfoChild(const asnber_node_t *content_info,
                                    const char *name) noexcept
{
    if (content_info == nullptr) {
        return nullptr;
    }
    return asnber_node_child_by_name(content_info, name);
}

/* ContentInfo.content 的内层完整 TLV；content 缺省时返回 ASNBER_OK + NULL/0。 */
asnber_err_t contentInfoContentTlv(const asnber_node_t *content_info,
                                 const uint8_t **out_data,
                                 size_t *out_size) noexcept
{
    const asnber_node_t *wrapper = contentInfoChild(content_info, "content");
    if (wrapper == nullptr) {
        *out_data = nullptr;
        *out_size = 0;
        return ASNBER_OK;
    }
    return explicitInnerTlv(wrapper, out_data, out_size);
}

asnber_err_t contentInfoType(const asnber_node_t *content_info,
                           const char **out_dotted,
                           size_t *out_size) noexcept
{
    const asnber_node_t *node =
        contentInfoChild(content_info, "contentType");
    if (node == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    return asnber_node_get_oid(node, out_dotted, out_size);
}

/* macData 下的直接字段；macData 缺省时返回 nullptr。 */
const asnber_node_t *macDataChild(const handle_base *pfx,
                                const char *name) noexcept
{
    const asnber_node_t *mac_data = field(pfx, "macData");
    if (mac_data == nullptr) {
        return nullptr;
    }
    return asnber_node_child_by_name(mac_data, name);
}

/* macData.mac.digestAlgorithm 下的字段。 */
const asnber_node_t *digestAlgorithmChild(const handle_base *pfx,
                                        const char *name) noexcept
{
    const asnber_node_t *mac = macDataChild(pfx, "mac");
    if (mac == nullptr) {
        return nullptr;
    }
    const asnber_node_t *algorithm =
        asnber_node_child_by_name(mac, "digestAlgorithm");
    if (algorithm == nullptr) {
        return nullptr;
    }
    return asnber_node_child_by_name(algorithm, name);
}

const asnber_node_t *bagAttributes(const asnber_node_t *bag) noexcept
{
    return asnber_node_child_by_name(bag, "bagAttributes");
}

} // namespace

/* ------------------------------------------------------------------------- */
/* PFX                                                                        */
/* ------------------------------------------------------------------------- */

struct asnber_pkcs12_pfx : handle_base {};

extern "C" ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_pfx_open(
    asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asnber_pkcs12_pfx_t **out_pfx)
{
    return openStructure(ctx, der, der_size, pkcs12SchemaTable(),
                         kPkcs12RootPfx, out_pfx);
}

extern "C" ASNBER_PKCS12_API void asnber_pkcs12_pfx_close(
    asnber_pkcs12_pfx_t *pfx)
{
    closeStructure(pfx);
}

extern "C" ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_pfx_version(
    const asnber_pkcs12_pfx_t *pfx, int64_t *out_version)
{
    if (pfx == nullptr || out_version == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = field(pfx, "version");
    if (node == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    return asnber_node_get_int64(node, out_version);
}

extern "C" ASNBER_PKCS12_API asnber_err_t
asnber_pkcs12_pfx_auth_safe_content_type(const asnber_pkcs12_pfx_t *pfx,
                                       const char **out_dotted,
                                       size_t *out_size)
{
    if (pfx == nullptr || out_dotted == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return contentInfoType(field(pfx, "authSafe"), out_dotted, out_size);
}

extern "C" ASNBER_PKCS12_API asnber_err_t
asnber_pkcs12_pfx_auth_safe_content_tlv(const asnber_pkcs12_pfx_t *pfx,
                                      const uint8_t **out_data,
                                      size_t *out_size)
{
    if (pfx == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return contentInfoContentTlv(field(pfx, "authSafe"), out_data, out_size);
}

extern "C" ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_pfx_mac_present(
    const asnber_pkcs12_pfx_t *pfx, int *out_present)
{
    if (pfx == nullptr || out_present == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_present = (field(pfx, "macData") != nullptr) ? 1 : 0;
    return ASNBER_OK;
}

extern "C" ASNBER_PKCS12_API asnber_err_t
asnber_pkcs12_pfx_mac_digest_algorithm_oid(const asnber_pkcs12_pfx_t *pfx,
                                         const char **out_dotted,
                                         size_t *out_size)
{
    if (pfx == nullptr || out_dotted == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = digestAlgorithmChild(pfx, "algorithm");
    if (node == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    return asnber_node_get_oid(node, out_dotted, out_size);
}

extern "C" ASNBER_PKCS12_API asnber_err_t
asnber_pkcs12_pfx_mac_digest_algorithm_parameters(
    const asnber_pkcs12_pfx_t *pfx, const uint8_t **out_data,
    size_t *out_size)
{
    if (pfx == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = digestAlgorithmChild(pfx, "parameters");
    if (node == nullptr) {
        /* macData 缺省属于错误；parameters 缺省属于“无参数”。 */
        if (field(pfx, "macData") == nullptr) {
            return ASNBER_E_SCHEMA_FIELD;
        }
        *out_data = nullptr;
        *out_size = 0;
        return ASNBER_OK;
    }
    *out_data = asnber_node_tlv(node, out_size);
    return (*out_data == nullptr) ? ASNBER_E_INVALID_STATE : ASNBER_OK;
}

extern "C" ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_pfx_mac_digest(
    const asnber_pkcs12_pfx_t *pfx, const uint8_t **out_data,
    size_t *out_size)
{
    if (pfx == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = macDataChild(pfx, "mac");
    if (node == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    const asnber_node_t *digest = asnber_node_child_by_name(node, "digest");
    if (digest == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    return asnber_node_get_octets(digest, out_data, out_size);
}

extern "C" ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_pfx_mac_salt(
    const asnber_pkcs12_pfx_t *pfx, const uint8_t **out_data,
    size_t *out_size)
{
    if (pfx == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = macDataChild(pfx, "macSalt");
    if (node == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    return asnber_node_get_octets(node, out_data, out_size);
}

extern "C" ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_pfx_mac_iterations(
    const asnber_pkcs12_pfx_t *pfx, int64_t *out_iterations)
{
    if (pfx == nullptr || out_iterations == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (field(pfx, "macData") == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    const asnber_node_t *node = macDataChild(pfx, "iterations");
    if (node == nullptr) {
        /* 描述表声明 DEFAULT 1；省略时给出默认值而不改动文档。 */
        *out_iterations = 1;
        return ASNBER_OK;
    }
    return asnber_node_get_int64(node, out_iterations);
}

/* ------------------------------------------------------------------------- */
/* AuthenticatedSafe                                                          */
/* ------------------------------------------------------------------------- */

struct asnber_pkcs12_authenticated_safe : handle_base {};

static const asnber_node_t *authenticatedSafeContentAt(
    const asnber_pkcs12_authenticated_safe_t *safe, size_t index) noexcept
{
    return asnber_node_child_at(safe->root, index);
}

extern "C" ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_authenticated_safe_open(
    asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asnber_pkcs12_authenticated_safe_t **out_safe)
{
    return openStructure(ctx, der, der_size,
                         pkcs12SchemaTable(), kPkcs12RootAuthenticatedSafe,
                         out_safe);
}

extern "C" ASNBER_PKCS12_API void asnber_pkcs12_authenticated_safe_close(
    asnber_pkcs12_authenticated_safe_t *safe)
{
    closeStructure(safe);
}

extern "C" ASNBER_PKCS12_API asnber_err_t
asnber_pkcs12_authenticated_safe_content_count(
    const asnber_pkcs12_authenticated_safe_t *safe, size_t *out_count)
{
    if (safe == nullptr || out_count == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_count = asnber_node_child_count(safe->root);
    return ASNBER_OK;
}

extern "C" ASNBER_PKCS12_API asnber_err_t
asnber_pkcs12_authenticated_safe_content_at(
    const asnber_pkcs12_authenticated_safe_t *safe, size_t index,
    const char **out_type_oid, size_t *out_type_oid_size,
    const uint8_t **out_content, size_t *out_content_size)
{
    if (safe == nullptr || out_type_oid == nullptr ||
        out_type_oid_size == nullptr || out_content == nullptr ||
        out_content_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_type_oid = nullptr;
    *out_type_oid_size = 0;
    *out_content = nullptr;
    *out_content_size = 0;

    const asnber_node_t *content_info =
        authenticatedSafeContentAt(safe, index);
    if (content_info == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber_err_t status = contentInfoType(content_info, out_type_oid,
                                        out_type_oid_size);
    if (status != ASNBER_OK) {
        return status;
    }
    return contentInfoContentTlv(content_info, out_content, out_content_size);
}

/* ------------------------------------------------------------------------- */
/* SafeContents / SafeBag                                                     */
/* ------------------------------------------------------------------------- */

struct asnber_pkcs12_safe_contents : handle_base {};

static const asnber_node_t *bagAt(const asnber_pkcs12_safe_contents_t *contents,
                                size_t index) noexcept
{
    return asnber_node_child_at(contents->root, index);
}

extern "C" ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_safe_contents_open(
    asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asnber_pkcs12_safe_contents_t **out_contents)
{
    return openStructure(ctx, der, der_size, pkcs12SchemaTable(),
                         kPkcs12RootSafeContents,
                         out_contents);
}

extern "C" ASNBER_PKCS12_API void asnber_pkcs12_safe_contents_close(
    asnber_pkcs12_safe_contents_t *contents)
{
    closeStructure(contents);
}

extern "C" ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_safe_contents_bag_count(
    const asnber_pkcs12_safe_contents_t *contents, size_t *out_count)
{
    if (contents == nullptr || out_count == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_count = asnber_node_child_count(contents->root);
    return ASNBER_OK;
}

extern "C" ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_safe_contents_bag_at(
    const asnber_pkcs12_safe_contents_t *contents, size_t index,
    const char **out_bag_id_oid, size_t *out_bag_id_oid_size,
    const uint8_t **out_bag_value_tlv, size_t *out_bag_value_tlv_size,
    size_t *out_attribute_count)
{
    if (contents == nullptr || out_bag_id_oid == nullptr ||
        out_bag_id_oid_size == nullptr || out_bag_value_tlv == nullptr ||
        out_bag_value_tlv_size == nullptr || out_attribute_count == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_bag_id_oid = nullptr;
    *out_bag_id_oid_size = 0;
    *out_bag_value_tlv = nullptr;
    *out_bag_value_tlv_size = 0;
    *out_attribute_count = 0;

    const asnber_node_t *bag = bagAt(contents, index);
    if (bag == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }

    const asnber_node_t *bag_id = asnber_node_child_by_name(bag, "bagId");
    if (bag_id == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }

    asnber_err_t status =
        asnber_node_get_oid(bag_id, out_bag_id_oid, out_bag_id_oid_size);
    if (status != ASNBER_OK) {
        return status;
    }
    status = explicitInnerTlv(asnber_node_child_by_name(bag, "bagValue"),
                              out_bag_value_tlv, out_bag_value_tlv_size);
    if (status != ASNBER_OK) {
        return status;
    }
    const asnber_node_t *attributes = bagAttributes(bag);
    *out_attribute_count =
        (attributes == nullptr) ? 0 : asnber_node_child_count(attributes);
    return ASNBER_OK;
}

extern "C" ASNBER_PKCS12_API asnber_err_t
asnber_pkcs12_safe_contents_bag_attribute_at(
    const asnber_pkcs12_safe_contents_t *contents, size_t bag_index,
    size_t attribute_index, const char **out_attr_id_oid,
    size_t *out_attr_id_oid_size, const asnber_node_t **out_values)
{
    if (contents == nullptr || out_attr_id_oid == nullptr ||
        out_attr_id_oid_size == nullptr || out_values == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_attr_id_oid = nullptr;
    *out_attr_id_oid_size = 0;
    *out_values = nullptr;

    const asnber_node_t *bag = bagAt(contents, bag_index);
    if (bag == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *attributes = bagAttributes(bag);
    if (attributes == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *attribute =
        asnber_node_child_at(attributes, attribute_index);
    if (attribute == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }

    const asnber_node_t *attr_id =
        asnber_node_child_by_name(attribute, "attrId");
    const asnber_node_t *values =
        asnber_node_child_by_name(attribute, "attrValues");
    if (attr_id == nullptr || values == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }

    asnber_err_t status =
        asnber_node_get_oid(attr_id, out_attr_id_oid, out_attr_id_oid_size);
    if (status != ASNBER_OK) {
        return status;
    }
    *out_values = values;
    return ASNBER_OK;
}

/* ------------------------------------------------------------------------- */
/* CertBag                                                                    */
/* ------------------------------------------------------------------------- */

struct asnber_pkcs12_cert_bag : handle_base {};

extern "C" ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_cert_bag_open(
    asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asnber_pkcs12_cert_bag_t **out_bag)
{
    return openStructure(ctx, der, der_size, pkcs12SchemaTable(),
                         kPkcs12RootCertBag, out_bag);
}

extern "C" ASNBER_PKCS12_API void asnber_pkcs12_cert_bag_close(
    asnber_pkcs12_cert_bag_t *bag)
{
    closeStructure(bag);
}

extern "C" ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_cert_bag_cert_id(
    const asnber_pkcs12_cert_bag_t *bag, const char **out_dotted,
    size_t *out_size)
{
    if (bag == nullptr || out_dotted == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = field(bag, "certId");
    if (node == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    return asnber_node_get_oid(node, out_dotted, out_size);
}

extern "C" ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_cert_bag_cert_value_tlv(
    const asnber_pkcs12_cert_bag_t *bag, const uint8_t **out_data,
    size_t *out_size)
{
    if (bag == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return explicitInnerTlv(field(bag, "certValue"), out_data, out_size);
}

extern "C" ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_cert_bag_certificate(
    const asnber_pkcs12_cert_bag_t *bag, const uint8_t **out_data,
    size_t *out_size)
{
    if (bag == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_data = nullptr;
    *out_size = 0;

    const asnber_node_t *cert_id = field(bag, "certId");
    if (cert_id == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    const char *dotted = nullptr;
    size_t dotted_size = 0;
    asnber_err_t status =
        asnber_node_get_oid(cert_id, &dotted, &dotted_size);
    if (status != ASNBER_OK) {
        return status;
    }
    if (!oidEquals(dotted, dotted_size, kX509CertificateOid)) {
        return ASNBER_E_UNSUPPORTED;
    }

    const uint8_t *inner = nullptr;
    size_t inner_size = 0;
    status = explicitInnerTlv(field(bag, "certValue"), &inner, &inner_size);
    if (status != ASNBER_OK) {
        return status;
    }
    status = octetsFromTlv(inner, inner_size, out_data, out_size);
    if (status != ASNBER_OK) {
        *out_data = nullptr;
        *out_size = 0;
    }
    return status;
}
