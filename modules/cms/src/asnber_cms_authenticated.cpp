/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-cms 只读切片的 AuthenticatedData 结构访问（RFC 5652 第 9 节）。
 *
 * 职责：用随模块发布的描述表加载 schema，按 DER 严格模式解码裸
 *       AuthenticatedData，并把 version、originatorInfo、recipientInfos、
 *       macAlgorithm、digestAlgorithm、EncapsulatedContentInfo、authAttrs、
 *       mac 与 unauthAttrs 投影为原始 TLV / 值。
 * 边界：不校验 MAC、不计算摘要、不做密钥派生/解密、不展开 RecipientInfo
 *       分支内部字段。ContentInfo 剥壳由调用方用既有 content_info API
 *       完成，本文件不提供自动剥壳。open 不校验 version 0/1/3 语义。
 * 依赖：只使用核心公共 C ABI；生成表由 asnberc 产出。
 * 所有权：句柄持有 schema 与文档，close 时逆序释放；访问器返回的指针
 *         借用句柄，close 后失效。
 */

#include "asnber/cms/cms.h"

#include <asnber/asnber_schema.h>

#include "cms_structure_support.h"
#include "cms_tables.h"

namespace {

using cms_detail::algorithmFields;
using cms_detail::closeStructure;
using cms_detail::field;
using cms_detail::handle_base;
using cms_detail::nestedField;
using cms_detail::openStructure;
using cms_detail::requireField;

constexpr uint32_t kTagSequence = 16;

const asnber_node_t *encapContentInfo(const handle_base *object) noexcept
{
    return field(object, "encapContentInfo");
}

/*
 * RecipientInfo 分支判别（RFC 5652 §6.2）：ktri 无标签（UNIVERSAL
 * SEQUENCE），kari..ori 为 `[n] IMPLICIT SEQUENCE`，按 context 标签 n 判别。
 */
int recipientChoiceKind(const asnber_node_t *node) noexcept
{
    if (node == nullptr) {
        return -1;
    }
    if (asnber_node_tag_class(node) == ASNBER_TAG_UNIVERSAL &&
        asnber_node_tag_number(node) == kTagSequence) {
        return ASNBER_CMS_RECIPIENT_KTRI;
    }
    if (asnber_node_tag_class(node) != ASNBER_TAG_CONTEXT) {
        return -1;
    }
    switch (asnber_node_tag_number(node)) {
    case 1:
        return ASNBER_CMS_RECIPIENT_KARI;
    case 2:
        return ASNBER_CMS_RECIPIENT_KEKRI;
    case 3:
        return ASNBER_CMS_RECIPIENT_PWRI;
    case 4:
        return ASNBER_CMS_RECIPIENT_ORI;
    default:
        return -1;
    }
}

} // namespace

struct asnber_cms_authenticated_data : cms_detail::handle_base {};

extern "C" ASNBER_CMS_API asnber_err_t asnber_cms_authenticated_data_open(
    asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asnber_cms_authenticated_data_t **out_authenticated_data)
{
    return openStructure(ctx, der, der_size, cmsSchemaTable(),
                         kCmsRootAuthenticatedData,
                         out_authenticated_data);
}

extern "C" ASNBER_CMS_API void asnber_cms_authenticated_data_close(
    asnber_cms_authenticated_data_t *authenticated_data)
{
    closeStructure(authenticated_data);
}

extern "C" ASNBER_CMS_API asnber_err_t asnber_cms_authenticated_data_version(
    const asnber_cms_authenticated_data_t *authenticated_data,
    int64_t *out_version)
{
    if (authenticated_data == nullptr || out_version == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = nullptr;
    asnber_err_t status =
        requireField(authenticated_data, "version", &node);
    if (status != ASNBER_OK) {
        return status;
    }
    return asnber_node_get_int64(node, out_version);
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_authenticated_data_originator_info_tlv(
    const asnber_cms_authenticated_data_t *authenticated_data,
    const uint8_t **out_data, size_t *out_size)
{
    if (authenticated_data == nullptr || out_data == nullptr ||
        out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = field(authenticated_data, "originatorInfo");
    if (node == nullptr) {
        *out_data = nullptr;
        *out_size = 0;
        return ASNBER_OK;
    }
    *out_data = asnber_node_tlv(node, out_size);
    return (*out_data == nullptr) ? ASNBER_E_INVALID_STATE : ASNBER_OK;
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_authenticated_data_recipient_count(
    const asnber_cms_authenticated_data_t *authenticated_data,
    size_t *out_count)
{
    if (authenticated_data == nullptr || out_count == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *recipients =
        field(authenticated_data, "recipientInfos");
    if (recipients == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    *out_count = asnber_node_child_count(recipients);
    return ASNBER_OK;
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_authenticated_data_recipient_at(
    const asnber_cms_authenticated_data_t *authenticated_data, size_t index,
    int *out_kind, const uint8_t **out_tlv, size_t *out_tlv_size)
{
    if (authenticated_data == nullptr || out_kind == nullptr ||
        out_tlv == nullptr || out_tlv_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_kind = -1;
    *out_tlv = nullptr;
    *out_tlv_size = 0;

    const asnber_node_t *recipients =
        field(authenticated_data, "recipientInfos");
    if (recipients == nullptr || index >= asnber_node_child_count(recipients)) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *item = asnber_node_child_at(recipients, index);
    const int kind = recipientChoiceKind(item);
    if (kind < 0) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    *out_kind = kind;
    *out_tlv = asnber_node_tlv(item, out_tlv_size);
    return (*out_tlv == nullptr) ? ASNBER_E_INVALID_STATE : ASNBER_OK;
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_authenticated_data_mac_algorithm(
    const asnber_cms_authenticated_data_t *authenticated_data,
    const char **out_oid, size_t *out_oid_size,
    const uint8_t **out_parameters, size_t *out_parameters_size)
{
    if (authenticated_data == nullptr || out_oid == nullptr ||
        out_oid_size == nullptr || out_parameters == nullptr ||
        out_parameters_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *algorithm =
        field(authenticated_data, "macAlgorithm");
    if (algorithm == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    return algorithmFields(algorithm, out_oid, out_oid_size, out_parameters,
                           out_parameters_size);
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_authenticated_data_digest_algorithm(
    const asnber_cms_authenticated_data_t *authenticated_data,
    const char **out_oid, size_t *out_oid_size,
    const uint8_t **out_parameters, size_t *out_parameters_size)
{
    if (authenticated_data == nullptr || out_oid == nullptr ||
        out_oid_size == nullptr || out_parameters == nullptr ||
        out_parameters_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *algorithm =
        field(authenticated_data, "digestAlgorithm");
    if (algorithm == nullptr) {
        *out_oid = nullptr;
        *out_oid_size = 0;
        *out_parameters = nullptr;
        *out_parameters_size = 0;
        return ASNBER_OK;
    }
    return algorithmFields(algorithm, out_oid, out_oid_size, out_parameters,
                           out_parameters_size);
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_authenticated_data_econtent_type(
    const asnber_cms_authenticated_data_t *authenticated_data,
    const char **out_oid, size_t *out_oid_size)
{
    if (authenticated_data == nullptr || out_oid == nullptr ||
        out_oid_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *info = encapContentInfo(authenticated_data);
    const asnber_node_t *node = nestedField(info, "eContentType");
    if (node == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    return asnber_node_get_oid(node, out_oid, out_oid_size);
}

extern "C" ASNBER_CMS_API asnber_err_t asnber_cms_authenticated_data_econtent(
    const asnber_cms_authenticated_data_t *authenticated_data,
    const uint8_t **out_data, size_t *out_size)
{
    if (authenticated_data == nullptr || out_data == nullptr ||
        out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *info = encapContentInfo(authenticated_data);
    const asnber_node_t *wrapper = nestedField(info, "eContent");
    if (wrapper == nullptr) {
        *out_data = nullptr;
        *out_size = 0;
        return ASNBER_OK;
    }
    /* eContent 为 [0] EXPLICIT OCTET STRING：唯一子节点才是 OCTET STRING。 */
    const asnber_node_t *octets = asnber_node_child_at(wrapper, 0);
    if (octets == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    return asnber_node_get_octets(octets, out_data, out_size);
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_authenticated_data_econtent_tlv(
    const asnber_cms_authenticated_data_t *authenticated_data,
    const uint8_t **out_data, size_t *out_size)
{
    if (authenticated_data == nullptr || out_data == nullptr ||
        out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *info = encapContentInfo(authenticated_data);
    const asnber_node_t *wrapper = nestedField(info, "eContent");
    if (wrapper == nullptr) {
        *out_data = nullptr;
        *out_size = 0;
        return ASNBER_OK;
    }
    const asnber_node_t *octets = asnber_node_child_at(wrapper, 0);
    if (octets == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    *out_data = asnber_node_tlv(octets, out_size);
    return (*out_data == nullptr) ? ASNBER_E_INVALID_STATE : ASNBER_OK;
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_authenticated_data_auth_attrs_tlv(
    const asnber_cms_authenticated_data_t *authenticated_data,
    const uint8_t **out_data, size_t *out_size)
{
    if (authenticated_data == nullptr || out_data == nullptr ||
        out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = field(authenticated_data, "authAttrs");
    if (node == nullptr) {
        *out_data = nullptr;
        *out_size = 0;
        return ASNBER_OK;
    }
    *out_data = asnber_node_tlv(node, out_size);
    return (*out_data == nullptr) ? ASNBER_E_INVALID_STATE : ASNBER_OK;
}

extern "C" ASNBER_CMS_API asnber_err_t asnber_cms_authenticated_data_mac(
    const asnber_cms_authenticated_data_t *authenticated_data,
    const uint8_t **out_data, size_t *out_size)
{
    if (authenticated_data == nullptr || out_data == nullptr ||
        out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = nullptr;
    asnber_err_t status =
        requireField(authenticated_data, "mac", &node);
    if (status != ASNBER_OK) {
        return status;
    }
    return asnber_node_get_octets(node, out_data, out_size);
}

extern "C" ASNBER_CMS_API asnber_err_t asnber_cms_authenticated_data_mac_tlv(
    const asnber_cms_authenticated_data_t *authenticated_data,
    const uint8_t **out_data, size_t *out_size)
{
    if (authenticated_data == nullptr || out_data == nullptr ||
        out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = nullptr;
    asnber_err_t status =
        requireField(authenticated_data, "mac", &node);
    if (status != ASNBER_OK) {
        return status;
    }
    *out_data = asnber_node_tlv(node, out_size);
    return (*out_data == nullptr) ? ASNBER_E_INVALID_STATE : ASNBER_OK;
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_authenticated_data_unauth_attrs_tlv(
    const asnber_cms_authenticated_data_t *authenticated_data,
    const uint8_t **out_data, size_t *out_size)
{
    if (authenticated_data == nullptr || out_data == nullptr ||
        out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = field(authenticated_data, "unauthAttrs");
    if (node == nullptr) {
        *out_data = nullptr;
        *out_size = 0;
        return ASNBER_OK;
    }
    *out_data = asnber_node_tlv(node, out_size);
    return (*out_data == nullptr) ? ASNBER_E_INVALID_STATE : ASNBER_OK;
}
