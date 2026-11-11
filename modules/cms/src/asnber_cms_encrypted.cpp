/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-cms 只读切片的 EncryptedData 结构访问（RFC 5652 第 8 节）。
 *
 * 职责：用随模块发布的描述表加载 schema，按 DER 严格模式解码裸
 *       EncryptedData，并把 version、encryptedContentInfo 与
 *       unprotectedAttrs 投影为原始 TLV / 值。
 * 边界：不解密、不派生密钥、不校验 MAC、不展开算法参数或属性内容。
 *       ContentInfo 剥壳由调用方用既有 content_info API 完成，本文件不提供
 *       自动剥壳。open 不校验 version 与 unprotectedAttrs 的配对语义。
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

const asnber_node_t *encryptedContentInfo(const handle_base *object) noexcept
{
    return field(object, "encryptedContentInfo");
}

} // namespace

struct asnber_cms_encrypted_data : cms_detail::handle_base {};

extern "C" ASNBER_CMS_API asnber_err_t asnber_cms_encrypted_data_open(
    asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asnber_cms_encrypted_data_t **out_encrypted_data)
{
    return openStructure(ctx, der, der_size, cmsSchemaTable(),
                         kCmsRootEncryptedData,
                         out_encrypted_data);
}

extern "C" ASNBER_CMS_API void asnber_cms_encrypted_data_close(
    asnber_cms_encrypted_data_t *encrypted_data)
{
    closeStructure(encrypted_data);
}

extern "C" ASNBER_CMS_API asnber_err_t asnber_cms_encrypted_data_version(
    const asnber_cms_encrypted_data_t *encrypted_data, int64_t *out_version)
{
    if (encrypted_data == nullptr || out_version == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = nullptr;
    asnber_err_t status =
        cms_detail::requireField(encrypted_data, "version", &node);
    if (status != ASNBER_OK) {
        return status;
    }
    return asnber_node_get_int64(node, out_version);
}

extern "C" ASNBER_CMS_API asnber_err_t asnber_cms_encrypted_data_content_type(
    const asnber_cms_encrypted_data_t *encrypted_data, const char **out_oid,
    size_t *out_oid_size)
{
    if (encrypted_data == nullptr || out_oid == nullptr ||
        out_oid_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *info = encryptedContentInfo(encrypted_data);
    const asnber_node_t *node = nestedField(info, "contentType");
    if (node == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    return asnber_node_get_oid(node, out_oid, out_oid_size);
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_encrypted_data_content_encryption_algorithm(
    const asnber_cms_encrypted_data_t *encrypted_data, const char **out_oid,
    size_t *out_oid_size, const uint8_t **out_parameters,
    size_t *out_parameters_size)
{
    if (encrypted_data == nullptr || out_oid == nullptr ||
        out_oid_size == nullptr || out_parameters == nullptr ||
        out_parameters_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *info = encryptedContentInfo(encrypted_data);
    const asnber_node_t *algorithm =
        nestedField(info, "contentEncryptionAlgorithm");
    if (algorithm == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    return algorithmFields(algorithm, out_oid, out_oid_size, out_parameters,
                           out_parameters_size);
}

extern "C" ASNBER_CMS_API asnber_err_t asnber_cms_encrypted_data_encrypted_content(
    const asnber_cms_encrypted_data_t *encrypted_data, const uint8_t **out_data,
    size_t *out_size)
{
    if (encrypted_data == nullptr || out_data == nullptr ||
        out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *info = encryptedContentInfo(encrypted_data);
    const asnber_node_t *node = nestedField(info, "encryptedContent");
    if (node == nullptr) {
        *out_data = nullptr;
        *out_size = 0;
        return ASNBER_OK;
    }
    /*
     * `[0] IMPLICIT OCTET STRING` 的节点带 context 标签，不满足
     * asnber_node_get_octets 的 UNIVERSAL 4 前置条件；get_raw_string 走同一
     * 合并实现（mergePrimitiveContent），构造形式按核心规则展平。
     */
    return asnber_node_get_raw_string(node, out_data, out_size);
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_encrypted_data_encrypted_content_tlv(
    const asnber_cms_encrypted_data_t *encrypted_data, const uint8_t **out_data,
    size_t *out_size)
{
    if (encrypted_data == nullptr || out_data == nullptr ||
        out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *info = encryptedContentInfo(encrypted_data);
    const asnber_node_t *node = nestedField(info, "encryptedContent");
    if (node == nullptr) {
        *out_data = nullptr;
        *out_size = 0;
        return ASNBER_OK;
    }
    *out_data = asnber_node_tlv(node, out_size);
    return (*out_data == nullptr) ? ASNBER_E_INVALID_STATE : ASNBER_OK;
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_encrypted_data_unprotected_attrs_tlv(
    const asnber_cms_encrypted_data_t *encrypted_data, const uint8_t **out_data,
    size_t *out_size)
{
    if (encrypted_data == nullptr || out_data == nullptr ||
        out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = field(encrypted_data, "unprotectedAttrs");
    if (node == nullptr) {
        *out_data = nullptr;
        *out_size = 0;
        return ASNBER_OK;
    }
    *out_data = asnber_node_tlv(node, out_size);
    return (*out_data == nullptr) ? ASNBER_E_INVALID_STATE : ASNBER_OK;
}
