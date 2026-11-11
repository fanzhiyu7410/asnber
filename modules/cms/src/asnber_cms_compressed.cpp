/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-cms 只读切片的 CompressedData 结构访问（RFC 3274 第 2 节）。
 *
 * 职责：用随模块发布的描述表加载 schema，按描述表解码裸 CompressedData
 *       （DER 输入；错标签按未知字段静默忽略，不启用严格模式），并把
 *       version、compressionAlgorithm 与 EncapsulatedContentInfo 投影为
 *       原始 TLV / 值。
 * 边界：不解压、不展开压缩算法参数或 eContent 内容。ContentInfo 剥壳由
 *       调用方用既有 content_info API 完成，本文件不提供自动剥壳。
 *       open 不校验 version 必须为 0 的语义。
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

const asnber_node_t *encapContentInfo(const handle_base *object) noexcept
{
    return field(object, "encapContentInfo");
}

} // namespace

struct asnber_cms_compressed_data : cms_detail::handle_base {};

extern "C" ASNBER_CMS_API asnber_err_t asnber_cms_compressed_data_open(
    asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asnber_cms_compressed_data_t **out_compressed_data)
{
    return openStructure(ctx, der, der_size, cmsSchemaTable(),
                         kCmsRootCompressedData,
                         out_compressed_data);
}

extern "C" ASNBER_CMS_API void asnber_cms_compressed_data_close(
    asnber_cms_compressed_data_t *compressed_data)
{
    closeStructure(compressed_data);
}

extern "C" ASNBER_CMS_API asnber_err_t asnber_cms_compressed_data_version(
    const asnber_cms_compressed_data_t *compressed_data, int64_t *out_version)
{
    if (compressed_data == nullptr || out_version == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = nullptr;
    asnber_err_t status =
        requireField(compressed_data, "version", &node);
    if (status != ASNBER_OK) {
        return status;
    }
    return asnber_node_get_int64(node, out_version);
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_compressed_data_compression_algorithm(
    const asnber_cms_compressed_data_t *compressed_data, const char **out_oid,
    size_t *out_oid_size, const uint8_t **out_parameters,
    size_t *out_parameters_size)
{
    if (compressed_data == nullptr || out_oid == nullptr ||
        out_oid_size == nullptr || out_parameters == nullptr ||
        out_parameters_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *algorithm =
        field(compressed_data, "compressionAlgorithm");
    if (algorithm == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    return algorithmFields(algorithm, out_oid, out_oid_size, out_parameters,
                           out_parameters_size);
}

extern "C" ASNBER_CMS_API asnber_err_t asnber_cms_compressed_data_econtent_type(
    const asnber_cms_compressed_data_t *compressed_data, const char **out_oid,
    size_t *out_oid_size)
{
    if (compressed_data == nullptr || out_oid == nullptr ||
        out_oid_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *info = encapContentInfo(compressed_data);
    const asnber_node_t *node = nestedField(info, "eContentType");
    if (node == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    return asnber_node_get_oid(node, out_oid, out_oid_size);
}

extern "C" ASNBER_CMS_API asnber_err_t asnber_cms_compressed_data_econtent(
    const asnber_cms_compressed_data_t *compressed_data, const uint8_t **out_data,
    size_t *out_size)
{
    if (compressed_data == nullptr || out_data == nullptr ||
        out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *info = encapContentInfo(compressed_data);
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

extern "C" ASNBER_CMS_API asnber_err_t asnber_cms_compressed_data_econtent_tlv(
    const asnber_cms_compressed_data_t *compressed_data, const uint8_t **out_data,
    size_t *out_size)
{
    if (compressed_data == nullptr || out_data == nullptr ||
        out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *info = encapContentInfo(compressed_data);
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
