/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-cms 只读切片的 ContentInfo / SignedData 结构访问。
 *
 * 职责：用随模块发布的描述表加载 schema，按 DER 严格模式解码
 *       ContentInfo 与 SignedData，并把结构字段投影为核心节点/值。
 * 边界：不验签、不计算摘要、不解密、不校验证书链；ANY 与属性集合只
 *       返回原始 TLV，密码学语义由调用方按 OID 二次解析。
 * 依赖：只使用核心公共 C ABI；生成表由 asnberc 产出。
 * 所有权：句柄持有 schema 与文档，close 时逆序释放；访问器返回的指针
 *         借用句柄，close 后失效。
 * 线程：模块没有全局可变状态；不同句柄/上下文互不影响。同一 ctx 的
 *       并发使用需由调用方加锁（核心错误状态挂在 ctx 上）。
 */

#include "asnber/cms/cms.h"

#include <asnber/asnber_schema.h>

#include "cms_structure_support.h"
#include "cms_tables.h"

namespace {

using cms_detail::algorithmFields;
using cms_detail::closeStructure;
using cms_detail::collectionItem;
using cms_detail::field;
using cms_detail::handle_base;
using cms_detail::kTagSequence;
using cms_detail::nestedField;
using cms_detail::openStructure;
using cms_detail::optionalCollectionCount;
using cms_detail::requireField;

/*
 * CertificateChoices 分支：按实际标签判别。证书是通用 SEQUENCE；其余
 * 分支分别是 context [0..3] IMPLICIT。
 */
int certificateChoiceKind(const asnber_node_t *node) noexcept
{
    if (node == nullptr) {
        return -1;
    }
    if (asnber_node_tag_class(node) == ASNBER_TAG_UNIVERSAL &&
        asnber_node_tag_number(node) == kTagSequence) {
        return ASNBER_CMS_CERT_CHOICE_CERTIFICATE;
    }
    if (asnber_node_tag_class(node) == ASNBER_TAG_CONTEXT) {
        switch (asnber_node_tag_number(node)) {
        case 0:
            return ASNBER_CMS_CERT_CHOICE_EXTENDED;
        case 1:
            return ASNBER_CMS_CERT_CHOICE_V1_ATTR_CERT;
        case 2:
            return ASNBER_CMS_CERT_CHOICE_V2_ATTR_CERT;
        case 3:
            return ASNBER_CMS_CERT_CHOICE_OTHER;
        default:
            break;
        }
    }
    return -1;
}

int revocationChoiceKind(const asnber_node_t *node) noexcept
{
    if (node == nullptr) {
        return -1;
    }
    if (asnber_node_tag_class(node) == ASNBER_TAG_UNIVERSAL &&
        asnber_node_tag_number(node) == kTagSequence) {
        return ASNBER_CMS_REVOCATION_CHOICE_CRL;
    }
    if (asnber_node_tag_class(node) == ASNBER_TAG_CONTEXT &&
        asnber_node_tag_number(node) == 1) {
        return ASNBER_CMS_REVOCATION_CHOICE_OTHER;
    }
    return -1;
}

int signerIdChoiceKind(const asnber_node_t *node) noexcept
{
    if (node == nullptr) {
        return -1;
    }
    if (asnber_node_tag_class(node) == ASNBER_TAG_UNIVERSAL &&
        asnber_node_tag_number(node) == kTagSequence) {
        return ASNBER_CMS_SID_ISSUER_AND_SERIAL;
    }
    if (asnber_node_tag_class(node) == ASNBER_TAG_CONTEXT &&
        asnber_node_tag_number(node) == 0) {
        return ASNBER_CMS_SID_SUBJECT_KEY_IDENTIFIER;
    }
    return -1;
}

/* TBSCertificate 字段访问：仅证书分支可用。 */
asnber_err_t certificateTbsField(const handle_base *signed_data,
                               size_t index, const char *name,
                               const asnber_node_t **out_node) noexcept
{
    const asnber_node_t *item = nullptr;
    asnber_err_t status =
        collectionItem(signed_data, "certificates", index, &item);
    if (status != ASNBER_OK) {
        return status;
    }
    if (certificateChoiceKind(item) != ASNBER_CMS_CERT_CHOICE_CERTIFICATE) {
        /* 扩展证书 / v1、v2 AttributeCertificate / other 只保留原始 TLV。 */
        return ASNBER_E_UNSUPPORTED;
    }
    const asnber_node_t *tbs = nestedField(item, "toBeSigned");
    if (tbs == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    *out_node = nestedField(tbs, name);
    return (*out_node == nullptr) ? ASNBER_E_SCHEMA_FIELD : ASNBER_OK;
}

asnber_err_t signerField(const handle_base *signed_data, size_t index,
                       const char *name, const asnber_node_t **out_node) noexcept
{
    const asnber_node_t *signer = nullptr;
    asnber_err_t status =
        collectionItem(signed_data, "signerInfos", index, &signer);
    if (status != ASNBER_OK) {
        return status;
    }
    *out_node = nestedField(signer, name);
    return (*out_node == nullptr) ? ASNBER_E_SCHEMA_FIELD : ASNBER_OK;
}

} // namespace

/* ------------------------------------------------------------------------- */
/* ContentInfo                                                                */
/* ------------------------------------------------------------------------- */

struct asnber_cms_content_info : handle_base {};

extern "C" ASNBER_CMS_API asnber_err_t asnber_cms_content_info_open(
    asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asnber_cms_content_info_t **out_info)
{
    return openStructure(ctx, der, der_size, cmsSchemaTable(),
                         kCmsRootContentInfo, out_info);
}

extern "C" ASNBER_CMS_API void asnber_cms_content_info_close(
    asnber_cms_content_info_t *info)
{
    closeStructure(info);
}

extern "C" ASNBER_CMS_API asnber_err_t asnber_cms_content_info_content_type(
    const asnber_cms_content_info_t *info, const char **out_dotted,
    size_t *out_size)
{
    if (info == nullptr || out_dotted == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = nullptr;
    asnber_err_t status = requireField(info, "contentType", &node);
    if (status != ASNBER_OK) {
        return status;
    }
    return asnber_node_get_oid(node, out_dotted, out_size);
}

extern "C" ASNBER_CMS_API asnber_err_t asnber_cms_content_info_content(
    const asnber_cms_content_info_t *info, const uint8_t **out_data,
    size_t *out_size)
{
    if (info == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = nullptr;
    asnber_err_t status = requireField(info, "content", &node);
    if (status != ASNBER_OK) {
        return status;
    }
    /* [0] EXPLICIT ANY：content 给出内层 ANY 的完整原始 TLV。 */
    return asnber_node_content(node, out_data, out_size);
}

/* ------------------------------------------------------------------------- */
/* SignedData                                                                 */
/* ------------------------------------------------------------------------- */

struct asnber_cms_signed_data : handle_base {};

extern "C" ASNBER_CMS_API asnber_err_t asnber_cms_signed_data_open(
    asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asnber_cms_signed_data_t **out_signed_data)
{
    return openStructure(ctx, der, der_size, cmsSchemaTable(),
                         kCmsRootSignedData,
                         out_signed_data);
}

extern "C" ASNBER_CMS_API void asnber_cms_signed_data_close(
    asnber_cms_signed_data_t *signed_data)
{
    closeStructure(signed_data);
}

extern "C" ASNBER_CMS_API asnber_err_t asnber_cms_signed_data_version(
    const asnber_cms_signed_data_t *signed_data, int64_t *out_version)
{
    if (signed_data == nullptr || out_version == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = nullptr;
    asnber_err_t status = requireField(signed_data, "version", &node);
    if (status != ASNBER_OK) {
        return status;
    }
    return asnber_node_get_int64(node, out_version);
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_signed_data_digest_algorithm_count(
    const asnber_cms_signed_data_t *signed_data, size_t *out_count)
{
    if (signed_data == nullptr || out_count == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return optionalCollectionCount(signed_data, "digestAlgorithms",
                                   out_count);
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_signed_data_digest_algorithm_at(
    const asnber_cms_signed_data_t *signed_data, size_t index,
    const char **out_oid, size_t *out_oid_size,
    const uint8_t **out_parameters, size_t *out_parameters_size)
{
    if (signed_data == nullptr || out_oid == nullptr ||
        out_oid_size == nullptr || out_parameters == nullptr ||
        out_parameters_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *algorithm = nullptr;
    asnber_err_t status =
        collectionItem(signed_data, "digestAlgorithms", index, &algorithm);
    if (status != ASNBER_OK) {
        return status;
    }
    return algorithmFields(algorithm, out_oid, out_oid_size, out_parameters,
                           out_parameters_size);
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_signed_data_encap_content_type(
    const asnber_cms_signed_data_t *signed_data, const char **out_dotted,
    size_t *out_size)
{
    if (signed_data == nullptr || out_dotted == nullptr ||
        out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *encap =
        field(signed_data, "encapContentInfo");
    const asnber_node_t *node = nestedField(encap, "eContentType");
    if (node == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    return asnber_node_get_oid(node, out_dotted, out_size);
}

extern "C" ASNBER_CMS_API asnber_err_t asnber_cms_signed_data_encap_content(
    const asnber_cms_signed_data_t *signed_data, const uint8_t **out_data,
    size_t *out_size)
{
    if (signed_data == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *encap =
        field(signed_data, "encapContentInfo");
    const asnber_node_t *wrapper = nestedField(encap, "eContent");
    if (wrapper == nullptr) {
        *out_data = nullptr;
        *out_size = 0;
        return ASNBER_OK;
    }
    /*
     * eContent 为 [0] EXPLICIT OCTET STRING：节点是外层包装，
     * 唯一子节点才是 OCTET STRING。
     */
    const asnber_node_t *octets = asnber_node_child_at(wrapper, 0);
    if (octets == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    return asnber_node_get_octets(octets, out_data, out_size);
}

extern "C" ASNBER_CMS_API asnber_err_t asnber_cms_signed_data_encap_content_tlv(
    const asnber_cms_signed_data_t *signed_data, const uint8_t **out_data,
    size_t *out_size)
{
    if (signed_data == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *encap =
        field(signed_data, "encapContentInfo");
    const asnber_node_t *wrapper = nestedField(encap, "eContent");
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
asnber_cms_signed_data_certificate_count(
    const asnber_cms_signed_data_t *signed_data, size_t *out_count)
{
    if (signed_data == nullptr || out_count == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return optionalCollectionCount(signed_data, "certificates", out_count);
}

extern "C" ASNBER_CMS_API asnber_err_t asnber_cms_signed_data_certificate_at(
    const asnber_cms_signed_data_t *signed_data, size_t index,
    int *out_choice, const uint8_t **out_tlv, size_t *out_tlv_size)
{
    if (signed_data == nullptr || out_choice == nullptr ||
        out_tlv == nullptr || out_tlv_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *item = nullptr;
    asnber_err_t status =
        collectionItem(signed_data, "certificates", index, &item);
    if (status != ASNBER_OK) {
        return status;
    }
    const int kind = certificateChoiceKind(item);
    if (kind < 0) {
        return ASNBER_E_SCHEMA_TYPE;
    }
    *out_tlv = asnber_node_tlv(item, out_tlv_size);
    if (*out_tlv == nullptr) {
        return ASNBER_E_INVALID_STATE;
    }
    *out_choice = kind;
    return ASNBER_OK;
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_signed_data_certificate_subject(
    const asnber_cms_signed_data_t *signed_data, size_t index,
    const uint8_t **out_data, size_t *out_size)
{
    if (signed_data == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = nullptr;
    asnber_err_t status =
        certificateTbsField(signed_data, index, "subject", &node);
    if (status != ASNBER_OK) {
        return status;
    }
    *out_data = asnber_node_tlv(node, out_size);
    return (*out_data == nullptr) ? ASNBER_E_INVALID_STATE : ASNBER_OK;
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_signed_data_certificate_issuer(
    const asnber_cms_signed_data_t *signed_data, size_t index,
    const uint8_t **out_data, size_t *out_size)
{
    if (signed_data == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = nullptr;
    asnber_err_t status =
        certificateTbsField(signed_data, index, "issuer", &node);
    if (status != ASNBER_OK) {
        return status;
    }
    *out_data = asnber_node_tlv(node, out_size);
    return (*out_data == nullptr) ? ASNBER_E_INVALID_STATE : ASNBER_OK;
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_signed_data_certificate_serial(
    const asnber_cms_signed_data_t *signed_data, size_t index,
    const char **out_decimal, size_t *out_size)
{
    if (signed_data == nullptr || out_decimal == nullptr ||
        out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = nullptr;
    asnber_err_t status =
        certificateTbsField(signed_data, index, "serialNumber", &node);
    if (status != ASNBER_OK) {
        return status;
    }
    return asnber_node_get_bigint_decimal(node, out_decimal, out_size);
}

extern "C" ASNBER_CMS_API asnber_err_t asnber_cms_signed_data_crl_count(
    const asnber_cms_signed_data_t *signed_data, size_t *out_count)
{
    if (signed_data == nullptr || out_count == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return optionalCollectionCount(signed_data, "crls", out_count);
}

extern "C" ASNBER_CMS_API asnber_err_t asnber_cms_signed_data_crl_at(
    const asnber_cms_signed_data_t *signed_data, size_t index,
    int *out_choice, const uint8_t **out_tlv, size_t *out_tlv_size)
{
    if (signed_data == nullptr || out_choice == nullptr ||
        out_tlv == nullptr || out_tlv_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *item = nullptr;
    asnber_err_t status = collectionItem(signed_data, "crls", index, &item);
    if (status != ASNBER_OK) {
        return status;
    }
    const int kind = revocationChoiceKind(item);
    if (kind < 0) {
        return ASNBER_E_SCHEMA_TYPE;
    }
    *out_tlv = asnber_node_tlv(item, out_tlv_size);
    if (*out_tlv == nullptr) {
        return ASNBER_E_INVALID_STATE;
    }
    *out_choice = kind;
    return ASNBER_OK;
}

extern "C" ASNBER_CMS_API asnber_err_t asnber_cms_signed_data_signer_count(
    const asnber_cms_signed_data_t *signed_data, size_t *out_count)
{
    if (signed_data == nullptr || out_count == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return optionalCollectionCount(signed_data, "signerInfos", out_count);
}

extern "C" ASNBER_CMS_API asnber_err_t asnber_cms_signed_data_signer_version(
    const asnber_cms_signed_data_t *signed_data, size_t index,
    int64_t *out_version)
{
    if (signed_data == nullptr || out_version == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = nullptr;
    asnber_err_t status = signerField(signed_data, index, "version", &node);
    if (status != ASNBER_OK) {
        return status;
    }
    return asnber_node_get_int64(node, out_version);
}

extern "C" ASNBER_CMS_API asnber_err_t asnber_cms_signed_data_signer_sid_choice(
    const asnber_cms_signed_data_t *signed_data, size_t index,
    int *out_choice)
{
    if (signed_data == nullptr || out_choice == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = nullptr;
    asnber_err_t status = signerField(signed_data, index, "sid", &node);
    if (status != ASNBER_OK) {
        return status;
    }
    const int kind = signerIdChoiceKind(node);
    if (kind < 0) {
        return ASNBER_E_SCHEMA_TYPE;
    }
    *out_choice = kind;
    return ASNBER_OK;
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_signed_data_signer_sid_issuer(
    const asnber_cms_signed_data_t *signed_data, size_t index,
    const uint8_t **out_data, size_t *out_size)
{
    if (signed_data == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *sid = nullptr;
    asnber_err_t status = signerField(signed_data, index, "sid", &sid);
    if (status != ASNBER_OK) {
        return status;
    }
    if (signerIdChoiceKind(sid) != ASNBER_CMS_SID_ISSUER_AND_SERIAL) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *issuer = nestedField(sid, "issuer");
    if (issuer == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    *out_data = asnber_node_tlv(issuer, out_size);
    return (*out_data == nullptr) ? ASNBER_E_INVALID_STATE : ASNBER_OK;
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_signed_data_signer_sid_serial(
    const asnber_cms_signed_data_t *signed_data, size_t index,
    const char **out_decimal, size_t *out_size)
{
    if (signed_data == nullptr || out_decimal == nullptr ||
        out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *sid = nullptr;
    asnber_err_t status = signerField(signed_data, index, "sid", &sid);
    if (status != ASNBER_OK) {
        return status;
    }
    if (signerIdChoiceKind(sid) != ASNBER_CMS_SID_ISSUER_AND_SERIAL) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *serial = nestedField(sid, "serialNumber");
    if (serial == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    return asnber_node_get_bigint_decimal(serial, out_decimal, out_size);
}

/* serialNumber 完整原始 TLV（供结构构造侧原样承载，避免十进制往返）。 */
extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_signed_data_signer_sid_serial_tlv(
    const asnber_cms_signed_data_t *signed_data, size_t index,
    const uint8_t **out_data, size_t *out_size)
{
    if (signed_data == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *sid = nullptr;
    asnber_err_t status = signerField(signed_data, index, "sid", &sid);
    if (status != ASNBER_OK) {
        return status;
    }
    if (signerIdChoiceKind(sid) != ASNBER_CMS_SID_ISSUER_AND_SERIAL) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *serial = nestedField(sid, "serialNumber");
    if (serial == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    *out_data = asnber_node_tlv(serial, out_size);
    return (*out_data == nullptr) ? ASNBER_E_INVALID_STATE : ASNBER_OK;
}

/*
 * SubjectKeyIdentifier 是 `[0] IMPLICIT OCTET STRING`：节点本身是
 * context 标签的基本类型，不满足 asnber_node_get_octets 的 UNIVERSAL 4
 * 前置条件，因此按基本节点内容读取（隐藏的 OCTET STRING 语义由 schema
 * 标签模型保证）。
 */
extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_signed_data_signer_sid_subject_key_identifier(
    const asnber_cms_signed_data_t *signed_data, size_t index,
    const uint8_t **out_data, size_t *out_size)
{
    if (signed_data == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *sid = nullptr;
    asnber_err_t status = signerField(signed_data, index, "sid", &sid);
    if (status != ASNBER_OK) {
        return status;
    }
    if (signerIdChoiceKind(sid) != ASNBER_CMS_SID_SUBJECT_KEY_IDENTIFIER) {
        return ASNBER_E_INVALID_ARG;
    }
    return asnber_node_content(sid, out_data, out_size);
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_signed_data_signer_digest_algorithm(
    const asnber_cms_signed_data_t *signed_data, size_t index,
    const char **out_oid, size_t *out_oid_size,
    const uint8_t **out_parameters, size_t *out_parameters_size)
{
    if (signed_data == nullptr || out_oid == nullptr ||
        out_oid_size == nullptr || out_parameters == nullptr ||
        out_parameters_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *algorithm = nullptr;
    asnber_err_t status =
        signerField(signed_data, index, "digestAlgorithm", &algorithm);
    if (status != ASNBER_OK) {
        return status;
    }
    return algorithmFields(algorithm, out_oid, out_oid_size, out_parameters,
                           out_parameters_size);
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_signed_data_signer_signed_attrs(
    const asnber_cms_signed_data_t *signed_data, size_t index,
    const uint8_t **out_data, size_t *out_size)
{
    if (signed_data == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = nullptr;
    asnber_err_t status =
        signerField(signed_data, index, "signedAttrs", &node);
    if (status == ASNBER_E_SCHEMA_FIELD) {
        *out_data = nullptr;
        *out_size = 0;
        return ASNBER_OK;
    }
    if (status != ASNBER_OK) {
        return status;
    }
    *out_data = asnber_node_tlv(node, out_size);
    return (*out_data == nullptr) ? ASNBER_E_INVALID_STATE : ASNBER_OK;
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_signed_data_signer_signature_algorithm(
    const asnber_cms_signed_data_t *signed_data, size_t index,
    const char **out_oid, size_t *out_oid_size,
    const uint8_t **out_parameters, size_t *out_parameters_size)
{
    if (signed_data == nullptr || out_oid == nullptr ||
        out_oid_size == nullptr || out_parameters == nullptr ||
        out_parameters_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *algorithm = nullptr;
    asnber_err_t status =
        signerField(signed_data, index, "signatureAlgorithm", &algorithm);
    if (status != ASNBER_OK) {
        return status;
    }
    return algorithmFields(algorithm, out_oid, out_oid_size, out_parameters,
                           out_parameters_size);
}

extern "C" ASNBER_CMS_API asnber_err_t asnber_cms_signed_data_signer_signature(
    const asnber_cms_signed_data_t *signed_data, size_t index,
    const uint8_t **out_data, size_t *out_size)
{
    if (signed_data == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = nullptr;
    asnber_err_t status =
        signerField(signed_data, index, "signature", &node);
    if (status != ASNBER_OK) {
        return status;
    }
    return asnber_node_get_octets(node, out_data, out_size);
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_signed_data_signer_signature_tlv(
    const asnber_cms_signed_data_t *signed_data, size_t index,
    const uint8_t **out_data, size_t *out_size)
{
    if (signed_data == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = nullptr;
    asnber_err_t status =
        signerField(signed_data, index, "signature", &node);
    if (status != ASNBER_OK) {
        return status;
    }
    *out_data = asnber_node_tlv(node, out_size);
    return (*out_data == nullptr) ? ASNBER_E_INVALID_STATE : ASNBER_OK;
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_signed_data_signer_unsigned_attrs(
    const asnber_cms_signed_data_t *signed_data, size_t index,
    const uint8_t **out_data, size_t *out_size)
{
    if (signed_data == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = nullptr;
    asnber_err_t status =
        signerField(signed_data, index, "unsignedAttrs", &node);
    if (status == ASNBER_E_SCHEMA_FIELD) {
        *out_data = nullptr;
        *out_size = 0;
        return ASNBER_OK;
    }
    if (status != ASNBER_OK) {
        return status;
    }
    *out_data = asnber_node_tlv(node, out_size);
    return (*out_data == nullptr) ? ASNBER_E_INVALID_STATE : ASNBER_OK;
}
