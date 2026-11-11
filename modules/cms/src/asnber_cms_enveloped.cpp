/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-cms 只读切片的 EnvelopedData 结构访问（RFC 5652 第 6 节）。
 *
 * 职责：用随模块发布的描述表加载 schema，按 DER 严格模式解码裸
 *       EnvelopedData，并把 version、recipientInfos 各分支、
 *       encryptedContentInfo、unprotectedAttrs 投影为原始 TLV / 值。
 * 边界：不解密、不做密钥协商、不做 KEK/口令派生、不校验 MAC、不展开
 *       encryptedKey / oriValue / keyAttr 的内部语义。ContentInfo 剥壳由
 *       调用方用既有 content_info API 完成，本文件不提供自动剥壳。
 * 依赖：只使用核心公共 C ABI；生成表由 asnberc 产出。
 * 所有权：句柄持有 schema 与文档，close 时逆序释放；访问器返回的指针
 *         借用句柄，close 后失效。
 */

#include "asnber/cms/cms.h"

#include <asnber/asnber_schema.h>

#include "cms_structure_support.h"
#include "cms_tables.h"

#include <cstring>

namespace {

using cms_detail::algorithmFields;
using cms_detail::closeStructure;
using cms_detail::collectionItem;
using cms_detail::field;
using cms_detail::handle_base;
using cms_detail::kTagSequence;
using cms_detail::nestedField;
using cms_detail::openStructure;

/*
 * RecipientInfo 分支判别（RFC 5652 §6.2）：ktri 无标签（UNIVERSAL SEQUENCE），
 * kari..ori 为 `[n] IMPLICIT SEQUENCE`，按 context 标签 n 判别。
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
    const uint32_t number = asnber_node_tag_number(node);
    if (number < 1u || number > 4u) {
        return -1;
    }
    return static_cast<int>(number);
}

asnber_err_t recipientNode(const handle_base *object, size_t index,
                         const asnber_node_t **out_node) noexcept
{
    return collectionItem(object, "recipientInfos", index, out_node);
}

/*
 * 取指定下标的分支节点；分支与 expected 不符时返回 UNSUPPORTED，
 * 下标越界返回 INVALID_ARG。
 */
asnber_err_t recipientBranch(const handle_base *object, size_t index,
                           int expected, const asnber_node_t **out_node) noexcept
{
    const asnber_node_t *node = nullptr;
    asnber_err_t status = recipientNode(object, index, &node);
    if (status != ASNBER_OK) {
        return status;
    }
    const int kind = recipientChoiceKind(node);
    if (kind < 0) {
        return ASNBER_E_SCHEMA_TYPE;
    }
    if (kind != expected) {
        return ASNBER_E_UNSUPPORTED;
    }
    *out_node = node;
    return ASNBER_OK;
}

/* ktri.rid 分支：issuerAndSerialNumber（SEQUENCE）或 [0] SubjectKeyIdentifier。 */
int recipientIdChoiceKind(const asnber_node_t *node) noexcept
{
    if (node == nullptr) {
        return -1;
    }
    if (asnber_node_tag_class(node) == ASNBER_TAG_UNIVERSAL &&
        asnber_node_tag_number(node) == kTagSequence) {
        return ASNBER_CMS_RID_ISSUER_AND_SERIAL;
    }
    if (asnber_node_tag_class(node) == ASNBER_TAG_CONTEXT &&
        asnber_node_tag_number(node) == 0) {
        return ASNBER_CMS_RID_SUBJECT_KEY_IDENTIFIER;
    }
    return -1;
}

asnber_err_t recipientIdNode(const handle_base *object, size_t index,
                           const asnber_node_t **out_node) noexcept
{
    const asnber_node_t *recipient = nullptr;
    asnber_err_t status =
        recipientBranch(object, index, ASNBER_CMS_RECIPIENT_KTRI, &recipient);
    if (status != ASNBER_OK) {
        return status;
    }
    *out_node = nestedField(recipient, "rid");
    return (*out_node == nullptr) ? ASNBER_E_SCHEMA_FIELD : ASNBER_OK;
}

/*
 * kari.originator 是 `[0] EXPLICIT` 包装，唯一子节点才是 CHOICE 分支。
 * 分支判别：issuerAndSerialNumber（SEQUENCE）、subjectKeyIdentifier [0]、
 * originatorKey [1]。
 */
int originatorChoiceKind(const asnber_node_t *branch) noexcept
{
    if (branch == nullptr) {
        return -1;
    }
    if (asnber_node_tag_class(branch) == ASNBER_TAG_UNIVERSAL &&
        asnber_node_tag_number(branch) == kTagSequence) {
        return ASNBER_CMS_ORIGINATOR_ISSUER_AND_SERIAL;
    }
    if (asnber_node_tag_class(branch) == ASNBER_TAG_CONTEXT) {
        switch (asnber_node_tag_number(branch)) {
        case 0:
            return ASNBER_CMS_ORIGINATOR_SUBJECT_KEY_IDENTIFIER;
        case 1:
            return ASNBER_CMS_ORIGINATOR_KEY;
        default:
            break;
        }
    }
    return -1;
}

asnber_err_t originatorNode(const handle_base *object, size_t index,
                          const asnber_node_t **out_node) noexcept
{
    const asnber_node_t *recipient = nullptr;
    asnber_err_t status =
        recipientBranch(object, index, ASNBER_CMS_RECIPIENT_KARI, &recipient);
    if (status != ASNBER_OK) {
        return status;
    }
    *out_node = nestedField(recipient, "originator");
    return (*out_node == nullptr) ? ASNBER_E_SCHEMA_FIELD : ASNBER_OK;
}

const asnber_node_t *encryptedContentInfo(const handle_base *object) noexcept
{
    return field(object, "encryptedContentInfo");
}

} // namespace

struct asnber_cms_enveloped_data : cms_detail::handle_base {};

extern "C" ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_data_open(
    asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asnber_cms_enveloped_data_t **out_enveloped_data)
{
    return openStructure(ctx, der, der_size, cmsSchemaTable(),
                         kCmsRootEnvelopedData,
                         out_enveloped_data);
}

extern "C" ASNBER_CMS_API void asnber_cms_enveloped_data_close(
    asnber_cms_enveloped_data_t *enveloped_data)
{
    closeStructure(enveloped_data);
}

extern "C" ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_data_version(
    const asnber_cms_enveloped_data_t *enveloped_data, int64_t *out_version)
{
    if (enveloped_data == nullptr || out_version == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = nullptr;
    asnber_err_t status =
        cms_detail::requireField(enveloped_data, "version", &node);
    if (status != ASNBER_OK) {
        return status;
    }
    return asnber_node_get_int64(node, out_version);
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_enveloped_data_originator_info_tlv(
    const asnber_cms_enveloped_data_t *enveloped_data, const uint8_t **out_data,
    size_t *out_size)
{
    if (enveloped_data == nullptr || out_data == nullptr ||
        out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = field(enveloped_data, "originatorInfo");
    if (node == nullptr) {
        *out_data = nullptr;
        *out_size = 0;
        return ASNBER_OK;
    }
    *out_data = asnber_node_tlv(node, out_size);
    return (*out_data == nullptr) ? ASNBER_E_INVALID_STATE : ASNBER_OK;
}

extern "C" ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_data_recipient_count(
    const asnber_cms_enveloped_data_t *enveloped_data, size_t *out_count)
{
    if (enveloped_data == nullptr || out_count == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return cms_detail::optionalCollectionCount(enveloped_data,
                                               "recipientInfos", out_count);
}

extern "C" ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_data_recipient_choice(
    const asnber_cms_enveloped_data_t *enveloped_data, size_t index,
    int *out_choice)
{
    if (enveloped_data == nullptr || out_choice == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = nullptr;
    asnber_err_t status = recipientNode(enveloped_data, index, &node);
    if (status != ASNBER_OK) {
        return status;
    }
    const int kind = recipientChoiceKind(node);
    if (kind < 0) {
        return ASNBER_E_SCHEMA_TYPE;
    }
    *out_choice = kind;
    return ASNBER_OK;
}

extern "C" ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_data_recipient_tlv(
    const asnber_cms_enveloped_data_t *enveloped_data, size_t index,
    const uint8_t **out_data, size_t *out_size)
{
    if (enveloped_data == nullptr || out_data == nullptr ||
        out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = nullptr;
    asnber_err_t status = recipientNode(enveloped_data, index, &node);
    if (status != ASNBER_OK) {
        return status;
    }
    *out_data = asnber_node_tlv(node, out_size);
    return (*out_data == nullptr) ? ASNBER_E_INVALID_STATE : ASNBER_OK;
}

extern "C" ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_data_recipient_version(
    const asnber_cms_enveloped_data_t *enveloped_data, size_t index,
    int64_t *out_version)
{
    if (enveloped_data == nullptr || out_version == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = nullptr;
    asnber_err_t status = recipientNode(enveloped_data, index, &node);
    if (status != ASNBER_OK) {
        return status;
    }
    const int kind = recipientChoiceKind(node);
    if (kind < 0) {
        return ASNBER_E_SCHEMA_TYPE;
    }
    if (kind == ASNBER_CMS_RECIPIENT_ORI) {
        return ASNBER_E_UNSUPPORTED;
    }
    const asnber_node_t *version = nestedField(node, "version");
    if (version == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    return asnber_node_get_int64(version, out_version);
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_enveloped_data_recipient_key_encryption_algorithm(
    const asnber_cms_enveloped_data_t *enveloped_data, size_t index,
    const char **out_oid, size_t *out_oid_size,
    const uint8_t **out_parameters, size_t *out_parameters_size)
{
    if (enveloped_data == nullptr || out_oid == nullptr ||
        out_oid_size == nullptr || out_parameters == nullptr ||
        out_parameters_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *recipient = nullptr;
    asnber_err_t status = recipientNode(enveloped_data, index, &recipient);
    if (status != ASNBER_OK) {
        return status;
    }
    const int kind = recipientChoiceKind(recipient);
    if (kind < 0) {
        return ASNBER_E_SCHEMA_TYPE;
    }
    if (kind == ASNBER_CMS_RECIPIENT_ORI) {
        return ASNBER_E_UNSUPPORTED;
    }
    const asnber_node_t *algorithm =
        nestedField(recipient, "keyEncryptionAlgorithm");
    if (algorithm == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    return algorithmFields(algorithm, out_oid, out_oid_size, out_parameters,
                           out_parameters_size);
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_enveloped_data_recipient_encrypted_key(
    const asnber_cms_enveloped_data_t *enveloped_data, size_t index,
    const uint8_t **out_data, size_t *out_size)
{
    if (enveloped_data == nullptr || out_data == nullptr ||
        out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *recipient = nullptr;
    asnber_err_t status = recipientNode(enveloped_data, index, &recipient);
    if (status != ASNBER_OK) {
        return status;
    }
    const int kind = recipientChoiceKind(recipient);
    if (kind < 0) {
        return ASNBER_E_SCHEMA_TYPE;
    }
    if (kind == ASNBER_CMS_RECIPIENT_KARI || kind == ASNBER_CMS_RECIPIENT_ORI) {
        return ASNBER_E_UNSUPPORTED;
    }
    const asnber_node_t *encrypted = nestedField(recipient, "encryptedKey");
    if (encrypted == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    return asnber_node_get_octets(encrypted, out_data, out_size);
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_enveloped_data_recipient_kekri_key_identifier(
    const asnber_cms_enveloped_data_t *enveloped_data, size_t index,
    const uint8_t **out_data, size_t *out_size)
{
    if (enveloped_data == nullptr || out_data == nullptr ||
        out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *recipient = nullptr;
    asnber_err_t status =
        recipientBranch(enveloped_data, index, ASNBER_CMS_RECIPIENT_KEKRI,
                        &recipient);
    if (status != ASNBER_OK) {
        return status;
    }
    const asnber_node_t *kekid = nestedField(recipient, "kekid");
    const asnber_node_t *key_id = nestedField(kekid, "keyIdentifier");
    if (key_id == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    return asnber_node_get_octets(key_id, out_data, out_size);
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_enveloped_data_recipient_pwri_key_derivation_algorithm_tlv(
    const asnber_cms_enveloped_data_t *enveloped_data, size_t index,
    const uint8_t **out_data, size_t *out_size)
{
    if (enveloped_data == nullptr || out_data == nullptr ||
        out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *recipient = nullptr;
    asnber_err_t status =
        recipientBranch(enveloped_data, index, ASNBER_CMS_RECIPIENT_PWRI,
                        &recipient);
    if (status != ASNBER_OK) {
        return status;
    }
    const asnber_node_t *node =
        nestedField(recipient, "keyDerivationAlgorithm");
    if (node == nullptr) {
        *out_data = nullptr;
        *out_size = 0;
        return ASNBER_OK;
    }
    *out_data = asnber_node_tlv(node, out_size);
    return (*out_data == nullptr) ? ASNBER_E_INVALID_STATE : ASNBER_OK;
}

extern "C" ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_data_recipient_ori_type(
    const asnber_cms_enveloped_data_t *enveloped_data, size_t index,
    const char **out_oid, size_t *out_oid_size)
{
    if (enveloped_data == nullptr || out_oid == nullptr ||
        out_oid_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *recipient = nullptr;
    asnber_err_t status =
        recipientBranch(enveloped_data, index, ASNBER_CMS_RECIPIENT_ORI,
                        &recipient);
    if (status != ASNBER_OK) {
        return status;
    }
    const asnber_node_t *node = nestedField(recipient, "oriType");
    if (node == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    return asnber_node_get_oid(node, out_oid, out_oid_size);
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_enveloped_data_recipient_ori_value_tlv(
    const asnber_cms_enveloped_data_t *enveloped_data, size_t index,
    const uint8_t **out_data, size_t *out_size)
{
    if (enveloped_data == nullptr || out_data == nullptr ||
        out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *recipient = nullptr;
    asnber_err_t status =
        recipientBranch(enveloped_data, index, ASNBER_CMS_RECIPIENT_ORI,
                        &recipient);
    if (status != ASNBER_OK) {
        return status;
    }
    const asnber_node_t *node = nestedField(recipient, "oriValue");
    if (node == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    *out_data = asnber_node_tlv(node, out_size);
    return (*out_data == nullptr) ? ASNBER_E_INVALID_STATE : ASNBER_OK;
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_enveloped_data_recipient_rid_choice(
    const asnber_cms_enveloped_data_t *enveloped_data, size_t index,
    int *out_choice)
{
    if (enveloped_data == nullptr || out_choice == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *rid = nullptr;
    asnber_err_t status = recipientIdNode(enveloped_data, index, &rid);
    if (status != ASNBER_OK) {
        return status;
    }
    const int kind = recipientIdChoiceKind(rid);
    if (kind < 0) {
        return ASNBER_E_SCHEMA_TYPE;
    }
    *out_choice = kind;
    return ASNBER_OK;
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_enveloped_data_recipient_rid_issuer_tlv(
    const asnber_cms_enveloped_data_t *enveloped_data, size_t index,
    const uint8_t **out_data, size_t *out_size)
{
    if (enveloped_data == nullptr || out_data == nullptr ||
        out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *rid = nullptr;
    asnber_err_t status = recipientIdNode(enveloped_data, index, &rid);
    if (status != ASNBER_OK) {
        return status;
    }
    if (recipientIdChoiceKind(rid) != ASNBER_CMS_RID_ISSUER_AND_SERIAL) {
        return ASNBER_E_UNSUPPORTED;
    }
    const asnber_node_t *issuer = nestedField(rid, "issuer");
    if (issuer == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    *out_data = asnber_node_tlv(issuer, out_size);
    return (*out_data == nullptr) ? ASNBER_E_INVALID_STATE : ASNBER_OK;
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_enveloped_data_recipient_rid_serial_tlv(
    const asnber_cms_enveloped_data_t *enveloped_data, size_t index,
    const uint8_t **out_data, size_t *out_size)
{
    if (enveloped_data == nullptr || out_data == nullptr ||
        out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *rid = nullptr;
    asnber_err_t status = recipientIdNode(enveloped_data, index, &rid);
    if (status != ASNBER_OK) {
        return status;
    }
    if (recipientIdChoiceKind(rid) != ASNBER_CMS_RID_ISSUER_AND_SERIAL) {
        return ASNBER_E_UNSUPPORTED;
    }
    const asnber_node_t *serial = nestedField(rid, "serialNumber");
    if (serial == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    *out_data = asnber_node_tlv(serial, out_size);
    return (*out_data == nullptr) ? ASNBER_E_INVALID_STATE : ASNBER_OK;
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_enveloped_data_recipient_rid_serial_decimal(
    const asnber_cms_enveloped_data_t *enveloped_data, size_t index, char *buf,
    size_t buf_size, size_t *out_size)
{
    if (enveloped_data == nullptr || buf == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *rid = nullptr;
    asnber_err_t status = recipientIdNode(enveloped_data, index, &rid);
    if (status != ASNBER_OK) {
        return status;
    }
    if (recipientIdChoiceKind(rid) != ASNBER_CMS_RID_ISSUER_AND_SERIAL) {
        return ASNBER_E_UNSUPPORTED;
    }
    const asnber_node_t *serial = nestedField(rid, "serialNumber");
    if (serial == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    const char *decimal = nullptr;
    size_t decimal_size = 0;
    status = asnber_node_get_bigint_decimal(serial, &decimal, &decimal_size);
    if (status != ASNBER_OK) {
        return status;
    }
    if (decimal_size >= buf_size) {
        return ASNBER_E_INVALID_ARG;
    }
    std::memcpy(buf, decimal, decimal_size);
    buf[decimal_size] = '\0';
    *out_size = decimal_size;
    return ASNBER_OK;
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_enveloped_data_recipient_rid_subject_key_id(
    const asnber_cms_enveloped_data_t *enveloped_data, size_t index,
    const uint8_t **out_data, size_t *out_size)
{
    if (enveloped_data == nullptr || out_data == nullptr ||
        out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *rid = nullptr;
    asnber_err_t status = recipientIdNode(enveloped_data, index, &rid);
    if (status != ASNBER_OK) {
        return status;
    }
    if (recipientIdChoiceKind(rid) != ASNBER_CMS_RID_SUBJECT_KEY_IDENTIFIER) {
        return ASNBER_E_UNSUPPORTED;
    }
    /* SubjectKeyIdentifier 是隐式 OCTET STRING：按基本节点内容读取。 */
    return asnber_node_content(rid, out_data, out_size);
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_enveloped_data_recipient_originator_choice(
    const asnber_cms_enveloped_data_t *enveloped_data, size_t index,
    int *out_choice)
{
    if (enveloped_data == nullptr || out_choice == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *wrapper = nullptr;
    asnber_err_t status = originatorNode(enveloped_data, index, &wrapper);
    if (status != ASNBER_OK) {
        return status;
    }
    const asnber_node_t *branch = asnber_node_child_at(wrapper, 0);
    if (branch == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    const int kind = originatorChoiceKind(branch);
    if (kind < 0) {
        return ASNBER_E_SCHEMA_TYPE;
    }
    *out_choice = kind;
    return ASNBER_OK;
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_enveloped_data_recipient_originator_tlv(
    const asnber_cms_enveloped_data_t *enveloped_data, size_t index,
    const uint8_t **out_data, size_t *out_size)
{
    if (enveloped_data == nullptr || out_data == nullptr ||
        out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *wrapper = nullptr;
    asnber_err_t status = originatorNode(enveloped_data, index, &wrapper);
    if (status != ASNBER_OK) {
        return status;
    }
    *out_data = asnber_node_tlv(wrapper, out_size);
    return (*out_data == nullptr) ? ASNBER_E_INVALID_STATE : ASNBER_OK;
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_enveloped_data_recipient_kari_encrypted_key_count(
    const asnber_cms_enveloped_data_t *enveloped_data, size_t index,
    size_t *out_count)
{
    if (enveloped_data == nullptr || out_count == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *recipient = nullptr;
    asnber_err_t status =
        recipientBranch(enveloped_data, index, ASNBER_CMS_RECIPIENT_KARI,
                        &recipient);
    if (status != ASNBER_OK) {
        return status;
    }
    const asnber_node_t *keys = nestedField(recipient, "recipientEncryptedKeys");
    if (keys == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    *out_count = asnber_node_child_count(keys);
    return ASNBER_OK;
}

extern "C" ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_data_content_type(
    const asnber_cms_enveloped_data_t *enveloped_data, const char **out_oid,
    size_t *out_oid_size)
{
    if (enveloped_data == nullptr || out_oid == nullptr ||
        out_oid_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *info = encryptedContentInfo(enveloped_data);
    const asnber_node_t *node = nestedField(info, "contentType");
    if (node == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    return asnber_node_get_oid(node, out_oid, out_oid_size);
}

extern "C" ASNBER_CMS_API asnber_err_t
asnber_cms_enveloped_data_content_encryption_algorithm(
    const asnber_cms_enveloped_data_t *enveloped_data, const char **out_oid,
    size_t *out_oid_size, const uint8_t **out_parameters,
    size_t *out_parameters_size)
{
    if (enveloped_data == nullptr || out_oid == nullptr ||
        out_oid_size == nullptr || out_parameters == nullptr ||
        out_parameters_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *info = encryptedContentInfo(enveloped_data);
    const asnber_node_t *algorithm =
        nestedField(info, "contentEncryptionAlgorithm");
    if (algorithm == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    return algorithmFields(algorithm, out_oid, out_oid_size, out_parameters,
                           out_parameters_size);
}

extern "C" ASNBER_CMS_API asnber_err_t asnber_cms_enveloped_data_encrypted_content(
    const asnber_cms_enveloped_data_t *enveloped_data, const uint8_t **out_data,
    size_t *out_size)
{
    if (enveloped_data == nullptr || out_data == nullptr ||
        out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *info = encryptedContentInfo(enveloped_data);
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
asnber_cms_enveloped_data_encrypted_content_tlv(
    const asnber_cms_enveloped_data_t *enveloped_data, const uint8_t **out_data,
    size_t *out_size)
{
    if (enveloped_data == nullptr || out_data == nullptr ||
        out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *info = encryptedContentInfo(enveloped_data);
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
asnber_cms_enveloped_data_unprotected_attrs_tlv(
    const asnber_cms_enveloped_data_t *enveloped_data, const uint8_t **out_data,
    size_t *out_size)
{
    if (enveloped_data == nullptr || out_data == nullptr ||
        out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = field(enveloped_data, "unprotectedAttrs");
    if (node == nullptr) {
        *out_data = nullptr;
        *out_size = 0;
        return ASNBER_OK;
    }
    *out_data = asnber_node_tlv(node, out_size);
    return (*out_data == nullptr) ? ASNBER_E_INVALID_STATE : ASNBER_OK;
}
