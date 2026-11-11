/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-cms EnvelopedData builder：RecipientInfo 适配、构树、编码与公共接口。
 */

#include "detail/cms_builder_internal.h"

#include <cstdlib>
#include <cstring>

namespace asnber_cms_detail {

asnber_err_t commitRecipient(asnber_cms_enveloped_builder *builder,
                           const recipient_entry &entry)
{
    if (!ensureCapacity(&builder->recipients, builder->recipient_count,
                        &builder->recipient_capacity)) {
        return ASNBER_E_NOMEM;
    }
    builder->recipients[builder->recipient_count] = entry;
    ++builder->recipient_count;
    return ASNBER_OK;
}

/* ktri.rid：issuerAndSerialNumber（SEQUENCE）或 subjectKeyIdentifier [0]。 */
asnber_err_t addRecipientId(asnber_doc_t *doc, asnber_node_t *parent,
                          const recipient_entry &recipient,
                          asnber_node_t **out_node)
{
    asnber_node_t *node = nullptr;
    if (recipient.rid_kind == ASNBER_CMS_RID_ISSUER_AND_SERIAL) {
        asnber_err_t rc = createNode(doc, parent, ASNBER_TAG_UNIVERSAL,
                                   kTagSequence, 1, &node);
        if (rc != ASNBER_OK) {
            return rc;
        }
        asnber_node_t *ignored = nullptr;
        rc = asnber_node_create_any(doc, node, recipient.rid1.data,
                                  recipient.rid1.size, &ignored);
        if (rc == ASNBER_OK) {
            rc = asnber_node_create_any(doc, node, recipient.rid2.data,
                                      recipient.rid2.size, &ignored);
        }
        if (rc != ASNBER_OK) {
            return rc;
        }
    } else {
        asnber_err_t rc = createNode(doc, parent, ASNBER_TAG_CONTEXT,
                                   kTagContext0, 0, &node);
        if (rc != ASNBER_OK) {
            return rc;
        }
        rc = asnber_node_set_content(node, recipient.rid1.data,
                                   recipient.rid1.size);
        if (rc != ASNBER_OK) {
            return rc;
        }
    }
    *out_node = node;
    return ASNBER_OK;
}

/* 组装一条 RecipientInfo（ktri 为 SEQUENCE，其余为 context [n]）。 */
asnber_err_t addRecipientInfo(asnber_doc_t *doc, asnber_node_t *parent,
                            const recipient_entry &recipient)
{
    asnber_node_t *node = nullptr;
    asnber_err_t rc;
    if (recipient.kind == ASNBER_CMS_RECIPIENT_KTRI) {
        rc = createNode(doc, parent, ASNBER_TAG_UNIVERSAL, kTagSequence, 1,
                        &node);
    } else {
        rc = createNode(doc, parent, ASNBER_TAG_CONTEXT,
                        static_cast<uint32_t>(recipient.kind), 1, &node);
    }
    if (rc != ASNBER_OK) {
        return rc;
    }

    asnber_node_t *ignored = nullptr;
    switch (recipient.kind) {
    case ASNBER_CMS_RECIPIENT_KTRI:
        rc = createIntegerNode(doc, node, recipient.version, &ignored);
        if (rc == ASNBER_OK) {
            rc = addRecipientId(doc, node, recipient, &ignored);
        }
        if (rc == ASNBER_OK) {
            rc = addAlgorithmIdentifier(doc, node,
                                        recipient.key_encryption_oid,
                                        recipient.key_encryption_params);
        }
        if (rc == ASNBER_OK) {
            rc = createOctetStringNode(doc, node,
                                       recipient.encrypted_key.data,
                                       recipient.encrypted_key.size,
                                       &ignored);
        }
        break;
    case ASNBER_CMS_RECIPIENT_KARI:
        rc = createIntegerNode(doc, node, recipient.version, &ignored);
        if (rc == ASNBER_OK) {
            rc = asnber_node_create_any(doc, node, recipient.originator.data,
                                      recipient.originator.size, &ignored);
        }
        if (rc == ASNBER_OK && recipient.ukm.size != 0) {
            rc = asnber_node_create_any(doc, node, recipient.ukm.data,
                                      recipient.ukm.size, &ignored);
        }
        if (rc == ASNBER_OK) {
            rc = addAlgorithmIdentifier(doc, node,
                                        recipient.key_encryption_oid,
                                        recipient.key_encryption_params);
        }
        if (rc == ASNBER_OK) {
            rc = asnber_node_create_any(
                doc, node, recipient.recipient_encrypted_keys.data,
                recipient.recipient_encrypted_keys.size, &ignored);
        }
        break;
    case ASNBER_CMS_RECIPIENT_KEKRI:
        rc = createIntegerNode(doc, node, recipient.version, &ignored);
        if (rc == ASNBER_OK) {
            rc = asnber_node_create_any(doc, node, recipient.kekid.data,
                                      recipient.kekid.size, &ignored);
        }
        if (rc == ASNBER_OK) {
            rc = addAlgorithmIdentifier(doc, node,
                                        recipient.key_encryption_oid,
                                        recipient.key_encryption_params);
        }
        if (rc == ASNBER_OK) {
            rc = createOctetStringNode(doc, node,
                                       recipient.encrypted_key.data,
                                       recipient.encrypted_key.size,
                                       &ignored);
        }
        break;
    case ASNBER_CMS_RECIPIENT_PWRI:
        rc = createIntegerNode(doc, node, recipient.version, &ignored);
        if (rc == ASNBER_OK &&
            recipient.key_derivation_algorithm.size != 0) {
            rc = asnber_node_create_any(
                doc, node, recipient.key_derivation_algorithm.data,
                recipient.key_derivation_algorithm.size, &ignored);
        }
        if (rc == ASNBER_OK) {
            rc = addAlgorithmIdentifier(doc, node,
                                        recipient.key_encryption_oid,
                                        recipient.key_encryption_params);
        }
        if (rc == ASNBER_OK) {
            rc = createOctetStringNode(doc, node,
                                       recipient.encrypted_key.data,
                                       recipient.encrypted_key.size,
                                       &ignored);
        }
        break;
    case ASNBER_CMS_RECIPIENT_ORI:
        rc = createOidNode(doc, node, recipient.ori_type, &ignored);
        if (rc == ASNBER_OK) {
            rc = asnber_node_create_any(doc, node, recipient.ori_value.data,
                                      recipient.ori_value.size, &ignored);
        }
        break;
    default:
        rc = ASNBER_E_INVALID_STATE;
        break;
    }
    return rc;
}

/* 组装 EnvelopedData 文档（不含 ContentInfo 包装）。 */
asnber_err_t buildEnvelopedData(const asnber_cms_enveloped_builder &builder,
                              asnber_doc_t **out_doc)
{
    asnber_doc_t *doc = nullptr;
    asnber_err_t rc = asnber_doc_create(builder.ctx, &doc);
    if (rc != ASNBER_OK) {
        return rc;
    }

    asnber_node_t *root = nullptr;
    asnber_node_t *ignored = nullptr;
    rc = createNode(doc, nullptr, ASNBER_TAG_UNIVERSAL, kTagSequence, 1, &root);
    if (rc == ASNBER_OK) {
        rc = createIntegerNode(doc, root, builder.version, &ignored);
    }
    if (rc == ASNBER_OK && builder.originator_info_set) {
        rc = asnber_node_create_any(doc, root, builder.originator_info.data,
                                  builder.originator_info.size, &ignored);
    }

    asnber_node_t *recipients = nullptr;
    if (rc == ASNBER_OK) {
        rc = createNode(doc, root, ASNBER_TAG_UNIVERSAL, kTagSet, 1,
                        &recipients);
    }
    for (size_t i = 0; rc == ASNBER_OK && i < builder.recipient_count; ++i) {
        rc = addRecipientInfo(doc, recipients, builder.recipients[i]);
    }

    asnber_node_t *encrypted_info = nullptr;
    if (rc == ASNBER_OK) {
        rc = createNode(doc, root, ASNBER_TAG_UNIVERSAL, kTagSequence, 1,
                        &encrypted_info);
    }
    if (rc == ASNBER_OK) {
        rc = createOidNode(doc, encrypted_info, builder.content_type,
                           &ignored);
    }
    if (rc == ASNBER_OK) {
        rc = addAlgorithmIdentifier(doc, encrypted_info,
                                    builder.content_alg_oid,
                                    builder.content_alg_params);
    }
    if (rc == ASNBER_OK && builder.encrypted_content_set) {
        asnber_node_t *content = nullptr;
        rc = createNode(doc, encrypted_info, ASNBER_TAG_CONTEXT, kTagContext0,
                        0, &content);
        if (rc == ASNBER_OK) {
            rc = asnber_node_set_content(content,
                                       builder.encrypted_content.data,
                                       builder.encrypted_content.size);
        }
    }

    if (rc == ASNBER_OK && builder.unprotected_attrs_set) {
        rc = asnber_node_create_any(doc, root, builder.unprotected_attrs.data,
                                  builder.unprotected_attrs.size, &ignored);
    }

    if (rc == ASNBER_OK) {
        rc = asnber_doc_seal(doc);
    }
    if (rc != ASNBER_OK) {
        asnber_doc_destroy(doc);
        return rc;
    }
    *out_doc = doc;
    return ASNBER_OK;
}

/* 编码 EnvelopedData 文档（schema 感知）。 */
asnber_err_t encodeEnvelopedData(const asnber_cms_enveloped_builder &builder,
                               const asnber_doc_t *doc, asnber_buf_t *out_buf)
{
    asnber_schema_t *schema = nullptr;
    asnber_err_t rc = loadTable(builder.ctx, cmsSchemaTable(),
                              kCmsRootEnvelopedData, &schema);
    if (rc != ASNBER_OK) {
        return rc;
    }
    asnber_encode_options_t options;
    asnber_encode_options_init(&options);
    options.schema = schema;
    rc = asnber_encode_buffer(builder.ctx, doc, &options, out_buf);
    asnber_schema_destroy(schema);
    return rc;
}

/* ---------- EncryptedData 构树 ---------- */


} /* namespace asnber_cms_detail */

using namespace asnber_cms_detail;

/* ========================================================================= */
/* EnvelopedData builder 公共接口                                            */
/* ========================================================================= */

extern "C" asnber_err_t asnber_cms_enveloped_builder_create(
    asnber_ctx_t *ctx, asnber_cms_enveloped_builder_t **out_builder)
{
    if (ctx == nullptr || out_builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_builder = nullptr;
    asnber_cms_enveloped_builder_t *builder =
        static_cast<asnber_cms_enveloped_builder_t *>(
            std::malloc(sizeof(asnber_cms_enveloped_builder_t)));
    if (builder == nullptr) {
        return ASNBER_E_NOMEM;
    }
    std::memset(builder, 0, sizeof(*builder));
    builder->ctx = ctx;
    *out_builder = builder;
    return ASNBER_OK;
}

extern "C" void asnber_cms_enveloped_builder_destroy(
    asnber_cms_enveloped_builder_t *builder)
{
    if (builder == nullptr) {
        return;
    }
    std::free(builder->originator_info.data);
    for (size_t i = 0; i < builder->recipient_count; ++i) {
        freeRecipient(&builder->recipients[i]);
    }
    std::free(builder->recipients);
    std::free(builder->content_type);
    std::free(builder->content_alg_oid);
    std::free(builder->content_alg_params.data);
    std::free(builder->encrypted_content.data);
    std::free(builder->unprotected_attrs.data);
    std::memset(builder, 0, sizeof(*builder));
    std::free(builder);
}

extern "C" asnber_err_t asnber_cms_enveloped_builder_set_version(
    asnber_cms_enveloped_builder_t *builder, int64_t version)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->version_set) {
        return ASNBER_E_INVALID_STATE;
    }
    builder->version = version;
    builder->version_set = true;
    return ASNBER_OK;
}

extern "C" asnber_err_t asnber_cms_enveloped_builder_set_originator_info(
    asnber_cms_enveloped_builder_t *builder, const uint8_t *tlv,
    size_t tlv_size)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->originator_info_set) {
        return ASNBER_E_INVALID_STATE;
    }
    asnber_err_t rc = validateTlvChildRules(
        builder->ctx, tlv, tlv_size, ASNBER_TAG_CONTEXT, kTagContext0, 1,
        kOriginatorInfoRules, arraySize(kOriginatorInfoRules));
    if (rc != ASNBER_OK) {
        return rc;
    }
    uint8_t *copy = copyBytes(tlv, tlv_size);
    if (copy == nullptr) {
        return ASNBER_E_NOMEM;
    }
    builder->originator_info.data = copy;
    builder->originator_info.size = tlv_size;
    builder->originator_info_set = true;
    return ASNBER_OK;
}

extern "C" asnber_err_t asnber_cms_enveloped_builder_add_ktri(
    asnber_cms_enveloped_builder_t *builder, int64_t version, int32_t rid_kind,
    const uint8_t *rid1, size_t rid1_size, const uint8_t *rid2,
    size_t rid2_size, const char *key_encryption_oid,
    const uint8_t *key_encryption_params, size_t key_encryption_params_size,
    const uint8_t *encrypted_key, size_t encrypted_key_size)
{
    if (builder == nullptr || key_encryption_oid == nullptr ||
        (encrypted_key == nullptr && encrypted_key_size != 0) ||
        (key_encryption_params == nullptr &&
         key_encryption_params_size != 0)) {
        return ASNBER_E_INVALID_ARG;
    }
    if (rid_kind != ASNBER_CMS_RID_ISSUER_AND_SERIAL &&
        rid_kind != ASNBER_CMS_RID_SUBJECT_KEY_IDENTIFIER) {
        return ASNBER_E_INVALID_VALUE;
    }

    asnber_err_t rc = ASNBER_OK;
    if (rid_kind == ASNBER_CMS_RID_ISSUER_AND_SERIAL) {
        rc = validateSingleDerRoot(builder->ctx, rid1, rid1_size,
                                   ASNBER_TAG_UNIVERSAL, kTagSequence, 1);
        if (rc == ASNBER_OK) {
            rc = validateSingleDerRoot(builder->ctx, rid2, rid2_size,
                                       ASNBER_TAG_UNIVERSAL, kTagInteger, 0);
        }
    } else if (rid1 == nullptr || rid1_size == 0 || rid2 != nullptr ||
               rid2_size != 0) {
        return ASNBER_E_INVALID_ARG;
    }
    if (rc == ASNBER_OK) {
        rc = validateOid(builder->ctx, key_encryption_oid);
    }
    if (rc == ASNBER_OK && key_encryption_params_size != 0) {
        rc = validateSingleDer(builder->ctx, key_encryption_params,
                               key_encryption_params_size, nullptr);
    }
    if (rc != ASNBER_OK) {
        return rc;
    }

    recipient_entry entry;
    std::memset(&entry, 0, sizeof(entry));
    entry.kind = ASNBER_CMS_RECIPIENT_KTRI;
    entry.version = version;
    entry.rid_kind = rid_kind;
    entry.rid1.data = copyBytes(rid1, rid1_size);
    entry.rid1.size = rid1_size;
    entry.key_encryption_oid = copyText(key_encryption_oid);
    if (rid2_size != 0) {
        entry.rid2.data = copyBytes(rid2, rid2_size);
        entry.rid2.size = rid2_size;
    }
    if (key_encryption_params_size != 0) {
        entry.key_encryption_params.data =
            copyBytes(key_encryption_params, key_encryption_params_size);
        entry.key_encryption_params.size = key_encryption_params_size;
    }
    if (encrypted_key_size != 0) {
        entry.encrypted_key.data =
            copyBytes(encrypted_key, encrypted_key_size);
        entry.encrypted_key.size = encrypted_key_size;
    }
    if (entry.rid1.data == nullptr || entry.key_encryption_oid == nullptr ||
        (rid2_size != 0 && entry.rid2.data == nullptr) ||
        (key_encryption_params_size != 0 &&
         entry.key_encryption_params.data == nullptr) ||
        (encrypted_key_size != 0 && entry.encrypted_key.data == nullptr)) {
        freeRecipient(&entry);
        return ASNBER_E_NOMEM;
    }
    rc = commitRecipient(builder, entry);
    if (rc != ASNBER_OK) {
        freeRecipient(&entry);
    }
    return rc;
}

extern "C" asnber_err_t asnber_cms_enveloped_builder_add_kari(
    asnber_cms_enveloped_builder_t *builder, int64_t version,
    const uint8_t *originator_tlv, size_t originator_size,
    const uint8_t *ukm_tlv, size_t ukm_size,
    const uint8_t *recipient_encrypted_keys_tlv,
    size_t recipient_encrypted_keys_size, const char *key_encryption_oid,
    const uint8_t *key_encryption_params, size_t key_encryption_params_size)
{
    if (builder == nullptr || key_encryption_oid == nullptr ||
        (ukm_tlv == nullptr && ukm_size != 0) ||
        (key_encryption_params == nullptr &&
         key_encryption_params_size != 0)) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber_err_t rc = validateTlvChildRules(
        builder->ctx, originator_tlv, originator_size, ASNBER_TAG_CONTEXT,
        kTagContext0, 1, kOriginatorRules, arraySize(kOriginatorRules));
    if (rc == ASNBER_OK && ukm_size != 0) {
        rc = validateTlvChildRules(builder->ctx, ukm_tlv, ukm_size,
                                   ASNBER_TAG_CONTEXT, kTagContext1, 1,
                                   kUkmRules, arraySize(kUkmRules));
    }
    if (rc == ASNBER_OK) {
        rc = validateTlvChildRules(
            builder->ctx, recipient_encrypted_keys_tlv,
            recipient_encrypted_keys_size, ASNBER_TAG_UNIVERSAL, kTagSequence, 1,
            kRecipientEncryptedKeysRules,
            arraySize(kRecipientEncryptedKeysRules));
    }
    if (rc == ASNBER_OK) {
        rc = validateOid(builder->ctx, key_encryption_oid);
    }
    if (rc == ASNBER_OK && key_encryption_params_size != 0) {
        rc = validateSingleDer(builder->ctx, key_encryption_params,
                               key_encryption_params_size, nullptr);
    }
    if (rc != ASNBER_OK) {
        return rc;
    }

    recipient_entry entry;
    std::memset(&entry, 0, sizeof(entry));
    entry.kind = ASNBER_CMS_RECIPIENT_KARI;
    entry.version = version;
    entry.originator.data = copyBytes(originator_tlv, originator_size);
    entry.originator.size = originator_size;
    entry.recipient_encrypted_keys.data =
        copyBytes(recipient_encrypted_keys_tlv,
                  recipient_encrypted_keys_size);
    entry.recipient_encrypted_keys.size = recipient_encrypted_keys_size;
    entry.key_encryption_oid = copyText(key_encryption_oid);
    if (ukm_size != 0) {
        entry.ukm.data = copyBytes(ukm_tlv, ukm_size);
        entry.ukm.size = ukm_size;
    }
    if (key_encryption_params_size != 0) {
        entry.key_encryption_params.data =
            copyBytes(key_encryption_params, key_encryption_params_size);
        entry.key_encryption_params.size = key_encryption_params_size;
    }
    if (entry.originator.data == nullptr ||
        entry.recipient_encrypted_keys.data == nullptr ||
        entry.key_encryption_oid == nullptr ||
        (ukm_size != 0 && entry.ukm.data == nullptr) ||
        (key_encryption_params_size != 0 &&
         entry.key_encryption_params.data == nullptr)) {
        freeRecipient(&entry);
        return ASNBER_E_NOMEM;
    }
    rc = commitRecipient(builder, entry);
    if (rc != ASNBER_OK) {
        freeRecipient(&entry);
    }
    return rc;
}

extern "C" asnber_err_t asnber_cms_enveloped_builder_add_kekri(
    asnber_cms_enveloped_builder_t *builder, int64_t version,
    const uint8_t *kekid_tlv, size_t kekid_size,
    const char *key_encryption_oid,
    const uint8_t *key_encryption_params, size_t key_encryption_params_size,
    const uint8_t *encrypted_key, size_t encrypted_key_size)
{
    if (builder == nullptr || key_encryption_oid == nullptr ||
        (encrypted_key == nullptr && encrypted_key_size != 0) ||
        (key_encryption_params == nullptr &&
         key_encryption_params_size != 0)) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber_err_t rc = validateTlvChildRules(
        builder->ctx, kekid_tlv, kekid_size, ASNBER_TAG_UNIVERSAL, kTagSequence,
        1, kKekIdentifierRules, arraySize(kKekIdentifierRules));
    if (rc == ASNBER_OK) {
        rc = validateOid(builder->ctx, key_encryption_oid);
    }
    if (rc == ASNBER_OK && key_encryption_params_size != 0) {
        rc = validateSingleDer(builder->ctx, key_encryption_params,
                               key_encryption_params_size, nullptr);
    }
    if (rc != ASNBER_OK) {
        return rc;
    }

    recipient_entry entry;
    std::memset(&entry, 0, sizeof(entry));
    entry.kind = ASNBER_CMS_RECIPIENT_KEKRI;
    entry.version = version;
    entry.kekid.data = copyBytes(kekid_tlv, kekid_size);
    entry.kekid.size = kekid_size;
    entry.key_encryption_oid = copyText(key_encryption_oid);
    if (key_encryption_params_size != 0) {
        entry.key_encryption_params.data =
            copyBytes(key_encryption_params, key_encryption_params_size);
        entry.key_encryption_params.size = key_encryption_params_size;
    }
    if (encrypted_key_size != 0) {
        entry.encrypted_key.data =
            copyBytes(encrypted_key, encrypted_key_size);
        entry.encrypted_key.size = encrypted_key_size;
    }
    if (entry.kekid.data == nullptr ||
        entry.key_encryption_oid == nullptr ||
        (key_encryption_params_size != 0 &&
         entry.key_encryption_params.data == nullptr) ||
        (encrypted_key_size != 0 && entry.encrypted_key.data == nullptr)) {
        freeRecipient(&entry);
        return ASNBER_E_NOMEM;
    }
    rc = commitRecipient(builder, entry);
    if (rc != ASNBER_OK) {
        freeRecipient(&entry);
    }
    return rc;
}

extern "C" asnber_err_t asnber_cms_enveloped_builder_add_pwri(
    asnber_cms_enveloped_builder_t *builder, int64_t version,
    const uint8_t *key_derivation_algorithm_tlv,
    size_t key_derivation_algorithm_size, const char *key_encryption_oid,
    const uint8_t *key_encryption_params, size_t key_encryption_params_size,
    const uint8_t *encrypted_key, size_t encrypted_key_size)
{
    if (builder == nullptr || key_encryption_oid == nullptr ||
        (key_derivation_algorithm_tlv == nullptr &&
         key_derivation_algorithm_size != 0) ||
        (encrypted_key == nullptr && encrypted_key_size != 0) ||
        (key_encryption_params == nullptr &&
         key_encryption_params_size != 0)) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber_err_t rc = ASNBER_OK;
    if (key_derivation_algorithm_size != 0) {
        rc = validateTlvChildRules(
            builder->ctx, key_derivation_algorithm_tlv,
            key_derivation_algorithm_size, ASNBER_TAG_CONTEXT, kTagContext0, 1,
            kKeyDerivationRules, arraySize(kKeyDerivationRules));
    }
    if (rc == ASNBER_OK) {
        rc = validateOid(builder->ctx, key_encryption_oid);
    }
    if (rc == ASNBER_OK && key_encryption_params_size != 0) {
        rc = validateSingleDer(builder->ctx, key_encryption_params,
                               key_encryption_params_size, nullptr);
    }
    if (rc != ASNBER_OK) {
        return rc;
    }

    recipient_entry entry;
    std::memset(&entry, 0, sizeof(entry));
    entry.kind = ASNBER_CMS_RECIPIENT_PWRI;
    entry.version = version;
    entry.key_encryption_oid = copyText(key_encryption_oid);
    if (key_derivation_algorithm_size != 0) {
        entry.key_derivation_algorithm.data =
            copyBytes(key_derivation_algorithm_tlv,
                      key_derivation_algorithm_size);
        entry.key_derivation_algorithm.size = key_derivation_algorithm_size;
    }
    if (key_encryption_params_size != 0) {
        entry.key_encryption_params.data =
            copyBytes(key_encryption_params, key_encryption_params_size);
        entry.key_encryption_params.size = key_encryption_params_size;
    }
    if (encrypted_key_size != 0) {
        entry.encrypted_key.data =
            copyBytes(encrypted_key, encrypted_key_size);
        entry.encrypted_key.size = encrypted_key_size;
    }
    if (entry.key_encryption_oid == nullptr ||
        (key_derivation_algorithm_size != 0 &&
         entry.key_derivation_algorithm.data == nullptr) ||
        (key_encryption_params_size != 0 &&
         entry.key_encryption_params.data == nullptr) ||
        (encrypted_key_size != 0 && entry.encrypted_key.data == nullptr)) {
        freeRecipient(&entry);
        return ASNBER_E_NOMEM;
    }
    rc = commitRecipient(builder, entry);
    if (rc != ASNBER_OK) {
        freeRecipient(&entry);
    }
    return rc;
}

extern "C" asnber_err_t asnber_cms_enveloped_builder_add_ori(
    asnber_cms_enveloped_builder_t *builder, const char *ori_type,
    const uint8_t *ori_value_tlv, size_t ori_value_size)
{
    if (builder == nullptr || ori_type == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber_err_t rc = validateOid(builder->ctx, ori_type);
    if (rc == ASNBER_OK) {
        rc = validateSingleDer(builder->ctx, ori_value_tlv, ori_value_size,
                               nullptr);
    }
    if (rc != ASNBER_OK) {
        return rc;
    }

    recipient_entry entry;
    std::memset(&entry, 0, sizeof(entry));
    entry.kind = ASNBER_CMS_RECIPIENT_ORI;
    entry.ori_type = copyText(ori_type);
    entry.ori_value.data = copyBytes(ori_value_tlv, ori_value_size);
    entry.ori_value.size = ori_value_size;
    if (entry.ori_type == nullptr || entry.ori_value.data == nullptr) {
        freeRecipient(&entry);
        return ASNBER_E_NOMEM;
    }
    rc = commitRecipient(builder, entry);
    if (rc != ASNBER_OK) {
        freeRecipient(&entry);
    }
    return rc;
}

extern "C" asnber_err_t asnber_cms_enveloped_builder_set_content_type(
    asnber_cms_enveloped_builder_t *builder, const char *oid)
{
    if (builder == nullptr || oid == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->content_type_set) {
        return ASNBER_E_INVALID_STATE;
    }
    asnber_err_t rc = validateOid(builder->ctx, oid);
    if (rc != ASNBER_OK) {
        return rc;
    }
    char *copy = copyText(oid);
    if (copy == nullptr) {
        return ASNBER_E_NOMEM;
    }
    builder->content_type = copy;
    builder->content_type_set = true;
    return ASNBER_OK;
}

extern "C" asnber_err_t
asnber_cms_enveloped_builder_set_content_encryption_algorithm(
    asnber_cms_enveloped_builder_t *builder, const char *oid,
    const uint8_t *params, size_t params_size)
{
    if (builder == nullptr || oid == nullptr ||
        (params == nullptr && params_size != 0)) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->content_alg_set) {
        return ASNBER_E_INVALID_STATE;
    }
    asnber_err_t rc = validateOid(builder->ctx, oid);
    if (rc == ASNBER_OK && params_size != 0) {
        rc = validateSingleDer(builder->ctx, params, params_size, nullptr);
    }
    if (rc != ASNBER_OK) {
        return rc;
    }

    char *copy = copyText(oid);
    uint8_t *params_copy = copyBytes(params, params_size);
    if (copy == nullptr || (params_size != 0 && params_copy == nullptr)) {
        std::free(copy);
        std::free(params_copy);
        return ASNBER_E_NOMEM;
    }
    builder->content_alg_oid = copy;
    builder->content_alg_params.data = params_copy;
    builder->content_alg_params.size = params_size;
    builder->content_alg_set = true;
    return ASNBER_OK;
}

extern "C" asnber_err_t asnber_cms_enveloped_builder_set_encrypted_content(
    asnber_cms_enveloped_builder_t *builder, const uint8_t *data, size_t size)
{
    if (builder == nullptr || (data == nullptr && size != 0)) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->encrypted_content_set) {
        return ASNBER_E_INVALID_STATE;
    }
    uint8_t *copy = copyBytes(data, size);
    if (size != 0 && copy == nullptr) {
        return ASNBER_E_NOMEM;
    }
    builder->encrypted_content.data = copy;
    builder->encrypted_content.size = size;
    builder->encrypted_content_set = true;
    return ASNBER_OK;
}

extern "C" asnber_err_t asnber_cms_enveloped_builder_set_unprotected_attrs(
    asnber_cms_enveloped_builder_t *builder, const uint8_t *tlv,
    size_t tlv_size)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->unprotected_attrs_set) {
        return ASNBER_E_INVALID_STATE;
    }
    byte_span rewritten;
    std::memset(&rewritten, 0, sizeof(rewritten));
    asnber_err_t rc = validateAndRewriteSet(builder->ctx, tlv, tlv_size, 0xA1,
                                          &rewritten);
    if (rc != ASNBER_OK) {
        return rc;
    }
    builder->unprotected_attrs = rewritten;
    builder->unprotected_attrs_set = true;
    return ASNBER_OK;
}

extern "C" asnber_err_t asnber_cms_enveloped_builder_encode(
    const asnber_cms_enveloped_builder_t *builder, asnber_buf_t *out_buf)
{
    if (builder == nullptr || out_buf == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    out_buf->data = nullptr;
    out_buf->size = 0;
    out_buf->capacity = 0;

    if (!builder->version_set || builder->recipient_count == 0 ||
        !builder->content_type_set || !builder->content_alg_set) {
        return ASNBER_E_INVALID_STATE;
    }

    asnber_doc_t *enveloped_data = nullptr;
    asnber_err_t rc = buildEnvelopedData(*builder, &enveloped_data);
    if (rc != ASNBER_OK) {
        return rc;
    }
    asnber_buf_t enveloped_buf;
    std::memset(&enveloped_buf, 0, sizeof(enveloped_buf));
    rc = encodeEnvelopedData(*builder, enveloped_data, &enveloped_buf);
    asnber_doc_destroy(enveloped_data);
    if (rc != ASNBER_OK) {
        return rc;
    }

    rc = encodeContentInfo(builder->ctx, kEnvelopedDataOid,
                           enveloped_buf.data, enveloped_buf.size, out_buf);
    asnber_buf_release(builder->ctx, &enveloped_buf);
    return rc;
}
