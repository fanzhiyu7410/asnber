/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-cms AuthenticatedData builder：构树、编码与公共接口。
 */

#include "detail/cms_builder_internal.h"

#include <cstdlib>
#include <cstring>

namespace asnber_cms_detail {

/* RecipientInfo 根标签：ktri 为 SEQUENCE，kari..ori 为 [1]..[4] 构造标签。 */
bool isRecipientInfoRoot(const der_root &root) noexcept
{
    if (root.tag_class == ASNBER_TAG_UNIVERSAL) {
        return root.tag_number == kTagSequence && root.constructed != 0;
    }
    if (root.tag_class != ASNBER_TAG_CONTEXT || root.constructed == 0) {
        return false;
    }
    return root.tag_number >= 1 && root.tag_number <= 4;
}

asnber_err_t buildAuthenticatedData(
    const asnber_cms_authenticated_builder &builder, asnber_doc_t **out_doc)
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
        rc = asnber_node_create_any(doc, recipients, builder.recipients[i].data,
                                  builder.recipients[i].size, &ignored);
    }

    if (rc == ASNBER_OK) {
        rc = addAlgorithmIdentifier(doc, root, builder.mac_alg_oid,
                                    builder.mac_alg_params);
    }
    if (rc == ASNBER_OK && builder.digest_alg_set) {
        rc = asnber_node_create_any(doc, root, builder.digest_alg.data,
                                  builder.digest_alg.size, &ignored);
    }

    asnber_node_t *encap = nullptr;
    if (rc == ASNBER_OK) {
        rc = createNode(doc, root, ASNBER_TAG_UNIVERSAL, kTagSequence, 1,
                        &encap);
    }
    if (rc == ASNBER_OK) {
        rc = createOidNode(doc, encap, builder.econtent_type, &ignored);
    }
    if (rc == ASNBER_OK && builder.econtent_set) {
        asnber_node_t *wrapper = nullptr;
        rc = createNode(doc, encap, ASNBER_TAG_CONTEXT, kTagContext0, 1,
                        &wrapper);
        if (rc == ASNBER_OK) {
            rc = createOctetStringNode(doc, wrapper, builder.econtent.data,
                                       builder.econtent.size, &ignored);
        }
    }

    if (rc == ASNBER_OK && builder.auth_attrs_set) {
        rc = asnber_node_create_any(doc, root, builder.auth_attrs.data,
                                  builder.auth_attrs.size, &ignored);
    }
    if (rc == ASNBER_OK) {
        rc = createOctetStringNode(doc, root, builder.mac.data,
                                   builder.mac.size, &ignored);
    }
    if (rc == ASNBER_OK && builder.unauth_attrs_set) {
        rc = asnber_node_create_any(doc, root, builder.unauth_attrs.data,
                                  builder.unauth_attrs.size, &ignored);
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

/* 编码 AuthenticatedData 文档（schema 感知）。 */
asnber_err_t encodeAuthenticatedData(
    const asnber_cms_authenticated_builder &builder, const asnber_doc_t *doc,
    asnber_buf_t *out_buf)
{
    asnber_schema_t *schema = nullptr;
    asnber_err_t rc =
        loadTable(builder.ctx, cmsSchemaTable(), kCmsRootAuthenticatedData,
                  &schema);
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

} /* namespace asnber_cms_detail */

using namespace asnber_cms_detail;

/* ========================================================================= */
/* AuthenticatedData builder 公共接口                                        */
/* ========================================================================= */

extern "C" asnber_err_t asnber_cms_authenticated_builder_create(
    asnber_ctx_t *ctx, asnber_cms_authenticated_builder_t **out_builder)
{
    if (ctx == nullptr || out_builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_builder = nullptr;
    asnber_cms_authenticated_builder_t *builder =
        static_cast<asnber_cms_authenticated_builder_t *>(
            std::malloc(sizeof(asnber_cms_authenticated_builder_t)));
    if (builder == nullptr) {
        return ASNBER_E_NOMEM;
    }
    std::memset(builder, 0, sizeof(*builder));
    builder->ctx = ctx;
    *out_builder = builder;
    return ASNBER_OK;
}

extern "C" void asnber_cms_authenticated_builder_destroy(
    asnber_cms_authenticated_builder_t *builder)
{
    if (builder == nullptr) {
        return;
    }
    std::free(builder->originator_info.data);
    /* freeSpans 负责释放数组本身，调用方不要再 free。 */
    freeSpans(builder->recipients, builder->recipient_count);
    std::free(builder->mac_alg_oid);
    std::free(builder->mac_alg_params.data);
    std::free(builder->digest_alg.data);
    std::free(builder->econtent_type);
    std::free(builder->econtent.data);
    std::free(builder->auth_attrs.data);
    std::free(builder->mac.data);
    std::free(builder->unauth_attrs.data);
    std::memset(builder, 0, sizeof(*builder));
    std::free(builder);
}

extern "C" asnber_err_t asnber_cms_authenticated_builder_set_version(
    asnber_cms_authenticated_builder_t *builder, int64_t version)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->version_set) {
        return ASNBER_E_INVALID_STATE;
    }
    /* RFC 5652 §9.1：AuthenticatedData 只出现 version 0、1、3。 */
    if (version != 0 && version != 1 && version != 3) {
        return ASNBER_E_INVALID_VALUE;
    }
    builder->version = version;
    builder->version_set = true;
    return ASNBER_OK;
}

extern "C" asnber_err_t
asnber_cms_authenticated_builder_set_originator_info(
    asnber_cms_authenticated_builder_t *builder, const uint8_t *tlv,
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

extern "C" asnber_err_t asnber_cms_authenticated_builder_add_recipient(
    asnber_cms_authenticated_builder_t *builder, const uint8_t *tlv,
    size_t tlv_size)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    der_root root;
    asnber_err_t rc = validateSingleDer(builder->ctx, tlv, tlv_size, &root);
    if (rc != ASNBER_OK) {
        return rc;
    }
    if (!isRecipientInfoRoot(root)) {
        return ASNBER_E_INVALID_VALUE;
    }
    if (!appendSpan(&builder->recipients, &builder->recipient_count,
                    &builder->recipient_capacity, tlv, tlv_size)) {
        return ASNBER_E_NOMEM;
    }
    return ASNBER_OK;
}

extern "C" asnber_err_t asnber_cms_authenticated_builder_set_mac_algorithm(
    asnber_cms_authenticated_builder_t *builder, const char *oid,
    const uint8_t *params, size_t params_size)
{
    if (builder == nullptr || oid == nullptr ||
        (params == nullptr && params_size != 0)) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->mac_alg_set) {
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
    builder->mac_alg_oid = copy;
    builder->mac_alg_params.data = params_copy;
    builder->mac_alg_params.size = params_size;
    builder->mac_alg_set = true;
    return ASNBER_OK;
}

extern "C" asnber_err_t
asnber_cms_authenticated_builder_set_digest_algorithm(
    asnber_cms_authenticated_builder_t *builder, const uint8_t *tlv,
    size_t tlv_size)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->digest_alg_set) {
        return ASNBER_E_INVALID_STATE;
    }
    asnber_err_t rc = validateTlvChildRules(
        builder->ctx, tlv, tlv_size, ASNBER_TAG_CONTEXT, kTagContext1, 1,
        kKeyDerivationRules, arraySize(kKeyDerivationRules));
    if (rc != ASNBER_OK) {
        return rc;
    }
    uint8_t *copy = copyBytes(tlv, tlv_size);
    if (copy == nullptr) {
        return ASNBER_E_NOMEM;
    }
    builder->digest_alg.data = copy;
    builder->digest_alg.size = tlv_size;
    builder->digest_alg_set = true;
    return ASNBER_OK;
}

extern "C" asnber_err_t asnber_cms_authenticated_builder_set_econtent_type(
    asnber_cms_authenticated_builder_t *builder, const char *oid)
{
    if (builder == nullptr || oid == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->econtent_type_set) {
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
    builder->econtent_type = copy;
    builder->econtent_type_set = true;
    return ASNBER_OK;
}

extern "C" asnber_err_t asnber_cms_authenticated_builder_set_econtent(
    asnber_cms_authenticated_builder_t *builder, const uint8_t *data, size_t size)
{
    if (builder == nullptr || (data == nullptr && size != 0)) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->econtent_set) {
        return ASNBER_E_INVALID_STATE;
    }
    uint8_t *copy = copyBytes(data, size);
    if (size != 0 && copy == nullptr) {
        return ASNBER_E_NOMEM;
    }
    builder->econtent.data = copy;
    builder->econtent.size = size;
    builder->econtent_set = true;
    return ASNBER_OK;
}

extern "C" asnber_err_t asnber_cms_authenticated_builder_set_auth_attrs(
    asnber_cms_authenticated_builder_t *builder, const uint8_t *tlv,
    size_t tlv_size)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->auth_attrs_set) {
        return ASNBER_E_INVALID_STATE;
    }
    byte_span rewritten;
    std::memset(&rewritten, 0, sizeof(rewritten));
    asnber_err_t rc = validateAndRewriteSet(builder->ctx, tlv, tlv_size, 0xA2,
                                          &rewritten);
    if (rc != ASNBER_OK) {
        return rc;
    }
    builder->auth_attrs = rewritten;
    builder->auth_attrs_set = true;
    return ASNBER_OK;
}

extern "C" asnber_err_t asnber_cms_authenticated_builder_set_mac(
    asnber_cms_authenticated_builder_t *builder, const uint8_t *data,
    size_t size)
{
    if (builder == nullptr || (data == nullptr && size != 0)) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->mac_set) {
        return ASNBER_E_INVALID_STATE;
    }
    uint8_t *copy = copyBytes(data, size);
    if (size != 0 && copy == nullptr) {
        return ASNBER_E_NOMEM;
    }
    builder->mac.data = copy;
    builder->mac.size = size;
    builder->mac_set = true;
    return ASNBER_OK;
}

extern "C" asnber_err_t asnber_cms_authenticated_builder_set_unauth_attrs(
    asnber_cms_authenticated_builder_t *builder, const uint8_t *tlv,
    size_t tlv_size)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->unauth_attrs_set) {
        return ASNBER_E_INVALID_STATE;
    }
    byte_span rewritten;
    std::memset(&rewritten, 0, sizeof(rewritten));
    asnber_err_t rc = validateAndRewriteSet(builder->ctx, tlv, tlv_size, 0xA3,
                                          &rewritten);
    if (rc != ASNBER_OK) {
        return rc;
    }
    builder->unauth_attrs = rewritten;
    builder->unauth_attrs_set = true;
    return ASNBER_OK;
}

extern "C" asnber_err_t asnber_cms_authenticated_builder_encode(
    const asnber_cms_authenticated_builder_t *builder, asnber_buf_t *out_buf)
{
    if (builder == nullptr || out_buf == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    out_buf->data = nullptr;
    out_buf->size = 0;
    out_buf->capacity = 0;

    if (!builder->version_set || builder->recipient_count == 0 ||
        !builder->mac_alg_set || !builder->econtent_type_set ||
        !builder->mac_set) {
        return ASNBER_E_INVALID_STATE;
    }
    if (builder->version != 0 && builder->version != 1 &&
        builder->version != 3) {
        return ASNBER_E_INVALID_VALUE;
    }
    /* version 1/3 只可能由 originatorInfo 的内容产生。 */
    if (builder->version != 0 && !builder->originator_info_set) {
        return ASNBER_E_INVALID_VALUE;
    }
    /* RFC 5652 §9.1：digestAlgorithm 与 authAttrs 必须同时出现。 */
    if (builder->digest_alg_set != builder->auth_attrs_set) {
        return ASNBER_E_INVALID_VALUE;
    }
    /*
     * RFC 5652 §9.1：内容类型不是 id-data 时 authAttrs 必须存在。
     * 只做结构配对校验，不生成或校验属性内容。
     */
    if (std::strcmp(builder->econtent_type, kDataOid) != 0 &&
        !builder->auth_attrs_set) {
        return ASNBER_E_INVALID_VALUE;
    }

    asnber_doc_t *authenticated_data = nullptr;
    asnber_err_t rc = buildAuthenticatedData(*builder, &authenticated_data);
    if (rc != ASNBER_OK) {
        return rc;
    }
    asnber_buf_t authenticated_buf;
    std::memset(&authenticated_buf, 0, sizeof(authenticated_buf));
    rc = encodeAuthenticatedData(*builder, authenticated_data,
                                 &authenticated_buf);
    asnber_doc_destroy(authenticated_data);
    if (rc != ASNBER_OK) {
        return rc;
    }

    rc = encodeContentInfo(builder->ctx, kAuthDataOid,
                           authenticated_buf.data, authenticated_buf.size,
                           out_buf);
    asnber_buf_release(builder->ctx, &authenticated_buf);
    return rc;
}
