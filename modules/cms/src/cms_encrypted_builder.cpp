/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-cms EncryptedData builder：构树、编码与公共接口。
 */

#include "detail/cms_builder_internal.h"

#include <cstdlib>
#include <cstring>

namespace asnber_cms_detail {

asnber_err_t buildEncryptedData(const asnber_cms_encrypted_builder &builder,
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

/* 编码 EncryptedData 文档（schema 感知）。 */
asnber_err_t encodeEncryptedData(const asnber_cms_encrypted_builder &builder,
                               const asnber_doc_t *doc, asnber_buf_t *out_buf)
{
    asnber_schema_t *schema = nullptr;
    asnber_err_t rc = loadTable(builder.ctx, cmsSchemaTable(),
                              kCmsRootEncryptedData, &schema);
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
/* EncryptedData builder 公共接口                                            */
/* ========================================================================= */

extern "C" asnber_err_t asnber_cms_encrypted_builder_create(
    asnber_ctx_t *ctx, asnber_cms_encrypted_builder_t **out_builder)
{
    if (ctx == nullptr || out_builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_builder = nullptr;
    asnber_cms_encrypted_builder_t *builder =
        static_cast<asnber_cms_encrypted_builder_t *>(
            std::malloc(sizeof(asnber_cms_encrypted_builder_t)));
    if (builder == nullptr) {
        return ASNBER_E_NOMEM;
    }
    std::memset(builder, 0, sizeof(*builder));
    builder->ctx = ctx;
    *out_builder = builder;
    return ASNBER_OK;
}

extern "C" void asnber_cms_encrypted_builder_destroy(
    asnber_cms_encrypted_builder_t *builder)
{
    if (builder == nullptr) {
        return;
    }
    std::free(builder->content_type);
    std::free(builder->content_alg_oid);
    std::free(builder->content_alg_params.data);
    std::free(builder->encrypted_content.data);
    std::free(builder->unprotected_attrs.data);
    std::memset(builder, 0, sizeof(*builder));
    std::free(builder);
}

extern "C" asnber_err_t asnber_cms_encrypted_builder_set_version(
    asnber_cms_encrypted_builder_t *builder, int64_t version)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->version_set) {
        return ASNBER_E_INVALID_STATE;
    }
    /*
     * EncryptedData 只有 v0（无 unprotectedAttrs）与 v2（有）两档，
     * 其他值在任何配对下都无法编码，setter 直接拒绝；0/2 与属性是否
     * 出现的一致性问题仍由 encode 判定。
     */
    if (version != 0 && version != 2) {
        return ASNBER_E_INVALID_VALUE;
    }
    builder->version = version;
    builder->version_set = true;
    return ASNBER_OK;
}

extern "C" asnber_err_t asnber_cms_encrypted_builder_set_content_type(
    asnber_cms_encrypted_builder_t *builder, const char *oid)
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
asnber_cms_encrypted_builder_set_content_encryption_algorithm(
    asnber_cms_encrypted_builder_t *builder, const char *oid,
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

extern "C" asnber_err_t asnber_cms_encrypted_builder_set_encrypted_content(
    asnber_cms_encrypted_builder_t *builder, const uint8_t *data, size_t size)
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

extern "C" asnber_err_t asnber_cms_encrypted_builder_set_unprotected_attrs(
    asnber_cms_encrypted_builder_t *builder, const uint8_t *tlv,
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

extern "C" asnber_err_t asnber_cms_encrypted_builder_encode(
    const asnber_cms_encrypted_builder_t *builder, asnber_buf_t *out_buf)
{
    if (builder == nullptr || out_buf == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    out_buf->data = nullptr;
    out_buf->size = 0;
    out_buf->capacity = 0;

    if (!builder->version_set || !builder->content_type_set ||
        !builder->content_alg_set) {
        return ASNBER_E_INVALID_STATE;
    }

    /*
     * RFC 5652 §8：无 unprotectedAttrs 时 version 必须为 0；带该字段时
     * 必须为 2。只校验，不改写调用方给出的值。
     */
    if (builder->unprotected_attrs_set) {
        if (builder->version != 2) {
            return ASNBER_E_INVALID_VALUE;
        }
    } else if (builder->version != 0) {
        return ASNBER_E_INVALID_VALUE;
    }

    asnber_doc_t *encrypted_data = nullptr;
    asnber_err_t rc = buildEncryptedData(*builder, &encrypted_data);
    if (rc != ASNBER_OK) {
        return rc;
    }
    asnber_buf_t encrypted_buf;
    std::memset(&encrypted_buf, 0, sizeof(encrypted_buf));
    rc = encodeEncryptedData(*builder, encrypted_data, &encrypted_buf);
    asnber_doc_destroy(encrypted_data);
    if (rc != ASNBER_OK) {
        return rc;
    }

    rc = encodeContentInfo(builder->ctx, kEncryptedDataOid,
                           encrypted_buf.data, encrypted_buf.size, out_buf);
    asnber_buf_release(builder->ctx, &encrypted_buf);
    return rc;
}
