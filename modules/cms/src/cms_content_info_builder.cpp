/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-cms ContentInfo builder：构树、编码与公共接口。
 */

#include "detail/cms_builder_internal.h"

#include <cstdlib>
#include <cstring>

namespace asnber_cms_detail {

/* 把原始字节包成 [0] EXPLICIT OCTET STRING 的完整 TLV。 */
static asnber_err_t encodeOctetsWrapper(asnber_ctx_t *ctx, const uint8_t *data,
                                      size_t size, asnber_buf_t *out_buf)
{
    asnber_doc_t *doc = nullptr;
    asnber_err_t rc = asnber_doc_create(ctx, &doc);
    if (rc != ASNBER_OK) {
        return rc;
    }
    asnber_node_t *wrapper = nullptr;
    asnber_node_t *octets = nullptr;
    rc = createNode(doc, nullptr, ASNBER_TAG_CONTEXT, kTagContext0, 1, &wrapper);
    if (rc == ASNBER_OK) {
        rc = createOctetStringNode(doc, wrapper, data, size, &octets);
    }
    if (rc == ASNBER_OK) {
        rc = asnber_doc_seal(doc);
    }
    if (rc != ASNBER_OK) {
        asnber_doc_destroy(doc);
        return rc;
    }
    rc = asnber_encode_buffer(ctx, doc, nullptr, out_buf);
    asnber_doc_destroy(doc);
    return rc;
}

asnber_err_t buildContentInfo(const asnber_cms_content_info_builder &builder,
                            asnber_doc_t **out_doc)
{
    asnber_buf_t wrapper;
    std::memset(&wrapper, 0, sizeof(wrapper));

    asnber_err_t rc = ASNBER_OK;
    if (builder.content_set) {
        rc = builder.content_is_octets
                 ? encodeOctetsWrapper(builder.ctx, builder.content.data,
                                       builder.content.size, &wrapper)
                 : encodeExplicitWrapper(builder.ctx, builder.content.data,
                                         builder.content.size, &wrapper);
        if (rc != ASNBER_OK) {
            return rc;
        }
    }

    asnber_doc_t *doc = nullptr;
    rc = asnber_doc_create(builder.ctx, &doc);
    if (rc != ASNBER_OK) {
        asnber_buf_release(builder.ctx, &wrapper);
        return rc;
    }

    asnber_node_t *root = nullptr;
    asnber_node_t *ignored = nullptr;
    rc = createNode(doc, nullptr, ASNBER_TAG_UNIVERSAL, kTagSequence, 1, &root);
    if (rc == ASNBER_OK) {
        rc = createOidNode(doc, root, builder.content_type, &ignored);
    }
    if (rc == ASNBER_OK && builder.content_set) {
        rc = asnber_node_create_any(doc, root, wrapper.data, wrapper.size,
                                  &ignored);
    }
    if (rc == ASNBER_OK) {
        rc = asnber_doc_seal(doc);
    }
    asnber_buf_release(builder.ctx, &wrapper);
    if (rc != ASNBER_OK) {
        asnber_doc_destroy(doc);
        return rc;
    }
    *out_doc = doc;
    return ASNBER_OK;
}

/* 编码 ContentInfo 文档（schema 感知）。 */
asnber_err_t encodeContentInfoDocument(
    const asnber_cms_content_info_builder &builder, const asnber_doc_t *doc,
    asnber_buf_t *out_buf)
{
    asnber_schema_t *schema = nullptr;
    asnber_err_t rc = loadTable(builder.ctx, cmsSchemaTable(), kCmsRootContentInfo,
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
/* ContentInfo builder 公共接口                                              */
/* ========================================================================= */

extern "C" asnber_err_t asnber_cms_content_info_builder_create(
    asnber_ctx_t *ctx, asnber_cms_content_info_builder_t **out_builder)
{
    if (ctx == nullptr || out_builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_builder = nullptr;
    asnber_cms_content_info_builder_t *builder =
        static_cast<asnber_cms_content_info_builder_t *>(
            std::malloc(sizeof(asnber_cms_content_info_builder_t)));
    if (builder == nullptr) {
        return ASNBER_E_NOMEM;
    }
    std::memset(builder, 0, sizeof(*builder));
    builder->ctx = ctx;
    *out_builder = builder;
    return ASNBER_OK;
}

extern "C" void asnber_cms_content_info_builder_destroy(
    asnber_cms_content_info_builder_t *builder)
{
    if (builder == nullptr) {
        return;
    }
    std::free(builder->content_type);
    std::free(builder->content.data);
    std::memset(builder, 0, sizeof(*builder));
    std::free(builder);
}

extern "C" asnber_err_t asnber_cms_content_info_builder_set_content_type(
    asnber_cms_content_info_builder_t *builder, const char *oid)
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

extern "C" asnber_err_t asnber_cms_content_info_builder_set_content_tlv(
    asnber_cms_content_info_builder_t *builder, const uint8_t *tlv,
    size_t tlv_size)
{
    if (builder == nullptr || tlv == nullptr || tlv_size == 0) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->content_set) {
        return ASNBER_E_INVALID_STATE;
    }
    asnber_err_t rc = validateSingleDer(builder->ctx, tlv, tlv_size, nullptr);
    if (rc != ASNBER_OK) {
        return rc;
    }
    uint8_t *copy = copyBytes(tlv, tlv_size);
    if (copy == nullptr) {
        return ASNBER_E_NOMEM;
    }
    builder->content.data = copy;
    builder->content.size = tlv_size;
    builder->content_is_octets = false;
    builder->content_set = true;
    return ASNBER_OK;
}

extern "C" asnber_err_t asnber_cms_content_info_builder_set_content_octets(
    asnber_cms_content_info_builder_t *builder, const uint8_t *data,
    size_t size)
{
    if (builder == nullptr || (data == nullptr && size != 0)) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->content_set) {
        return ASNBER_E_INVALID_STATE;
    }
    uint8_t *copy = copyBytes(data, size);
    if (size != 0 && copy == nullptr) {
        return ASNBER_E_NOMEM;
    }
    builder->content.data = copy;
    builder->content.size = size;
    builder->content_is_octets = true;
    builder->content_set = true;
    return ASNBER_OK;
}

extern "C" asnber_err_t asnber_cms_content_info_builder_encode(
    const asnber_cms_content_info_builder_t *builder, asnber_buf_t *out_buf)
{
    if (builder == nullptr || out_buf == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    out_buf->data = nullptr;
    out_buf->size = 0;
    out_buf->capacity = 0;

    if (!builder->content_type_set) {
        return ASNBER_E_INVALID_STATE;
    }

    asnber_doc_t *content_info = nullptr;
    asnber_err_t rc = buildContentInfo(*builder, &content_info);
    if (rc != ASNBER_OK) {
        return rc;
    }
    rc = encodeContentInfoDocument(*builder, content_info, out_buf);
    asnber_doc_destroy(content_info);
    return rc;
}
