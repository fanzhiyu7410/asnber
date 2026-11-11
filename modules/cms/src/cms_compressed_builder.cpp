/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-cms CompressedData builder：构树、编码与公共接口。
 */

#include "detail/cms_builder_internal.h"

#include <cstdlib>
#include <cstring>

namespace asnber_cms_detail {

asnber_err_t buildCompressedData(const asnber_cms_compressed_builder &builder,
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
    if (rc == ASNBER_OK) {
        rc = addAlgorithmIdentifier(doc, root, builder.compression_alg_oid,
                                    builder.compression_alg_params);
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

/* 编码 CompressedData 文档（schema 感知）。 */
asnber_err_t encodeCompressedData(const asnber_cms_compressed_builder &builder,
                                const asnber_doc_t *doc, asnber_buf_t *out_buf)
{
    asnber_schema_t *schema = nullptr;
    asnber_err_t rc = loadTable(builder.ctx, cmsSchemaTable(),
                              kCmsRootCompressedData, &schema);
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
/* CompressedData builder 公共接口                                           */
/* ========================================================================= */

extern "C" asnber_err_t asnber_cms_compressed_builder_create(
    asnber_ctx_t *ctx, asnber_cms_compressed_builder_t **out_builder)
{
    if (ctx == nullptr || out_builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_builder = nullptr;
    asnber_cms_compressed_builder_t *builder =
        static_cast<asnber_cms_compressed_builder_t *>(
            std::malloc(sizeof(asnber_cms_compressed_builder_t)));
    if (builder == nullptr) {
        return ASNBER_E_NOMEM;
    }
    std::memset(builder, 0, sizeof(*builder));
    builder->ctx = ctx;
    *out_builder = builder;
    return ASNBER_OK;
}

extern "C" void asnber_cms_compressed_builder_destroy(
    asnber_cms_compressed_builder_t *builder)
{
    if (builder == nullptr) {
        return;
    }
    std::free(builder->compression_alg_oid);
    std::free(builder->compression_alg_params.data);
    std::free(builder->econtent_type);
    std::free(builder->econtent.data);
    std::memset(builder, 0, sizeof(*builder));
    std::free(builder);
}

extern "C" asnber_err_t asnber_cms_compressed_builder_set_version(
    asnber_cms_compressed_builder_t *builder, int64_t version)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->version_set) {
        return ASNBER_E_INVALID_STATE;
    }
    /* RFC 3274 §2：CompressedData 的 version 必须为 0。 */
    if (version != 0) {
        return ASNBER_E_INVALID_VALUE;
    }
    builder->version = version;
    builder->version_set = true;
    return ASNBER_OK;
}

extern "C" asnber_err_t
asnber_cms_compressed_builder_set_compression_algorithm(
    asnber_cms_compressed_builder_t *builder, const char *oid,
    const uint8_t *params, size_t params_size)
{
    if (builder == nullptr || oid == nullptr ||
        (params == nullptr && params_size != 0)) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->compression_alg_set) {
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
    builder->compression_alg_oid = copy;
    builder->compression_alg_params.data = params_copy;
    builder->compression_alg_params.size = params_size;
    builder->compression_alg_set = true;
    return ASNBER_OK;
}

extern "C" asnber_err_t asnber_cms_compressed_builder_set_econtent_type(
    asnber_cms_compressed_builder_t *builder, const char *oid)
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

extern "C" asnber_err_t asnber_cms_compressed_builder_set_econtent(
    asnber_cms_compressed_builder_t *builder, const uint8_t *data, size_t size)
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

extern "C" asnber_err_t asnber_cms_compressed_builder_encode(
    const asnber_cms_compressed_builder_t *builder, asnber_buf_t *out_buf)
{
    if (builder == nullptr || out_buf == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    out_buf->data = nullptr;
    out_buf->size = 0;
    out_buf->capacity = 0;

    if (!builder->version_set || !builder->compression_alg_set ||
        !builder->econtent_type_set) {
        return ASNBER_E_INVALID_STATE;
    }
    if (builder->version != 0) {
        return ASNBER_E_INVALID_VALUE;
    }

    asnber_doc_t *compressed_data = nullptr;
    asnber_err_t rc = buildCompressedData(*builder, &compressed_data);
    if (rc != ASNBER_OK) {
        return rc;
    }
    asnber_buf_t compressed_buf;
    std::memset(&compressed_buf, 0, sizeof(compressed_buf));
    rc = encodeCompressedData(*builder, compressed_data, &compressed_buf);
    asnber_doc_destroy(compressed_data);
    if (rc != ASNBER_OK) {
        return rc;
    }

    rc = encodeContentInfo(builder->ctx, kCompressedDataOid,
                           compressed_buf.data, compressed_buf.size, out_buf);
    asnber_buf_release(builder->ctx, &compressed_buf);
    return rc;
}
