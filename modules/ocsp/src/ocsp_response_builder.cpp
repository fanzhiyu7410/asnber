/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/* OCSPResponse 结构 builder。responseBytes 保持不透明。 */

#include "ocsp_builder_internal.h"

namespace asnber_ocsp_detail {

asnber_err_t buildResponse(const asnber_ocsp_response_builder &builder,
                           asnber_doc_t **out_doc)
{
    asnber_doc_t *doc = nullptr;
    asnber_err_t rc = asnber_doc_create(builder.ctx, &doc);
    if (rc != ASNBER_OK) {
        return rc;
    }
    asnber_node_t *root = nullptr;
    rc = createNode(doc, nullptr, ASNBER_TAG_UNIVERSAL, kTagSequence, 1, &root);
    asnber_node_t *ignored = nullptr;
    if (rc == ASNBER_OK) {
        rc = createEnumerated(doc, root, builder.status, &ignored);
    }
    if (rc == ASNBER_OK && builder.bytes_set) {
        asnber_node_t *wrapper = nullptr;
        rc = createNode(doc, root, ASNBER_TAG_CONTEXT, 0, 1, &wrapper);
        asnber_node_t *bytes = nullptr;
        if (rc == ASNBER_OK) {
            rc = createNode(doc, wrapper, ASNBER_TAG_UNIVERSAL, kTagSequence, 1,
                            &bytes);
        }
        if (rc == ASNBER_OK) {
            rc = createOidNode(doc, bytes, builder.type_oid, &ignored);
        }
        if (rc == ASNBER_OK) {
            rc = createOctetStringNode(doc, bytes, builder.response.data,
                                       builder.response.size, &ignored);
        }
    }
    if (rc != ASNBER_OK) {
        asnber_doc_destroy(doc);
        return rc;
    }
    *out_doc = doc;
    return ASNBER_OK;
}

} // namespace asnber_ocsp_detail

using namespace asnber_ocsp_detail;

extern "C" ASNBER_OCSP_API asnber_err_t asnber_ocsp_response_builder_create(
    asnber_ctx_t *ctx, asnber_ocsp_response_builder_t **out_builder)
{
    if (ctx == nullptr || out_builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_builder = nullptr;
    auto *builder = static_cast<asnber_ocsp_response_builder_t *>(
        std::malloc(sizeof(asnber_ocsp_response_builder_t)));
    if (builder == nullptr) {
        return ASNBER_E_NOMEM;
    }
    std::memset(builder, 0, sizeof(*builder));
    builder->ctx = ctx;
    *out_builder = builder;
    return ASNBER_OK;
}

extern "C" ASNBER_OCSP_API void asnber_ocsp_response_builder_destroy(
    asnber_ocsp_response_builder_t *builder)
{
    if (builder == nullptr) {
        return;
    }
    std::free(builder->type_oid);
    std::free(builder->response.data);
    std::memset(builder, 0, sizeof(*builder));
    std::free(builder);
}

extern "C" ASNBER_OCSP_API asnber_err_t asnber_ocsp_response_builder_set_status(
    asnber_ocsp_response_builder_t *builder, int64_t status)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->status_set) {
        return ASNBER_E_INVALID_STATE;
    }
    if (!responseStatusOk(status)) {
        return ASNBER_E_INVALID_VALUE;
    }
    builder->status = status;
    builder->status_set = true;
    return ASNBER_OK;
}

extern "C" ASNBER_OCSP_API asnber_err_t asnber_ocsp_response_builder_set_bytes(
    asnber_ocsp_response_builder_t *builder, const char *type_oid,
    const uint8_t *response, size_t response_size)
{
    if (builder == nullptr || type_oid == nullptr || response == nullptr ||
        response_size == 0) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->bytes_set) {
        return ASNBER_E_INVALID_STATE;
    }
    asnber_err_t rc = validateOid(builder->ctx, type_oid);
    if (rc != ASNBER_OK) {
        return rc;
    }
    char *oid = copyText(type_oid);
    if (oid == nullptr) {
        return ASNBER_E_NOMEM;
    }
    rc = copySpan(&builder->response, response, response_size);
    if (rc != ASNBER_OK) {
        std::free(oid);
        return rc;
    }
    builder->type_oid = oid;
    builder->bytes_set = true;
    return ASNBER_OK;
}

extern "C" ASNBER_OCSP_API asnber_err_t asnber_ocsp_response_builder_encode(
    const asnber_ocsp_response_builder_t *builder, asnber_buf_t *out_buf)
{
    if (builder == nullptr || out_buf == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    resetBuffer(out_buf);
    if (!builder->status_set) {
        return ASNBER_E_INVALID_STATE;
    }
    asnber_doc_t *doc = nullptr;
    asnber_err_t rc = buildResponse(*builder, &doc);
    if (rc != ASNBER_OK) {
        return rc;
    }
    return finishEncode(builder->ctx, doc, kOcspRootResponse, out_buf);
}
