/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/* OCSPRequest 结构 builder。 */

#include "ocsp_builder_internal.h"

namespace asnber_ocsp_detail {

asnber_err_t buildRequest(const asnber_ocsp_request_builder &builder,
                          asnber_doc_t **out_doc)
{
    asnber_doc_t *doc = nullptr;
    asnber_err_t rc = asnber_doc_create(builder.ctx, &doc);
    if (rc != ASNBER_OK) {
        return rc;
    }
    asnber_node_t *root = nullptr;
    rc = createNode(doc, nullptr, ASNBER_TAG_UNIVERSAL, kTagSequence, 1, &root);
    asnber_node_t *tbs = nullptr;
    if (rc == ASNBER_OK) {
        rc = createNode(doc, root, ASNBER_TAG_UNIVERSAL, kTagSequence, 1, &tbs);
    }
    if (rc == ASNBER_OK && builder.version != 0) {
        asnber_node_t *wrapper = nullptr;
        rc = createNode(doc, tbs, ASNBER_TAG_CONTEXT, 0, 1, &wrapper);
        asnber_node_t *ignored = nullptr;
        if (rc == ASNBER_OK) {
            rc = createIntegerNode(doc, wrapper, builder.version, &ignored);
        }
    }
    if (rc == ASNBER_OK && builder.requestor_set) {
        asnber_node_t *ignored = nullptr;
        rc = createExplicitAny(doc, tbs, 1, builder.requestor.data,
                               builder.requestor.size, &ignored);
    }
    asnber_node_t *list = nullptr;
    if (rc == ASNBER_OK) {
        rc = createNode(doc, tbs, ASNBER_TAG_UNIVERSAL, kTagSequence, 1, &list);
    }
    for (size_t i = 0; rc == ASNBER_OK && i < builder.request_count; ++i) {
        asnber_node_t *item = nullptr;
        rc = createNode(doc, list, ASNBER_TAG_UNIVERSAL, kTagSequence, 1, &item);
        if (rc == ASNBER_OK) {
            rc = addCertId(doc, item, builder.requests[i].cert_id);
        }
        if (rc == ASNBER_OK) {
            rc = addWrappedExtensions(doc, item, 0, builder.requests[i].extensions,
                                      builder.requests[i].extension_count);
        }
    }
    if (rc == ASNBER_OK) {
        rc = addWrappedExtensions(doc, tbs, 2, builder.extensions,
                                  builder.extension_count);
    }
    if (rc == ASNBER_OK && builder.signature.set) {
        asnber_node_t *wrapper = nullptr;
        rc = createNode(doc, root, ASNBER_TAG_CONTEXT, 0, 1, &wrapper);
        asnber_node_t *signature = nullptr;
        if (rc == ASNBER_OK) {
            rc = createNode(doc, wrapper, ASNBER_TAG_UNIVERSAL, kTagSequence, 1,
                            &signature);
        }
        if (rc == ASNBER_OK) {
            rc = addSignature(doc, signature, builder.signature);
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

extern "C" ASNBER_OCSP_API asnber_err_t asnber_ocsp_request_builder_create(
    asnber_ctx_t *ctx, asnber_ocsp_request_builder_t **out_builder)
{
    if (ctx == nullptr || out_builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_builder = nullptr;
    auto *builder = static_cast<asnber_ocsp_request_builder_t *>(
        std::malloc(sizeof(asnber_ocsp_request_builder_t)));
    if (builder == nullptr) {
        return ASNBER_E_NOMEM;
    }
    std::memset(builder, 0, sizeof(*builder));
    builder->ctx = ctx;
    *out_builder = builder;
    return ASNBER_OK;
}

extern "C" ASNBER_OCSP_API void asnber_ocsp_request_builder_destroy(
    asnber_ocsp_request_builder_t *builder)
{
    if (builder == nullptr) {
        return;
    }
    std::free(builder->requestor.data);
    freeRequests(builder->requests, builder->request_count);
    freeExtensions(builder->extensions, builder->extension_count);
    freeSignature(&builder->signature);
    std::memset(builder, 0, sizeof(*builder));
    std::free(builder);
}

extern "C" ASNBER_OCSP_API asnber_err_t asnber_ocsp_request_builder_set_version(
    asnber_ocsp_request_builder_t *builder, int64_t version)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return setVersion(&builder->version_set, &builder->version, version);
}

extern "C" ASNBER_OCSP_API asnber_err_t asnber_ocsp_request_builder_set_requestor(
    asnber_ocsp_request_builder_t *builder, const uint8_t *name_der,
    size_t name_size)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->requestor_set) {
        return ASNBER_E_INVALID_STATE;
    }
    asnber_err_t rc = checkTlv(builder->ctx, name_der, name_size);
    if (rc != ASNBER_OK) {
        return rc;
    }
    rc = copySpan(&builder->requestor, name_der, name_size);
    if (rc != ASNBER_OK) {
        return rc;
    }
    builder->requestor_set = true;
    return ASNBER_OK;
}

extern "C" ASNBER_OCSP_API asnber_err_t asnber_ocsp_request_builder_add_request(
    asnber_ocsp_request_builder_t *builder, const char *hash_oid,
    const uint8_t *hash_params, size_t hash_params_size,
    const uint8_t *name_hash, size_t name_hash_size, const uint8_t *key_hash,
    size_t key_hash_size, const uint8_t *serial, size_t serial_size)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    cert_id_store cert_id;
    asnber_err_t rc =
        storeCertId(builder->ctx, &cert_id, hash_oid, hash_params, hash_params_size,
                    name_hash, name_hash_size, key_hash, key_hash_size, serial,
                    serial_size);
    if (rc != ASNBER_OK) {
        return rc;
    }
    if (!ensureCapacity(&builder->requests, builder->request_count,
                        &builder->request_capacity)) {
        freeCertId(&cert_id);
        return ASNBER_E_NOMEM;
    }
    request_item &item = builder->requests[builder->request_count];
    std::memset(&item, 0, sizeof(item));
    item.cert_id = cert_id;
    ++builder->request_count;
    return ASNBER_OK;
}

extern "C" ASNBER_OCSP_API asnber_err_t
asnber_ocsp_request_builder_add_single_extension(
    asnber_ocsp_request_builder_t *builder, size_t request_index,
    const char *extn_oid, int critical, const uint8_t *extn_value_der,
    size_t extn_value_size)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (request_index >= builder->request_count) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber_err_t rc =
        checkExtension(builder->ctx, extn_oid, extn_value_der, extn_value_size);
    if (rc != ASNBER_OK) {
        return rc;
    }
    request_item &item = builder->requests[request_index];
    if (hasExtension(item.extensions, item.extension_count, extn_oid)) {
        return ASNBER_E_INVALID_VALUE;
    }
    return appendExtension(&item.extensions, &item.extension_count,
                           &item.extension_capacity, extn_oid, critical != 0,
                           extn_value_der, extn_value_size);
}

extern "C" ASNBER_OCSP_API asnber_err_t asnber_ocsp_request_builder_add_extension(
    asnber_ocsp_request_builder_t *builder, const char *extn_oid, int critical,
    const uint8_t *extn_value_der, size_t extn_value_size)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber_err_t rc =
        checkExtension(builder->ctx, extn_oid, extn_value_der, extn_value_size);
    if (rc != ASNBER_OK) {
        return rc;
    }
    if (hasExtension(builder->extensions, builder->extension_count, extn_oid)) {
        return ASNBER_E_INVALID_VALUE;
    }
    return appendExtension(&builder->extensions, &builder->extension_count,
                           &builder->extension_capacity, extn_oid, critical != 0,
                           extn_value_der, extn_value_size);
}

extern "C" ASNBER_OCSP_API asnber_err_t asnber_ocsp_request_builder_set_signature(
    asnber_ocsp_request_builder_t *builder, const char *oid, const uint8_t *params,
    size_t params_size, const uint8_t *bits, size_t bits_size, uint8_t unused_bits)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return storeSignature(builder->ctx, &builder->signature, oid, params, params_size,
                          bits, bits_size, unused_bits);
}

extern "C" ASNBER_OCSP_API asnber_err_t
asnber_ocsp_request_builder_add_signature_cert(
    asnber_ocsp_request_builder_t *builder, const uint8_t *cert_der,
    size_t cert_size)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return addCert(builder->ctx, &builder->signature, cert_der, cert_size);
}

extern "C" ASNBER_OCSP_API asnber_err_t asnber_ocsp_request_builder_encode(
    const asnber_ocsp_request_builder_t *builder, asnber_buf_t *out_buf)
{
    if (builder == nullptr || out_buf == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    resetBuffer(out_buf);
    if (builder->request_count == 0) {
        return ASNBER_E_INVALID_STATE;
    }
    asnber_doc_t *doc = nullptr;
    asnber_err_t rc = buildRequest(*builder, &doc);
    if (rc != ASNBER_OK) {
        return rc;
    }
    return finishEncode(builder->ctx, doc, kOcspRootRequest, out_buf);
}
