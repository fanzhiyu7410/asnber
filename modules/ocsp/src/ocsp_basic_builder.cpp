/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/* BasicOCSPResponse 结构 builder。 */

#include "ocsp_builder_internal.h"

namespace asnber_ocsp_detail {

asnber_err_t addRevokedStatus(asnber_doc_t *doc, asnber_node_t *parent,
                              const single_item &item)
{
    asnber_node_t *status = nullptr;
    asnber_err_t rc = createNode(doc, parent, ASNBER_TAG_CONTEXT, 1, 1, &status);
    asnber_node_t *ignored = nullptr;
    if (rc == ASNBER_OK) {
        rc = createGeneralizedTime(doc, status, &item.revocation_time, &ignored);
    }
    if (rc == ASNBER_OK && item.reason_set) {
        asnber_node_t *wrapper = nullptr;
        rc = createNode(doc, status, ASNBER_TAG_CONTEXT, 0, 1, &wrapper);
        if (rc == ASNBER_OK) {
            rc = createEnumerated(doc, wrapper, item.reason, &ignored);
        }
    }
    return rc;
}

asnber_err_t buildBasic(const asnber_ocsp_basic_builder &builder,
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
    if (rc == ASNBER_OK && builder.responder_by_name) {
        asnber_node_t *ignored = nullptr;
        rc = createExplicitAny(doc, tbs, 1, builder.responder.data,
                               builder.responder.size, &ignored);
    } else if (rc == ASNBER_OK) {
        asnber_node_t *wrapper = nullptr;
        rc = createNode(doc, tbs, ASNBER_TAG_CONTEXT, 2, 1, &wrapper);
        asnber_node_t *ignored = nullptr;
        if (rc == ASNBER_OK) {
            rc = createOctetStringNode(doc, wrapper, builder.responder.data,
                                       builder.responder.size, &ignored);
        }
    }
    if (rc == ASNBER_OK) {
        asnber_node_t *ignored = nullptr;
        rc = createGeneralizedTime(doc, tbs, &builder.produced_at, &ignored);
    }
    asnber_node_t *list = nullptr;
    if (rc == ASNBER_OK) {
        rc = createNode(doc, tbs, ASNBER_TAG_UNIVERSAL, kTagSequence, 1, &list);
    }
    for (size_t i = 0; rc == ASNBER_OK && i < builder.response_count; ++i) {
        const single_item &item = builder.responses[i];
        asnber_node_t *single = nullptr;
        rc = createNode(doc, list, ASNBER_TAG_UNIVERSAL, kTagSequence, 1, &single);
        if (rc == ASNBER_OK) {
            rc = addCertId(doc, single, item.cert_id);
        }
        asnber_node_t *ignored = nullptr;
        if (rc == ASNBER_OK && item.status == kStatusGood) {
            rc = createNullStatus(doc, single, 0, &ignored);
        } else if (rc == ASNBER_OK && item.status == kStatusUnknown) {
            rc = createNullStatus(doc, single, 2, &ignored);
        } else if (rc == ASNBER_OK) {
            rc = addRevokedStatus(doc, single, item);
        }
        if (rc == ASNBER_OK) {
            rc = createGeneralizedTime(doc, single, &item.this_update, &ignored);
        }
        if (rc == ASNBER_OK && item.next_set) {
            asnber_node_t *wrapper = nullptr;
            rc = createNode(doc, single, ASNBER_TAG_CONTEXT, 0, 1, &wrapper);
            if (rc == ASNBER_OK) {
                rc = createGeneralizedTime(doc, wrapper, &item.next_update, &ignored);
            }
        }
        if (rc == ASNBER_OK) {
            rc = addWrappedExtensions(doc, single, 1, item.extensions,
                                      item.extension_count);
        }
    }
    if (rc == ASNBER_OK) {
        rc = addWrappedExtensions(doc, tbs, 1, builder.extensions,
                                  builder.extension_count);
    }
    if (rc == ASNBER_OK) {
        rc = addSignature(doc, root, builder.signature);
    }
    if (rc != ASNBER_OK) {
        asnber_doc_destroy(doc);
        return rc;
    }
    *out_doc = doc;
    return ASNBER_OK;
}

asnber_err_t storeTime(const asnber_time_t *time, bool *set, asnber_time_t *stored)
{
    asnber_err_t rc = validateTime(time);
    if (rc != ASNBER_OK) {
        return rc;
    }
    *stored = *time;
    *set = true;
    return ASNBER_OK;
}

asnber_err_t appendSingle(asnber_ocsp_basic_builder *builder, int status,
                          cert_id_store *cert_id, const asnber_time_t *this_update,
                          const asnber_time_t *next_update,
                          const asnber_time_t *revocation_time, int64_t reason,
                          int reason_present)
{
    single_item item;
    std::memset(&item, 0, sizeof(item));
    item.cert_id = *cert_id;
    std::memset(cert_id, 0, sizeof(*cert_id));
    item.status = status;
    bool stored = false;
    asnber_err_t rc = storeTime(this_update, &stored, &item.this_update);
    if (rc == ASNBER_OK && !stored) {
        rc = ASNBER_E_INVALID_STATE;
    }
    if (rc == ASNBER_OK && next_update != nullptr) {
        rc = storeTime(next_update, &item.next_set, &item.next_update);
    }
    if (rc == ASNBER_OK && revocation_time != nullptr) {
        bool ignored = false;
        rc = storeTime(revocation_time, &ignored, &item.revocation_time);
    }
    if (rc == ASNBER_OK && reason_present != 0) {
        if (!crlReasonOk(reason)) {
            rc = ASNBER_E_INVALID_VALUE;
        } else {
            item.reason = reason;
            item.reason_set = true;
        }
    }
    if (rc != ASNBER_OK) {
        freeCertId(&item.cert_id);
        return rc;
    }
    if (!ensureCapacity(&builder->responses, builder->response_count,
                        &builder->response_capacity)) {
        freeCertId(&item.cert_id);
        return ASNBER_E_NOMEM;
    }
    builder->responses[builder->response_count++] = item;
    return ASNBER_OK;
}

} // namespace asnber_ocsp_detail

using namespace asnber_ocsp_detail;

extern "C" ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_builder_create(
    asnber_ctx_t *ctx, asnber_ocsp_basic_builder_t **out_builder)
{
    if (ctx == nullptr || out_builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_builder = nullptr;
    auto *builder = static_cast<asnber_ocsp_basic_builder_t *>(
        std::malloc(sizeof(asnber_ocsp_basic_builder_t)));
    if (builder == nullptr) {
        return ASNBER_E_NOMEM;
    }
    std::memset(builder, 0, sizeof(*builder));
    builder->ctx = ctx;
    *out_builder = builder;
    return ASNBER_OK;
}

extern "C" ASNBER_OCSP_API void asnber_ocsp_basic_builder_destroy(
    asnber_ocsp_basic_builder_t *builder)
{
    if (builder == nullptr) {
        return;
    }
    std::free(builder->responder.data);
    freeSingles(builder->responses, builder->response_count);
    freeExtensions(builder->extensions, builder->extension_count);
    freeSignature(&builder->signature);
    std::memset(builder, 0, sizeof(*builder));
    std::free(builder);
}

extern "C" ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_builder_set_version(
    asnber_ocsp_basic_builder_t *builder, int64_t version)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return setVersion(&builder->version_set, &builder->version, version);
}

extern "C" ASNBER_OCSP_API asnber_err_t
asnber_ocsp_basic_builder_set_responder_name(asnber_ocsp_basic_builder_t *builder,
                                             const uint8_t *name_der,
                                             size_t name_size)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->responder_set) {
        return ASNBER_E_INVALID_STATE;
    }
    asnber_err_t rc = checkTlv(builder->ctx, name_der, name_size);
    if (rc != ASNBER_OK) {
        return rc;
    }
    rc = copySpan(&builder->responder, name_der, name_size);
    if (rc != ASNBER_OK) {
        return rc;
    }
    builder->responder_by_name = true;
    builder->responder_set = true;
    return ASNBER_OK;
}

extern "C" ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_builder_set_responder_key(
    asnber_ocsp_basic_builder_t *builder, const uint8_t *key_hash,
    size_t key_hash_size)
{
    if (builder == nullptr || key_hash == nullptr || key_hash_size == 0) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->responder_set) {
        return ASNBER_E_INVALID_STATE;
    }
    asnber_err_t rc = copySpan(&builder->responder, key_hash, key_hash_size);
    if (rc != ASNBER_OK) {
        return rc;
    }
    builder->responder_by_name = false;
    builder->responder_set = true;
    return ASNBER_OK;
}

extern "C" ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_builder_set_produced_at(
    asnber_ocsp_basic_builder_t *builder, const asnber_time_t *produced_at)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->produced_set) {
        return ASNBER_E_INVALID_STATE;
    }
    bool set = false;
    asnber_err_t rc = storeTime(produced_at, &set, &builder->produced_at);
    if (rc != ASNBER_OK) {
        return rc;
    }
    builder->produced_set = true;
    return ASNBER_OK;
}

namespace {

asnber_err_t addBasicResponse(asnber_ocsp_basic_builder_t *builder, int status,
                              const char *hash_oid, const uint8_t *hash_params,
                              size_t hash_params_size, const uint8_t *name_hash,
                              size_t name_hash_size, const uint8_t *key_hash,
                              size_t key_hash_size, const uint8_t *serial,
                              size_t serial_size, const asnber_time_t *this_update,
                              const asnber_time_t *next_update,
                              const asnber_time_t *revocation_time, int64_t reason,
                              int reason_present)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    cert_id_store cert_id;
    asnber_err_t rc = storeCertId(builder->ctx, &cert_id, hash_oid, hash_params,
                                  hash_params_size, name_hash, name_hash_size,
                                  key_hash, key_hash_size, serial, serial_size);
    if (rc != ASNBER_OK) {
        return rc;
    }
    return appendSingle(builder, status, &cert_id, this_update, next_update,
                        revocation_time, reason, reason_present);
}

} // namespace

extern "C" ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_builder_add_good(
    asnber_ocsp_basic_builder_t *builder, const char *hash_oid,
    const uint8_t *hash_params, size_t hash_params_size,
    const uint8_t *name_hash, size_t name_hash_size, const uint8_t *key_hash,
    size_t key_hash_size, const uint8_t *serial, size_t serial_size,
    const asnber_time_t *this_update, const asnber_time_t *next_update)
{
    return addBasicResponse(builder, kStatusGood, hash_oid, hash_params,
                            hash_params_size, name_hash, name_hash_size, key_hash,
                            key_hash_size, serial, serial_size, this_update,
                            next_update, nullptr, 0, 0);
}

extern "C" ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_builder_add_unknown(
    asnber_ocsp_basic_builder_t *builder, const char *hash_oid,
    const uint8_t *hash_params, size_t hash_params_size,
    const uint8_t *name_hash, size_t name_hash_size, const uint8_t *key_hash,
    size_t key_hash_size, const uint8_t *serial, size_t serial_size,
    const asnber_time_t *this_update, const asnber_time_t *next_update)
{
    return addBasicResponse(builder, kStatusUnknown, hash_oid, hash_params,
                            hash_params_size, name_hash, name_hash_size, key_hash,
                            key_hash_size, serial, serial_size, this_update,
                            next_update, nullptr, 0, 0);
}

extern "C" ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_builder_add_revoked(
    asnber_ocsp_basic_builder_t *builder, const char *hash_oid,
    const uint8_t *hash_params, size_t hash_params_size,
    const uint8_t *name_hash, size_t name_hash_size, const uint8_t *key_hash,
    size_t key_hash_size, const uint8_t *serial, size_t serial_size,
    const asnber_time_t *this_update, const asnber_time_t *next_update,
    const asnber_time_t *revocation_time, int64_t reason, int reason_present)
{
    if (revocation_time == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return addBasicResponse(builder, kStatusRevoked, hash_oid, hash_params,
                            hash_params_size, name_hash, name_hash_size, key_hash,
                            key_hash_size, serial, serial_size, this_update,
                            next_update, revocation_time, reason, reason_present);
}

extern "C" ASNBER_OCSP_API asnber_err_t
asnber_ocsp_basic_builder_add_single_extension(
    asnber_ocsp_basic_builder_t *builder, size_t response_index,
    const char *extn_oid, int critical, const uint8_t *extn_value_der,
    size_t extn_value_size)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (response_index >= builder->response_count) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber_err_t rc =
        checkExtension(builder->ctx, extn_oid, extn_value_der, extn_value_size);
    if (rc != ASNBER_OK) {
        return rc;
    }
    single_item &item = builder->responses[response_index];
    if (hasExtension(item.extensions, item.extension_count, extn_oid)) {
        return ASNBER_E_INVALID_VALUE;
    }
    return appendExtension(&item.extensions, &item.extension_count,
                           &item.extension_capacity, extn_oid, critical != 0,
                           extn_value_der, extn_value_size);
}

extern "C" ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_builder_add_extension(
    asnber_ocsp_basic_builder_t *builder, const char *extn_oid, int critical,
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

extern "C" ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_builder_set_signature(
    asnber_ocsp_basic_builder_t *builder, const char *oid, const uint8_t *params,
    size_t params_size, const uint8_t *bits, size_t bits_size, uint8_t unused_bits)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return storeSignature(builder->ctx, &builder->signature, oid, params, params_size,
                          bits, bits_size, unused_bits);
}

extern "C" ASNBER_OCSP_API asnber_err_t
asnber_ocsp_basic_builder_add_signature_cert(asnber_ocsp_basic_builder_t *builder,
                                             const uint8_t *cert_der,
                                             size_t cert_size)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return addCert(builder->ctx, &builder->signature, cert_der, cert_size);
}

extern "C" ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_builder_encode(
    const asnber_ocsp_basic_builder_t *builder, asnber_buf_t *out_buf)
{
    if (builder == nullptr || out_buf == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    resetBuffer(out_buf);
    if (!builder->responder_set || !builder->produced_set ||
        builder->response_count == 0 || !builder->signature.set) {
        return ASNBER_E_INVALID_STATE;
    }
    asnber_doc_t *doc = nullptr;
    asnber_err_t rc = buildBasic(*builder, &doc);
    if (rc != ASNBER_OK) {
        return rc;
    }
    return finishEncode(builder->ctx, doc, kOcspRootBasic, out_buf);
}
