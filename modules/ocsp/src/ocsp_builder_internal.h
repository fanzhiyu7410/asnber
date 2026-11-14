/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-ocsp 构造侧内部共享定义（模块私有）。
 *
 * 只允许 modules/ocsp 构造侧的 cpp 包含。不安装，也不进入公共头。
 */

#ifndef ASNBER_OCSP_BUILDER_INTERNAL_H_INCLUDED
#define ASNBER_OCSP_BUILDER_INTERNAL_H_INCLUDED

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include <asnber/ocsp/ocsp_builder.h>

#include "detail/module_builder_support.h"
#include "detail/x509_primitives.h"

#include "ocsp_tables.h"

using asnber::module_detail::addAlgorithmIdentifier;
using asnber::module_detail::appendSpan;
using asnber::module_detail::byte_span;
using asnber::module_detail::copyBytes;
using asnber::module_detail::copyText;
using asnber::module_detail::createBigIntegerNode;
using asnber::module_detail::createBitStringNode;
using asnber::module_detail::createExtensionsNode;
using asnber::module_detail::createIntegerNode;
using asnber::module_detail::createNode;
using asnber::module_detail::createOctetStringNode;
using asnber::module_detail::createOidNode;
using asnber::module_detail::ensureCapacity;
using asnber::module_detail::extension_entry;
using asnber::module_detail::freeSpans;
using asnber::module_detail::kTagGeneralizedTime;
using asnber::module_detail::kTagSequence;
using asnber::module_detail::loadTable;
using asnber::module_detail::validateBitString;
using asnber::module_detail::validateOid;
using asnber::module_detail::validateSingleDer;
using asnber::module_detail::validateTime;
using asnber::module_detail::writeFourDigits;
using asnber::module_detail::writeTwoDigits;

struct extension_store {
    char *oid;
    bool critical;
    uint8_t *value;
    size_t value_size;
};

struct cert_id_store {
    char *hash_oid;
    byte_span hash_params;
    byte_span name_hash;
    byte_span key_hash;
    byte_span serial;
};

struct request_item {
    cert_id_store cert_id;
    extension_store *extensions;
    size_t extension_count;
    size_t extension_capacity;
};

struct single_item {
    cert_id_store cert_id;
    int status;
    asnber_time_t this_update;
    bool next_set;
    asnber_time_t next_update;
    bool reason_set;
    int64_t reason;
    asnber_time_t revocation_time;
    extension_store *extensions;
    size_t extension_count;
    size_t extension_capacity;
};

struct signature_store {
    bool set;
    char *oid;
    byte_span params;
    byte_span bits;
    uint8_t unused_bits;
    byte_span *certs;
    size_t cert_count;
    size_t cert_capacity;
};

struct asnber_ocsp_request_builder {
    asnber_ctx_t *ctx;
    bool version_set;
    int64_t version;
    bool requestor_set;
    byte_span requestor;
    request_item *requests;
    size_t request_count;
    size_t request_capacity;
    extension_store *extensions;
    size_t extension_count;
    size_t extension_capacity;
    signature_store signature;
};

struct asnber_ocsp_response_builder {
    asnber_ctx_t *ctx;
    bool status_set;
    int64_t status;
    bool bytes_set;
    char *type_oid;
    byte_span response;
};

struct asnber_ocsp_basic_builder {
    asnber_ctx_t *ctx;
    bool version_set;
    int64_t version;
    bool responder_set;
    bool responder_by_name;
    byte_span responder;
    bool produced_set;
    asnber_time_t produced_at;
    single_item *responses;
    size_t response_count;
    size_t response_capacity;
    extension_store *extensions;
    size_t extension_count;
    size_t extension_capacity;
    signature_store signature;
};

namespace asnber_ocsp_detail {

constexpr uint32_t kTagEnumerated = 10;
constexpr int kStatusGood = 0;
constexpr int kStatusRevoked = 1;
constexpr int kStatusUnknown = 2;

void freeExtensions(extension_store *extensions, size_t count);
void freeCertId(cert_id_store *cert_id);
void freeSignature(signature_store *signature);
void resetBuffer(asnber_buf_t *buf);
bool responseStatusOk(int64_t status);
bool crlReasonOk(int64_t reason);
bool hasExtension(const extension_store *extensions, size_t count, const char *oid);
asnber_err_t copySpan(byte_span *out, const uint8_t *data, size_t size);
asnber_err_t checkTlv(asnber_ctx_t *ctx, const uint8_t *tlv, size_t size);
asnber_err_t checkExtension(asnber_ctx_t *ctx, const char *oid, const uint8_t *value,
                            size_t value_size);
asnber_err_t appendExtension(extension_store **extensions, size_t *count,
                             size_t *capacity, const char *oid, bool critical,
                             const uint8_t *value, size_t value_size);
asnber_err_t storeCertId(asnber_ctx_t *ctx, cert_id_store *out, const char *hash_oid,
                         const uint8_t *hash_params, size_t hash_params_size,
                         const uint8_t *name_hash, size_t name_hash_size,
                         const uint8_t *key_hash, size_t key_hash_size,
                         const uint8_t *serial, size_t serial_size);
asnber_err_t storeSignature(asnber_ctx_t *ctx, signature_store *out, const char *oid,
                            const uint8_t *params, size_t params_size,
                            const uint8_t *bits, size_t bits_size,
                            uint8_t unused_bits);
asnber_err_t addCert(asnber_ctx_t *ctx, signature_store *signature,
                     const uint8_t *cert_der, size_t cert_size);
asnber_err_t createExplicitAny(asnber_doc_t *doc, asnber_node_t *parent,
                               uint32_t tag_number, const uint8_t *inner,
                               size_t inner_size, asnber_node_t **out_node);
asnber_err_t createGeneralizedTime(asnber_doc_t *doc, asnber_node_t *parent,
                                   const asnber_time_t *time,
                                   asnber_node_t **out_node);
asnber_err_t createEnumerated(asnber_doc_t *doc, asnber_node_t *parent,
                              int64_t value, asnber_node_t **out_node);
asnber_err_t createNullStatus(asnber_doc_t *doc, asnber_node_t *parent,
                              uint32_t tag_number, asnber_node_t **out_node);
asnber_err_t addWrappedExtensions(asnber_doc_t *doc, asnber_node_t *parent,
                                  uint32_t tag_number,
                                  const extension_store *extensions, size_t count);
asnber_err_t addCertId(asnber_doc_t *doc, asnber_node_t *parent,
                       const cert_id_store &cert_id);
asnber_err_t addSignature(asnber_doc_t *doc, asnber_node_t *parent,
                          const signature_store &signature);
asnber_err_t setVersion(bool *version_set, int64_t *stored, int64_t version);
asnber_err_t finishEncode(asnber_ctx_t *ctx, asnber_doc_t *doc, uint32_t root,
                          asnber_buf_t *out_buf);
void freeRequests(request_item *items, size_t count);
void freeSingles(single_item *items, size_t count);

} // namespace asnber_ocsp_detail

#endif /* ASNBER_OCSP_BUILDER_INTERNAL_H_INCLUDED */
