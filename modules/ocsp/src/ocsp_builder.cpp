/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * OCSP 三个根的结构 builder。不签名、不验签、不判断证书状态。
 * 根类型编号与只读侧相同：请求 14，响应 17，基本响应 24。
 */

#include <asnber/ocsp/ocsp_builder.h>

#include "ocsp_tables.h"

#include "detail/module_builder_support.h"
#include "detail/x509_primitives.h"

#include <cstring>

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

namespace {

constexpr uint32_t kTagEnumerated = 10;
constexpr int kStatusGood = 0;
constexpr int kStatusRevoked = 1;
constexpr int kStatusUnknown = 2;

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

void freeExtensions(extension_store *extensions, size_t count)
{
    if (extensions == nullptr) {
        return;
    }
    for (size_t i = 0; i < count; ++i) {
        std::free(extensions[i].oid);
        std::free(extensions[i].value);
    }
    std::free(extensions);
}

void freeCertId(cert_id_store *cert_id)
{
    if (cert_id == nullptr) {
        return;
    }
    std::free(cert_id->hash_oid);
    std::free(cert_id->hash_params.data);
    std::free(cert_id->name_hash.data);
    std::free(cert_id->key_hash.data);
    std::free(cert_id->serial.data);
    std::memset(cert_id, 0, sizeof(*cert_id));
}

void freeSignature(signature_store *signature)
{
    if (signature == nullptr) {
        return;
    }
    std::free(signature->oid);
    std::free(signature->params.data);
    std::free(signature->bits.data);
    freeSpans(signature->certs, signature->cert_count);
    std::memset(signature, 0, sizeof(*signature));
}

void resetBuffer(asnber_buf_t *buf)
{
    buf->data = nullptr;
    buf->size = 0;
    buf->capacity = 0;
}

bool responseStatusOk(int64_t status)
{
    return status == 0 || status == 1 || status == 2 || status == 3 ||
           status == 5 || status == 6;
}

bool crlReasonOk(int64_t reason)
{
    switch (reason) {
    case 0:
    case 1:
    case 2:
    case 3:
    case 4:
    case 5:
    case 6:
    case 8:
    case 9:
    case 10:
        return true;
    default:
        return false;
    }
}

bool hasExtension(const extension_store *extensions, size_t count, const char *oid)
{
    for (size_t i = 0; i < count; ++i) {
        if (std::strcmp(extensions[i].oid, oid) == 0) {
            return true;
        }
    }
    return false;
}

asnber_err_t copySpan(byte_span *out, const uint8_t *data, size_t size)
{
    out->data = nullptr;
    out->size = 0;
    if (size == 0) {
        return ASNBER_OK;
    }
    uint8_t *copy = copyBytes(data, size);
    if (copy == nullptr) {
        return ASNBER_E_NOMEM;
    }
    out->data = copy;
    out->size = size;
    return ASNBER_OK;
}

asnber_err_t checkTlv(asnber_ctx_t *ctx, const uint8_t *tlv, size_t size)
{
    if (tlv == nullptr || size == 0) {
        return ASNBER_E_INVALID_ARG;
    }
    return validateSingleDer(ctx, tlv, size, nullptr);
}

asnber_err_t checkExtension(asnber_ctx_t *ctx, const char *oid, const uint8_t *value,
                            size_t value_size)
{
    if (oid == nullptr || value == nullptr || value_size == 0) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber_err_t rc = validateOid(ctx, oid);
    if (rc != ASNBER_OK) {
        return rc;
    }
    return checkTlv(ctx, value, value_size);
}

asnber_err_t appendExtension(extension_store **extensions, size_t *count,
                             size_t *capacity, const char *oid, bool critical,
                             const uint8_t *value, size_t value_size)
{
    if (!ensureCapacity(extensions, *count, capacity)) {
        return ASNBER_E_NOMEM;
    }
    extension_store &slot = (*extensions)[*count];
    std::memset(&slot, 0, sizeof(slot));
    slot.oid = copyText(oid);
    slot.value = copyBytes(value, value_size);
    if (slot.oid == nullptr || slot.value == nullptr) {
        std::free(slot.oid);
        std::free(slot.value);
        std::memset(&slot, 0, sizeof(slot));
        return ASNBER_E_NOMEM;
    }
    slot.critical = critical;
    slot.value_size = value_size;
    ++*count;
    return ASNBER_OK;
}

asnber_err_t storeOptionalParams(asnber_ctx_t *ctx, byte_span *out,
                                 const uint8_t *params, size_t params_size)
{
    if (params_size == 0) {
        out->data = nullptr;
        out->size = 0;
        return ASNBER_OK;
    }
    if (params == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber_err_t rc = checkTlv(ctx, params, params_size);
    if (rc != ASNBER_OK) {
        return rc;
    }
    return copySpan(out, params, params_size);
}

asnber_err_t storeCertId(asnber_ctx_t *ctx, cert_id_store *out, const char *hash_oid,
                         const uint8_t *hash_params, size_t hash_params_size,
                         const uint8_t *name_hash, size_t name_hash_size,
                         const uint8_t *key_hash, size_t key_hash_size,
                         const uint8_t *serial, size_t serial_size)
{
    std::memset(out, 0, sizeof(*out));
    if (hash_oid == nullptr || name_hash == nullptr || name_hash_size == 0 ||
        key_hash == nullptr || key_hash_size == 0 || serial == nullptr ||
        serial_size == 0) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber_err_t rc = validateOid(ctx, hash_oid);
    if (rc != ASNBER_OK) {
        return rc;
    }
    rc = storeOptionalParams(ctx, &out->hash_params, hash_params, hash_params_size);
    if (rc != ASNBER_OK) {
        return rc;
    }
    out->hash_oid = copyText(hash_oid);
    rc = out->hash_oid == nullptr ? ASNBER_E_NOMEM : ASNBER_OK;
    if (rc == ASNBER_OK) {
        rc = copySpan(&out->name_hash, name_hash, name_hash_size);
    }
    if (rc == ASNBER_OK) {
        rc = copySpan(&out->key_hash, key_hash, key_hash_size);
    }
    if (rc == ASNBER_OK) {
        rc = copySpan(&out->serial, serial, serial_size);
    }
    if (rc != ASNBER_OK) {
        freeCertId(out);
    }
    return rc;
}

asnber_err_t storeSignature(asnber_ctx_t *ctx, signature_store *out, const char *oid,
                            const uint8_t *params, size_t params_size,
                            const uint8_t *bits, size_t bits_size,
                            uint8_t unused_bits)
{
    if (out->set) {
        return ASNBER_E_INVALID_STATE;
    }
    if (oid == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber_err_t rc = validateOid(ctx, oid);
    if (rc != ASNBER_OK) {
        return rc;
    }
    rc = validateBitString(bits, bits_size, unused_bits);
    if (rc != ASNBER_OK) {
        return rc;
    }
    signature_store stored;
    std::memset(&stored, 0, sizeof(stored));
    rc = storeOptionalParams(ctx, &stored.params, params, params_size);
    if (rc != ASNBER_OK) {
        return rc;
    }
    stored.oid = copyText(oid);
    if (stored.oid == nullptr) {
        std::free(stored.params.data);
        return ASNBER_E_NOMEM;
    }
    rc = copySpan(&stored.bits, bits, bits_size);
    if (rc != ASNBER_OK) {
        std::free(stored.oid);
        std::free(stored.params.data);
        return rc;
    }
    stored.unused_bits = unused_bits;
    stored.set = true;
    *out = stored;
    return ASNBER_OK;
}

asnber_err_t addCert(asnber_ctx_t *ctx, signature_store *signature,
                     const uint8_t *cert_der, size_t cert_size)
{
    if (!signature->set) {
        return ASNBER_E_INVALID_STATE;
    }
    asnber_err_t rc = checkTlv(ctx, cert_der, cert_size);
    if (rc != ASNBER_OK) {
        return rc;
    }
    if (!appendSpan(&signature->certs, &signature->cert_count,
                    &signature->cert_capacity, cert_der, cert_size)) {
        return ASNBER_E_NOMEM;
    }
    return ASNBER_OK;
}

size_t derLengthSize(size_t length)
{
    if (length < 128) {
        return 1;
    }
    size_t count = 0;
    size_t value = length;
    while (value > 0) {
        ++count;
        value >>= 8;
    }
    return 1 + count;
}

void writeDerLength(uint8_t *dst, size_t length)
{
    if (length < 128) {
        dst[0] = static_cast<uint8_t>(length);
        return;
    }
    uint8_t bytes[sizeof(size_t)];
    size_t count = 0;
    size_t value = length;
    while (value > 0) {
        bytes[count++] = static_cast<uint8_t>(value & 0xFFu);
        value >>= 8;
    }
    dst[0] = static_cast<uint8_t>(0x80u | count);
    for (size_t i = 0; i < count; ++i) {
        dst[1 + i] = bytes[count - 1 - i];
    }
}

/* EXPLICIT ANY：节点标签是外层上下文标签，content 保存内层完整 TLV。 */
asnber_err_t createExplicitAny(asnber_doc_t *doc, asnber_node_t *parent,
                               uint32_t tag_number, const uint8_t *inner,
                               size_t inner_size, asnber_node_t **out_node)
{
    if (tag_number >= 31 || inner_size > SIZE_MAX - 1 - derLengthSize(inner_size)) {
        return ASNBER_E_INVALID_ARG;
    }
    const size_t length_size = derLengthSize(inner_size);
    const size_t total = 1 + length_size + inner_size;
    uint8_t *wrapper = static_cast<uint8_t *>(std::malloc(total));
    if (wrapper == nullptr) {
        return ASNBER_E_NOMEM;
    }
    wrapper[0] = static_cast<uint8_t>(0xA0u | tag_number);
    writeDerLength(wrapper + 1, inner_size);
    std::memcpy(wrapper + 1 + length_size, inner, inner_size);
    asnber_err_t rc =
        asnber_node_create_any(doc, parent, wrapper, total, out_node);
    std::free(wrapper);
    return rc;
}

asnber_err_t createGeneralizedTime(asnber_doc_t *doc, asnber_node_t *parent,
                                   const asnber_time_t *time,
                                   asnber_node_t **out_node)
{
    asnber_err_t rc = validateTime(time);
    if (rc != ASNBER_OK) {
        return rc;
    }
    uint8_t text[15];
    writeFourDigits(text, static_cast<uint32_t>(time->year));
    writeTwoDigits(text + 4, time->month);
    writeTwoDigits(text + 6, time->day);
    writeTwoDigits(text + 8, time->hour);
    writeTwoDigits(text + 10, time->minute);
    writeTwoDigits(text + 12, time->second);
    text[14] = 'Z';

    asnber_node_t *node = nullptr;
    rc = createNode(doc, parent, ASNBER_TAG_UNIVERSAL, kTagGeneralizedTime, 0,
                    &node);
    if (rc != ASNBER_OK) {
        return rc;
    }
    rc = asnber_node_set_content(node, text, sizeof(text));
    if (rc != ASNBER_OK) {
        return rc;
    }
    *out_node = node;
    return ASNBER_OK;
}

asnber_err_t createEnumerated(asnber_doc_t *doc, asnber_node_t *parent,
                              int64_t value, asnber_node_t **out_node)
{
    asnber_node_t *node = nullptr;
    asnber_err_t rc =
        createNode(doc, parent, ASNBER_TAG_UNIVERSAL, kTagEnumerated, 0, &node);
    if (rc != ASNBER_OK) {
        return rc;
    }
    rc = asnber_node_set_int64(node, value);
    if (rc != ASNBER_OK) {
        return rc;
    }
    *out_node = node;
    return ASNBER_OK;
}

asnber_err_t createNullStatus(asnber_doc_t *doc, asnber_node_t *parent,
                              uint32_t tag_number, asnber_node_t **out_node)
{
    asnber_node_t *node = nullptr;
    asnber_err_t rc =
        createNode(doc, parent, ASNBER_TAG_CONTEXT, tag_number, 0, &node);
    if (rc != ASNBER_OK) {
        return rc;
    }
    rc = asnber_node_set_content(node, nullptr, 0);
    if (rc != ASNBER_OK) {
        return rc;
    }
    *out_node = node;
    return ASNBER_OK;
}

asnber_err_t addWrappedExtensions(asnber_doc_t *doc, asnber_node_t *parent,
                                  uint32_t tag_number,
                                  const extension_store *extensions, size_t count)
{
    if (count == 0) {
        return ASNBER_OK;
    }
    extension_entry *views = static_cast<extension_entry *>(
        std::calloc(count, sizeof(extension_entry)));
    if (views == nullptr) {
        return ASNBER_E_NOMEM;
    }
    for (size_t i = 0; i < count; ++i) {
        views[i].oid = extensions[i].oid;
        views[i].critical = extensions[i].critical;
        views[i].value = extensions[i].value;
        views[i].value_size = extensions[i].value_size;
    }
    asnber_node_t *wrapper = nullptr;
    asnber_err_t rc =
        createNode(doc, parent, ASNBER_TAG_CONTEXT, tag_number, 1, &wrapper);
    if (rc == ASNBER_OK) {
        asnber_node_t *ignored = nullptr;
        rc = createExtensionsNode(doc, wrapper, views, count, &ignored);
    }
    std::free(views);
    return rc;
}

asnber_err_t addCertId(asnber_doc_t *doc, asnber_node_t *parent,
                       const cert_id_store &cert_id)
{
    asnber_node_t *sequence = nullptr;
    asnber_err_t rc =
        createNode(doc, parent, ASNBER_TAG_UNIVERSAL, kTagSequence, 1, &sequence);
    if (rc != ASNBER_OK) {
        return rc;
    }
    rc = addAlgorithmIdentifier(doc, sequence, cert_id.hash_oid, cert_id.hash_params);
    asnber_node_t *ignored = nullptr;
    if (rc == ASNBER_OK) {
        rc = createOctetStringNode(doc, sequence, cert_id.name_hash.data,
                                   cert_id.name_hash.size, &ignored);
    }
    if (rc == ASNBER_OK) {
        rc = createOctetStringNode(doc, sequence, cert_id.key_hash.data,
                                   cert_id.key_hash.size, &ignored);
    }
    if (rc == ASNBER_OK) {
        rc = createBigIntegerNode(doc, sequence, cert_id.serial.data,
                                  cert_id.serial.size, &ignored);
    }
    return rc;
}

asnber_err_t addSignature(asnber_doc_t *doc, asnber_node_t *parent,
                          const signature_store &signature)
{
    asnber_err_t rc =
        addAlgorithmIdentifier(doc, parent, signature.oid, signature.params);
    asnber_node_t *ignored = nullptr;
    if (rc == ASNBER_OK) {
        rc = createBitStringNode(doc, parent, signature.bits.data, signature.bits.size,
                                 signature.unused_bits, &ignored);
    }
    if (rc == ASNBER_OK && signature.cert_count != 0) {
        asnber_node_t *wrapper = nullptr;
        rc = createNode(doc, parent, ASNBER_TAG_CONTEXT, 0, 1, &wrapper);
        asnber_node_t *certs = nullptr;
        if (rc == ASNBER_OK) {
            rc = createNode(doc, wrapper, ASNBER_TAG_UNIVERSAL, kTagSequence, 1,
                            &certs);
        }
        for (size_t i = 0; rc == ASNBER_OK && i < signature.cert_count; ++i) {
            rc = asnber_node_create_any(doc, certs, signature.certs[i].data,
                                        signature.certs[i].size, &ignored);
        }
    }
    return rc;
}

asnber_err_t setVersion(bool *version_set, int64_t *stored, int64_t version)
{
    if (*version_set) {
        return ASNBER_E_INVALID_STATE;
    }
    /* Version ::= INTEGER { v1(0) }，描述表只接受 0。 */
    if (version != 0) {
        return ASNBER_E_INVALID_VALUE;
    }
    *stored = version;
    *version_set = true;
    return ASNBER_OK;
}

asnber_err_t encodeWithRoot(asnber_ctx_t *ctx, const asnber_doc_t *doc,
                            uint32_t root_type_id, asnber_buf_t *out_buf)
{
    const ocsp_table_view table = ocspSchemaTable();
    asnber_schema_t *schema = nullptr;
    asnber_err_t rc =
        loadTable(ctx, table.data, table.size, root_type_id, &schema);
    if (rc != ASNBER_OK) {
        return rc;
    }
    asnber_encode_options_t options;
    asnber_encode_options_init(&options);
    options.schema = schema;
    rc = asnber_encode_buffer(ctx, doc, &options, out_buf);
    asnber_schema_destroy(schema);
    if (rc != ASNBER_OK) {
        resetBuffer(out_buf);
    }
    return rc;
}

asnber_err_t finishEncode(asnber_ctx_t *ctx, asnber_doc_t *doc, uint32_t root,
                          asnber_buf_t *out_buf)
{
    asnber_err_t rc = asnber_doc_seal(doc);
    if (rc == ASNBER_OK) {
        rc = encodeWithRoot(ctx, doc, root, out_buf);
    }
    asnber_doc_destroy(doc);
    return rc;
}

} // namespace

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

namespace {

void freeRequests(request_item *items, size_t count)
{
    if (items == nullptr) {
        return;
    }
    for (size_t i = 0; i < count; ++i) {
        freeCertId(&items[i].cert_id);
        freeExtensions(items[i].extensions, items[i].extension_count);
    }
    std::free(items);
}

void freeSingles(single_item *items, size_t count)
{
    if (items == nullptr) {
        return;
    }
    for (size_t i = 0; i < count; ++i) {
        freeCertId(&items[i].cert_id);
        freeExtensions(items[i].extensions, items[i].extension_count);
    }
    std::free(items);
}

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

} // namespace

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
