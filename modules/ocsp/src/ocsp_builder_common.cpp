/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/* 三个 OCSP builder 共用的存储释放、校验和构树。 */

#include "ocsp_builder_internal.h"

namespace asnber_ocsp_detail {

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

} // namespace asnber_ocsp_detail
