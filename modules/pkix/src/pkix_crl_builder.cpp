/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * CertificateList builder。只组装字段，不签名、不判断吊销。
 * 根类型编号与只读侧相同：完整表里的 CertificateList = 28。
 */

#include "detail/x509_primitives.h"
#include "pkix_builder_internal.h"
#include "pkix_schema.h"

#include <cstdlib>
#include <cstring>

using asnber::module_detail::addAlgorithmIdentifier;
using asnber::module_detail::byte_span;
using asnber::module_detail::copyBytes;
using asnber::module_detail::copyText;
using asnber::module_detail::createBigIntegerNode;
using asnber::module_detail::createBitStringNode;
using asnber::module_detail::createExtensionsNode;
using asnber::module_detail::createIntegerNode;
using asnber::module_detail::createNameNode;
using asnber::module_detail::createNode;
using asnber::module_detail::createTimeNode;
using asnber::module_detail::ensureCapacity;
using asnber::module_detail::extension_entry;
using asnber::module_detail::kTagIa5String;
using asnber::module_detail::kTagPrintableString;
using asnber::module_detail::kTagSequence;
using asnber::module_detail::kTagUtf8String;
using asnber::module_detail::loadTable;
using asnber::module_detail::nameStringValid;
using asnber::module_detail::name_attribute;
using asnber::module_detail::name_rdn;
using asnber::module_detail::selectNameStringTag;
using asnber::module_detail::validateBitString;
using asnber::module_detail::validateOid;
using asnber::module_detail::validateSingleDer;
using asnber::module_detail::validateTime;

namespace {

constexpr uint32_t kPkixRootCertificateList = 28;

void freeName(name_store *store)
{
    if (store == nullptr) {
        return;
    }
    for (size_t i = 0; i < store->attribute_count; ++i) {
        std::free(store->attributes[i].oid);
        std::free(store->attributes[i].value);
    }
    std::free(store->attributes);
    std::free(store->rdns);
    std::free(store->views);
    std::memset(store, 0, sizeof(*store));
}

void resetBuffer(asnber_buf_t *buf)
{
    buf->data = nullptr;
    buf->size = 0;
    buf->capacity = 0;
}

asnber_err_t copyName(asnber_ctx_t *ctx, name_store *out,
                    const asnber_pkix_name_rdn_t *rdns, size_t rdn_count)
{
    size_t total = 0;
    for (size_t i = 0; i < rdn_count; ++i) {
        if (rdns[i].attributes == nullptr || rdns[i].count == 0 ||
            rdns[i].count > SIZE_MAX - total) {
            return ASNBER_E_INVALID_ARG;
        }
        for (size_t j = 0; j < rdns[i].count; ++j) {
            const asnber_pkix_name_attribute_t &attribute = rdns[i].attributes[j];
            if (attribute.oid == nullptr ||
                (attribute.value == nullptr && attribute.value_size != 0)) {
                return ASNBER_E_INVALID_ARG;
            }
            asnber_err_t rc = validateOid(ctx, attribute.oid);
            if (rc != ASNBER_OK) {
                return rc;
            }
            const uint32_t tag = attribute.string_tag == 0
                                     ? selectNameStringTag(attribute.oid)
                                     : attribute.string_tag;
            if (tag != kTagUtf8String && tag != kTagPrintableString &&
                tag != kTagIa5String) {
                return ASNBER_E_INVALID_ARG;
            }
            if (!nameStringValid(tag, attribute.value, attribute.value_size)) {
                return ASNBER_E_INVALID_VALUE;
            }
        }
        total += rdns[i].count;
    }

    name_store store;
    std::memset(&store, 0, sizeof(store));
    if (total != 0) {
        store.attributes = static_cast<name_attribute_store *>(
            std::calloc(total, sizeof(name_attribute_store)));
        store.views = static_cast<name_attribute *>(
            std::calloc(total, sizeof(name_attribute)));
        if (store.attributes == nullptr || store.views == nullptr) {
            freeName(&store);
            return ASNBER_E_NOMEM;
        }
    }
    if (rdn_count != 0) {
        store.rdns =
            static_cast<name_rdn *>(std::calloc(rdn_count, sizeof(name_rdn)));
        if (store.rdns == nullptr) {
            freeName(&store);
            return ASNBER_E_NOMEM;
        }
    }

    size_t filled = 0;
    for (size_t i = 0; i < rdn_count; ++i) {
        store.rdns[i].attributes = &store.views[filled];
        store.rdns[i].count = rdns[i].count;
        for (size_t j = 0; j < rdns[i].count; ++j, ++filled) {
            const asnber_pkix_name_attribute_t &source = rdns[i].attributes[j];
            store.attributes[filled].oid = copyText(source.oid);
            store.attributes[filled].value =
                copyBytes(source.value, source.value_size);
            if (store.attributes[filled].oid == nullptr ||
                (source.value_size != 0 && store.attributes[filled].value == nullptr)) {
                store.attribute_count = filled + 1;
                freeName(&store);
                return ASNBER_E_NOMEM;
            }
            store.attributes[filled].value_size = source.value_size;
            store.attributes[filled].string_tag =
                source.string_tag == 0 ? selectNameStringTag(source.oid)
                                       : source.string_tag;
            store.views[filled].oid = store.attributes[filled].oid;
            store.views[filled].value = store.attributes[filled].value;
            store.views[filled].value_size = store.attributes[filled].value_size;
            store.views[filled].string_tag = store.attributes[filled].string_tag;
        }
    }
    store.attribute_count = total;
    store.rdn_count = rdn_count;
    *out = store;
    return ASNBER_OK;
}

struct ext_store {
    char *oid;
    bool critical;
    byte_span value;
};

struct revoked_entry {
    byte_span serial;
    asnber_time_t when;
    ext_store *extensions;
    size_t extension_count;
    size_t extension_capacity;
};

void freeExtensions(ext_store *extensions, size_t count)
{
    if (extensions == nullptr) {
        return;
    }
    for (size_t i = 0; i < count; ++i) {
        std::free(extensions[i].oid);
        std::free(extensions[i].value.data);
    }
    std::free(extensions);
}

bool hasExtension(const ext_store *extensions, size_t count, const char *oid)
{
    for (size_t i = 0; i < count; ++i) {
        if (std::strcmp(extensions[i].oid, oid) == 0) {
            return true;
        }
    }
    return false;
}

asnber_err_t appendExtension(ext_store **extensions, size_t *count,
                           size_t *capacity, const char *oid, bool critical,
                           const uint8_t *value, size_t value_size)
{
    if (!ensureCapacity(extensions, *count, capacity)) {
        return ASNBER_E_NOMEM;
    }
    char *oid_copy = copyText(oid);
    uint8_t *value_copy = copyBytes(value, value_size);
    if (oid_copy == nullptr || value_copy == nullptr) {
        std::free(oid_copy);
        std::free(value_copy);
        return ASNBER_E_NOMEM;
    }
    ext_store &entry = (*extensions)[*count];
    entry.oid = oid_copy;
    entry.critical = critical;
    entry.value.data = value_copy;
    entry.value.size = value_size;
    ++*count;
    return ASNBER_OK;
}

asnber_err_t writeExtensions(asnber_doc_t *doc, asnber_node_t *parent,
                           const ext_store *extensions, size_t count)
{
    extension_entry *views = static_cast<extension_entry *>(
        std::calloc(count, sizeof(extension_entry)));
    if (views == nullptr) {
        return ASNBER_E_NOMEM;
    }
    for (size_t i = 0; i < count; ++i) {
        views[i].oid = extensions[i].oid;
        views[i].critical = extensions[i].critical;
        views[i].value = extensions[i].value.data;
        views[i].value_size = extensions[i].value.size;
    }
    asnber_node_t *ignored = nullptr;
    asnber_err_t rc = createExtensionsNode(doc, parent, views, count, &ignored);
    std::free(views);
    return rc;
}

} /* namespace */

struct asnber_pkix_crl_builder {
    asnber_ctx_t *ctx;
    bool version_set;
    int64_t version;
    bool signature_algorithm_set;
    char *signature_algorithm_oid;
    byte_span signature_algorithm_params;
    bool issuer_set;
    name_store issuer;
    bool this_update_set;
    asnber_time_t this_update;
    bool next_update_set;
    asnber_time_t next_update;
    revoked_entry *revoked;
    size_t revoked_count;
    size_t revoked_capacity;
    bool signature_value_set;
    byte_span signature_value;
    uint8_t signature_value_unused_bits;
    ext_store *extensions;
    size_t extension_count;
    size_t extension_capacity;
};

namespace {

asnber_err_t buildCrl(const asnber_pkix_crl_builder_t &builder,
                    asnber_doc_t **out_doc)
{
    asnber_doc_t *doc = nullptr;
    asnber_err_t rc = asnber_doc_create(builder.ctx, &doc);
    if (rc != ASNBER_OK) {
        return rc;
    }

    asnber_node_t *root = nullptr;
    asnber_node_t *tbs = nullptr;
    asnber_node_t *ignored = nullptr;
    rc = createNode(doc, nullptr, ASNBER_TAG_UNIVERSAL, kTagSequence, 1, &root);
    if (rc == ASNBER_OK) {
        rc = createNode(doc, root, ASNBER_TAG_UNIVERSAL, kTagSequence, 1, &tbs);
    }
    if (rc == ASNBER_OK && builder.version != 0) {
        rc = createIntegerNode(doc, tbs, builder.version, &ignored);
    }
    if (rc == ASNBER_OK) {
        rc = addAlgorithmIdentifier(doc, tbs, builder.signature_algorithm_oid,
                                    builder.signature_algorithm_params);
    }
    if (rc == ASNBER_OK) {
        rc = createNameNode(doc, tbs, builder.issuer.rdns, builder.issuer.rdn_count,
                            &ignored);
    }
    if (rc == ASNBER_OK) {
        rc = createTimeNode(doc, tbs, &builder.this_update, &ignored);
    }
    if (rc == ASNBER_OK && builder.next_update_set) {
        rc = createTimeNode(doc, tbs, &builder.next_update, &ignored);
    }
    if (rc == ASNBER_OK && builder.revoked_count != 0) {
        asnber_node_t *list = nullptr;
        rc = createNode(doc, tbs, ASNBER_TAG_UNIVERSAL, kTagSequence, 1, &list);
        for (size_t i = 0; rc == ASNBER_OK && i < builder.revoked_count; ++i) {
            asnber_node_t *entry = nullptr;
            rc = createNode(doc, list, ASNBER_TAG_UNIVERSAL, kTagSequence, 1,
                            &entry);
            if (rc == ASNBER_OK) {
                rc = createBigIntegerNode(doc, entry, builder.revoked[i].serial.data,
                                          builder.revoked[i].serial.size, &ignored);
            }
            if (rc == ASNBER_OK) {
                rc = createTimeNode(doc, entry, &builder.revoked[i].when, &ignored);
            }
            if (rc == ASNBER_OK && builder.revoked[i].extension_count != 0) {
                rc = writeExtensions(doc, entry, builder.revoked[i].extensions,
                                     builder.revoked[i].extension_count);
            }
        }
    }
    if (rc == ASNBER_OK && builder.extension_count != 0) {
        asnber_node_t *wrapped = nullptr;
        rc = createNode(doc, tbs, ASNBER_TAG_CONTEXT, 0, 1, &wrapped);
        if (rc == ASNBER_OK) {
            rc = writeExtensions(doc, wrapped, builder.extensions,
                                 builder.extension_count);
        }
    }
    if (rc == ASNBER_OK) {
        rc = addAlgorithmIdentifier(doc, root, builder.signature_algorithm_oid,
                                    builder.signature_algorithm_params);
    }
    if (rc == ASNBER_OK) {
        rc = createBitStringNode(doc, root, builder.signature_value.data,
                                 builder.signature_value.size,
                                 builder.signature_value_unused_bits, &ignored);
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

asnber_err_t encodeCrl(const asnber_pkix_crl_builder_t &builder,
                     const asnber_doc_t *doc, asnber_buf_t *out_buf)
{
    asnber_schema_t *schema = nullptr;
    asnber_err_t rc = loadTable(builder.ctx, kPKIXFlattened2009Schema,
                              kPKIXFlattened2009Schema_size,
                              kPkixRootCertificateList, &schema);
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

} /* namespace */

extern "C" ASNBER_PKIX_API asnber_err_t asnber_pkix_crl_builder_create(
    asnber_ctx_t *ctx, asnber_pkix_crl_builder_t **out_builder)
{
    if (ctx == nullptr || out_builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_builder = nullptr;
    auto *builder = static_cast<asnber_pkix_crl_builder_t *>(
        std::malloc(sizeof(asnber_pkix_crl_builder_t)));
    if (builder == nullptr) {
        return ASNBER_E_NOMEM;
    }
    std::memset(builder, 0, sizeof(*builder));
    builder->ctx = ctx;
    *out_builder = builder;
    return ASNBER_OK;
}

extern "C" ASNBER_PKIX_API void asnber_pkix_crl_builder_destroy(
    asnber_pkix_crl_builder_t *builder)
{
    if (builder == nullptr) {
        return;
    }
    std::free(builder->signature_algorithm_oid);
    std::free(builder->signature_algorithm_params.data);
    freeName(&builder->issuer);
    for (size_t i = 0; i < builder->revoked_count; ++i) {
        std::free(builder->revoked[i].serial.data);
        freeExtensions(builder->revoked[i].extensions,
                       builder->revoked[i].extension_count);
    }
    std::free(builder->revoked);
    freeExtensions(builder->extensions, builder->extension_count);
    std::free(builder->signature_value.data);
    std::memset(builder, 0, sizeof(*builder));
    std::free(builder);
}

extern "C" ASNBER_PKIX_API asnber_err_t asnber_pkix_crl_builder_set_version(
    asnber_pkix_crl_builder_t *builder, int64_t version)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->version_set) {
        return ASNBER_E_INVALID_STATE;
    }
    if (version != 0 && version != 1) {
        return ASNBER_E_INVALID_VALUE;
    }
    builder->version = version;
    builder->version_set = true;
    return ASNBER_OK;
}

extern "C" ASNBER_PKIX_API asnber_err_t
asnber_pkix_crl_builder_set_signature_algorithm(
    asnber_pkix_crl_builder_t *builder, const char *oid,
    const uint8_t *parameters_tlv, size_t parameters_size)
{
    if (builder == nullptr || oid == nullptr ||
        (parameters_tlv == nullptr && parameters_size != 0)) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->signature_algorithm_set) {
        return ASNBER_E_INVALID_STATE;
    }
    asnber_err_t rc = validateOid(builder->ctx, oid);
    if (rc != ASNBER_OK) {
        return rc;
    }
    if (parameters_size != 0) {
        rc = validateSingleDer(builder->ctx, parameters_tlv, parameters_size,
                               nullptr);
        if (rc != ASNBER_OK) {
            return rc;
        }
    }
    char *oid_copy = copyText(oid);
    uint8_t *params_copy = copyBytes(parameters_tlv, parameters_size);
    if (oid_copy == nullptr || (parameters_size != 0 && params_copy == nullptr)) {
        std::free(oid_copy);
        std::free(params_copy);
        return ASNBER_E_NOMEM;
    }
    builder->signature_algorithm_oid = oid_copy;
    builder->signature_algorithm_params.data = params_copy;
    builder->signature_algorithm_params.size = parameters_size;
    builder->signature_algorithm_set = true;
    return ASNBER_OK;
}

extern "C" ASNBER_PKIX_API asnber_err_t asnber_pkix_crl_builder_set_issuer(
    asnber_pkix_crl_builder_t *builder, const asnber_pkix_name_rdn_t *rdns,
    size_t rdn_count)
{
    if (builder == nullptr || (rdns == nullptr && rdn_count != 0)) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->issuer_set) {
        return ASNBER_E_INVALID_STATE;
    }
    name_store store;
    std::memset(&store, 0, sizeof(store));
    asnber_err_t rc = copyName(builder->ctx, &store, rdns, rdn_count);
    if (rc != ASNBER_OK) {
        return rc;
    }
    builder->issuer = store;
    builder->issuer_set = true;
    return ASNBER_OK;
}

extern "C" ASNBER_PKIX_API asnber_err_t asnber_pkix_crl_builder_set_this_update(
    asnber_pkix_crl_builder_t *builder, const asnber_time_t *time)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->this_update_set) {
        return ASNBER_E_INVALID_STATE;
    }
    asnber_err_t rc = validateTime(time);
    if (rc != ASNBER_OK) {
        return rc;
    }
    builder->this_update = *time;
    builder->this_update_set = true;
    return ASNBER_OK;
}

extern "C" ASNBER_PKIX_API asnber_err_t asnber_pkix_crl_builder_set_next_update(
    asnber_pkix_crl_builder_t *builder, const asnber_time_t *time)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->next_update_set) {
        return ASNBER_E_INVALID_STATE;
    }
    asnber_err_t rc = validateTime(time);
    if (rc != ASNBER_OK) {
        return rc;
    }
    builder->next_update = *time;
    builder->next_update_set = true;
    return ASNBER_OK;
}

extern "C" ASNBER_PKIX_API asnber_err_t asnber_pkix_crl_builder_add_revoked(
    asnber_pkix_crl_builder_t *builder, const uint8_t *serial, size_t serial_size,
    const asnber_time_t *revocation_date)
{
    if (builder == nullptr || serial == nullptr || serial_size == 0) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber_err_t rc = validateTime(revocation_date);
    if (rc != ASNBER_OK) {
        return rc;
    }
    uint8_t *copy = copyBytes(serial, serial_size);
    if (copy == nullptr) {
        return ASNBER_E_NOMEM;
    }
    if (builder->revoked_count == builder->revoked_capacity) {
        if (builder->revoked_capacity > SIZE_MAX / 2 / sizeof(revoked_entry)) {
            std::free(copy);
            return ASNBER_E_NOMEM;
        }
        const size_t capacity =
            builder->revoked_capacity == 0 ? 4 : builder->revoked_capacity * 2;
        auto *grown = static_cast<revoked_entry *>(
            std::realloc(builder->revoked, capacity * sizeof(revoked_entry)));
        if (grown == nullptr) {
            std::free(copy);
            return ASNBER_E_NOMEM;
        }
        builder->revoked = grown;
        builder->revoked_capacity = capacity;
    }
    revoked_entry &added = builder->revoked[builder->revoked_count];
    added.serial.data = copy;
    added.serial.size = serial_size;
    added.when = *revocation_date;
    added.extensions = nullptr;
    added.extension_count = 0;
    added.extension_capacity = 0;
    ++builder->revoked_count;
    return ASNBER_OK;
}

extern "C" ASNBER_PKIX_API asnber_err_t
asnber_pkix_crl_builder_set_signature_value(asnber_pkix_crl_builder_t *builder,
                                           const uint8_t *bits, size_t size,
                                           uint8_t unused_bits)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->signature_value_set) {
        return ASNBER_E_INVALID_STATE;
    }
    asnber_err_t rc = validateBitString(bits, size, unused_bits);
    if (rc != ASNBER_OK) {
        return rc;
    }
    uint8_t *copy = copyBytes(bits, size);
    if (size != 0 && copy == nullptr) {
        return ASNBER_E_NOMEM;
    }
    builder->signature_value.data = copy;
    builder->signature_value.size = size;
    builder->signature_value_unused_bits = unused_bits;
    builder->signature_value_set = true;
    return ASNBER_OK;
}

namespace {

asnber_err_t checkExtension(asnber_ctx_t *ctx, const char *oid,
                          const uint8_t *value, size_t value_size)
{
    if (oid == nullptr || value == nullptr || value_size == 0) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber_err_t rc = validateOid(ctx, oid);
    if (rc != ASNBER_OK) {
        return rc;
    }
    return validateSingleDer(ctx, value, value_size, nullptr);
}

} /* namespace */

extern "C" ASNBER_PKIX_API asnber_err_t asnber_pkix_crl_builder_add_extension(
    asnber_pkix_crl_builder_t *builder, const char *extn_oid, int critical,
    const uint8_t *extn_value_der, size_t extn_value_size)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber_err_t rc = checkExtension(builder->ctx, extn_oid, extn_value_der,
                                   extn_value_size);
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

extern "C" ASNBER_PKIX_API asnber_err_t
asnber_pkix_crl_builder_add_entry_extension(
    asnber_pkix_crl_builder_t *builder, size_t revoked_index, const char *extn_oid,
    int critical, const uint8_t *extn_value_der, size_t extn_value_size)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (revoked_index >= builder->revoked_count) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber_err_t rc = checkExtension(builder->ctx, extn_oid, extn_value_der,
                                   extn_value_size);
    if (rc != ASNBER_OK) {
        return rc;
    }
    revoked_entry &entry = builder->revoked[revoked_index];
    if (hasExtension(entry.extensions, entry.extension_count, extn_oid)) {
        return ASNBER_E_INVALID_VALUE;
    }
    return appendExtension(&entry.extensions, &entry.extension_count,
                           &entry.extension_capacity, extn_oid, critical != 0,
                           extn_value_der, extn_value_size);
}

extern "C" ASNBER_PKIX_API asnber_err_t asnber_pkix_crl_builder_encode(
    const asnber_pkix_crl_builder_t *builder, asnber_buf_t *out_buf)
{
    if (builder == nullptr || out_buf == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    resetBuffer(out_buf);
    if (!builder->signature_algorithm_set || !builder->issuer_set ||
        !builder->this_update_set || !builder->signature_value_set) {
        return ASNBER_E_INVALID_STATE;
    }
    bool has_extensions = builder->extension_count != 0;
    for (size_t i = 0; i < builder->revoked_count && !has_extensions; ++i) {
        has_extensions = builder->revoked[i].extension_count != 0;
    }
    if (has_extensions && builder->version != 1) {
        return ASNBER_E_INVALID_VALUE;
    }
    asnber_doc_t *doc = nullptr;
    asnber_err_t rc = buildCrl(*builder, &doc);
    if (rc != ASNBER_OK) {
        return rc;
    }
    rc = encodeCrl(*builder, doc, out_buf);
    asnber_doc_destroy(doc);
    return rc;
}
