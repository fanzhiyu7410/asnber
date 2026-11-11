/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-pkix Certificate builder：构树、扩展便捷函数与 schema 编码。
 *
 * 只做结构组装，不签名也不验签；扩展编码复用共享层的纯函数，不依赖
 * asnber-pkcs10。所有输入在 set/add 时深拷贝。
 */

#include <asnber/pkix/pkix.h>

#include "detail/module_builder_support.h"
#include "detail/x509_primitives.h"
#include "pkix_builder_internal.h"

/* 由 asnberc 生成；ASNBER_PKIX_REGENERATE_TABLE=ON 时来自构建目录。 */
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
using asnber::module_detail::createImplicitBitStringNode;
using asnber::module_detail::createIntegerNode;
using asnber::module_detail::createNameNode;
using asnber::module_detail::createNode;
using asnber::module_detail::createTimeNode;
using asnber::module_detail::kTagIa5String;
using asnber::module_detail::kTagPrintableString;
using asnber::module_detail::kTagSequence;
using asnber::module_detail::kTagUtf8String;
using asnber::module_detail::name_attribute;
using asnber::module_detail::name_rdn;
using asnber::module_detail::nameStringValid;
using asnber::module_detail::selectNameStringTag;
using asnber::module_detail::validateBitString;
using asnber::module_detail::validateOid;
using asnber::module_detail::validateSingleDer;
using asnber::module_detail::validateTime;

namespace {

constexpr uint32_t kPkixFormatVersion = 1u << 16;

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

} /* namespace */

namespace {

/* 校验 algorithm 输入：OID 合法，参数为可选单 DER TLV。 */
asnber_err_t checkAlgorithm(asnber_ctx_t *ctx, const char *oid,
                          const uint8_t *parameters, size_t parameters_size)
{
    if (ctx == nullptr || oid == nullptr ||
        (parameters == nullptr && parameters_size != 0)) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber_err_t rc = validateOid(ctx, oid);
    if (rc != ASNBER_OK) {
        return rc;
    }
    if (parameters_size != 0) {
        rc = validateSingleDer(ctx, parameters, parameters_size, nullptr);
    }
    return rc;
}

asnber_err_t copyAlgorithm(asnber_ctx_t *ctx, const char *oid,
                         const uint8_t *parameters, size_t parameters_size,
                         char **out_oid, byte_span *out_parameters)
{
    asnber_err_t rc = checkAlgorithm(ctx, oid, parameters, parameters_size);
    if (rc != ASNBER_OK) {
        return rc;
    }
    char *oid_copy = copyText(oid);
    uint8_t *params_copy = copyBytes(parameters, parameters_size);
    if (oid_copy == nullptr || (parameters_size != 0 && params_copy == nullptr)) {
        std::free(oid_copy);
        std::free(params_copy);
        return ASNBER_E_NOMEM;
    }
    *out_oid = oid_copy;
    out_parameters->data = params_copy;
    out_parameters->size = parameters_size;
    return ASNBER_OK;
}

/* 复制并校验 Name；失败时不留下部分状态。 */
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
        store.rdns = static_cast<name_rdn *>(
            std::calloc(rdn_count, sizeof(name_rdn)));
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
                store.attributes[filled].value == nullptr) {
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

asnber_err_t buildCertificate(const asnber_pkix_certificate_builder_t &builder,
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

    /* version DEFAULT v1：0 与未设置都省略 [0] EXPLICIT。 */
    if (rc == ASNBER_OK && builder.version != 0) {
        asnber_node_t *version = nullptr;
        rc = createNode(doc, tbs, ASNBER_TAG_CONTEXT, 0, 1, &version);
        if (rc == ASNBER_OK) {
            rc = createIntegerNode(doc, version, builder.version, &ignored);
        }
    }
    if (rc == ASNBER_OK) {
        rc = createBigIntegerNode(doc, tbs, builder.serial.data,
                                  builder.serial.size, &ignored);
    }
    if (rc == ASNBER_OK) {
        rc = addAlgorithmIdentifier(doc, tbs, builder.signature_algorithm_oid,
                                    builder.signature_algorithm_params);
    }
    if (rc == ASNBER_OK) {
        rc = createNameNode(doc, tbs, builder.issuer.rdns,
                            builder.issuer.rdn_count, &ignored);
    }

    asnber_node_t *validity = nullptr;
    if (rc == ASNBER_OK) {
        rc = createNode(doc, tbs, ASNBER_TAG_UNIVERSAL, kTagSequence, 1,
                        &validity);
    }
    if (rc == ASNBER_OK) {
        rc = createTimeNode(doc, validity, &builder.not_before, &ignored);
    }
    if (rc == ASNBER_OK) {
        rc = createTimeNode(doc, validity, &builder.not_after, &ignored);
    }
    if (rc == ASNBER_OK) {
        rc = createNameNode(doc, tbs, builder.subject.rdns,
                            builder.subject.rdn_count, &ignored);
    }

    asnber_node_t *public_key_info = nullptr;
    if (rc == ASNBER_OK) {
        rc = createNode(doc, tbs, ASNBER_TAG_UNIVERSAL, kTagSequence, 1,
                        &public_key_info);
    }
    if (rc == ASNBER_OK) {
        rc = addAlgorithmIdentifier(doc, public_key_info,
                                    builder.subject_public_key_algorithm_oid,
                                    builder.subject_public_key_algorithm_params);
    }
    if (rc == ASNBER_OK) {
        rc = createBitStringNode(doc, public_key_info,
                                 builder.subject_public_key.data,
                                 builder.subject_public_key.size,
                                 builder.subject_public_key_unused_bits,
                                 &ignored);
    }
    if (rc == ASNBER_OK && builder.issuer_unique_id_set) {
        rc = createImplicitBitStringNode(
            doc, tbs, 1, builder.issuer_unique_id.data,
            builder.issuer_unique_id.size, builder.issuer_unique_id_unused_bits,
            &ignored);
    }
    if (rc == ASNBER_OK && builder.subject_unique_id_set) {
        rc = createImplicitBitStringNode(
            doc, tbs, 2, builder.subject_unique_id.data,
            builder.subject_unique_id.size,
            builder.subject_unique_id_unused_bits, &ignored);
    }
    if (rc == ASNBER_OK && builder.extension_count != 0) {
        asnber_node_t *extensions = nullptr;
        rc = createNode(doc, tbs, ASNBER_TAG_CONTEXT, 3, 1, &extensions);
        if (rc == ASNBER_OK) {
            rc = createExtensionsNode(doc, extensions, builder.extensions,
                                      builder.extension_count, &ignored);
        }
    }

    if (rc == ASNBER_OK) {
        rc = addAlgorithmIdentifier(doc, root, builder.signature_algorithm_oid,
                                    builder.signature_algorithm_params);
    }
    if (rc == ASNBER_OK) {
        rc = createBitStringNode(doc, root, builder.signature_value.data,
                                 builder.signature_value.size,
                                 builder.signature_value_unused_bits,
                                 &ignored);
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

asnber_err_t encodeCertificate(const asnber_pkix_certificate_builder_t &builder,
                             const asnber_doc_t *doc, asnber_buf_t *out_buf)
{
    asnber_schema_table_t table;
    table.struct_size = sizeof(table);
    table.data = kPKIXFlattened2009Schema;
    table.size = kPKIXFlattened2009Schema_size;
    table.format_version = kPkixFormatVersion;
    table.reserved = 0;

    asnber_schema_t *schema = nullptr;
    asnber_err_t rc = asnber_schema_load(builder.ctx, &table, &schema);
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

extern "C" ASNBER_PKIX_API asnber_err_t asnber_pkix_certificate_builder_create(
    asnber_ctx_t *ctx, asnber_pkix_certificate_builder_t **out_builder)
{
    if (ctx == nullptr || out_builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_builder = nullptr;
    asnber_pkix_certificate_builder_t *builder =
        static_cast<asnber_pkix_certificate_builder_t *>(
            std::malloc(sizeof(asnber_pkix_certificate_builder_t)));
    if (builder == nullptr) {
        return ASNBER_E_NOMEM;
    }
    std::memset(builder, 0, sizeof(*builder));
    builder->ctx = ctx;
    *out_builder = builder;
    return ASNBER_OK;
}

extern "C" ASNBER_PKIX_API void asnber_pkix_certificate_builder_destroy(
    asnber_pkix_certificate_builder_t *builder)
{
    if (builder == nullptr) {
        return;
    }
    freeName(&builder->issuer);
    freeName(&builder->subject);

    std::free(builder->serial.data);
    std::free(builder->signature_algorithm_oid);
    std::free(builder->signature_algorithm_params.data);
    std::free(builder->subject_public_key_algorithm_oid);
    std::free(builder->subject_public_key_algorithm_params.data);
    std::free(builder->subject_public_key.data);
    std::free(builder->issuer_unique_id.data);
    std::free(builder->subject_unique_id.data);
    std::free(builder->signature_value.data);

    for (size_t i = 0; i < builder->extension_count; ++i) {
        std::free(const_cast<char *>(builder->extensions[i].oid));
        std::free(const_cast<uint8_t *>(builder->extensions[i].value));
    }
    std::free(builder->extensions);

    std::memset(builder, 0, sizeof(*builder));
    std::free(builder);
}

extern "C" ASNBER_PKIX_API asnber_err_t asnber_pkix_certificate_builder_set_version(
    asnber_pkix_certificate_builder_t *builder, int64_t version)
{
    if (builder == nullptr || version < 0 || version > 2) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->version_set) {
        return ASNBER_E_INVALID_STATE;
    }
    builder->version = version;
    builder->version_set = true;
    return ASNBER_OK;
}

extern "C" ASNBER_PKIX_API asnber_err_t
asnber_pkix_certificate_builder_set_serial_number(
    asnber_pkix_certificate_builder_t *builder, const uint8_t *magnitude,
    size_t size)
{
    if (builder == nullptr || magnitude == nullptr || size == 0) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->serial_set) {
        return ASNBER_E_INVALID_STATE;
    }
    uint8_t *copy = copyBytes(magnitude, size);
    if (copy == nullptr) {
        return ASNBER_E_NOMEM;
    }
    builder->serial.data = copy;
    builder->serial.size = size;
    builder->serial_set = true;
    return ASNBER_OK;
}

extern "C" ASNBER_PKIX_API asnber_err_t
asnber_pkix_certificate_builder_set_signature_algorithm(
    asnber_pkix_certificate_builder_t *builder, const char *oid,
    const uint8_t *parameters_tlv, size_t parameters_size)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->signature_algorithm_set) {
        return ASNBER_E_INVALID_STATE;
    }
    asnber_err_t rc = copyAlgorithm(
        builder->ctx, oid, parameters_tlv, parameters_size,
        &builder->signature_algorithm_oid,
        &builder->signature_algorithm_params);
    if (rc != ASNBER_OK) {
        return rc;
    }
    builder->signature_algorithm_set = true;
    return ASNBER_OK;
}

extern "C" ASNBER_PKIX_API asnber_err_t asnber_pkix_certificate_builder_set_issuer(
    asnber_pkix_certificate_builder_t *builder,
    const asnber_pkix_name_rdn_t *rdns, size_t rdn_count)
{
    if (builder == nullptr || (rdns == nullptr && rdn_count != 0)) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->issuer_set) {
        return ASNBER_E_INVALID_STATE;
    }
    asnber_err_t rc = copyName(builder->ctx, &builder->issuer, rdns, rdn_count);
    if (rc != ASNBER_OK) {
        return rc;
    }
    builder->issuer_set = true;
    return ASNBER_OK;
}

extern "C" ASNBER_PKIX_API asnber_err_t asnber_pkix_certificate_builder_set_validity(
    asnber_pkix_certificate_builder_t *builder,
    const asnber_time_t *not_before, const asnber_time_t *not_after)
{
    if (builder == nullptr || not_before == nullptr || not_after == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->validity_set) {
        return ASNBER_E_INVALID_STATE;
    }
    asnber_err_t rc = validateTime(not_before);
    if (rc != ASNBER_OK) {
        return rc;
    }
    rc = validateTime(not_after);
    if (rc != ASNBER_OK) {
        return rc;
    }
    builder->not_before = *not_before;
    builder->not_after = *not_after;
    builder->validity_set = true;
    return ASNBER_OK;
}

extern "C" ASNBER_PKIX_API asnber_err_t asnber_pkix_certificate_builder_set_subject(
    asnber_pkix_certificate_builder_t *builder,
    const asnber_pkix_name_rdn_t *rdns, size_t rdn_count)
{
    if (builder == nullptr || (rdns == nullptr && rdn_count != 0)) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->subject_set) {
        return ASNBER_E_INVALID_STATE;
    }
    asnber_err_t rc = copyName(builder->ctx, &builder->subject, rdns, rdn_count);
    if (rc != ASNBER_OK) {
        return rc;
    }
    builder->subject_set = true;
    return ASNBER_OK;
}

extern "C" ASNBER_PKIX_API asnber_err_t
asnber_pkix_certificate_builder_set_subject_public_key_algorithm(
    asnber_pkix_certificate_builder_t *builder, const char *oid,
    const uint8_t *parameters_tlv, size_t parameters_size)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->subject_public_key_algorithm_set) {
        return ASNBER_E_INVALID_STATE;
    }
    asnber_err_t rc = copyAlgorithm(
        builder->ctx, oid, parameters_tlv, parameters_size,
        &builder->subject_public_key_algorithm_oid,
        &builder->subject_public_key_algorithm_params);
    if (rc != ASNBER_OK) {
        return rc;
    }
    builder->subject_public_key_algorithm_set = true;
    return ASNBER_OK;
}

extern "C" ASNBER_PKIX_API asnber_err_t
asnber_pkix_certificate_builder_set_subject_public_key(
    asnber_pkix_certificate_builder_t *builder, const uint8_t *bits,
    size_t size, uint8_t unused_bits)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->subject_public_key_set) {
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
    builder->subject_public_key.data = copy;
    builder->subject_public_key.size = size;
    builder->subject_public_key_unused_bits = unused_bits;
    builder->subject_public_key_set = true;
    return ASNBER_OK;
}

extern "C" ASNBER_PKIX_API asnber_err_t
asnber_pkix_certificate_builder_set_issuer_unique_id(
    asnber_pkix_certificate_builder_t *builder, const uint8_t *bits,
    size_t size, uint8_t unused_bits)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->issuer_unique_id_set) {
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
    builder->issuer_unique_id.data = copy;
    builder->issuer_unique_id.size = size;
    builder->issuer_unique_id_unused_bits = unused_bits;
    builder->issuer_unique_id_set = true;
    return ASNBER_OK;
}

extern "C" ASNBER_PKIX_API asnber_err_t
asnber_pkix_certificate_builder_set_subject_unique_id(
    asnber_pkix_certificate_builder_t *builder, const uint8_t *bits,
    size_t size, uint8_t unused_bits)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->subject_unique_id_set) {
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
    builder->subject_unique_id.data = copy;
    builder->subject_unique_id.size = size;
    builder->subject_unique_id_unused_bits = unused_bits;
    builder->subject_unique_id_set = true;
    return ASNBER_OK;
}

extern "C" ASNBER_PKIX_API asnber_err_t
asnber_pkix_certificate_builder_set_signature_value(
    asnber_pkix_certificate_builder_t *builder, const uint8_t *bits,
    size_t size, uint8_t unused_bits)
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

extern "C" ASNBER_PKIX_API asnber_err_t asnber_pkix_certificate_builder_encode(
    const asnber_pkix_certificate_builder_t *builder, asnber_buf_t *out_buf)
{
    if (builder == nullptr || out_buf == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    resetBuffer(out_buf);

    if (!builder->serial_set || !builder->signature_algorithm_set ||
        !builder->issuer_set || !builder->validity_set ||
        !builder->subject_set || !builder->subject_public_key_algorithm_set ||
        !builder->subject_public_key_set || !builder->signature_value_set) {
        return ASNBER_E_INVALID_STATE;
    }

    asnber_doc_t *doc = nullptr;
    asnber_err_t rc = buildCertificate(*builder, &doc);
    if (rc != ASNBER_OK) {
        return rc;
    }
    rc = encodeCertificate(*builder, doc, out_buf);
    asnber_doc_destroy(doc);
    return rc;
}
