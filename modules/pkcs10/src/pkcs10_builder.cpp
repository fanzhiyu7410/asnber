/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-pkcs10 CertificationRequest builder：构树、编码与公共接口。
 *
 * 与只读侧共享同一张描述表；构造侧只负责把调用方给出的字段按 RFC 2986
 * 顺序组装成一棵树，再走 schema 感知编码。attributes 的 SET OF 排序通过
 * “先按通用 DER 编出 SET、再把外层标记改写为 [0] IMPLICIT”完成。
 */

#include <asnber/pkcs10/pkcs10.h>

#include "detail/module_builder_support.h"
#include "detail/x509_primitives.h"
#include "pkcs10_tables.h"

#include <cstdlib>
#include <cstring>

using asnber::module_detail::addAlgorithmIdentifier;
using asnber::module_detail::byte_span;
using asnber::module_detail::copyBytes;
using asnber::module_detail::copyText;
using asnber::module_detail::createBitStringNode;
using asnber::module_detail::createIntegerNode;
using asnber::module_detail::createNameNode;
using asnber::module_detail::createNode;
using asnber::module_detail::encodeExtensions;
using asnber::module_detail::ensureCapacity;
using asnber::module_detail::extension_entry;
using asnber::module_detail::kTagIa5String;
using asnber::module_detail::kTagPrintableString;
using asnber::module_detail::kTagSequence;
using asnber::module_detail::kTagSet;
using asnber::module_detail::kTagUtf8String;
using asnber::module_detail::loadTable;
using asnber::module_detail::name_attribute;
using asnber::module_detail::name_rdn;
using asnber::module_detail::nameStringValid;
using asnber::module_detail::selectNameStringTag;
using asnber::module_detail::validateBitString;
using asnber::module_detail::validateOid;
using asnber::module_detail::validateSingleDer;

namespace {

/* extensionRequest 属性类型：1.2.840.113549.1.9.14。 */
constexpr const char *kExtensionRequestOid = "1.2.840.113549.1.9.14";

struct builder_attribute {
    char *oid;
    byte_span *values;
    size_t value_count;
};

struct builder_name_attribute {
    char *oid;
    uint8_t *value;
    size_t value_size;
    uint32_t string_tag;
};

struct builder_rdn {
    size_t first;
    size_t count;
};

void freeAttribute(builder_attribute *attribute)
{
    if (attribute == nullptr) {
        return;
    }
    std::free(attribute->oid);
    if (attribute->values != nullptr) {
        for (size_t i = 0; i < attribute->value_count; ++i) {
            std::free(attribute->values[i].data);
        }
    }
    std::free(attribute->values);
    std::memset(attribute, 0, sizeof(*attribute));
}

void resetBuffer(asnber_buf_t *buf)
{
    buf->data = nullptr;
    buf->size = 0;
    buf->capacity = 0;
}

} /* namespace */

/* 与 pkcs10.h 的前向声明同名同域：内部状态对构造侧翻译单元可见。 */
struct asnber_pkcs_certification_request_builder {
    asnber_ctx_t *ctx;

    bool version_set;
    int64_t version;

    bool subject_set;
    builder_name_attribute *name_attributes;
    size_t name_attribute_count;
    builder_rdn *name_rdns;
    size_t name_rdn_count;
    name_attribute *name_attribute_views;
    name_rdn *name_rdn_views;

    bool subject_public_key_algorithm_set;
    char *subject_public_key_algorithm_oid;
    byte_span subject_public_key_algorithm_params;

    bool subject_public_key_set;
    byte_span subject_public_key;
    uint8_t subject_public_key_unused_bits;

    bool signature_algorithm_set;
    char *signature_algorithm_oid;
    byte_span signature_algorithm_params;

    bool signature_set;
    byte_span signature;
    uint8_t signature_unused_bits;

    builder_attribute *attributes;
    size_t attribute_count;
    size_t attribute_capacity;

    extension_entry *extensions;
    size_t extension_count;
    size_t extension_capacity;
};

namespace {

/* 复制并校验 subject；失败时不留下任何状态。 */
asnber_err_t copySubject(asnber_pkcs_certification_request_builder_t *builder,
                       const asnber_pkcs_name_rdn_t *rdns, size_t rdn_count)
{
    size_t total = 0;
    for (size_t i = 0; i < rdn_count; ++i) {
        if (rdns[i].attributes == nullptr || rdns[i].count == 0 ||
            rdns[i].count > SIZE_MAX - total) {
            return ASNBER_E_INVALID_ARG;
        }
        for (size_t j = 0; j < rdns[i].count; ++j) {
            const asnber_pkcs_name_attribute_t &attribute = rdns[i].attributes[j];
            if (attribute.oid == nullptr ||
                (attribute.value == nullptr && attribute.value_size != 0)) {
                return ASNBER_E_INVALID_ARG;
            }
            asnber_err_t rc = validateOid(builder->ctx, attribute.oid);
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

    builder_name_attribute *attributes = nullptr;
    name_attribute *attribute_views = nullptr;
    builder_rdn *name_rdns = nullptr;
    name_rdn *rdn_views = nullptr;
    if (total != 0) {
        attributes = static_cast<builder_name_attribute *>(
            std::calloc(total, sizeof(builder_name_attribute)));
        attribute_views = static_cast<name_attribute *>(
            std::calloc(total, sizeof(name_attribute)));
        if (attributes == nullptr || attribute_views == nullptr) {
            std::free(attributes);
            std::free(attribute_views);
            return ASNBER_E_NOMEM;
        }
    }
    if (rdn_count != 0) {
        name_rdns = static_cast<builder_rdn *>(
            std::calloc(rdn_count, sizeof(builder_rdn)));
        rdn_views = static_cast<name_rdn *>(
            std::calloc(rdn_count, sizeof(name_rdn)));
        if (name_rdns == nullptr || rdn_views == nullptr) {
            std::free(attributes);
            std::free(attribute_views);
            std::free(name_rdns);
            std::free(rdn_views);
            return ASNBER_E_NOMEM;
        }
    }

    size_t filled = 0;
    for (size_t i = 0; i < rdn_count; ++i) {
        name_rdns[i].first = filled;
        name_rdns[i].count = rdns[i].count;
        for (size_t j = 0; j < rdns[i].count; ++j, ++filled) {
            const asnber_pkcs_name_attribute_t &source = rdns[i].attributes[j];
            attributes[filled].oid = copyText(source.oid);
            attributes[filled].value =
                copyBytes(source.value, source.value_size);
            if (attributes[filled].oid == nullptr ||
                attributes[filled].value == nullptr) {
                for (size_t k = 0; k <= filled; ++k) {
                    std::free(attributes[k].oid);
                    std::free(attributes[k].value);
                }
                std::free(attributes);
                std::free(attribute_views);
                std::free(name_rdns);
                std::free(rdn_views);
                return ASNBER_E_NOMEM;
            }
            attributes[filled].value_size = source.value_size;
            attributes[filled].string_tag =
                source.string_tag == 0 ? selectNameStringTag(source.oid)
                                       : source.string_tag;

            attribute_views[filled].oid = attributes[filled].oid;
            attribute_views[filled].value = attributes[filled].value;
            attribute_views[filled].value_size = attributes[filled].value_size;
            attribute_views[filled].string_tag = attributes[filled].string_tag;
        }
        rdn_views[i].attributes =
            rdn_count == 0 ? nullptr : &attribute_views[name_rdns[i].first];
        rdn_views[i].count = name_rdns[i].count;
    }

    builder->name_attributes = attributes;
    builder->name_attribute_count = total;
    builder->name_rdns = name_rdns;
    builder->name_rdn_count = rdn_count;
    builder->name_attribute_views = attribute_views;
    builder->name_rdn_views = rdn_views;
    return ASNBER_OK;
}

/* 追加一个通用 Attribute，values 在调用前已校验。 */
asnber_err_t appendAttribute(asnber_pkcs_certification_request_builder_t *builder,
                           const char *oid, const uint8_t *const *values,
                           const size_t *value_sizes, size_t value_count)
{
    if (!ensureCapacity(&builder->attributes, builder->attribute_count,
                        &builder->attribute_capacity)) {
        return ASNBER_E_NOMEM;
    }
    builder_attribute attribute;
    std::memset(&attribute, 0, sizeof(attribute));
    attribute.values = static_cast<byte_span *>(
        std::calloc(value_count, sizeof(byte_span)));
    attribute.oid = copyText(oid);
    if (attribute.values == nullptr || attribute.oid == nullptr) {
        freeAttribute(&attribute);
        return ASNBER_E_NOMEM;
    }
    for (size_t i = 0; i < value_count; ++i) {
        attribute.values[i].data = copyBytes(values[i], value_sizes[i]);
        if (attribute.values[i].data == nullptr) {
            freeAttribute(&attribute);
            return ASNBER_E_NOMEM;
        }
        attribute.values[i].size = value_sizes[i];
        attribute.value_count = i + 1;
    }
    builder->attributes[builder->attribute_count++] = attribute;
    return ASNBER_OK;
}

/*
 * 把 attributes 编成完整的 [0] IMPLICIT SET OF Attribute TLV。
 *
 * 选在独立文档里按通用 DER 编出 `31 ...`，由核心完成 SET OF 排序，再把外层
 * 标记改写为 `A0`。这样既保留 DER 规范化，又不需要在运行期节点上重排。
 */
asnber_err_t encodeAttributes(asnber_ctx_t *ctx,
                            const asnber_pkcs_certification_request_builder_t &builder,
                            asnber_buf_t *out)
{
    resetBuffer(out);

    asnber_doc_t *doc = nullptr;
    asnber_err_t rc = asnber_doc_create(ctx, &doc);
    if (rc != ASNBER_OK) {
        return rc;
    }
    asnber_node_t *root = nullptr;
    rc = createNode(doc, nullptr, ASNBER_TAG_UNIVERSAL, kTagSet, 1, &root);
    if (rc != ASNBER_OK) {
        asnber_doc_destroy(doc);
        return rc;
    }

    for (size_t i = 0; i < builder.attribute_count && rc == ASNBER_OK; ++i) {
        const builder_attribute &attribute = builder.attributes[i];
        asnber_node_t *sequence = nullptr;
        asnber_node_t *ignored = nullptr;
        rc = createNode(doc, root, ASNBER_TAG_UNIVERSAL, kTagSequence, 1,
                        &sequence);
        if (rc != ASNBER_OK) {
            break;
        }
        rc = asnber::module_detail::createOidNode(doc, sequence, attribute.oid,
                                                &ignored);
        if (rc != ASNBER_OK) {
            break;
        }
        asnber_node_t *values = nullptr;
        rc = createNode(doc, sequence, ASNBER_TAG_UNIVERSAL, kTagSet, 1, &values);
        for (size_t j = 0; j < attribute.value_count && rc == ASNBER_OK; ++j) {
            rc = asnber_node_create_any(doc, values, attribute.values[j].data,
                                      attribute.values[j].size, &ignored);
        }
    }

    if (rc == ASNBER_OK && builder.extension_count != 0) {
        asnber_buf_t extensions;
        rc = encodeExtensions(ctx, builder.extensions, builder.extension_count,
                              &extensions);
        if (rc == ASNBER_OK) {
            asnber_node_t *sequence = nullptr;
            asnber_node_t *ignored = nullptr;
            rc = createNode(doc, root, ASNBER_TAG_UNIVERSAL, kTagSequence, 1,
                            &sequence);
            if (rc == ASNBER_OK) {
                rc = asnber::module_detail::createOidNode(
                    doc, sequence, kExtensionRequestOid, &ignored);
            }
            asnber_node_t *values = nullptr;
            if (rc == ASNBER_OK) {
                rc = createNode(doc, sequence, ASNBER_TAG_UNIVERSAL, kTagSet, 1,
                                &values);
            }
            if (rc == ASNBER_OK) {
                rc = asnber_node_create_any(doc, values, extensions.data,
                                          extensions.size, &ignored);
            }
            asnber_buf_release(ctx, &extensions);
        }
    }

    if (rc == ASNBER_OK) {
        rc = asnber_doc_seal(doc);
    }
    if (rc == ASNBER_OK) {
        asnber_encode_options_t options;
        asnber_encode_options_init(&options);
        rc = asnber_encode_buffer(ctx, doc, &options, out);
    }
    asnber_doc_destroy(doc);
    if (rc != ASNBER_OK) {
        resetBuffer(out);
        return rc;
    }
    if (out->size == 0 || out->data[0] != 0x31) {
        asnber_buf_release(ctx, out);
        return ASNBER_E_INVALID_STATE;
    }
    out->data[0] = 0xA0;
    return ASNBER_OK;
}

asnber_err_t buildCertificationRequest(
    const asnber_pkcs_certification_request_builder_t &builder,
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
    asnber_node_t *info = nullptr;
    if (rc == ASNBER_OK) {
        rc = createNode(doc, root, ASNBER_TAG_UNIVERSAL, kTagSequence, 1, &info);
    }
    if (rc == ASNBER_OK) {
        rc = createIntegerNode(doc, info, builder.version, &ignored);
    }
    if (rc == ASNBER_OK) {
        rc = createNameNode(doc, info, builder.name_rdn_views,
                            builder.name_rdn_count, &ignored);
    }
    asnber_node_t *public_key_info = nullptr;
    if (rc == ASNBER_OK) {
        rc = createNode(doc, info, ASNBER_TAG_UNIVERSAL, kTagSequence, 1,
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
    if (rc == ASNBER_OK) {
        asnber_buf_t attributes;
        rc = encodeAttributes(builder.ctx, builder, &attributes);
        if (rc == ASNBER_OK) {
            rc = asnber_node_create_any(doc, info, attributes.data,
                                      attributes.size, &ignored);
            asnber_buf_release(builder.ctx, &attributes);
        }
    }
    if (rc == ASNBER_OK) {
        rc = addAlgorithmIdentifier(doc, root, builder.signature_algorithm_oid,
                                    builder.signature_algorithm_params);
    }
    if (rc == ASNBER_OK) {
        rc = createBitStringNode(doc, root, builder.signature.data,
                                 builder.signature.size,
                                 builder.signature_unused_bits, &ignored);
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

asnber_err_t encodeCertificationRequest(
    const asnber_pkcs_certification_request_builder_t &builder,
    const asnber_doc_t *doc, asnber_buf_t *out_buf)
{
    pkcs10_table_view table = pkcs10SchemaTable();
    asnber_schema_t *schema = nullptr;
    asnber_err_t rc = loadTable(builder.ctx, table.data, table.size,
                              kPkcs10RootCertificationRequest, &schema);
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

} /* namespace */

extern "C" ASNBER_PKCS10_API asnber_err_t
asnber_pkcs_certification_request_builder_create(
    asnber_ctx_t *ctx, asnber_pkcs_certification_request_builder_t **out_builder)
{
    if (ctx == nullptr || out_builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_builder = nullptr;
    asnber_pkcs_certification_request_builder_t *builder =
        static_cast<asnber_pkcs_certification_request_builder_t *>(
            std::malloc(sizeof(asnber_pkcs_certification_request_builder_t)));
    if (builder == nullptr) {
        return ASNBER_E_NOMEM;
    }
    std::memset(builder, 0, sizeof(*builder));
    builder->ctx = ctx;
    *out_builder = builder;
    return ASNBER_OK;
}

extern "C" ASNBER_PKCS10_API void
asnber_pkcs_certification_request_builder_destroy(
    asnber_pkcs_certification_request_builder_t *builder)
{
    if (builder == nullptr) {
        return;
    }
    for (size_t i = 0; i < builder->name_attribute_count; ++i) {
        std::free(builder->name_attributes[i].oid);
        std::free(builder->name_attributes[i].value);
    }
    std::free(builder->name_attributes);
    std::free(builder->name_rdns);
    std::free(builder->name_attribute_views);
    std::free(builder->name_rdn_views);

    std::free(builder->subject_public_key_algorithm_oid);
    std::free(builder->subject_public_key_algorithm_params.data);
    std::free(builder->subject_public_key.data);
    std::free(builder->signature_algorithm_oid);
    std::free(builder->signature_algorithm_params.data);
    std::free(builder->signature.data);

    for (size_t i = 0; i < builder->attribute_count; ++i) {
        freeAttribute(&builder->attributes[i]);
    }
    std::free(builder->attributes);

    for (size_t i = 0; i < builder->extension_count; ++i) {
        std::free(const_cast<char *>(builder->extensions[i].oid));
        std::free(const_cast<uint8_t *>(builder->extensions[i].value));
    }
    std::free(builder->extensions);

    std::memset(builder, 0, sizeof(*builder));
    std::free(builder);
}

extern "C" ASNBER_PKCS10_API asnber_err_t
asnber_pkcs_certification_request_builder_set_version(
    asnber_pkcs_certification_request_builder_t *builder, int64_t version)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->version_set) {
        return ASNBER_E_INVALID_STATE;
    }
    builder->version = version;
    builder->version_set = true;
    return ASNBER_OK;
}

extern "C" ASNBER_PKCS10_API asnber_err_t
asnber_pkcs_certification_request_builder_set_subject(
    asnber_pkcs_certification_request_builder_t *builder,
    const asnber_pkcs_name_rdn_t *rdns, size_t rdn_count)
{
    if (builder == nullptr || (rdns == nullptr && rdn_count != 0)) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->subject_set) {
        return ASNBER_E_INVALID_STATE;
    }
    asnber_err_t rc = copySubject(builder, rdns, rdn_count);
    if (rc != ASNBER_OK) {
        return rc;
    }
    builder->subject_set = true;
    return ASNBER_OK;
}

extern "C" ASNBER_PKCS10_API asnber_err_t
asnber_pkcs_certification_request_builder_set_subject_public_key_algorithm(
    asnber_pkcs_certification_request_builder_t *builder, const char *oid,
    const uint8_t *parameters_tlv, size_t parameters_size)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->subject_public_key_algorithm_set) {
        return ASNBER_E_INVALID_STATE;
    }
    asnber_err_t rc =
        checkAlgorithm(builder->ctx, oid, parameters_tlv, parameters_size);
    if (rc != ASNBER_OK) {
        return rc;
    }
    char *oid_copy = copyText(oid);
    uint8_t *params_copy = copyBytes(parameters_tlv, parameters_size);
    if (oid_copy == nullptr || (parameters_size != 0 && params_copy == nullptr)) {
        std::free(oid_copy);
        std::free(params_copy);
        return ASNBER_E_NOMEM;
    }
    builder->subject_public_key_algorithm_oid = oid_copy;
    builder->subject_public_key_algorithm_params.data = params_copy;
    builder->subject_public_key_algorithm_params.size = parameters_size;
    builder->subject_public_key_algorithm_set = true;
    return ASNBER_OK;
}

extern "C" ASNBER_PKCS10_API asnber_err_t
asnber_pkcs_certification_request_builder_set_subject_public_key(
    asnber_pkcs_certification_request_builder_t *builder, const uint8_t *bits,
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

extern "C" ASNBER_PKCS10_API asnber_err_t
asnber_pkcs_certification_request_builder_set_signature_algorithm(
    asnber_pkcs_certification_request_builder_t *builder, const char *oid,
    const uint8_t *parameters_tlv, size_t parameters_size)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->signature_algorithm_set) {
        return ASNBER_E_INVALID_STATE;
    }
    asnber_err_t rc =
        checkAlgorithm(builder->ctx, oid, parameters_tlv, parameters_size);
    if (rc != ASNBER_OK) {
        return rc;
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

extern "C" ASNBER_PKCS10_API asnber_err_t
asnber_pkcs_certification_request_builder_set_signature(
    asnber_pkcs_certification_request_builder_t *builder, const uint8_t *bits,
    size_t size, uint8_t unused_bits)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->signature_set) {
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
    builder->signature.data = copy;
    builder->signature.size = size;
    builder->signature_unused_bits = unused_bits;
    builder->signature_set = true;
    return ASNBER_OK;
}

extern "C" ASNBER_PKCS10_API asnber_err_t
asnber_pkcs_certification_request_builder_add_attribute(
    asnber_pkcs_certification_request_builder_t *builder, const char *type_oid,
    const uint8_t *const *values, const size_t *value_sizes,
    size_t value_count)
{
    if (builder == nullptr || type_oid == nullptr || values == nullptr ||
        value_sizes == nullptr || value_count == 0) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber_err_t rc = validateOid(builder->ctx, type_oid);
    if (rc != ASNBER_OK) {
        return rc;
    }
    for (size_t i = 0; i < value_count; ++i) {
        if (values[i] == nullptr || value_sizes[i] == 0) {
            return ASNBER_E_INVALID_ARG;
        }
        rc = validateSingleDer(builder->ctx, values[i], value_sizes[i],
                               nullptr);
        if (rc != ASNBER_OK) {
            return rc;
        }
    }
    return appendAttribute(builder, type_oid, values, value_sizes,
                           value_count);
}

extern "C" ASNBER_PKCS10_API asnber_err_t
asnber_pkcs_certification_request_builder_add_extension(
    asnber_pkcs_certification_request_builder_t *builder, const char *extn_oid,
    int critical, const uint8_t *extn_value_der, size_t extn_value_size)
{
    if (builder == nullptr || extn_oid == nullptr ||
        extn_value_der == nullptr || extn_value_size == 0) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber_err_t rc = validateOid(builder->ctx, extn_oid);
    if (rc != ASNBER_OK) {
        return rc;
    }
    rc = validateSingleDer(builder->ctx, extn_value_der, extn_value_size,
                           nullptr);
    if (rc != ASNBER_OK) {
        return rc;
    }
    for (size_t i = 0; i < builder->extension_count; ++i) {
        if (std::strcmp(builder->extensions[i].oid, extn_oid) == 0) {
            return ASNBER_E_INVALID_VALUE;
        }
    }
    if (!ensureCapacity(&builder->extensions, builder->extension_count,
                        &builder->extension_capacity)) {
        return ASNBER_E_NOMEM;
    }
    char *oid_copy = copyText(extn_oid);
    uint8_t *value_copy = copyBytes(extn_value_der, extn_value_size);
    if (oid_copy == nullptr || value_copy == nullptr) {
        std::free(oid_copy);
        std::free(value_copy);
        return ASNBER_E_NOMEM;
    }
    extension_entry &entry = builder->extensions[builder->extension_count++];
    entry.oid = oid_copy;
    entry.critical = critical != 0;
    entry.value = value_copy;
    entry.value_size = extn_value_size;
    return ASNBER_OK;
}

extern "C" ASNBER_PKCS10_API asnber_err_t
asnber_pkcs_certification_request_builder_encode(
    const asnber_pkcs_certification_request_builder_t *builder,
    asnber_buf_t *out_buf)
{
    if (builder == nullptr || out_buf == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    resetBuffer(out_buf);

    if (!builder->version_set || !builder->subject_set ||
        !builder->subject_public_key_algorithm_set ||
        !builder->subject_public_key_set ||
        !builder->signature_algorithm_set || !builder->signature_set) {
        return ASNBER_E_INVALID_STATE;
    }

    asnber_doc_t *doc = nullptr;
    asnber_err_t rc = buildCertificationRequest(*builder, &doc);
    if (rc != ASNBER_OK) {
        return rc;
    }
    rc = encodeCertificationRequest(*builder, doc, out_buf);
    asnber_doc_destroy(doc);
    return rc;
}
