/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-pkcs8 PrivateKeyInfo builder：构树、编码与公共接口。
 *
 * 与只读侧共享同一张描述表；构造侧只负责把调用方给出的字段按 RFC 5208
 * 顺序组装成一棵树，再走 schema 感知编码。
 */

#include <asnber/pkcs8/pkcs8.h>

#include "detail/module_builder_support.h"
#include "pkcs8_tables.h"

#include <cstdlib>
#include <cstring>

using asnber::module_detail::addAlgorithmIdentifier;
using asnber::module_detail::byte_span;
using asnber::module_detail::copyBytes;
using asnber::module_detail::copyText;
using asnber::module_detail::createIntegerNode;
using asnber::module_detail::createNode;
using asnber::module_detail::createOctetStringNode;
using asnber::module_detail::kTagSequence;
using asnber::module_detail::loadTable;
using asnber::module_detail::validateAndRewriteSet;
using asnber::module_detail::validateOid;
using asnber::module_detail::validateSingleDer;

/* 与 pkcs8.h 的前向声明同名同域：内部状态对构造侧翻译单元可见。 */
struct asnber_pkcs_private_key_info_builder {
    asnber_ctx_t *ctx;
    bool version_set;
    int64_t version;
    bool algorithm_set;
    char *algorithm_oid;
    byte_span algorithm_params; /* 完整 DER TLV；缺省时 size == 0。 */
    bool private_key_set;
    byte_span private_key; /* OCTET STRING 内容字节。 */
    bool attributes_set;
    byte_span attributes; /* 已改写为 [0] IMPLICIT 的完整 TLV。 */
};

namespace {

void resetBuffer(asnber_buf_t *buf)
{
    buf->data = nullptr;
    buf->size = 0;
    buf->capacity = 0;
}

asnber_err_t buildPrivateKeyInfo(
    const asnber_pkcs_private_key_info_builder &builder, asnber_doc_t **out_doc)
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
        rc = addAlgorithmIdentifier(doc, root, builder.algorithm_oid,
                                    builder.algorithm_params);
    }
    if (rc == ASNBER_OK) {
        rc = createOctetStringNode(doc, root, builder.private_key.data,
                                   builder.private_key.size, &ignored);
    }
    if (rc == ASNBER_OK && builder.attributes_set) {
        rc = asnber_node_create_any(doc, root, builder.attributes.data,
                                  builder.attributes.size, &ignored);
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

asnber_err_t encodePrivateKeyInfo(
    const asnber_pkcs_private_key_info_builder &builder, const asnber_doc_t *doc,
    asnber_buf_t *out_buf)
{
    pkcs8_table_view table = pkcs8SchemaTable();
    asnber_schema_t *schema = nullptr;
    asnber_err_t rc = loadTable(builder.ctx, table.data, table.size,
                              kPkcs8RootPrivateKeyInfo, &schema);
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

extern "C" asnber_err_t asnber_pkcs_private_key_info_builder_create(
    asnber_ctx_t *ctx, asnber_pkcs_private_key_info_builder_t **out_builder)
{
    if (ctx == nullptr || out_builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_builder = nullptr;
    asnber_pkcs_private_key_info_builder_t *builder =
        static_cast<asnber_pkcs_private_key_info_builder_t *>(
            std::malloc(sizeof(asnber_pkcs_private_key_info_builder_t)));
    if (builder == nullptr) {
        return ASNBER_E_NOMEM;
    }
    std::memset(builder, 0, sizeof(*builder));
    builder->ctx = ctx;
    *out_builder = builder;
    return ASNBER_OK;
}

extern "C" void asnber_pkcs_private_key_info_builder_destroy(
    asnber_pkcs_private_key_info_builder_t *builder)
{
    if (builder == nullptr) {
        return;
    }
    std::free(builder->algorithm_oid);
    std::free(builder->algorithm_params.data);
    std::free(builder->private_key.data);
    std::free(builder->attributes.data);
    std::memset(builder, 0, sizeof(*builder));
    std::free(builder);
}

extern "C" asnber_err_t asnber_pkcs_private_key_info_builder_set_version(
    asnber_pkcs_private_key_info_builder_t *builder, int64_t version)
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

extern "C" asnber_err_t asnber_pkcs_private_key_info_builder_set_algorithm(
    asnber_pkcs_private_key_info_builder_t *builder, const char *oid,
    const uint8_t *parameters_tlv, size_t parameters_size)
{
    if (builder == nullptr || oid == nullptr ||
        (parameters_tlv == nullptr && parameters_size != 0)) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->algorithm_set) {
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
    if (oid_copy == nullptr) {
        return ASNBER_E_NOMEM;
    }
    uint8_t *params_copy = copyBytes(parameters_tlv, parameters_size);
    if (parameters_size != 0 && params_copy == nullptr) {
        std::free(oid_copy);
        return ASNBER_E_NOMEM;
    }
    builder->algorithm_oid = oid_copy;
    builder->algorithm_params.data = params_copy;
    builder->algorithm_params.size = parameters_size;
    builder->algorithm_set = true;
    return ASNBER_OK;
}

extern "C" asnber_err_t asnber_pkcs_private_key_info_builder_set_private_key(
    asnber_pkcs_private_key_info_builder_t *builder, const uint8_t *data,
    size_t size)
{
    if (builder == nullptr || (data == nullptr && size != 0)) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->private_key_set) {
        return ASNBER_E_INVALID_STATE;
    }
    uint8_t *copy = copyBytes(data, size);
    if (size != 0 && copy == nullptr) {
        return ASNBER_E_NOMEM;
    }
    builder->private_key.data = copy;
    builder->private_key.size = size;
    builder->private_key_set = true;
    return ASNBER_OK;
}

extern "C" asnber_err_t asnber_pkcs_private_key_info_builder_set_attributes(
    asnber_pkcs_private_key_info_builder_t *builder, const uint8_t *set_tlv,
    size_t set_size)
{
    if (builder == nullptr || set_tlv == nullptr || set_size == 0) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->attributes_set) {
        return ASNBER_E_INVALID_STATE;
    }
    byte_span rewritten;
    std::memset(&rewritten, 0, sizeof(rewritten));
    asnber_err_t rc = validateAndRewriteSet(builder->ctx, set_tlv, set_size,
                                          0xA0, &rewritten);
    if (rc != ASNBER_OK) {
        return rc;
    }
    builder->attributes = rewritten;
    builder->attributes_set = true;
    return ASNBER_OK;
}

extern "C" asnber_err_t asnber_pkcs_private_key_info_builder_encode(
    const asnber_pkcs_private_key_info_builder_t *builder, asnber_buf_t *out_buf)
{
    if (builder == nullptr || out_buf == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    resetBuffer(out_buf);

    if (!builder->version_set || !builder->algorithm_set ||
        !builder->private_key_set) {
        return ASNBER_E_INVALID_STATE;
    }

    asnber_doc_t *doc = nullptr;
    asnber_err_t rc = buildPrivateKeyInfo(*builder, &doc);
    if (rc != ASNBER_OK) {
        return rc;
    }
    rc = encodePrivateKeyInfo(*builder, doc, out_buf);
    asnber_doc_destroy(doc);
    return rc;
}
