/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-pkcs12 PFX / AuthenticatedSafe 构造。
 *
 * 职责：按调用方给出的版本、ContentInfo 与 macData 组装 PFX，并按 data /
 *       encryptedData 两种形态组装 AuthenticatedSafe。
 * 边界：不做口令密钥派生、不加密/解密、不计算或校验 MAC；ContentInfo 的
 *       content 由调用方决定（方案 A），只有 AuthenticatedSafe 的 data 形态
 *       由 builder 负责套 OCTET STRING。
 * 依赖：核心公共 C ABI 与模块共享构造支撑；描述表取自模块内 pkcs12_tables。
 * 所有权：builder 深拷贝所有输入，destroy 释放；encode 输出由调用方用
 *       asnber_buf_release 归还。
 */

#include <asnber/pkcs12/pkcs12.h>

#include "detail/module_builder_support.h"
#include "detail/x509_primitives.h"
#include "pkcs12_tables.h"

#include <cstdlib>
#include <cstring>

using asnber::module_detail::addAlgorithmIdentifier;
using asnber::module_detail::byte_span;
using asnber::module_detail::copyBytes;
using asnber::module_detail::copyText;
using asnber::module_detail::createIntegerNode;
using asnber::module_detail::createNode;
using asnber::module_detail::createOctetStringNode;
using asnber::module_detail::createOidNode;
using asnber::module_detail::ensureCapacity;
using asnber::module_detail::kTagContext0;
using asnber::module_detail::kTagOctetString;
using asnber::module_detail::kTagSequence;
using asnber::module_detail::validateOid;
using asnber::module_detail::validateSingleDer;

namespace {

/* PKCS#7 data / encryptedData 的 contentType。 */
constexpr const char *kDataOid = "1.2.840.113549.1.7.1";
constexpr const char *kEncryptedDataOid = "1.2.840.113549.1.7.6";

constexpr int64_t kDefaultPfxVersion = 3;
constexpr uint32_t kPkcs12FormatVersion = 1u << 16;

void resetBuffer(asnber_buf_t *buf)
{
    buf->data = nullptr;
    buf->size = 0;
    buf->capacity = 0;
}

void freeSpan(byte_span *span)
{
    std::free(span->data);
    span->data = nullptr;
    span->size = 0;
}

bool copySpan(byte_span *span, const uint8_t *data, size_t size)
{
    freeSpan(span);
    span->data = copyBytes(data, size);
    span->size = (span->data == nullptr) ? 0 : size;
    return span->data != nullptr;
}

/* 从完整 DER OCTET STRING TLV 取内容；非 OCTET STRING 或长度不符返回失败。 */
bool octetsFromTlv(const uint8_t *tlv, size_t tlv_size, const uint8_t **out_data,
                   size_t *out_size)
{
    if (tlv == nullptr || tlv_size < 2 || tlv[0] != kTagOctetString) {
        return false;
    }
    size_t header = 2;
    size_t length = tlv[1];
    if ((length & 0x80u) != 0) {
        const size_t count = length & 0x7Fu;
        if (count == 0 || count > sizeof(size_t) || tlv_size < 2 + count) {
            return false;
        }
        length = 0;
        for (size_t i = 0; i < count; ++i) {
            if (length > (SIZE_MAX >> 8)) {
                return false;
            }
            length = (length << 8) | tlv[2 + i];
        }
        header = 2 + count;
    }
    if (length != tlv_size - header) {
        return false;
    }
    *out_data = tlv + header;
    *out_size = length;
    return true;
}

asnber_err_t loadSchema(asnber_ctx_t *ctx, uint32_t root_type_id,
                      asnber_schema_t **out_schema)
{
    const pkcs12_table_view view = pkcs12SchemaTable();
    asnber_schema_table_t table;
    table.struct_size = sizeof(table);
    table.data = view.data;
    table.size = view.size;
    table.format_version = kPkcs12FormatVersion;
    table.reserved = 0;
    return asnber_schema_load_with_root(ctx, &table, root_type_id, out_schema);
}

asnber_err_t encodeDocument(asnber_ctx_t *ctx, asnber_doc_t *doc,
                          uint32_t root_type_id, asnber_buf_t *out)
{
    resetBuffer(out);
    asnber_err_t rc = asnber_doc_seal(doc);
    if (rc != ASNBER_OK) {
        return rc;
    }
    asnber_schema_t *schema = nullptr;
    rc = loadSchema(ctx, root_type_id, &schema);
    if (rc != ASNBER_OK) {
        return rc;
    }
    asnber_encode_options_t options;
    asnber_encode_options_init(&options);
    options.schema = schema;
    rc = asnber_encode_buffer(ctx, doc, &options, out);
    asnber_schema_destroy(schema);
    if (rc != ASNBER_OK) {
        resetBuffer(out);
    }
    return rc;
}

/*
 * 预编码 [0] EXPLICIT 包装：包装内放 inner 的完整 TLV（原样），或放一个
 * content 为 inner 字节的 OCTET STRING（data 形态）。
 *
 * schema 感知编码要求 ContentInfo 的 content 字段以「携带整段包装 TLV 的
 * ANY 节点」出现，否则会退化成对运行时节点取原始切片并失败。因此这里先
 * 用一个独立文档编出包装字节，再整体作为 ANY 挂到 ContentInfo 下。
 */
asnber_err_t encodeContentWrapper(asnber_ctx_t *ctx, const uint8_t *inner,
                                size_t inner_size, bool as_octets,
                                asnber_buf_t *out_buf)
{
    resetBuffer(out_buf);
    asnber_doc_t *doc = nullptr;
    asnber_err_t rc = asnber_doc_create(ctx, &doc);
    if (rc != ASNBER_OK) {
        return rc;
    }
    asnber_node_t *wrapper = nullptr;
    asnber_node_t *child = nullptr;
    rc = createNode(doc, nullptr, ASNBER_TAG_CONTEXT, kTagContext0, 1, &wrapper);
    if (rc == ASNBER_OK) {
        rc = as_octets ? createOctetStringNode(doc, wrapper, inner, inner_size,
                                               &child)
                       : asnber_node_create_any(doc, wrapper, inner, inner_size,
                                              &child);
    }
    if (rc == ASNBER_OK) {
        rc = asnber_doc_seal(doc);
    }
    if (rc == ASNBER_OK) {
        rc = asnber_encode_buffer(ctx, doc, nullptr, out_buf);
    }
    asnber_doc_destroy(doc);
    if (rc != ASNBER_OK) {
        resetBuffer(out_buf);
    }
    return rc;
}

/*
 * ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }。
 * content 以完整 TLV 原样放入 [0] 包装，不做重编码。
 */
asnber_err_t buildContentInfo(asnber_ctx_t *ctx, asnber_doc_t *doc,
                            asnber_node_t *parent, const char *oid,
                            const uint8_t *content, size_t content_size,
                            bool as_octets, asnber_node_t **out_node)
{
    asnber_buf_t wrapper;
    asnber_err_t rc =
        encodeContentWrapper(ctx, content, content_size, as_octets, &wrapper);
    if (rc != ASNBER_OK) {
        return rc;
    }
    asnber_node_t *content_info = nullptr;
    rc = createNode(doc, parent, ASNBER_TAG_UNIVERSAL, kTagSequence, 1,
                    &content_info);
    if (rc == ASNBER_OK) {
        asnber_node_t *ignored = nullptr;
        rc = createOidNode(doc, content_info, oid, &ignored);
    }
    if (rc == ASNBER_OK) {
        asnber_node_t *ignored = nullptr;
        rc = asnber_node_create_any(doc, content_info, wrapper.data, wrapper.size,
                                  &ignored);
    }
    asnber_buf_release(ctx, &wrapper);
    if (rc != ASNBER_OK) {
        return rc;
    }
    *out_node = content_info;
    return ASNBER_OK;
}

} /* namespace */

struct asnber_pkcs12_authenticated_safe_builder {
    asnber_ctx_t *ctx;
    struct entry {
        bool is_data;
        byte_span payload;
    } *entries;
    size_t count;
    size_t capacity;
};

struct asnber_pkcs12_pfx_builder {
    asnber_ctx_t *ctx;
    bool version_set;
    int64_t version;

    bool auth_safe_set;
    char *auth_safe_type;
    byte_span auth_safe_content;

    bool mac_set;
    char *mac_digest_oid;
    byte_span mac_digest_params;
    byte_span mac_digest;
    byte_span mac_salt;
    int64_t mac_iterations;
};

/* ----------------------------- AuthenticatedSafe ------------------------- */

extern "C" ASNBER_PKCS12_API asnber_err_t
asnber_pkcs12_authenticated_safe_builder_create(
    asnber_ctx_t *ctx, asnber_pkcs12_authenticated_safe_builder_t **out_builder)
{
    if (ctx == nullptr || out_builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_builder = nullptr;
    asnber_pkcs12_authenticated_safe_builder_t *builder =
        static_cast<asnber_pkcs12_authenticated_safe_builder_t *>(
            std::malloc(sizeof(*builder)));
    if (builder == nullptr) {
        return ASNBER_E_NOMEM;
    }
    builder->ctx = ctx;
    builder->entries = nullptr;
    builder->count = 0;
    builder->capacity = 0;
    *out_builder = builder;
    return ASNBER_OK;
}

extern "C" ASNBER_PKCS12_API void asnber_pkcs12_authenticated_safe_builder_destroy(
    asnber_pkcs12_authenticated_safe_builder_t *builder)
{
    if (builder == nullptr) {
        return;
    }
    for (size_t i = 0; i < builder->count; ++i) {
        freeSpan(&builder->entries[i].payload);
    }
    std::free(builder->entries);
    std::free(builder);
}

namespace {

asnber_err_t appendEntry(asnber_pkcs12_authenticated_safe_builder_t *builder,
                       bool is_data, const uint8_t *payload, size_t size)
{
    if (!ensureCapacity(&builder->entries, builder->count,
                        &builder->capacity)) {
        return ASNBER_E_NOMEM;
    }
    builder->entries[builder->count].is_data = is_data;
    byte_span &span = builder->entries[builder->count].payload;
    span.data = nullptr;
    span.size = 0;
    if (!copySpan(&span, payload, size)) {
        return ASNBER_E_NOMEM;
    }
    ++builder->count;
    return ASNBER_OK;
}

} /* namespace */

extern "C" ASNBER_PKCS12_API asnber_err_t
asnber_pkcs12_authenticated_safe_builder_add_data(
    asnber_pkcs12_authenticated_safe_builder_t *builder,
    const uint8_t *safe_contents_der, size_t safe_contents_size)
{
    if (builder == nullptr || safe_contents_der == nullptr ||
        safe_contents_size == 0) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber_err_t rc = validateSingleDer(builder->ctx, safe_contents_der,
                                      safe_contents_size, nullptr);
    if (rc != ASNBER_OK) {
        return rc;
    }
    return appendEntry(builder, true, safe_contents_der, safe_contents_size);
}

extern "C" ASNBER_PKCS12_API asnber_err_t
asnber_pkcs12_authenticated_safe_builder_add_encrypted_data(
    asnber_pkcs12_authenticated_safe_builder_t *builder,
    const uint8_t *encrypted_data_tlv, size_t encrypted_data_size)
{
    if (builder == nullptr || encrypted_data_tlv == nullptr ||
        encrypted_data_size == 0) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber_err_t rc = validateSingleDer(builder->ctx, encrypted_data_tlv,
                                      encrypted_data_size, nullptr);
    if (rc != ASNBER_OK) {
        return rc;
    }
    return appendEntry(builder, false, encrypted_data_tlv,
                       encrypted_data_size);
}

extern "C" ASNBER_PKCS12_API asnber_err_t
asnber_pkcs12_authenticated_safe_builder_encode(
    asnber_pkcs12_authenticated_safe_builder_t *builder, asnber_buf_t *out_der)
{
    if (builder == nullptr || out_der == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    resetBuffer(out_der);

    asnber_doc_t *doc = nullptr;
    asnber_err_t rc = asnber_doc_create(builder->ctx, &doc);
    if (rc != ASNBER_OK) {
        return rc;
    }
    asnber_node_t *root = nullptr;
    rc = createNode(doc, nullptr, ASNBER_TAG_UNIVERSAL, kTagSequence, 1, &root);
    for (size_t i = 0; i < builder->count && rc == ASNBER_OK; ++i) {
        asnber_node_t *ignored = nullptr;
        const byte_span &payload = builder->entries[i].payload;
        if (builder->entries[i].is_data) {
            rc = buildContentInfo(builder->ctx, doc, root, kDataOid,
                                  payload.data, payload.size, true, &ignored);
        } else {
            rc = buildContentInfo(builder->ctx, doc, root, kEncryptedDataOid,
                                  payload.data, payload.size, false, &ignored);
        }
    }
    if (rc == ASNBER_OK) {
        rc = encodeDocument(builder->ctx, doc, kPkcs12RootAuthenticatedSafe,
                            out_der);
    }
    asnber_doc_destroy(doc);
    return rc;
}

/* ----------------------------------- PFX --------------------------------- */

extern "C" ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_pfx_builder_create(
    asnber_ctx_t *ctx, asnber_pkcs12_pfx_builder_t **out_builder)
{
    if (ctx == nullptr || out_builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_builder = nullptr;
    asnber_pkcs12_pfx_builder_t *builder =
        static_cast<asnber_pkcs12_pfx_builder_t *>(std::malloc(sizeof(*builder)));
    if (builder == nullptr) {
        return ASNBER_E_NOMEM;
    }
    std::memset(builder, 0, sizeof(*builder));
    builder->ctx = ctx;
    builder->version = kDefaultPfxVersion;
    builder->mac_iterations = 1;
    *out_builder = builder;
    return ASNBER_OK;
}

extern "C" ASNBER_PKCS12_API void asnber_pkcs12_pfx_builder_destroy(
    asnber_pkcs12_pfx_builder_t *builder)
{
    if (builder == nullptr) {
        return;
    }
    std::free(builder->auth_safe_type);
    freeSpan(&builder->auth_safe_content);
    std::free(builder->mac_digest_oid);
    freeSpan(&builder->mac_digest_params);
    freeSpan(&builder->mac_digest);
    freeSpan(&builder->mac_salt);
    std::free(builder);
}

extern "C" ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_pfx_builder_set_version(
    asnber_pkcs12_pfx_builder_t *builder, int64_t version)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->version_set) {
        return ASNBER_E_INVALID_STATE;
    }
    if (version < 0) {
        return ASNBER_E_INVALID_VALUE;
    }
    builder->version = version;
    builder->version_set = true;
    return ASNBER_OK;
}

extern "C" ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_pfx_builder_set_auth_safe(
    asnber_pkcs12_pfx_builder_t *builder, const char *content_type_oid,
    const uint8_t *content_tlv, size_t content_size)
{
    if (builder == nullptr || content_type_oid == nullptr ||
        content_tlv == nullptr || content_size == 0) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->auth_safe_set) {
        return ASNBER_E_INVALID_STATE;
    }
    asnber_err_t rc = validateOid(builder->ctx, content_type_oid);
    if (rc != ASNBER_OK) {
        return rc;
    }
    rc = validateSingleDer(builder->ctx, content_tlv, content_size, nullptr);
    if (rc != ASNBER_OK) {
        return rc;
    }
    char *type_copy = copyText(content_type_oid);
    if (type_copy == nullptr) {
        return ASNBER_E_NOMEM;
    }
    builder->auth_safe_type = type_copy;
    if (!copySpan(&builder->auth_safe_content, content_tlv, content_size)) {
        std::free(builder->auth_safe_type);
        builder->auth_safe_type = nullptr;
        return ASNBER_E_NOMEM;
    }
    builder->auth_safe_set = true;
    return ASNBER_OK;
}

extern "C" ASNBER_PKCS12_API asnber_err_t
asnber_pkcs12_pfx_builder_auth_safe_content_octets(
    const asnber_pkcs12_pfx_builder_t *builder, const uint8_t **out_data,
    size_t *out_size)
{
    if (builder == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_data = nullptr;
    *out_size = 0;
    if (!builder->auth_safe_set ||
        std::strcmp(builder->auth_safe_type, kDataOid) != 0) {
        return ASNBER_E_INVALID_STATE;
    }
    if (!octetsFromTlv(builder->auth_safe_content.data,
                       builder->auth_safe_content.size, out_data, out_size)) {
        return ASNBER_E_INVALID_STATE;
    }
    return ASNBER_OK;
}

extern "C" ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_pfx_builder_set_mac_data(
    asnber_pkcs12_pfx_builder_t *builder, const char *digest_algorithm_oid,
    const uint8_t *digest_algorithm_parameters,
    size_t digest_algorithm_parameters_size, const uint8_t *digest,
    size_t digest_size, const uint8_t *mac_salt, size_t mac_salt_size,
    int64_t iterations)
{
    if (builder == nullptr || digest_algorithm_oid == nullptr ||
        digest == nullptr || digest_size == 0 || mac_salt == nullptr ||
        mac_salt_size == 0) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->mac_set) {
        return ASNBER_E_INVALID_STATE;
    }
    if (iterations < 1) {
        return ASNBER_E_INVALID_VALUE;
    }
    asnber_err_t rc = validateOid(builder->ctx, digest_algorithm_oid);
    if (rc != ASNBER_OK) {
        return rc;
    }
    if (digest_algorithm_parameters_size != 0) {
        rc = validateSingleDer(builder->ctx, digest_algorithm_parameters,
                               digest_algorithm_parameters_size, nullptr);
        if (rc != ASNBER_OK) {
            return rc;
        }
    }

    char *oid_copy = copyText(digest_algorithm_oid);
    if (oid_copy == nullptr) {
        return ASNBER_E_NOMEM;
    }
    builder->mac_digest_oid = oid_copy;
    if ((digest_algorithm_parameters_size != 0 &&
         !copySpan(&builder->mac_digest_params, digest_algorithm_parameters,
                   digest_algorithm_parameters_size)) ||
        !copySpan(&builder->mac_digest, digest, digest_size) ||
        !copySpan(&builder->mac_salt, mac_salt, mac_salt_size)) {
        std::free(builder->mac_digest_oid);
        builder->mac_digest_oid = nullptr;
        freeSpan(&builder->mac_digest_params);
        freeSpan(&builder->mac_digest);
        freeSpan(&builder->mac_salt);
        return ASNBER_E_NOMEM;
    }
    builder->mac_iterations = iterations;
    builder->mac_set = true;
    return ASNBER_OK;
}

namespace {

/* MacData ::= SEQUENCE { mac DigestInfo, macSalt OCTET STRING, iterations OPT } */
asnber_err_t buildMacData(const asnber_pkcs12_pfx_builder_t &builder,
                        asnber_doc_t *doc, asnber_node_t *parent)
{
    asnber_node_t *mac_data = nullptr;
    asnber_err_t rc = createNode(doc, parent, ASNBER_TAG_UNIVERSAL, kTagSequence, 1,
                               &mac_data);
    if (rc != ASNBER_OK) {
        return rc;
    }
    asnber_node_t *digest_info = nullptr;
    rc = createNode(doc, mac_data, ASNBER_TAG_UNIVERSAL, kTagSequence, 1,
                    &digest_info);
    if (rc != ASNBER_OK) {
        return rc;
    }
    byte_span params;
    params.data = builder.mac_digest_params.data;
    params.size = builder.mac_digest_params.size;
    rc = addAlgorithmIdentifier(doc, digest_info, builder.mac_digest_oid,
                                params);
    if (rc != ASNBER_OK) {
        return rc;
    }
    asnber_node_t *ignored = nullptr;
    rc = createOctetStringNode(doc, digest_info, builder.mac_digest.data,
                               builder.mac_digest.size, &ignored);
    if (rc != ASNBER_OK) {
        return rc;
    }
    rc = createOctetStringNode(doc, mac_data, builder.mac_salt.data,
                               builder.mac_salt.size, &ignored);
    if (rc != ASNBER_OK) {
        return rc;
    }
    if (builder.mac_iterations != 1) {
        rc = createIntegerNode(doc, mac_data, builder.mac_iterations,
                               &ignored);
    }
    return rc;
}

} /* namespace */

extern "C" ASNBER_PKCS12_API asnber_err_t asnber_pkcs12_pfx_builder_encode(
    asnber_pkcs12_pfx_builder_t *builder, asnber_buf_t *out_der)
{
    if (builder == nullptr || out_der == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    resetBuffer(out_der);
    if (!builder->auth_safe_set) {
        return ASNBER_E_INVALID_STATE;
    }

    asnber_doc_t *doc = nullptr;
    asnber_err_t rc = asnber_doc_create(builder->ctx, &doc);
    if (rc != ASNBER_OK) {
        return rc;
    }
    asnber_node_t *root = nullptr;
    asnber_node_t *ignored = nullptr;
    rc = createNode(doc, nullptr, ASNBER_TAG_UNIVERSAL, kTagSequence, 1, &root);
    if (rc == ASNBER_OK) {
        rc = createIntegerNode(doc, root, builder->version, &ignored);
    }
    if (rc == ASNBER_OK) {
        rc = buildContentInfo(builder->ctx, doc, root,
                              builder->auth_safe_type,
                              builder->auth_safe_content.data,
                              builder->auth_safe_content.size, false, &ignored);
    }
    if (rc == ASNBER_OK && builder->mac_set) {
        rc = buildMacData(*builder, doc, root);
    }
    if (rc == ASNBER_OK) {
        rc = encodeDocument(builder->ctx, doc, kPkcs12RootPfx, out_der);
    }
    asnber_doc_destroy(doc);
    return rc;
}
