/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-pkix Certificate builder 的扩展部分：通用扩展与便捷函数。
 *
 * 与主流程分开实现，只为把单个翻译单元控制在文件规模上限内；两条路径
 * 共享 pkix_builder_internal.h 中的 builder 状态，不新增导出符号。
 */

#include <asnber/pkix/pkix.h>

#include "detail/module_builder_support.h"
#include "detail/x509_primitives.h"
#include "pkix_builder_internal.h"

#include <cstdlib>
#include <cstring>

using asnber::module_detail::copyBytes;
using asnber::module_detail::copyText;
using asnber::module_detail::createBitStringNode;
using asnber::module_detail::createBooleanNode;
using asnber::module_detail::createIntegerNode;
using asnber::module_detail::createNode;
using asnber::module_detail::createOidNode;
using asnber::module_detail::ensureCapacity;
using asnber::module_detail::extension_entry;
using asnber::module_detail::kTagSequence;
using asnber::module_detail::validateOid;
using asnber::module_detail::validateSingleDer;

namespace {

constexpr const char *kBasicConstraintsOid = "2.5.29.19";
constexpr const char *kKeyUsageOid = "2.5.29.15";
constexpr const char *kExtendedKeyUsageOid = "2.5.29.37";

void resetBuffer(asnber_buf_t *buf)
{
    buf->data = nullptr;
    buf->size = 0;
    buf->capacity = 0;
}

/* 通用 DER 编码：独立文档 seal 后无 schema 编码。 */
asnber_err_t encodeDocument(asnber_ctx_t *ctx, asnber_doc_t *doc, asnber_buf_t *out)
{
    resetBuffer(out);
    asnber_err_t rc = asnber_doc_seal(doc);
    if (rc != ASNBER_OK) {
        return rc;
    }
    asnber_encode_options_t options;
    asnber_encode_options_init(&options);
    rc = asnber_encode_buffer(ctx, doc, &options, out);
    if (rc != ASNBER_OK) {
        resetBuffer(out);
    }
    return rc;
}

/* BasicConstraints ::= SEQUENCE { cA DEFAULT FALSE, pathLenConstraint OPT }. */
asnber_err_t buildBasicConstraints(asnber_ctx_t *ctx, bool is_ca, bool has_path_len,
                                 uint32_t path_len, asnber_buf_t *out)
{
    asnber_doc_t *doc = nullptr;
    asnber_err_t rc = asnber_doc_create(ctx, &doc);
    if (rc != ASNBER_OK) {
        return rc;
    }
    asnber_node_t *root = nullptr;
    asnber_node_t *ignored = nullptr;
    rc = createNode(doc, nullptr, ASNBER_TAG_UNIVERSAL, kTagSequence, 1, &root);
    if (rc == ASNBER_OK && is_ca) {
        rc = createBooleanNode(doc, root, true, &ignored);
    }
    if (rc == ASNBER_OK && has_path_len) {
        rc = createIntegerNode(doc, root, static_cast<int64_t>(path_len),
                               &ignored);
    }
    if (rc == ASNBER_OK) {
        rc = encodeDocument(ctx, doc, out);
    }
    asnber_doc_destroy(doc);
    return rc;
}

/* KeyUsage ::= BIT STRING。 */
asnber_err_t buildKeyUsage(asnber_ctx_t *ctx, const uint8_t *bits, size_t size,
                         uint8_t unused_bits, asnber_buf_t *out)
{
    asnber_doc_t *doc = nullptr;
    asnber_err_t rc = asnber_doc_create(ctx, &doc);
    if (rc != ASNBER_OK) {
        return rc;
    }
    asnber_node_t *root = nullptr;
    rc = createBitStringNode(doc, nullptr, bits, size, unused_bits, &root);
    if (rc == ASNBER_OK) {
        rc = encodeDocument(ctx, doc, out);
    }
    asnber_doc_destroy(doc);
    return rc;
}

/* ExtendedKeyUsage ::= SEQUENCE OF KeyPurposeId。 */
asnber_err_t buildExtendedKeyUsage(asnber_ctx_t *ctx, const char *const *oids,
                                 size_t count, asnber_buf_t *out)
{
    asnber_doc_t *doc = nullptr;
    asnber_err_t rc = asnber_doc_create(ctx, &doc);
    if (rc != ASNBER_OK) {
        return rc;
    }
    asnber_node_t *root = nullptr;
    rc = createNode(doc, nullptr, ASNBER_TAG_UNIVERSAL, kTagSequence, 1, &root);
    for (size_t i = 0; i < count && rc == ASNBER_OK; ++i) {
        asnber_node_t *ignored = nullptr;
        rc = createOidNode(doc, root, oids[i], &ignored);
    }
    if (rc == ASNBER_OK) {
        rc = encodeDocument(ctx, doc, out);
    }
    asnber_doc_destroy(doc);
    return rc;
}

/* 追加已在 builder 内校验过的扩展值（深拷贝）。调用方保证 OID 不重复。 */
asnber_err_t appendExtension(asnber_pkix_certificate_builder_t *builder,
                           const char *oid, bool critical,
                           const uint8_t *value, size_t value_size)
{
    if (!ensureCapacity(&builder->extensions, builder->extension_count,
                        &builder->extension_capacity)) {
        return ASNBER_E_NOMEM;
    }
    char *oid_copy = copyText(oid);
    uint8_t *value_copy = copyBytes(value, value_size);
    if (oid_copy == nullptr || value_copy == nullptr) {
        std::free(oid_copy);
        std::free(value_copy);
        return ASNBER_E_NOMEM;
    }
    extension_entry &entry = builder->extensions[builder->extension_count++];
    entry.oid = oid_copy;
    entry.critical = critical;
    entry.value = value_copy;
    entry.value_size = value_size;
    return ASNBER_OK;
}

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

bool hasExtension(const asnber_pkix_certificate_builder_t *builder,
                  const char *oid)
{
    for (size_t i = 0; i < builder->extension_count; ++i) {
        if (std::strcmp(builder->extensions[i].oid, oid) == 0) {
            return true;
        }
    }
    return false;
}

/* 便捷函数共用：编码扩展值后按统一规则追加。 */
asnber_err_t appendBuiltExtension(asnber_pkix_certificate_builder_t *builder,
                                const char *oid, int critical,
                                asnber_buf_t *value)
{
    if (hasExtension(builder, oid)) {
        asnber_buf_release(builder->ctx, value);
        return ASNBER_E_INVALID_VALUE;
    }
    asnber_err_t rc = appendExtension(builder, oid, critical != 0, value->data,
                                    value->size);
    asnber_buf_release(builder->ctx, value);
    return rc;
}

} /* namespace */

extern "C" ASNBER_PKIX_API asnber_err_t
asnber_pkix_certificate_builder_add_extension(
    asnber_pkix_certificate_builder_t *builder, const char *extn_oid,
    int critical, const uint8_t *extn_value_der, size_t extn_value_size)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber_err_t rc =
        checkExtension(builder->ctx, extn_oid, extn_value_der, extn_value_size);
    if (rc != ASNBER_OK) {
        return rc;
    }
    if (hasExtension(builder, extn_oid)) {
        return ASNBER_E_INVALID_VALUE;
    }
    return appendExtension(builder, extn_oid, critical != 0, extn_value_der,
                           extn_value_size);
}

extern "C" ASNBER_PKIX_API asnber_err_t
asnber_pkix_certificate_builder_add_basic_constraints(
    asnber_pkix_certificate_builder_t *builder, int critical, int is_ca,
    int has_path_len, uint32_t path_len)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (is_ca == 0 && has_path_len != 0) {
        return ASNBER_E_INVALID_VALUE;
    }
    asnber_buf_t value;
    asnber_err_t rc = buildBasicConstraints(builder->ctx, is_ca != 0,
                                          has_path_len != 0, path_len, &value);
    if (rc != ASNBER_OK) {
        return rc;
    }
    return appendBuiltExtension(builder, kBasicConstraintsOid, critical,
                                &value);
}

extern "C" ASNBER_PKIX_API asnber_err_t
asnber_pkix_certificate_builder_add_key_usage(
    asnber_pkix_certificate_builder_t *builder, int critical,
    const uint8_t *bits, size_t size, uint8_t unused_bits)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber_buf_t value;
    asnber_err_t rc = buildKeyUsage(builder->ctx, bits, size, unused_bits, &value);
    if (rc != ASNBER_OK) {
        return rc;
    }
    return appendBuiltExtension(builder, kKeyUsageOid, critical, &value);
}

extern "C" ASNBER_PKIX_API asnber_err_t
asnber_pkix_certificate_builder_add_extended_key_usage(
    asnber_pkix_certificate_builder_t *builder, int critical,
    const char *const *oids, size_t count)
{
    if (builder == nullptr || oids == nullptr || count == 0) {
        return ASNBER_E_INVALID_ARG;
    }
    for (size_t i = 0; i < count; ++i) {
        if (oids[i] == nullptr) {
            return ASNBER_E_INVALID_ARG;
        }
        asnber_err_t rc = validateOid(builder->ctx, oids[i]);
        if (rc != ASNBER_OK) {
            return rc;
        }
    }
    asnber_buf_t value;
    asnber_err_t rc = buildExtendedKeyUsage(builder->ctx, oids, count, &value);
    if (rc != ASNBER_OK) {
        return rc;
    }
    return appendBuiltExtension(builder, kExtendedKeyUsageOid, critical,
                                &value);
}
