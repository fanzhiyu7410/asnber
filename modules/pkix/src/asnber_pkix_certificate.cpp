/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-pkix 证书打开、路径查找与便捷字段访问。
 *
 * 职责：用随模块发布的 PKIX 描述表加载 schema，按 DER 严格模式解码
 *       Certificate，并把常用字段投影为核心节点/值。
 * 依赖：只使用核心公共 C ABI（asnber/asnber*.h）；生成表由 asnberc 产出。
 * 所有权：句柄持有 schema 与文档，close 时逆序释放；访问器返回的指针
 *         借用句柄，close 后失效。
 * 线程：模块没有全局可变状态；不同句柄/上下文互不影响。同一 ctx 的
 *       并发使用需由调用方加锁（核心错误状态挂在 ctx 上）。
 */

#include "asnber/pkix/pkix.h"

#include <asnber/asnber_schema.h>

#include <cstdlib>
#include <cstring>

/* 由 asnberc 生成；ASNBER_PKIX_REGENERATE_TABLE=ON 时来自构建目录。 */
#include "pkix_schema.h"

struct asnber_pkix_certificate {
    asnber_ctx_t *ctx;
    asnber_schema_t *schema;
    asnber_doc_t *doc;
    const asnber_node_t *root;
};

namespace {

constexpr uint32_t kPkixFormatVersion = 1u << 16;

/*
 * 展平模块把 SIGNED{T} 展开为具名字段 toBeSigned / algorithmIdentifier /
 * signature；对外同时接受 RFC 5280 的常用叫法，避免调用方记两套名字。
 */
const char *canonicalSegment(const char *segment) noexcept
{
    if (std::strcmp(segment, "tbsCertificate") == 0) {
        return "toBeSigned";
    }
    if (std::strcmp(segment, "signatureAlgorithm") == 0) {
        return "algorithmIdentifier";
    }
    if (std::strcmp(segment, "signatureValue") == 0) {
        return "signature";
    }
    return segment;
}

/* 沿 '.' 逐段查找；空串返回根。调用方保证输出参数非空。 */
asnber_err_t findPath(const asnber_pkix_certificate_t *cert, const char *path,
                    const asnber_node_t **out_node) noexcept
{
    const asnber_node_t *node = cert->root;
    if (path[0] == '\0') {
        *out_node = node;
        return ASNBER_OK;
    }

    const size_t length = std::strlen(path);
    char *copy = static_cast<char *>(std::malloc(length + 1));
    if (copy == nullptr) {
        return ASNBER_E_NOMEM;
    }
    std::memcpy(copy, path, length + 1);

    asnber_err_t status = ASNBER_OK;
    char *segment = copy;
    while (segment != nullptr) {
        if (segment[0] == '\0') {
            status = ASNBER_E_INVALID_ARG;
            break;
        }
        char *dot = std::strchr(segment, '.');
        if (dot == segment) {
            status = ASNBER_E_INVALID_ARG;
            break;
        }
        if (dot != nullptr) {
            *dot = '\0';
        }
        node = asnber_node_child_by_name(node, canonicalSegment(segment));
        if (node == nullptr) {
            break; /* 路径不存在：按“无节点”返回，不报错 */
        }
        segment = (dot == nullptr) ? nullptr : dot + 1;
    }

    std::free(copy);
    if (status != ASNBER_OK) {
        return status;
    }
    *out_node = node;
    return ASNBER_OK;
}

/* 剥掉 [n] EXPLICIT 外层包装，返回内层节点。 */
const asnber_node_t *unwrapExplicit(const asnber_node_t *node) noexcept
{
    if (node != nullptr && asnber_node_tag_class(node) == ASNBER_TAG_CONTEXT &&
        asnber_node_child_count(node) == 1) {
        return asnber_node_child_at(node, 0);
    }
    return node;
}

asnber_err_t requireNode(const asnber_pkix_certificate_t *cert, const char *path,
                       const asnber_node_t **out_node) noexcept
{
    asnber_err_t status = findPath(cert, path, out_node);
    if (status != ASNBER_OK) {
        return status;
    }
    if (*out_node == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    return ASNBER_OK;
}

} // namespace

extern "C" ASNBER_PKIX_API asnber_err_t asnber_pkix_certificate_open(
    asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asnber_pkix_certificate_t **out_cert)
{
    if (ctx == nullptr || der == nullptr || der_size == 0 ||
        out_cert == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_cert = nullptr;

    asnber_schema_table_t table;
    table.struct_size = sizeof(table);
    table.data = kPKIXFlattened2009Schema;
    table.size = kPKIXFlattened2009Schema_size;
    table.format_version = kPkixFormatVersion;
    table.reserved = 0;

    asnber_schema_t *schema = nullptr;
    asnber_err_t status = asnber_schema_load(ctx, &table, &schema);
    if (status != ASNBER_OK) {
        return status;
    }

    asnber_decode_options_t options;
    asnber_decode_options_init(&options);
    options.encoding = ASNBER_ENCODING_DER;
    options.flags = ASNBER_DECODE_COPY_INPUT;

    asnber_doc_t *doc = nullptr;
    size_t consumed = 0;
    status = asnber_decode_buffer_with_schema(ctx, der, der_size, schema,
                                            &options, &doc, &consumed);
    if (status != ASNBER_OK) {
        asnber_schema_destroy(schema);
        return status;
    }

    asnber_pkix_certificate_t *cert =
        static_cast<asnber_pkix_certificate_t *>(std::malloc(sizeof(*cert)));
    if (cert == nullptr) {
        asnber_doc_destroy(doc);
        asnber_schema_destroy(schema);
        return ASNBER_E_NOMEM;
    }

    cert->ctx = ctx;
    cert->schema = schema;
    cert->doc = doc;
    cert->root = asnber_doc_root(doc);
    *out_cert = cert;
    return ASNBER_OK;
}

extern "C" ASNBER_PKIX_API void asnber_pkix_certificate_close(
    asnber_pkix_certificate_t *cert)
{
    if (cert == nullptr) {
        return;
    }
    asnber_doc_destroy(cert->doc);
    asnber_schema_destroy(cert->schema);
    std::free(cert);
}

extern "C" ASNBER_PKIX_API asnber_err_t asnber_pkix_certificate_find(
    const asnber_pkix_certificate_t *cert, const char *path,
    const asnber_node_t **out_node)
{
    if (cert == nullptr || path == nullptr || out_node == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_node = nullptr;
    return findPath(cert, path, out_node);
}

extern "C" ASNBER_PKIX_API asnber_err_t
asnber_pkix_certificate_signature_algorithm_oid(
    const asnber_pkix_certificate_t *cert, const char **out_dotted,
    size_t *out_size)
{
    if (cert == nullptr || out_dotted == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = nullptr;
    asnber_err_t status =
        requireNode(cert, "signatureAlgorithm.algorithm", &node);
    if (status != ASNBER_OK) {
        return status;
    }
    return asnber_node_get_oid(node, out_dotted, out_size);
}

extern "C" ASNBER_PKIX_API asnber_err_t asnber_pkix_certificate_signature_value(
    const asnber_pkix_certificate_t *cert, const uint8_t **out_data,
    size_t *out_size, size_t *out_bit_length, uint8_t *out_unused_bits)
{
    if (cert == nullptr || out_data == nullptr || out_size == nullptr ||
        out_bit_length == nullptr || out_unused_bits == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = nullptr;
    asnber_err_t status = requireNode(cert, "signatureValue", &node);
    if (status != ASNBER_OK) {
        return status;
    }
    return asnber_node_get_bits(node, out_data, out_size, out_bit_length,
                              out_unused_bits);
}

extern "C" ASNBER_PKIX_API asnber_err_t asnber_pkix_certificate_serial_number(
    const asnber_pkix_certificate_t *cert, const char **out_decimal,
    size_t *out_size)
{
    if (cert == nullptr || out_decimal == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = nullptr;
    asnber_err_t status =
        requireNode(cert, "tbsCertificate.serialNumber", &node);
    if (status != ASNBER_OK) {
        return status;
    }
    return asnber_node_get_bigint_decimal(node, out_decimal, out_size);
}

extern "C" ASNBER_PKIX_API asnber_err_t asnber_pkix_certificate_version(
    const asnber_pkix_certificate_t *cert, uint32_t *out_version)
{
    if (cert == nullptr || out_version == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }

    const asnber_node_t *node = nullptr;
    asnber_err_t status = findPath(cert, "tbsCertificate.version", &node);
    if (status != ASNBER_OK) {
        return status;
    }
    if (node == nullptr) {
        *out_version = 0; /* DEFAULT v1 */
        return ASNBER_OK;
    }

    int64_t value = 0;
    status = asnber_node_get_int64(unwrapExplicit(node), &value);
    if (status != ASNBER_OK) {
        return status;
    }
    if (value < 0 || value > 2) {
        return ASNBER_E_INVALID_VALUE;
    }
    *out_version = static_cast<uint32_t>(value);
    return ASNBER_OK;
}

extern "C" ASNBER_PKIX_API asnber_err_t asnber_pkix_certificate_issuer_der(
    const asnber_pkix_certificate_t *cert, const uint8_t **out_data,
    size_t *out_size)
{
    if (cert == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = nullptr;
    asnber_err_t status = requireNode(cert, "tbsCertificate.issuer", &node);
    if (status != ASNBER_OK) {
        return status;
    }
    *out_data = asnber_node_tlv(node, out_size);
    return (*out_data == nullptr) ? ASNBER_E_INVALID_STATE : ASNBER_OK;
}

extern "C" ASNBER_PKIX_API asnber_err_t asnber_pkix_certificate_subject_der(
    const asnber_pkix_certificate_t *cert, const uint8_t **out_data,
    size_t *out_size)
{
    if (cert == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = nullptr;
    asnber_err_t status = requireNode(cert, "tbsCertificate.subject", &node);
    if (status != ASNBER_OK) {
        return status;
    }
    *out_data = asnber_node_tlv(node, out_size);
    return (*out_data == nullptr) ? ASNBER_E_INVALID_STATE : ASNBER_OK;
}

extern "C" ASNBER_PKIX_API asnber_err_t asnber_pkix_certificate_validity(
    const asnber_pkix_certificate_t *cert, asnber_time_t *out_not_before,
    asnber_time_t *out_not_after)
{
    if (cert == nullptr || out_not_before == nullptr ||
        out_not_after == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }

    const asnber_node_t *before_node = nullptr;
    asnber_err_t status = requireNode(
        cert, "tbsCertificate.validity.notBefore", &before_node);
    if (status != ASNBER_OK) {
        return status;
    }
    const asnber_node_t *after_node = nullptr;
    status = requireNode(cert, "tbsCertificate.validity.notAfter",
                         &after_node);
    if (status != ASNBER_OK) {
        return status;
    }

    asnber_time_t before;
    asnber_time_t after;
    before.struct_size = sizeof(before);
    after.struct_size = sizeof(after);

    status = asnber_node_get_time(before_node, &before);
    if (status != ASNBER_OK) {
        return status;
    }
    status = asnber_node_get_time(after_node, &after);
    if (status != ASNBER_OK) {
        return status;
    }

    *out_not_before = before;
    *out_not_after = after;
    return ASNBER_OK;
}
