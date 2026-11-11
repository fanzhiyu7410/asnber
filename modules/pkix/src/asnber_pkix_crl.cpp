/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * CertificateList 打开与字段访问。只投影结构，不判断吊销。
 * 描述表默认根是 Certificate，这里用 load_with_root 指定 CertificateList。
 */

#include "asnber/pkix/pkix.h"

#include <asnber/asnber_schema.h>

#include <cstdlib>
#include <cstring>

#include "pkix_schema.h"

struct asnber_pkix_crl {
    asnber_ctx_t *ctx;
    asnber_schema_t *schema;
    asnber_doc_t *doc;
    const asnber_node_t *root;
};

namespace {

constexpr uint32_t kPkixFormatVersion = 1u << 16;
/* 完整表里 CertificateList 的类型编号。复核：
 * python 解析 generated/pkix_schema.h 的类型名表，CertificateList = 28。 */
constexpr uint32_t kPkixRootCertificateList = 28;

const char *canonicalSegment(const char *segment) noexcept
{
    if (std::strcmp(segment, "tbsCertList") == 0) {
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

asnber_err_t findPath(const asnber_pkix_crl_t *crl, const char *path,
                    const asnber_node_t **out_node) noexcept
{
    const asnber_node_t *node = crl->root;
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
        char *dot = nullptr;
        for (char *p = segment; *p != '\0'; ++p) {
            if (*p == '.') {
                dot = p;
                break;
            }
        }
        if (segment[0] == '\0') {
            status = ASNBER_E_INVALID_ARG;
            break;
        }
        if (dot != nullptr) {
            *dot = '\0';
        }
        node = asnber_node_child_by_name(node, canonicalSegment(segment));
        if (node == nullptr) {
            break;
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

asnber_err_t requireNode(const asnber_pkix_crl_t *crl, const char *path,
                       const asnber_node_t **out_node) noexcept
{
    asnber_err_t status = findPath(crl, path, out_node);
    if (status != ASNBER_OK) {
        return status;
    }
    if (*out_node == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    return ASNBER_OK;
}

asnber_err_t revokedEntry(const asnber_pkix_crl_t *crl, size_t index,
                        const asnber_node_t **out_entry) noexcept
{
    const asnber_node_t *list = nullptr;
    asnber_err_t status = findPath(crl, "tbsCertList.revokedCertificates", &list);
    if (status != ASNBER_OK) {
        return status;
    }
    if (list == nullptr || index >= asnber_node_child_count(list)) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_entry = asnber_node_child_at(list, index);
    if (*out_entry == nullptr) {
        return ASNBER_E_INVALID_STATE;
    }
    return ASNBER_OK;
}

asnber_err_t readTime(const asnber_node_t *node, asnber_time_t *out_time) noexcept
{
    asnber_time_t time;
    std::memset(&time, 0, sizeof(time));
    time.struct_size = sizeof(time);
    asnber_err_t status = asnber_node_get_time(node, &time);
    if (status != ASNBER_OK) {
        return status;
    }
    *out_time = time;
    return ASNBER_OK;
}

} /* namespace */

extern "C" ASNBER_PKIX_API asnber_err_t asnber_pkix_crl_open(
    asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asnber_pkix_crl_t **out_crl)
{
    if (ctx == nullptr || der == nullptr || der_size == 0 || out_crl == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_crl = nullptr;

    asnber_schema_table_t table;
    table.struct_size = sizeof(table);
    table.data = kPKIXFlattened2009Schema;
    table.size = kPKIXFlattened2009Schema_size;
    table.format_version = kPkixFormatVersion;
    table.reserved = 0;

    asnber_schema_t *schema = nullptr;
    asnber_err_t status = asnber_schema_load_with_root(
        ctx, &table, kPkixRootCertificateList, &schema);
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

    asnber_pkix_crl_t *crl =
        static_cast<asnber_pkix_crl_t *>(std::malloc(sizeof(*crl)));
    if (crl == nullptr) {
        asnber_doc_destroy(doc);
        asnber_schema_destroy(schema);
        return ASNBER_E_NOMEM;
    }
    crl->ctx = ctx;
    crl->schema = schema;
    crl->doc = doc;
    crl->root = asnber_doc_root(doc);
    *out_crl = crl;
    return ASNBER_OK;
}

extern "C" ASNBER_PKIX_API void asnber_pkix_crl_close(asnber_pkix_crl_t *crl)
{
    if (crl == nullptr) {
        return;
    }
    asnber_doc_destroy(crl->doc);
    asnber_schema_destroy(crl->schema);
    std::free(crl);
}

extern "C" ASNBER_PKIX_API asnber_err_t asnber_pkix_crl_find(
    const asnber_pkix_crl_t *crl, const char *path, const asnber_node_t **out_node)
{
    if (crl == nullptr || path == nullptr || out_node == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_node = nullptr;
    return findPath(crl, path, out_node);
}

extern "C" ASNBER_PKIX_API asnber_err_t asnber_pkix_crl_signature_algorithm_oid(
    const asnber_pkix_crl_t *crl, const char **out_dotted, size_t *out_size)
{
    if (crl == nullptr || out_dotted == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = nullptr;
    asnber_err_t status =
        requireNode(crl, "signatureAlgorithm.algorithm", &node);
    if (status != ASNBER_OK) {
        return status;
    }
    return asnber_node_get_oid(node, out_dotted, out_size);
}

extern "C" ASNBER_PKIX_API asnber_err_t asnber_pkix_crl_signature_value(
    const asnber_pkix_crl_t *crl, const uint8_t **out_data, size_t *out_size,
    size_t *out_bit_length, uint8_t *out_unused_bits)
{
    if (crl == nullptr || out_data == nullptr || out_size == nullptr ||
        out_bit_length == nullptr || out_unused_bits == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = nullptr;
    asnber_err_t status = requireNode(crl, "signatureValue", &node);
    if (status != ASNBER_OK) {
        return status;
    }
    return asnber_node_get_bits(node, out_data, out_size, out_bit_length,
                              out_unused_bits);
}

extern "C" ASNBER_PKIX_API asnber_err_t asnber_pkix_crl_issuer_der(
    const asnber_pkix_crl_t *crl, const uint8_t **out_data, size_t *out_size)
{
    if (crl == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = nullptr;
    asnber_err_t status = requireNode(crl, "tbsCertList.issuer", &node);
    if (status != ASNBER_OK) {
        return status;
    }
    *out_data = asnber_node_tlv(node, out_size);
    return (*out_data == nullptr) ? ASNBER_E_INVALID_STATE : ASNBER_OK;
}

extern "C" ASNBER_PKIX_API asnber_err_t asnber_pkix_crl_version(
    const asnber_pkix_crl_t *crl, uint32_t *out_version)
{
    if (crl == nullptr || out_version == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = nullptr;
    asnber_err_t status = findPath(crl, "tbsCertList.version", &node);
    if (status != ASNBER_OK) {
        return status;
    }
    if (node == nullptr) {
        *out_version = 0;
        return ASNBER_OK;
    }
    int64_t value = 0;
    status = asnber_node_get_int64(node, &value);
    if (status != ASNBER_OK) {
        return status;
    }
    if (value < 0 || value > 2) {
        return ASNBER_E_INVALID_VALUE;
    }
    *out_version = static_cast<uint32_t>(value);
    return ASNBER_OK;
}

extern "C" ASNBER_PKIX_API asnber_err_t asnber_pkix_crl_this_update(
    const asnber_pkix_crl_t *crl, asnber_time_t *out_time)
{
    if (crl == nullptr || out_time == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = nullptr;
    asnber_err_t status = requireNode(crl, "tbsCertList.thisUpdate", &node);
    if (status != ASNBER_OK) {
        return status;
    }
    return readTime(node, out_time);
}

extern "C" ASNBER_PKIX_API asnber_err_t asnber_pkix_crl_next_update(
    const asnber_pkix_crl_t *crl, asnber_time_t *out_time, int *out_present)
{
    if (crl == nullptr || out_time == nullptr || out_present == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = nullptr;
    asnber_err_t status = findPath(crl, "tbsCertList.nextUpdate", &node);
    if (status != ASNBER_OK) {
        return status;
    }
    if (node == nullptr) {
        *out_present = 0;
        return ASNBER_OK;
    }
    status = readTime(node, out_time);
    if (status != ASNBER_OK) {
        return status;
    }
    *out_present = 1;
    return ASNBER_OK;
}

extern "C" ASNBER_PKIX_API asnber_err_t asnber_pkix_crl_revoked_count(
    const asnber_pkix_crl_t *crl, size_t *out_count)
{
    if (crl == nullptr || out_count == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *list = nullptr;
    asnber_err_t status = findPath(crl, "tbsCertList.revokedCertificates", &list);
    if (status != ASNBER_OK) {
        return status;
    }
    *out_count = (list == nullptr) ? 0 : asnber_node_child_count(list);
    return ASNBER_OK;
}

extern "C" ASNBER_PKIX_API asnber_err_t asnber_pkix_crl_revoked_serial(
    const asnber_pkix_crl_t *crl, size_t index, const char **out_decimal,
    size_t *out_size)
{
    if (crl == nullptr || out_decimal == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *entry = nullptr;
    asnber_err_t status = revokedEntry(crl, index, &entry);
    if (status != ASNBER_OK) {
        return status;
    }
    const asnber_node_t *serial =
        asnber_node_child_by_name(entry, "userCertificate");
    if (serial == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    return asnber_node_get_bigint_decimal(serial, out_decimal, out_size);
}

const asnber_node_t *unwrapExplicit(const asnber_node_t *node) noexcept
{
    if (node != nullptr && asnber_node_tag_class(node) == ASNBER_TAG_CONTEXT &&
        asnber_node_child_count(node) == 1) {
        return asnber_node_child_at(node, 0);
    }
    return node;
}

asnber_err_t extensionList(const asnber_pkix_crl_t *crl, const char *path,
                         const asnber_node_t **out_list) noexcept
{
    const asnber_node_t *node = nullptr;
    asnber_err_t status = findPath(crl, path, &node);
    if (status != ASNBER_OK) {
        return status;
    }
    *out_list = unwrapExplicit(node);
    return ASNBER_OK;
}

asnber_err_t extensionAt(const asnber_node_t *list, size_t index,
                       const char **out_oid, size_t *out_oid_size,
                       int *out_critical, const uint8_t **out_value,
                       size_t *out_value_size) noexcept
{
    if (list == nullptr || index >= asnber_node_child_count(list)) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *extension = asnber_node_child_at(list, index);
    const asnber_node_t *oid = asnber_node_child_by_name(extension, "extnID");
    const asnber_node_t *value = asnber_node_child_by_name(extension, "extnValue");
    if (oid == nullptr || value == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    const char *dotted = nullptr;
    size_t dotted_size = 0;
    asnber_err_t status = asnber_node_get_oid(oid, &dotted, &dotted_size);
    if (status != ASNBER_OK) {
        return status;
    }
    const uint8_t *octets = nullptr;
    size_t octets_size = 0;
    status = asnber_node_get_octets(value, &octets, &octets_size);
    if (status != ASNBER_OK) {
        return status;
    }
    int critical = 0;
    const asnber_node_t *flag = asnber_node_child_by_name(extension, "critical");
    if (flag != nullptr) {
        status = asnber_node_get_bool(flag, &critical);
        if (status != ASNBER_OK) {
            return status;
        }
    }
    *out_oid = dotted;
    *out_oid_size = dotted_size;
    *out_critical = critical;
    *out_value = octets;
    *out_value_size = octets_size;
    return ASNBER_OK;
}

extern "C" ASNBER_PKIX_API asnber_err_t asnber_pkix_crl_revoked_date(
    const asnber_pkix_crl_t *crl, size_t index, asnber_time_t *out_time)
{
    if (crl == nullptr || out_time == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *entry = nullptr;
    asnber_err_t status = revokedEntry(crl, index, &entry);
    if (status != ASNBER_OK) {
        return status;
    }
    const asnber_node_t *when =
        asnber_node_child_by_name(entry, "revocationDate");
    if (when == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    return readTime(when, out_time);
}

extern "C" ASNBER_PKIX_API asnber_err_t asnber_pkix_crl_extension_count(
    const asnber_pkix_crl_t *crl, size_t *out_count)
{
    if (crl == nullptr || out_count == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *list = nullptr;
    asnber_err_t status = extensionList(crl, "tbsCertList.crlExtensions", &list);
    if (status != ASNBER_OK) {
        return status;
    }
    *out_count = list == nullptr ? 0 : asnber_node_child_count(list);
    return ASNBER_OK;
}

extern "C" ASNBER_PKIX_API asnber_err_t asnber_pkix_crl_extension_at(
    const asnber_pkix_crl_t *crl, size_t index, const char **out_oid,
    size_t *out_oid_size, int *out_critical, const uint8_t **out_value,
    size_t *out_value_size)
{
    if (crl == nullptr || out_oid == nullptr || out_oid_size == nullptr ||
        out_critical == nullptr || out_value == nullptr ||
        out_value_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *list = nullptr;
    asnber_err_t status = extensionList(crl, "tbsCertList.crlExtensions", &list);
    if (status != ASNBER_OK) {
        return status;
    }
    return extensionAt(list, index, out_oid, out_oid_size, out_critical, out_value,
                       out_value_size);
}

extern "C" ASNBER_PKIX_API asnber_err_t asnber_pkix_crl_entry_extension_count(
    const asnber_pkix_crl_t *crl, size_t revoked_index, size_t *out_count)
{
    if (crl == nullptr || out_count == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *entry = nullptr;
    asnber_err_t status = revokedEntry(crl, revoked_index, &entry);
    if (status != ASNBER_OK) {
        return status;
    }
    const asnber_node_t *list =
        asnber_node_child_by_name(entry, "crlEntryExtensions");
    *out_count = list == nullptr ? 0 : asnber_node_child_count(list);
    return ASNBER_OK;
}

extern "C" ASNBER_PKIX_API asnber_err_t asnber_pkix_crl_entry_extension_at(
    const asnber_pkix_crl_t *crl, size_t revoked_index, size_t index,
    const char **out_oid, size_t *out_oid_size, int *out_critical,
    const uint8_t **out_value, size_t *out_value_size)
{
    if (crl == nullptr || out_oid == nullptr || out_oid_size == nullptr ||
        out_critical == nullptr || out_value == nullptr ||
        out_value_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *entry = nullptr;
    asnber_err_t status = revokedEntry(crl, revoked_index, &entry);
    if (status != ASNBER_OK) {
        return status;
    }
    const asnber_node_t *list =
        asnber_node_child_by_name(entry, "crlEntryExtensions");
    return extensionAt(list, index, out_oid, out_oid_size, out_critical, out_value,
                       out_value_size);
}
