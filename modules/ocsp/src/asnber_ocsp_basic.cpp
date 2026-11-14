/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * BasicOCSPResponse 打开与字段访问。只投影结构，不验签、不判断证书状态、
 * 不解释扩展，也不核对 responseType。
 */

#include "ocsp_internal.h"

#include <cstdint>
#include <cstring>

namespace {

const asnber_node_t *tbsResponse(const asnber_ocsp_basic_t *basic) noexcept
{
    return asnber_node_child_by_name(basic->root, "tbsResponseData");
}

asnber_err_t responseList(const asnber_ocsp_basic_t *basic,
                          const asnber_node_t **out_list) noexcept
{
    const asnber_node_t *tbs = tbsResponse(basic);
    if (tbs == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    const asnber_node_t *list = asnber_node_child_by_name(tbs, "responses");
    if (list == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    *out_list = list;
    return ASNBER_OK;
}

asnber_err_t responseAt(const asnber_ocsp_basic_t *basic, size_t index,
                        const asnber_node_t **out_item) noexcept
{
    const asnber_node_t *list = nullptr;
    asnber_err_t status = responseList(basic, &list);
    if (status != ASNBER_OK) {
        return status;
    }
    if (index >= asnber_node_child_count(list)) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_item = asnber_node_child_at(list, index);
    return ASNBER_OK;
}

asnber_err_t extensionList(const asnber_node_t *parent, const char *name,
                           const asnber_node_t **out_list) noexcept
{
    if (parent == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    *out_list = ocspUnwrapExplicit(asnber_node_child_by_name(parent, name));
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

asnber_err_t certStatus(const asnber_ocsp_basic_t *basic, size_t index,
                        const asnber_node_t **out_status) noexcept
{
    const asnber_node_t *item = nullptr;
    asnber_err_t status = responseAt(basic, index, &item);
    if (status != ASNBER_OK) {
        return status;
    }
    const asnber_node_t *node = asnber_node_child_by_name(item, "certStatus");
    if (node == nullptr || asnber_node_tag_class(node) != ASNBER_TAG_CONTEXT) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    *out_status = node;
    return ASNBER_OK;
}

} // namespace

extern "C" ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_open(
    asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asnber_ocsp_basic_t **out_basic)
{
    return ocspOpenBasic(ctx, der, der_size, out_basic);
}

extern "C" ASNBER_OCSP_API void asnber_ocsp_basic_close(asnber_ocsp_basic_t *basic)
{
    ocspCloseBasic(basic);
}

extern "C" ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_version(
    const asnber_ocsp_basic_t *basic, uint32_t *out_version)
{
    if (basic == nullptr || out_version == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *tbs = tbsResponse(basic);
    if (tbs == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    const asnber_node_t *version = asnber_node_child_by_name(tbs, "version");
    if (version == nullptr) {
        *out_version = 0;
        return ASNBER_OK;
    }

    int64_t value = 0;
    asnber_err_t status =
        asnber_node_get_int64(ocspUnwrapExplicit(version), &value);
    if (status != ASNBER_OK) {
        return status;
    }
    if (value < 0 || static_cast<uint64_t>(value) > UINT32_MAX) {
        return ASNBER_E_INVALID_VALUE;
    }
    *out_version = static_cast<uint32_t>(value);
    return ASNBER_OK;
}

extern "C" ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_responder(
    const asnber_ocsp_basic_t *basic, int *out_choice, const uint8_t **out_name,
    size_t *out_name_size, const uint8_t **out_key, size_t *out_key_size)
{
    if (basic == nullptr || out_choice == nullptr || out_name == nullptr ||
        out_name_size == nullptr || out_key == nullptr ||
        out_key_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *tbs = tbsResponse(basic);
    if (tbs == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    const asnber_node_t *responder =
        asnber_node_child_by_name(tbs, "responderID");
    if (responder == nullptr ||
        asnber_node_tag_class(responder) != ASNBER_TAG_CONTEXT) {
        return ASNBER_E_SCHEMA_FIELD;
    }

    const uint32_t tag = asnber_node_tag_number(responder);
    if (tag == 1) {
        const uint8_t *name = nullptr;
        size_t name_size = 0;
        /* EXPLICIT ANY 的 content 是内层 Name TLV，不含外层 [1]。 */
        asnber_err_t status = asnber_node_content(responder, &name, &name_size);
        if (status != ASNBER_OK || name == nullptr) {
            return status != ASNBER_OK ? status : ASNBER_E_INVALID_STATE;
        }
        *out_choice = 1;
        *out_name = name;
        *out_name_size = name_size;
        *out_key = nullptr;
        *out_key_size = 0;
        return ASNBER_OK;
    }
    if (tag == 2) {
        const uint8_t *key = nullptr;
        size_t key_size = 0;
        asnber_err_t status = asnber_node_get_octets(
            ocspUnwrapExplicit(responder), &key, &key_size);
        if (status != ASNBER_OK) {
            return status;
        }
        *out_choice = 2;
        *out_name = nullptr;
        *out_name_size = 0;
        *out_key = key;
        *out_key_size = key_size;
        return ASNBER_OK;
    }
    return ASNBER_E_SCHEMA_TYPE;
}

extern "C" ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_produced_at(
    const asnber_ocsp_basic_t *basic, asnber_time_t *out_time)
{
    if (basic == nullptr || out_time == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *tbs = tbsResponse(basic);
    if (tbs == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    const asnber_node_t *produced = asnber_node_child_by_name(tbs, "producedAt");
    if (produced == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    return readTime(produced, out_time);
}

extern "C" ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_response_count(
    const asnber_ocsp_basic_t *basic, size_t *out_count)
{
    if (basic == nullptr || out_count == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *list = nullptr;
    asnber_err_t status = responseList(basic, &list);
    if (status != ASNBER_OK) {
        return status;
    }
    *out_count = asnber_node_child_count(list);
    return ASNBER_OK;
}

extern "C" ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_cert_id(
    const asnber_ocsp_basic_t *basic, size_t index, const char **out_hash_oid,
    size_t *out_hash_oid_size, const uint8_t **out_hash_params,
    size_t *out_hash_params_size, int *out_hash_params_present,
    const uint8_t **out_name_hash, size_t *out_name_hash_size,
    const uint8_t **out_key_hash, size_t *out_key_hash_size,
    const char **out_serial, size_t *out_serial_size)
{
    if (basic == nullptr || out_hash_oid == nullptr ||
        out_hash_oid_size == nullptr || out_hash_params == nullptr ||
        out_hash_params_size == nullptr || out_hash_params_present == nullptr ||
        out_name_hash == nullptr || out_name_hash_size == nullptr ||
        out_key_hash == nullptr || out_key_hash_size == nullptr ||
        out_serial == nullptr || out_serial_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }

    const asnber_node_t *item = nullptr;
    asnber_err_t status = responseAt(basic, index, &item);
    if (status != ASNBER_OK) {
        return status;
    }
    const asnber_node_t *cert_id = asnber_node_child_by_name(item, "certID");
    if (cert_id == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    const asnber_node_t *hash =
        asnber_node_child_by_name(cert_id, "hashAlgorithm");
    const asnber_node_t *name_hash =
        asnber_node_child_by_name(cert_id, "issuerNameHash");
    const asnber_node_t *key_hash =
        asnber_node_child_by_name(cert_id, "issuerKeyHash");
    const asnber_node_t *serial =
        asnber_node_child_by_name(cert_id, "serialNumber");
    if (hash == nullptr || name_hash == nullptr || key_hash == nullptr ||
        serial == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }

    const char *oid = nullptr;
    size_t oid_size = 0;
    const uint8_t *params = nullptr;
    size_t params_size = 0;
    int params_present = 0;
    status = ocspReadAlgorithm(hash, &oid, &oid_size, &params, &params_size,
                               &params_present);
    if (status != ASNBER_OK) {
        return status;
    }

    const uint8_t *name_bytes = nullptr;
    size_t name_size = 0;
    status = asnber_node_get_octets(name_hash, &name_bytes, &name_size);
    if (status != ASNBER_OK) {
        return status;
    }
    const uint8_t *key_bytes = nullptr;
    size_t key_size = 0;
    status = asnber_node_get_octets(key_hash, &key_bytes, &key_size);
    if (status != ASNBER_OK) {
        return status;
    }
    const char *decimal = nullptr;
    size_t decimal_size = 0;
    status = asnber_node_get_bigint_decimal(serial, &decimal, &decimal_size);
    if (status != ASNBER_OK) {
        return status;
    }

    *out_hash_oid = oid;
    *out_hash_oid_size = oid_size;
    *out_hash_params = params;
    *out_hash_params_size = params_size;
    *out_hash_params_present = params_present;
    *out_name_hash = name_bytes;
    *out_name_hash_size = name_size;
    *out_key_hash = key_bytes;
    *out_key_hash_size = key_size;
    *out_serial = decimal;
    *out_serial_size = decimal_size;
    return ASNBER_OK;
}

extern "C" ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_cert_status(
    const asnber_ocsp_basic_t *basic, size_t index, int *out_status)
{
    if (basic == nullptr || out_status == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = nullptr;
    asnber_err_t status = certStatus(basic, index, &node);
    if (status != ASNBER_OK) {
        return status;
    }
    const uint32_t tag = asnber_node_tag_number(node);
    if (tag > 2) {
        return ASNBER_E_SCHEMA_TYPE;
    }
    *out_status = static_cast<int>(tag);
    return ASNBER_OK;
}

extern "C" ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_revocation(
    const asnber_ocsp_basic_t *basic, size_t index, asnber_time_t *out_time,
    int64_t *out_reason, int *out_reason_present)
{
    if (basic == nullptr || out_time == nullptr || out_reason == nullptr ||
        out_reason_present == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *node = nullptr;
    asnber_err_t status = certStatus(basic, index, &node);
    if (status != ASNBER_OK) {
        return status;
    }
    if (asnber_node_tag_number(node) != 1) {
        return ASNBER_E_INVALID_ARG;
    }

    const asnber_node_t *when =
        asnber_node_child_by_name(node, "revocationTime");
    if (when == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    asnber_time_t time;
    status = readTime(when, &time);
    if (status != ASNBER_OK) {
        return status;
    }

    int64_t reason = 0;
    int present = 0;
    const asnber_node_t *reason_node =
        asnber_node_child_by_name(node, "revocationReason");
    if (reason_node != nullptr) {
        status = asnber_node_get_int64(ocspUnwrapExplicit(reason_node), &reason);
        if (status != ASNBER_OK) {
            return status;
        }
        present = 1;
    }

    *out_time = time;
    *out_reason = reason;
    *out_reason_present = present;
    return ASNBER_OK;
}

extern "C" ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_this_update(
    const asnber_ocsp_basic_t *basic, size_t index, asnber_time_t *out_time)
{
    if (basic == nullptr || out_time == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *item = nullptr;
    asnber_err_t status = responseAt(basic, index, &item);
    if (status != ASNBER_OK) {
        return status;
    }
    const asnber_node_t *when = asnber_node_child_by_name(item, "thisUpdate");
    if (when == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    return readTime(when, out_time);
}

extern "C" ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_next_update(
    const asnber_ocsp_basic_t *basic, size_t index, asnber_time_t *out_time,
    int *out_present)
{
    if (basic == nullptr || out_time == nullptr || out_present == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *item = nullptr;
    asnber_err_t status = responseAt(basic, index, &item);
    if (status != ASNBER_OK) {
        return status;
    }
    const asnber_node_t *when = asnber_node_child_by_name(item, "nextUpdate");
    if (when == nullptr) {
        *out_present = 0;
        return ASNBER_OK;
    }
    status = readTime(ocspUnwrapExplicit(when), out_time);
    if (status != ASNBER_OK) {
        return status;
    }
    *out_present = 1;
    return ASNBER_OK;
}

extern "C" ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_single_extension_count(
    const asnber_ocsp_basic_t *basic, size_t response_index, size_t *out_count)
{
    if (basic == nullptr || out_count == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *item = nullptr;
    asnber_err_t status = responseAt(basic, response_index, &item);
    if (status != ASNBER_OK) {
        return status;
    }
    const asnber_node_t *list = nullptr;
    status = extensionList(item, "singleExtensions", &list);
    if (status != ASNBER_OK) {
        return status;
    }
    *out_count = (list == nullptr) ? 0 : asnber_node_child_count(list);
    return ASNBER_OK;
}

extern "C" ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_single_extension_at(
    const asnber_ocsp_basic_t *basic, size_t response_index, size_t index,
    const char **out_oid, size_t *out_oid_size, int *out_critical,
    const uint8_t **out_value, size_t *out_value_size)
{
    if (basic == nullptr || out_oid == nullptr || out_oid_size == nullptr ||
        out_critical == nullptr || out_value == nullptr ||
        out_value_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *item = nullptr;
    asnber_err_t status = responseAt(basic, response_index, &item);
    if (status != ASNBER_OK) {
        return status;
    }
    const asnber_node_t *list = nullptr;
    status = extensionList(item, "singleExtensions", &list);
    if (status != ASNBER_OK) {
        return status;
    }
    return ocspExtensionAt(list, index, out_oid, out_oid_size, out_critical,
                           out_value, out_value_size);
}

extern "C" ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_extension_count(
    const asnber_ocsp_basic_t *basic, size_t *out_count)
{
    if (basic == nullptr || out_count == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *list = nullptr;
    asnber_err_t status =
        extensionList(tbsResponse(basic), "responseExtensions", &list);
    if (status != ASNBER_OK) {
        return status;
    }
    *out_count = (list == nullptr) ? 0 : asnber_node_child_count(list);
    return ASNBER_OK;
}

extern "C" ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_extension_at(
    const asnber_ocsp_basic_t *basic, size_t index, const char **out_oid,
    size_t *out_oid_size, int *out_critical, const uint8_t **out_value,
    size_t *out_value_size)
{
    if (basic == nullptr || out_oid == nullptr || out_oid_size == nullptr ||
        out_critical == nullptr || out_value == nullptr ||
        out_value_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *list = nullptr;
    asnber_err_t status =
        extensionList(tbsResponse(basic), "responseExtensions", &list);
    if (status != ASNBER_OK) {
        return status;
    }
    return ocspExtensionAt(list, index, out_oid, out_oid_size, out_critical,
                           out_value, out_value_size);
}

extern "C" ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_signature(
    const asnber_ocsp_basic_t *basic, const char **out_oid, size_t *out_oid_size,
    const uint8_t **out_params, size_t *out_params_size, int *out_params_present,
    const uint8_t **out_bits, size_t *out_bits_size, size_t *out_bit_length,
    uint8_t *out_unused_bits, size_t *out_cert_count)
{
    if (basic == nullptr || out_oid == nullptr || out_oid_size == nullptr ||
        out_params == nullptr || out_params_size == nullptr ||
        out_params_present == nullptr || out_bits == nullptr ||
        out_bits_size == nullptr || out_bit_length == nullptr ||
        out_unused_bits == nullptr || out_cert_count == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }

    const asnber_node_t *algorithm =
        asnber_node_child_by_name(basic->root, "signatureAlgorithm");
    const asnber_node_t *bits = asnber_node_child_by_name(basic->root, "signature");
    if (algorithm == nullptr || bits == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }

    const char *oid = nullptr;
    size_t oid_size = 0;
    const uint8_t *params = nullptr;
    size_t params_size = 0;
    int params_present = 0;
    asnber_err_t status = ocspReadAlgorithm(algorithm, &oid, &oid_size, &params,
                                            &params_size, &params_present);
    if (status != ASNBER_OK) {
        return status;
    }

    const uint8_t *bit_bytes = nullptr;
    size_t bit_size = 0;
    size_t bit_length = 0;
    uint8_t unused = 0;
    status = asnber_node_get_bits(bits, &bit_bytes, &bit_size, &bit_length,
                                  &unused);
    if (status != ASNBER_OK) {
        return status;
    }

    const asnber_node_t *certs = ocspUnwrapExplicit(
        asnber_node_child_by_name(basic->root, "certs"));
    const size_t cert_count =
        (certs == nullptr) ? 0 : asnber_node_child_count(certs);

    *out_oid = oid;
    *out_oid_size = oid_size;
    *out_params = params;
    *out_params_size = params_size;
    *out_params_present = params_present;
    *out_bits = bit_bytes;
    *out_bits_size = bit_size;
    *out_bit_length = bit_length;
    *out_unused_bits = unused;
    *out_cert_count = cert_count;
    return ASNBER_OK;
}

extern "C" ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_signature_cert(
    const asnber_ocsp_basic_t *basic, size_t index, const uint8_t **out_data,
    size_t *out_size)
{
    if (basic == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *certs = ocspUnwrapExplicit(
        asnber_node_child_by_name(basic->root, "certs"));
    if (certs == nullptr || index >= asnber_node_child_count(certs)) {
        return ASNBER_E_INVALID_ARG;
    }
    const uint8_t *bytes =
        asnber_node_tlv(asnber_node_child_at(certs, index), out_size);
    if (bytes == nullptr) {
        return ASNBER_E_INVALID_STATE;
    }
    *out_data = bytes;
    return ASNBER_OK;
}
