/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * OCSPResponse 打开与字段访问。response 保持为 OCTET STRING 内容，
 * 不在这里解码成 BasicOCSPResponse。
 */

#include "ocsp_internal.h"

namespace {

void clearResponseBytes(const char **out_type_oid, size_t *out_type_oid_size,
                        const uint8_t **out_response, size_t *out_response_size,
                        int *out_present) noexcept
{
    *out_type_oid = nullptr;
    *out_type_oid_size = 0;
    *out_response = nullptr;
    *out_response_size = 0;
    *out_present = 0;
}

} // namespace

extern "C" ASNBER_OCSP_API asnber_err_t asnber_ocsp_response_open(
    asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asnber_ocsp_response_t **out_response)
{
    return ocspOpenResponse(ctx, der, der_size, out_response);
}

extern "C" ASNBER_OCSP_API void asnber_ocsp_response_close(
    asnber_ocsp_response_t *response)
{
    ocspCloseResponse(response);
}

extern "C" ASNBER_OCSP_API asnber_err_t asnber_ocsp_response_status(
    const asnber_ocsp_response_t *response, int64_t *out_status)
{
    if (response == nullptr || out_status == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber_node_t *status_node =
        asnber_node_child_by_name(response->root, "responseStatus");
    if (status_node == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    return asnber_node_get_int64(status_node, out_status);
}

extern "C" ASNBER_OCSP_API asnber_err_t asnber_ocsp_response_bytes(
    const asnber_ocsp_response_t *response, const char **out_type_oid,
    size_t *out_type_oid_size, const uint8_t **out_response,
    size_t *out_response_size, int *out_present)
{
    if (response == nullptr || out_type_oid == nullptr ||
        out_type_oid_size == nullptr || out_response == nullptr ||
        out_response_size == nullptr || out_present == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }

    int64_t status_value = 0;
    asnber_err_t status = asnber_ocsp_response_status(response, &status_value);
    if (status != ASNBER_OK) {
        return status;
    }
    if (status_value != 0) {
        clearResponseBytes(out_type_oid, out_type_oid_size, out_response,
                           out_response_size, out_present);
        return ASNBER_OK;
    }

    const asnber_node_t *bytes =
        asnber_node_child_by_name(response->root, "responseBytes");
    if (bytes == nullptr) {
        clearResponseBytes(out_type_oid, out_type_oid_size, out_response,
                           out_response_size, out_present);
        return ASNBER_OK;
    }

    const asnber_node_t *inner = ocspUnwrapExplicit(bytes);
    const asnber_node_t *type_oid =
        asnber_node_child_by_name(inner, "responseType");
    const asnber_node_t *content = asnber_node_child_by_name(inner, "response");
    if (type_oid == nullptr || content == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }

    const char *dotted = nullptr;
    size_t dotted_size = 0;
    status = asnber_node_get_oid(type_oid, &dotted, &dotted_size);
    if (status != ASNBER_OK) {
        return status;
    }
    const uint8_t *payload = nullptr;
    size_t payload_size = 0;
    status = asnber_node_get_octets(content, &payload, &payload_size);
    if (status != ASNBER_OK) {
        return status;
    }

    *out_type_oid = dotted;
    *out_type_oid_size = dotted_size;
    *out_response = payload;
    *out_response_size = payload_size;
    *out_present = 1;
    return ASNBER_OK;
}
