/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

#include "ocsp_internal.h"

#include "ocsp_tables.h"

#include <cstdlib>

namespace {

constexpr uint32_t kOcspFormatVersion = 1u << 16;

template <typename T>
asnber_err_t openWithRoot(asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
                          uint32_t root_type_id, T **out_object) noexcept
{
    if (ctx == nullptr || der == nullptr || der_size == 0 ||
        out_object == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_object = nullptr;

    const ocsp_table_view table = ocspSchemaTable();
    asnber_schema_table_t schema_table;
    schema_table.struct_size = sizeof(schema_table);
    schema_table.data = table.data;
    schema_table.size = table.size;
    schema_table.format_version = kOcspFormatVersion;
    schema_table.reserved = 0;

    asnber_schema_t *schema = nullptr;
    asnber_err_t status = asnber_schema_load_with_root(ctx, &schema_table,
                                                       root_type_id, &schema);
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

    T *object = static_cast<T *>(std::malloc(sizeof(T)));
    if (object == nullptr) {
        asnber_doc_destroy(doc);
        asnber_schema_destroy(schema);
        return ASNBER_E_NOMEM;
    }

    object->ctx = ctx;
    object->schema = schema;
    object->doc = doc;
    object->root = asnber_doc_root(doc);
    *out_object = object;
    return ASNBER_OK;
}

template <typename T>
void closeObject(T *object) noexcept
{
    if (object == nullptr) {
        return;
    }
    asnber_doc_destroy(object->doc);
    asnber_schema_destroy(object->schema);
    std::free(object);
}

} // namespace

asnber_err_t ocspOpenRequest(asnber_ctx_t *ctx, const uint8_t *der,
                             size_t der_size,
                             asnber_ocsp_request_t **out_request) noexcept
{
    return openWithRoot(ctx, der, der_size, kOcspRootRequest, out_request);
}

asnber_err_t ocspOpenResponse(asnber_ctx_t *ctx, const uint8_t *der,
                              size_t der_size,
                              asnber_ocsp_response_t **out_response) noexcept
{
    return openWithRoot(ctx, der, der_size, kOcspRootResponse, out_response);
}

void ocspCloseRequest(asnber_ocsp_request_t *request) noexcept
{
    closeObject(request);
}

void ocspCloseResponse(asnber_ocsp_response_t *response) noexcept
{
    closeObject(response);
}

const asnber_node_t *ocspUnwrapExplicit(const asnber_node_t *node) noexcept
{
    if (node != nullptr && asnber_node_tag_class(node) == ASNBER_TAG_CONTEXT &&
        asnber_node_child_count(node) == 1) {
        return asnber_node_child_at(node, 0);
    }
    return node;
}

asnber_err_t ocspReadAlgorithm(const asnber_node_t *algorithm,
                               const char **out_oid, size_t *out_oid_size,
                               const uint8_t **out_params, size_t *out_params_size,
                               int *out_params_present) noexcept
{
    if (algorithm == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    const asnber_node_t *oid = asnber_node_child_by_name(algorithm, "algorithm");
    if (oid == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    const char *dotted = nullptr;
    size_t dotted_size = 0;
    asnber_err_t status = asnber_node_get_oid(oid, &dotted, &dotted_size);
    if (status != ASNBER_OK) {
        return status;
    }

    const uint8_t *params = nullptr;
    size_t params_size = 0;
    int present = 0;
    const asnber_node_t *param_node =
        asnber_node_child_by_name(algorithm, "parameters");
    if (param_node != nullptr) {
        params = asnber_node_tlv(param_node, &params_size);
        if (params == nullptr) {
            return ASNBER_E_INVALID_STATE;
        }
        present = 1;
    }

    *out_oid = dotted;
    *out_oid_size = dotted_size;
    *out_params = params;
    *out_params_size = params_size;
    *out_params_present = present;
    return ASNBER_OK;
}

asnber_err_t ocspExtensionAt(const asnber_node_t *list, size_t index,
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
