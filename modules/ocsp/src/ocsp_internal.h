/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-ocsp 句柄与字段访问工具（私有）。
 * 这些符号不导出，只供模块自身编译单元使用。
 */

#ifndef ASNBER_OCSP_INTERNAL_H_INCLUDED
#define ASNBER_OCSP_INTERNAL_H_INCLUDED

#include <asnber/ocsp/ocsp.h>

#include <asnber/asnber_node.h>
#include <asnber/asnber_schema.h>

struct asnber_ocsp_request {
    asnber_ctx_t *ctx;
    asnber_schema_t *schema;
    asnber_doc_t *doc;
    const asnber_node_t *root;
};

struct asnber_ocsp_response {
    asnber_ctx_t *ctx;
    asnber_schema_t *schema;
    asnber_doc_t *doc;
    const asnber_node_t *root;
};

struct asnber_ocsp_basic {
    asnber_ctx_t *ctx;
    asnber_schema_t *schema;
    asnber_doc_t *doc;
    const asnber_node_t *root;
};

asnber_err_t ocspOpenRequest(asnber_ctx_t *ctx, const uint8_t *der,
                             size_t der_size,
                             asnber_ocsp_request_t **out_request) noexcept;

asnber_err_t ocspOpenResponse(asnber_ctx_t *ctx, const uint8_t *der,
                              size_t der_size,
                              asnber_ocsp_response_t **out_response) noexcept;

asnber_err_t ocspOpenBasic(asnber_ctx_t *ctx, const uint8_t *der,
                           size_t der_size,
                           asnber_ocsp_basic_t **out_basic) noexcept;

void ocspCloseRequest(asnber_ocsp_request_t *request) noexcept;
void ocspCloseResponse(asnber_ocsp_response_t *response) noexcept;
void ocspCloseBasic(asnber_ocsp_basic_t *basic) noexcept;

const asnber_node_t *ocspUnwrapExplicit(const asnber_node_t *node) noexcept;

asnber_err_t ocspReadAlgorithm(const asnber_node_t *algorithm,
                               const char **out_oid, size_t *out_oid_size,
                               const uint8_t **out_params, size_t *out_params_size,
                               int *out_params_present) noexcept;

asnber_err_t ocspExtensionAt(const asnber_node_t *list, size_t index,
                             const char **out_oid, size_t *out_oid_size,
                             int *out_critical, const uint8_t **out_value,
                             size_t *out_value_size) noexcept;

#endif /* ASNBER_OCSP_INTERNAL_H_INCLUDED */
