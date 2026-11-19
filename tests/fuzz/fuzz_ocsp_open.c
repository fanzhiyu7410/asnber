/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * libFuzzer harness：asnber-ocsp 三个根的打开与只读访问面。
 *
 * 同一输入依次按 OCSPRequest、OCSPResponse、BasicOCSPResponse 尝试 open。
 * 若响应带 responseBytes，再用内容字节打开 BasicOCSPResponse。判据只有
 * 崩溃 / ASan / LSan；任何错误码都属于正常行为。
 */
#include <asnber/ocsp/ocsp.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "fuzz_common.h"

static void probe_indices(size_t count, void (*fn)(size_t, void *), void *ctx)
{
    static const size_t kExtra[] = {0u, SIZE_MAX};
    size_t i;

    fn(0u, ctx);
    if (count > 0u) {
        fn(count - 1u, ctx);
    }
    fn(count, ctx);
    for (i = 0; i < sizeof(kExtra) / sizeof(kExtra[0]); ++i) {
        fn(kExtra[i], ctx);
    }
}

static void scan_request_cert_id(size_t index, void *ctx)
{
    const asnber_ocsp_request_t *request = (const asnber_ocsp_request_t *)ctx;
    const char *oid = NULL;
    size_t oid_size = 0;
    const uint8_t *params = NULL;
    size_t params_size = 0;
    int params_present = 0;
    const uint8_t *name_hash = NULL;
    size_t name_hash_size = 0;
    const uint8_t *key_hash = NULL;
    size_t key_hash_size = 0;
    const char *serial = NULL;
    size_t serial_size = 0;

    (void)asnber_ocsp_request_cert_id(
        request, index, &oid, &oid_size, &params, &params_size,
        &params_present, &name_hash, &name_hash_size, &key_hash,
        &key_hash_size, &serial, &serial_size);
    (void)asnber_ocsp_request_cert_id(request, index, NULL, &oid_size, &params,
                                      &params_size, &params_present, &name_hash,
                                      &name_hash_size, &key_hash, &key_hash_size,
                                      &serial, &serial_size);
}

static void scan_request_extension(size_t index, void *ctx)
{
    const asnber_ocsp_request_t *request = (const asnber_ocsp_request_t *)ctx;
    const char *oid = NULL;
    size_t oid_size = 0;
    int critical = 0;
    const uint8_t *value = NULL;
    size_t value_size = 0;

    (void)asnber_ocsp_request_extension_at(request, index, &oid, &oid_size,
                                           &critical, &value, &value_size);
    (void)asnber_ocsp_request_extension_at(request, index, NULL, &oid_size,
                                           &critical, &value, &value_size);
}

typedef struct {
    const asnber_ocsp_request_t *request;
    size_t request_index;
} request_single_ext_ctx;

static void scan_request_single_extension(size_t index, void *ctx)
{
    request_single_ext_ctx *env = (request_single_ext_ctx *)ctx;
    const char *oid = NULL;
    size_t oid_size = 0;
    int critical = 0;
    const uint8_t *value = NULL;
    size_t value_size = 0;

    (void)asnber_ocsp_request_single_extension_at(
        env->request, env->request_index, index, &oid, &oid_size, &critical,
        &value, &value_size);
}

static void scan_request_sig_cert(size_t index, void *ctx)
{
    const asnber_ocsp_request_t *request = (const asnber_ocsp_request_t *)ctx;
    const uint8_t *data = NULL;
    size_t size = 0;

    (void)asnber_ocsp_request_signature_cert(request, index, &data, &size);
    (void)asnber_ocsp_request_signature_cert(request, index, NULL, &size);
}

static void scan_request(const asnber_ocsp_request_t *request)
{
    uint32_t version = 0;
    size_t count = 0;
    size_t ext_count = 0;
    size_t i;
    const uint8_t *bytes = NULL;
    size_t bytes_size = 0;
    int present = 0;
    const char *oid = NULL;
    size_t oid_size = 0;
    const uint8_t *params = NULL;
    size_t params_size = 0;
    int params_present = 0;
    const uint8_t *bits = NULL;
    size_t bits_size = 0;
    size_t bit_length = 0;
    uint8_t unused_bits = 0;
    size_t cert_count = 0;

    (void)asnber_ocsp_request_version(request, &version);
    (void)asnber_ocsp_request_version(request, NULL);
    (void)asnber_ocsp_request_count(request, &count);
    (void)asnber_ocsp_request_count(request, NULL);
    probe_indices(count, scan_request_cert_id, (void *)request);

    for (i = 0; i < count && i < 4u; ++i) {
        size_t single_count = 0;
        request_single_ext_ctx env;

        (void)asnber_ocsp_request_single_extension_count(request, i,
                                                         &single_count);
        env.request = request;
        env.request_index = i;
        probe_indices(single_count, scan_request_single_extension, &env);
    }

    (void)asnber_ocsp_request_requestor(request, &bytes, &bytes_size, &present);
    (void)asnber_ocsp_request_requestor(request, NULL, &bytes_size, &present);
    (void)asnber_ocsp_request_requestor(request, &bytes, NULL, &present);
    (void)asnber_ocsp_request_requestor(request, &bytes, &bytes_size, NULL);

    (void)asnber_ocsp_request_extension_count(request, &ext_count);
    probe_indices(ext_count, scan_request_extension, (void *)request);

    (void)asnber_ocsp_request_signature(
        request, &oid, &oid_size, &params, &params_size, &params_present, &bits,
        &bits_size, &bit_length, &unused_bits, &cert_count, &present);
    (void)asnber_ocsp_request_signature(request, NULL, &oid_size, &params,
                                        &params_size, &params_present, &bits,
                                        &bits_size, &bit_length, &unused_bits,
                                        &cert_count, &present);
    probe_indices(cert_count, scan_request_sig_cert, (void *)request);
}

static void scan_basic_cert_id(size_t index, void *ctx)
{
    const asnber_ocsp_basic_t *basic = (const asnber_ocsp_basic_t *)ctx;
    const char *oid = NULL;
    size_t oid_size = 0;
    const uint8_t *params = NULL;
    size_t params_size = 0;
    int params_present = 0;
    const uint8_t *name_hash = NULL;
    size_t name_hash_size = 0;
    const uint8_t *key_hash = NULL;
    size_t key_hash_size = 0;
    const char *serial = NULL;
    size_t serial_size = 0;
    int status = 0;
    asnber_time_t time_value;
    int64_t reason = 0;
    int reason_present = 0;
    int present = 0;

    (void)asnber_ocsp_basic_cert_id(
        basic, index, &oid, &oid_size, &params, &params_size, &params_present,
        &name_hash, &name_hash_size, &key_hash, &key_hash_size, &serial,
        &serial_size);
    (void)asnber_ocsp_basic_cert_status(basic, index, &status);
    (void)asnber_ocsp_basic_cert_status(basic, index, NULL);

    memset(&time_value, 0, sizeof(time_value));
    (void)asnber_ocsp_basic_revocation(basic, index, &time_value, &reason,
                                       &reason_present);
    (void)asnber_ocsp_basic_revocation(basic, index, NULL, &reason,
                                       &reason_present);

    memset(&time_value, 0, sizeof(time_value));
    (void)asnber_ocsp_basic_this_update(basic, index, &time_value);
    (void)asnber_ocsp_basic_this_update(basic, index, NULL);

    memset(&time_value, 0, sizeof(time_value));
    (void)asnber_ocsp_basic_next_update(basic, index, &time_value, &present);
    (void)asnber_ocsp_basic_next_update(basic, index, NULL, &present);
    (void)asnber_ocsp_basic_next_update(basic, index, &time_value, NULL);
}

typedef struct {
    const asnber_ocsp_basic_t *basic;
    size_t response_index;
} basic_single_ext_ctx;

static void scan_basic_single_extension(size_t index, void *ctx)
{
    basic_single_ext_ctx *env = (basic_single_ext_ctx *)ctx;
    const char *oid = NULL;
    size_t oid_size = 0;
    int critical = 0;
    const uint8_t *value = NULL;
    size_t value_size = 0;

    (void)asnber_ocsp_basic_single_extension_at(
        env->basic, env->response_index, index, &oid, &oid_size, &critical,
        &value, &value_size);
}

static void scan_basic_extension(size_t index, void *ctx)
{
    const asnber_ocsp_basic_t *basic = (const asnber_ocsp_basic_t *)ctx;
    const char *oid = NULL;
    size_t oid_size = 0;
    int critical = 0;
    const uint8_t *value = NULL;
    size_t value_size = 0;

    (void)asnber_ocsp_basic_extension_at(basic, index, &oid, &oid_size,
                                         &critical, &value, &value_size);
}

static void scan_basic_sig_cert(size_t index, void *ctx)
{
    const asnber_ocsp_basic_t *basic = (const asnber_ocsp_basic_t *)ctx;
    const uint8_t *data = NULL;
    size_t size = 0;

    (void)asnber_ocsp_basic_signature_cert(basic, index, &data, &size);
}

static void scan_basic(const asnber_ocsp_basic_t *basic)
{
    uint32_t version = 0;
    int choice = 0;
    const uint8_t *name = NULL;
    size_t name_size = 0;
    const uint8_t *key = NULL;
    size_t key_size = 0;
    asnber_time_t produced_at;
    size_t count = 0;
    size_t ext_count = 0;
    size_t i;
    const char *oid = NULL;
    size_t oid_size = 0;
    const uint8_t *params = NULL;
    size_t params_size = 0;
    int params_present = 0;
    const uint8_t *bits = NULL;
    size_t bits_size = 0;
    size_t bit_length = 0;
    uint8_t unused_bits = 0;
    size_t cert_count = 0;

    (void)asnber_ocsp_basic_version(basic, &version);
    (void)asnber_ocsp_basic_version(basic, NULL);

    (void)asnber_ocsp_basic_responder(basic, &choice, &name, &name_size, &key,
                                      &key_size);
    (void)asnber_ocsp_basic_responder(basic, NULL, &name, &name_size, &key,
                                      &key_size);

    memset(&produced_at, 0, sizeof(produced_at));
    (void)asnber_ocsp_basic_produced_at(basic, &produced_at);
    (void)asnber_ocsp_basic_produced_at(basic, NULL);

    (void)asnber_ocsp_basic_response_count(basic, &count);
    probe_indices(count, scan_basic_cert_id, (void *)basic);

    for (i = 0; i < count && i < 4u; ++i) {
        size_t single_count = 0;
        basic_single_ext_ctx env;

        (void)asnber_ocsp_basic_single_extension_count(basic, i, &single_count);
        env.basic = basic;
        env.response_index = i;
        probe_indices(single_count, scan_basic_single_extension, &env);
    }

    (void)asnber_ocsp_basic_extension_count(basic, &ext_count);
    probe_indices(ext_count, scan_basic_extension, (void *)basic);

    (void)asnber_ocsp_basic_signature(
        basic, &oid, &oid_size, &params, &params_size, &params_present, &bits,
        &bits_size, &bit_length, &unused_bits, &cert_count);
    (void)asnber_ocsp_basic_signature(basic, NULL, &oid_size, &params,
                                      &params_size, &params_present, &bits,
                                      &bits_size, &bit_length, &unused_bits,
                                      &cert_count);
    probe_indices(cert_count, scan_basic_sig_cert, (void *)basic);
}

static void open_and_scan_basic(asnber_ctx_t *ctx, const uint8_t *data,
                                size_t size)
{
    asnber_ocsp_basic_t *basic = NULL;
    asnber_err_t status = asnber_ocsp_basic_open(ctx, data, size, &basic);
    if (status == ASNBER_OK && basic != NULL) {
        scan_basic(basic);
        asnber_ocsp_basic_close(basic);
        basic = NULL;
        asnber_ocsp_basic_close(basic);
    } else {
        asnber_ocsp_basic_close(basic);
        basic = NULL;
        asnber_ocsp_basic_close(basic);
    }
}

static void scan_response(asnber_ctx_t *ctx,
                          const asnber_ocsp_response_t *response)
{
    int64_t status_value = 0;
    const char *type_oid = NULL;
    size_t type_oid_size = 0;
    const uint8_t *content = NULL;
    size_t content_size = 0;
    int present = 0;

    (void)asnber_ocsp_response_status(response, &status_value);
    (void)asnber_ocsp_response_status(response, NULL);

    (void)asnber_ocsp_response_bytes(response, &type_oid, &type_oid_size,
                                     &content, &content_size, &present);
    (void)asnber_ocsp_response_bytes(response, NULL, &type_oid_size, &content,
                                     &content_size, &present);
    (void)asnber_ocsp_response_bytes(response, &type_oid, &type_oid_size, NULL,
                                     &content_size, &present);
    (void)asnber_ocsp_response_bytes(response, &type_oid, &type_oid_size,
                                     &content, &content_size, NULL);

    if (present != 0 && content != NULL && content_size > 0u) {
        open_and_scan_basic(ctx, content, content_size);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    asnber_ctx_t *ctx = fuzz_ctx_create();
    if (ctx == NULL) {
        return 0;
    }

    (void)asnber_ocsp_version_string();

    {
        asnber_ocsp_request_t *probe = NULL;
        (void)asnber_ocsp_request_open(NULL, data, size, &probe);
        probe = NULL;
        (void)asnber_ocsp_request_open(ctx, NULL, size, &probe);
        probe = NULL;
        (void)asnber_ocsp_request_open(ctx, data, 0, &probe);
        probe = NULL;
        (void)asnber_ocsp_request_open(ctx, data, size, NULL);
        probe = NULL;
        (void)asnber_ocsp_request_open(ctx, data, SIZE_MAX, &probe);
        asnber_ocsp_request_close(probe);
    }

    {
        asnber_ocsp_request_t *request = NULL;
        asnber_err_t status =
            asnber_ocsp_request_open(ctx, data, size, &request);
        if (status == ASNBER_OK && request != NULL) {
            scan_request(request);
            asnber_ocsp_request_close(request);
            request = NULL;
            asnber_ocsp_request_close(request);
        } else {
            asnber_ocsp_request_close(request);
            request = NULL;
            asnber_ocsp_request_close(request);
        }
    }

    {
        asnber_ocsp_response_t *probe = NULL;
        (void)asnber_ocsp_response_open(NULL, data, size, &probe);
        probe = NULL;
        (void)asnber_ocsp_response_open(ctx, NULL, size, &probe);
        probe = NULL;
        (void)asnber_ocsp_response_open(ctx, data, 0, &probe);
        probe = NULL;
        (void)asnber_ocsp_response_open(ctx, data, size, NULL);
        asnber_ocsp_response_close(probe);
    }

    {
        asnber_ocsp_response_t *response = NULL;
        asnber_err_t status =
            asnber_ocsp_response_open(ctx, data, size, &response);
        if (status == ASNBER_OK && response != NULL) {
            scan_response(ctx, response);
            asnber_ocsp_response_close(response);
            response = NULL;
            asnber_ocsp_response_close(response);
        } else {
            asnber_ocsp_response_close(response);
            response = NULL;
            asnber_ocsp_response_close(response);
        }
    }

    {
        asnber_ocsp_basic_t *probe = NULL;
        (void)asnber_ocsp_basic_open(NULL, data, size, &probe);
        probe = NULL;
        (void)asnber_ocsp_basic_open(ctx, NULL, size, &probe);
        probe = NULL;
        (void)asnber_ocsp_basic_open(ctx, data, 0, &probe);
        probe = NULL;
        (void)asnber_ocsp_basic_open(ctx, data, size, NULL);
        asnber_ocsp_basic_close(probe);
    }

    open_and_scan_basic(ctx, data, size);

    asnber_ctx_destroy(ctx);
    return 0;
}
