/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * asnber-ocsp：OCSPRequest / OCSPResponse 只读访问。
 * OpenSSL 样本只断言结构字段。带签名请求的 nonce 和签名值会随重新生成变化。
 */

#include <asnber/asnber.h>
#include <asnber/ocsp/ocsp.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../data/ocsp_request.h"
#include "../data/ocsp_request_signed.h"
#include "check.h"

/*
 * 结构夹具，不是 OpenSSL 样本。OpenSSL 的 ocsp 子命令不写
 * singleRequestExtensions，也不让调用方指定 requestorName 的字节。
 * 这份请求带显式 version、空 Name、一条 singleRequestExtensions、
 * 一条 requestExtensions，以及一张占位证书的 optionalSignature。
 */
static const unsigned char kRichRequest[] = {
    0x30, 0x7E, 0x30, 0x63, 0xA0, 0x03, 0x02, 0x01, 0x00, 0xA1, 0x02, 0x30,
    0x00, 0x30, 0x4B, 0x30, 0x49, 0x30, 0x3A, 0x30, 0x09, 0x06, 0x05, 0x2B,
    0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x04, 0x14, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x02, 0x01, 0x2A, 0xA0, 0x0B, 0x30, 0x09, 0x30, 0x07, 0x06,
    0x02, 0x2A, 0x03, 0x04, 0x01, 0x01, 0xA2, 0x0B, 0x30, 0x09, 0x30, 0x07,
    0x06, 0x02, 0x2A, 0x03, 0x04, 0x01, 0x01, 0xA0, 0x17, 0x30, 0x15, 0x30,
    0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x03, 0x02,
    0x00, 0xAA, 0xA0, 0x04, 0x30, 0x02, 0x30, 0x00,
};

/* successful + responseBytes，内容字节是 01 02 03，不是 BasicOCSPResponse。 */
static const unsigned char kSuccessfulResponse[] = {
    0x30, 0x17, 0x0A, 0x01, 0x00, 0xA0, 0x12, 0x30, 0x10, 0x06, 0x09, 0x2B,
    0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01, 0x04, 0x03, 0x01, 0x02,
    0x03,
};

/* malformedRequest，线上仍带 responseBytes。访问器按状态把输出留空。 */
static const unsigned char kMalformedWithBytes[] = {
    0x30, 0x17, 0x0A, 0x01, 0x01, 0xA0, 0x12, 0x30, 0x10, 0x06, 0x09, 0x2B,
    0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01, 0x04, 0x03, 0x01, 0x02,
    0x03,
};

static const unsigned char kTryLater[] = {0x30, 0x03, 0x0A, 0x01, 0x03};
static const unsigned char kSuccessfulEmpty[] = {0x30, 0x03, 0x0A, 0x01, 0x00};

static const unsigned char kNameHash[20] = {
    0xE3, 0x20, 0x0D, 0xBB, 0xE8, 0x5E, 0xD9, 0x2E, 0x30, 0x5C,
    0x17, 0x42, 0xA5, 0x82, 0x49, 0x68, 0x23, 0x7B, 0x9D, 0xFB,
};
static const unsigned char kKeyHash[20] = {
    0xA8, 0x4A, 0xEF, 0xD4, 0x3E, 0x3A, 0x5A, 0x12, 0x4F, 0x28,
    0xFA, 0x95, 0x0E, 0xC3, 0x7B, 0xFB, 0x0F, 0xDC, 0xA6, 0xD4,
};
static const char kSerial[] =
    "651241625021466612160683104114604757680343021109";

static int test_module_version(void)
{
    const char *runtime = asnber_ocsp_version_string();
    asnber_version_info_t info;

    memset(&info, 0, sizeof(info));
    info.struct_size = sizeof(info);
    ASNBER_TEST_CHECK(runtime != NULL);
    ASNBER_TEST_CHECK(strcmp(runtime, ASNBER_OCSP_VERSION_STRING) == 0);
    ASNBER_TEST_CHECK(asnber_version(&info) == ASNBER_OK);
    ASNBER_TEST_CHECK(info.string != NULL);
    ASNBER_TEST_CHECK(strcmp(runtime, info.string) == 0);
    return 0;
}

static asnber_ctx_t *make_ctx(void)
{
    asnber_ctx_config_t config;
    asnber_ctx_config_init(&config);
    asnber_ctx_t *ctx = NULL;
    if (asnber_ctx_create(&config, &ctx) != ASNBER_OK) {
        return NULL;
    }
    return ctx;
}

static int text_is(const char *text, size_t size, const char *expected)
{
    return text != NULL && size == strlen(expected) &&
           memcmp(text, expected, size) == 0;
}

static int check_openssl_cert_id(const asnber_ocsp_request_t *request)
{
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

    ASNBER_TEST_CHECK(asnber_ocsp_request_cert_id(
                        request, 0, &oid, &oid_size, &params, &params_size,
                        &params_present, &name_hash, &name_hash_size, &key_hash,
                        &key_hash_size, &serial, &serial_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(text_is(oid, oid_size, "1.3.14.3.2.26"));
    ASNBER_TEST_CHECK(params_present == 1);
    ASNBER_TEST_CHECK(params != NULL && params_size == 2);
    ASNBER_TEST_CHECK(params[0] == 0x05 && params[1] == 0x00);
    ASNBER_TEST_CHECK(name_hash_size == sizeof(kNameHash));
    ASNBER_TEST_CHECK(memcmp(name_hash, kNameHash, sizeof(kNameHash)) == 0);
    ASNBER_TEST_CHECK(key_hash_size == sizeof(kKeyHash));
    ASNBER_TEST_CHECK(memcmp(key_hash, kKeyHash, sizeof(kKeyHash)) == 0);
    ASNBER_TEST_CHECK(text_is(serial, serial_size, kSerial));
    ASNBER_TEST_CHECK(asnber_ocsp_request_cert_id(
                        request, 1, &oid, &oid_size, &params, &params_size,
                        &params_present, &name_hash, &name_hash_size, &key_hash,
                        &key_hash_size, &serial, &serial_size) ==
                    ASNBER_E_INVALID_ARG);
    return 0;
}

static int test_openssl_request(asnber_ctx_t *ctx)
{
    asnber_ocsp_request_t *request = NULL;
    uint32_t version = 99;
    size_t count = 99;
    const uint8_t *requestor = NULL;
    size_t requestor_size = 99;
    int present = 1;
    const char *oid = NULL;
    size_t oid_size = 0;
    const uint8_t *params = NULL;
    size_t params_size = 0;
    int params_present = 1;
    const uint8_t *bits = NULL;
    size_t bits_size = 99;
    size_t bit_length = 99;
    uint8_t unused = 9;
    size_t cert_count = 99;

    ASNBER_TEST_CHECK(asnber_ocsp_request_open(ctx, kOcspRequest, kOcspRequestSize,
                                             &request) == ASNBER_OK);
    ASNBER_TEST_CHECK(request != NULL);
    ASNBER_TEST_CHECK(asnber_ocsp_request_version(request, &version) == ASNBER_OK);
    ASNBER_TEST_CHECK(version == 0);
    ASNBER_TEST_CHECK(asnber_ocsp_request_count(request, &count) == ASNBER_OK);
    ASNBER_TEST_CHECK(count == 1);
    ASNBER_TEST_CHECK(check_openssl_cert_id(request) == 0);
    ASNBER_TEST_CHECK(asnber_ocsp_request_requestor(request, &requestor,
                                                  &requestor_size,
                                                  &present) == ASNBER_OK);
    ASNBER_TEST_CHECK(present == 0);
    ASNBER_TEST_CHECK(requestor == NULL && requestor_size == 0);
    ASNBER_TEST_CHECK(asnber_ocsp_request_extension_count(request, &count) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(count == 0);
    ASNBER_TEST_CHECK(asnber_ocsp_request_single_extension_count(request, 0,
                                                               &count) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(count == 0);
    ASNBER_TEST_CHECK(asnber_ocsp_request_signature(
                        request, &oid, &oid_size, &params, &params_size,
                        &params_present, &bits, &bits_size, &bit_length, &unused,
                        &cert_count, &present) == ASNBER_OK);
    ASNBER_TEST_CHECK(present == 0);
    ASNBER_TEST_CHECK(oid == NULL && cert_count == 0 && bits == NULL);
    ASNBER_TEST_CHECK(asnber_ocsp_request_signature_cert(request, 0, &bits,
                                                       &bits_size) ==
                    ASNBER_E_INVALID_ARG);

    asnber_ocsp_response_t *response = NULL;
    ASNBER_TEST_CHECK(asnber_ocsp_response_open(ctx, kOcspRequest, kOcspRequestSize,
                                              &response) != ASNBER_OK);
    ASNBER_TEST_CHECK(response == NULL);
    asnber_ocsp_request_close(request);
    return 0;
}

static int test_openssl_signed_request(asnber_ctx_t *ctx)
{
    asnber_ocsp_request_t *request = NULL;
    uint32_t version = 99;
    size_t count = 0;
    const uint8_t *requestor = NULL;
    size_t requestor_size = 0;
    int present = 0;
    const char *oid = NULL;
    size_t oid_size = 0;
    int critical = 1;
    const uint8_t *value = NULL;
    size_t value_size = 0;
    const uint8_t *params = NULL;
    size_t params_size = 0;
    int params_present = 0;
    const uint8_t *bits = NULL;
    size_t bits_size = 0;
    size_t bit_length = 0;
    uint8_t unused = 9;
    size_t cert_count = 0;

    ASNBER_TEST_CHECK(asnber_ocsp_request_open(
                        ctx, kOcspRequestSigned, kOcspRequestSignedSize,
                        &request) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_ocsp_request_version(request, &version) == ASNBER_OK);
    ASNBER_TEST_CHECK(version == 0);
    ASNBER_TEST_CHECK(asnber_ocsp_request_count(request, &count) == ASNBER_OK);
    ASNBER_TEST_CHECK(count == 1);
    ASNBER_TEST_CHECK(check_openssl_cert_id(request) == 0);

    ASNBER_TEST_CHECK(asnber_ocsp_request_requestor(request, &requestor,
                                                  &requestor_size,
                                                  &present) == ASNBER_OK);
    ASNBER_TEST_CHECK(present == 1);
    ASNBER_TEST_CHECK(requestor != NULL && requestor_size > 2);
    ASNBER_TEST_CHECK(requestor[0] == 0xA4);

    ASNBER_TEST_CHECK(asnber_ocsp_request_extension_count(request, &count) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(count == 1);
    ASNBER_TEST_CHECK(asnber_ocsp_request_extension_at(
                        request, 0, &oid, &oid_size, &critical, &value,
                        &value_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(text_is(oid, oid_size, "1.3.6.1.5.5.7.48.1.2"));
    ASNBER_TEST_CHECK(critical == 0);
    ASNBER_TEST_CHECK(value != NULL && value_size >= 2 && value[0] == 0x04);
    ASNBER_TEST_CHECK(asnber_ocsp_request_single_extension_count(request, 0,
                                                               &count) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(count == 0);

    ASNBER_TEST_CHECK(asnber_ocsp_request_signature(
                        request, &oid, &oid_size, &params, &params_size,
                        &params_present, &bits, &bits_size, &bit_length, &unused,
                        &cert_count, &present) == ASNBER_OK);
    ASNBER_TEST_CHECK(present == 1);
    ASNBER_TEST_CHECK(text_is(oid, oid_size, "1.2.840.113549.1.1.11"));
    ASNBER_TEST_CHECK(params_present == 1 && params_size == 2);
    ASNBER_TEST_CHECK(params[0] == 0x05 && params[1] == 0x00);
    ASNBER_TEST_CHECK(bits != NULL && bits_size > 0);
    ASNBER_TEST_CHECK(unused == 0);
    ASNBER_TEST_CHECK(bit_length == bits_size * 8);
    ASNBER_TEST_CHECK(cert_count == 1);
    ASNBER_TEST_CHECK(asnber_ocsp_request_signature_cert(request, 0, &value,
                                                       &value_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(value != NULL && value_size > 100 && value[0] == 0x30);
    ASNBER_TEST_CHECK(asnber_ocsp_request_signature_cert(request, 1, &value,
                                                       &value_size) ==
                    ASNBER_E_INVALID_ARG);

    asnber_ocsp_request_close(request);
    asnber_ocsp_request_close(NULL);
    return 0;
}

static int test_rich_request(asnber_ctx_t *ctx)
{
    asnber_ocsp_request_t *request = NULL;
    uint32_t version = 99;
    size_t count = 0;
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
    const uint8_t *requestor = NULL;
    size_t requestor_size = 0;
    int present = 0;
    int critical = 1;
    const uint8_t *value = NULL;
    size_t value_size = 0;
    const uint8_t *bits = NULL;
    size_t bits_size = 0;
    size_t bit_length = 0;
    uint8_t unused = 9;
    size_t cert_count = 0;

    ASNBER_TEST_CHECK(asnber_ocsp_request_open(ctx, kRichRequest, sizeof(kRichRequest),
                                             &request) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_ocsp_request_version(request, &version) == ASNBER_OK);
    ASNBER_TEST_CHECK(version == 0);
    ASNBER_TEST_CHECK(asnber_ocsp_request_count(request, &count) == ASNBER_OK);
    ASNBER_TEST_CHECK(count == 1);
    ASNBER_TEST_CHECK(asnber_ocsp_request_cert_id(
                        request, 0, &oid, &oid_size, &params, &params_size,
                        &params_present, &name_hash, &name_hash_size, &key_hash,
                        &key_hash_size, &serial, &serial_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(text_is(oid, oid_size, "1.3.14.3.2.26"));
    ASNBER_TEST_CHECK(params_present == 1 && params_size == 2);
    ASNBER_TEST_CHECK(name_hash_size == 20 && name_hash[0] == 0x11);
    ASNBER_TEST_CHECK(key_hash_size == 20 && key_hash[0] == 0x22);
    ASNBER_TEST_CHECK(text_is(serial, serial_size, "42"));

    ASNBER_TEST_CHECK(asnber_ocsp_request_requestor(request, &requestor,
                                                  &requestor_size,
                                                  &present) == ASNBER_OK);
    ASNBER_TEST_CHECK(present == 1 && requestor_size == 2);
    ASNBER_TEST_CHECK(requestor[0] == 0x30 && requestor[1] == 0x00);

    ASNBER_TEST_CHECK(asnber_ocsp_request_extension_count(request, &count) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(count == 1);
    ASNBER_TEST_CHECK(asnber_ocsp_request_extension_at(
                        request, 0, &oid, &oid_size, &critical, &value,
                        &value_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(text_is(oid, oid_size, "1.2.3"));
    ASNBER_TEST_CHECK(critical == 0 && value_size == 1 && value[0] == 0x01);
    ASNBER_TEST_CHECK(asnber_ocsp_request_single_extension_count(request, 0,
                                                               &count) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(count == 1);
    ASNBER_TEST_CHECK(asnber_ocsp_request_single_extension_at(
                        request, 0, 0, &oid, &oid_size, &critical, &value,
                        &value_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(text_is(oid, oid_size, "1.2.3"));
    ASNBER_TEST_CHECK(asnber_ocsp_request_single_extension_count(request, 1,
                                                               &count) ==
                    ASNBER_E_INVALID_ARG);

    ASNBER_TEST_CHECK(asnber_ocsp_request_signature(
                        request, &oid, &oid_size, &params, &params_size,
                        &params_present, &bits, &bits_size, &bit_length, &unused,
                        &cert_count, &present) == ASNBER_OK);
    ASNBER_TEST_CHECK(present == 1);
    ASNBER_TEST_CHECK(text_is(oid, oid_size, "1.3.14.3.2.26"));
    ASNBER_TEST_CHECK(bits_size == 1 && bits[0] == 0xAA);
    ASNBER_TEST_CHECK(unused == 0 && bit_length == 8);
    ASNBER_TEST_CHECK(cert_count == 1);
    ASNBER_TEST_CHECK(asnber_ocsp_request_signature_cert(request, 0, &value,
                                                       &value_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(value_size == 2 && value[0] == 0x30 && value[1] == 0x00);

    asnber_ocsp_request_close(request);
    return 0;
}

static int check_bytes_absent(const asnber_ocsp_response_t *response)
{
    const char *oid = (const char *)0x1;
    size_t oid_size = 9;
    const uint8_t *payload = (const uint8_t *)0x1;
    size_t payload_size = 9;
    int present = 1;
    ASNBER_TEST_CHECK(asnber_ocsp_response_bytes(response, &oid, &oid_size,
                                               &payload, &payload_size,
                                               &present) == ASNBER_OK);
    ASNBER_TEST_CHECK(present == 0);
    ASNBER_TEST_CHECK(oid == NULL && oid_size == 0);
    ASNBER_TEST_CHECK(payload == NULL && payload_size == 0);
    return 0;
}

static int test_response(asnber_ctx_t *ctx)
{
    asnber_ocsp_response_t *response = NULL;
    int64_t status = -1;
    const char *oid = NULL;
    size_t oid_size = 0;
    const uint8_t *payload = NULL;
    size_t payload_size = 0;
    int present = 0;

    ASNBER_TEST_CHECK(asnber_ocsp_response_open(ctx, kTryLater, sizeof(kTryLater),
                                              &response) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_ocsp_response_status(response, &status) == ASNBER_OK);
    ASNBER_TEST_CHECK(status == 3);
    ASNBER_TEST_CHECK(check_bytes_absent(response) == 0);
    ASNBER_TEST_CHECK(asnber_ocsp_request_open(ctx, kTryLater, sizeof(kTryLater),
                                             NULL) == ASNBER_E_INVALID_ARG);
    {
        asnber_ocsp_request_t *request = NULL;
        ASNBER_TEST_CHECK(asnber_ocsp_request_open(ctx, kTryLater, sizeof(kTryLater),
                                                 &request) != ASNBER_OK);
        ASNBER_TEST_CHECK(request == NULL);
    }
    asnber_ocsp_response_close(response);

    ASNBER_TEST_CHECK(asnber_ocsp_response_open(
                        ctx, kSuccessfulEmpty, sizeof(kSuccessfulEmpty),
                        &response) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_ocsp_response_status(response, &status) == ASNBER_OK);
    ASNBER_TEST_CHECK(status == 0);
    ASNBER_TEST_CHECK(check_bytes_absent(response) == 0);
    asnber_ocsp_response_close(response);

    ASNBER_TEST_CHECK(asnber_ocsp_response_open(
                        ctx, kSuccessfulResponse, sizeof(kSuccessfulResponse),
                        &response) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_ocsp_response_status(response, &status) == ASNBER_OK);
    ASNBER_TEST_CHECK(status == 0);
    ASNBER_TEST_CHECK(asnber_ocsp_response_bytes(response, &oid, &oid_size,
                                               &payload, &payload_size,
                                               &present) == ASNBER_OK);
    ASNBER_TEST_CHECK(present == 1);
    ASNBER_TEST_CHECK(text_is(oid, oid_size, "1.3.6.1.5.5.7.48.1.1"));
    ASNBER_TEST_CHECK(payload_size == 3);
    ASNBER_TEST_CHECK(payload[0] == 0x01 && payload[1] == 0x02 &&
                    payload[2] == 0x03);
    asnber_ocsp_response_close(response);

    ASNBER_TEST_CHECK(asnber_ocsp_response_open(
                        ctx, kMalformedWithBytes, sizeof(kMalformedWithBytes),
                        &response) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_ocsp_response_status(response, &status) == ASNBER_OK);
    ASNBER_TEST_CHECK(status == 1);
    ASNBER_TEST_CHECK(check_bytes_absent(response) == 0);
    asnber_ocsp_response_close(response);
    asnber_ocsp_response_close(NULL);
    return 0;
}

static int test_negative(asnber_ctx_t *ctx)
{
    asnber_ocsp_request_t *request = NULL;
    asnber_ocsp_response_t *response = NULL;
    uint32_t version = 0;
    size_t count = 0;

    ASNBER_TEST_CHECK(asnber_ocsp_request_open(NULL, kOcspRequest, kOcspRequestSize,
                                             &request) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_ocsp_request_open(ctx, NULL, kOcspRequestSize,
                                             &request) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_ocsp_request_open(ctx, kOcspRequest, 0, &request) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_ocsp_request_open(ctx, kOcspRequest, kOcspRequestSize,
                                             NULL) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_ocsp_request_open(ctx, kOcspRequest, 4, &request) !=
                    ASNBER_OK);
    ASNBER_TEST_CHECK(request == NULL);

    ASNBER_TEST_CHECK(asnber_ocsp_response_open(NULL, kTryLater, sizeof(kTryLater),
                                              &response) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_ocsp_response_open(ctx, kTryLater, 0, &response) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_ocsp_request_version(NULL, &version) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_ocsp_request_count(NULL, &count) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_ocsp_response_status(NULL, NULL) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_ocsp_response_bytes(NULL, NULL, NULL, NULL, NULL,
                                               NULL) == ASNBER_E_INVALID_ARG);
    return 0;
}

int main(void)
{
    if (test_module_version() != 0) {
        return 1;
    }
    asnber_ctx_t *ctx = make_ctx();
    if (ctx == NULL) {
        return 1;
    }
    int failed = 0;
    if (test_openssl_request(ctx) != 0 || test_openssl_signed_request(ctx) != 0 ||
        test_rich_request(ctx) != 0 || test_response(ctx) != 0 ||
        test_negative(ctx) != 0) {
        failed = 1;
    }
    asnber_ctx_destroy(ctx);
    return failed;
}
