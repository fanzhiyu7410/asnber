/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * asnber-ocsp builder：OpenSSL 样本解码后再编码必须逐字节一致。
 * 负例覆盖缺必填、重复设置、非法 OID、非法 TLV，以及失败时输出被清零。
 */

#include <asnber/asnber.h>
#include <asnber/ocsp/ocsp_builder.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../data/ocsp_request.h"
#include "../data/ocsp_request_signed.h"
#include "../data/ocsp_response.h"
#include "../data/ocsp_response_bykey.h"
#include "check.h"

static const unsigned char kNameHash[20] = {
    0xE3, 0x20, 0x0D, 0xBB, 0xE8, 0x5E, 0xD9, 0x2E, 0x30, 0x5C,
    0x17, 0x42, 0xA5, 0x82, 0x49, 0x68, 0x23, 0x7B, 0x9D, 0xFB,
};
static const unsigned char kKeyHash[20] = {
    0xA8, 0x4A, 0xEF, 0xD4, 0x3E, 0x3A, 0x5A, 0x12, 0x4F, 0x28,
    0xFA, 0x95, 0x0E, 0xC3, 0x7B, 0xFB, 0x0F, 0xDC, 0xA6, 0xD4,
};
static const unsigned char kSerial[20] = {
    0x72, 0x12, 0xAF, 0x38, 0x15, 0x28, 0xA1, 0x36, 0x6D, 0x0B,
    0xFC, 0x55, 0x0F, 0xBA, 0x9B, 0x5D, 0x7E, 0x90, 0xF6, 0x35,
};
static const unsigned char kSerialTwo[] = {0x02};
static const unsigned char kSerialThree[] = {0x03};
static const unsigned char kNullParams[] = {0x05, 0x00};
static const char kSha1[] = "1.3.14.3.2.26";
static const char kSha256Rsa[] = "1.2.840.113549.1.1.11";
static const char kBasicOid[] = "1.3.6.1.5.5.7.48.1.1";

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

static int same_bytes(const uint8_t *got, size_t got_size, const uint8_t *want,
                      size_t want_size)
{
    size_t i = 0;
    size_t limit = got_size < want_size ? got_size : want_size;
    if (got_size == want_size && memcmp(got, want, got_size) == 0) {
        return 1;
    }
    while (i < limit && got[i] == want[i]) {
        ++i;
    }
    fprintf(stderr, "der mismatch: got %zu want %zu first %zu\n", got_size,
            want_size, i);
    return 0;
}

static void poison(asnber_buf_t *buf)
{
    buf->data = (uint8_t *)(uintptr_t)1;
    buf->size = 1;
    buf->capacity = 1;
}

static int buf_cleared(const asnber_buf_t *buf)
{
    return buf->data == NULL && buf->size == 0 && buf->capacity == 0;
}

static int add_known_request(asnber_ocsp_request_builder_t *builder)
{
    return asnber_ocsp_request_builder_add_request(
               builder, kSha1, kNullParams, sizeof(kNullParams), kNameHash,
               sizeof(kNameHash), kKeyHash, sizeof(kKeyHash), kSerial,
               sizeof(kSerial)) == ASNBER_OK;
}

static int test_unsigned_request(asnber_ctx_t *ctx)
{
    asnber_ocsp_request_builder_t *builder = NULL;
    asnber_buf_t encoded;
    asnber_ocsp_request_t *request = NULL;
    uint32_t version = 99;

    ASNBER_TEST_CHECK(asnber_ocsp_request_builder_create(ctx, &builder) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_ocsp_request_builder_set_version(builder, 0) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(add_known_request(builder));
    poison(&encoded);
    ASNBER_TEST_CHECK(asnber_ocsp_request_builder_encode(builder, &encoded) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(same_bytes(encoded.data, encoded.size, kOcspRequest,
                               kOcspRequestSize));
    ASNBER_TEST_CHECK(asnber_ocsp_request_open(ctx, encoded.data, encoded.size,
                                             &request) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_ocsp_request_version(request, &version) == ASNBER_OK);
    ASNBER_TEST_CHECK(version == 0);
    asnber_ocsp_request_close(request);
    asnber_buf_release(ctx, &encoded);
    asnber_ocsp_request_builder_destroy(builder);
    return 0;
}

static const unsigned char *serial_magnitude(const char *text, size_t size,
                                             size_t *out_size)
{
    if (text_is(text, size, "2")) {
        *out_size = sizeof(kSerialTwo);
        return kSerialTwo;
    }
    if (text_is(text, size, "3")) {
        *out_size = sizeof(kSerialThree);
        return kSerialThree;
    }
    *out_size = sizeof(kSerial);
    return kSerial;
}

static int copy_extensions_request(const asnber_ocsp_request_t *request,
                                   asnber_ocsp_request_builder_t *builder)
{
    size_t count = 0;
    size_t i = 0;
    ASNBER_TEST_CHECK(asnber_ocsp_request_extension_count(request, &count) ==
                    ASNBER_OK);
    for (i = 0; i < count; ++i) {
        const char *oid = NULL;
        size_t oid_size = 0;
        int critical = 0;
        const uint8_t *value = NULL;
        size_t value_size = 0;
        ASNBER_TEST_CHECK(asnber_ocsp_request_extension_at(
                            request, i, &oid, &oid_size, &critical, &value,
                            &value_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_ocsp_request_builder_add_extension(
                            builder, oid, critical, value, value_size) ==
                        ASNBER_OK);
    }
    return 0;
}

static int test_signed_request(asnber_ctx_t *ctx)
{
    asnber_ocsp_request_t *request = NULL;
    asnber_ocsp_request_builder_t *builder = NULL;
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
    const uint8_t *bits = NULL;
    size_t bits_size = 0;
    size_t bit_length = 0;
    uint8_t unused = 0;
    size_t cert_count = 0;
    size_t i = 0;
    asnber_buf_t encoded;

    ASNBER_TEST_CHECK(asnber_ocsp_request_open(ctx, kOcspRequestSigned,
                                             kOcspRequestSignedSize,
                                             &request) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_ocsp_request_builder_create(ctx, &builder) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_ocsp_request_requestor(request, &requestor,
                                                  &requestor_size,
                                                  &present) == ASNBER_OK);
    ASNBER_TEST_CHECK(present == 1);
    ASNBER_TEST_CHECK(asnber_ocsp_request_builder_set_requestor(
                        builder, requestor, requestor_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_ocsp_request_cert_id(
                        request, 0, &oid, &oid_size, &params, &params_size,
                        &params_present, &name_hash, &name_hash_size, &key_hash,
                        &key_hash_size, &serial, &serial_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(text_is(
        serial, serial_size,
        "651241625021466612160683104114604757680343021109"));
    ASNBER_TEST_CHECK(asnber_ocsp_request_builder_add_request(
                        builder, kSha1, params, params_present ? params_size : 0,
                        name_hash, name_hash_size, key_hash, key_hash_size, kSerial,
                        sizeof(kSerial)) == ASNBER_OK);
    ASNBER_TEST_CHECK(copy_extensions_request(request, builder) == 0);
    ASNBER_TEST_CHECK(asnber_ocsp_request_signature(
                        request, &oid, &oid_size, &params, &params_size,
                        &params_present, &bits, &bits_size, &bit_length, &unused,
                        &cert_count, &present) == ASNBER_OK);
    ASNBER_TEST_CHECK(present == 1);
    ASNBER_TEST_CHECK(asnber_ocsp_request_builder_set_signature(
                        builder, kSha256Rsa, params,
                        params_present ? params_size : 0, bits, bits_size,
                        unused) == ASNBER_OK);
    for (i = 0; i < cert_count; ++i) {
        const uint8_t *cert = NULL;
        size_t cert_size = 0;
        ASNBER_TEST_CHECK(asnber_ocsp_request_signature_cert(request, i, &cert,
                                                           &cert_size) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_ocsp_request_builder_add_signature_cert(
                            builder, cert, cert_size) == ASNBER_OK);
    }
    poison(&encoded);
    ASNBER_TEST_CHECK(asnber_ocsp_request_builder_encode(builder, &encoded) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(same_bytes(encoded.data, encoded.size, kOcspRequestSigned,
                               kOcspRequestSignedSize));
    asnber_buf_release(ctx, &encoded);
    asnber_ocsp_request_builder_destroy(builder);
    asnber_ocsp_request_close(request);
    return 0;
}

static int add_rebuilt_response(const asnber_ocsp_basic_t *basic, size_t index,
                                asnber_ocsp_basic_builder_t *builder)
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
    const char *serial_text = NULL;
    size_t serial_size = 0;
    const unsigned char *serial = NULL;
    size_t magnitude_size = 0;
    int status = -1;
    asnber_time_t this_update;
    asnber_time_t next_update;
    int next_present = 0;
    size_t ext_count = 0;
    size_t i = 0;

    memset(&this_update, 0, sizeof(this_update));
    memset(&next_update, 0, sizeof(next_update));
    this_update.struct_size = sizeof(this_update);
    next_update.struct_size = sizeof(next_update);

    ASNBER_TEST_CHECK(asnber_ocsp_basic_cert_id(
                        basic, index, &oid, &oid_size, &params, &params_size,
                        &params_present, &name_hash, &name_hash_size, &key_hash,
                        &key_hash_size, &serial_text, &serial_size) == ASNBER_OK);
    serial = serial_magnitude(serial_text, serial_size, &magnitude_size);
    ASNBER_TEST_CHECK(asnber_ocsp_basic_cert_status(basic, index, &status) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_ocsp_basic_this_update(basic, index, &this_update) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_ocsp_basic_next_update(basic, index, &next_update,
                                                  &next_present) == ASNBER_OK);
    if (status == 1) {
        asnber_time_t revoked_at;
        int64_t reason = 0;
        int reason_present = 0;
        memset(&revoked_at, 0, sizeof(revoked_at));
        revoked_at.struct_size = sizeof(revoked_at);
        ASNBER_TEST_CHECK(asnber_ocsp_basic_revocation(basic, index, &revoked_at,
                                                     &reason,
                                                     &reason_present) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_ocsp_basic_builder_add_revoked(
                            builder, kSha1, params,
                            params_present ? params_size : 0, name_hash,
                            name_hash_size, key_hash, key_hash_size, serial,
                            magnitude_size, &this_update,
                            next_present ? &next_update : NULL, &revoked_at,
                            reason, reason_present) == ASNBER_OK);
    } else if (status == 2) {
        ASNBER_TEST_CHECK(asnber_ocsp_basic_builder_add_unknown(
                            builder, kSha1, params,
                            params_present ? params_size : 0, name_hash,
                            name_hash_size, key_hash, key_hash_size, serial,
                            magnitude_size, &this_update,
                            next_present ? &next_update : NULL) == ASNBER_OK);
    } else {
        ASNBER_TEST_CHECK(status == 0);
        ASNBER_TEST_CHECK(asnber_ocsp_basic_builder_add_good(
                            builder, kSha1, params,
                            params_present ? params_size : 0, name_hash,
                            name_hash_size, key_hash, key_hash_size, serial,
                            magnitude_size, &this_update,
                            next_present ? &next_update : NULL) == ASNBER_OK);
    }
    ASNBER_TEST_CHECK(asnber_ocsp_basic_single_extension_count(basic, index,
                                                             &ext_count) ==
                    ASNBER_OK);
    for (i = 0; i < ext_count; ++i) {
        const char *ext_oid = NULL;
        size_t ext_oid_size = 0;
        int critical = 0;
        const uint8_t *value = NULL;
        size_t value_size = 0;
        ASNBER_TEST_CHECK(asnber_ocsp_basic_single_extension_at(
                            basic, index, i, &ext_oid, &ext_oid_size, &critical,
                            &value, &value_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_ocsp_basic_builder_add_single_extension(
                            builder, index, ext_oid, critical, value,
                            value_size) == ASNBER_OK);
    }
    return 0;
}

static int test_basic_roundtrip(asnber_ctx_t *ctx, const uint8_t *der,
                                size_t der_size)
{
    asnber_ocsp_response_t *response = NULL;
    asnber_ocsp_basic_t *basic = NULL;
    asnber_ocsp_basic_builder_t *builder = NULL;
    asnber_ocsp_response_builder_t *outer = NULL;
    const char *type_oid = NULL;
    size_t type_oid_size = 0;
    const uint8_t *payload = NULL;
    size_t payload_size = 0;
    int present = 0;
    int choice = 0;
    const uint8_t *name = NULL;
    size_t name_size = 0;
    const uint8_t *key = NULL;
    size_t key_size = 0;
    asnber_time_t produced;
    size_t count = 0;
    size_t i = 0;
    const char *oid = NULL;
    size_t oid_size = 0;
    const uint8_t *params = NULL;
    size_t params_size = 0;
    int params_present = 0;
    const uint8_t *bits = NULL;
    size_t bits_size = 0;
    size_t bit_length = 0;
    uint8_t unused = 0;
    size_t cert_count = 0;
    asnber_buf_t encoded;

    memset(&produced, 0, sizeof(produced));
    produced.struct_size = sizeof(produced);

    ASNBER_TEST_CHECK(asnber_ocsp_response_open(ctx, der, der_size, &response) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_ocsp_response_bytes(response, &type_oid,
                                               &type_oid_size, &payload,
                                               &payload_size, &present) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(present == 1);
    ASNBER_TEST_CHECK(asnber_ocsp_basic_open(ctx, payload, payload_size, &basic) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_ocsp_basic_builder_create(ctx, &builder) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_ocsp_basic_responder(basic, &choice, &name, &name_size,
                                                &key, &key_size) == ASNBER_OK);
    if (choice == 1) {
        ASNBER_TEST_CHECK(asnber_ocsp_basic_builder_set_responder_name(
                            builder, name, name_size) == ASNBER_OK);
    } else {
        ASNBER_TEST_CHECK(choice == 2);
        ASNBER_TEST_CHECK(asnber_ocsp_basic_builder_set_responder_key(
                            builder, key, key_size) == ASNBER_OK);
    }
    ASNBER_TEST_CHECK(asnber_ocsp_basic_produced_at(basic, &produced) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_ocsp_basic_builder_set_produced_at(builder,
                                                             &produced) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_ocsp_basic_response_count(basic, &count) == ASNBER_OK);
    for (i = 0; i < count; ++i) {
        ASNBER_TEST_CHECK(add_rebuilt_response(basic, i, builder) == 0);
    }
    ASNBER_TEST_CHECK(asnber_ocsp_basic_extension_count(basic, &count) ==
                    ASNBER_OK);
    for (i = 0; i < count; ++i) {
        const char *ext_oid = NULL;
        size_t ext_oid_size = 0;
        int critical = 0;
        const uint8_t *value = NULL;
        size_t value_size = 0;
        ASNBER_TEST_CHECK(asnber_ocsp_basic_extension_at(
                            basic, i, &ext_oid, &ext_oid_size, &critical, &value,
                            &value_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_ocsp_basic_builder_add_extension(
                            builder, ext_oid, critical, value, value_size) ==
                        ASNBER_OK);
    }
    ASNBER_TEST_CHECK(asnber_ocsp_basic_signature(
                        basic, &oid, &oid_size, &params, &params_size,
                        &params_present, &bits, &bits_size, &bit_length, &unused,
                        &cert_count) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_ocsp_basic_builder_set_signature(
                        builder, kSha256Rsa, params,
                        params_present ? params_size : 0, bits, bits_size,
                        unused) == ASNBER_OK);
    for (i = 0; i < cert_count; ++i) {
        const uint8_t *cert = NULL;
        size_t cert_size = 0;
        ASNBER_TEST_CHECK(asnber_ocsp_basic_signature_cert(basic, i, &cert,
                                                         &cert_size) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_ocsp_basic_builder_add_signature_cert(
                            builder, cert, cert_size) == ASNBER_OK);
    }
    poison(&encoded);
    ASNBER_TEST_CHECK(asnber_ocsp_basic_builder_encode(builder, &encoded) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(same_bytes(encoded.data, encoded.size, payload, payload_size));
    asnber_buf_release(ctx, &encoded);

    ASNBER_TEST_CHECK(asnber_ocsp_response_builder_create(ctx, &outer) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_ocsp_response_builder_set_status(outer, 0) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_ocsp_response_builder_set_bytes(
                        outer, kBasicOid, payload, payload_size) == ASNBER_OK);
    poison(&encoded);
    ASNBER_TEST_CHECK(asnber_ocsp_response_builder_encode(outer, &encoded) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(same_bytes(encoded.data, encoded.size, der, der_size));
    asnber_buf_release(ctx, &encoded);

    asnber_ocsp_response_builder_destroy(outer);
    asnber_ocsp_basic_builder_destroy(builder);
    asnber_ocsp_basic_close(basic);
    asnber_ocsp_response_close(response);
    return 0;
}

static int contains(const uint8_t *data, size_t size, const uint8_t *needle,
                    size_t needle_size)
{
    size_t i = 0;
    if (needle_size > size) {
        return 0;
    }
    for (i = 0; i + needle_size <= size; ++i) {
        if (memcmp(data + i, needle, needle_size) == 0) {
            return 1;
        }
    }
    return 0;
}

static int test_negative(asnber_ctx_t *ctx)
{
    asnber_ocsp_request_builder_t *request = NULL;
    asnber_ocsp_response_builder_t *response = NULL;
    asnber_ocsp_basic_builder_t *basic = NULL;
    asnber_buf_t encoded;
    asnber_ocsp_request_t *opened = NULL;
    uint32_t version = 0;
    size_t extension_count = 0;
    static const unsigned char kBadTlv[] = {0x30, 0x03, 0x01};
    static const unsigned char kNonce[] = {0x04, 0x01, 0x7F};
    static const unsigned char kPayload[] = {0x01, 0x02, 0x03};
    static const unsigned char kWrapped[] = {0x04, 0x03, 0x01, 0x02, 0x03};
    asnber_time_t when;
    const char *type_oid = NULL;
    size_t type_oid_size = 0;
    const uint8_t *bytes = NULL;
    size_t bytes_size = 0;
    int present = 1;
    int64_t status = -1;

    memset(&when, 0, sizeof(when));
    when.struct_size = sizeof(when);
    when.year = 2026;
    when.month = 11;
    when.day = 14;
    when.flags = ASNBER_TIME_GENERALIZED;

    ASNBER_TEST_CHECK(asnber_ocsp_request_builder_create(NULL, &request) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(request == NULL);
    asnber_ocsp_request_builder_destroy(NULL);
    ASNBER_TEST_CHECK(asnber_ocsp_request_builder_create(ctx, &request) ==
                    ASNBER_OK);
    poison(&encoded);
    ASNBER_TEST_CHECK(asnber_ocsp_request_builder_encode(request, &encoded) ==
                    ASNBER_E_INVALID_STATE);
    ASNBER_TEST_CHECK(buf_cleared(&encoded));
    ASNBER_TEST_CHECK(asnber_ocsp_request_builder_set_version(request, -1) ==
                    ASNBER_E_INVALID_VALUE);
    ASNBER_TEST_CHECK(asnber_ocsp_request_builder_set_version(request, 1) ==
                    ASNBER_E_INVALID_VALUE);
    ASNBER_TEST_CHECK(asnber_ocsp_request_builder_set_version(request, 0) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_ocsp_request_builder_set_version(request, 0) ==
                    ASNBER_E_INVALID_STATE);
    ASNBER_TEST_CHECK(asnber_ocsp_request_builder_set_requestor(
                        request, kBadTlv, sizeof(kBadTlv)) != ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_ocsp_request_builder_add_request(
                        request, "1.2.3.", kNullParams, sizeof(kNullParams),
                        kNameHash, sizeof(kNameHash), kKeyHash, sizeof(kKeyHash),
                        kSerial, sizeof(kSerial)) != ASNBER_OK);
    ASNBER_TEST_CHECK(add_known_request(request));
    ASNBER_TEST_CHECK(asnber_ocsp_request_builder_add_extension(
                        request, "1.2.3", 0, kNonce, sizeof(kNonce)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_ocsp_request_builder_add_extension(
                        request, "1.2.3", 0, kNonce, sizeof(kNonce)) ==
                    ASNBER_E_INVALID_VALUE);
    ASNBER_TEST_CHECK(asnber_ocsp_request_builder_add_signature_cert(
                        request, kOcspRequest, kOcspRequestSize) ==
                    ASNBER_E_INVALID_STATE);
    ASNBER_TEST_CHECK(asnber_ocsp_request_builder_encode(request, &encoded) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_ocsp_request_open(ctx, encoded.data, encoded.size,
                                             &opened) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_ocsp_request_version(opened, &version) == ASNBER_OK);
    ASNBER_TEST_CHECK(version == 0);
    ASNBER_TEST_CHECK(asnber_ocsp_request_extension_count(opened,
                                                        &extension_count) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(extension_count == 1);
    asnber_ocsp_request_close(opened);
    asnber_buf_release(ctx, &encoded);
    asnber_ocsp_request_builder_destroy(request);

    ASNBER_TEST_CHECK(asnber_ocsp_response_builder_create(ctx, &response) ==
                    ASNBER_OK);
    poison(&encoded);
    ASNBER_TEST_CHECK(asnber_ocsp_response_builder_encode(response, &encoded) ==
                    ASNBER_E_INVALID_STATE);
    ASNBER_TEST_CHECK(buf_cleared(&encoded));
    ASNBER_TEST_CHECK(asnber_ocsp_response_builder_set_status(response, 4) ==
                    ASNBER_E_INVALID_VALUE);
    ASNBER_TEST_CHECK(asnber_ocsp_response_builder_set_bytes(
                        response, "1.2.", kPayload, sizeof(kPayload)) != ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_ocsp_response_builder_set_status(response, 1) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_ocsp_response_builder_set_bytes(
                        response, kBasicOid, kPayload, sizeof(kPayload)) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_ocsp_response_builder_encode(response, &encoded) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(contains(encoded.data, encoded.size, kWrapped,
                             sizeof(kWrapped)));
    {
        asnber_ocsp_response_t *opened_response = NULL;
        ASNBER_TEST_CHECK(asnber_ocsp_response_open(ctx, encoded.data, encoded.size,
                                                  &opened_response) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_ocsp_response_status(opened_response, &status) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(status == 1);
        ASNBER_TEST_CHECK(asnber_ocsp_response_bytes(
                            opened_response, &type_oid, &type_oid_size, &bytes,
                            &bytes_size, &present) == ASNBER_OK);
        ASNBER_TEST_CHECK(present == 0);
        asnber_ocsp_response_close(opened_response);
    }
    asnber_buf_release(ctx, &encoded);
    asnber_ocsp_response_builder_destroy(response);

    ASNBER_TEST_CHECK(asnber_ocsp_basic_builder_create(ctx, &basic) == ASNBER_OK);
    poison(&encoded);
    ASNBER_TEST_CHECK(asnber_ocsp_basic_builder_encode(basic, &encoded) ==
                    ASNBER_E_INVALID_STATE);
    ASNBER_TEST_CHECK(buf_cleared(&encoded));
    ASNBER_TEST_CHECK(asnber_ocsp_basic_builder_set_responder_name(
                        basic, kNullParams, sizeof(kNullParams)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_ocsp_basic_builder_set_responder_key(
                        basic, kKeyHash, sizeof(kKeyHash)) == ASNBER_E_INVALID_STATE);
    ASNBER_TEST_CHECK(asnber_ocsp_basic_builder_add_revoked(
                        basic, kSha1, kNullParams, sizeof(kNullParams), kNameHash,
                        sizeof(kNameHash), kKeyHash, sizeof(kKeyHash), kSerialTwo,
                        sizeof(kSerialTwo), &when, NULL, NULL, 1, 1) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_ocsp_basic_builder_add_revoked(
                        basic, kSha1, kNullParams, sizeof(kNullParams), kNameHash,
                        sizeof(kNameHash), kKeyHash, sizeof(kKeyHash), kSerialTwo,
                        sizeof(kSerialTwo), &when, NULL, &when, 7, 1) ==
                    ASNBER_E_INVALID_VALUE);
    asnber_ocsp_basic_builder_destroy(basic);
    asnber_ocsp_basic_builder_destroy(NULL);
    return 0;
}

int main(void)
{
    asnber_ctx_t *ctx = make_ctx();
    if (ctx == NULL) {
        return 1;
    }
    if (test_unsigned_request(ctx) != 0 || test_signed_request(ctx) != 0 ||
        test_basic_roundtrip(ctx, kOcspResponse, kOcspResponseSize) != 0 ||
        test_basic_roundtrip(ctx, kOcspResponseBykey, kOcspResponseBykeySize) !=
            0 ||
        test_negative(ctx) != 0) {
        asnber_ctx_destroy(ctx);
        return 1;
    }
    asnber_ctx_destroy(ctx);
    return 0;
}
