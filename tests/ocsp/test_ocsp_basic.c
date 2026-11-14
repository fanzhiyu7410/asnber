/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * asnber-ocsp：BasicOCSPResponse 只读访问。
 * OpenSSL 成功响应含 good / revoked / unknown。producedAt、thisUpdate、
 * nextUpdate、nonce 和签名会随重新生成变化，测试不断言这些字节。
 */

#include <asnber/asnber.h>
#include <asnber/ocsp/ocsp.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../data/cert_rsa_selfsigned.h"
#include "../data/ocsp_request.h"
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
static const char kGoodSerial[] =
    "651241625021466612160683104114604757680343021109";

static const int kStatusGood = 0;
static const int kStatusRevoked = 1;
static const int kStatusUnknown = 2;

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

static int check_cert_id(const asnber_ocsp_basic_t *basic, size_t index,
                         const char *serial)
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
    const char *got = NULL;
    size_t got_size = 0;

    ASNBER_TEST_CHECK(asnber_ocsp_basic_cert_id(
                        basic, index, &oid, &oid_size, &params, &params_size,
                        &params_present, &name_hash, &name_hash_size, &key_hash,
                        &key_hash_size, &got, &got_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(text_is(oid, oid_size, "1.3.14.3.2.26"));
    ASNBER_TEST_CHECK(params_present == 1);
    ASNBER_TEST_CHECK(params != NULL && params_size == 2);
    ASNBER_TEST_CHECK(params[0] == 0x05 && params[1] == 0x00);
    ASNBER_TEST_CHECK(name_hash_size == sizeof(kNameHash));
    ASNBER_TEST_CHECK(memcmp(name_hash, kNameHash, sizeof(kNameHash)) == 0);
    ASNBER_TEST_CHECK(key_hash_size == sizeof(kKeyHash));
    ASNBER_TEST_CHECK(memcmp(key_hash, kKeyHash, sizeof(kKeyHash)) == 0);
    ASNBER_TEST_CHECK(text_is(got, got_size, serial));
    return 0;
}

static int check_time_ok(const asnber_time_t *time)
{
    ASNBER_TEST_CHECK(time->struct_size == sizeof(*time));
    ASNBER_TEST_CHECK((time->flags & ASNBER_TIME_GENERALIZED) != 0);
    ASNBER_TEST_CHECK(time->month >= 1 && time->month <= 12);
    ASNBER_TEST_CHECK(time->day >= 1 && time->day <= 31);
    return 0;
}

static int check_statuses(const asnber_ocsp_basic_t *basic)
{
    int status = -1;
    int present = 0;
    int64_t reason = -1;
    asnber_time_t when;
    asnber_time_t revocation;
    size_t count = 0;
    const char *oid = NULL;
    size_t oid_size = 0;
    int critical = 1;
    const uint8_t *value = NULL;
    size_t value_size = 0;

    memset(&when, 0, sizeof(when));
    memset(&revocation, 0, sizeof(revocation));

    ASNBER_TEST_CHECK(check_cert_id(basic, 0, kGoodSerial) == 0);
    ASNBER_TEST_CHECK(check_cert_id(basic, 1, "2") == 0);
    ASNBER_TEST_CHECK(check_cert_id(basic, 2, "3") == 0);
    ASNBER_TEST_CHECK(asnber_ocsp_basic_cert_id(
                        basic, 3, &oid, &oid_size, &value, &value_size, &critical,
                        &value, &value_size, &value, &value_size, &oid,
                        &oid_size) == ASNBER_E_INVALID_ARG);

    ASNBER_TEST_CHECK(asnber_ocsp_basic_cert_status(basic, 0, &status) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(status == kStatusGood);
    ASNBER_TEST_CHECK(asnber_ocsp_basic_revocation(basic, 0, &revocation, &reason,
                                                 &present) ==
                    ASNBER_E_INVALID_ARG);

    ASNBER_TEST_CHECK(asnber_ocsp_basic_cert_status(basic, 1, &status) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(status == kStatusRevoked);
    ASNBER_TEST_CHECK(asnber_ocsp_basic_revocation(basic, 1, &revocation, &reason,
                                                 &present) == ASNBER_OK);
    ASNBER_TEST_CHECK(revocation.year == 2024);
    ASNBER_TEST_CHECK(revocation.month == 11);
    ASNBER_TEST_CHECK(revocation.day == 14);
    ASNBER_TEST_CHECK(revocation.hour == 0);
    ASNBER_TEST_CHECK(revocation.minute == 0);
    ASNBER_TEST_CHECK(revocation.second == 0);
    ASNBER_TEST_CHECK((revocation.flags & ASNBER_TIME_GENERALIZED) != 0);
    ASNBER_TEST_CHECK((revocation.flags & ASNBER_TIME_HAS_OFFSET) == 0);
    ASNBER_TEST_CHECK(present == 1);
    ASNBER_TEST_CHECK(reason == 1);

    ASNBER_TEST_CHECK(asnber_ocsp_basic_cert_status(basic, 2, &status) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(status == kStatusUnknown);
    ASNBER_TEST_CHECK(asnber_ocsp_basic_revocation(basic, 2, &revocation, &reason,
                                                 &present) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_ocsp_basic_cert_status(basic, 3, &status) ==
                    ASNBER_E_INVALID_ARG);

    ASNBER_TEST_CHECK(asnber_ocsp_basic_this_update(basic, 0, &when) == ASNBER_OK);
    ASNBER_TEST_CHECK(check_time_ok(&when) == 0);
    ASNBER_TEST_CHECK(asnber_ocsp_basic_next_update(basic, 0, &when, &present) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(present == 1);
    ASNBER_TEST_CHECK(check_time_ok(&when) == 0);

    ASNBER_TEST_CHECK(asnber_ocsp_basic_single_extension_count(basic, 0,
                                                             &count) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(count == 0);
    ASNBER_TEST_CHECK(asnber_ocsp_basic_single_extension_at(
                        basic, 0, 0, &oid, &oid_size, &critical, &value,
                        &value_size) == ASNBER_E_INVALID_ARG);
    return 0;
}

static int check_signature(const asnber_ocsp_basic_t *basic)
{
    const char *oid = NULL;
    size_t oid_size = 0;
    const uint8_t *params = NULL;
    size_t params_size = 0;
    int params_present = 0;
    const uint8_t *bits = NULL;
    size_t bits_size = 0;
    size_t bit_length = 0;
    uint8_t unused = 0xFF;
    size_t cert_count = 0;
    const uint8_t *cert = NULL;
    size_t cert_size = 0;

    ASNBER_TEST_CHECK(asnber_ocsp_basic_signature(
                        basic, &oid, &oid_size, &params, &params_size,
                        &params_present, &bits, &bits_size, &bit_length, &unused,
                        &cert_count) == ASNBER_OK);
    ASNBER_TEST_CHECK(text_is(oid, oid_size, "1.2.840.113549.1.1.11"));
    ASNBER_TEST_CHECK(params_present == 1);
    ASNBER_TEST_CHECK(params != NULL && params_size == 2);
    ASNBER_TEST_CHECK(params[0] == 0x05 && params[1] == 0x00);
    ASNBER_TEST_CHECK(unused == 0);
    ASNBER_TEST_CHECK(bit_length == 2048);
    ASNBER_TEST_CHECK(bits != NULL && bits_size == 256);
    ASNBER_TEST_CHECK(cert_count == 1);
    ASNBER_TEST_CHECK(asnber_ocsp_basic_signature_cert(basic, 0, &cert,
                                                     &cert_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(cert_size == kCertRsaSelfsignedSize);
    ASNBER_TEST_CHECK(memcmp(cert, kCertRsaSelfsigned, cert_size) == 0);
    ASNBER_TEST_CHECK(asnber_ocsp_basic_signature_cert(basic, 1, &cert,
                                                     &cert_size) ==
                    ASNBER_E_INVALID_ARG);
    return 0;
}

static int test_openssl_response(asnber_ctx_t *ctx)
{
    asnber_ocsp_response_t *response = NULL;
    asnber_ocsp_response_t *rejected_response = NULL;
    asnber_ocsp_basic_t *basic = NULL;
    asnber_ocsp_basic_t *rejected = NULL;
    const char *type_oid = NULL;
    size_t type_oid_size = 0;
    const uint8_t *payload = NULL;
    size_t payload_size = 0;
    int present = 0;
    int64_t response_status = -1;
    uint32_t version = 99;
    int choice = 0;
    const uint8_t *name = NULL;
    size_t name_size = 0;
    const uint8_t *key = NULL;
    size_t key_size = 0;
    asnber_time_t produced;
    size_t count = 0;
    const char *ext_oid = NULL;
    size_t ext_oid_size = 0;
    int critical = 1;
    const uint8_t *ext_value = NULL;
    size_t ext_value_size = 0;

    memset(&produced, 0, sizeof(produced));

    ASNBER_TEST_CHECK(asnber_ocsp_response_open(
                        ctx, kOcspResponse, kOcspResponseSize, &response) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_ocsp_response_status(response, &response_status) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(response_status == 0);
    ASNBER_TEST_CHECK(asnber_ocsp_response_bytes(
                        response, &type_oid, &type_oid_size, &payload,
                        &payload_size, &present) == ASNBER_OK);
    ASNBER_TEST_CHECK(present == 1);
    ASNBER_TEST_CHECK(text_is(type_oid, type_oid_size, "1.3.6.1.5.5.7.48.1.1"));
    ASNBER_TEST_CHECK(payload != NULL && payload_size > 0);

    ASNBER_TEST_CHECK(asnber_ocsp_basic_open(ctx, kOcspResponse, kOcspResponseSize,
                                           &rejected) != ASNBER_OK);
    ASNBER_TEST_CHECK(rejected == NULL);
    ASNBER_TEST_CHECK(asnber_ocsp_basic_open(ctx, payload, payload_size, &basic) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_ocsp_response_open(ctx, payload, payload_size,
                                              &rejected_response) != ASNBER_OK);
    ASNBER_TEST_CHECK(rejected_response == NULL);

    ASNBER_TEST_CHECK(asnber_ocsp_basic_version(basic, &version) == ASNBER_OK);
    ASNBER_TEST_CHECK(version == 0);
    ASNBER_TEST_CHECK(asnber_ocsp_basic_responder(basic, &choice, &name,
                                                &name_size, &key,
                                                &key_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(choice == 1);
    ASNBER_TEST_CHECK(name != NULL && name_size > 2);
    ASNBER_TEST_CHECK(name[0] == 0x30);
    ASNBER_TEST_CHECK(key == NULL && key_size == 0);
    ASNBER_TEST_CHECK(asnber_ocsp_basic_produced_at(basic, &produced) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(check_time_ok(&produced) == 0);
    ASNBER_TEST_CHECK(asnber_ocsp_basic_response_count(basic, &count) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(count == 3);
    ASNBER_TEST_CHECK(check_statuses(basic) == 0);

    ASNBER_TEST_CHECK(asnber_ocsp_basic_extension_count(basic, &count) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(count == 1);
    ASNBER_TEST_CHECK(asnber_ocsp_basic_extension_at(
                        basic, 0, &ext_oid, &ext_oid_size, &critical, &ext_value,
                        &ext_value_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(text_is(ext_oid, ext_oid_size, "1.3.6.1.5.5.7.48.1.2"));
    ASNBER_TEST_CHECK(critical == 0);
    ASNBER_TEST_CHECK(ext_value != NULL && ext_value_size > 0);
    ASNBER_TEST_CHECK(asnber_ocsp_basic_extension_at(
                        basic, 1, &ext_oid, &ext_oid_size, &critical, &ext_value,
                        &ext_value_size) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(check_signature(basic) == 0);

    asnber_ocsp_basic_close(basic);
    asnber_ocsp_basic_close(NULL);
    asnber_ocsp_response_close(response);
    return 0;
}

static int test_openssl_bykey(asnber_ctx_t *ctx)
{
    asnber_ocsp_response_t *response = NULL;
    asnber_ocsp_basic_t *basic = NULL;
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

    ASNBER_TEST_CHECK(asnber_ocsp_response_open(ctx, kOcspResponseBykey,
                                              kOcspResponseBykeySize,
                                              &response) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_ocsp_response_bytes(
                        response, &type_oid, &type_oid_size, &payload,
                        &payload_size, &present) == ASNBER_OK);
    ASNBER_TEST_CHECK(present == 1);
    ASNBER_TEST_CHECK(asnber_ocsp_basic_open(ctx, payload, payload_size, &basic) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_ocsp_basic_responder(basic, &choice, &name,
                                                &name_size, &key,
                                                &key_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(choice == 2);
    ASNBER_TEST_CHECK(name == NULL && name_size == 0);
    ASNBER_TEST_CHECK(key != NULL && key_size == sizeof(kKeyHash));
    ASNBER_TEST_CHECK(memcmp(key, kKeyHash, sizeof(kKeyHash)) == 0);
    ASNBER_TEST_CHECK(check_statuses(basic) == 0);
    ASNBER_TEST_CHECK(check_signature(basic) == 0);

    asnber_ocsp_basic_close(basic);
    asnber_ocsp_response_close(response);
    return 0;
}

static int test_negative(asnber_ctx_t *ctx)
{
    asnber_ocsp_basic_t *basic = NULL;
    uint32_t version = 0;
    size_t count = 0;
    static const unsigned char kNotBasic[] = {0x01, 0x02, 0x03};

    ASNBER_TEST_CHECK(asnber_ocsp_basic_open(NULL, kOcspResponse, kOcspResponseSize,
                                           &basic) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(basic == NULL);
    ASNBER_TEST_CHECK(asnber_ocsp_basic_open(ctx, NULL, kOcspResponseSize,
                                           &basic) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_ocsp_basic_open(ctx, kOcspResponse, 0, &basic) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_ocsp_basic_open(ctx, kNotBasic, sizeof(kNotBasic),
                                           &basic) != ASNBER_OK);
    ASNBER_TEST_CHECK(basic == NULL);
    ASNBER_TEST_CHECK(asnber_ocsp_basic_open(ctx, kOcspRequest, kOcspRequestSize,
                                           &basic) != ASNBER_OK);
    ASNBER_TEST_CHECK(basic == NULL);
    ASNBER_TEST_CHECK(asnber_ocsp_basic_version(NULL, &version) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_ocsp_basic_response_count(NULL, &count) ==
                    ASNBER_E_INVALID_ARG);
    return 0;
}

int main(void)
{
    asnber_ctx_t *ctx = make_ctx();
    if (ctx == NULL) {
        return 1;
    }
    if (test_openssl_response(ctx) != 0 || test_openssl_bykey(ctx) != 0 ||
        test_negative(ctx) != 0) {
        asnber_ctx_destroy(ctx);
        return 1;
    }
    asnber_ctx_destroy(ctx);
    return 0;
}
