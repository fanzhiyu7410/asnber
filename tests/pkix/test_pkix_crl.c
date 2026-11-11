/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * CertificateList 结构往返：builder 组装，open 读回字段。
 * 不签名、不判断吊销。
 */

#include <asnber/asnber.h>
#include <asnber/pkix/pkix.h>

#include <string.h>

#include "check.h"

static asnber_ctx_t *make_ctx(void)
{
    asnber_ctx_config_t config;
    asnber_ctx_t *ctx = NULL;
    asnber_ctx_config_init(&config);
    if (asnber_ctx_create(&config, &ctx) != ASNBER_OK) {
        return NULL;
    }
    return ctx;
}

static void make_time(asnber_time_t *time, int32_t year, uint8_t month,
                      uint8_t day)
{
    memset(time, 0, sizeof(*time));
    time->struct_size = sizeof(*time);
    time->year = year;
    time->month = month;
    time->day = day;
}

static int test_roundtrip(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_pkix_crl_builder_t *builder = NULL;
    asnber_pkix_crl_t *crl = NULL;
    asnber_buf_t encoded;
    asnber_pkix_name_attribute_t attribute;
    asnber_pkix_name_rdn_t rdn;
    asnber_time_t this_update;
    asnber_time_t next_update;
    asnber_time_t revoked_at;
    const uint8_t serial[1] = {0x01};
    const uint8_t signature[1] = {0xAB};
    const uint8_t null_params[2] = {0x05, 0x00};
    const char *oid = NULL;
    size_t oid_size = 0;
    const uint8_t *issuer = NULL;
    size_t issuer_size = 0;
    const uint8_t *sig = NULL;
    size_t sig_size = 0;
    size_t bit_length = 0;
    uint8_t unused = 0xFF;
    uint32_t version = 99;
    asnber_time_t read_time;
    int present = 1;
    size_t count = 99;
    const char *decimal = NULL;
    size_t decimal_size = 0;
    const asnber_node_t *node = NULL;

    ASNBER_TEST_CHECK(ctx != NULL);
    memset(&encoded, 0, sizeof(encoded));
    memset(&attribute, 0, sizeof(attribute));
    attribute.oid = "2.5.4.6";
    attribute.value = (const uint8_t *)"CN";
    attribute.value_size = 2;
    rdn.attributes = &attribute;
    rdn.count = 1;
    make_time(&this_update, 2020, 1, 2);
    make_time(&next_update, 2021, 1, 2);
    make_time(&revoked_at, 2020, 6, 1);

    ASNBER_TEST_CHECK(asnber_pkix_crl_builder_create(ctx, &builder) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_crl_builder_encode(builder, &encoded) ==
                    ASNBER_E_INVALID_STATE);
    ASNBER_TEST_CHECK(asnber_pkix_crl_builder_set_version(builder, 2) ==
                    ASNBER_E_INVALID_VALUE);
    ASNBER_TEST_CHECK(asnber_pkix_crl_builder_set_version(builder, 1) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_crl_builder_set_signature_algorithm(
                        builder, "1.2.840.113549.1.1.11", null_params,
                        sizeof(null_params)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_crl_builder_set_issuer(builder, &rdn, 1) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_crl_builder_set_this_update(
                        builder, &this_update) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_crl_builder_set_next_update(
                        builder, &next_update) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_crl_builder_add_revoked(
                        builder, serial, sizeof(serial), &revoked_at) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_crl_builder_set_signature_value(
                        builder, signature, sizeof(signature), 0) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_crl_builder_encode(builder, &encoded) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(encoded.data != NULL && encoded.size > 0);

    ASNBER_TEST_CHECK(asnber_pkix_crl_open(ctx, encoded.data, encoded.size, &crl) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_crl_version(crl, &version) == ASNBER_OK);
    ASNBER_TEST_CHECK(version == 1);
    ASNBER_TEST_CHECK(asnber_pkix_crl_signature_algorithm_oid(crl, &oid,
                                                           &oid_size) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(oid != NULL);
    ASNBER_TEST_CHECK(strcmp(oid, "1.2.840.113549.1.1.11") == 0);
    ASNBER_TEST_CHECK(asnber_pkix_crl_issuer_der(crl, &issuer, &issuer_size) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(issuer != NULL && issuer_size > 0 && issuer[0] == 0x30);
    memset(&read_time, 0, sizeof(read_time));
    ASNBER_TEST_CHECK(asnber_pkix_crl_this_update(crl, &read_time) == ASNBER_OK);
    ASNBER_TEST_CHECK(read_time.year == 2020 && read_time.month == 1 &&
                    read_time.day == 2);
    present = 0;
    memset(&read_time, 0, sizeof(read_time));
    ASNBER_TEST_CHECK(asnber_pkix_crl_next_update(crl, &read_time, &present) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(present == 1);
    ASNBER_TEST_CHECK(read_time.year == 2021);
    ASNBER_TEST_CHECK(asnber_pkix_crl_revoked_count(crl, &count) == ASNBER_OK);
    ASNBER_TEST_CHECK(count == 1);
    ASNBER_TEST_CHECK(asnber_pkix_crl_revoked_serial(crl, 0, &decimal,
                                                   &decimal_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(decimal != NULL && strcmp(decimal, "1") == 0);
    ASNBER_TEST_CHECK(asnber_pkix_crl_revoked_serial(crl, 1, &decimal,
                                                   &decimal_size) ==
                    ASNBER_E_INVALID_ARG);
    memset(&read_time, 0, sizeof(read_time));
    ASNBER_TEST_CHECK(asnber_pkix_crl_revoked_date(crl, 0, &read_time) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(read_time.year == 2020 && read_time.month == 6);
    ASNBER_TEST_CHECK(asnber_pkix_crl_signature_value(crl, &sig, &sig_size,
                                                    &bit_length, &unused) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(sig != NULL && sig_size == 1 && sig[0] == 0xAB &&
                    unused == 0);
    ASNBER_TEST_CHECK(asnber_pkix_crl_find(crl, "tbsCertList.issuer", &node) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(node != NULL);
    ASNBER_TEST_CHECK(asnber_pkix_crl_find(crl, "tbsCertList.missing", &node) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(node == NULL);

    asnber_pkix_crl_close(crl);
    asnber_buf_release(ctx, &encoded);
    asnber_pkix_crl_builder_destroy(builder);
    asnber_pkix_crl_close(NULL);
    asnber_pkix_crl_builder_destroy(NULL);
    asnber_ctx_destroy(ctx);
    return 0;
}

static int test_v1_without_revocations(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_pkix_crl_builder_t *builder = NULL;
    asnber_pkix_crl_t *crl = NULL;
    asnber_buf_t encoded;
    asnber_pkix_name_attribute_t attribute;
    asnber_pkix_name_rdn_t rdn;
    asnber_time_t this_update;
    asnber_time_t read_time;
    const uint8_t signature[1] = {0x00};
    uint32_t version = 99;
    int present = 1;
    size_t count = 99;

    ASNBER_TEST_CHECK(ctx != NULL);
    memset(&encoded, 0, sizeof(encoded));
    memset(&attribute, 0, sizeof(attribute));
    attribute.oid = "2.5.4.6";
    attribute.value = (const uint8_t *)"CN";
    attribute.value_size = 2;
    rdn.attributes = &attribute;
    rdn.count = 1;
    make_time(&this_update, 2019, 12, 31);

    ASNBER_TEST_CHECK(asnber_pkix_crl_builder_create(ctx, &builder) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_crl_builder_set_signature_algorithm(
                        builder, "1.2.840.113549.1.1.11", NULL, 0) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_crl_builder_set_issuer(builder, &rdn, 1) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_crl_builder_set_this_update(
                        builder, &this_update) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_crl_builder_set_signature_value(
                        builder, signature, sizeof(signature), 0) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_crl_builder_encode(builder, &encoded) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_crl_open(ctx, encoded.data, encoded.size, &crl) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_pkix_crl_version(crl, &version) == ASNBER_OK);
    ASNBER_TEST_CHECK(version == 0);
    present = 1;
    memset(&read_time, 0, sizeof(read_time));
    ASNBER_TEST_CHECK(asnber_pkix_crl_next_update(crl, &read_time, &present) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(present == 0);
    ASNBER_TEST_CHECK(asnber_pkix_crl_revoked_count(crl, &count) == ASNBER_OK);
    ASNBER_TEST_CHECK(count == 0);

    asnber_pkix_crl_close(crl);
    asnber_buf_release(ctx, &encoded);
    asnber_pkix_crl_builder_destroy(builder);
    asnber_ctx_destroy(ctx);
    return 0;
}

int main(void)
{
    if (test_roundtrip() != 0) {
        return 1;
    }
    if (test_v1_without_revocations() != 0) {
        return 1;
    }
    return 0;
}
