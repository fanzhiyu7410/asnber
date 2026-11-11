/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * 语义读取：BOOLEAN、INTEGER、OCTET/BIT STRING、OID、字符串、大整数与时间。
 */
#include <asnber/asnber.h>

#include <stddef.h>
#include <string.h>

#include "check.h"

static asnber_doc_t *decode_one(asnber_ctx_t *ctx, const uint8_t *data,
                              size_t size)
{
    asnber_doc_t *doc = NULL;
    size_t consumed = 0;
    if (asnber_decode_buffer(ctx, data, size, NULL, &doc, &consumed) != ASNBER_OK) {
        return NULL;
    }
    return doc;
}

static int expectTimeError(asnber_ctx_t *ctx, const uint8_t *data, size_t size,
                           asnber_err_t expected)
{
    asnber_doc_t *doc = decode_one(ctx, data, size);
    ASNBER_TEST_CHECK(doc != NULL);
    asnber_time_t time;
    memset(&time, 0, sizeof(time));
    time.struct_size = sizeof(time);
    ASNBER_TEST_CHECK(asnber_node_get_time(asnber_doc_root(doc), &time) == expected);
    asnber_doc_destroy(doc);
    return 0;
}

int main(void)
{
    asnber_ctx_config_t config;
    asnber_ctx_config_init(&config);
    asnber_ctx_t *ctx = NULL;
    ASNBER_TEST_CHECK(asnber_ctx_create(&config, &ctx) == ASNBER_OK);

    /* BOOLEAN。 */
    static const uint8_t bool_false[] = {0x01, 0x01, 0x00};
    asnber_doc_t *doc = decode_one(ctx, bool_false, sizeof(bool_false));
    ASNBER_TEST_CHECK(doc != NULL);
    int bool_value = -1;
    ASNBER_TEST_CHECK(asnber_node_get_bool(asnber_doc_root(doc), &bool_value) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(bool_value == 0);
    asnber_doc_destroy(doc);

    static const uint8_t bool_true[] = {0x01, 0x01, 0xFF};
    doc = decode_one(ctx, bool_true, sizeof(bool_true));
    ASNBER_TEST_CHECK(doc != NULL);
    ASNBER_TEST_CHECK(asnber_node_get_bool(asnber_doc_root(doc), &bool_value) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(bool_value == 1);
    asnber_doc_destroy(doc);

    /* DER 下 BOOLEAN 非 0xFF/0x00 在解码阶段即被拒。 */
    static const uint8_t bool_der_bad[] = {0x01, 0x01, 0x01};
    asnber_decode_options_t options;
    asnber_decode_options_init(&options);
    options.encoding = ASNBER_ENCODING_DER;
    size_t consumed = 0;
    doc = NULL;
    ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, bool_der_bad, sizeof(bool_der_bad),
                                       &options, &doc, &consumed) ==
                    ASNBER_E_NON_CANONICAL);
    ASNBER_TEST_CHECK(doc == NULL);

    /* INTEGER：负数、正数、越界。 */
    static const uint8_t integer_neg[] = {0x02, 0x01, 0xFF};
    doc = decode_one(ctx, integer_neg, sizeof(integer_neg));
    ASNBER_TEST_CHECK(doc != NULL);
    int64_t int_value = 0;
    ASNBER_TEST_CHECK(asnber_node_get_int64(asnber_doc_root(doc), &int_value) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(int_value == -1);
    asnber_doc_destroy(doc);

    static const uint8_t integer_255[] = {0x02, 0x02, 0x00, 0xFF};
    doc = decode_one(ctx, integer_255, sizeof(integer_255));
    ASNBER_TEST_CHECK(doc != NULL);
    ASNBER_TEST_CHECK(asnber_node_get_int64(asnber_doc_root(doc), &int_value) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(int_value == 255);
    asnber_doc_destroy(doc);

    static const uint8_t integer_range[] = {
        0x02, 0x09, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    doc = decode_one(ctx, integer_range, sizeof(integer_range));
    ASNBER_TEST_CHECK(doc != NULL);
    ASNBER_TEST_CHECK(asnber_node_get_int64(asnber_doc_root(doc), &int_value) ==
                    ASNBER_E_RANGE);
    asnber_doc_destroy(doc);

    /* 构造 OCTET STRING 合并。 */
    static const uint8_t octets_constructed[] = {
        0x24, 0x09, 0x04, 0x03, 0x01, 0x02, 0x03, 0x04, 0x02, 0x04, 0x05};
    doc = decode_one(ctx, octets_constructed, sizeof(octets_constructed));
    ASNBER_TEST_CHECK(doc != NULL);
    const uint8_t *data = NULL;
    size_t size = 0;
    ASNBER_TEST_CHECK(asnber_node_get_octets(asnber_doc_root(doc), &data, &size) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(size == 5);
    ASNBER_TEST_CHECK(data != NULL);
    ASNBER_TEST_CHECK(memcmp(data, "\x01\x02\x03\x04\x05", 5) == 0);
    ASNBER_TEST_CHECK(asnber_node_content(asnber_doc_root(doc), &data, &size) ==
                    ASNBER_E_INVALID_STATE);
    asnber_doc_destroy(doc);

    /* BIT STRING：非零与零值。 */
    static const uint8_t bits[] = {0x03, 0x02, 0x04, 0xA0};
    doc = decode_one(ctx, bits, sizeof(bits));
    ASNBER_TEST_CHECK(doc != NULL);
    size_t bit_length = 0;
    uint8_t unused = 0;
    ASNBER_TEST_CHECK(asnber_node_get_bits(asnber_doc_root(doc), &data, &size,
                                       &bit_length, &unused) == ASNBER_OK);
    ASNBER_TEST_CHECK(size == 1);
    ASNBER_TEST_CHECK(bit_length == 4);
    ASNBER_TEST_CHECK(unused == 4);
    ASNBER_TEST_CHECK(data != NULL && data[0] == 0xA0);
    asnber_doc_destroy(doc);

    static const uint8_t bits_zero[] = {0x03, 0x01, 0x00};
    doc = decode_one(ctx, bits_zero, sizeof(bits_zero));
    ASNBER_TEST_CHECK(doc != NULL);
    ASNBER_TEST_CHECK(asnber_node_get_bits(asnber_doc_root(doc), &data, &size,
                                       &bit_length, &unused) == ASNBER_OK);
    ASNBER_TEST_CHECK(size == 0);
    ASNBER_TEST_CHECK(bit_length == 0);
    ASNBER_TEST_CHECK(unused == 0);
    asnber_doc_destroy(doc);

    /* BER 构造 BIT STRING：两段不同 unused_bits 的按位拼接。 */
    static const uint8_t bits_constructed[] = {
        0x23, 0x08, 0x03, 0x02, 0x00, 0x0F, 0x03, 0x02, 0x04, 0xA0};
    doc = decode_one(ctx, bits_constructed, sizeof(bits_constructed));
    ASNBER_TEST_CHECK(doc != NULL);
    ASNBER_TEST_CHECK(asnber_node_get_bits(asnber_doc_root(doc), &data, &size,
                                       &bit_length, &unused) == ASNBER_OK);
    ASNBER_TEST_CHECK(size == 2);
    ASNBER_TEST_CHECK(bit_length == 12);
    ASNBER_TEST_CHECK(unused == 4);
    ASNBER_TEST_CHECK(data != NULL && data[0] == 0x0F && data[1] == 0xA0);
    asnber_doc_destroy(doc);

    /* 构造 BIT STRING 内出现非 BIT STRING 段 / unused_bits 越界。 */
    static const uint8_t bits_constructed_bad_child[] = {
        0x23, 0x04, 0x04, 0x02, 0x00, 0x00};
    doc = decode_one(ctx, bits_constructed_bad_child,
                     sizeof(bits_constructed_bad_child));
    ASNBER_TEST_CHECK(doc != NULL);
    ASNBER_TEST_CHECK(asnber_node_get_bits(asnber_doc_root(doc), &data, &size,
                                       &bit_length, &unused) ==
                    ASNBER_E_MALFORMED_VALUE);
    asnber_doc_destroy(doc);

    static const uint8_t bits_unused_overflow[] = {0x03, 0x02, 0x08, 0x00};
    doc = decode_one(ctx, bits_unused_overflow, sizeof(bits_unused_overflow));
    ASNBER_TEST_CHECK(doc != NULL);
    ASNBER_TEST_CHECK(asnber_node_get_bits(asnber_doc_root(doc), &data, &size,
                                       &bit_length, &unused) ==
                    ASNBER_E_MALFORMED_VALUE);
    asnber_doc_destroy(doc);

    /* OID。 */
    static const uint8_t oid[] = {0x06, 0x03, 0x55, 0x04, 0x03};
    doc = decode_one(ctx, oid, sizeof(oid));
    ASNBER_TEST_CHECK(doc != NULL);
    const char *text = NULL;
    ASNBER_TEST_CHECK(asnber_node_get_oid(asnber_doc_root(doc), &text, &size) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(size == 7);
    ASNBER_TEST_CHECK(strcmp(text, "2.5.4.3") == 0);
    asnber_doc_destroy(doc);

    /* 字符串：PrintableString、UTF8String、T61 拒绝。 */
    static const uint8_t printable[] = {0x13, 0x03, 0x61, 0x62, 0x63};
    doc = decode_one(ctx, printable, sizeof(printable));
    ASNBER_TEST_CHECK(doc != NULL);
    ASNBER_TEST_CHECK(asnber_node_get_utf8(asnber_doc_root(doc), &text, &size) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(size == 3);
    ASNBER_TEST_CHECK(strcmp(text, "abc") == 0);
    ASNBER_TEST_CHECK(asnber_node_get_raw_string(asnber_doc_root(doc), &data,
                                             &size) == ASNBER_OK);
    ASNBER_TEST_CHECK(size == 3);
    asnber_doc_destroy(doc);

    static const uint8_t utf8_chinese[] = {0x0C, 0x03, 0xE4, 0xB8, 0xAD};
    doc = decode_one(ctx, utf8_chinese, sizeof(utf8_chinese));
    ASNBER_TEST_CHECK(doc != NULL);
    ASNBER_TEST_CHECK(asnber_node_get_utf8(asnber_doc_root(doc), &text, &size) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(size == 3);
    asnber_doc_destroy(doc);

    static const uint8_t t61[] = {0x14, 0x01, 0x41};
    doc = decode_one(ctx, t61, sizeof(t61));
    ASNBER_TEST_CHECK(doc != NULL);
    ASNBER_TEST_CHECK(asnber_node_get_utf8(asnber_doc_root(doc), &text, &size) ==
                    ASNBER_E_CONVERSION);
    ASNBER_TEST_CHECK(asnber_node_get_raw_string(asnber_doc_root(doc), &data,
                                             &size) == ASNBER_OK);
    ASNBER_TEST_CHECK(size == 1);
    asnber_doc_destroy(doc);

    /* 空 UTF8String：合法空串走零长度分支。 */
    static const uint8_t utf8_empty[] = {0x0C, 0x00};
    doc = decode_one(ctx, utf8_empty, sizeof(utf8_empty));
    ASNBER_TEST_CHECK(doc != NULL);
    ASNBER_TEST_CHECK(asnber_node_get_utf8(asnber_doc_root(doc), &text, &size) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(text == NULL);
    ASNBER_TEST_CHECK(size == 0);
    asnber_doc_destroy(doc);

    /* 四字节 UTF-8（U+1F600）往返。 */
    static const uint8_t utf8_emoji[] = {0x0C, 0x04, 0xF0, 0x9F, 0x98, 0x80};
    doc = decode_one(ctx, utf8_emoji, sizeof(utf8_emoji));
    ASNBER_TEST_CHECK(doc != NULL);
    ASNBER_TEST_CHECK(asnber_node_get_utf8(asnber_doc_root(doc), &text, &size) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(size == 4);
    ASNBER_TEST_CHECK(memcmp(text, "\xF0\x9F\x98\x80", 4) == 0);
    asnber_doc_destroy(doc);

    /* UTF-8 非法序列：截断、坏续字节、过长编码、代理区、越界与非法首字节。 */
    static const uint8_t utf8_two_truncated[] = {0x0C, 0x01, 0xC2};
    static const uint8_t utf8_bad_continuation[] = {0x0C, 0x02, 0xC2, 0x41};
    static const uint8_t utf8_overlong_two[] = {0x0C, 0x02, 0xC0, 0x80};
    static const uint8_t utf8_overlong_three[] = {0x0C, 0x03, 0xE0, 0x80, 0x80};
    static const uint8_t utf8_surrogate[] = {0x0C, 0x03, 0xED, 0xA0, 0x80};
    static const uint8_t utf8_too_large[] = {0x0C, 0x04, 0xF4, 0x90, 0x80, 0x80};
    static const uint8_t utf8_four_truncated[] = {0x0C, 0x03, 0xF0, 0x9F, 0x98};
    static const uint8_t utf8_bad_lead[] = {0x0C, 0x01, 0xF5};
    static const uint8_t utf8_stray_continuation[] = {0x0C, 0x01, 0x80};
    static const struct {
        const uint8_t *bytes;
        size_t size;
    } utf8_invalid[] = {
        {utf8_two_truncated, sizeof(utf8_two_truncated)},
        {utf8_bad_continuation, sizeof(utf8_bad_continuation)},
        {utf8_overlong_two, sizeof(utf8_overlong_two)},
        {utf8_overlong_three, sizeof(utf8_overlong_three)},
        {utf8_surrogate, sizeof(utf8_surrogate)},
        {utf8_too_large, sizeof(utf8_too_large)},
        {utf8_four_truncated, sizeof(utf8_four_truncated)},
        {utf8_bad_lead, sizeof(utf8_bad_lead)},
        {utf8_stray_continuation, sizeof(utf8_stray_continuation)},
    };
    for (size_t i = 0; i < sizeof(utf8_invalid) / sizeof(utf8_invalid[0]);
         ++i) {
        doc = decode_one(ctx, utf8_invalid[i].bytes, utf8_invalid[i].size);
        ASNBER_TEST_CHECK(doc != NULL);
        text = NULL;
        ASNBER_TEST_CHECK(asnber_node_get_utf8(asnber_doc_root(doc), &text, &size) ==
                        ASNBER_E_CONVERSION);
        asnber_doc_destroy(doc);
    }

    /* ASCII 家族字符集不接受高位字节。 */
    static const uint8_t printable_high[] = {0x13, 0x01, 0x80};
    doc = decode_one(ctx, printable_high, sizeof(printable_high));
    ASNBER_TEST_CHECK(doc != NULL);
    ASNBER_TEST_CHECK(asnber_node_get_utf8(asnber_doc_root(doc), &text, &size) ==
                    ASNBER_E_CONVERSION);
    asnber_doc_destroy(doc);

    /* BMPString：ASCII、代理对与各类非法组合。 */
    static const uint8_t bmp_ascii[] = {0x1E, 0x02, 0x00, 0x41};
    doc = decode_one(ctx, bmp_ascii, sizeof(bmp_ascii));
    ASNBER_TEST_CHECK(doc != NULL);
    ASNBER_TEST_CHECK(asnber_node_get_utf8(asnber_doc_root(doc), &text, &size) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(size == 1);
    ASNBER_TEST_CHECK(strcmp(text, "A") == 0);
    asnber_doc_destroy(doc);

    static const uint8_t bmp_pair[] = {0x1E, 0x04, 0xD8, 0x3D, 0xDE, 0x00};
    doc = decode_one(ctx, bmp_pair, sizeof(bmp_pair));
    ASNBER_TEST_CHECK(doc != NULL);
    ASNBER_TEST_CHECK(asnber_node_get_utf8(asnber_doc_root(doc), &text, &size) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(size == 4);
    ASNBER_TEST_CHECK(memcmp(text, "\xF0\x9F\x98\x80", 4) == 0);
    asnber_doc_destroy(doc);

    static const uint8_t bmp_odd[] = {0x1E, 0x01, 0x00};
    static const uint8_t bmp_lone_high[] = {0x1E, 0x02, 0xD8, 0x00};
    static const uint8_t bmp_bad_low[] = {0x1E, 0x04, 0xD8, 0x00, 0x00, 0x41};
    static const uint8_t bmp_lone_low[] = {0x1E, 0x02, 0xDC, 0x00};
    static const struct {
        const uint8_t *bytes;
        size_t size;
    } bmp_invalid[] = {
        {bmp_odd, sizeof(bmp_odd)},
        {bmp_lone_high, sizeof(bmp_lone_high)},
        {bmp_bad_low, sizeof(bmp_bad_low)},
        {bmp_lone_low, sizeof(bmp_lone_low)},
    };
    for (size_t i = 0; i < sizeof(bmp_invalid) / sizeof(bmp_invalid[0]); ++i) {
        doc = decode_one(ctx, bmp_invalid[i].bytes, bmp_invalid[i].size);
        ASNBER_TEST_CHECK(doc != NULL);
        text = NULL;
        ASNBER_TEST_CHECK(asnber_node_get_utf8(asnber_doc_root(doc), &text, &size) ==
                        ASNBER_E_CONVERSION);
        asnber_doc_destroy(doc);
    }

    /* UniversalString：合法码点、长度非 4 的倍数、越界与代理区。 */
    static const uint8_t universal_ascii[] = {0x1C, 0x04, 0x00, 0x00, 0x00, 0x41};
    doc = decode_one(ctx, universal_ascii, sizeof(universal_ascii));
    ASNBER_TEST_CHECK(doc != NULL);
    ASNBER_TEST_CHECK(asnber_node_get_utf8(asnber_doc_root(doc), &text, &size) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(size == 1);
    ASNBER_TEST_CHECK(strcmp(text, "A") == 0);
    asnber_doc_destroy(doc);

    static const uint8_t universal_short[] = {0x1C, 0x02, 0x00, 0x41};
    static const uint8_t universal_too_large[] = {0x1C, 0x04, 0x00, 0x11, 0x00,
                                                  0x00};
    static const uint8_t universal_surrogate[] = {0x1C, 0x04, 0x00, 0x00, 0xD8,
                                                  0x00};
    static const struct {
        const uint8_t *bytes;
        size_t size;
    } universal_invalid[] = {
        {universal_short, sizeof(universal_short)},
        {universal_too_large, sizeof(universal_too_large)},
        {universal_surrogate, sizeof(universal_surrogate)},
    };
    for (size_t i = 0;
         i < sizeof(universal_invalid) / sizeof(universal_invalid[0]); ++i) {
        doc = decode_one(ctx, universal_invalid[i].bytes,
                         universal_invalid[i].size);
        ASNBER_TEST_CHECK(doc != NULL);
        text = NULL;
        ASNBER_TEST_CHECK(asnber_node_get_utf8(asnber_doc_root(doc), &text, &size) ==
                        ASNBER_E_CONVERSION);
        asnber_doc_destroy(doc);
    }

    /* 大整数十进制。 */
    static const uint8_t bigint_neg[] = {0x02, 0x01, 0x80};
    doc = decode_one(ctx, bigint_neg, sizeof(bigint_neg));
    ASNBER_TEST_CHECK(doc != NULL);
    ASNBER_TEST_CHECK(asnber_node_get_bigint_decimal(asnber_doc_root(doc), &text,
                                                 &size) == ASNBER_OK);
    ASNBER_TEST_CHECK(strcmp(text, "-128") == 0);
    ASNBER_TEST_CHECK(size == 4);
    asnber_doc_destroy(doc);

    static const uint8_t bigint_255[] = {0x02, 0x02, 0x00, 0xFF};
    doc = decode_one(ctx, bigint_255, sizeof(bigint_255));
    ASNBER_TEST_CHECK(doc != NULL);
    ASNBER_TEST_CHECK(asnber_node_get_bigint_decimal(asnber_doc_root(doc), &text,
                                                 &size) == ASNBER_OK);
    ASNBER_TEST_CHECK(strcmp(text, "255") == 0);
    asnber_doc_destroy(doc);

    /* 时间：UTCTime、GeneralizedTime 小数、DER 缺秒。 */
    static const uint8_t utc_time[] = {
        0x17, 0x0D, 0x39, 0x39, 0x30, 0x31, 0x30, 0x31,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A};
    doc = decode_one(ctx, utc_time, sizeof(utc_time));
    ASNBER_TEST_CHECK(doc != NULL);
    asnber_time_t time;
    time.struct_size = sizeof(time);
    ASNBER_TEST_CHECK(asnber_node_get_time(asnber_doc_root(doc), &time) == ASNBER_OK);
    ASNBER_TEST_CHECK(time.year == 1999);
    ASNBER_TEST_CHECK(time.month == 1);
    ASNBER_TEST_CHECK(time.day == 1);
    ASNBER_TEST_CHECK(time.hour == 0);
    ASNBER_TEST_CHECK((time.flags & ASNBER_TIME_UTC) != 0);
    ASNBER_TEST_CHECK((time.flags & ASNBER_TIME_HAS_OFFSET) == 0);
    ASNBER_TEST_CHECK((time.flags & ASNBER_TIME_LOCAL) == 0);
    asnber_doc_destroy(doc);

    static const uint8_t generalized[] = {
        0x18, 0x11, 0x32, 0x30, 0x32, 0x34, 0x30, 0x31, 0x30,
        0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x2E, 0x35, 0x5A};
    doc = decode_one(ctx, generalized, sizeof(generalized));
    ASNBER_TEST_CHECK(doc != NULL);
    time.struct_size = sizeof(time);
    ASNBER_TEST_CHECK(asnber_node_get_time(asnber_doc_root(doc), &time) == ASNBER_OK);
    ASNBER_TEST_CHECK(time.year == 2024);
    ASNBER_TEST_CHECK(time.nanosecond == 500000000);
    ASNBER_TEST_CHECK((time.flags & ASNBER_TIME_GENERALIZED) != 0);
    ASNBER_TEST_CHECK((time.flags & ASNBER_TIME_FRACTIONAL) != 0);
    asnber_doc_destroy(doc);

    static const uint8_t utc_der_no_seconds[] = {
        0x17, 0x0B, 0x39, 0x39, 0x30, 0x31, 0x30, 0x31,
        0x30, 0x30, 0x30, 0x30, 0x5A};
    asnber_decode_options_init(&options);
    options.encoding = ASNBER_ENCODING_DER;
    doc = NULL;
    ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, utc_der_no_seconds,
                                       sizeof(utc_der_no_seconds), &options,
                                       &doc, &consumed) ==
                    ASNBER_E_NON_CANONICAL);
    ASNBER_TEST_CHECK(doc == NULL);

    /* BER 本地时间：无偏移。 */
    static const uint8_t utc_local[] = {
        0x17, 0x0A, 0x39, 0x39, 0x30, 0x31,
        0x30, 0x31, 0x30, 0x30, 0x30, 0x30};
    doc = decode_one(ctx, utc_local, sizeof(utc_local));
    ASNBER_TEST_CHECK(doc != NULL);
    time.struct_size = sizeof(time);
    ASNBER_TEST_CHECK(asnber_node_get_time(asnber_doc_root(doc), &time) == ASNBER_OK);
    ASNBER_TEST_CHECK((time.flags & ASNBER_TIME_LOCAL) != 0);
    ASNBER_TEST_CHECK((time.flags & ASNBER_TIME_HAS_OFFSET) == 0);
    ASNBER_TEST_CHECK(time.utc_offset_minutes == 0);
    asnber_doc_destroy(doc);

    /* 时间偏移、小数与各类非法输入。 */
    static const uint8_t utc_offset_plus[] = {
        0x17, 0x11, 0x39, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32,
        0x33, 0x35, 0x39, 0x35, 0x39, 0x2B, 0x30, 0x31, 0x33, 0x30};
    doc = decode_one(ctx, utc_offset_plus, sizeof(utc_offset_plus));
    ASNBER_TEST_CHECK(doc != NULL);
    time.struct_size = sizeof(time);
    ASNBER_TEST_CHECK(asnber_node_get_time(asnber_doc_root(doc), &time) == ASNBER_OK);
    ASNBER_TEST_CHECK(time.year == 1999);
    ASNBER_TEST_CHECK(time.month == 12 && time.day == 31);
    ASNBER_TEST_CHECK(time.second == 59);
    ASNBER_TEST_CHECK(time.utc_offset_minutes == 90);
    ASNBER_TEST_CHECK((time.flags & ASNBER_TIME_HAS_OFFSET) != 0);
    ASNBER_TEST_CHECK((time.flags & ASNBER_TIME_LOCAL) == 0);
    asnber_doc_destroy(doc);

    static const uint8_t utc_offset_minus[] = {
        0x17, 0x11, 0x32, 0x34, 0x30, 0x31, 0x30, 0x31, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x2D, 0x30, 0x35, 0x30, 0x30};
    doc = decode_one(ctx, utc_offset_minus, sizeof(utc_offset_minus));
    ASNBER_TEST_CHECK(doc != NULL);
    time.struct_size = sizeof(time);
    ASNBER_TEST_CHECK(asnber_node_get_time(asnber_doc_root(doc), &time) == ASNBER_OK);
    ASNBER_TEST_CHECK(time.year == 2024);
    ASNBER_TEST_CHECK(time.utc_offset_minutes == -300);
    asnber_doc_destroy(doc);

    /* BER 允许省略秒。 */
    static const uint8_t utc_no_seconds[] = {
        0x17, 0x0B, 0x39, 0x39, 0x31, 0x32, 0x33, 0x31,
        0x32, 0x33, 0x35, 0x39, 0x5A};
    doc = decode_one(ctx, utc_no_seconds, sizeof(utc_no_seconds));
    ASNBER_TEST_CHECK(doc != NULL);
    time.struct_size = sizeof(time);
    ASNBER_TEST_CHECK(asnber_node_get_time(asnber_doc_root(doc), &time) == ASNBER_OK);
    ASNBER_TEST_CHECK(time.second == 0);
    ASNBER_TEST_CHECK(time.minute == 59);
    asnber_doc_destroy(doc);

    static const uint8_t gen_offset[] = {
        0x18, 0x13, 0x32, 0x30, 0x32, 0x34, 0x30, 0x31, 0x30, 0x31,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x2B, 0x30, 0x35, 0x33, 0x30};
    doc = decode_one(ctx, gen_offset, sizeof(gen_offset));
    ASNBER_TEST_CHECK(doc != NULL);
    time.struct_size = sizeof(time);
    ASNBER_TEST_CHECK(asnber_node_get_time(asnber_doc_root(doc), &time) == ASNBER_OK);
    ASNBER_TEST_CHECK(time.utc_offset_minutes == 330);
    ASNBER_TEST_CHECK((time.flags & ASNBER_TIME_GENERALIZED) != 0);
    ASNBER_TEST_CHECK((time.flags & ASNBER_TIME_HAS_OFFSET) != 0);
    asnber_doc_destroy(doc);

    /* GeneralizedTime 以逗号作小数分隔符；超过 9 位只取前 9 位。 */
    static const uint8_t gen_comma_fraction[] = {
        0x18, 0x12, 0x32, 0x30, 0x32, 0x34, 0x30, 0x31, 0x30,
        0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x2C, 0x32,
        0x35, 0x5A};
    doc = decode_one(ctx, gen_comma_fraction, sizeof(gen_comma_fraction));
    ASNBER_TEST_CHECK(doc != NULL);
    time.struct_size = sizeof(time);
    ASNBER_TEST_CHECK(asnber_node_get_time(asnber_doc_root(doc), &time) == ASNBER_OK);
    ASNBER_TEST_CHECK(time.nanosecond == 250000000u);
    ASNBER_TEST_CHECK((time.flags & ASNBER_TIME_FRACTIONAL) != 0);
    asnber_doc_destroy(doc);

    static const uint8_t gen_long_fraction[] = {
        0x18, 0x1C, 0x32, 0x30, 0x32, 0x34, 0x30, 0x31, 0x30, 0x31,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x2E, 0x31, 0x32, 0x33,
        0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x31, 0x32, 0x33, 0x5A};
    doc = decode_one(ctx, gen_long_fraction, sizeof(gen_long_fraction));
    ASNBER_TEST_CHECK(doc != NULL);
    time.struct_size = sizeof(time);
    ASNBER_TEST_CHECK(asnber_node_get_time(asnber_doc_root(doc), &time) == ASNBER_OK);
    ASNBER_TEST_CHECK(time.nanosecond == 123456789u);
    asnber_doc_destroy(doc);

    static const uint8_t gen_no_seconds[] = {
        0x18, 0x0D, 0x32, 0x30, 0x32, 0x34, 0x30, 0x31,
        0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x5A};
    doc = decode_one(ctx, gen_no_seconds, sizeof(gen_no_seconds));
    ASNBER_TEST_CHECK(doc != NULL);
    time.struct_size = sizeof(time);
    ASNBER_TEST_CHECK(asnber_node_get_time(asnber_doc_root(doc), &time) == ASNBER_OK);
    ASNBER_TEST_CHECK(time.second == 0);
    ASNBER_TEST_CHECK((time.flags & ASNBER_TIME_FRACTIONAL) == 0);
    asnber_doc_destroy(doc);

    /* 闰年 2 月 29 日合法。 */
    static const uint8_t gen_leap_day[] = {
        0x18, 0x0F, 0x32, 0x30, 0x32, 0x34, 0x30, 0x32,
        0x32, 0x39, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A};
    doc = decode_one(ctx, gen_leap_day, sizeof(gen_leap_day));
    ASNBER_TEST_CHECK(doc != NULL);
    time.struct_size = sizeof(time);
    ASNBER_TEST_CHECK(asnber_node_get_time(asnber_doc_root(doc), &time) == ASNBER_OK);
    ASNBER_TEST_CHECK(time.month == 2 && time.day == 29);
    asnber_doc_destroy(doc);

    /* 非法取值与非时间标签。 */
    static const uint8_t time_bad_month[] = {
        0x18, 0x0F, 0x32, 0x30, 0x32, 0x34, 0x31, 0x33,
        0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A};
    ASNBER_TEST_CHECK(expectTimeError(ctx, time_bad_month,
                                    sizeof(time_bad_month),
                                    ASNBER_E_MALFORMED_VALUE) == 0);

    static const uint8_t time_feb_30[] = {
        0x18, 0x0F, 0x32, 0x30, 0x32, 0x33, 0x30, 0x32,
        0x33, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A};
    ASNBER_TEST_CHECK(expectTimeError(ctx, time_feb_30, sizeof(time_feb_30),
                                    ASNBER_E_MALFORMED_VALUE) == 0);

    static const uint8_t time_bad_hour[] = {
        0x18, 0x0F, 0x32, 0x30, 0x32, 0x34, 0x30, 0x31,
        0x30, 0x31, 0x32, 0x34, 0x30, 0x30, 0x30, 0x30, 0x5A};
    ASNBER_TEST_CHECK(expectTimeError(ctx, time_bad_hour, sizeof(time_bad_hour),
                                    ASNBER_E_MALFORMED_VALUE) == 0);

    static const uint8_t time_bad_minute[] = {
        0x18, 0x0F, 0x32, 0x30, 0x32, 0x34, 0x30, 0x31,
        0x30, 0x31, 0x30, 0x30, 0x36, 0x30, 0x30, 0x30, 0x5A};
    ASNBER_TEST_CHECK(expectTimeError(ctx, time_bad_minute,
                                    sizeof(time_bad_minute),
                                    ASNBER_E_MALFORMED_VALUE) == 0);

    static const uint8_t time_bad_second[] = {
        0x18, 0x0F, 0x32, 0x30, 0x32, 0x34, 0x30, 0x31,
        0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x36, 0x31, 0x5A};
    ASNBER_TEST_CHECK(expectTimeError(ctx, time_bad_second,
                                    sizeof(time_bad_second),
                                    ASNBER_E_MALFORMED_VALUE) == 0);

    static const uint8_t time_bad_terminator[] = {
        0x18, 0x0F, 0x32, 0x30, 0x32, 0x34, 0x30, 0x31,
        0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x58};
    ASNBER_TEST_CHECK(expectTimeError(ctx, time_bad_terminator,
                                    sizeof(time_bad_terminator),
                                    ASNBER_E_MALFORMED_VALUE) == 0);

    static const uint8_t time_offset_hour[] = {
        0x18, 0x13, 0x32, 0x30, 0x32, 0x34, 0x30, 0x31, 0x30, 0x31,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x2B, 0x31, 0x35, 0x30, 0x30};
    ASNBER_TEST_CHECK(expectTimeError(ctx, time_offset_hour,
                                    sizeof(time_offset_hour),
                                    ASNBER_E_MALFORMED_VALUE) == 0);

    static const uint8_t time_offset_minute[] = {
        0x18, 0x13, 0x32, 0x30, 0x32, 0x34, 0x30, 0x31, 0x30, 0x31,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x2B, 0x30, 0x30, 0x36, 0x30};
    ASNBER_TEST_CHECK(expectTimeError(ctx, time_offset_minute,
                                    sizeof(time_offset_minute),
                                    ASNBER_E_MALFORMED_VALUE) == 0);

    static const uint8_t time_offset_1401[] = {
        0x18, 0x13, 0x32, 0x30, 0x32, 0x34, 0x30, 0x31, 0x30, 0x31,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x2B, 0x31, 0x34, 0x30, 0x31};
    ASNBER_TEST_CHECK(expectTimeError(ctx, time_offset_1401,
                                    sizeof(time_offset_1401),
                                    ASNBER_E_MALFORMED_VALUE) == 0);

    static const uint8_t time_empty_fraction[] = {
        0x18, 0x10, 0x32, 0x30, 0x32, 0x34, 0x30, 0x31, 0x30,
        0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x2E, 0x5A};
    ASNBER_TEST_CHECK(expectTimeError(ctx, time_empty_fraction,
                                    sizeof(time_empty_fraction),
                                    ASNBER_E_MALFORMED_VALUE) == 0);

    static const uint8_t utc_three_second_digits[] = {
        0x17, 0x0E, 0x39, 0x39, 0x31, 0x32, 0x33, 0x31,
        0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x31, 0x5A};
    ASNBER_TEST_CHECK(expectTimeError(ctx, utc_three_second_digits,
                                    sizeof(utc_three_second_digits),
                                    ASNBER_E_MALFORMED_VALUE) == 0);

    static const uint8_t utc_truncated[] = {
        0x17, 0x09, 0x39, 0x39, 0x30, 0x31,
        0x30, 0x31, 0x30, 0x30, 0x5A};
    ASNBER_TEST_CHECK(expectTimeError(ctx, utc_truncated, sizeof(utc_truncated),
                                    ASNBER_E_MALFORMED_VALUE) == 0);

    static const uint8_t time_truncated_offset[] = {
        0x18, 0x12, 0x32, 0x30, 0x32, 0x34, 0x30, 0x31, 0x30,
        0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x2B, 0x30, 0x31, 0x5A};
    ASNBER_TEST_CHECK(expectTimeError(ctx, time_truncated_offset,
                                    sizeof(time_truncated_offset),
                                    ASNBER_E_MALFORMED_VALUE) == 0);

    static const uint8_t time_wrong_tag[] = {0x02, 0x01, 0x05};
    ASNBER_TEST_CHECK(expectTimeError(ctx, time_wrong_tag,
                                    sizeof(time_wrong_tag),
                                    ASNBER_E_INVALID_VALUE) == 0);

    static const uint8_t time_empty_content[] = {0x17, 0x00};
    ASNBER_TEST_CHECK(expectTimeError(ctx, time_empty_content,
                                    sizeof(time_empty_content),
                                    ASNBER_E_MALFORMED_VALUE) == 0);

    static const uint8_t time_constructed[] = {0x37, 0x00};
    ASNBER_TEST_CHECK(expectTimeError(ctx, time_constructed,
                                    sizeof(time_constructed),
                                    ASNBER_E_MALFORMED_VALUE) == 0);

    /* 类型不匹配。 */
    static const uint8_t integer_node[] = {0x02, 0x01, 0x05};
    doc = decode_one(ctx, integer_node, sizeof(integer_node));
    ASNBER_TEST_CHECK(doc != NULL);
    ASNBER_TEST_CHECK(asnber_node_get_octets(asnber_doc_root(doc), &data, &size) ==
                    ASNBER_E_INVALID_VALUE);
    ASNBER_TEST_CHECK(asnber_node_get_oid(asnber_doc_root(doc), &text, &size) ==
                    ASNBER_E_INVALID_VALUE);
    asnber_doc_destroy(doc);

    asnber_ctx_destroy(ctx);
    return 0;
}
