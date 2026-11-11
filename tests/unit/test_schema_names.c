/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * 描述表名称表（header_size = 108）：手写夹具的加载、BIT_NAME /
 * NUMBER_NAME 双向查询、运行时注册路径与异常夹具。
 */

#include <asnber/asnber.h>

#include <stdio.h>
#include <string.h>

#include "check.h"

/* 夹具的总布局（全部为绝对文件偏移）。 */
#define TABLE_SIZE 536u
#define OFF_STRING_POOL 112u
#define SIZE_STRING_POOL 64u
#define OFF_TYPE_TABLE 176u
#define COUNT_TYPE 3u
#define OFF_CONSTRAINT_TABLE 320u
#define COUNT_CONSTRAINT 1u
#define OFF_NAME_TABLE 368u
#define COUNT_NAME 7u

/* 字符串池内的绝对偏移。 */
#define STR_BITS_TYPE 113u
#define STR_ENUM_TYPE 122u
#define STR_INT_TYPE 131u
#define STR_ALPHA 139u
#define STR_BETA 145u
#define STR_GAMMA 150u
#define STR_ONE 156u
#define STR_TWO 160u
#define STR_THREE 164u
#define STR_SEVEN 170u

static const uint8_t kMagic[8] = {0x41, 0x53, 0x4E, 0x31,
                                  0x53, 0x43, 0x48, 0x1A};

/* ===== 小端写入辅助（夹具侧独立实现） ===== */

static void put_u16(uint8_t *buf, size_t off, uint16_t value)
{
    buf[off] = (uint8_t)(value & 0xFFu);
    buf[off + 1] = (uint8_t)((value >> 8) & 0xFFu);
}

static uint32_t get_u32(const uint8_t *buf, size_t off)
{
    return (uint32_t)buf[off] | ((uint32_t)buf[off + 1] << 8) |
           ((uint32_t)buf[off + 2] << 16) |
           ((uint32_t)buf[off + 3] << 24);
}

static void put_u32(uint8_t *buf, size_t off, uint32_t value)
{
    buf[off] = (uint8_t)(value & 0xFFu);
    buf[off + 1] = (uint8_t)((value >> 8) & 0xFFu);
    buf[off + 2] = (uint8_t)((value >> 16) & 0xFFu);
    buf[off + 3] = (uint8_t)((value >> 24) & 0xFFu);
}

static void put_u64(uint8_t *buf, size_t off, uint64_t value)
{
    put_u32(buf, off, (uint32_t)(value & 0xFFFFFFFFu));
    put_u32(buf, off + 4, (uint32_t)((value >> 32) & 0xFFFFFFFFu));
}

static void put_i64(uint8_t *buf, size_t off, int64_t value)
{
    uint64_t raw;
    if (value >= 0) {
        raw = (uint64_t)value;
    } else {
        raw = UINT64_MAX - (uint64_t)(-(value + 1));
    }
    put_u64(buf, off, raw);
}

/* 测试侧独立 CRC32C（Castagnoli，反射实现）。 */
static uint32_t crc32c_zeroed(const uint8_t *data, size_t size,
                              size_t zero_off, size_t zero_len)
{
    uint32_t crc = 0xFFFFFFFFu;
    size_t i;
    for (i = 0; i < size; ++i) {
        uint32_t byte = (uint32_t)data[i];
        uint32_t bit;
        if (i >= zero_off && i < zero_off + zero_len) {
            byte = 0;
        }
        crc ^= byte;
        for (bit = 0; bit < 8; ++bit) {
            uint32_t mask = (uint32_t)(0u - (crc & 1u));
            crc = (crc >> 1) ^ (0x82F63B78u & mask);
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

static void refresh_checksum(uint8_t *buf)
{
    uint32_t crc;
    put_u32(buf, 80, 0);
    crc = crc32c_zeroed(buf, TABLE_SIZE, 80, 4);
    put_u32(buf, 80, crc);
}

/* ===== 夹具构造 ===== */

static void put_type(uint8_t *buf, uint32_t index, uint32_t name_off,
                     uint16_t kind, uint8_t flags, uint32_t tag_number,
                     uint32_t constraint_start, uint32_t constraint_count)
{
    uint8_t *rec = buf + OFF_TYPE_TABLE + (size_t)index * 48u;
    memset(rec, 0, 48u);
    put_u32(rec, 0, name_off);
    put_u16(rec, 4, kind);
    rec[7] = flags;
    put_u32(rec, 12, tag_number);
    put_u32(rec, 28, constraint_start);
    put_u32(rec, 32, constraint_count);
}

static void put_name(uint8_t *buf, uint32_t index, uint32_t type_id,
                     uint32_t name_off, uint16_t kind, uint16_t flags,
                     int64_t value)
{
    uint8_t *rec = buf + OFF_NAME_TABLE + (size_t)index * 24u;
    memset(rec, 0, 24u);
    put_u32(rec, 0, type_id);
    put_u32(rec, 4, name_off);
    put_u16(rec, 8, kind);
    put_u16(rec, 10, flags);
    put_i64(rec, 16, value);
}

static void build_base_table(uint8_t *buf)
{
    memset(buf, 0, TABLE_SIZE);
    memcpy(buf, kMagic, 8);
    put_u32(buf, 8, 0x00010000u);
    put_u32(buf, 12, 108u); /* header_size 含名称表字段 */
    put_u32(buf, 16, 0x01020304u);
    put_u32(buf, 20, 2u); /* module_tag_mode = IMPLICIT */
    put_u32(buf, 24, 1u);
    put_u32(buf, 28, 1u);
    put_u64(buf, 32, TABLE_SIZE);
    put_u32(buf, 40, OFF_STRING_POOL);
    put_u32(buf, 44, SIZE_STRING_POOL);
    put_u32(buf, 48, OFF_TYPE_TABLE);
    put_u32(buf, 52, COUNT_TYPE);
    put_u32(buf, 56, 0u); /* 字段表为空 */
    put_u32(buf, 60, 0u);
    put_u32(buf, 64, OFF_CONSTRAINT_TABLE);
    put_u32(buf, 68, COUNT_CONSTRAINT);
    put_u32(buf, 72, 0u); /* 默认值表为空 */
    put_u32(buf, 76, 0u);
    put_u32(buf, 96, 0u);
    put_u32(buf, 100, OFF_NAME_TABLE);
    put_u32(buf, 104, COUNT_NAME);

    /* 字符串池。 */
    buf[OFF_STRING_POOL] = 0;
    memcpy(buf + STR_BITS_TYPE, "BitsType", 9);
    memcpy(buf + STR_ENUM_TYPE, "EnumType", 9);
    memcpy(buf + STR_INT_TYPE, "IntType", 8);
    memcpy(buf + STR_ALPHA, "alpha", 6);
    memcpy(buf + STR_BETA, "beta", 5);
    memcpy(buf + STR_GAMMA, "gamma", 6);
    memcpy(buf + STR_ONE, "one", 4);
    memcpy(buf + STR_TWO, "two", 4);
    memcpy(buf + STR_THREE, "three", 6);
    memcpy(buf + STR_SEVEN, "seven", 6);

    /* 类型表：BIT STRING SIZE (0..16)、EXTENSIBLE ENUMERATED、INTEGER。 */
    put_type(buf, 0, STR_BITS_TYPE, ASNBER_TYPE_KIND_SIMPLE, 0u, 3u, 0u, 1u);
    put_type(buf, 1, STR_ENUM_TYPE, ASNBER_TYPE_KIND_SIMPLE,
             ASNBER_TYPE_EXTENSIBLE, 10u, 0u, 0u);
    put_type(buf, 2, STR_INT_TYPE, ASNBER_TYPE_KIND_SIMPLE, 0u, 2u, 0u, 0u);

    /* SIZE (0..16)。 */
    memset(buf + OFF_CONSTRAINT_TABLE, 0, 48u);
    put_u16(buf + OFF_CONSTRAINT_TABLE, 0, ASNBER_CONSTRAINT_SIZE);
    put_i64(buf + OFF_CONSTRAINT_TABLE, 28, 0);
    put_i64(buf + OFF_CONSTRAINT_TABLE, 36, 16);

    /* 名称表：BIT 0/7/15；枚举 0/5（扩展）/9；整数 7。 */
    put_name(buf, 0, 1u, STR_ALPHA, ASNBER_SCHEMA_NAME_KIND_BIT, 0u, 0);
    put_name(buf, 1, 1u, STR_BETA, ASNBER_SCHEMA_NAME_KIND_BIT, 0u, 7);
    put_name(buf, 2, 1u, STR_GAMMA, ASNBER_SCHEMA_NAME_KIND_BIT, 0u, 15);
    put_name(buf, 3, 2u, STR_ONE, ASNBER_SCHEMA_NAME_KIND_NUMBER, 0u, 0);
    put_name(buf, 4, 2u, STR_TWO, ASNBER_SCHEMA_NAME_KIND_NUMBER,
             ASNBER_SCHEMA_NAME_FLAG_EXTENSION, 5);
    put_name(buf, 5, 2u, STR_THREE, ASNBER_SCHEMA_NAME_KIND_NUMBER, 0u, 9);
    put_name(buf, 6, 3u, STR_SEVEN, ASNBER_SCHEMA_NAME_KIND_NUMBER, 0u, 7);

    refresh_checksum(buf);
}

static asnber_schema_table_t make_table(const uint8_t *data, size_t size)
{
    asnber_schema_table_t table;
    memset(&table, 0, sizeof(table));
    table.struct_size = sizeof(table);
    table.data = data;
    table.size = size;
    table.format_version = 0x00010000u;
    return table;
}

static int expect_load_error(asnber_ctx_t *ctx, const uint8_t *data,
                             size_t size, asnber_err_t expected)
{
    asnber_schema_table_t table = make_table(data, size);
    asnber_schema_t *schema = (asnber_schema_t *)(void *)0x1;
    asnber_err_t rc = asnber_schema_load(ctx, &table, &schema);
    if (rc != expected || schema != NULL) {
        fprintf(stderr, "load error mismatch: got %d, expected %d\n",
                (int)rc, (int)expected);
        return 0;
    }
    return 1;
}

static int expect_name_at(const asnber_schema_t *schema, uint32_t type_id,
                          uint32_t index, uint32_t kind, uint32_t flags,
                          int64_t value, const char *name)
{
    asnber_schema_name_info_t info;
    memset(&info, 0, sizeof(info));
    info.struct_size = sizeof(info);
    if (asnber_schema_name_at(schema, type_id, index, &info) != ASNBER_OK) {
        return 0;
    }
    return info.type_id == type_id && info.kind == kind &&
           info.flags == flags && info.value == value &&
           strcmp(info.name, name) == 0;
}

static int expect_for_bit(const asnber_schema_t *schema, uint32_t type_id,
                          uint32_t bit, const char *name)
{
    const char *out = (const char *)(void *)0x1;
    asnber_err_t rc = asnber_schema_name_for_bit(schema, type_id, bit, &out);
    if (rc != ASNBER_OK) {
        return 0;
    }
    if (name == NULL) {
        return out == NULL;
    }
    return out != NULL && strcmp(out, name) == 0;
}

static int expect_for_value(const asnber_schema_t *schema, uint32_t type_id,
                            int64_t value, const char *name)
{
    const char *out = (const char *)(void *)0x1;
    asnber_err_t rc = asnber_schema_name_for_value(schema, type_id, value, &out);
    if (rc != ASNBER_OK) {
        return 0;
    }
    if (name == NULL) {
        return out == NULL;
    }
    return out != NULL && strcmp(out, name) == 0;
}

static int expect_value_for_name(const asnber_schema_t *schema,
                                 uint32_t type_id, const char *name,
                                 int64_t value, int found)
{
    int64_t out_value = -1;
    int out_found = -1;
    asnber_err_t rc = asnber_schema_value_for_name(schema, type_id, name,
                                               &out_value, &out_found);
    if (rc != ASNBER_OK) {
        return 0;
    }
    if (found) {
        return out_found == 1 && out_value == value;
    }
    return out_found == 0 && out_value == 0;
}

static int build_runtime_schema(asnber_ctx_t *ctx, asnber_schema_t **out_schema)
{
    asnber_schema_t *schema = NULL;
    asnber_type_desc_t desc;
    uint32_t id = 0;

    if (asnber_schema_create(ctx, ASNBER_TAG_MODE_IMPLICIT, &schema) != ASNBER_OK) {
        return 0;
    }
    memset(&desc, 0, sizeof(desc));
    desc.struct_size = sizeof(desc);
    desc.name = "Flag";
    desc.kind = ASNBER_TYPE_KIND_SIMPLE;
    desc.tag_class = ASNBER_TAG_UNIVERSAL;
    desc.tag_number = 1;
    desc.tag_mode = ASNBER_TAG_MODE_DEFAULT;
    if (asnber_schema_add_type(schema, &desc, &id) != ASNBER_OK || id != 1u) {
        return 0;
    }
    *out_schema = schema;
    return 1;
}

int main(void)
{
    static uint8_t base[TABLE_SIZE];
    static uint8_t work[TABLE_SIZE];
    asnber_ctx_config_t config;
    asnber_ctx_t *ctx = NULL;
    asnber_schema_table_t table;
    asnber_schema_t *loaded = NULL;
    asnber_schema_t *runtime = NULL;
    asnber_schema_t *unsealed = NULL;
    const char *name_out = NULL;
    uint32_t count = 99u;
    int64_t value_out = 0;
    int found_out = 0;

    build_base_table(base);
    ASNBER_TEST_CHECK(crc32c_zeroed(base, TABLE_SIZE, 80, 4) ==
                    get_u32(base, 80));

    asnber_ctx_config_init(&config);
    ASNBER_TEST_CHECK(asnber_ctx_create(&config, &ctx) == ASNBER_OK);

    /* 正例：加载并逐项查询。 */
    table = make_table(base, TABLE_SIZE);
    ASNBER_TEST_CHECK(asnber_schema_load(ctx, &table, &loaded) == ASNBER_OK);
    ASNBER_TEST_CHECK(loaded != NULL);

    ASNBER_TEST_CHECK(asnber_schema_name_count(loaded, 1u, &count) == ASNBER_OK);
    ASNBER_TEST_CHECK(count == 3u);
    ASNBER_TEST_CHECK(expect_name_at(loaded, 1u, 0u, ASNBER_SCHEMA_NAME_KIND_BIT,
                                   0u, 0, "alpha") == 1);
    ASNBER_TEST_CHECK(expect_name_at(loaded, 1u, 1u, ASNBER_SCHEMA_NAME_KIND_BIT,
                                   0u, 7, "beta") == 1);
    ASNBER_TEST_CHECK(expect_name_at(loaded, 1u, 2u, ASNBER_SCHEMA_NAME_KIND_BIT,
                                   0u, 15, "gamma") == 1);
    ASNBER_TEST_CHECK(expect_for_bit(loaded, 1u, 0u, "alpha") == 1);
    ASNBER_TEST_CHECK(expect_for_bit(loaded, 1u, 7u, "beta") == 1);
    ASNBER_TEST_CHECK(expect_for_bit(loaded, 1u, 15u, "gamma") == 1);
    ASNBER_TEST_CHECK(expect_for_bit(loaded, 1u, 20u, NULL) == 1);
    ASNBER_TEST_CHECK(expect_for_value(loaded, 1u, 0, NULL) == 1);
    ASNBER_TEST_CHECK(expect_value_for_name(loaded, 1u, "alpha", 0, 1) == 1);
    ASNBER_TEST_CHECK(expect_value_for_name(loaded, 1u, "missing", 0, 0) == 1);

    ASNBER_TEST_CHECK(asnber_schema_name_count(loaded, 2u, &count) == ASNBER_OK);
    ASNBER_TEST_CHECK(count == 3u);
    ASNBER_TEST_CHECK(expect_name_at(loaded, 2u, 0u,
                                   ASNBER_SCHEMA_NAME_KIND_NUMBER, 0u, 0,
                                   "one") == 1);
    ASNBER_TEST_CHECK(expect_name_at(loaded, 2u, 1u,
                                   ASNBER_SCHEMA_NAME_KIND_NUMBER,
                                   ASNBER_SCHEMA_NAME_FLAG_EXTENSION, 5,
                                   "two") == 1);
    ASNBER_TEST_CHECK(expect_name_at(loaded, 2u, 2u,
                                   ASNBER_SCHEMA_NAME_KIND_NUMBER, 0u, 9,
                                   "three") == 1);
    ASNBER_TEST_CHECK(expect_for_value(loaded, 2u, 0, "one") == 1);
    ASNBER_TEST_CHECK(expect_for_value(loaded, 2u, 5, "two") == 1);
    ASNBER_TEST_CHECK(expect_for_value(loaded, 2u, 9, "three") == 1);
    ASNBER_TEST_CHECK(expect_for_value(loaded, 2u, 4, NULL) == 1);
    ASNBER_TEST_CHECK(expect_for_bit(loaded, 2u, 0u, NULL) == 1);
    ASNBER_TEST_CHECK(expect_value_for_name(loaded, 2u, "two", 5, 1) == 1);
    ASNBER_TEST_CHECK(expect_value_for_name(loaded, 2u, "absent", 0, 0) == 1);

    ASNBER_TEST_CHECK(asnber_schema_name_count(loaded, 3u, &count) == ASNBER_OK);
    ASNBER_TEST_CHECK(count == 1u);
    ASNBER_TEST_CHECK(expect_name_at(loaded, 3u, 0u,
                                   ASNBER_SCHEMA_NAME_KIND_NUMBER, 0u, 7,
                                   "seven") == 1);
    ASNBER_TEST_CHECK(expect_for_value(loaded, 3u, 7, "seven") == 1);
    ASNBER_TEST_CHECK(expect_for_bit(loaded, 3u, 0u, NULL) == 1);
    ASNBER_TEST_CHECK(expect_value_for_name(loaded, 3u, "seven", 7, 1) == 1);

    /* 查询参数错误。 */
    ASNBER_TEST_CHECK(asnber_schema_name_count(NULL, 1u, &count) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_schema_name_count(loaded, 1u, NULL) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_schema_name_count(loaded, 0u, &count) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_schema_name_count(loaded, 4u, &count) ==
                    ASNBER_E_INVALID_ARG);
    {
        asnber_schema_name_info_t info;
        memset(&info, 0, sizeof(info));
        info.struct_size = sizeof(info) - 1u;
        ASNBER_TEST_CHECK(asnber_schema_name_at(loaded, 1u, 0u, &info) ==
                        ASNBER_E_INVALID_CONFIG);
        info.struct_size = sizeof(info);
        ASNBER_TEST_CHECK(asnber_schema_name_at(loaded, 1u, 3u, &info) ==
                        ASNBER_E_INVALID_ARG);
        ASNBER_TEST_CHECK(asnber_schema_name_at(NULL, 1u, 0u, &info) ==
                        ASNBER_E_INVALID_ARG);
        ASNBER_TEST_CHECK(asnber_schema_name_at(loaded, 1u, 0u, NULL) ==
                        ASNBER_E_INVALID_ARG);
    }
    ASNBER_TEST_CHECK(asnber_schema_name_for_bit(NULL, 1u, 0u, &name_out) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_schema_name_for_bit(loaded, 1u, 0u, NULL) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_schema_name_for_bit(loaded, 4u, 0u, &name_out) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_schema_name_for_value(NULL, 1u, 0, &name_out) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_schema_name_for_value(loaded, 1u, 0, NULL) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_schema_name_for_value(loaded, 0u, 0, &name_out) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_schema_value_for_name(NULL, 1u, "alpha",
                                               &value_out, &found_out) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_schema_value_for_name(loaded, 1u, NULL,
                                               &value_out, &found_out) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_schema_value_for_name(loaded, 1u, "alpha", NULL,
                                               &found_out) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_schema_value_for_name(loaded, 1u, "alpha",
                                               &value_out, NULL) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_schema_value_for_name(loaded, 4u, "alpha",
                                               &value_out, &found_out) ==
                    ASNBER_E_INVALID_ARG);

    /* 运行时注册：名称恒为空，未封存时返回 INVALID_STATE。 */
    ASNBER_TEST_CHECK(build_runtime_schema(ctx, &runtime) == 1);
    unsealed = runtime;
    ASNBER_TEST_CHECK(asnber_schema_name_count(unsealed, 1u, &count) ==
                    ASNBER_E_INVALID_STATE);
    ASNBER_TEST_CHECK(asnber_schema_name_for_bit(unsealed, 1u, 0u, &name_out) ==
                    ASNBER_E_INVALID_STATE);
    ASNBER_TEST_CHECK(asnber_schema_name_for_value(unsealed, 1u, 0, &name_out) ==
                    ASNBER_E_INVALID_STATE);
    ASNBER_TEST_CHECK(asnber_schema_value_for_name(unsealed, 1u, "alpha",
                                               &value_out, &found_out) ==
                    ASNBER_E_INVALID_STATE);
    ASNBER_TEST_CHECK(asnber_schema_seal(runtime) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_schema_name_count(runtime, 1u, &count) == ASNBER_OK);
    ASNBER_TEST_CHECK(count == 0u);
    ASNBER_TEST_CHECK(expect_for_bit(runtime, 1u, 0u, NULL) == 1);
    ASNBER_TEST_CHECK(expect_for_value(runtime, 1u, 0, NULL) == 1);
    ASNBER_TEST_CHECK(expect_value_for_name(runtime, 1u, "alpha", 0, 0) == 1);
    {
        asnber_schema_name_info_t info;
        memset(&info, 0, sizeof(info));
        info.struct_size = sizeof(info);
        ASNBER_TEST_CHECK(asnber_schema_name_at(runtime, 1u, 0u, &info) ==
                        ASNBER_E_INVALID_ARG);
    }

    asnber_schema_destroy(runtime);
    asnber_schema_destroy(loaded);

    /* ===== 负例：均返回 ASNBER_E_SCHEMA_FORMAT ===== */

    /* type_id 为 0 / type_count + 1。 */
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, OFF_NAME_TABLE, 0u);
    refresh_checksum(work);
    ASNBER_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASNBER_E_SCHEMA_FORMAT));
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, OFF_NAME_TABLE, COUNT_TYPE + 1u);
    refresh_checksum(work);
    ASNBER_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASNBER_E_SCHEMA_FORMAT));

    /* 同类型重复名称。 */
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, OFF_NAME_TABLE + 24u + 4u, STR_ALPHA);
    refresh_checksum(work);
    ASNBER_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASNBER_E_SCHEMA_FORMAT));

    /* 同 kind 重复数值。 */
    memcpy(work, base, TABLE_SIZE);
    put_i64(work, OFF_NAME_TABLE + 24u + 16u, 0);
    refresh_checksum(work);
    ASNBER_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASNBER_E_SCHEMA_FORMAT));

    /* 同类型混用 BIT_NAME / NUMBER_NAME。 */
    memcpy(work, base, TABLE_SIZE);
    put_u16(work, OFF_NAME_TABLE + 4u * 24u + 8u,
            ASNBER_SCHEMA_NAME_KIND_BIT);
    refresh_checksum(work);
    ASNBER_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASNBER_E_SCHEMA_FORMAT));

    /* BIT_NAME 挂在非 BIT STRING 类型上。 */
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, OFF_NAME_TABLE, 2u);
    refresh_checksum(work);
    ASNBER_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASNBER_E_SCHEMA_FORMAT));

    /* NUMBER_NAME 挂在 BIT STRING 类型上。 */
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, OFF_NAME_TABLE + 6u * 24u, 1u);
    refresh_checksum(work);
    ASNBER_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASNBER_E_SCHEMA_FORMAT));

    /* 位号等于 SIZE 上界（必须严格小于 16）。 */
    memcpy(work, base, TABLE_SIZE);
    put_i64(work, OFF_NAME_TABLE + 2u * 24u + 16u, 16);
    refresh_checksum(work);
    ASNBER_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASNBER_E_SCHEMA_FORMAT));

    /* flags 位 0 出现在非扩展 ENUMERATED。 */
    memcpy(work, base, TABLE_SIZE);
    work[OFF_TYPE_TABLE + 48u + 7u] = 0u; /* 清除 EXTENSIBLE */
    put_u16(work, OFF_NAME_TABLE + 3u * 24u + 10u,
            ASNBER_SCHEMA_NAME_FLAG_EXTENSION);
    refresh_checksum(work);
    ASNBER_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASNBER_E_SCHEMA_FORMAT));

    /* name_off 指向字符串池首字节（空哨兵）。 */
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, OFF_NAME_TABLE + 4u, OFF_STRING_POOL);
    refresh_checksum(work);
    ASNBER_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASNBER_E_SCHEMA_FORMAT));

    /* reserved0 非 0。 */
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, OFF_NAME_TABLE + 12u, 1u);
    refresh_checksum(work);
    ASNBER_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASNBER_E_SCHEMA_FORMAT));

    /* 名称表区间与类型表重叠。 */
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, 100, OFF_TYPE_TABLE);
    refresh_checksum(work);
    ASNBER_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASNBER_E_SCHEMA_FORMAT));

    asnber_ctx_destroy(ctx);
    return 0;
}
