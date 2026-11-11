/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * 宿主测量用例：静态池 + 加载 PKIX 描述表 + 解码一张真实证书 所需的最小池。
 * 二分求最小 static_pool_size，使“创建 ctx → 加载 PKIX 表 → 解码证书 → 销毁”
 * 全程不从池耗尽（即不返回 ASNBER_E_STATIC_POOL_EXHAUSTED、不做堆回退）。
 * 仅宿主运行；交叉编译不构建、不运行。
 */
#include <asnber/asnber.h>
#include <pkix_schema.h>

#include <stdio.h>

#include "../data/cert_rsa_selfsigned.h"

#define MAX_POOL ((size_t)1u << 20)

static union align_pool {
    long double align_ld;
    void *align_ptr;
    unsigned char bytes[MAX_POOL];
} g_pool;

static int try_pool(size_t size)
{
    asnber_ctx_config_t config;
    asnber_ctx_t *ctx = NULL;
    asnber_schema_t *schema = NULL;
    asnber_schema_table_t table;
    asnber_doc_t *doc = NULL;
    asnber_decode_options_t options;
    size_t consumed = 0;
    int ok = 0;

    asnber_ctx_config_init(&config);
    config.static_pool = g_pool.bytes;
    config.static_pool_size = size;

    if (asnber_ctx_create(&config, &ctx) != ASNBER_OK) {
        return 0;
    }

    table.struct_size = sizeof(table);
    table.data = kPKIXFlattened2009Schema;
    table.size = kPKIXFlattened2009Schema_size;
    table.format_version = 1u << 16;
    table.reserved = 0;

    if (asnber_schema_load(ctx, &table, &schema) != ASNBER_OK) {
        goto fail;
    }
    if (schema == NULL) {
        goto fail;
    }

    asnber_decode_options_init(&options);
    options.encoding = ASNBER_ENCODING_DER;
    if (asnber_decode_buffer_with_schema(
            ctx, kCertRsaSelfsigned, kCertRsaSelfsignedSize, schema, &options,
            &doc, &consumed) != ASNBER_OK) {
        goto fail;
    }
    if (doc == NULL) {
        goto fail;
    }

    ok = 1;

fail:
    if (doc != NULL) {
        asnber_doc_destroy(doc);
    }
    if (schema != NULL) {
        asnber_schema_destroy(schema);
    }
    asnber_ctx_destroy(ctx);
    return ok;
}

static size_t find_min_pool(void)
{
    size_t lo = 1;
    size_t hi = MAX_POOL;

    if (!try_pool(hi)) {
        return 0; /* 上限内仍不满足（异常）。 */
    }
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (try_pool(mid)) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    return lo;
}

int main(void)
{
    asnber_ctx_config_t cfg;
    size_t ctx_floor = 0;
    asnber_ctx_config_init(&cfg);
    (void)asnber_ctx_size_for_config(&cfg, &ctx_floor);
    size_t min_pool = find_min_pool();

    printf("asnber_ctx_size_for_config = %zu bytes\n", ctx_floor);
    printf("min_static_pool_size(PKIX table + cert decode) = %zu bytes\n",
           min_pool);

    if (min_pool == 0 || min_pool > MAX_POOL) {
        fprintf(stderr, "FAIL: 未能在 %zu 字节内满足\n", MAX_POOL);
        return 1;
    }
    /* 池必须足以覆盖 ctx 固定开销。 */
    if (min_pool < ctx_floor) {
        fprintf(stderr, "FAIL: 最小池小于 ctx 固定开销\n");
        return 1;
    }
    printf("OK\n");
    return 0;
}