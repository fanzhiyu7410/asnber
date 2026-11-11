/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * 静态池下限测量。
 *
 * 无参数：对一条 3 字节 INTEGER 做无 schema 解码，二分求最小静态池。
 * 两个参数：schema.bin 与 input.der，测量“创建上下文 + 加载描述表 + DER 解码”。
 *
 * 这是实测，不是公式。打印的字节数是这次输入的下限，换样本要重测。
 */

#include <asnber/asnber.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define POOL_CAP ((size_t)1u << 22)

static union {
    long double align_ld;
    void *align_ptr;
    unsigned char bytes[POOL_CAP];
} g_pool;

static unsigned char *read_file(const char *path, size_t *out_size)
{
    FILE *file = fopen(path, "rb");
    unsigned char *data = NULL;
    long length = 0;
    if (file == NULL) {
        return NULL;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return NULL;
    }
    length = ftell(file);
    if (length < 0 || (unsigned long)length > ((size_t)1u << 24)) {
        fclose(file);
        return NULL;
    }
    if (fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return NULL;
    }
    data = (unsigned char *)malloc((size_t)length == 0 ? 1 : (size_t)length);
    if (data == NULL) {
        fclose(file);
        return NULL;
    }
    if (length > 0 && fread(data, 1, (size_t)length, file) != (size_t)length) {
        free(data);
        fclose(file);
        return NULL;
    }
    fclose(file);
    *out_size = (size_t)length;
    return data;
}

static int try_pool(size_t size, const unsigned char *schema, size_t schema_size,
                    const unsigned char *der, size_t der_size)
{
    asnber_ctx_config_t config;
    asnber_ctx_t *ctx = NULL;
    asnber_schema_t *loaded = NULL;
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

    if (schema != NULL) {
        asnber_schema_table_t table;
        table.struct_size = sizeof(table);
        table.data = schema;
        table.size = schema_size;
        table.format_version = 1u << 16;
        table.reserved = 0;
        if (asnber_schema_load(ctx, &table, &loaded) != ASNBER_OK) {
            goto done;
        }
    }

    asnber_decode_options_init(&options);
    options.encoding = ASNBER_ENCODING_DER;
    if (loaded != NULL) {
        if (asnber_decode_buffer_with_schema(ctx, der, der_size, loaded, &options,
                                           &doc, &consumed) != ASNBER_OK) {
            goto done;
        }
    } else if (asnber_decode_buffer(ctx, der, der_size, &options, &doc,
                                  &consumed) != ASNBER_OK) {
        goto done;
    }
    ok = (doc != NULL);

done:
    if (doc != NULL) {
        asnber_doc_destroy(doc);
    }
    if (loaded != NULL) {
        asnber_schema_destroy(loaded);
    }
    asnber_ctx_destroy(ctx);
    return ok;
}

static size_t find_min(const unsigned char *schema, size_t schema_size,
                       const unsigned char *der, size_t der_size)
{
    size_t lo = 1;
    size_t hi = POOL_CAP;
    if (!try_pool(hi, schema, schema_size, der, der_size)) {
        return 0;
    }
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (try_pool(mid, schema, schema_size, der, der_size)) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    return lo;
}

int main(int argc, char **argv)
{
    static const unsigned char kInteger[3] = {0x02, 0x01, 0x01};
    const unsigned char *der = kInteger;
    size_t der_size = sizeof(kInteger);
    unsigned char *schema = NULL;
    size_t schema_size = 0;
    unsigned char *owned_der = NULL;
    asnber_ctx_config_t config;
    size_t ctx_floor = 0;
    size_t min_pool = 0;

    if (argc != 1 && argc != 3) {
        fprintf(stderr,
                "usage: %s [schema.bin input.der]\n"
                "无参数时测量一条 INTEGER 的无 schema 解码。\n",
                argv[0]);
        return 2;
    }
    if (argc == 3) {
        schema = read_file(argv[1], &schema_size);
        owned_der = read_file(argv[2], &der_size);
        if (schema == NULL || owned_der == NULL || schema_size == 0 ||
            der_size == 0) {
            fprintf(stderr, "无法读取输入文件\n");
            free(schema);
            free(owned_der);
            return 1;
        }
        der = owned_der;
    }

    asnber_ctx_config_init(&config);
    if (asnber_ctx_size_for_config(&config, &ctx_floor) != ASNBER_OK) {
        free(schema);
        free(owned_der);
        return 1;
    }
    min_pool = find_min(schema, schema_size, der, der_size);
    free(schema);
    free(owned_der);
    if (min_pool == 0 || min_pool < ctx_floor) {
        fprintf(stderr, "在 %zu 字节内没有找到可用静态池\n", POOL_CAP);
        return 1;
    }
    printf("ctx_fixed=%zu\n", ctx_floor);
    printf("min_static_pool=%zu\n", min_pool);
    return 0;
}
