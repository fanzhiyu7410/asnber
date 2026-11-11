/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-pkix 打开/关闭基准（可选，默认不构建）。
 *
 * 测量内容：
 *   - N 次 asnber_pkix_certificate_open + close 的进程 CPU 时间与单次均值；
 *   - 通过计数分配器测出单张证书打开期间的峰值堆占用。
 *
 * 结论只用于判断“是否需要核心 ctx 级 schema 缓存”，本轮不改核心 ABI。
 * 模块当前策略：每次 open 用调用方 ctx 加载一次描述表，schema 随句柄存活到
 * close，无全局缓存。
 *
 * 用法：asnber_pkix_bench [证书 DER 路径] [迭代次数...]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <asnber/asnber_allocator.h>
#include <asnber/pkix/pkix.h>

/* 计数分配器：块头按最大对齐填充，保证返回地址满足库的对齐要求。 */
typedef union {
    struct {
        size_t size;
    } info;
    long double align_ld;
    void *align_ptr;
} block_header_t;

static size_t g_live_bytes;
static size_t g_peak_bytes;

static void *counting_alloc(void *user, size_t size)
{
    block_header_t *header;
    (void)user;
    if (size == 0) {
        return NULL;
    }
    header = (block_header_t *)malloc(sizeof(block_header_t) + size);
    if (header == NULL) {
        return NULL;
    }
    header->info.size = size;
    g_live_bytes += size;
    if (g_live_bytes > g_peak_bytes) {
        g_peak_bytes = g_live_bytes;
    }
    return (void *)((unsigned char *)header + sizeof(block_header_t));
}

static void counting_free(void *user, void *ptr)
{
    block_header_t *header;
    (void)user;
    if (ptr == NULL) {
        return;
    }
    header = (block_header_t *)((unsigned char *)ptr - sizeof(block_header_t));
    g_live_bytes -= header->info.size;
    free(header);
}

static uint8_t *load_file(const char *path, size_t *out_size)
{
    FILE *file = fopen(path, "rb");
    uint8_t *data;
    long file_size;

    if (file == NULL) {
        fprintf(stderr, "无法打开证书文件: %s\n", path);
        return NULL;
    }
    if (fseek(file, 0, SEEK_END) != 0 || (file_size = ftell(file)) <= 0 ||
        fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        fprintf(stderr, "证书文件大小非法: %s\n", path);
        return NULL;
    }
    data = (uint8_t *)malloc((size_t)file_size);
    if (data == NULL) {
        fclose(file);
        return NULL;
    }
    if (fread(data, 1, (size_t)file_size, file) != (size_t)file_size) {
        free(data);
        fclose(file);
        fprintf(stderr, "证书文件读取不完整: %s\n", path);
        return NULL;
    }
    fclose(file);
    *out_size = (size_t)file_size;
    return data;
}

static int run_iterations(const uint8_t *der, size_t der_size, size_t iterations)
{
    asnber_ctx_config_t config;
    asnber_allocator_t allocator;
    asnber_ctx_t *ctx = NULL;
    clock_t start;
    clock_t stop;
    double elapsed_ms;
    double per_open_us;
    size_t i;
    size_t failures = 0;

    g_live_bytes = 0;
    g_peak_bytes = 0;

    allocator.struct_size = sizeof(allocator);
    allocator.user = NULL;
    allocator.alloc = counting_alloc;
    allocator.realloc = NULL;
    allocator.free = counting_free;

    asnber_ctx_config_init(&config);
    config.allocator = &allocator;
    if (asnber_ctx_create(&config, &ctx) != ASNBER_OK || ctx == NULL) {
        fprintf(stderr, "上下文创建失败\n");
        return 0;
    }

    start = clock();
    for (i = 0; i < iterations; ++i) {
        asnber_pkix_certificate_t *cert = NULL;
        if (asnber_pkix_certificate_open(ctx, der, der_size, &cert) != ASNBER_OK) {
            ++failures;
            continue;
        }
        asnber_pkix_certificate_close(cert);
    }
    stop = clock();

    elapsed_ms = ((double)(stop - start) * 1000.0) / (double)CLOCKS_PER_SEC;
    per_open_us = iterations == 0 ? 0.0
                                  : (elapsed_ms * 1000.0) / (double)iterations;

    fprintf(stderr,
            "iterations=%zu failures=%zu cpu_ms=%.3f per_open_close_us=%.3f "
            "peak_heap_bytes=%zu\n",
            iterations, failures, elapsed_ms, per_open_us, g_peak_bytes);

    asnber_ctx_destroy(ctx);
    return failures == 0;
}

int main(int argc, char **argv)
{
    const char *path = argc > 1 ? argv[1] : "tests/data/cert_rsa_selfsigned.der";
    uint8_t *der;
    size_t der_size = 0;
    int ok;

    der = load_file(path, &der_size);
    if (der == NULL) {
        return 1;
    }
    fprintf(stderr, "cert_path=%s cert_bytes=%zu\n", path, der_size);

    ok = run_iterations(der, der_size, 1000u);
    ok = run_iterations(der, der_size, 10000u) && ok;

    free(der);
    return ok ? 0 : 1;
}
