/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 模块 open/close 成本基线（可选，ASNBER_BUILD_BENCHMARKS=ON 时构建）。
 *
 * 五组固定输入，分别覆盖 PKIX、PKCS#8、PKCS#1、PKCS#10 与 CMS：
 *   - 每组先预热一次，再分别执行 1,000 与 10,000 次 open + close；
 *   - 记录每次调用的墙钟耗时，输出 count/min/median/p95/mean；
 *   - 通过计数分配器给出打开期间的峰值堆占用与关闭后的存活字节。
 *
 * 用法：bench_module_open [数据目录]
 * 数据目录默认指向源码树 tests/data（构建期注入绝对路径）。
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <asnber/asnber.h>
#include <asnber/asnber_allocator.h>
#include <asnber/cms/cms.h>
#include <asnber/pkcs/pkcs.h>
#include <asnber/pkix/pkix.h>

#ifdef _WIN32
#include <windows.h>
#endif

#ifndef ASNBER_BENCH_DATA_DIR
#define ASNBER_BENCH_DATA_DIR "tests/data"
#endif

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

static double now_us(void)
{
#ifdef _WIN32
    static double frequency;
    LARGE_INTEGER counter;
    if (frequency == 0.0) {
        LARGE_INTEGER value;
        QueryPerformanceFrequency(&value);
        frequency = (double)value.QuadPart;
    }
    QueryPerformanceCounter(&counter);
    return ((double)counter.QuadPart * 1000000.0) / frequency;
#else
    struct timespec value;
    clock_gettime(CLOCK_MONOTONIC, &value);
    return (double)value.tv_sec * 1000000.0 + (double)value.tv_nsec / 1000.0;
#endif
}

typedef asnber_err_t (*bench_open_fn)(asnber_ctx_t *, const uint8_t *, size_t,
                                    void **);
typedef void (*bench_close_fn)(void *);

static asnber_err_t open_pkix_certificate(asnber_ctx_t *ctx, const uint8_t *der,
                                        size_t der_size, void **out)
{
    return asnber_pkix_certificate_open(
        ctx, der, der_size, (asnber_pkix_certificate_t **)out);
}

static void close_pkix_certificate(void *handle)
{
    asnber_pkix_certificate_close((asnber_pkix_certificate_t *)handle);
}

static asnber_err_t open_pkcs8_private_key_info(asnber_ctx_t *ctx,
                                              const uint8_t *der,
                                              size_t der_size, void **out)
{
    return asnber_pkcs_private_key_info_open(
        ctx, der, der_size, (asnber_pkcs_private_key_info_t **)out);
}

static void close_pkcs8_private_key_info(void *handle)
{
    asnber_pkcs_private_key_info_close((asnber_pkcs_private_key_info_t *)handle);
}

static asnber_err_t open_pkcs1_rsa_private_key(asnber_ctx_t *ctx,
                                             const uint8_t *der,
                                             size_t der_size, void **out)
{
    return asnber_pkcs_rsa_private_key_open(
        ctx, der, der_size, (asnber_pkcs_rsa_private_key_t **)out);
}

static void close_pkcs1_rsa_private_key(void *handle)
{
    asnber_pkcs_rsa_private_key_close((asnber_pkcs_rsa_private_key_t *)handle);
}

static asnber_err_t open_pkcs10_request(asnber_ctx_t *ctx, const uint8_t *der,
                                      size_t der_size, void **out)
{
    return asnber_pkcs_certification_request_open(
        ctx, der, der_size, (asnber_pkcs_certification_request_t **)out);
}

static void close_pkcs10_request(void *handle)
{
    asnber_pkcs_certification_request_close(
        (asnber_pkcs_certification_request_t *)handle);
}

static asnber_err_t open_cms_content_info(asnber_ctx_t *ctx, const uint8_t *der,
                                        size_t der_size, void **out)
{
    return asnber_cms_content_info_open(
        ctx, der, der_size, (asnber_cms_content_info_t **)out);
}

static void close_cms_content_info(void *handle)
{
    asnber_cms_content_info_close((asnber_cms_content_info_t *)handle);
}

typedef struct {
    const char *name;
    const char *file;
    bench_open_fn open;
    bench_close_fn close;
} bench_group_t;

static const bench_group_t kGroups[] = {
    {"pkix_certificate", "cert_rsa_selfsigned.der", open_pkix_certificate,
     close_pkix_certificate},
    {"pkcs8_private_key_info", "key_rsa_pkcs8.der",
     open_pkcs8_private_key_info, close_pkcs8_private_key_info},
    {"pkcs1_rsa_private_key", "key_rsa_pkcs1_private.der",
     open_pkcs1_rsa_private_key, close_pkcs1_rsa_private_key},
    {"pkcs10_certification_request", "csr_rsa.der", open_pkcs10_request,
     close_pkcs10_request},
    {"cms_content_info", "cms_rsa_attached.der", open_cms_content_info,
     close_cms_content_info},
};

static uint8_t *load_file(const char *path, size_t *out_size)
{
    FILE *file;
    uint8_t *data;
    long file_size;

    file = fopen(path, "rb");
    if (file == NULL) {
        fprintf(stderr, "无法打开输入文件：%s\n", path);
        return NULL;
    }
    if (fseek(file, 0, SEEK_END) != 0 || (file_size = ftell(file)) <= 0 ||
        fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        fprintf(stderr, "输入文件大小非法：%s\n", path);
        return NULL;
    }
    data = (uint8_t *)malloc((size_t)file_size);
    if (data == NULL) {
        fclose(file);
        fprintf(stderr, "无法为输入文件分配内存：%s\n", path);
        return NULL;
    }
    if (fread(data, 1, (size_t)file_size, file) != (size_t)file_size) {
        free(data);
        fclose(file);
        fprintf(stderr, "输入文件读取不完整：%s\n", path);
        return NULL;
    }
    fclose(file);
    *out_size = (size_t)file_size;
    return data;
}

static int compare_double(const void *left, const void *right)
{
    double a = *(const double *)left;
    double b = *(const double *)right;
    if (a < b) {
        return -1;
    }
    if (a > b) {
        return 1;
    }
    return 0;
}

static int run_case(const bench_group_t *group, const uint8_t *der,
                    size_t der_size, size_t iterations)
{
    asnber_ctx_config_t config;
    asnber_allocator_t allocator;
    asnber_ctx_t *ctx = NULL;
    double *samples;
    double total_us = 0.0;
    size_t baseline_bytes;
    size_t i;
    size_t failures = 0;
    void *handle = NULL;
    asnber_err_t err;

    samples = (double *)malloc(iterations * sizeof(double));
    if (samples == NULL) {
        fprintf(stderr, "无法分配耗时样本数组\n");
        return 0;
    }

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
        free(samples);
        return 0;
    }
    baseline_bytes = g_live_bytes;
    g_peak_bytes = baseline_bytes;

    /* 预热一次，避免首次加载描述表的冷启动计入正式样本。 */
    err = group->open(ctx, der, der_size, &handle);
    if (err != ASNBER_OK || handle == NULL) {
        fprintf(stderr, "%s 预热失败：error=%d\n", group->name, (int)err);
        asnber_ctx_destroy(ctx);
        free(samples);
        return 0;
    }
    group->close(handle);

    for (i = 0; i < iterations; ++i) {
        double start;
        handle = NULL;
        start = now_us();
        err = group->open(ctx, der, der_size, &handle);
        if (err == ASNBER_OK && handle != NULL) {
            group->close(handle);
        } else {
            ++failures;
            if (handle != NULL) {
                group->close(handle);
            }
        }
        samples[i] = now_us() - start;
        total_us += samples[i];
    }

    qsort(samples, iterations, sizeof(double), compare_double);
    {
        double min_us = samples[0];
        double median_us = samples[iterations / 2];
        size_t p95_rank = (iterations * 95 + 99) / 100;
        double p95_us;
        double mean_us = total_us / (double)iterations;

        if (p95_rank == 0) {
            p95_rank = 1;
        }
        p95_us = samples[p95_rank - 1];
        if (iterations % 2 == 0) {
            median_us = (samples[iterations / 2 - 1] +
                         samples[iterations / 2]) /
                        2.0;
        }

        printf("case=%s file=%s input_bytes=%zu iterations=%zu failures=%zu\n",
               group->name, group->file, der_size, iterations, failures);
        printf("  count=%zu min_us=%.3f median_us=%.3f p95_us=%.3f "
               "mean_us=%.3f total_ms=%.3f\n",
               iterations, min_us, median_us, p95_us, mean_us,
               total_us / 1000.0);
        printf("  peak_heap_bytes=%zu baseline_heap_bytes=%zu "
               "peak_delta_bytes=%zu live_after_close_delta=%zu\n",
               g_peak_bytes, baseline_bytes, g_peak_bytes - baseline_bytes,
               g_live_bytes - baseline_bytes);
    }

    asnber_ctx_destroy(ctx);
    if (g_live_bytes != 0) {
        fprintf(stderr, "%s 关闭后仍有 %zu 字节未释放\n", group->name,
                g_live_bytes);
        failures += 1;
    }
    free(samples);
    return failures == 0;
}

int main(int argc, char **argv)
{
    const char *data_dir = argc > 1 ? argv[1] : ASNBER_BENCH_DATA_DIR;
    size_t group_index;
    int ok = 1;

    for (group_index = 0;
         group_index < sizeof(kGroups) / sizeof(kGroups[0]); ++group_index) {
        const bench_group_t *group = &kGroups[group_index];
        char path[1024];
        uint8_t *der;
        size_t der_size = 0;
        int written;

        written = snprintf(path, sizeof(path), "%s/%s", data_dir, group->file);
        if (written < 0 || (size_t)written >= sizeof(path)) {
            fprintf(stderr, "输入路径过长：%s/%s\n", data_dir, group->file);
            ok = 0;
            continue;
        }
        der = load_file(path, &der_size);
        if (der == NULL) {
            ok = 0;
            continue;
        }
        ok = run_case(group, der, der_size, 1000u) && ok;
        ok = run_case(group, der, der_size, 10000u) && ok;
        free(der);
    }
    return ok ? 0 : 1;
}
