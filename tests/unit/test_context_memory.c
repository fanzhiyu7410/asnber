/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * 上下文与内存：配置校验、静态池、尺寸查询与错误状态。
 */
#include <asnber/asnber.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "check.h"

/* 提供 max_align_t 级别对齐的静态池存储。 */
static union {
    long double ld;
    double d;
    void *p;
    unsigned long long u;
    unsigned char bytes[16384];
} pool_storage;

/* 与真实上下文无关的零填充区域，用于验证 magic 校验的防御分支。 */
static union {
    long double ld;
    void *p;
    unsigned char bytes[4096];
} foreign_ctx;

typedef struct {
    size_t alloc_calls;
    size_t free_calls;
    void *live[64];
    size_t live_count;
    int fail_next;
} counting_state;

static void *counting_alloc(void *user, size_t size)
{
    counting_state *state = (counting_state *)user;
    if (state->fail_next != 0) {
        state->fail_next = 0;
        return NULL;
    }
    void *memory = malloc(size);
    if (memory != NULL && state->live_count < 64) {
        state->live[state->live_count++] = memory;
    }
    ++state->alloc_calls;
    return memory;
}

static void counting_free(void *user, void *ptr)
{
    counting_state *state = (counting_state *)user;
    ++state->free_calls;
    for (size_t i = 0; i < state->live_count; ++i) {
        if (state->live[i] == ptr) {
            state->live[i] = state->live[state->live_count - 1];
            --state->live_count;
            break;
        }
    }
    free(ptr);
}

int main(void)
{
    asnber_ctx_config_t config;
    asnber_ctx_config_init(&config);
    ASNBER_TEST_CHECK(config.struct_size == sizeof(config));
    ASNBER_TEST_CHECK(config.allocator == NULL);
    ASNBER_TEST_CHECK(config.static_pool == NULL);
    ASNBER_TEST_CHECK(config.max_depth == 0);
    ASNBER_TEST_CHECK(config.max_warnings == 0);

    size_t required = 0;
    ASNBER_TEST_CHECK(asnber_ctx_size_for_config(&config, &required) == ASNBER_OK);
    ASNBER_TEST_CHECK(required > 0);
    size_t rejected_size = 0;
    ASNBER_TEST_CHECK(asnber_ctx_size_for_config(NULL, &rejected_size) ==
                    ASNBER_E_INVALID_ARG);

    asnber_ctx_t *ctx = NULL;
    ASNBER_TEST_CHECK(asnber_ctx_create(&config, &ctx) == ASNBER_OK);
    ASNBER_TEST_CHECK(ctx != NULL);

    asnber_error_info_t info;
    info.struct_size = sizeof(info);
    ASNBER_TEST_CHECK(asnber_ctx_get_error(ctx, &info) == ASNBER_OK);
    ASNBER_TEST_CHECK(info.code == ASNBER_OK);
    ASNBER_TEST_CHECK(info.message == NULL);
    ASNBER_TEST_CHECK(info.callback_code == 0);
    ASNBER_TEST_CHECK(info.offset == SIZE_MAX);
    ASNBER_TEST_CHECK(info.depth == 0);
    ASNBER_TEST_CHECK(info.path == NULL);

    asnber_ctx_destroy(ctx);
    asnber_ctx_destroy(NULL);

    /* struct_size 错误与预留字段非零。 */
    ASNBER_TEST_CHECK(asnber_ctx_create(NULL, &ctx) == ASNBER_E_INVALID_ARG);
    config.struct_size = 0;
    ASNBER_TEST_CHECK(asnber_ctx_create(&config, &ctx) == ASNBER_E_INVALID_CONFIG);
    asnber_ctx_config_init(&config);
    config.reserved_flags = 1;
    ASNBER_TEST_CHECK(asnber_ctx_create(&config, &ctx) == ASNBER_E_INVALID_CONFIG);
    asnber_ctx_config_init(&config);
    config.reserved[0] = 1;
    ASNBER_TEST_CHECK(asnber_ctx_create(&config, &ctx) == ASNBER_E_INVALID_CONFIG);

    /* 静态池：正常创建与销毁。 */
    asnber_ctx_config_init(&config);
    config.static_pool = (void *)&pool_storage;
    config.static_pool_size = sizeof(pool_storage);
    ASNBER_TEST_CHECK(asnber_ctx_create(&config, &ctx) == ASNBER_OK);

    asnber_doc_t *doc = NULL;
    ASNBER_TEST_CHECK(asnber_doc_create(ctx, &doc) == ASNBER_OK);
    asnber_node_t *root = NULL;
    ASNBER_TEST_CHECK(asnber_node_create(doc, NULL, ASNBER_TAG_UNIVERSAL, 16, 1,
                                     &root) == ASNBER_OK);
    asnber_node_t *child = NULL;
    ASNBER_TEST_CHECK(asnber_node_create(doc, root, ASNBER_TAG_UNIVERSAL, 2, 0,
                                     &child) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_node_set_int64(child, 7) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_doc_seal(doc) == ASNBER_OK);
    asnber_doc_destroy(doc);
    asnber_ctx_destroy(ctx);

    /* 静态池过小：上下文创建失败。 */
    asnber_ctx_config_init(&config);
    config.static_pool = (void *)&pool_storage;
    config.static_pool_size = required - 1;
    ASNBER_TEST_CHECK(asnber_ctx_create(&config, &ctx) == ASNBER_E_INVALID_CONFIG);

    /* 池恰好容纳上下文：上下文级分配返回耗尽错误。 */
    config.static_pool_size = required;
    ASNBER_TEST_CHECK(asnber_ctx_create(&config, &ctx) == ASNBER_OK);
    doc = NULL;
    ASNBER_TEST_CHECK(asnber_doc_create(ctx, &doc) ==
                    ASNBER_E_STATIC_POOL_EXHAUSTED);
    ASNBER_TEST_CHECK(doc == NULL);
    ASNBER_TEST_CHECK(asnber_ctx_get_error(ctx, &info) == ASNBER_OK);
    ASNBER_TEST_CHECK(info.code == ASNBER_E_STATIC_POOL_EXHAUSTED);
    asnber_ctx_destroy(ctx);

    /* 地址非空但尺寸为 0、地址为空但尺寸非 0。 */
    asnber_ctx_config_init(&config);
    config.static_pool = (void *)&pool_storage;
    config.static_pool_size = 0;
    ASNBER_TEST_CHECK(asnber_ctx_create(&config, &ctx) == ASNBER_E_INVALID_CONFIG);
    asnber_ctx_config_init(&config);
    config.static_pool_size = sizeof(pool_storage);
    ASNBER_TEST_CHECK(asnber_ctx_create(&config, &ctx) == ASNBER_E_INVALID_CONFIG);

    /* 静态池起始地址未按 max_align_t 对齐。 */
    asnber_ctx_config_init(&config);
    config.static_pool = (void *)(pool_storage.bytes + 1);
    config.static_pool_size = sizeof(pool_storage) - 1;
    ASNBER_TEST_CHECK(asnber_ctx_create(&config, &ctx) == ASNBER_E_INVALID_ARG);

    /* 尺寸查询的输入校验。 */
    asnber_ctx_config_init(&config);
    ASNBER_TEST_CHECK(asnber_ctx_size_for_config(&config, NULL) ==
                    ASNBER_E_INVALID_ARG);
    config.struct_size = 0;
    required = 123;
    ASNBER_TEST_CHECK(asnber_ctx_size_for_config(&config, &required) ==
                    ASNBER_E_INVALID_CONFIG);
    ASNBER_TEST_CHECK(required == 0);

    /* 分配器契约校验：struct_size、alloc/free 缺失均为配置错误。 */
    asnber_ctx_config_init(&config);
    ASNBER_TEST_CHECK(asnber_ctx_create(&config, NULL) == ASNBER_E_INVALID_ARG);

    asnber_allocator_t bad_allocator;
    bad_allocator.struct_size = sizeof(bad_allocator) - 1;
    bad_allocator.user = NULL;
    bad_allocator.alloc = counting_alloc;
    bad_allocator.realloc = NULL;
    bad_allocator.free = counting_free;
    config.allocator = &bad_allocator;
    ASNBER_TEST_CHECK(asnber_ctx_create(&config, &ctx) == ASNBER_E_INVALID_CONFIG);

    bad_allocator.struct_size = sizeof(bad_allocator);
    bad_allocator.alloc = NULL;
    ASNBER_TEST_CHECK(asnber_ctx_create(&config, &ctx) == ASNBER_E_INVALID_CONFIG);
    bad_allocator.alloc = counting_alloc;
    bad_allocator.free = NULL;
    ASNBER_TEST_CHECK(asnber_ctx_create(&config, &ctx) == ASNBER_E_INVALID_CONFIG);

    /* 自定义分配器：创建/销毁走同一 vtable，且全部内存归还。 */
    counting_state counting;
    memset(&counting, 0, sizeof(counting));
    asnber_allocator_t allocator;
    allocator.struct_size = sizeof(allocator);
    allocator.user = &counting;
    allocator.alloc = counting_alloc;
    allocator.realloc = NULL;
    allocator.free = counting_free;

    asnber_ctx_config_init(&config);
    config.allocator = &allocator;
    ASNBER_TEST_CHECK(asnber_ctx_create(&config, &ctx) == ASNBER_OK);
    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(counting.alloc_calls == 1);
    ASNBER_TEST_CHECK(counting.live_count == 1);

    doc = NULL;
    ASNBER_TEST_CHECK(asnber_doc_create(ctx, &doc) == ASNBER_OK);
    root = NULL;
    ASNBER_TEST_CHECK(asnber_node_create(doc, NULL, ASNBER_TAG_UNIVERSAL, 16, 1,
                                     &root) == ASNBER_OK);
    asnber_doc_destroy(doc);
    asnber_ctx_destroy(ctx);
    ASNBER_TEST_CHECK(counting.live_count == 0);
    ASNBER_TEST_CHECK(counting.alloc_calls == counting.free_calls);

    /* 分配器返回 NULL：创建报 NOMEM 且不泄漏。 */
    memset(&counting, 0, sizeof(counting));
    counting.fail_next = 1;
    config.allocator = &allocator;
    ctx = NULL;
    ASNBER_TEST_CHECK(asnber_ctx_create(&config, &ctx) == ASNBER_E_NOMEM);
    ASNBER_TEST_CHECK(ctx == NULL);
    ASNBER_TEST_CHECK(counting.live_count == 0);

    /* 错误状态接口的输入校验与正常读取。 */
    asnber_ctx_config_init(&config);
    ASNBER_TEST_CHECK(asnber_ctx_create(&config, &ctx) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_ctx_get_error(ctx, NULL) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_ctx_get_error(NULL, &info) == ASNBER_E_INVALID_ARG);
    info.struct_size = sizeof(info) - 1;
    ASNBER_TEST_CHECK(asnber_ctx_get_error(ctx, &info) == ASNBER_E_INVALID_CONFIG);
    asnber_ctx_clear_error(NULL);
    asnber_ctx_clear_error(ctx);

    /* 告警接口：本版本不产生告警，但注册与查询路径必须可用。 */
    ASNBER_TEST_CHECK(asnber_ctx_set_warning_handler(NULL, NULL, NULL) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_ctx_set_warning_handler(ctx, NULL, NULL) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_ctx_warning_count(ctx) == 0);
    ASNBER_TEST_CHECK(asnber_ctx_warning_count(NULL) == 0);
    asnber_warning_t warning;
    memset(&warning, 0, sizeof(warning));
    ASNBER_TEST_CHECK(asnber_ctx_get_warning(ctx, 0, &warning) ==
                    ASNBER_E_INVALID_CONFIG);
    warning.struct_size = sizeof(warning);
    ASNBER_TEST_CHECK(asnber_ctx_get_warning(ctx, 0, &warning) ==
                    ASNBER_E_INVALID_ARG);
    warning.struct_size = sizeof(warning) - 1;
    ASNBER_TEST_CHECK(asnber_ctx_get_warning(ctx, 0, &warning) ==
                    ASNBER_E_INVALID_CONFIG);
    ASNBER_TEST_CHECK(asnber_ctx_get_warning(ctx, 0, NULL) == ASNBER_E_INVALID_ARG);
    asnber_ctx_clear_warnings(NULL);
    asnber_ctx_clear_warnings(ctx);

    /* 非上下文本对象：magic 校验统一拒绝，不写入输出参数。 */
    memset(&foreign_ctx, 0, sizeof(foreign_ctx));
    asnber_ctx_t *foreign = (asnber_ctx_t *)&foreign_ctx;
    ASNBER_TEST_CHECK(asnber_ctx_set_warning_handler(foreign, NULL, NULL) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_ctx_warning_count(foreign) == 0);
    info.struct_size = sizeof(info);
    ASNBER_TEST_CHECK(asnber_ctx_get_error(foreign, &info) == ASNBER_E_INVALID_ARG);
    warning.struct_size = sizeof(warning);
    ASNBER_TEST_CHECK(asnber_ctx_get_warning(foreign, 0, &warning) ==
                    ASNBER_E_INVALID_ARG);
    asnber_ctx_clear_error(foreign);
    asnber_ctx_clear_warnings(foreign);
    asnber_ctx_destroy(foreign);

    asnber_ctx_destroy(ctx);

    return 0;
}
