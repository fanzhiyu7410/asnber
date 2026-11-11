/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 分配器 vtable、上下文配置与上下文生命周期。契约见
 * docs/02-C-API规范.md 第 4、5、8 节与 docs/04-数据与内存模型.md 第 4 节。
 */
#ifndef ASNBER_ASNBER_ALLOCATOR_H_INCLUDED
#define ASNBER_ASNBER_ALLOCATOR_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include <asnber/asnber_error.h>
#include <asnber/asnber_export.h>

typedef struct asnber_ctx asnber_ctx_t;

/*
 * 分配器回调。alloc 与 free 必须提供；realloc 可为 NULL（库会用
 * alloc + memcpy + free 模拟）。所有回调必须返回 max_align_t 对齐的地址，
 * 且不得抛出异常。
 */
typedef struct asnber_allocator {
    size_t struct_size;                 /* 必须为 sizeof(asnber_allocator_t) */
    void  *user;                        /* 原样回传给回调 */
    void *(*alloc)(void *user, size_t size);
    void *(*realloc)(void *user, void *ptr, size_t size);
    void  (*free)(void *user, void *ptr);
} asnber_allocator_t;

/*
 * 上下文配置。所有 0 值预算字段表示使用默认值：
 * max_depth = 64、max_warnings = 1024、max_nodes = 1,000,000、
 * max_input_bytes = 64 MiB、max_output_bytes = 256 MiB。
 */
typedef struct asnber_ctx_config {
    size_t struct_size;                 /* 必须为 sizeof(asnber_ctx_config_t) */
    const asnber_allocator_t *allocator;  /* NULL 表示默认堆分配器 */
    void  *static_pool;                 /* 可选静态池起始地址 */
    size_t static_pool_size;            /* 0 表示不使用静态池 */
    uint32_t max_depth;                 /* 0 表示默认值 64 */
    uint32_t max_warnings;              /* 0 表示默认值 1024 */
    uint32_t reserved_flags;            /* 必须置零 */
    uint64_t max_nodes;                 /* 0 表示默认值 1,000,000 */
    uint64_t max_input_bytes;           /* 0 表示默认值 64 MiB */
    uint64_t max_output_bytes;          /* 0 表示默认值 256 MiB */
    uint32_t reserved[4];               /* 必须置零 */
} asnber_ctx_config_t;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 把 config 清零并写入 struct_size = sizeof(asnber_ctx_config_t)。
 * 默认预算字段保持 0，表示使用默认值。
 */
ASNBER_API void asnber_ctx_config_init(asnber_ctx_config_t *config);

/*
 * 计算满足该配置的静态池最小字节数（含上下文对象、对齐填充与固定簿记）。
 * config.static_pool 可为 NULL（此时只计算尺寸）。
 * 失败：config/out_size 为 NULL 返回 ASNBER_E_INVALID_ARG；配置非法返回
 * ASNBER_E_INVALID_CONFIG；尺寸溢出返回 ASNBER_E_MEMORY_LIMIT。
 */
ASNBER_API asnber_err_t asnber_ctx_size_for_config(const asnber_ctx_config_t *config,
                                             size_t *out_size);

/*
 * 创建上下文。失败时 *out_ctx 置 NULL。
 * config == NULL 或 out_ctx == NULL 返回 ASNBER_E_INVALID_ARG。
 * 配置非法返回 ASNBER_E_INVALID_CONFIG；静态池对齐非法返回 ASNBER_E_INVALID_ARG；
 * 分配失败返回 ASNBER_E_NOMEM；静态池耗尽返回 ASNBER_E_STATIC_POOL_EXHAUSTED。
 */
ASNBER_API asnber_err_t asnber_ctx_create(const asnber_ctx_config_t *config,
                                    asnber_ctx_t **out_ctx);

/* 销毁上下文；ctx == NULL 为空操作。调用方必须先销毁文档与 schema。 */
ASNBER_API void asnber_ctx_destroy(asnber_ctx_t *ctx);

/* 读取最近一次错误；无错误时以 ASNBER_OK + 空详情返回。 */
ASNBER_API asnber_err_t asnber_ctx_get_error(const asnber_ctx_t *ctx,
                                       asnber_error_info_t *out_info);

/* 清除错误状态；ctx == NULL 为空操作。 */
ASNBER_API void asnber_ctx_clear_error(asnber_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* ASNBER_ASNBER_ALLOCATOR_H_INCLUDED */
