/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 告警结构、告警回调与上下文级告警记录。语义见
 * docs/02-C-API规范.md 6.7 与第 10 节。
 */
#ifndef ASNBER_ASNBER_WARNING_H_INCLUDED
#define ASNBER_ASNBER_WARNING_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include <asnber/asnber_allocator.h>
#include <asnber/asnber_error.h>
#include <asnber/asnber_export.h>

/*
 * 告警记录。struct_size 必须为 sizeof(asnber_warning_t)。
 * field_name 与 message 由上下文持有，有效期到下一次解码或上下文销毁。
 */
typedef struct asnber_warning {
    size_t struct_size;                 /* 输入：必须为 sizeof(asnber_warning_t) */
    asnber_err_t code;                    /* 告警类错误码（稳定） */
    size_t offset;                      /* 输入字节偏移；无意义时为 SIZE_MAX */
    uint32_t depth;                     /* 嵌套深度；无意义时为 0 */
    const char *field_name;             /* schema 字段名；无则为 NULL */
    const char *message;                /* 上下文持有的英文短消息 */
} asnber_warning_t;

/* 告警回调返回 void；告警不影响解码流程、不写入主错误码、不中止解码。 */
typedef void (*asnber_warning_fn)(void *user, const asnber_warning_t *warning);

#ifdef __cplusplus
extern "C" {
#endif

/* 注册回调；handler == NULL 表示清除回调。 */
ASNBER_API asnber_err_t asnber_ctx_set_warning_handler(asnber_ctx_t *ctx,
                                                 asnber_warning_fn handler,
                                                 void *user);

/* 当前已记录的告警数量。 */
ASNBER_API size_t asnber_ctx_warning_count(const asnber_ctx_t *ctx);

/*
 * 读取告警。index 从 0 开始；index >= 数量时返回 ASNBER_E_INVALID_ARG，
 * 且不修改 out_warning。
 */
ASNBER_API asnber_err_t asnber_ctx_get_warning(const asnber_ctx_t *ctx,
                                         size_t index,
                                         asnber_warning_t *out_warning);

/* 清空告警记录；ctx == NULL 为空操作。 */
ASNBER_API void asnber_ctx_clear_warnings(asnber_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* ASNBER_ASNBER_WARNING_H_INCLUDED */
