/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 错误码与错误详情。错误码表与分类见 docs/05-错误模型.md；错误详情字段
 * 语义见 docs/02-C-API规范.md 第 7 节。
 *
 * 本头文件不声明任何函数；错误状态通过 asnber/asnber_allocator.h 中的上下文
 * 接口读取与清除。
 */
#ifndef ASNBER_ASNBER_ERROR_H_INCLUDED
#define ASNBER_ASNBER_ERROR_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

typedef int32_t asnber_err_t;

/* 成功。 */
#define ASNBER_OK ((asnber_err_t)0)

/* 调用/配置错误（1000–1999）。 */
#define ASNBER_E_INVALID_ARG ((asnber_err_t)1001)
#define ASNBER_E_INVALID_CONFIG ((asnber_err_t)1002)
#define ASNBER_E_INVALID_STATE ((asnber_err_t)1003)
#define ASNBER_E_UNSUPPORTED ((asnber_err_t)1004)
#define ASNBER_E_VERSION_MISMATCH ((asnber_err_t)1005)

/* 内存错误（2000–2999）。 */
#define ASNBER_E_NOMEM ((asnber_err_t)2001)
#define ASNBER_E_MEMORY_LIMIT ((asnber_err_t)2002)
#define ASNBER_E_STATIC_POOL_EXHAUSTED ((asnber_err_t)2003)

/* 解码/数据错误（3000–3999）。 */
#define ASNBER_E_TRUNCATED ((asnber_err_t)3001)
#define ASNBER_E_MALFORMED_TAG ((asnber_err_t)3002)
#define ASNBER_E_MALFORMED_LENGTH ((asnber_err_t)3003)
#define ASNBER_E_LENGTH_MISMATCH ((asnber_err_t)3004)
#define ASNBER_E_INDEFINITE_NOT_ALLOWED ((asnber_err_t)3005)
#define ASNBER_E_TRAILING_DATA ((asnber_err_t)3006)
#define ASNBER_E_MALFORMED_VALUE ((asnber_err_t)3007)
#define ASNBER_E_NON_CANONICAL ((asnber_err_t)3008)

/* 编码/值错误（4000–4999）。 */
#define ASNBER_E_UNSUPPORTED_ENCODING ((asnber_err_t)4001)
#define ASNBER_E_INVALID_VALUE ((asnber_err_t)4002)
#define ASNBER_E_RANGE ((asnber_err_t)4003)
#define ASNBER_E_CONVERSION ((asnber_err_t)4004)

/* 资源上限（5000–5999）。 */
#define ASNBER_E_DEPTH_LIMIT ((asnber_err_t)5001)
#define ASNBER_E_NODE_LIMIT ((asnber_err_t)5002)
#define ASNBER_E_INPUT_LIMIT ((asnber_err_t)5003)
#define ASNBER_E_OUTPUT_LIMIT ((asnber_err_t)5004)

/* IO/回调错误（6000–6999）。 */
#define ASNBER_E_IO_READ ((asnber_err_t)6001)
#define ASNBER_E_IO_WRITE ((asnber_err_t)6002)

/* 模板/模式校验（7000–7999）。 */
#define ASNBER_E_SCHEMA_FORMAT ((asnber_err_t)7001)
#define ASNBER_E_SCHEMA_TYPE ((asnber_err_t)7002)
#define ASNBER_E_SCHEMA_FIELD ((asnber_err_t)7003)
#define ASNBER_E_SCHEMA_CONSTRAINT ((asnber_err_t)7004)
#define ASNBER_E_SCHEMA_DEFAULT ((asnber_err_t)7005)

/* 内部错误（8000–8999）。 */
#define ASNBER_E_INTERNAL ((asnber_err_t)8001)

/*
 * 错误详情。调用方必须把 struct_size 初始化为 sizeof(asnber_error_info_t)。
 * 成功读取（asnber_ctx_get_error 返回 ASNBER_OK）时各字段按下表填充：
 * 无错误时 code = ASNBER_OK、message = NULL、callback_code = 0、
 * offset = SIZE_MAX、depth = 0、path = NULL。
 */
typedef struct asnber_error_info {
    size_t struct_size;      /* 输入：必须为 sizeof(asnber_error_info_t) */
    asnber_err_t code;         /* 最近一次失败的稳定错误码 */
    int32_t callback_code;   /* 原始 reader/writer 回调错误码；无则为 0 */
    const char *message;     /* 静态英文短消息；无错误为 NULL */
    size_t offset;           /* 输入字节偏移；无意义时为 SIZE_MAX */
    uint32_t depth;          /* 出错时的嵌套深度；无意义时为 0 */
    uint32_t reserved;       /* 必须置零 */
    const char *path;        /* schema 字段路径；无 schema 或无法定位时为 NULL */
} asnber_error_info_t;

#endif /* ASNBER_ASNBER_ERROR_H_INCLUDED */
