/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * libFuzzer harness 公共辅助：默认堆上下文、节点递归遍历、内存 reader、
 * 最小手工 schema（SEQUENCE { OID 必选, ANY 可选 }，根类型已封存）。
 * 只依赖公共 C ABI。
 */
#ifndef ASNBER_TESTS_FUZZ_FUZZ_COMMON_H_INCLUDED
#define ASNBER_TESTS_FUZZ_FUZZ_COMMON_H_INCLUDED

#include <asnber/asnber.h>

#include <stddef.h>
#include <stdint.h>

/* 创建默认堆上下文；失败返回 NULL。 */
asnber_ctx_t *fuzz_ctx_create(void);

/* 递归遍历节点，触发只读访问路径（不检查返回值，仅确保不崩溃）。 */
void fuzz_walk(const asnber_node_t *node);

/* 内存 reader：从固定缓冲区按块供应字节，块边界由 capacity 决定。 */
typedef struct fuzz_mem_reader {
    const uint8_t *data;
    size_t size;
    size_t pos;
} fuzz_mem_reader_t;

asnber_err_t fuzz_mem_read(void *user, uint8_t *dst, size_t capacity,
                         size_t *out_size);

/*
 * 构造并封存一个最小 schema：SEQUENCE { algorithm OID 必选, parameters ANY
 * 可选 }。用于 schema 感知解码 / reader-with-schema 覆盖未知字段与 ANY 分支。
 * 失败返回 NULL。
 */
asnber_schema_t *fuzz_min_schema_create(asnber_ctx_t *ctx);

#endif /* ASNBER_TESTS_FUZZ_FUZZ_COMMON_H_INCLUDED */