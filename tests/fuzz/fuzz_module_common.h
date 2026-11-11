/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * 模块级 harness 公共辅助：统一的“按索引探测”约定。
 *
 * 所有带下标（index）的模块访问器都按 0 / count / SIZE_MAX 三个值探测，
 * 分别覆盖：首个元素、越界一个、索引加法溢出。返回值一律忽略，只有
 * 崩溃 / ASan / LSan 报错才算失败。
 */
#ifndef ASNBER_TESTS_FUZZ_FUZZ_MODULE_COMMON_H_INCLUDED
#define ASNBER_TESTS_FUZZ_FUZZ_MODULE_COMMON_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

enum {
    FUZZ_INDEX_ZERO = 0,
    FUZZ_INDEX_COUNT = 1,
    FUZZ_INDEX_MAX = 2,
    FUZZ_INDEX_PROBES = 3
};

/* 把探针序号映射为实际 index：0 / count / SIZE_MAX。 */
static size_t fuzz_probe_index(size_t count, int probe)
{
    switch (probe) {
    case FUZZ_INDEX_ZERO:
        return 0;
    case FUZZ_INDEX_COUNT:
        return count;
    default:
        return SIZE_MAX;
    }
}

#endif /* ASNBER_TESTS_FUZZ_FUZZ_MODULE_COMMON_H_INCLUDED */
