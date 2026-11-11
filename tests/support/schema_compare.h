/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * 测试专用 schema 等价比较：逐类型/字段/约束比较两条已封存类型树。
 * 仅位于 tests/ 下，不是公共 ABI。
 */
#ifndef ASNBER_TESTS_SUPPORT_SCHEMA_COMPARE_H_INCLUDED
#define ASNBER_TESTS_SUPPORT_SCHEMA_COMPARE_H_INCLUDED

#include <asnber/asnber.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 比较两条类型树。返回 0 表示完全相等；非 0 为编号错误（编号语义与原
 * test_schema_table.c 内的实现保持一致，便于定位首个不一致的位置）。
 */
int asnber_test_compare_schemas(const asnber_schema_t *lhs,
                              const asnber_schema_t *rhs);

#ifdef __cplusplus
}
#endif

#endif /* ASNBER_TESTS_SUPPORT_SCHEMA_COMPARE_H_INCLUDED */
