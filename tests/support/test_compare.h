/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * 测试共用比较辅助：编码字节、十进制/点分文本与 TLV 外层标签改写。
 * 返回 1 表示相等/成功，0 表示不相等，改写失败返回错误码。
 */
#ifndef ASNBER_TESTS_SUPPORT_TEST_COMPARE_H_INCLUDED
#define ASNBER_TESTS_SUPPORT_TEST_COMPARE_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

int bytes_equal(const uint8_t *actual, size_t actual_size,
                const void *expected, size_t expected_size);
int text_equals(const char *actual, size_t actual_size, const char *expected);
int rewrite_outer_tag(const uint8_t *source, size_t source_size, uint8_t tag,
                      uint8_t **out_data, size_t *out_size);

#endif /* ASNBER_TESTS_SUPPORT_TEST_COMPARE_H_INCLUDED */
