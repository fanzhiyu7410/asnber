/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * 测试共用比较辅助实现，供 tests/ 下各用例共享。
 */

#include "test_compare.h"

#include <stdlib.h>
#include <string.h>

#include <asnber/asnber.h>

int bytes_equal(const uint8_t *actual, size_t actual_size,
                const void *expected, size_t expected_size)
{
    return actual != NULL && actual_size == expected_size &&
           memcmp(actual, expected, expected_size) == 0;
}

int text_equals(const char *actual, size_t actual_size, const char *expected)
{
    return actual != NULL && actual_size == strlen(expected) &&
           memcmp(actual, expected, actual_size) == 0;
}

int rewrite_outer_tag(const uint8_t *source, size_t source_size, uint8_t tag,
                      uint8_t **out_data, size_t *out_size)
{
    uint8_t *copy = (uint8_t *)malloc(source_size);
    if (copy == NULL) {
        return ASNBER_E_NOMEM;
    }
    memcpy(copy, source, source_size);
    copy[0] = tag;
    *out_data = copy;
    *out_size = source_size;
    return ASNBER_OK;
}
