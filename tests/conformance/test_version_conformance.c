/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * 生成头、运行期版本与版本编号规则三者的一致性断言。
 */
#include <asnber/asnber.h>

#include <stdio.h>
#include <string.h>

#include "check.h"

int main(void)
{
    asnber_version_info_t info;
    char expected[64];

    info.struct_size = sizeof(info);
    ASNBER_TEST_CHECK(asnber_version(&info) == ASNBER_OK);

    (void)snprintf(expected, sizeof(expected), "%u.%u.%u",
                   (unsigned)ASNBER_VERSION_MAJOR,
                   (unsigned)ASNBER_VERSION_MINOR,
                   (unsigned)ASNBER_VERSION_PATCH);

    ASNBER_TEST_CHECK(strcmp(expected, ASNBER_VERSION_STRING) == 0);
    ASNBER_TEST_CHECK(strcmp(info.string, expected) == 0);
    ASNBER_TEST_CHECK(ASNBER_VERSION_ENCODED ==
                    ((ASNBER_VERSION_MAJOR << 16) | (ASNBER_VERSION_MINOR << 8) |
                     ASNBER_VERSION_PATCH));

    /* 次版本差异视为兼容，只有主版本不一致才失败。 */
    ASNBER_TEST_CHECK(asnber_version_check(ASNBER_VERSION_MAJOR, ASNBER_VERSION_MINOR + 1u) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_version_check(ASNBER_VERSION_MAJOR + 1u, ASNBER_VERSION_MINOR) ==
                    ASNBER_E_VERSION_MISMATCH);

    return 0;
}
