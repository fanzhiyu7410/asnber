/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * 验证测试辅助头与生成版本宏可用。
 */
#include <asnber/asnber.h>

#include "check.h"

int main(void)
{
    ASNBER_TEST_CHECK(ASNBER_VERSION_STRING[0] != '\0');
    ASNBER_TEST_CHECK(ASNBER_VERSION_ENCODED ==
                    ((ASNBER_VERSION_MAJOR << 16) | (ASNBER_VERSION_MINOR << 8) |
                     ASNBER_VERSION_PATCH));
    return 0;
}
