/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * 版本查询与自检的最小单元断言。
 */
#include <asnber/asnber.h>

#include <string.h>

#include "check.h"

int main(void)
{
    asnber_version_info_t info;
    info.struct_size = sizeof(info);

    ASNBER_TEST_CHECK(asnber_version(&info) == ASNBER_OK);
    ASNBER_TEST_CHECK(info.struct_size == sizeof(info));
    ASNBER_TEST_CHECK(info.major == ASNBER_VERSION_MAJOR);
    ASNBER_TEST_CHECK(info.minor == ASNBER_VERSION_MINOR);
    ASNBER_TEST_CHECK(info.patch == ASNBER_VERSION_PATCH);
    ASNBER_TEST_CHECK(info.reserved == 0);
    ASNBER_TEST_CHECK(info.string != NULL);
    ASNBER_TEST_CHECK(strcmp(info.string, ASNBER_VERSION_STRING) == 0);

    ASNBER_TEST_CHECK(asnber_version_check(ASNBER_VERSION_MAJOR, ASNBER_VERSION_MINOR) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_version_check(ASNBER_VERSION_MAJOR + 1u, ASNBER_VERSION_MINOR) ==
                    ASNBER_E_VERSION_MISMATCH);

    info.struct_size = 0;
    ASNBER_TEST_CHECK(asnber_version(&info) == ASNBER_E_INVALID_CONFIG);
    ASNBER_TEST_CHECK(asnber_version(NULL) == ASNBER_E_INVALID_ARG);

    return 0;
}
