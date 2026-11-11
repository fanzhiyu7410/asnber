/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * 以 C99 编译器和公共头验证 C ABI 的版本查询与能力位行为。
 */
#include <asnber/asnber.h>

#include <string.h>

#include "check.h"

int main(void)
{
    asnber_version_info_t info;
    info.struct_size = sizeof(asnber_version_info_t);

    ASNBER_TEST_CHECK(asnber_version(&info) == ASNBER_OK);
    ASNBER_TEST_CHECK(info.struct_size == sizeof(asnber_version_info_t));
    ASNBER_TEST_CHECK(info.reserved == 0);
    ASNBER_TEST_CHECK(info.string != NULL);
    /* 已验收能力位全部置位；CER/PER 仍为保留位。 */
    const uint64_t expected = ASNBER_CAP_SCHEMA_TABLE_LOAD |
                              ASNBER_CAP_SCHEMA_RUNTIME_REGISTER |
                              ASNBER_CAP_STRICT_SCHEMA | ASNBER_CAP_WARNING |
                              ASNBER_CAP_BER_CONSTRUCTED_STRING |
                              ASNBER_CAP_TIME_NANOSECOND |
                              ASNBER_CAP_BIGINT_DECIMAL |
                              ASNBER_CAP_ENCODE_SCHEMA_AWARE |
                              ASNBER_CAP_ANY_OPEN_TYPE |
                              ASNBER_CAP_SCHEMA_NAMES;
    ASNBER_TEST_CHECK(info.capabilities == expected);
    ASNBER_TEST_CHECK(asnber_has_capability(ASNBER_CAP_SCHEMA_NAMES) == 1);
    ASNBER_TEST_CHECK(asnber_has_capability(ASNBER_CAP_ANY_OPEN_TYPE) == 1);
    ASNBER_TEST_CHECK(asnber_has_capability(ASNBER_CAP_ENCODE_SCHEMA_AWARE) == 1);

    /* 0、多位组合与未定义位一律返回 0。 */
    ASNBER_TEST_CHECK(asnber_has_capability(0) == 0);
    ASNBER_TEST_CHECK(asnber_has_capability(ASNBER_CAP_CER | ASNBER_CAP_PER) == 0);
    ASNBER_TEST_CHECK(asnber_has_capability(UINT64_C(1) << 63) == 0);

    ASNBER_TEST_CHECK(asnber_version_check(ASNBER_VERSION_MAJOR, ASNBER_VERSION_MINOR) == ASNBER_OK);
    ASNBER_TEST_CHECK(strcmp(info.string, ASNBER_VERSION_STRING) == 0);

    return 0;
}
