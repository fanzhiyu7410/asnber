/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * 确定性冒烟用例：反复调用已落地的版本接口，验证无状态残留与稳定返回。
 * 真实 fuzz harness 待 libFuzzer 接入后替换本用例的注册方式。
 */
#include <asnber/asnber.h>

#include "check.h"

int main(void)
{
    unsigned i;

    for (i = 0; i < 1000u; ++i) {
        asnber_version_info_t info;
        info.struct_size = sizeof(info);
        ASNBER_TEST_CHECK(asnber_version(&info) == ASNBER_OK);
        ASNBER_TEST_CHECK(info.major == ASNBER_VERSION_MAJOR);
        ASNBER_TEST_CHECK(asnber_has_capability(0) == 0);
    }

    return 0;
}
