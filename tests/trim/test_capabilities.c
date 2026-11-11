/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * 裁剪核心能力位断言：编码与运行时注册能力必须清除，
 * 描述表加载与名称查询必须保留。
 */
#include <asnber/asnber.h>

#include <stdio.h>

int main(void)
{
    if (asnber_has_capability(ASNBER_CAP_ENCODE_SCHEMA_AWARE) != 0) {
        fprintf(stderr, "FAIL: encode 能力位未清除\n");
        return 1;
    }
    if (asnber_has_capability(ASNBER_CAP_SCHEMA_RUNTIME_REGISTER) != 0) {
        fprintf(stderr, "FAIL: schema 运行时注册能力位未清除\n");
        return 1;
    }
    if (asnber_has_capability(ASNBER_CAP_SCHEMA_TABLE_LOAD) != 1) {
        fprintf(stderr, "FAIL: 描述表加载能力位缺失\n");
        return 1;
    }
    if (asnber_has_capability(ASNBER_CAP_SCHEMA_NAMES) != 1) {
        fprintf(stderr, "FAIL: 名称查询能力位缺失\n");
        return 1;
    }
    printf("OK\n");
    return 0;
}
