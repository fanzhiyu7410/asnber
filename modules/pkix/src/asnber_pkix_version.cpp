/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-pkix 版本查询。版本值只来自 CMake 生成的 pkix_version.h。
 */

#include "asnber/pkix/pkix.h"

extern "C" ASNBER_PKIX_API const char *asnber_pkix_version_string(void)
{
    return ASNBER_PKIX_VERSION_STRING;
}
