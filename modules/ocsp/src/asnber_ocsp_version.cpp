/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-ocsp 版本查询。版本值只来自 CMake 生成的 ocsp_version.h。
 */

#include "asnber/ocsp/ocsp.h"

extern "C" ASNBER_OCSP_API const char *asnber_ocsp_version_string(void)
{
    return ASNBER_OCSP_VERSION_STRING;
}
