/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-cms 版本查询。版本值只来自 CMake 生成的 cms_version.h。
 */

#include "asnber/cms/cms.h"

extern "C" ASNBER_CMS_API const char *asnber_cms_version_string(void)
{
    return ASNBER_CMS_VERSION_STRING;
}
