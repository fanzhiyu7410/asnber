/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * asnber-pkcs 聚合包：版本宏与核心同源、聚合头可用。
 */

#include <asnber/asnber.h>
#include <asnber/pkcs/pkcs.h>

#include <stddef.h>
#include <string.h>

#include "check.h"

int main(void)
{
    asnber_version_info_t info;

    memset(&info, 0, sizeof(info));
    info.struct_size = sizeof(info);
    ASNBER_TEST_CHECK(asnber_version(&info) == ASNBER_OK);
    ASNBER_TEST_CHECK(info.string != NULL);
    ASNBER_TEST_CHECK(strcmp(ASNBER_PKCS_VERSION_STRING, info.string) == 0);
    return 0;
}
