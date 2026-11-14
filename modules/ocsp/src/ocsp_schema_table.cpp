/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/* 由 asnberc 生成；ASNBER_OCSP_REGENERATE_TABLE=ON 时来自构建目录。 */
#include "ocsp_schema.h"

#include "ocsp_tables.h"

static_assert(kOcspRootRequest == 14, "OCSPRequest 类型号");
static_assert(kOcspRootResponse == 17, "OCSPResponse 类型号");
static_assert(kOcspRootBasic == 24, "BasicOCSPResponse 类型号");

ocsp_table_view ocspSchemaTable()
{
    ocsp_table_view view = {kOCSPFlattened6960Schema,
                            kOCSPFlattened6960Schema_size};
    return view;
}
