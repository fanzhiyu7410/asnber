/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-ocsp 描述表访问（模块私有）。
 *
 * 一个 ASN.1 文件只生成一张表（头部默认根 OCSPResponse）。另外两个根在
 * asnber_schema_load_with_root 时指定类型号。号是具名类型在展平文件中的
 * 出现顺序，从 1 起：OCSPRequest = 14，OCSPResponse = 17，
 * BasicOCSPResponse = 24。
 */

#ifndef ASNBER_OCSP_TABLES_H_INCLUDED
#define ASNBER_OCSP_TABLES_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

struct ocsp_table_view {
    const uint8_t *data;
    size_t size;
};

constexpr uint32_t kOcspRootRequest = 14;
constexpr uint32_t kOcspRootResponse = 17;
constexpr uint32_t kOcspRootBasic = 24;

ocsp_table_view ocspSchemaTable();

#endif /* ASNBER_OCSP_TABLES_H_INCLUDED */
