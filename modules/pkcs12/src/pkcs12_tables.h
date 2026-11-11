/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-pkcs12 描述表访问（模块私有）。
 *
 * 一个 ASN.1 文件只生成一张表（头部默认根 PFX）。AuthenticatedSafe /
 * SafeContents / CertBag 通过 asnber_schema_load_with_root 在加载期指定根
 * 类型编号。根编号取自原多表产物 .bin 头部偏移 96（小端 uint32），复核命令：
 *   python -c "print(int.from_bytes(open(PATH,'rb').read()[96:100],'little'))"
 */

#ifndef ASNBER_PKCS12_TABLES_H_INCLUDED
#define ASNBER_PKCS12_TABLES_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

struct pkcs12_table_view {
    const uint8_t *data;
    size_t size;
};

constexpr uint32_t kPkcs12RootPfx = 1;
constexpr uint32_t kPkcs12RootAuthenticatedSafe = 7;
constexpr uint32_t kPkcs12RootSafeContents = 8;
constexpr uint32_t kPkcs12RootCertBag = 11;

pkcs12_table_view pkcs12SchemaTable();

#endif /* ASNBER_PKCS12_TABLES_H_INCLUDED */
