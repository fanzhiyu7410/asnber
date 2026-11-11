/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-pkcs1 描述表访问（模块私有）。
 *
 * 一个 ASN.1 文件只生成一张表（头部默认根 RSAPublicKey）。RSAPrivateKey
 * 通过 asnber_schema_load_with_root 在加载期指定根类型编号。根编号取自原
 * 多表产物 .bin 头部偏移 96（小端 uint32），复核命令：
 *   python -c "print(int.from_bytes(open(PATH,'rb').read()[96:100],'little'))"
 */

#ifndef ASNBER_PKCS1_TABLES_H_INCLUDED
#define ASNBER_PKCS1_TABLES_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

struct pkcs1_table_view {
    const uint8_t *data;
    size_t size;
};

constexpr uint32_t kPkcs1RootRsaPublicKey = 1;
constexpr uint32_t kPkcs1RootRsaPrivateKey = 2;

pkcs1_table_view pkcs1SchemaTable();

#endif /* ASNBER_PKCS1_TABLES_H_INCLUDED */
