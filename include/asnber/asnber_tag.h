/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * UNIVERSAL 标签号与编码形态常量。
 *
 * asnber_node_create 的 tag_number 是 X.690 的标签号，不是完整的
 * identifier octet；constructed 是 identifier octet 中的 P/C 位。
 * 这些常量只提供可读名称，不改变运行期校验：库不会根据 tag_number
 * 推导 constructed，也不会校验 UNIVERSAL 标签与 constructed 的组合。
 */
#ifndef ASNBER_ASNBER_TAG_H_INCLUDED
#define ASNBER_ASNBER_TAG_H_INCLUDED

/* UNIVERSAL 标签号（X.690 / ASN.1 内建类型）。
 * 本表只列常用类型；未列出的 UNIVERSAL 标签号仍可直接作为 tag_number 传入。 */
#define ASNBER_UNIVERSAL_BOOLEAN           1u
#define ASNBER_UNIVERSAL_INTEGER           2u
#define ASNBER_UNIVERSAL_BIT_STRING        3u
#define ASNBER_UNIVERSAL_OCTET_STRING      4u
#define ASNBER_UNIVERSAL_NULL              5u
#define ASNBER_UNIVERSAL_OID               6u /* OBJECT IDENTIFIER */
#define ASNBER_UNIVERSAL_ENUMERATED        10u
#define ASNBER_UNIVERSAL_UTF8_STRING       12u
#define ASNBER_UNIVERSAL_SEQUENCE          16u
#define ASNBER_UNIVERSAL_SET               17u
#define ASNBER_UNIVERSAL_NUMERIC_STRING    18u
#define ASNBER_UNIVERSAL_PRINTABLE_STRING  19u
#define ASNBER_UNIVERSAL_T61_STRING        20u /* T61String / TeletexString */
#define ASNBER_UNIVERSAL_IA5_STRING        22u
#define ASNBER_UNIVERSAL_UTC_TIME          23u
#define ASNBER_UNIVERSAL_GENERALIZED_TIME  24u
#define ASNBER_UNIVERSAL_VISIBLE_STRING    26u
#define ASNBER_UNIVERSAL_UNIVERSAL_STRING  28u
#define ASNBER_UNIVERSAL_BMP_STRING        30u

/* asnber_node_create 的 constructed 参数。 */
#define ASNBER_PRIMITIVE   0
#define ASNBER_CONSTRUCTED 1

#endif /* ASNBER_ASNBER_TAG_H_INCLUDED */
