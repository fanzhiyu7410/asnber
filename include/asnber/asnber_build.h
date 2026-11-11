/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * runtime 构树：创建文档、创建节点、设置内容与封存。契约见
 * docs/02-C-API规范.md 6.1 与 docs/04-数据与内存模型.md 2.1。
 */
#ifndef ASNBER_ASNBER_BUILD_H_INCLUDED
#define ASNBER_ASNBER_BUILD_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include <asnber/asnber_decode.h>
#include <asnber/asnber_error.h>
#include <asnber/asnber_export.h>
#include <asnber/asnber_features.h>

typedef enum asnber_tag_class {
    ASNBER_TAG_UNIVERSAL = 0,
    ASNBER_TAG_APPLICATION = 1,
    ASNBER_TAG_CONTEXT = 2,
    ASNBER_TAG_PRIVATE = 3
} asnber_tag_class_t;

#ifdef __cplusplus
extern "C" {
#endif

#if ASNBER_FEATURE_BUILD_API
/* 创建空文档（未封存、源编码 ASNBER_ENCODING_NONE）；失败时 *out_doc 置 NULL。 */
ASNBER_API asnber_err_t asnber_doc_create(asnber_ctx_t *ctx, asnber_doc_t **out_doc);

/*
 * 冻结文档并校验结构（根存在、基本节点已设置内容、构造节点无内容）。
 * 幂等：已封存文档再次调用返回 ASNBER_OK。失败时文档仍可销毁。
 */
ASNBER_API asnber_err_t asnber_doc_seal(asnber_doc_t *doc);

/*
 * 创建节点。parent == NULL 表示设置根节点（只能一次）；非空 parent 表示
 * 追加为最后一个子节点，parent 必须是构造节点。
 * constructed 是运行期构造位；tag_class 必须是合法枚举值。
 * UNIVERSAL + tag_number 0 非法；其他标签类下 tag_number 0 合法。
 */
ASNBER_API asnber_err_t asnber_node_create(asnber_doc_t *doc,
                                     asnber_node_t *parent,
                                     asnber_tag_class_t tag_class,
                                     uint32_t tag_number,
                                     int constructed,
                                     asnber_node_t **out_node);

/*
 * 创建 ANY/开放类型节点：tlv 必须恰好是一个完整、长度确定的 TLV。
 * 字节复制进文档 arena；tag_class/tag_number/constructed 从 TLV 头推导，
 * content 指向副本内的内容切片（不含 tag/len）。
 *
 * 本入口只校验 TLV 结构，不校验 DER 规范性：非最短长度、非规范
 * INTEGER/BOOLEAN 内容等都会被接受。三段分工：创建接受非规范 TLV；
 * schema 感知编码按 DER 校验并拒绝（ASNBER_E_NON_CANONICAL）；无 schema
 * 编码原样写出保留字节，不做规范化。
 *
 * 拒绝：空输入（ASNBER_E_INVALID_ARG）、截断（ASNBER_E_TRUNCATED）、
 * 不定长（ASNBER_E_INDEFINITE_NOT_ALLOWED）、尾随字节
 * （ASNBER_E_TRAILING_DATA）、畸形标签/长度（ASNBER_E_MALFORMED_TAG /
 * ASNBER_E_MALFORMED_LENGTH）。失败时 *out_node 置 NULL；解析失败写入
 * 上下文错误 offset（TLV 内字节偏移），父节点不匹配、分配失败等非解析
 * 失败不保证 offset，调用方应按错误码判断。
 *
 * ANY 节点不得挂子节点；对其调用 asnber_node_create 返回
 * ASNBER_E_INVALID_STATE。ANY 节点也不接受 asnber_node_set_content。
 */
ASNBER_API asnber_err_t asnber_node_create_any(asnber_doc_t *doc,
                                        asnber_node_t *parent,
                                        const uint8_t *tlv, size_t tlv_size,
                                        asnber_node_t **out_node);

/* 把内容复制进文档 arena；同一节点只允许设置一次内容。 */
ASNBER_API asnber_err_t asnber_node_set_content(asnber_node_t *node,
                                          const uint8_t *data, size_t size);

/* 写入规范 BOOLEAN 内容（false = 0x00，true = 0xFF）。 */
ASNBER_API asnber_err_t asnber_node_set_bool(asnber_node_t *node, int value);

/* 写入最小长度二进制补码 INTEGER 内容。 */
ASNBER_API asnber_err_t asnber_node_set_int64(asnber_node_t *node, int64_t value);

/* 把点分十进制 OID 编码为内容字节并复制进 arena。 */
ASNBER_API asnber_err_t asnber_node_set_oid(asnber_node_t *node, const char *dotted);

/* 把 UTF-8 文本字节复制进 arena；不做字符集校验。 */
ASNBER_API asnber_err_t asnber_node_set_utf8(asnber_node_t *node,
                                       const char *text, size_t size);
#endif

#ifdef __cplusplus
}
#endif

#endif /* ASNBER_ASNBER_BUILD_H_INCLUDED */
