/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 只读节点访问与语义读取。契约见 docs/02-C-API规范.md 第 6 节与 6.6。
 * 所有指针均为文档借用，生命周期不超过所属文档。
 */
#ifndef ASNBER_ASNBER_NODE_H_INCLUDED
#define ASNBER_ASNBER_NODE_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include <asnber/asnber_build.h>
#include <asnber/asnber_decode.h>
#include <asnber/asnber_error.h>
#include <asnber/asnber_export.h>

/* 节点在源编码中实际使用的形式（与 schema 的 kind 无关）。 */
typedef enum asnber_encoding_form {
    ASNBER_FORM_PRIMITIVE = 0,    /* 基本形式 */
    ASNBER_FORM_CONSTRUCTED = 1   /* 构造形式（含 BER 构造字符串） */
} asnber_encoding_form_t;

/* ASNBER_TIME_* 位标志，语义见 docs/02-C-API规范.md 5.3。 */
#define ASNBER_TIME_UTC ((uint32_t)(1u << 0))
#define ASNBER_TIME_GENERALIZED ((uint32_t)(1u << 1))
#define ASNBER_TIME_HAS_OFFSET ((uint32_t)(1u << 2))
#define ASNBER_TIME_FRACTIONAL ((uint32_t)(1u << 3))
#define ASNBER_TIME_LOCAL ((uint32_t)(1u << 4))

/*
 * 结构化时间。struct_size 必须为 sizeof(asnber_time_t)。
 * 时间三态：HAS_OFFSET 表示显式偏移，LOCAL 表示本地时间且无偏移，
 * 两者都不置位表示 Z。
 */
typedef struct asnber_time {
    size_t struct_size;                 /* 输入：必须为 sizeof(asnber_time_t) */
    int32_t year;
    uint8_t month;
    uint8_t day;
    uint8_t hour;
    uint8_t minute;
    uint8_t second;
    uint8_t reserved_flags;             /* 必须置零（输出恒为 0） */
    int16_t utc_offset_minutes;         /* 仅 HAS_OFFSET 时有效 */
    uint32_t nanosecond;                /* 0..999,999,999；仅 FRACTIONAL 时有效 */
    uint32_t flags;                     /* ASNBER_TIME_* */
} asnber_time_t;

#ifdef __cplusplus
extern "C" {
#endif

/* 文档与节点只读访问。 */
ASNBER_API const asnber_node_t   *asnber_doc_root(const asnber_doc_t *doc);
ASNBER_API asnber_encoding_t      asnber_doc_source_encoding(const asnber_doc_t *doc);
ASNBER_API asnber_tag_class_t     asnber_node_tag_class(const asnber_node_t *node);
ASNBER_API uint32_t             asnber_node_tag_number(const asnber_node_t *node);
ASNBER_API asnber_encoding_form_t asnber_node_encoding_form(const asnber_node_t *node);
ASNBER_API int                  asnber_node_is_indefinite(const asnber_node_t *node);
ASNBER_API size_t               asnber_node_child_count(const asnber_node_t *node);
ASNBER_API const asnber_node_t   *asnber_node_child_at(const asnber_node_t *node,
                                                 size_t index);
ASNBER_API const asnber_node_t   *asnber_node_child_by_name(const asnber_node_t *node,
                                                      const char *field_name);
ASNBER_API const char          *asnber_node_field_name(const asnber_node_t *node);
ASNBER_API const asnber_node_t   *asnber_node_parent(const asnber_node_t *node);
ASNBER_API asnber_err_t asnber_node_content(const asnber_node_t *node,
                                      const uint8_t **out_data,
                                      size_t *out_size);
ASNBER_API const uint8_t       *asnber_node_tlv(const asnber_node_t *node,
                                            size_t *out_size);
ASNBER_API size_t               asnber_node_offset(const asnber_node_t *node);

/* 语义读取：失败返回错误码，且不写部分输出。 */
ASNBER_API asnber_err_t asnber_node_get_bool(const asnber_node_t *node, int *out_value);
ASNBER_API asnber_err_t asnber_node_get_int64(const asnber_node_t *node, int64_t *out_value);
ASNBER_API asnber_err_t asnber_node_get_octets(const asnber_node_t *node,
                                         const uint8_t **out_data,
                                         size_t *out_size);
ASNBER_API asnber_err_t asnber_node_get_oid(const asnber_node_t *node,
                                      const char **out_dotted,
                                      size_t *out_size);
ASNBER_API asnber_err_t asnber_node_get_bits(const asnber_node_t *node,
                                       const uint8_t **out_data,
                                       size_t *out_size,
                                       size_t *out_bit_length,
                                       uint8_t *out_unused_bits);
ASNBER_API asnber_err_t asnber_node_get_raw_string(const asnber_node_t *node,
                                             const uint8_t **out_data,
                                             size_t *out_size);
ASNBER_API asnber_err_t asnber_node_get_utf8(const asnber_node_t *node,
                                       const char **out_text,
                                       size_t *out_size);
ASNBER_API asnber_err_t asnber_node_get_bigint_decimal(const asnber_node_t *node,
                                                 const char **out_text,
                                                 size_t *out_size);
ASNBER_API asnber_err_t asnber_node_get_time(const asnber_node_t *node,
                                       asnber_time_t *out_time);

#ifdef __cplusplus
}
#endif

#endif /* ASNBER_ASNBER_NODE_H_INCLUDED */
