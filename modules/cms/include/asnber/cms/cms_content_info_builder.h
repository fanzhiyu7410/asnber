/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-cms 公共子头文件：ContentInfo（RFC 5652 第 3 节）构造（写）。
 */

#ifndef ASNBER_CMS_CONTENT_INFO_BUILDER_H_INCLUDED
#define ASNBER_CMS_CONTENT_INFO_BUILDER_H_INCLUDED

#include <asnber/cms/cms_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* 结构构造（写）：ContentInfo builder                                         */
/* ------------------------------------------------------------------------- */

/*
 * 只做结构构造与 DER 编码：contentType 与 content 全部由调用方给值，模块
 * 原样承载。不做任何密码学处理。
 *
 * 组合约束：
 * - contentType 必填；
 * - content 必填（RFC 5652 的 ContentInfo 中 content 不是 OPTIONAL），
 *   两个 set_content_* 二选一；
 * - 两个 set_content_* 互斥，任一设置后另一种返回 ASNBER_E_INVALID_STATE；
 * - 每个单值字段只允许设置一次，重复设置返回 ASNBER_E_INVALID_STATE。
 */
typedef struct asnber_cms_content_info_builder asnber_cms_content_info_builder_t;

ASNBER_CMS_API asnber_err_t asnber_cms_content_info_builder_create(
    asnber_ctx_t *ctx, asnber_cms_content_info_builder_t **out_builder);

ASNBER_CMS_API void asnber_cms_content_info_builder_destroy(
    asnber_cms_content_info_builder_t *builder);

/* contentType：必填，重复设置返回 ASNBER_E_INVALID_STATE。 */
ASNBER_CMS_API asnber_err_t asnber_cms_content_info_builder_set_content_type(
    asnber_cms_content_info_builder_t *builder, const char *oid);

/* content：已编码的完整 TLV（含 tag/len），写入 [0] EXPLICIT 内层。 */
ASNBER_CMS_API asnber_err_t asnber_cms_content_info_builder_set_content_tlv(
    asnber_cms_content_info_builder_t *builder, const uint8_t *tlv,
    size_t tlv_size);

/* content：原始字节，模块补 OCTET STRING（PKCS#12 的 authSafe 用法）。 */
ASNBER_CMS_API asnber_err_t asnber_cms_content_info_builder_set_content_octets(
    asnber_cms_content_info_builder_t *builder, const uint8_t *data,
    size_t size);

/*
 * 组装并编码 ContentInfo。成功时 out_buf 由上下文分配，调用方用
 * asnber_buf_release 归还；失败时 out_buf 清零且不产出半成品。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_content_info_builder_encode(
    const asnber_cms_content_info_builder_t *builder, asnber_buf_t *out_buf);

#ifdef __cplusplus
}
#endif

#endif /* ASNBER_CMS_CONTENT_INFO_BUILDER_H_INCLUDED */
