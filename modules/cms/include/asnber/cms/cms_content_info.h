/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-cms 公共子头文件：ContentInfo（RFC 5652 第 3 节）只读访问。
 */

#ifndef ASNBER_CMS_CONTENT_INFO_H_INCLUDED
#define ASNBER_CMS_CONTENT_INFO_H_INCLUDED

#include <asnber/cms/cms_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* ContentInfo（RFC 5652 第 3 节）                                            */
/* ------------------------------------------------------------------------- */

/*
 * 打开 DER 编码的 ContentInfo。
 *
 * - 使用模块随包发布的描述表加载 schema，并以 DER 严格模式解码；
 * - 输入被复制进文档 arena，调用方可在 open 返回后释放 der；
 * - 成功时 *out_info 非 NULL；失败时置 NULL 并返回核心错误码；
 * - 空参返回 ASNBER_E_INVALID_ARG；分配失败返回 ASNBER_E_NOMEM。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_content_info_open(
    asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asnber_cms_content_info_t **out_info);

/* 关闭句柄；info == NULL 为空操作。 */
ASNBER_CMS_API void asnber_cms_content_info_close(
    asnber_cms_content_info_t *info);

/* contentType：OID 点分十进制文本（借用句柄）。 */
ASNBER_CMS_API asnber_err_t asnber_cms_content_info_content_type(
    const asnber_cms_content_info_t *info, const char **out_dotted,
    size_t *out_size);

/*
 * content：`[0] EXPLICIT ANY` 内层的完整原始 TLV（含 tag/len，借用句柄），
 * 即被封装结构的 DER，可直接交给对应的 open 函数（如 SignedData）。
 * 外层 `[0]` 包装不包含在返回值内。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_content_info_content(
    const asnber_cms_content_info_t *info, const uint8_t **out_data,
    size_t *out_size);


#ifdef __cplusplus
}
#endif

#endif /* ASNBER_CMS_CONTENT_INFO_H_INCLUDED */
