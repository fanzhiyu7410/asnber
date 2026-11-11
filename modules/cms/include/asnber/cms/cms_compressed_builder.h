/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-cms 公共子头文件：CompressedData 构造（写）。
 */

#ifndef ASNBER_CMS_COMPRESSED_BUILDER_H_INCLUDED
#define ASNBER_CMS_COMPRESSED_BUILDER_H_INCLUDED

#include <asnber/cms/cms_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* 结构构造（写）：CompressedData builder                                      */
/* ------------------------------------------------------------------------- */

/*
 * 只做结构构造与 DER 编码：压缩算法 OID、内容类型与已压缩内容全部由调用方
 * 给值，模块原样承载。不做压缩/解压、不生成随机数。
 *
 * 组合约束：
 * - version / compressionAlgorithm / eContentType 必填；
 * - RFC 3274 规定 version 必须为 0，set_version 只接受 0，其他值立即返回
 *   ASNBER_E_INVALID_VALUE；
 * - eContent 可缺省，表示 detached 形式；
 * - 每个单值字段只允许设置一次，重复设置返回 ASNBER_E_INVALID_STATE。
 */
typedef struct asnber_cms_compressed_builder asnber_cms_compressed_builder_t;

ASNBER_CMS_API asnber_err_t asnber_cms_compressed_builder_create(
    asnber_ctx_t *ctx, asnber_cms_compressed_builder_t **out_builder);

ASNBER_CMS_API void asnber_cms_compressed_builder_destroy(
    asnber_cms_compressed_builder_t *builder);

/* CompressedData.version。必填；只接受 0。 */
ASNBER_CMS_API asnber_err_t asnber_cms_compressed_builder_set_version(
    asnber_cms_compressed_builder_t *builder, int64_t version);

/* compressionAlgorithm。必填，重复设置返回 INVALID_STATE。 */
ASNBER_CMS_API asnber_err_t asnber_cms_compressed_builder_set_compression_algorithm(
    asnber_cms_compressed_builder_t *builder, const char *oid,
    const uint8_t *params, size_t params_size);

/* EncapsulatedContentInfo.eContentType。必填，重复设置 INVALID_STATE。 */
ASNBER_CMS_API asnber_err_t asnber_cms_compressed_builder_set_econtent_type(
    asnber_cms_compressed_builder_t *builder, const char *oid);

/*
 * eContent：OCTET STRING 内容字节（不含 tag/len）。可选；不设置即 detached。
 * 允许空内容。重复设置返回 ASNBER_E_INVALID_STATE。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_compressed_builder_set_econtent(
    asnber_cms_compressed_builder_t *builder, const uint8_t *data, size_t size);

/*
 * 组装并编码 ContentInfo（contentType = id-ct-compressedData）。
 * 成功时 out_buf 由上下文分配，调用方用 asnber_buf_release 归还；失败时
 * out_buf 清零且不产出半成品。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_compressed_builder_encode(
    const asnber_cms_compressed_builder_t *builder, asnber_buf_t *out_buf);


#ifdef __cplusplus
}
#endif

#endif /* ASNBER_CMS_COMPRESSED_BUILDER_H_INCLUDED */
