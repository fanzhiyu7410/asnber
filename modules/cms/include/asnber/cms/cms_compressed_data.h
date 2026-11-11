/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-cms 公共子头文件：CompressedData（RFC 3274 第 2 节）只读访问。
 */

#ifndef ASNBER_CMS_COMPRESSED_DATA_H_INCLUDED
#define ASNBER_CMS_COMPRESSED_DATA_H_INCLUDED

#include <asnber/cms/cms_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* CompressedData（RFC 3274 第 2 节，只读）                                    */
/* ------------------------------------------------------------------------- */

/*
 * 打开 DER 编码的 CompressedData（**不含外层 ContentInfo**）。调用方先用
 * asnber_cms_content_info_open + asnber_cms_content_info_content 取 `[0]` 内层
 * TLV，再传入本函数；模块不提供自动剥壳入口。
 *
 * 只读结构访问：不解压、不展开压缩算法参数或 eContent 内容。version 原样
 * 返回，不在此处校验 RFC 3274 的 version 0 语义。读侧不启用
 * ASNBER_DECODE_STRICT_SCHEMA：错标签按未知字段静默忽略，根 SEQUENCE 之后的
 * 尾随数据返回 ASNBER_E_TRAILING_DATA（与 AuthenticatedData 一致）。
 *
 * 指针所有权：所有 `*_tlv` / 字符串 / 字节访问器返回的指针都**借用**
 * 句柄内部的输入缓冲区，不复制、不需释放；`close` 后一律失效。
 * 对同一句柄重复调用 `close` 属未定义行为。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_compressed_data_open(
    asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asnber_cms_compressed_data_t **out_compressed_data);

ASNBER_CMS_API void asnber_cms_compressed_data_close(
    asnber_cms_compressed_data_t *compressed_data);

/* version：原样返回 CMSVersion 整数值，不做范围校验。 */
ASNBER_CMS_API asnber_err_t asnber_cms_compressed_data_version(
    const asnber_cms_compressed_data_t *compressed_data, int64_t *out_version);

/* compressionAlgorithm：OID + parameters TLV（缺省时 NULL/0）。 */
ASNBER_CMS_API asnber_err_t asnber_cms_compressed_data_compression_algorithm(
    const asnber_cms_compressed_data_t *compressed_data, const char **out_oid,
    size_t *out_oid_size, const uint8_t **out_parameters,
    size_t *out_parameters_size);

/* EncapsulatedContentInfo.eContentType：OID 点分文本。 */
ASNBER_CMS_API asnber_err_t asnber_cms_compressed_data_econtent_type(
    const asnber_cms_compressed_data_t *compressed_data, const char **out_oid,
    size_t *out_oid_size);

/*
 * eContent 内容字节（不含 tag/len）。字段缺省（detached）返回 ASNBER_OK 且
 * NULL/0；空内容返回非 NULL、size 0。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_compressed_data_econtent(
    const asnber_cms_compressed_data_t *compressed_data, const uint8_t **out_data,
    size_t *out_size);

/* eContent 内层 OCTET STRING 的完整原始 TLV（不含外层 `[0]` 包装）；缺省 NULL/0。 */
ASNBER_CMS_API asnber_err_t asnber_cms_compressed_data_econtent_tlv(
    const asnber_cms_compressed_data_t *compressed_data, const uint8_t **out_data,
    size_t *out_size);


#ifdef __cplusplus
}
#endif

#endif /* ASNBER_CMS_COMPRESSED_DATA_H_INCLUDED */
