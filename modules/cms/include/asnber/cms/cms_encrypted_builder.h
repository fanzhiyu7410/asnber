/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-cms 公共子头文件：EncryptedData 构造（写）。
 */

#ifndef ASNBER_CMS_ENCRYPTED_BUILDER_H_INCLUDED
#define ASNBER_CMS_ENCRYPTED_BUILDER_H_INCLUDED

#include <asnber/cms/cms_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* 结构构造（写）：EncryptedData builder                                       */
/* ------------------------------------------------------------------------- */

/*
 * 只做结构构造与 DER 编码：内容类型、算法 OID、加密后的内容与属性集合全部
 * 由调用方给值，模块原样承载。不做内容加密/解密、MAC 计算、密钥派生、
 * 时间与随机数生成。
 *
 * 与 EnvelopedData builder 相同：
 * - 算法 parameters 为空表示缺省，否则必须是完整规范 DER TLV；
 * - 所有输入字节在调用返回时已复制，调用方可立即释放原缓冲。
 *
 * 组合约束：
 * - version / contentType / contentEncryptionAlgorithm 必填；
 * - set_version 只接受 0 / 2，其他值立即返回 ASNBER_E_INVALID_VALUE；
 * - encode 检查配对：无 unprotectedAttrs 时 version 必须为 0，带该字段时
 *   必须为 2；不一致返回 ASNBER_E_INVALID_VALUE，模块不改写 version；
 * - encryptedContent 可缺省，表示 detached 形式；
 * - 每个单值字段只允许设置一次，重复设置返回 ASNBER_E_INVALID_STATE。
 *
 * 生命周期与 destroy 契约同 EnvelopedData builder：destroy(NULL) 为空操作；
 * 同一句柄只能 destroy 一次。
 */

typedef struct asnber_cms_encrypted_builder asnber_cms_encrypted_builder_t;

ASNBER_CMS_API asnber_err_t asnber_cms_encrypted_builder_create(
    asnber_ctx_t *ctx, asnber_cms_encrypted_builder_t **out_builder);

ASNBER_CMS_API void asnber_cms_encrypted_builder_destroy(
    asnber_cms_encrypted_builder_t *builder);

/*
 * EncryptedData.version。必填；只接受 0 / 2，其他值返回
 * ASNBER_E_INVALID_VALUE；重复设置返回 ASNBER_E_INVALID_STATE。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_encrypted_builder_set_version(
    asnber_cms_encrypted_builder_t *builder, int64_t version);

/* EncryptedContentInfo.contentType。必填，重复设置返回 INVALID_STATE。 */
ASNBER_CMS_API asnber_err_t asnber_cms_encrypted_builder_set_content_type(
    asnber_cms_encrypted_builder_t *builder, const char *oid);

/* EncryptedContentInfo.contentEncryptionAlgorithm。必填，重复设置 INVALID_STATE。 */
ASNBER_CMS_API asnber_err_t
asnber_cms_encrypted_builder_set_content_encryption_algorithm(
    asnber_cms_encrypted_builder_t *builder, const char *oid,
    const uint8_t *params, size_t params_size);

/*
 * EncryptedContentInfo.encryptedContent：OCTET STRING 内容字节（不含
 * tag/len）。可选；不设置即 detached。允许空内容（编码为 `80 00`），
 * 重复设置返回 ASNBER_E_INVALID_STATE。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_encrypted_builder_set_encrypted_content(
    asnber_cms_encrypted_builder_t *builder, const uint8_t *data, size_t size);

/*
 * unprotectedAttrs：完整、非空 `SET OF Attribute`（外层 0x31，元素为
 * SEQUENCE）。模块把外层标签改写为 0xA1（`[1] IMPLICIT`），长度与内容
 * 逐字节不变。设置该字段时 version 必须为 2。
 * 可选，重复设置返回 ASNBER_E_INVALID_STATE。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_encrypted_builder_set_unprotected_attrs(
    asnber_cms_encrypted_builder_t *builder, const uint8_t *tlv,
    size_t tlv_size);

/*
 * 组装并编码 ContentInfo（contentType = id-encryptedData）。
 * 成功时 out_buf 由上下文分配，调用方用 asnber_buf_release 归还；失败时
 * out_buf 清零且不产出半成品。
 */
ASNBER_CMS_API asnber_err_t asnber_cms_encrypted_builder_encode(
    const asnber_cms_encrypted_builder_t *builder, asnber_buf_t *out_buf);


#ifdef __cplusplus
}
#endif

#endif /* ASNBER_CMS_ENCRYPTED_BUILDER_H_INCLUDED */
