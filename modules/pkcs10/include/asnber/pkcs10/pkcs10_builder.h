/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-pkcs10 构造接口：CertificationRequest（RFC 2986）。
 *
 * CertificationRequest ::= SEQUENCE {
 *     certificationRequestInfo CertificationRequestInfo,
 *     signatureAlgorithm       AlgorithmIdentifier,
 *     signature                BIT STRING }
 *
 * CertificationRequestInfo ::= SEQUENCE {
 *     version        INTEGER,
 *     subject        Name,
 *     subjectPKInfo  SubjectPublicKeyInfo,
 *     attributes [0] IMPLICIT SET OF Attribute }
 *
 * 构造侧只做结构组装：不签名、不验签，不解析 subjectPKInfo 内部密钥，
 * 也不解释 Attribute / Extension 的语义。所有输入在 set/add 时深拷贝，
 * 调用方可在返回后释放原缓冲。
 */

#ifndef ASNBER_PKCS10_PKCS10_BUILDER_H_INCLUDED
#define ASNBER_PKCS10_PKCS10_BUILDER_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include <asnber/asnber_encode.h>
#include <asnber/pkcs10/pkcs10.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 不透明 builder 句柄；布局属于模块私有实现。 */
typedef struct asnber_pkcs_certification_request_builder
    asnber_pkcs_certification_request_builder_t;

/*
 * 一个 RDN 属性。string_tag 为 0 时按 OID 选择字符串类型（C/serialNumber/
 * dnQualifier -> PrintableString，DC/emailAddress -> IA5String，其余
 * UTF8String）；非 0 时必须显式给出 12/19/22，并按对应字符集校验。
 */
typedef struct asnber_pkcs_name_attribute {
    const char *oid;
    const uint8_t *value; /* 文本字节 */
    size_t value_size;
    uint32_t string_tag;
} asnber_pkcs_name_attribute_t;

/* 一个 RelativeDistinguishedName；count 必须 >= 1。 */
typedef struct asnber_pkcs_name_rdn {
    const asnber_pkcs_name_attribute_t *attributes;
    size_t count;
} asnber_pkcs_name_rdn_t;

/*
 * 创建 builder。builder 借用调用方的 ctx，ctx 必须比 builder 存活更久。
 * 空参返回 ASNBER_E_INVALID_ARG 且 *out_builder = NULL；分配失败返回
 * ASNBER_E_NOMEM。
 */
ASNBER_PKCS10_API asnber_err_t asnber_pkcs_certification_request_builder_create(
    asnber_ctx_t *ctx, asnber_pkcs_certification_request_builder_t **out_builder);

/* 销毁 builder；builder == NULL 为空操作。 */
ASNBER_PKCS10_API void asnber_pkcs_certification_request_builder_destroy(
    asnber_pkcs_certification_request_builder_t *builder);

/*
 * 设置 version（必填，只允许设置一次）。模块不推导、不改写该值。
 * 重复设置返回 ASNBER_E_INVALID_STATE。
 */
ASNBER_PKCS10_API asnber_err_t
asnber_pkcs_certification_request_builder_set_version(
    asnber_pkcs_certification_request_builder_t *builder, int64_t version);

/*
 * 设置 subject（必填，只允许设置一次）。
 *
 * rdns == NULL 且 rdn_count == 0 表示空 Name；否则每个 RDN 必须至少含一个
 * 属性。OID、字符串类型与字符集沿用 Name 编码规则。RDN 之间的顺序保持
 * 调用方数组顺序；RDN 内部的 SET OF 字节序由核心 DER 编码完成。
 * 重复设置返回 ASNBER_E_INVALID_STATE。
 */
ASNBER_PKCS10_API asnber_err_t
asnber_pkcs_certification_request_builder_set_subject(
    asnber_pkcs_certification_request_builder_t *builder,
    const asnber_pkcs_name_rdn_t *rdns, size_t rdn_count);

/*
 * 设置 subjectPKInfo.algorithm（必填，只允许设置一次）。
 *
 * - oid 为点分十进制文本，写入前校验；
 * - parameters_tlv 为完整 DER TLV（含 tag/len）；NULL 且 size 为 0 表示
 *   parameters 缺省；
 * - 重复设置返回 ASNBER_E_INVALID_STATE。
 */
ASNBER_PKCS10_API asnber_err_t
asnber_pkcs_certification_request_builder_set_subject_public_key_algorithm(
    asnber_pkcs_certification_request_builder_t *builder, const char *oid,
    const uint8_t *parameters_tlv, size_t parameters_size);

/*
 * 设置 subjectPKInfo.subjectPublicKey（必填，只允许设置一次）。bits 为位串
 * 字节，unused_bits 为末尾未用位数（0..7）；空位串必须 unused_bits == 0。
 * 重复设置返回 ASNBER_E_INVALID_STATE。
 */
ASNBER_PKCS10_API asnber_err_t
asnber_pkcs_certification_request_builder_set_subject_public_key(
    asnber_pkcs_certification_request_builder_t *builder, const uint8_t *bits,
    size_t size, uint8_t unused_bits);

/*
 * 设置 signatureAlgorithm（必填，只允许设置一次）；参数语义同上。
 */
ASNBER_PKCS10_API asnber_err_t
asnber_pkcs_certification_request_builder_set_signature_algorithm(
    asnber_pkcs_certification_request_builder_t *builder, const char *oid,
    const uint8_t *parameters_tlv, size_t parameters_size);

/*
 * 设置 signature（必填，只允许设置一次）。模块不计算、不改写签名值。
 */
ASNBER_PKCS10_API asnber_err_t
asnber_pkcs_certification_request_builder_set_signature(
    asnber_pkcs_certification_request_builder_t *builder, const uint8_t *bits,
    size_t size, uint8_t unused_bits);

/*
 * 追加一个通用 Attribute：SEQUENCE { type OID, values SET OF ANY }。
 *
 * values 与 value_sizes 一一对应，value_count 必须 >= 1；每个 value 必须是
 * 单个规范 DER TLV。多次调用按调用顺序累积，SET OF 排序由核心编码完成。
 */
ASNBER_PKCS10_API asnber_err_t
asnber_pkcs_certification_request_builder_add_attribute(
    asnber_pkcs_certification_request_builder_t *builder, const char *type_oid,
    const uint8_t *const *values, const size_t *value_sizes,
    size_t value_count);

/*
 * 追加一条扩展，最终合成单个 extensionRequest 属性
 * （1.2.840.113549.1.9.14）。extn_value_der 是 extnValue OCTET STRING 的
 * 内容（内层 DER TLV），必须为非空单个规范 DER TLV。
 *
 * critical 仅 != 0 时写 BOOLEAN TRUE；为 0 时完全省略（DEFAULT FALSE）。
 * 同一 builder 内扩展 OID 不得重复，重复返回 ASNBER_E_INVALID_VALUE。
 */
ASNBER_PKCS10_API asnber_err_t
asnber_pkcs_certification_request_builder_add_extension(
    asnber_pkcs_certification_request_builder_t *builder, const char *extn_oid,
    int critical, const uint8_t *extn_value_der, size_t extn_value_size);

/*
 * 结束并编码。version、subject、subjectPKInfo 算法与位串、signatureAlgorithm、
 * signature 必须都已设置，否则返回 ASNBER_E_INVALID_STATE。成功时 out_buf 由
 * ctx 分配，调用方用 asnber_buf_release 释放；失败时 out_buf 被清零。
 */
ASNBER_PKCS10_API asnber_err_t asnber_pkcs_certification_request_builder_encode(
    const asnber_pkcs_certification_request_builder_t *builder,
    asnber_buf_t *out_buf);

#ifdef __cplusplus
}
#endif

#endif /* ASNBER_PKCS10_PKCS10_BUILDER_H_INCLUDED */
