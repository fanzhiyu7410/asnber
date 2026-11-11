/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-pkix 构造接口：X.509 Certificate / TBSCertificate（RFC 5280）。
 *
 * Certificate ::= SEQUENCE {
 *     tbsCertificate       TBSCertificate,
 *     signatureAlgorithm   AlgorithmIdentifier,
 *     signatureValue       BIT STRING }
 *
 * 构造侧只做结构组装：不签名、不验签，不解释扩展语义。所有输入在 set/add
 * 时深拷贝，调用方可在返回后释放原缓冲。
 */

#ifndef ASNBER_PKIX_PKIX_BUILDER_H_INCLUDED
#define ASNBER_PKIX_PKIX_BUILDER_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include <asnber/asnber_features.h>
#include <asnber/asnber_encode.h>
#include <asnber/pkix/pkix.h>

#ifdef __cplusplus
extern "C" {
#endif

#if ASNBER_FEATURE_PKIX_BUILDER && ASNBER_FEATURE_ENCODE && ASNBER_FEATURE_BUILD_API
/* 不透明 builder 句柄；布局属于模块私有实现。 */
typedef struct asnber_pkix_certificate_builder asnber_pkix_certificate_builder_t;

/* 一个 RDN 属性；string_tag 为 0 时按 OID 选择字符串类型。 */
typedef struct asnber_pkix_name_attribute {
    const char *oid;
    const uint8_t *value;
    size_t value_size;
    uint32_t string_tag;
} asnber_pkix_name_attribute_t;

/* 一个 RelativeDistinguishedName；count 必须 >= 1。 */
typedef struct asnber_pkix_name_rdn {
    const asnber_pkix_name_attribute_t *attributes;
    size_t count;
} asnber_pkix_name_rdn_t;

/*
 * 创建 builder。builder 借用调用方的 ctx，ctx 必须比 builder 存活更久。
 * 空参返回 ASNBER_E_INVALID_ARG 且 *out_builder = NULL；分配失败返回
 * ASNBER_E_NOMEM。
 */
ASNBER_PKIX_API asnber_err_t asnber_pkix_certificate_builder_create(
    asnber_ctx_t *ctx, asnber_pkix_certificate_builder_t **out_builder);

/* 销毁 builder；builder == NULL 为空操作。 */
ASNBER_PKIX_API void asnber_pkix_certificate_builder_destroy(
    asnber_pkix_certificate_builder_t *builder);

/*
 * 设置 version（可选，只允许设置一次）。仅接受 0/1/2；0（v1）与未设置都
 * 按 DEFAULT v1 完全省略 [0] EXPLICIT 包装。越界返回 ASNBER_E_INVALID_ARG。
 */
ASNBER_PKIX_API asnber_err_t asnber_pkix_certificate_builder_set_version(
    asnber_pkix_certificate_builder_t *builder, int64_t version);

/*
 * 设置 serialNumber（必填，只允许设置一次）。magnitude 为无符号大端幅值，
 * 由共享层规范化为正数 DER INTEGER（去前导零、必要时补 0x00）。
 */
ASNBER_PKIX_API asnber_err_t asnber_pkix_certificate_builder_set_serial_number(
    asnber_pkix_certificate_builder_t *builder, const uint8_t *magnitude,
    size_t size);

/*
 * 设置签名算法（必填，只允许设置一次）。同一算法同时写入
 * tbsCertificate.signature 与 Certificate.signatureAlgorithm；parameters_tlv
 * 为完整 DER TLV，NULL/0 表示缺省。
 */
ASNBER_PKIX_API asnber_err_t asnber_pkix_certificate_builder_set_signature_algorithm(
    asnber_pkix_certificate_builder_t *builder, const char *oid,
    const uint8_t *parameters_tlv, size_t parameters_size);

/*
 * 设置 issuer（必填，只允许设置一次）。rdns == NULL 且 rdn_count == 0
 * 表示空 Name；RDN 内部 SET OF 排序由核心 DER 编码完成。
 */
ASNBER_PKIX_API asnber_err_t asnber_pkix_certificate_builder_set_issuer(
    asnber_pkix_certificate_builder_t *builder,
    const asnber_pkix_name_rdn_t *rdns, size_t rdn_count);

/*
 * 设置 validity（必填，只允许设置一次）。两个时间沿用 P3 规则：1950..2049
 * 用 UTCTime，其余用 GeneralizedTime；拒绝偏移/本地时间/小数秒。
 */
ASNBER_PKIX_API asnber_err_t asnber_pkix_certificate_builder_set_validity(
    asnber_pkix_certificate_builder_t *builder,
    const asnber_time_t *not_before, const asnber_time_t *not_after);

/* 设置 subject（必填，只允许设置一次）；语义同 set_issuer。 */
ASNBER_PKIX_API asnber_err_t asnber_pkix_certificate_builder_set_subject(
    asnber_pkix_certificate_builder_t *builder,
    const asnber_pkix_name_rdn_t *rdns, size_t rdn_count);

/* 设置 subjectPublicKeyInfo.algorithm（必填，只允许设置一次）。 */
ASNBER_PKIX_API asnber_err_t
asnber_pkix_certificate_builder_set_subject_public_key_algorithm(
    asnber_pkix_certificate_builder_t *builder, const char *oid,
    const uint8_t *parameters_tlv, size_t parameters_size);

/* 设置 subjectPublicKeyInfo.subjectPublicKey（必填，只允许设置一次）。 */
ASNBER_PKIX_API asnber_err_t
asnber_pkix_certificate_builder_set_subject_public_key(
    asnber_pkix_certificate_builder_t *builder, const uint8_t *bits,
    size_t size, uint8_t unused_bits);

/* 设置 issuerUniqueID（可选，只允许设置一次，[1] IMPLICIT BIT STRING）。 */
ASNBER_PKIX_API asnber_err_t asnber_pkix_certificate_builder_set_issuer_unique_id(
    asnber_pkix_certificate_builder_t *builder, const uint8_t *bits,
    size_t size, uint8_t unused_bits);

/* 设置 subjectUniqueID（可选，只允许设置一次，[2] IMPLICIT BIT STRING）。 */
ASNBER_PKIX_API asnber_err_t asnber_pkix_certificate_builder_set_subject_unique_id(
    asnber_pkix_certificate_builder_t *builder, const uint8_t *bits,
    size_t size, uint8_t unused_bits);

/*
 * 追加一条通用扩展。extn_value_der 是 extnValue OCTET STRING 的内容（内层
 * DER TLV），必须为非空单个规范 DER TLV。critical 仅在 != 0 时写 BOOLEAN
 * TRUE；同一 builder 内扩展 OID 不得重复。
 */
ASNBER_PKIX_API asnber_err_t asnber_pkix_certificate_builder_add_extension(
    asnber_pkix_certificate_builder_t *builder, const char *extn_oid,
    int critical, const uint8_t *extn_value_der, size_t extn_value_size);

/*
 * 便捷扩展：BasicConstraints（2.5.29.19）。
 *
 * - is_ca != 0 时写 BOOLEAN TRUE；
 * - pathLenConstraint 仅在 is_ca != 0 且 has_path_len != 0 时写入；
 *   is_ca == 0 且 has_path_len != 0 返回 ASNBER_E_INVALID_VALUE；
 * - critical == 0 时完全省略 BOOLEAN。
 */
ASNBER_PKIX_API asnber_err_t asnber_pkix_certificate_builder_add_basic_constraints(
    asnber_pkix_certificate_builder_t *builder, int critical, int is_ca,
    int has_path_len, uint32_t path_len);

/* 便捷扩展：KeyUsage（2.5.29.15），把位串包成 extnValue。 */
ASNBER_PKIX_API asnber_err_t asnber_pkix_certificate_builder_add_key_usage(
    asnber_pkix_certificate_builder_t *builder, int critical,
    const uint8_t *bits, size_t size, uint8_t unused_bits);

/* 便捷扩展：ExtendedKeyUsage（2.5.29.37），SEQUENCE OF OID。 */
ASNBER_PKIX_API asnber_err_t
asnber_pkix_certificate_builder_add_extended_key_usage(
    asnber_pkix_certificate_builder_t *builder, int critical,
    const char *const *oids, size_t count);

/* 设置 signatureValue（必填，只允许设置一次）；模块不计算、不改写签名值。 */
ASNBER_PKIX_API asnber_err_t asnber_pkix_certificate_builder_set_signature_value(
    asnber_pkix_certificate_builder_t *builder, const uint8_t *bits,
    size_t size, uint8_t unused_bits);

/*
 * 结束并编码。serialNumber、签名算法、issuer、validity、subject、
 * subjectPublicKeyInfo 与 signatureValue 必须已设置，否则返回
 * ASNBER_E_INVALID_STATE。成功时 out_buf 由 ctx 分配，调用方用
 * asnber_buf_release 释放；失败时 out_buf 被清零。
 */
ASNBER_PKIX_API asnber_err_t asnber_pkix_certificate_builder_encode(
    const asnber_pkix_certificate_builder_t *builder, asnber_buf_t *out_buf);

/*
 * CertificateList 结构组装。不签名、不决定吊销。issuer 复用证书侧的
 * RDN 结构。version 只接受 0（省略，v1）与 1（写出 INTEGER 1，v2）。
 * 吊销项只写 userCertificate 与 revocationDate，不写条目扩展。
 */
typedef struct asnber_pkix_crl_builder asnber_pkix_crl_builder_t;

ASNBER_PKIX_API asnber_err_t asnber_pkix_crl_builder_create(
    asnber_ctx_t *ctx, asnber_pkix_crl_builder_t **out_builder);
ASNBER_PKIX_API void asnber_pkix_crl_builder_destroy(
    asnber_pkix_crl_builder_t *builder);

/* 只允许设置一次。0 省略 version，1 写出 v2；其他值返回 ASNBER_E_INVALID_VALUE。 */
ASNBER_PKIX_API asnber_err_t asnber_pkix_crl_builder_set_version(
    asnber_pkix_crl_builder_t *builder, int64_t version);

/* 同一算法写入 TBSCertList.signature 与外层 algorithmIdentifier。 */
ASNBER_PKIX_API asnber_err_t asnber_pkix_crl_builder_set_signature_algorithm(
    asnber_pkix_crl_builder_t *builder, const char *oid,
    const uint8_t *parameters_tlv, size_t parameters_size);

/* issuer（必填，只允许设置一次）。空 Name 用 rdn_count == 0。 */
ASNBER_PKIX_API asnber_err_t asnber_pkix_crl_builder_set_issuer(
    asnber_pkix_crl_builder_t *builder, const asnber_pkix_name_rdn_t *rdns,
    size_t rdn_count);

ASNBER_PKIX_API asnber_err_t asnber_pkix_crl_builder_set_this_update(
    asnber_pkix_crl_builder_t *builder, const asnber_time_t *time);
ASNBER_PKIX_API asnber_err_t asnber_pkix_crl_builder_set_next_update(
    asnber_pkix_crl_builder_t *builder, const asnber_time_t *time);

/*
 * 追加一条吊销记录。serial 为无符号大端幅值。可多次调用。
 * 不写 crlEntryExtensions。
 */
ASNBER_PKIX_API asnber_err_t asnber_pkix_crl_builder_add_revoked(
    asnber_pkix_crl_builder_t *builder, const uint8_t *serial, size_t serial_size,
    const asnber_time_t *revocation_date);

/* 外层 signature BIT STRING。模块不计算签名。 */
ASNBER_PKIX_API asnber_err_t asnber_pkix_crl_builder_set_signature_value(
    asnber_pkix_crl_builder_t *builder, const uint8_t *bits, size_t size,
    uint8_t unused_bits);

/*
 * 签名算法、issuer、thisUpdate、signatureValue 必须已设置，否则返回
 * ASNBER_E_INVALID_STATE。成功时 out_buf 由 ctx 分配。
 */
ASNBER_PKIX_API asnber_err_t asnber_pkix_crl_builder_encode(
    const asnber_pkix_crl_builder_t *builder, asnber_buf_t *out_buf);
#endif

#ifdef __cplusplus
}
#endif

#endif /* ASNBER_PKIX_PKIX_BUILDER_H_INCLUDED */
