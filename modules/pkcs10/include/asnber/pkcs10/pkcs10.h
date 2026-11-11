/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-pkcs10 公共头文件（RFC 2986 只读结构访问）。
 *
 * 只读语义：不验证 signatureValue，不对 certificationRequestInfo 做任何
 * 密码学处理，也不解析 SPKI 内部的密钥；开放类型只返回完整原始 TLV。
 *
 * 生命周期：句柄由 open 创建、close 销毁；内部文档与 schema 随句柄创建
 * 和销毁。句柄借用调用方的 asnber_ctx_t，ctx 必须比句柄存活更久。所有由
 * 访问器返回的指针均借用句柄，close 后立即失效。
 */

#ifndef ASNBER_PKCS10_PKCS10_H_INCLUDED
#define ASNBER_PKCS10_PKCS10_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include <asnber/asnber_build.h>
#include <asnber/asnber_node.h>

#if defined(ASNBER_PKCS10_STATIC)
#define ASNBER_PKCS10_API
#elif defined(_WIN32) || defined(__CYGWIN__)
#if defined(ASNBER_PKCS10_BUILDING_LIBRARY)
#define ASNBER_PKCS10_API __declspec(dllexport)
#else
#define ASNBER_PKCS10_API __declspec(dllimport)
#endif
#elif defined(__GNUC__) && __GNUC__ >= 4
#define ASNBER_PKCS10_API __attribute__((visibility("default")))
#else
#define ASNBER_PKCS10_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* 不透明句柄；具体布局属于模块私有实现。 */
typedef struct asnber_pkcs_certification_request
    asnber_pkcs_certification_request_t;

/*
 * 打开 DER 编码的 CertificationRequest。
 *
 * 只读结构：不验证 signatureValue，也不对 certificationRequestInfo 做任何
 * 密码学处理；attributes 只按通用结构给出类型 OID 与 ANY 值节点。
 */
ASNBER_PKCS10_API asnber_err_t asnber_pkcs_certification_request_open(
    asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asnber_pkcs_certification_request_t **out_request);

/* 关闭句柄；request == NULL 为空操作。 */
ASNBER_PKCS10_API void asnber_pkcs_certification_request_close(
    asnber_pkcs_certification_request_t *request);

/*
 * certificationRequestInfo.version。
 *
 * RFC 2986 只定义 v1 = 0；非 0 属不常见但合法的 DER 输入，不应视为错误。
 * 本函数采取“返回成功、原样给出值”：不做范围校验，也不把非 0 静默改写
 * 为 0；调用方需要判断 v1 时自行比较 *out_version == 0。模块不为此发
 * 告警（核心未提供模块侧告警写入接口），也不额外引入错误码。
 */
ASNBER_PKCS10_API asnber_err_t asnber_pkcs_certification_request_version(
    const asnber_pkcs_certification_request_t *request,
    int64_t *out_version);

/* certificationRequestInfo.subject 完整 DER TLV（借用句柄）。 */
ASNBER_PKCS10_API asnber_err_t asnber_pkcs_certification_request_subject_der(
    const asnber_pkcs_certification_request_t *request, const uint8_t **out_data,
    size_t *out_size);

/* subjectPKInfo.algorithm.algorithm：OID 点分十进制文本（借用句柄）。 */
ASNBER_PKCS10_API asnber_err_t
asnber_pkcs_certification_request_subject_public_key_algorithm_oid(
    const asnber_pkcs_certification_request_t *request, const char **out_dotted,
    size_t *out_size);

/* subjectPKInfo.algorithm.parameters：ANY 原始 TLV；缺省返回 NULL/0。 */
ASNBER_PKCS10_API asnber_err_t
asnber_pkcs_certification_request_subject_public_key_algorithm_parameters(
    const asnber_pkcs_certification_request_t *request,
    const uint8_t **out_data, size_t *out_size);

/* subjectPKInfo.subjectPublicKey：BIT STRING 位字节（借用句柄）。 */
ASNBER_PKCS10_API asnber_err_t
asnber_pkcs_certification_request_subject_public_key(
    const asnber_pkcs_certification_request_t *request,
    const uint8_t **out_data, size_t *out_size);

/* subjectPKInfo.subjectPublicKey 字段完整 TLV（借用句柄）。 */
ASNBER_PKCS10_API asnber_err_t
asnber_pkcs_certification_request_subject_public_key_tlv(
    const asnber_pkcs_certification_request_t *request,
    const uint8_t **out_data, size_t *out_size);

/* certificationRequestInfo.attributes 中的属性个数；空集合为 0。 */
ASNBER_PKCS10_API asnber_err_t asnber_pkcs_certification_request_attribute_count(
    const asnber_pkcs_certification_request_t *request, size_t *out_count);

/*
 * 按下标访问 Attribute：type OID 点分十进制 + values（SET OF ANY）借用节点。
 * index 越界返回 ASNBER_E_INVALID_ARG。
 */
ASNBER_PKCS10_API asnber_err_t asnber_pkcs_certification_request_attribute_at(
    const asnber_pkcs_certification_request_t *request, size_t index,
    const char **out_type_oid, size_t *out_type_oid_size,
    const asnber_node_t **out_values);

/* signatureAlgorithm.algorithm：OID 点分十进制文本（借用句柄）。 */
ASNBER_PKCS10_API asnber_err_t
asnber_pkcs_certification_request_signature_algorithm_oid(
    const asnber_pkcs_certification_request_t *request, const char **out_dotted,
    size_t *out_size);

/* signatureAlgorithm.parameters：ANY 原始 TLV；缺省返回 NULL/0。 */
ASNBER_PKCS10_API asnber_err_t
asnber_pkcs_certification_request_signature_algorithm_parameters(
    const asnber_pkcs_certification_request_t *request,
    const uint8_t **out_data, size_t *out_size);

/* signature：BIT STRING 位字节（借用于句柄，不解码、不验签）。 */
ASNBER_PKCS10_API asnber_err_t asnber_pkcs_certification_request_signature_value(
    const asnber_pkcs_certification_request_t *request,
    const uint8_t **out_data, size_t *out_size);

/* signature 字段完整 TLV（借用句柄）。 */
ASNBER_PKCS10_API asnber_err_t
asnber_pkcs_certification_request_signature_value_tlv(
    const asnber_pkcs_certification_request_t *request,
    const uint8_t **out_data, size_t *out_size);

#ifdef __cplusplus
}
#endif

/* 构造接口单列一个子头，读写两侧可分别包含。 */
#include <asnber/pkcs10/pkcs10_builder.h>

#endif /* ASNBER_PKCS10_PKCS10_H_INCLUDED */
