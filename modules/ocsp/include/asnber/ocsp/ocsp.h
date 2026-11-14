/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-ocsp 公共头文件（RFC 6960 只读结构访问）。
 *
 * 只读语义：不验签，不判断证书状态，不解释扩展。response 的 OCTET STRING
 * 不会在打开 OCSPResponse 时自动解成 BasicOCSPResponse。调用方把
 * asnber_ocsp_response_bytes 给出的内容字节交给 asnber_ocsp_basic_open；
 * 打开基本响应时不核对 responseType。
 *
 * 生命周期：句柄由 open 创建、close 销毁；内部文档与 schema 随句柄创建
 * 和销毁。句柄借用调用方的 asnber_ctx_t，ctx 必须比句柄存活更久。所有由
 * 访问器返回的指针均借用句柄，close 后立即失效。close(NULL) 为空操作。
 */

#ifndef ASNBER_OCSP_OCSP_H_INCLUDED
#define ASNBER_OCSP_OCSP_H_INCLUDED

/* 由 CMake 从 project(asnber-ocsp VERSION ...) 生成，源码树中不手写版本宏。 */
#include <asnber/ocsp/ocsp_version.h>

#include <stddef.h>
#include <stdint.h>

#include <asnber/asnber_build.h>
#include <asnber/asnber_node.h>

#if defined(ASNBER_OCSP_STATIC)
#define ASNBER_OCSP_API
#elif defined(_WIN32) || defined(__CYGWIN__)
#if defined(ASNBER_OCSP_BUILDING_LIBRARY)
#define ASNBER_OCSP_API __declspec(dllexport)
#else
#define ASNBER_OCSP_API __declspec(dllimport)
#endif
#elif defined(__GNUC__) && __GNUC__ >= 4
#define ASNBER_OCSP_API __attribute__((visibility("default")))
#else
#define ASNBER_OCSP_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* 不透明句柄；具体布局属于模块私有实现。 */
typedef struct asnber_ocsp_request asnber_ocsp_request_t;
typedef struct asnber_ocsp_response asnber_ocsp_response_t;
typedef struct asnber_ocsp_basic asnber_ocsp_basic_t;

/* 返回模块版本字符串；静态存储，调用方不得释放。 */
ASNBER_OCSP_API const char *asnber_ocsp_version_string(void);

/*
 * 打开一条 DER 编码的 OCSPRequest。输入被复制进文档 arena。
 * 成功时 *out_request 非 NULL；失败时 *out_request 置 NULL。
 * 空参或 der_size == 0 返回 ASNBER_E_INVALID_ARG。
 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_request_open(
    asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asnber_ocsp_request_t **out_request);

/* 关闭请求句柄；request == NULL 为空操作。 */
ASNBER_OCSP_API void asnber_ocsp_request_close(asnber_ocsp_request_t *request);

/*
 * tbsRequest.version。字段缺省时返回 0（DEFAULT v1），不要求线上有 [0]。
 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_request_version(
    const asnber_ocsp_request_t *request, uint32_t *out_version);

/* requestList 条数。 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_request_count(
    const asnber_ocsp_request_t *request, size_t *out_count);

/*
 * 按下标读取 CertID。hash 参数缺省时 *out_params_present = 0，参数指针为空。
 * 越界返回 ASNBER_E_INVALID_ARG。序列号是严格十进制文本，借用句柄。
 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_request_cert_id(
    const asnber_ocsp_request_t *request, size_t index,
    const char **out_hash_oid, size_t *out_hash_oid_size,
    const uint8_t **out_hash_params, size_t *out_hash_params_size,
    int *out_hash_params_present, const uint8_t **out_name_hash,
    size_t *out_name_hash_size, const uint8_t **out_key_hash,
    size_t *out_key_hash_size, const char **out_serial, size_t *out_serial_size);

/*
 * requestorName 的 GeneralName 原始 DER（含标签和长度，不含外层 [1]）。
 * 缺省时返回 ASNBER_OK，*out_present = 0，数据指针为空。
 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_request_requestor(
    const asnber_ocsp_request_t *request, const uint8_t **out_data,
    size_t *out_size, int *out_present);

/* requestExtensions 条数；字段缺省时为 0。 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_request_extension_count(
    const asnber_ocsp_request_t *request, size_t *out_count);

/*
 * 按下标读取请求扩展。extnValue 是 OCTET STRING 内容（内层 DER），借用句柄。
 * critical 缺省时 *out_critical = 0。越界返回 ASNBER_E_INVALID_ARG。
 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_request_extension_at(
    const asnber_ocsp_request_t *request, size_t index, const char **out_oid,
    size_t *out_oid_size, int *out_critical, const uint8_t **out_value,
    size_t *out_value_size);

/* 某条 Request 的 singleRequestExtensions 条数；缺省时为 0。记录越界返回 ASNBER_E_INVALID_ARG。 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_request_single_extension_count(
    const asnber_ocsp_request_t *request, size_t request_index, size_t *out_count);

/* 按下标读取 singleRequestExtensions。语义同 asnber_ocsp_request_extension_at。 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_request_single_extension_at(
    const asnber_ocsp_request_t *request, size_t request_index, size_t index,
    const char **out_oid, size_t *out_oid_size, int *out_critical,
    const uint8_t **out_value, size_t *out_value_size);

/*
 * optionalSignature。缺省时返回 ASNBER_OK，*out_present = 0，其余输出为空。
 * 存在时给出签名算法 OID、parameters 的完整 TLV、签名位串内容，以及 certs 个数。
 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_request_signature(
    const asnber_ocsp_request_t *request, const char **out_oid,
    size_t *out_oid_size, const uint8_t **out_params, size_t *out_params_size,
    int *out_params_present, const uint8_t **out_bits, size_t *out_bits_size,
    size_t *out_bit_length, uint8_t *out_unused_bits, size_t *out_cert_count,
    int *out_present);

/*
 * optionalSignature.certs 中一张证书的原始 DER。没有签名、没有 certs 或下标越界
 * 时返回 ASNBER_E_INVALID_ARG。
 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_request_signature_cert(
    const asnber_ocsp_request_t *request, size_t index, const uint8_t **out_data,
    size_t *out_size);

/*
 * 打开一条 DER 编码的 OCSPResponse。不展开 response 里的内容字节。
 * 空参或 der_size == 0 返回 ASNBER_E_INVALID_ARG。
 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_response_open(
    asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asnber_ocsp_response_t **out_response);

/* 关闭响应句柄；response == NULL 为空操作。 */
ASNBER_OCSP_API void asnber_ocsp_response_close(asnber_ocsp_response_t *response);

/*
 * responseStatus 的枚举值。successful = 0，malformedRequest = 1，
 * internalError = 2，tryLater = 3，sigRequired = 5，unauthorized = 6。
 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_response_status(
    const asnber_ocsp_response_t *response, int64_t *out_status);

/*
 * responseBytes。仅当 responseStatus 为 successful(0) 且字段存在时
 * *out_present = 1，并给出 responseType 的点分 OID 与 response 的内容字节
 * （不含 OCTET STRING 标签）。状态不是 successful，或没有 responseBytes 时，
 * 返回 ASNBER_OK，*out_present = 0，输出为空。模块不判断 OID 是否为
 * id-pkix-ocsp-basic。
 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_response_bytes(
    const asnber_ocsp_response_t *response, const char **out_type_oid,
    size_t *out_type_oid_size, const uint8_t **out_response,
    size_t *out_response_size, int *out_present);

/*
 * 打开一条 DER 编码的 BasicOCSPResponse。输入是 response 的内容字节，
 * 不是外层 OCSPResponse。不核对 responseType。成功时 *out_basic 非 NULL；
 * 失败时 *out_basic 置 NULL。空参或 der_size == 0 返回 ASNBER_E_INVALID_ARG。
 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_open(
    asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asnber_ocsp_basic_t **out_basic);

/* 关闭基本响应句柄；basic == NULL 为空操作。 */
ASNBER_OCSP_API void asnber_ocsp_basic_close(asnber_ocsp_basic_t *basic);

/*
 * version。字段缺省时 *out_version = 0（v1）。值为负或超过 uint32_t
 * 时返回 ASNBER_E_INVALID_VALUE。
 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_version(
    const asnber_ocsp_basic_t *basic, uint32_t *out_version);

/*
 * responderID。*out_choice 为 1 表示 byName，为 2 表示 byKey，与上下文
 * 标签号一致。byName 时 *out_name 是 Name 的完整 TLV（不含外层 [1]），
 * *out_key 为空。byKey 时 *out_key 是 KeyHash 的内容字节，*out_name 为空。
 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_responder(
    const asnber_ocsp_basic_t *basic, int *out_choice, const uint8_t **out_name,
    size_t *out_name_size, const uint8_t **out_key, size_t *out_key_size);

/* producedAt。调用方无需预先填写 struct_size。 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_produced_at(
    const asnber_ocsp_basic_t *basic, asnber_time_t *out_time);

/* responses 中的 SingleResponse 条数。 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_response_count(
    const asnber_ocsp_basic_t *basic, size_t *out_count);

/*
 * 第 index 条 SingleResponse 的 CertID。越界返回 ASNBER_E_INVALID_ARG。
 * 哈希参数是 AlgorithmIdentifier.parameters 的完整 TLV。序列号是十进制文本。
 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_cert_id(
    const asnber_ocsp_basic_t *basic, size_t index, const char **out_hash_oid,
    size_t *out_hash_oid_size, const uint8_t **out_hash_params,
    size_t *out_hash_params_size, int *out_hash_params_present,
    const uint8_t **out_name_hash, size_t *out_name_hash_size,
    const uint8_t **out_key_hash, size_t *out_key_hash_size,
    const char **out_serial, size_t *out_serial_size);

/*
 * certStatus。*out_status 为 0 表示 good，1 表示 revoked，2 表示 unknown，
 * 与上下文标签号一致。越界返回 ASNBER_E_INVALID_ARG。
 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_cert_status(
    const asnber_ocsp_basic_t *basic, size_t index, int *out_status);

/*
 * revoked 的 revocationTime，以及可选的 revocationReason。certStatus
 * 不是 revoked 时返回 ASNBER_E_INVALID_ARG。没有 revocationReason 时
 * *out_reason_present = 0。
 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_revocation(
    const asnber_ocsp_basic_t *basic, size_t index, asnber_time_t *out_time,
    int64_t *out_reason, int *out_reason_present);

/* thisUpdate。调用方无需预先填写 struct_size。 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_this_update(
    const asnber_ocsp_basic_t *basic, size_t index, asnber_time_t *out_time);

/*
 * nextUpdate。字段缺省时返回 ASNBER_OK，*out_present = 0。
 * 调用方无需预先填写 struct_size。
 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_next_update(
    const asnber_ocsp_basic_t *basic, size_t index, asnber_time_t *out_time,
    int *out_present);

/* 第 index 条 SingleResponse 的 singleExtensions 个数；缺省为 0。 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_single_extension_count(
    const asnber_ocsp_basic_t *basic, size_t response_index, size_t *out_count);

/*
 * 第 response_index 条 SingleResponse 的第 index 个扩展。
 * extnValue 是 OCTET STRING 的内容字节。critical 缺省为 0。
 * 越界返回 ASNBER_E_INVALID_ARG。
 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_single_extension_at(
    const asnber_ocsp_basic_t *basic, size_t response_index, size_t index,
    const char **out_oid, size_t *out_oid_size, int *out_critical,
    const uint8_t **out_value, size_t *out_value_size);

/* responseExtensions 个数；缺省为 0。 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_extension_count(
    const asnber_ocsp_basic_t *basic, size_t *out_count);

/* responseExtensions 的第 index 个扩展。越界返回 ASNBER_E_INVALID_ARG。 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_extension_at(
    const asnber_ocsp_basic_t *basic, size_t index, const char **out_oid,
    size_t *out_oid_size, int *out_critical, const uint8_t **out_value,
    size_t *out_value_size);

/*
 * signatureAlgorithm 与 signature。证书个数写入 *out_cert_count，没有
 * certs 时为 0。哈希参数是 parameters 的完整 TLV。
 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_signature(
    const asnber_ocsp_basic_t *basic, const char **out_oid, size_t *out_oid_size,
    const uint8_t **out_params, size_t *out_params_size, int *out_params_present,
    const uint8_t **out_bits, size_t *out_bits_size, size_t *out_bit_length,
    uint8_t *out_unused_bits, size_t *out_cert_count);

/*
 * certs 中第 index 张证书的完整 DER。没有 certs 或越界返回
 * ASNBER_E_INVALID_ARG。
 */
ASNBER_OCSP_API asnber_err_t asnber_ocsp_basic_signature_cert(
    const asnber_ocsp_basic_t *basic, size_t index, const uint8_t **out_data,
    size_t *out_size);

#ifdef __cplusplus
}
#endif

#endif /* ASNBER_OCSP_OCSP_H_INCLUDED */
