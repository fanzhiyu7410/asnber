/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-pkix 公共头文件。
 *
 * 本模块承载 RFC 5912（PKIX1Explicit-2009 / PKIX1Implicit-2009 /
 * PKIX-CommonTypes-2009）展平模块生成的描述表与证书字段访问 API。
 * 来源、勘误与更新链见 docs/11-描述表格式.md 第 15 节；模块只依赖
 * 核心公共 C ABI，不包含核心私有头，也不复制核心解析逻辑。
 *
 * 生命周期：asnber_pkix_certificate_t 由 open 创建、close 销毁；内部文档与
 * schema 随句柄创建和销毁。句柄借用调用方的 asnber_ctx_t，ctx 必须比句柄
 * 存活更久。所有由访问器返回的指针均借用句柄，close 后立即失效。
 */

#ifndef ASNBER_PKIX_PKIX_H_INCLUDED
#define ASNBER_PKIX_PKIX_H_INCLUDED

/* 由 CMake 从 project(asnber-pkix VERSION ...) 生成，源码树中不手写版本宏。 */
#include <asnber/pkix/pkix_version.h>

#include <stddef.h>
#include <stdint.h>

#include <asnber/asnber_allocator.h>
#include <asnber/asnber_build.h>
#include <asnber/asnber_node.h>

#if defined(ASNBER_PKIX_STATIC)
#define ASNBER_PKIX_API
#elif defined(_WIN32) || defined(__CYGWIN__)
#if defined(ASNBER_PKIX_BUILDING_LIBRARY)
#define ASNBER_PKIX_API __declspec(dllexport)
#else
#define ASNBER_PKIX_API __declspec(dllimport)
#endif
#elif defined(__GNUC__) && __GNUC__ >= 4
#define ASNBER_PKIX_API __attribute__((visibility("default")))
#else
#define ASNBER_PKIX_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* 不透明证书句柄；具体布局属于模块私有实现。 */
typedef struct asnber_pkix_certificate asnber_pkix_certificate_t;

/* 返回模块版本字符串；静态存储，调用方不得释放。 */
ASNBER_PKIX_API const char *asnber_pkix_version_string(void);

/*
 * 打开一张 DER 编码的 X.509 证书。
 *
 * - 使用模块随包发布的 PKIX 描述表加载 schema，并以 DER 严格模式解码；
 * - 输入被复制进文档 arena，调用方可在 open 返回后释放 der；
 * - 成功时 *out_cert 非 NULL；失败时 *out_cert 置 NULL 并返回核心错误码
 *   （截断、非法 DER、不符合 Certificate schema 等）；
 * - 空参返回 ASNBER_E_INVALID_ARG；分配失败返回 ASNBER_E_NOMEM。
 */
ASNBER_PKIX_API asnber_err_t asnber_pkix_certificate_open(
    asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asnber_pkix_certificate_t **out_cert);

/* 关闭证书句柄；cert == NULL 为空操作。 */
ASNBER_PKIX_API void asnber_pkix_certificate_close(
    asnber_pkix_certificate_t *cert);

/*
 * 按路径取节点。路径以 '.' 分隔字段名，相对 Certificate 根；空串表示根。
 * 例："tbsCertificate.subject"、"tbsCertificate.validity.notBefore"、
 * "tbsCertificate.extensions"。
 *
 * - 命中时 *out_node 非 NULL，为文档借用；
 * - 路径不存在（含 DEFAULT/OPTIONAL 字段缺省）返回 ASNBER_OK 且
 *   *out_node = NULL，不报错；
 * - 空参或路径为空段返回 ASNBER_E_INVALID_ARG。
 */
ASNBER_PKIX_API asnber_err_t asnber_pkix_certificate_find(
    const asnber_pkix_certificate_t *cert, const char *path,
    const asnber_node_t **out_node);

/*
 * 便捷访问器：签名算法 OID（点分十进制，借用句柄）。
 * 失败时不写任何输出；字段缺失返回 ASNBER_E_SCHEMA_FIELD。
 */
ASNBER_PKIX_API asnber_err_t asnber_pkix_certificate_signature_algorithm_oid(
    const asnber_pkix_certificate_t *cert, const char **out_dotted,
    size_t *out_size);

/*
 * 签名值 BIT STRING 原始内容：不含 unused-bits 首字节。
 * out_bit_length = out_size * 8 - out_unused_bits；借用句柄。
 */
ASNBER_PKIX_API asnber_err_t asnber_pkix_certificate_signature_value(
    const asnber_pkix_certificate_t *cert, const uint8_t **out_data,
    size_t *out_size, size_t *out_bit_length, uint8_t *out_unused_bits);

/* 证书序列号：大整数严格十进制文本（借用句柄）。 */
ASNBER_PKIX_API asnber_err_t asnber_pkix_certificate_serial_number(
    const asnber_pkix_certificate_t *cert, const char **out_decimal,
    size_t *out_size);

/* 证书版本：0 = v1、1 = v2、2 = v3；DEFAULT v1 缺省时返回 0。 */
ASNBER_PKIX_API asnber_err_t asnber_pkix_certificate_version(
    const asnber_pkix_certificate_t *cert, uint32_t *out_version);

/* issuer / subject 的完整原始 DER（含 tag/len，借用句柄）。 */
ASNBER_PKIX_API asnber_err_t asnber_pkix_certificate_issuer_der(
    const asnber_pkix_certificate_t *cert, const uint8_t **out_data,
    size_t *out_size);
ASNBER_PKIX_API asnber_err_t asnber_pkix_certificate_subject_der(
    const asnber_pkix_certificate_t *cert, const uint8_t **out_data,
    size_t *out_size);

/*
 * 有效期起止时间（结构化）。两个 asnber_time_t 的 struct_size 必须由调用方
 * 初始化为 sizeof(asnber_time_t)；失败时不写部分输出。
 */
ASNBER_PKIX_API asnber_err_t asnber_pkix_certificate_validity(
    const asnber_pkix_certificate_t *cert, asnber_time_t *out_not_before,
    asnber_time_t *out_not_after);

#ifdef __cplusplus
}
#endif

/* 构造侧接口（Certificate / TBSCertificate）。 */
#include <asnber/pkix/pkix_builder.h>

#endif /* ASNBER_PKIX_PKIX_H_INCLUDED */
