/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * libFuzzer harness：asnber-pkix 证书打开与只读访问面。
 *
 * 输入被当作 X.509 Certificate DER：先探测 open 的参数边界，再对成功打开
 * 的句柄遍历 find 路径与全部便捷访问器。判据只有崩溃 / ASan / LSan 报错；
 * 返回任何错误码都属于正常行为。
 */
#include <asnber/pkix/pkix.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "fuzz_common.h"

static void scan_find_paths(const asnber_pkix_certificate_t *cert)
{
    static const char *const kPaths[] = {
        "",
        "tbsCertificate",
        "tbsCertificate.version",
        "tbsCertificate.serialNumber",
        "tbsCertificate.signature",
        "tbsCertificate.issuer",
        "tbsCertificate.subject",
        "tbsCertificate.validity",
        "tbsCertificate.validity.notBefore",
        "tbsCertificate.validity.notAfter",
        "tbsCertificate.extensions",
        "signatureAlgorithm",
        "signatureValue",
    };
    size_t i;
    const asnber_node_t *node = NULL;

    for (i = 0; i < sizeof(kPaths) / sizeof(kPaths[0]); ++i) {
        node = NULL;
        (void)asnber_pkix_certificate_find(cert, kPaths[i], &node);
        fuzz_walk(node);
    }

    /* 参数边界：NULL 路径、NULL 输出、空路径段、不存在的路径。 */
    (void)asnber_pkix_certificate_find(cert, NULL, &node);
    (void)asnber_pkix_certificate_find(cert, "tbsCertificate", NULL);
    (void)asnber_pkix_certificate_find(cert, "tbsCertificate..subject", &node);
    (void)asnber_pkix_certificate_find(cert, "no.such.field", &node);
}

static void scan_accessors(const asnber_pkix_certificate_t *cert)
{
    const char *text = NULL;
    size_t text_size = 0;
    const uint8_t *bytes = NULL;
    size_t bytes_size = 0;
    size_t bit_length = 0;
    uint8_t unused_bits = 0;
    uint32_t version = 0;
    asnber_time_t before;
    asnber_time_t after;

    (void)asnber_pkix_certificate_signature_algorithm_oid(
        cert, &text, &text_size);
    (void)asnber_pkix_certificate_signature_algorithm_oid(cert, NULL,
                                                        &text_size);
    (void)asnber_pkix_certificate_signature_algorithm_oid(cert, &text, NULL);

    (void)asnber_pkix_certificate_serial_number(cert, &text, &text_size);
    (void)asnber_pkix_certificate_serial_number(cert, NULL, &text_size);
    (void)asnber_pkix_certificate_serial_number(cert, &text, NULL);

    (void)asnber_pkix_certificate_version(cert, &version);
    (void)asnber_pkix_certificate_version(cert, NULL);

    (void)asnber_pkix_certificate_signature_value(
        cert, &bytes, &bytes_size, &bit_length, &unused_bits);
    (void)asnber_pkix_certificate_signature_value(cert, NULL, &bytes_size,
                                                &bit_length, &unused_bits);
    (void)asnber_pkix_certificate_signature_value(cert, &bytes, NULL,
                                                &bit_length, &unused_bits);
    (void)asnber_pkix_certificate_signature_value(cert, &bytes, &bytes_size,
                                                NULL, &unused_bits);
    (void)asnber_pkix_certificate_signature_value(cert, &bytes, &bytes_size,
                                                &bit_length, NULL);

    (void)asnber_pkix_certificate_issuer_der(cert, &bytes, &bytes_size);
    (void)asnber_pkix_certificate_issuer_der(cert, NULL, &bytes_size);
    (void)asnber_pkix_certificate_issuer_der(cert, &bytes, NULL);
    (void)asnber_pkix_certificate_subject_der(cert, &bytes, &bytes_size);
    (void)asnber_pkix_certificate_subject_der(cert, NULL, &bytes_size);
    (void)asnber_pkix_certificate_subject_der(cert, &bytes, NULL);

    memset(&before, 0, sizeof(before));
    memset(&after, 0, sizeof(after));
    before.struct_size = sizeof(before);
    after.struct_size = sizeof(after);
    (void)asnber_pkix_certificate_validity(cert, &before, &after);
    (void)asnber_pkix_certificate_validity(cert, NULL, NULL);
    (void)asnber_pkix_certificate_validity(cert, &before, NULL);
    (void)asnber_pkix_certificate_validity(cert, NULL, &after);

    /* struct_size 未初始化：必须被参数校验拒绝，而不是越界读写。 */
    memset(&before, 0, sizeof(before));
    memset(&after, 0, sizeof(after));
    (void)asnber_pkix_certificate_validity(cert, &before, &after);
    before.struct_size = sizeof(before);
    (void)asnber_pkix_certificate_validity(cert, &before, &after);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    asnber_ctx_t *ctx = fuzz_ctx_create();
    if (ctx == NULL) {
        return 0;
    }

    /* open 参数边界：NULL ctx / NULL 输入 / 空输入 / NULL 输出 / 超长声明。
     * 不传 size + 1：API 按 (data, size) 契约有权读取 size 字节，放大声明是
     * 调用方 UB，ASan 会把它误报成库内越界。 */
    {
        asnber_pkix_certificate_t *probe = NULL;
        (void)asnber_pkix_certificate_open(NULL, data, size, &probe);
        probe = NULL;
        (void)asnber_pkix_certificate_open(ctx, NULL, size, &probe);
        probe = NULL;
        (void)asnber_pkix_certificate_open(ctx, data, 0, &probe);
        probe = NULL;
        (void)asnber_pkix_certificate_open(ctx, data, size, NULL);
        probe = NULL;
        (void)asnber_pkix_certificate_open(ctx, data, SIZE_MAX, &probe);
        probe = NULL;
        asnber_pkix_certificate_close(probe);
    }

    {
        asnber_pkix_certificate_t *cert = NULL;
        asnber_err_t status =
            asnber_pkix_certificate_open(ctx, data, size, &cert);
        if (status == ASNBER_OK && cert != NULL) {
            scan_find_paths(cert);
            scan_accessors(cert);
            asnber_pkix_certificate_close(cert);
            /* close(NULL) 与“置空后再 close”的防御写法都是空操作。 */
            cert = NULL;
            asnber_pkix_certificate_close(cert);
        } else {
            /* open 失败时契约要求句柄为 NULL，close 仍须可安全调用；
             * 置空后再 close 一次覆盖 close(NULL) 的重复调用写法。
             * 同一非空指针的重复 close 不在契约内，不在此构造。 */
            asnber_pkix_certificate_close(cert);
            cert = NULL;
            asnber_pkix_certificate_close(cert);
        }
    }

    asnber_ctx_destroy(ctx);
    return 0;
}
