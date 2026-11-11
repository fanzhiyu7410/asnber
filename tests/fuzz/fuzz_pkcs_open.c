/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * libFuzzer harness：asnber-pkcs 只读结构的打开与访问面。
 *
 * 同一份输入依次尝试 PrivateKeyInfo / EncryptedPrivateKeyInfo /
 * RSAPublicKey / RSAPrivateKey / CertificationRequest 以及 PKCS#12 的
 * PFX / AuthenticatedSafe / SafeContents / CertBag；任一 open 成功就遍历
 * 该句柄的全部访问器，并按 contentType/bagId 继续解析嵌套结构。带下标的
 * 访问器按 0 / count / SIZE_MAX 探测。
 */
#include <asnber/pkcs/pkcs.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "fuzz_common.h"
#include "fuzz_module_common.h"

/* open 参数边界：NULL ctx / NULL 输入 / 空输入 / NULL 输出 / 超长声明。
 * 不传 size + 1：API 按 (data, size) 契约有权读取 size 字节，放大声明是
 * 调用方 UB，ASan 会把它误报成库内越界。 */
#define FUZZ_OPEN_ARG_PROBES(open_fn, handle_type, ctx, data, size)           \
    do {                                                                      \
        handle_type *probe_ = NULL;                                           \
        (void)open_fn(NULL, (data), (size), &probe_);                         \
        probe_ = NULL;                                                        \
        (void)open_fn((ctx), NULL, (size), &probe_);                          \
        probe_ = NULL;                                                        \
        (void)open_fn((ctx), (data), 0, &probe_);                             \
        probe_ = NULL;                                                        \
        (void)open_fn((ctx), (data), (size), NULL);                           \
        probe_ = NULL;                                                        \
        (void)open_fn((ctx), (data), SIZE_MAX, &probe_);                      \
        probe_ = NULL;                                                        \
    } while (0)

static void scan_private_key_info_attributes(
    const asnber_pkcs_private_key_info_t *info)
{
    size_t count = 0;
    int probe;

    if (asnber_pkcs_private_key_info_attribute_count(info, &count) != ASNBER_OK) {
        return;
    }
    for (probe = 0; probe < FUZZ_INDEX_PROBES; ++probe) {
        const char *oid = NULL;
        size_t oid_size = 0;
        const asnber_node_t *values = NULL;
        size_t index = fuzz_probe_index(count, probe);
        (void)asnber_pkcs_private_key_info_attribute_at(
            info, index, &oid, &oid_size, &values);
        fuzz_walk(values);
    }

    /* NULL 输出参数单独探测。 */
    {
        const char *oid = NULL;
        size_t oid_size = 0;
        const asnber_node_t *values = NULL;
        (void)asnber_pkcs_private_key_info_attribute_at(
            info, 0, NULL, &oid_size, &values);
        (void)asnber_pkcs_private_key_info_attribute_at(
            info, 0, &oid, NULL, &values);
        (void)asnber_pkcs_private_key_info_attribute_at(
            info, 0, &oid, &oid_size, NULL);
    }
}

static void scan_private_key_info(const asnber_pkcs_private_key_info_t *info)
{
    int64_t version = 0;
    const char *text = NULL;
    size_t text_size = 0;
    const uint8_t *bytes = NULL;
    size_t bytes_size = 0;
    size_t count = 0;

    (void)asnber_pkcs_private_key_info_version(info, &version);
    (void)asnber_pkcs_private_key_info_version(info, NULL);

    (void)asnber_pkcs_private_key_info_algorithm_oid(info, &text, &text_size);
    (void)asnber_pkcs_private_key_info_algorithm_oid(info, NULL, &text_size);
    (void)asnber_pkcs_private_key_info_algorithm_oid(info, &text, NULL);

    (void)asnber_pkcs_private_key_info_algorithm_parameters(
        info, &bytes, &bytes_size);
    (void)asnber_pkcs_private_key_info_algorithm_parameters(
        info, NULL, &bytes_size);
    (void)asnber_pkcs_private_key_info_algorithm_parameters(info, &bytes, NULL);

    (void)asnber_pkcs_private_key_info_private_key(
        info, &bytes, &bytes_size);
    (void)asnber_pkcs_private_key_info_private_key(info, NULL, &bytes_size);
    (void)asnber_pkcs_private_key_info_private_key(info, &bytes, NULL);

    (void)asnber_pkcs_private_key_info_private_key_tlv(
        info, &bytes, &bytes_size);
    (void)asnber_pkcs_private_key_info_private_key_tlv(info, NULL, &bytes_size);
    (void)asnber_pkcs_private_key_info_private_key_tlv(info, &bytes, NULL);

    (void)asnber_pkcs_private_key_info_attribute_count(info, &count);
    (void)asnber_pkcs_private_key_info_attribute_count(info, NULL);
    scan_private_key_info_attributes(info);
}

static void scan_encrypted_private_key_info(
    const asnber_pkcs_encrypted_private_key_info_t *info)
{
    const char *text = NULL;
    size_t text_size = 0;
    const uint8_t *bytes = NULL;
    size_t bytes_size = 0;

    (void)asnber_pkcs_encrypted_private_key_info_algorithm_oid(
        info, &text, &text_size);
    (void)asnber_pkcs_encrypted_private_key_info_algorithm_oid(
        info, NULL, &text_size);
    (void)asnber_pkcs_encrypted_private_key_info_algorithm_oid(
        info, &text, NULL);

    (void)asnber_pkcs_encrypted_private_key_info_algorithm_parameters(
        info, &bytes, &bytes_size);
    (void)asnber_pkcs_encrypted_private_key_info_algorithm_parameters(
        info, NULL, &bytes_size);
    (void)asnber_pkcs_encrypted_private_key_info_algorithm_parameters(
        info, &bytes, NULL);

    (void)asnber_pkcs_encrypted_private_key_info_encrypted_data(
        info, &bytes, &bytes_size);
    (void)asnber_pkcs_encrypted_private_key_info_encrypted_data(
        info, NULL, &bytes_size);
    (void)asnber_pkcs_encrypted_private_key_info_encrypted_data(
        info, &bytes, NULL);

    (void)asnber_pkcs_encrypted_private_key_info_encrypted_data_tlv(
        info, &bytes, &bytes_size);
    (void)asnber_pkcs_encrypted_private_key_info_encrypted_data_tlv(
        info, NULL, &bytes_size);
    (void)asnber_pkcs_encrypted_private_key_info_encrypted_data_tlv(
        info, &bytes, NULL);
}

static void scan_rsa_public_key(const asnber_pkcs_rsa_public_key_t *key)
{
    const char *text = NULL;
    size_t text_size = 0;

    (void)asnber_pkcs_rsa_public_key_modulus(key, &text, &text_size);
    (void)asnber_pkcs_rsa_public_key_modulus(key, NULL, &text_size);
    (void)asnber_pkcs_rsa_public_key_modulus(key, &text, NULL);

    (void)asnber_pkcs_rsa_public_key_public_exponent(key, &text, &text_size);
    (void)asnber_pkcs_rsa_public_key_public_exponent(key, NULL, &text_size);
    (void)asnber_pkcs_rsa_public_key_public_exponent(key, &text, NULL);
}

#define FUZZ_SCAN_RSA_DECIMAL(fn)                                             \
    do {                                                                      \
        const char *text_ = NULL;                                             \
        size_t text_size_ = 0;                                                \
        (void)fn(key, &text_, &text_size_);                                   \
        (void)fn(key, NULL, &text_size_);                                     \
        (void)fn(key, &text_, NULL);                                          \
    } while (0)

static void scan_rsa_private_key(const asnber_pkcs_rsa_private_key_t *key)
{
    int64_t version = 0;

    (void)asnber_pkcs_rsa_private_key_version(key, &version);
    (void)asnber_pkcs_rsa_private_key_version(key, NULL);

    FUZZ_SCAN_RSA_DECIMAL(asnber_pkcs_rsa_private_key_modulus);
    FUZZ_SCAN_RSA_DECIMAL(asnber_pkcs_rsa_private_key_public_exponent);
    FUZZ_SCAN_RSA_DECIMAL(asnber_pkcs_rsa_private_key_private_exponent);
    FUZZ_SCAN_RSA_DECIMAL(asnber_pkcs_rsa_private_key_prime1);
    FUZZ_SCAN_RSA_DECIMAL(asnber_pkcs_rsa_private_key_prime2);
    FUZZ_SCAN_RSA_DECIMAL(asnber_pkcs_rsa_private_key_exponent1);
    FUZZ_SCAN_RSA_DECIMAL(asnber_pkcs_rsa_private_key_exponent2);
    FUZZ_SCAN_RSA_DECIMAL(asnber_pkcs_rsa_private_key_coefficient);
}

#undef FUZZ_SCAN_RSA_DECIMAL

static void scan_certification_request_attributes(
    const asnber_pkcs_certification_request_t *request)
{
    size_t count = 0;
    int probe;

    if (asnber_pkcs_certification_request_attribute_count(request, &count) !=
        ASNBER_OK) {
        return;
    }
    for (probe = 0; probe < FUZZ_INDEX_PROBES; ++probe) {
        const char *oid = NULL;
        size_t oid_size = 0;
        const asnber_node_t *values = NULL;
        size_t index = fuzz_probe_index(count, probe);
        (void)asnber_pkcs_certification_request_attribute_at(
            request, index, &oid, &oid_size, &values);
        fuzz_walk(values);
    }

    {
        const char *oid = NULL;
        size_t oid_size = 0;
        const asnber_node_t *values = NULL;
        (void)asnber_pkcs_certification_request_attribute_at(
            request, 0, NULL, &oid_size, &values);
        (void)asnber_pkcs_certification_request_attribute_at(
            request, 0, &oid, NULL, &values);
        (void)asnber_pkcs_certification_request_attribute_at(
            request, 0, &oid, &oid_size, NULL);
    }
}

static void scan_certification_request(
    const asnber_pkcs_certification_request_t *request)
{
    int64_t version = 0;
    const char *text = NULL;
    size_t text_size = 0;
    const uint8_t *bytes = NULL;
    size_t bytes_size = 0;
    size_t count = 0;

    (void)asnber_pkcs_certification_request_version(request, &version);
    (void)asnber_pkcs_certification_request_version(request, NULL);

    (void)asnber_pkcs_certification_request_subject_der(
        request, &bytes, &bytes_size);
    (void)asnber_pkcs_certification_request_subject_der(
        request, NULL, &bytes_size);
    (void)asnber_pkcs_certification_request_subject_der(
        request, &bytes, NULL);

    (void)asnber_pkcs_certification_request_subject_public_key_algorithm_oid(
        request, &text, &text_size);
    (void)asnber_pkcs_certification_request_subject_public_key_algorithm_oid(
        request, NULL, &text_size);
    (void)asnber_pkcs_certification_request_subject_public_key_algorithm_oid(
        request, &text, NULL);

    (void)asnber_pkcs_certification_request_subject_public_key_algorithm_parameters(
        request, &bytes, &bytes_size);
    (void)asnber_pkcs_certification_request_subject_public_key_algorithm_parameters(
        request, NULL, &bytes_size);
    (void)asnber_pkcs_certification_request_subject_public_key_algorithm_parameters(
        request, &bytes, NULL);

    (void)asnber_pkcs_certification_request_subject_public_key(
        request, &bytes, &bytes_size);
    (void)asnber_pkcs_certification_request_subject_public_key(
        request, NULL, &bytes_size);
    (void)asnber_pkcs_certification_request_subject_public_key(
        request, &bytes, NULL);

    (void)asnber_pkcs_certification_request_subject_public_key_tlv(
        request, &bytes, &bytes_size);
    (void)asnber_pkcs_certification_request_subject_public_key_tlv(
        request, NULL, &bytes_size);
    (void)asnber_pkcs_certification_request_subject_public_key_tlv(
        request, &bytes, NULL);

    (void)asnber_pkcs_certification_request_attribute_count(request, &count);
    (void)asnber_pkcs_certification_request_attribute_count(request, NULL);
    scan_certification_request_attributes(request);

    (void)asnber_pkcs_certification_request_signature_algorithm_oid(
        request, &text, &text_size);
    (void)asnber_pkcs_certification_request_signature_algorithm_oid(
        request, NULL, &text_size);
    (void)asnber_pkcs_certification_request_signature_algorithm_oid(
        request, &text, NULL);

    (void)asnber_pkcs_certification_request_signature_algorithm_parameters(
        request, &bytes, &bytes_size);
    (void)asnber_pkcs_certification_request_signature_algorithm_parameters(
        request, NULL, &bytes_size);
    (void)asnber_pkcs_certification_request_signature_algorithm_parameters(
        request, &bytes, NULL);

    (void)asnber_pkcs_certification_request_signature_value(
        request, &bytes, &bytes_size);
    (void)asnber_pkcs_certification_request_signature_value(
        request, NULL, &bytes_size);
    (void)asnber_pkcs_certification_request_signature_value(
        request, &bytes, NULL);

    (void)asnber_pkcs_certification_request_signature_value_tlv(
        request, &bytes, &bytes_size);
    (void)asnber_pkcs_certification_request_signature_value_tlv(
        request, NULL, &bytes_size);
    (void)asnber_pkcs_certification_request_signature_value_tlv(
        request, &bytes, NULL);
}

/* ---------- PKCS#12 ---------- */

/* 从完整 TLV 中取 primitive OCTET STRING 内容；不匹配返回 NULL。 */
static const uint8_t *octets_content(const uint8_t *tlv, size_t tlv_size,
                                     size_t *out_size)
{
    size_t header = 2;
    size_t length;
    if (tlv == NULL || tlv_size < 2 || tlv[0] != 0x04u) {
        return NULL;
    }
    length = tlv[1];
    if ((length & 0x80u) != 0) {
        size_t count = length & 0x7Fu;
        if (count == 0 || count > sizeof(size_t) ||
            tlv_size < 2 + count) {
            return NULL;
        }
        length = 0;
        for (size_t i = 0; i < count; ++i) {
            if (length > (SIZE_MAX >> 8)) {
                return NULL;
            }
            length = (length << 8) | tlv[2 + i];
        }
        header = 2 + count;
    }
    if (length != tlv_size - header) {
        return NULL;
    }
    *out_size = length;
    return tlv + header;
}

static int text_is(const char *text, size_t text_size, const char *expected)
{
    size_t expected_size = strlen(expected);
    return text != NULL && text_size == expected_size &&
           memcmp(text, expected, expected_size) == 0;
}

static void scan_cert_bag(const asnber_pkcs12_cert_bag_t *bag)
{
    const char *text = NULL;
    size_t text_size = 0;
    const uint8_t *bytes = NULL;
    size_t bytes_size = 0;

    (void)asnber_pkcs12_cert_bag_cert_id(bag, &text, &text_size);
    (void)asnber_pkcs12_cert_bag_cert_id(bag, NULL, &text_size);
    (void)asnber_pkcs12_cert_bag_cert_id(bag, &text, NULL);

    (void)asnber_pkcs12_cert_bag_cert_value_tlv(bag, &bytes, &bytes_size);
    (void)asnber_pkcs12_cert_bag_cert_value_tlv(bag, NULL, &bytes_size);
    (void)asnber_pkcs12_cert_bag_cert_value_tlv(bag, &bytes, NULL);

    (void)asnber_pkcs12_cert_bag_certificate(bag, &bytes, &bytes_size);
    (void)asnber_pkcs12_cert_bag_certificate(bag, NULL, &bytes_size);
    (void)asnber_pkcs12_cert_bag_certificate(bag, &bytes, NULL);
}

static void scan_safe_contents(asnber_ctx_t *ctx,
                               const asnber_pkcs12_safe_contents_t *contents);

static void scan_safe_bag(asnber_ctx_t *ctx,
                          const asnber_pkcs12_safe_contents_t *contents,
                          size_t bag_index)
{
    const char *bag_id = NULL;
    size_t bag_id_size = 0;
    const uint8_t *value = NULL;
    size_t value_size = 0;
    size_t attribute_count = 0;
    int probe;

    if (asnber_pkcs12_safe_contents_bag_at(contents, bag_index, &bag_id,
                                         &bag_id_size, &value,
                                         &value_size,
                                         &attribute_count) != ASNBER_OK) {
        return;
    }

    /* bagValue 的完整 TLV：按 bagId 尝试可继续解析的结构。 */
    if (value != NULL) {
        if (text_is(bag_id, bag_id_size,
                    "1.2.840.113549.1.12.10.1.3")) {
            asnber_pkcs12_cert_bag_t *bag = NULL;
            if (asnber_pkcs12_cert_bag_open(
                    ctx, value, value_size, &bag) ==
                    ASNBER_OK &&
                bag != NULL) {
                scan_cert_bag(bag);
            }
            asnber_pkcs12_cert_bag_close(bag);
        } else if (text_is(bag_id, bag_id_size,
                           "1.2.840.113549.1.12.10.1.1")) {
            asnber_pkcs_private_key_info_t *info = NULL;
            if (asnber_pkcs_private_key_info_open(
                    ctx, value, value_size, &info) ==
                    ASNBER_OK &&
                info != NULL) {
                scan_private_key_info(info);
            }
            asnber_pkcs_private_key_info_close(info);
        } else if (text_is(bag_id, bag_id_size,
                           "1.2.840.113549.1.12.10.1.2")) {
            asnber_pkcs_encrypted_private_key_info_t *info = NULL;
            if (asnber_pkcs_encrypted_private_key_info_open(
                    ctx, value, value_size, &info) ==
                    ASNBER_OK &&
                info != NULL) {
                scan_encrypted_private_key_info(info);
            }
            asnber_pkcs_encrypted_private_key_info_close(info);
        }
    }

    for (probe = 0; probe < FUZZ_INDEX_PROBES; ++probe) {
        const char *attr_id = NULL;
        size_t attr_id_size = 0;
        const asnber_node_t *values = NULL;
        size_t index = fuzz_probe_index(attribute_count, probe);
        (void)asnber_pkcs12_safe_contents_bag_attribute_at(
            contents, bag_index, index, &attr_id, &attr_id_size, &values);
        fuzz_walk(values);
    }

    {
        const char *attr_id = NULL;
        size_t attr_id_size = 0;
        const asnber_node_t *values = NULL;
        (void)asnber_pkcs12_safe_contents_bag_attribute_at(
            contents, bag_index, 0, NULL, &attr_id_size, &values);
        (void)asnber_pkcs12_safe_contents_bag_attribute_at(
            contents, bag_index, 0, &attr_id, NULL, &values);
        (void)asnber_pkcs12_safe_contents_bag_attribute_at(
            contents, bag_index, 0, &attr_id, &attr_id_size, NULL);
    }

}

static void scan_safe_contents(asnber_ctx_t *ctx,
                               const asnber_pkcs12_safe_contents_t *contents)
{
    size_t count = 0;
    int probe;

    (void)asnber_pkcs12_safe_contents_bag_count(contents, &count);
    (void)asnber_pkcs12_safe_contents_bag_count(contents, NULL);

    for (probe = 0; probe < FUZZ_INDEX_PROBES; ++probe) {
        size_t index = fuzz_probe_index(count, probe);
        scan_safe_bag(ctx, contents, index);
    }

    {
        const char *bag_id = NULL;
        size_t bag_id_size = 0;
        const uint8_t *value = NULL;
        size_t value_size = 0;
        size_t attribute_count = 0;
        (void)asnber_pkcs12_safe_contents_bag_at(
            contents, 0, NULL, &bag_id_size, &value, &value_size,
            &attribute_count);
        (void)asnber_pkcs12_safe_contents_bag_at(
            contents, 0, &bag_id, NULL, &value, &value_size,
            &attribute_count);
        (void)asnber_pkcs12_safe_contents_bag_at(
            contents, 0, &bag_id, &bag_id_size, NULL, &value_size,
            &attribute_count);
        (void)asnber_pkcs12_safe_contents_bag_at(
            contents, 0, &bag_id, &bag_id_size, &value, NULL,
            &attribute_count);
        (void)asnber_pkcs12_safe_contents_bag_at(
            contents, 0, &bag_id, &bag_id_size, &value, &value_size, NULL);
    }
}

static void scan_authenticated_safe(
    asnber_ctx_t *ctx, const asnber_pkcs12_authenticated_safe_t *safe)
{
    size_t count = 0;
    int probe;

    (void)asnber_pkcs12_authenticated_safe_content_count(safe, &count);
    (void)asnber_pkcs12_authenticated_safe_content_count(safe, NULL);

    for (probe = 0; probe < FUZZ_INDEX_PROBES; ++probe) {
        const char *type_oid = NULL;
        size_t type_oid_size = 0;
        const uint8_t *inner = NULL;
        size_t inner_size = 0;
        size_t index = fuzz_probe_index(count, probe);
        if (asnber_pkcs12_authenticated_safe_content_at(
                safe, index, &type_oid, &type_oid_size, &inner,
                &inner_size) != ASNBER_OK) {
            continue;
        }
        if (text_is(type_oid, type_oid_size, "1.2.840.113549.1.7.1")) {
            size_t payload_size = 0;
            const uint8_t *payload =
                octets_content(inner, inner_size, &payload_size);
            if (payload != NULL) {
                asnber_pkcs12_safe_contents_t *contents = NULL;
                if (asnber_pkcs12_safe_contents_open(
                        ctx, payload, payload_size,
                        &contents) == ASNBER_OK &&
                    contents != NULL) {
                    scan_safe_contents(ctx, contents);
                }
                asnber_pkcs12_safe_contents_close(contents);
            }
        }
    }

    {
        const char *type_oid = NULL;
        size_t type_oid_size = 0;
        const uint8_t *inner = NULL;
        size_t inner_size = 0;
        (void)asnber_pkcs12_authenticated_safe_content_at(
            safe, 0, NULL, &type_oid_size, &inner, &inner_size);
        (void)asnber_pkcs12_authenticated_safe_content_at(
            safe, 0, &type_oid, NULL, &inner, &inner_size);
        (void)asnber_pkcs12_authenticated_safe_content_at(
            safe, 0, &type_oid, &type_oid_size, NULL, &inner_size);
        (void)asnber_pkcs12_authenticated_safe_content_at(
            safe, 0, &type_oid, &type_oid_size, &inner, NULL);
    }
}

static void scan_pfx(asnber_ctx_t *ctx, const asnber_pkcs12_pfx_t *pfx)
{
    int64_t version = 0;
    const char *text = NULL;
    size_t text_size = 0;
    const uint8_t *bytes = NULL;
    size_t bytes_size = 0;
    int present = 0;
    int64_t iterations = 0;

    (void)asnber_pkcs12_pfx_version(pfx, &version);
    (void)asnber_pkcs12_pfx_version(pfx, NULL);

    (void)asnber_pkcs12_pfx_auth_safe_content_type(pfx, &text, &text_size);
    (void)asnber_pkcs12_pfx_auth_safe_content_type(pfx, NULL, &text_size);
    (void)asnber_pkcs12_pfx_auth_safe_content_type(pfx, &text, NULL);

    (void)asnber_pkcs12_pfx_mac_present(pfx, &present);
    (void)asnber_pkcs12_pfx_mac_present(pfx, NULL);

    (void)asnber_pkcs12_pfx_mac_digest_algorithm_oid(pfx, &text, &text_size);
    (void)asnber_pkcs12_pfx_mac_digest_algorithm_oid(pfx, NULL, &text_size);
    (void)asnber_pkcs12_pfx_mac_digest_algorithm_oid(pfx, &text, NULL);

    (void)asnber_pkcs12_pfx_mac_digest_algorithm_parameters(
        pfx, &bytes, &bytes_size);
    (void)asnber_pkcs12_pfx_mac_digest_algorithm_parameters(
        pfx, NULL, &bytes_size);
    (void)asnber_pkcs12_pfx_mac_digest_algorithm_parameters(pfx, &bytes, NULL);

    (void)asnber_pkcs12_pfx_mac_digest(pfx, &bytes, &bytes_size);
    (void)asnber_pkcs12_pfx_mac_digest(pfx, NULL, &bytes_size);
    (void)asnber_pkcs12_pfx_mac_digest(pfx, &bytes, NULL);

    (void)asnber_pkcs12_pfx_mac_salt(pfx, &bytes, &bytes_size);
    (void)asnber_pkcs12_pfx_mac_salt(pfx, NULL, &bytes_size);
    (void)asnber_pkcs12_pfx_mac_salt(pfx, &bytes, NULL);

    (void)asnber_pkcs12_pfx_mac_iterations(pfx, &iterations);
    (void)asnber_pkcs12_pfx_mac_iterations(pfx, NULL);

    {
        size_t payload_size = 0;
        const uint8_t *payload = NULL;
        if (asnber_pkcs12_pfx_auth_safe_content_tlv(pfx, &bytes,
                                                  &bytes_size) == ASNBER_OK) {
            payload = octets_content(bytes, bytes_size, &payload_size);
        }
        (void)asnber_pkcs12_pfx_auth_safe_content_tlv(pfx, NULL, &bytes_size);
        (void)asnber_pkcs12_pfx_auth_safe_content_tlv(pfx, &bytes, NULL);
        if (payload != NULL) {
            asnber_pkcs12_authenticated_safe_t *safe = NULL;
            if (asnber_pkcs12_authenticated_safe_open(
                    ctx, payload, payload_size,
                    &safe) == ASNBER_OK &&
                safe != NULL) {
                scan_authenticated_safe(ctx, safe);
            }
            asnber_pkcs12_authenticated_safe_close(safe);
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    asnber_ctx_t *ctx = fuzz_ctx_create();
    if (ctx == NULL) {
        return 0;
    }

    FUZZ_OPEN_ARG_PROBES(asnber_pkcs_private_key_info_open,
                         asnber_pkcs_private_key_info_t, ctx, data, size);
    FUZZ_OPEN_ARG_PROBES(asnber_pkcs_encrypted_private_key_info_open,
                         asnber_pkcs_encrypted_private_key_info_t, ctx, data,
                         size);
    FUZZ_OPEN_ARG_PROBES(asnber_pkcs_rsa_public_key_open,
                         asnber_pkcs_rsa_public_key_t, ctx, data, size);
    FUZZ_OPEN_ARG_PROBES(asnber_pkcs_rsa_private_key_open,
                         asnber_pkcs_rsa_private_key_t, ctx, data, size);
    FUZZ_OPEN_ARG_PROBES(asnber_pkcs_certification_request_open,
                         asnber_pkcs_certification_request_t, ctx, data, size);
    FUZZ_OPEN_ARG_PROBES(asnber_pkcs12_pfx_open, asnber_pkcs12_pfx_t, ctx, data,
                         size);
    FUZZ_OPEN_ARG_PROBES(asnber_pkcs12_authenticated_safe_open,
                         asnber_pkcs12_authenticated_safe_t, ctx, data, size);
    FUZZ_OPEN_ARG_PROBES(asnber_pkcs12_safe_contents_open,
                         asnber_pkcs12_safe_contents_t, ctx, data, size);
    FUZZ_OPEN_ARG_PROBES(asnber_pkcs12_cert_bag_open,
                         asnber_pkcs12_cert_bag_t, ctx, data, size);

    /* 同一输入按各结构依次尝试；只扫描打开成功的句柄。
     * 每个句柄 close 一次；置空后再 close 覆盖 close(NULL) 重复调用。
     * 同一非空指针的重复 close 不在契约内，不在此构造。 */
    {
        asnber_pkcs_private_key_info_t *handle = NULL;
        if (asnber_pkcs_private_key_info_open(ctx, data, size, &handle) ==
                ASNBER_OK &&
            handle != NULL) {
            scan_private_key_info(handle);
        }
        asnber_pkcs_private_key_info_close(handle);
        handle = NULL;
        asnber_pkcs_private_key_info_close(handle);
    }
    {
        asnber_pkcs_encrypted_private_key_info_t *handle = NULL;
        if (asnber_pkcs_encrypted_private_key_info_open(ctx, data, size,
                                                      &handle) == ASNBER_OK &&
            handle != NULL) {
            scan_encrypted_private_key_info(handle);
        }
        asnber_pkcs_encrypted_private_key_info_close(handle);
        handle = NULL;
        asnber_pkcs_encrypted_private_key_info_close(handle);
    }
    {
        asnber_pkcs_rsa_public_key_t *handle = NULL;
        if (asnber_pkcs_rsa_public_key_open(ctx, data, size, &handle) ==
                ASNBER_OK &&
            handle != NULL) {
            scan_rsa_public_key(handle);
        }
        asnber_pkcs_rsa_public_key_close(handle);
        handle = NULL;
        asnber_pkcs_rsa_public_key_close(handle);
    }
    {
        asnber_pkcs_rsa_private_key_t *handle = NULL;
        if (asnber_pkcs_rsa_private_key_open(ctx, data, size, &handle) ==
                ASNBER_OK &&
            handle != NULL) {
            scan_rsa_private_key(handle);
        }
        asnber_pkcs_rsa_private_key_close(handle);
        handle = NULL;
        asnber_pkcs_rsa_private_key_close(handle);
    }
    {
        asnber_pkcs_certification_request_t *handle = NULL;
        if (asnber_pkcs_certification_request_open(ctx, data, size, &handle) ==
                ASNBER_OK &&
            handle != NULL) {
            scan_certification_request(handle);
        }
        asnber_pkcs_certification_request_close(handle);
        handle = NULL;
        asnber_pkcs_certification_request_close(handle);
    }
    {
        asnber_pkcs12_pfx_t *handle = NULL;
        if (asnber_pkcs12_pfx_open(ctx, data, size, &handle) == ASNBER_OK &&
            handle != NULL) {
            scan_pfx(ctx, handle);
        }
        asnber_pkcs12_pfx_close(handle);
        handle = NULL;
        asnber_pkcs12_pfx_close(handle);
    }
    {
        asnber_pkcs12_authenticated_safe_t *handle = NULL;
        if (asnber_pkcs12_authenticated_safe_open(ctx, data, size, &handle) ==
                ASNBER_OK &&
            handle != NULL) {
            scan_authenticated_safe(ctx, handle);
        }
        asnber_pkcs12_authenticated_safe_close(handle);
        handle = NULL;
        asnber_pkcs12_authenticated_safe_close(handle);
    }
    {
        asnber_pkcs12_safe_contents_t *handle = NULL;
        if (asnber_pkcs12_safe_contents_open(ctx, data, size, &handle) ==
                ASNBER_OK &&
            handle != NULL) {
            scan_safe_contents(ctx, handle);
        }
        asnber_pkcs12_safe_contents_close(handle);
        handle = NULL;
        asnber_pkcs12_safe_contents_close(handle);
    }
    {
        asnber_pkcs12_cert_bag_t *handle = NULL;
        if (asnber_pkcs12_cert_bag_open(ctx, data, size, &handle) == ASNBER_OK &&
            handle != NULL) {
            scan_cert_bag(handle);
        }
        asnber_pkcs12_cert_bag_close(handle);
        handle = NULL;
        asnber_pkcs12_cert_bag_close(handle);
    }

    asnber_ctx_destroy(ctx);
    return 0;
}
