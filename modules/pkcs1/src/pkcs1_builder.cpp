/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-pkcs1 构造侧：RSAPublicKey / RSAPrivateKey 组装与编码。
 *
 * 与只读侧共享同一张描述表；构造侧只按 RFC 8017 顺序组装一棵树，再走
 * schema 感知编码。大整数一律经共享层 createBigIntegerNode 规整。
 */

#include <asnber/pkcs1/pkcs1.h>

#include "detail/module_builder_support.h"
#include "pkcs1_tables.h"

#include <cstdlib>
#include <cstring>

using asnber::module_detail::byte_span;
using asnber::module_detail::copyBytes;
using asnber::module_detail::createBigIntegerNode;
using asnber::module_detail::createIntegerNode;
using asnber::module_detail::createNode;
using asnber::module_detail::kMaxBigIntegerBytes;
using asnber::module_detail::kTagSequence;
using asnber::module_detail::loadTable;

/* 与 pkcs1_builder.h 的前向声明同名同域：内部状态对构造侧翻译单元可见。 */
struct asnber_pkcs_rsa_public_key_builder {
    asnber_ctx_t *ctx;
    bool modulus_set;
    byte_span modulus;
    bool public_exponent_set;
    byte_span public_exponent;
};

/* RSAPrivateKey 的 8 个大整数字段，编号同时决定编码顺序。 */
enum private_field_index {
    kPrivateModulus = 0,
    kPrivatePublicExponent,
    kPrivatePrivateExponent,
    kPrivatePrime1,
    kPrivatePrime2,
    kPrivateExponent1,
    kPrivateExponent2,
    kPrivateCoefficient,
    kPrivateFieldCount
};

struct asnber_pkcs_rsa_private_key_builder {
    asnber_ctx_t *ctx;
    bool field_set[kPrivateFieldCount];
    byte_span field[kPrivateFieldCount];
};

namespace {

void resetBuffer(asnber_buf_t *buf)
{
    buf->data = nullptr;
    buf->size = 0;
    buf->capacity = 0;
}

/* 复制一个大端无符号幅值并标记字段已设置。 */
asnber_err_t setMagnitude(byte_span *slot, bool *flag,
                        const uint8_t *magnitude, size_t size)
{
    if (magnitude == nullptr || size == 0) {
        return ASNBER_E_INVALID_ARG;
    }
    if (*flag) {
        return ASNBER_E_INVALID_STATE;
    }
    if (size > kMaxBigIntegerBytes) {
        return ASNBER_E_INPUT_LIMIT;
    }
    uint8_t *copy = copyBytes(magnitude, size);
    if (copy == nullptr) {
        return ASNBER_E_NOMEM;
    }
    slot->data = copy;
    slot->size = size;
    *flag = true;
    return ASNBER_OK;
}

asnber_err_t buildPublicKey(const asnber_pkcs_rsa_public_key_builder &builder,
                          asnber_doc_t **out_doc)
{
    asnber_doc_t *doc = nullptr;
    asnber_err_t rc = asnber_doc_create(builder.ctx, &doc);
    if (rc != ASNBER_OK) {
        return rc;
    }

    asnber_node_t *root = nullptr;
    asnber_node_t *ignored = nullptr;
    rc = createNode(doc, nullptr, ASNBER_TAG_UNIVERSAL, kTagSequence, 1, &root);
    if (rc == ASNBER_OK) {
        rc = createBigIntegerNode(doc, root, builder.modulus.data,
                                  builder.modulus.size, &ignored);
    }
    if (rc == ASNBER_OK) {
        rc = createBigIntegerNode(doc, root, builder.public_exponent.data,
                                  builder.public_exponent.size, &ignored);
    }
    if (rc == ASNBER_OK) {
        rc = asnber_doc_seal(doc);
    }
    if (rc != ASNBER_OK) {
        asnber_doc_destroy(doc);
        return rc;
    }
    *out_doc = doc;
    return ASNBER_OK;
}

asnber_err_t encodePublicKey(
    const asnber_pkcs_rsa_public_key_builder &builder, const asnber_doc_t *doc,
    asnber_buf_t *out_buf)
{
    pkcs1_table_view table = pkcs1SchemaTable();
    asnber_schema_t *schema = nullptr;
    asnber_err_t rc = loadTable(builder.ctx, table.data, table.size,
                              kPkcs1RootRsaPublicKey, &schema);
    if (rc != ASNBER_OK) {
        return rc;
    }
    asnber_encode_options_t options;
    asnber_encode_options_init(&options);
    options.schema = schema;
    rc = asnber_encode_buffer(builder.ctx, doc, &options, out_buf);
    asnber_schema_destroy(schema);
    return rc;
}

asnber_err_t buildPrivateKey(const asnber_pkcs_rsa_private_key_builder &builder,
                           asnber_doc_t **out_doc)
{
    asnber_doc_t *doc = nullptr;
    asnber_err_t rc = asnber_doc_create(builder.ctx, &doc);
    if (rc != ASNBER_OK) {
        return rc;
    }

    asnber_node_t *root = nullptr;
    asnber_node_t *ignored = nullptr;
    rc = createNode(doc, nullptr, ASNBER_TAG_UNIVERSAL, kTagSequence, 1, &root);
    if (rc == ASNBER_OK) {
        /* version 固定为 two-prime（0），不暴露 setter。 */
        rc = createIntegerNode(doc, root, 0, &ignored);
    }
    for (size_t i = 0; rc == ASNBER_OK && i < kPrivateFieldCount; ++i) {
        rc = createBigIntegerNode(doc, root, builder.field[i].data,
                                  builder.field[i].size, &ignored);
    }
    if (rc == ASNBER_OK) {
        rc = asnber_doc_seal(doc);
    }
    if (rc != ASNBER_OK) {
        asnber_doc_destroy(doc);
        return rc;
    }
    *out_doc = doc;
    return ASNBER_OK;
}

asnber_err_t encodePrivateKey(
    const asnber_pkcs_rsa_private_key_builder &builder, const asnber_doc_t *doc,
    asnber_buf_t *out_buf)
{
    pkcs1_table_view table = pkcs1SchemaTable();
    asnber_schema_t *schema = nullptr;
    asnber_err_t rc = loadTable(builder.ctx, table.data, table.size,
                              kPkcs1RootRsaPrivateKey, &schema);
    if (rc != ASNBER_OK) {
        return rc;
    }
    asnber_encode_options_t options;
    asnber_encode_options_init(&options);
    options.schema = schema;
    rc = asnber_encode_buffer(builder.ctx, doc, &options, out_buf);
    asnber_schema_destroy(schema);
    return rc;
}

} /* namespace */

extern "C" asnber_err_t asnber_pkcs_rsa_public_key_builder_create(
    asnber_ctx_t *ctx, asnber_pkcs_rsa_public_key_builder_t **out_builder)
{
    if (ctx == nullptr || out_builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_builder = nullptr;
    asnber_pkcs_rsa_public_key_builder_t *builder =
        static_cast<asnber_pkcs_rsa_public_key_builder_t *>(
            std::malloc(sizeof(asnber_pkcs_rsa_public_key_builder_t)));
    if (builder == nullptr) {
        return ASNBER_E_NOMEM;
    }
    std::memset(builder, 0, sizeof(*builder));
    builder->ctx = ctx;
    *out_builder = builder;
    return ASNBER_OK;
}

extern "C" void asnber_pkcs_rsa_public_key_builder_destroy(
    asnber_pkcs_rsa_public_key_builder_t *builder)
{
    if (builder == nullptr) {
        return;
    }
    std::free(builder->modulus.data);
    std::free(builder->public_exponent.data);
    std::memset(builder, 0, sizeof(*builder));
    std::free(builder);
}

extern "C" asnber_err_t asnber_pkcs_rsa_public_key_builder_set_modulus(
    asnber_pkcs_rsa_public_key_builder_t *builder, const uint8_t *magnitude,
    size_t size)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return setMagnitude(&builder->modulus, &builder->modulus_set, magnitude,
                        size);
}

extern "C" asnber_err_t asnber_pkcs_rsa_public_key_builder_set_public_exponent(
    asnber_pkcs_rsa_public_key_builder_t *builder, const uint8_t *magnitude,
    size_t size)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return setMagnitude(&builder->public_exponent,
                        &builder->public_exponent_set, magnitude, size);
}

extern "C" asnber_err_t asnber_pkcs_rsa_public_key_builder_encode(
    const asnber_pkcs_rsa_public_key_builder_t *builder, asnber_buf_t *out_buf)
{
    if (builder == nullptr || out_buf == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    resetBuffer(out_buf);

    if (!builder->modulus_set || !builder->public_exponent_set) {
        return ASNBER_E_INVALID_STATE;
    }

    asnber_doc_t *doc = nullptr;
    asnber_err_t rc = buildPublicKey(*builder, &doc);
    if (rc != ASNBER_OK) {
        return rc;
    }
    rc = encodePublicKey(*builder, doc, out_buf);
    asnber_doc_destroy(doc);
    return rc;
}

extern "C" asnber_err_t asnber_pkcs_rsa_private_key_builder_create(
    asnber_ctx_t *ctx, asnber_pkcs_rsa_private_key_builder_t **out_builder)
{
    if (ctx == nullptr || out_builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_builder = nullptr;
    asnber_pkcs_rsa_private_key_builder_t *builder =
        static_cast<asnber_pkcs_rsa_private_key_builder_t *>(
            std::malloc(sizeof(asnber_pkcs_rsa_private_key_builder_t)));
    if (builder == nullptr) {
        return ASNBER_E_NOMEM;
    }
    std::memset(builder, 0, sizeof(*builder));
    builder->ctx = ctx;
    *out_builder = builder;
    return ASNBER_OK;
}

extern "C" void asnber_pkcs_rsa_private_key_builder_destroy(
    asnber_pkcs_rsa_private_key_builder_t *builder)
{
    if (builder == nullptr) {
        return;
    }
    for (size_t i = 0; i < kPrivateFieldCount; ++i) {
        std::free(builder->field[i].data);
    }
    std::memset(builder, 0, sizeof(*builder));
    std::free(builder);
}

extern "C" asnber_err_t asnber_pkcs_rsa_private_key_builder_set_modulus(
    asnber_pkcs_rsa_private_key_builder_t *builder, const uint8_t *magnitude,
    size_t size)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return setMagnitude(&builder->field[kPrivateModulus],
                        &builder->field_set[kPrivateModulus], magnitude, size);
}

extern "C" asnber_err_t asnber_pkcs_rsa_private_key_builder_set_public_exponent(
    asnber_pkcs_rsa_private_key_builder_t *builder, const uint8_t *magnitude,
    size_t size)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return setMagnitude(&builder->field[kPrivatePublicExponent],
                        &builder->field_set[kPrivatePublicExponent], magnitude,
                        size);
}

extern "C" asnber_err_t asnber_pkcs_rsa_private_key_builder_set_private_exponent(
    asnber_pkcs_rsa_private_key_builder_t *builder, const uint8_t *magnitude,
    size_t size)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return setMagnitude(&builder->field[kPrivatePrivateExponent],
                        &builder->field_set[kPrivatePrivateExponent],
                        magnitude, size);
}

extern "C" asnber_err_t asnber_pkcs_rsa_private_key_builder_set_prime1(
    asnber_pkcs_rsa_private_key_builder_t *builder, const uint8_t *magnitude,
    size_t size)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return setMagnitude(&builder->field[kPrivatePrime1],
                        &builder->field_set[kPrivatePrime1], magnitude, size);
}

extern "C" asnber_err_t asnber_pkcs_rsa_private_key_builder_set_prime2(
    asnber_pkcs_rsa_private_key_builder_t *builder, const uint8_t *magnitude,
    size_t size)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return setMagnitude(&builder->field[kPrivatePrime2],
                        &builder->field_set[kPrivatePrime2], magnitude, size);
}

extern "C" asnber_err_t asnber_pkcs_rsa_private_key_builder_set_exponent1(
    asnber_pkcs_rsa_private_key_builder_t *builder, const uint8_t *magnitude,
    size_t size)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return setMagnitude(&builder->field[kPrivateExponent1],
                        &builder->field_set[kPrivateExponent1], magnitude,
                        size);
}

extern "C" asnber_err_t asnber_pkcs_rsa_private_key_builder_set_exponent2(
    asnber_pkcs_rsa_private_key_builder_t *builder, const uint8_t *magnitude,
    size_t size)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return setMagnitude(&builder->field[kPrivateExponent2],
                        &builder->field_set[kPrivateExponent2], magnitude,
                        size);
}

extern "C" asnber_err_t asnber_pkcs_rsa_private_key_builder_set_coefficient(
    asnber_pkcs_rsa_private_key_builder_t *builder, const uint8_t *magnitude,
    size_t size)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return setMagnitude(&builder->field[kPrivateCoefficient],
                        &builder->field_set[kPrivateCoefficient], magnitude,
                        size);
}

extern "C" asnber_err_t asnber_pkcs_rsa_private_key_builder_encode(
    const asnber_pkcs_rsa_private_key_builder_t *builder, asnber_buf_t *out_buf)
{
    if (builder == nullptr || out_buf == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    resetBuffer(out_buf);

    for (size_t i = 0; i < kPrivateFieldCount; ++i) {
        if (!builder->field_set[i]) {
            return ASNBER_E_INVALID_STATE;
        }
    }

    asnber_doc_t *doc = nullptr;
    asnber_err_t rc = buildPrivateKey(*builder, &doc);
    if (rc != ASNBER_OK) {
        return rc;
    }
    rc = encodePrivateKey(*builder, doc, out_buf);
    asnber_doc_destroy(doc);
    return rc;
}
