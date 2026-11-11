/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * schema 感知解码与文档校验入口。
 *
 * 职责：校验上下文/schema 句柄与选项，解码输入后调用绑定逻辑；reader
 *       入口先读满数据并强制复制输入；asnber_doc_validate 复用同一套绑定
 *       逻辑但不修改节点。
 * 依赖：ber/asnber_ber_decoder.h、core/asnber_context.h、schema/asnber_schema.h、
 *       types/asnber_dom.h。
 * 所有权：不创建新文档；字段名复制进现有文档 arena；ANY 原始 TLV 指向
 *         文档输入切片（借用或已复制）。
 */

#include <asnber/asnber.h>

#include <cstddef>
#include <cstdint>

#include "ber/asnber_ber_decoder.h"
#include "core/asnber_context.h"
#include "schema/asnber_schema.h"
#include "schema/detail/schema_decode_internal.h"
#include "types/asnber_dom.h"

namespace {

bool hasKnownFlags(uint32_t flags)
{
    return (flags & ~(ASNBER_DECODE_COPY_INPUT | ASNBER_DECODE_STRICT_SCHEMA |
                      ASNBER_DECODE_WARN_UNKNOWN_FIELD |
                      ASNBER_DECODE_ALLOW_TRAILING)) == 0;
}

asnber_err_t prepareOptions(asnber::Context *ctx,
                          const asnber_decode_options_t *options,
                          uint32_t *outMaxDepth, bool *outCopyInput,
                          bool *outAllowTrailing, bool *outStrict, bool *outWarn)
{
    uint32_t maxDepth = ctx->m_maxDepth;
    bool copyInput = false;
    bool allowTrailing = false;
    bool strict = false;
    bool warn = false;
    if (options != nullptr) {
        if (options->struct_size != sizeof(asnber_decode_options_t)) {
            return ASNBER_E_INVALID_CONFIG;
        }
        if (options->reserved[0] != 0 || options->reserved[1] != 0 ||
            options->reserved[2] != 0) {
            return ASNBER_E_INVALID_CONFIG;
        }
        if (options->encoding != ASNBER_ENCODING_BER &&
            options->encoding != ASNBER_ENCODING_DER) {
            return ASNBER_E_UNSUPPORTED_ENCODING;
        }
        if (!hasKnownFlags(options->flags)) {
            return ASNBER_E_INVALID_CONFIG;
        }
        if (options->max_depth != 0) {
            if (options->max_depth > ctx->m_maxDepth) {
                return ASNBER_E_INVALID_CONFIG;
            }
            maxDepth = options->max_depth;
        }
        copyInput = (options->flags & ASNBER_DECODE_COPY_INPUT) != 0;
        allowTrailing = (options->flags & ASNBER_DECODE_ALLOW_TRAILING) != 0;
        strict = (options->flags & ASNBER_DECODE_STRICT_SCHEMA) != 0;
        warn = (options->flags & ASNBER_DECODE_WARN_UNKNOWN_FIELD) != 0;
    }
    *outMaxDepth = maxDepth;
    *outCopyInput = copyInput;
    *outAllowTrailing = allowTrailing;
    *outStrict = strict;
    *outWarn = strict ? false : warn;
    return ASNBER_OK;
}

asnber::Schema *schemaOf(const asnber_schema_t *handle)
{
    if (handle == nullptr) {
        return nullptr;
    }
    return static_cast<asnber::Schema *>(
        const_cast<void *>(static_cast<const void *>(handle)));
}

void reportError(asnber::Context *ctx, asnber_err_t code)
{
    asnber::contextSetError(ctx, code, SIZE_MAX, 0);
}

} /* namespace */

using namespace asnber::schema_decode_detail;

extern "C" asnber_err_t asnber_decode_buffer_with_schema(
    asnber_ctx_t *ctxHandle, const uint8_t *data, size_t size,
    const asnber_schema_t *schemaHandle, const asnber_decode_options_t *options,
    asnber_doc_t **out_doc, size_t *consumed)
{
    if (out_doc == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_doc = nullptr;
    if (ctxHandle == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber::Context *ctx = static_cast<asnber::Context *>(
        static_cast<void *>(ctxHandle));
    if (ctx->m_magic != asnber::kContextMagic || ctx->m_dead) {
        return ASNBER_E_INVALID_ARG;
    }
    if (data == nullptr && size != 0) {
        reportError(ctx, ASNBER_E_INVALID_ARG);
        return ASNBER_E_INVALID_ARG;
    }
    asnber::Schema *schema = schemaOf(schemaHandle);
    if (schema == nullptr || schema->magic != asnber::kSchemaMagic ||
        schema->ctx != ctx) {
        reportError(ctx, ASNBER_E_INVALID_ARG);
        return ASNBER_E_INVALID_ARG;
    }
    if (!schema->sealed) {
        reportError(ctx, ASNBER_E_INVALID_STATE);
        return ASNBER_E_INVALID_STATE;
    }
    if (schema->rootTypeId == 0) {
        reportError(ctx, ASNBER_E_SCHEMA_TYPE);
        return ASNBER_E_SCHEMA_TYPE;
    }

    uint32_t maxDepth = 0;
    bool copyInput = false;
    bool allowTrailing = false;
    bool strict = false;
    bool warn = false;
    const asnber_err_t optionRc =
        prepareOptions(ctx, options, &maxDepth, &copyInput, &allowTrailing,
                       &strict, &warn);
    if (optionRc != ASNBER_OK) {
        reportError(ctx, optionRc);
        return optionRc;
    }

    const asnber_encoding_t encoding =
        options == nullptr ? ASNBER_ENCODING_BER : options->encoding;

    asnber::contextClearWarnings(ctx);

    asnber::Document *doc = nullptr;
    const asnber_err_t decodeRc =
        asnber::decodeBuffer(ctx, data, size, maxDepth, copyInput, allowTrailing,
                           encoding, &doc, consumed);
    if (decodeRc != ASNBER_OK) {
        return decodeRc;
    }

    BindContext bind{};
    bind.ctx = ctx;
    bind.schema = schema;
    bind.doc = doc;
    bind.strict = strict;
    bind.warn = warn;
    bind.mutate = true;
    bind.maxDepth = maxDepth;

    const asnber_err_t bindRc =
        bindType(bind, schema->rootTypeId, doc->root, nullptr, false, 0, "");
    if (bindRc != ASNBER_OK) {
        asnber::documentDestroy(doc);
        return bindRc;
    }

    *out_doc = reinterpret_cast<asnber_doc_t *>(doc);
    return ASNBER_OK;
}

extern "C" asnber_err_t asnber_decode_reader_with_schema(
    asnber_ctx_t *ctxHandle, const asnber_reader_t *reader,
    const asnber_schema_t *schema, const asnber_decode_options_t *options,
    asnber_doc_t **out_doc, size_t *consumed)
{
    if (out_doc == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_doc = nullptr;
    if (ctxHandle == nullptr || reader == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber::Context *ctx = static_cast<asnber::Context *>(
        static_cast<void *>(ctxHandle));
    if (ctx->m_magic != asnber::kContextMagic || ctx->m_dead) {
        return ASNBER_E_INVALID_ARG;
    }
    if (reader->read == nullptr ||
        reader->struct_size != sizeof(asnber_reader_t)) {
        reportError(ctx, ASNBER_E_INVALID_CONFIG);
        return ASNBER_E_INVALID_CONFIG;
    }

    uint8_t *buffer = nullptr;
    size_t used = 0;
    asnber_err_t rc = asnber::readReaderInput(ctx, reader, &buffer, &used);
    if (rc != ASNBER_OK) {
        return rc;
    }

    asnber_decode_options_t copyOptions;
    const asnber_decode_options_t *effective = options;
    if (options != nullptr) {
        copyOptions = *options;
        copyOptions.flags |= ASNBER_DECODE_COPY_INPUT;
        effective = &copyOptions;
    } else {
        asnber_decode_options_init(&copyOptions);
        copyOptions.flags |= ASNBER_DECODE_COPY_INPUT;
        effective = &copyOptions;
    }
    size_t rootEnd = 0;
    rc = asnber_decode_buffer_with_schema(ctxHandle, buffer, used, schema,
                                        effective, out_doc, &rootEnd);
    asnber::contextRelease(ctx, buffer);
    if (rc == ASNBER_OK) {
        /* consumed 为实际拉取字节数：允许因预读大于顶层 TLV 长度。 */
        if (consumed != nullptr) {
            *consumed = used;
        }
    }
    return rc;
}

extern "C" asnber_err_t asnber_doc_validate(asnber_ctx_t *ctxHandle,
                                        const asnber_doc_t *docHandle,
                                        const asnber_schema_t *schemaHandle,
                                        const asnber_decode_options_t *options)
{
    if (ctxHandle == nullptr || docHandle == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber::Context *ctx = static_cast<asnber::Context *>(
        static_cast<void *>(ctxHandle));
    if (ctx->m_magic != asnber::kContextMagic || ctx->m_dead) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber::Document *doc = static_cast<asnber::Document *>(
        const_cast<void *>(static_cast<const void *>(docHandle)));
    if (doc->magic != asnber::kDocumentMagic || doc->root == nullptr) {
        reportError(ctx, ASNBER_E_INVALID_ARG);
        return ASNBER_E_INVALID_ARG;
    }
    asnber::Schema *schema = schemaOf(schemaHandle);
    if (schema == nullptr || schema->magic != asnber::kSchemaMagic ||
        schema->ctx != ctx) {
        reportError(ctx, ASNBER_E_INVALID_ARG);
        return ASNBER_E_INVALID_ARG;
    }
    if (!schema->sealed || schema->rootTypeId == 0) {
        reportError(ctx, ASNBER_E_INVALID_STATE);
        return ASNBER_E_INVALID_STATE;
    }

    uint32_t maxDepth = 0;
    bool copyInput = false;
    bool allowTrailing = false;
    bool strict = false;
    bool warn = false;
    const asnber_err_t optionRc =
        prepareOptions(ctx, options, &maxDepth, &copyInput, &allowTrailing,
                       &strict, &warn);
    if (optionRc != ASNBER_OK) {
        reportError(ctx, optionRc);
        return optionRc;
    }
    (void)copyInput;
    (void)allowTrailing;

    BindContext bind{};
    bind.ctx = ctx;
    bind.schema = schema;
    bind.doc = doc;
    bind.strict = strict;
    bind.warn = warn;
    bind.mutate = false;
    bind.maxDepth = maxDepth;

    return bindType(bind, schema->rootTypeId, doc->root, nullptr, false, 0,
                    "");
}