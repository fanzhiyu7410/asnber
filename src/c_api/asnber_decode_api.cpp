/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 解码 C API 边界：选项校验、文档生命周期与 BER 解码入口。
 *
 * 职责：把公共选项转换为内部参数并调用 ber 解码器。
 * 依赖：ber/asnber_ber_decoder.h、types/asnber_dom.h。
 */

// ============================================================================
// 依赖与前置声明
// ============================================================================

#include <asnber/asnber.h>

#include <cstring>
#include <new>

#include "ber/asnber_ber_decoder.h"
#include "core/asnber_context.h"
#include "types/asnber_dom.h"

namespace {

asnber::Context *contextOf(asnber_ctx_t *handle) noexcept
{
    return static_cast<asnber::Context *>(static_cast<void *>(handle));
}

asnber::Document *documentOf(asnber_doc_t *handle) noexcept
{
    return static_cast<asnber::Document *>(static_cast<void *>(handle));
}

/* 已知的 ASNBER_DECODE_* 位；其余位视为配置错误。 */
constexpr uint32_t kKnownDecodeFlags =
    ASNBER_DECODE_COPY_INPUT | ASNBER_DECODE_STRICT_SCHEMA |
    ASNBER_DECODE_WARN_UNKNOWN_FIELD | ASNBER_DECODE_ALLOW_TRAILING;

asnber_err_t validateDecodeOptions(const asnber::Context *ctx,
                                 const asnber_decode_options_t *options,
                                 uint32_t *outMaxDepth, bool *outCopyInput,
                                 bool *outAllowTrailing) noexcept
{
    uint32_t maxDepth = ctx->m_maxDepth;
    bool copyInput = false;
    bool allowTrailing = false;

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
        if ((options->flags & ~kKnownDecodeFlags) != 0) {
            return ASNBER_E_INVALID_CONFIG;
        }
        if ((options->flags & ASNBER_DECODE_STRICT_SCHEMA) != 0) {
            /* 本调用没有 schema 参数，严格 schema 模式无法启用。 */
            return ASNBER_E_INVALID_ARG;
        }
        if (options->max_depth != 0) {
            if (options->max_depth > ctx->m_maxDepth) {
                return ASNBER_E_INVALID_CONFIG;
            }
            maxDepth = options->max_depth;
        }
        copyInput = (options->flags & ASNBER_DECODE_COPY_INPUT) != 0;
        allowTrailing = (options->flags & ASNBER_DECODE_ALLOW_TRAILING) != 0;
    }

    *outMaxDepth = maxDepth;
    *outCopyInput = copyInput;
    *outAllowTrailing = allowTrailing;
    return ASNBER_OK;
}

} /* namespace */

// ============================================================================
// 类型定义
// ============================================================================

// 内部类型位于 core/context 与 types/dom 头文件。

// ============================================================================
// 静态常量 / 内部辅助类型
// ============================================================================

// kKnownDecodeFlags 定义于上方匿名命名空间。

// ============================================================================
// 构造与析构
// ============================================================================

extern "C" void asnber_decode_options_init(asnber_decode_options_t *options)
{
    if (options == nullptr) {
        return;
    }
    options->struct_size = sizeof(asnber_decode_options_t);
    options->encoding = ASNBER_ENCODING_BER;
    options->flags = 0;
    options->max_depth = 0;
    options->reserved[0] = 0;
    options->reserved[1] = 0;
    options->reserved[2] = 0;
}

extern "C" asnber_err_t asnber_decode_buffer(asnber_ctx_t *ctxHandle,
                                         const uint8_t *data, size_t size,
                                         const asnber_decode_options_t *options,
                                         asnber_doc_t **out_doc,
                                         size_t *consumed)
{
    if (out_doc == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_doc = nullptr;
    if (ctxHandle == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }

    asnber::Context *ctx = contextOf(ctxHandle);
    if (ctx->m_magic != asnber::kContextMagic || ctx->m_dead) {
        return ASNBER_E_INVALID_ARG;
    }

    if (data == nullptr && size != 0) {
        asnber::contextSetError(ctx, ASNBER_E_INVALID_ARG, SIZE_MAX, 0);
        return ASNBER_E_INVALID_ARG;
    }

    uint32_t maxDepth = 0;
    bool copyInput = false;
    bool allowTrailing = false;
    const asnber_err_t rc = validateDecodeOptions(ctx, options, &maxDepth,
                                                &copyInput, &allowTrailing);
    if (rc != ASNBER_OK) {
        asnber::contextSetError(ctx, rc, SIZE_MAX, 0);
        return rc;
    }

    const asnber_encoding_t encoding =
        options == nullptr ? ASNBER_ENCODING_BER : options->encoding;

    /* 文档约定：下一次解码开始时清空上一轮告警。 */
    asnber::contextClearWarnings(ctx);

    asnber::Document *doc = nullptr;
    const asnber_err_t decodeRc =
        asnber::decodeBuffer(ctx, data, size, maxDepth, copyInput, allowTrailing,
                           encoding, &doc, consumed);
    if (decodeRc != ASNBER_OK) {
        return decodeRc;
    }

    *out_doc = reinterpret_cast<asnber_doc_t *>(doc);
    return ASNBER_OK;
}

extern "C" asnber_err_t asnber_decode_reader(asnber_ctx_t *ctxHandle,
                                         const asnber_reader_t *reader,
                                         const asnber_decode_options_t *options,
                                         asnber_doc_t **out_doc,
                                         size_t *consumed)
{
    if (out_doc == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_doc = nullptr;
    if (ctxHandle == nullptr || reader == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber::Context *ctx = contextOf(ctxHandle);
    if (ctx->m_magic != asnber::kContextMagic || ctx->m_dead) {
        return ASNBER_E_INVALID_ARG;
    }
    uint32_t maxDepth = 0;
    bool copyInput = false;
    bool allowTrailing = false;
    const asnber_err_t optionRc = validateDecodeOptions(ctx, options, &maxDepth,
                                                     &copyInput, &allowTrailing);
    if (optionRc != ASNBER_OK) {
        asnber::contextSetError(ctx, optionRc, SIZE_MAX, 0);
        return optionRc;
    }
    /* reader 生命周期由调用方保证：输入总是复制进文档，COPY_INPUT 忽略。 */
    (void)copyInput;

    const asnber_encoding_t encoding =
        options == nullptr ? ASNBER_ENCODING_BER : options->encoding;

    asnber::contextClearWarnings(ctx);

    uint8_t *buffer = nullptr;
    size_t used = 0;
    asnber_err_t rc = asnber::readReaderInput(ctx, reader, &buffer, &used);
    if (rc != ASNBER_OK) {
        return rc;
    }

    asnber::Document *doc = nullptr;
    size_t rootEnd = 0;
    rc = asnber::decodeBuffer(ctx, buffer, used, maxDepth, true, allowTrailing,
                            encoding, &doc, &rootEnd);
    asnber::contextRelease(ctx, buffer);
    if (rc != ASNBER_OK) {
        return rc;
    }
    /* consumed 为实际拉取字节数：允许因预读大于顶层 TLV 长度。 */
    if (consumed != nullptr) {
        *consumed = used;
    }
    *out_doc = reinterpret_cast<asnber_doc_t *>(doc);
    return ASNBER_OK;
}

extern "C" void asnber_doc_destroy(asnber_doc_t *handle)
{
    if (handle == nullptr) {
        return;
    }
    asnber::Document *doc = documentOf(handle);
    if (doc->magic != asnber::kDocumentMagic) {
        return;
    }
    asnber::documentDestroy(doc);
}

/* ============================================================================
 * 增量 feed 解码器（push 模式）
 * ========================================================================== */

namespace {

struct AsnberDecoder {
    asnber::Context *ctx = nullptr;
    asnber_decode_options_t options{};
    uint8_t *buffer = nullptr;
    size_t size = 0;
    size_t capacity = 0;
    bool finalized = false;
};

/* 保证 buffer 至少容纳 need 字节；失败返回错误码，成功返回 ASNBER_OK。 */
asnber_err_t decoderReserve(AsnberDecoder *decoder, size_t need)
{
    if (need <= decoder->capacity) {
        return ASNBER_OK;
    }
    size_t newCap = decoder->capacity == 0 ? 256 : decoder->capacity;
    while (newCap < need) {
        newCap *= 2;
    }
    void *raw = nullptr;
    asnber_err_t rc = asnber::contextAllocate(
        decoder->ctx, newCap, asnber::AllocationKind::kGeneric, &raw);
    if (rc != ASNBER_OK) {
        return rc;
    }
    uint8_t *newBuf = static_cast<uint8_t *>(raw);
    if (decoder->size > 0) {
        memcpy(newBuf, decoder->buffer, decoder->size);
    }
    if (decoder->buffer != nullptr) {
        asnber::contextRelease(decoder->ctx, decoder->buffer);
    }
    decoder->buffer = newBuf;
    decoder->capacity = newCap;
    return ASNBER_OK;
}

} /* namespace */

extern "C" asnber_decoder_t *asnber_decoder_create(
    asnber_ctx_t *ctxHandle, const asnber_decode_options_t *options)
{
    if (ctxHandle == nullptr) {
        return nullptr;
    }
    asnber::Context *ctx = contextOf(ctxHandle);
    if (ctx->m_magic != asnber::kContextMagic || ctx->m_dead) {
        return nullptr;
    }

    void *raw = nullptr;
    asnber_err_t rc = asnber::contextAllocate(
        ctx, sizeof(AsnberDecoder), asnber::AllocationKind::kGeneric, &raw);
    if (rc != ASNBER_OK) {
        return nullptr;
    }
    auto *decoder = new (raw) AsnberDecoder();
    decoder->ctx = ctx;
    if (options != nullptr) {
        if (options->struct_size != sizeof(asnber_decode_options_t)) {
            decoder->~AsnberDecoder();
            asnber::contextRelease(ctx, raw);
            return nullptr;
        }
        decoder->options = *options;
    } else {
        asnber_decode_options_init(&decoder->options);
    }
    return reinterpret_cast<asnber_decoder_t *>(decoder);
}

extern "C" void asnber_decoder_destroy(asnber_decoder_t *handle)
{
    if (handle == nullptr) {
        return;
    }
    auto *decoder = reinterpret_cast<AsnberDecoder *>(handle);
    asnber::Context *ctx = decoder->ctx;
    if (decoder->buffer != nullptr && ctx != nullptr) {
        asnber::contextRelease(ctx, decoder->buffer);
    }
    decoder->~AsnberDecoder();
    if (ctx != nullptr) {
        asnber::contextRelease(ctx, decoder);
    }
}

extern "C" asnber_err_t asnber_decoder_feed(asnber_ctx_t *ctxHandle,
                                        asnber_decoder_t *handle,
                                        const uint8_t *data, size_t size)
{
    if (handle == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    auto *decoder = reinterpret_cast<AsnberDecoder *>(handle);
    if (decoder->finalized) {
        return ASNBER_E_INVALID_ARG;
    }
    if (data == nullptr && size != 0) {
        return ASNBER_E_INVALID_ARG;
    }
    if (size == 0) {
        return ASNBER_OK;
    }

    asnber::Context *ctx = decoder->ctx;
    asnber_err_t rc = decoderReserve(decoder, decoder->size + size);
    if (rc != ASNBER_OK) {
        if (ctx != nullptr) {
            asnber::contextSetError(ctx, ASNBER_E_NOMEM, SIZE_MAX, 0);
        }
        return ASNBER_E_NOMEM;
    }
    memcpy(decoder->buffer + decoder->size, data, size);
    decoder->size += size;
    (void)ctxHandle;
    return ASNBER_OK;
}

extern "C" asnber_err_t asnber_decoder_finalize(asnber_ctx_t *ctxHandle,
                                             asnber_decoder_t *handle,
                                             asnber_doc_t **out_doc,
                                             size_t *consumed)
{
    if (out_doc == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_doc = nullptr;
    if (handle == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    auto *decoder = reinterpret_cast<AsnberDecoder *>(handle);
    if (decoder->finalized) {
        return ASNBER_E_INVALID_ARG;
    }
    decoder->finalized = true;

    if (ctxHandle == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber::Context *ctx = contextOf(ctxHandle);
    if (ctx->m_magic != asnber::kContextMagic || ctx->m_dead) {
        return ASNBER_E_INVALID_ARG;
    }

    uint32_t maxDepth = 0;
    bool copyInput = false;
    bool allowTrailing = false;
    const asnber_err_t optionRc = validateDecodeOptions(
        ctx, &decoder->options, &maxDepth, &copyInput, &allowTrailing);
    if (optionRc != ASNBER_OK) {
        asnber::contextSetError(ctx, optionRc, SIZE_MAX, 0);
        return optionRc;
    }
    (void)copyInput; /* feed 数据总是复制进内部 buffer，COPY_INPUT 忽略。 */

    const asnber_encoding_t encoding = decoder->options.encoding;

    asnber::contextClearWarnings(ctx);

    asnber::Document *doc = nullptr;
    size_t rootEnd = 0;
    const asnber_err_t rc = asnber::decodeBuffer(
        ctx, decoder->buffer, decoder->size, maxDepth, true, allowTrailing,
        encoding, &doc, &rootEnd);
    if (rc != ASNBER_OK) {
        return rc;
    }
    if (consumed != nullptr) {
        *consumed = decoder->size;
    }
    *out_doc = reinterpret_cast<asnber_doc_t *>(doc);
    return ASNBER_OK;
}
