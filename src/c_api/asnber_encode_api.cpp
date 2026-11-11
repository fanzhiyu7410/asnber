/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 编码的 C ABI 边界：选项/句柄校验、输出缓冲所有权与 writer 适配。
 *
 * 职责：把公共编码接口转发到 der/asnber_encoder.h 或 schema/asnber_schema_encode.h，
 *       并在入口完成参数、状态与预算检查。options->schema 非空时使用 schema
 *       感知编码（DEFAULT 省略、字段顺序、SET/SET OF 排序、EXPLICIT ANY 重包）。
 * 依赖：core/asnber_context.h、types/asnber_dom.h、schema/asnber_schema.h、
 *       schema/asnber_schema_encode.h、der/asnber_encoder.h。
 */

#include <asnber/asnber.h>

#include "core/asnber_context.h"
#include "der/asnber_encoder.h"
#include "schema/asnber_schema.h"
#include "schema/asnber_schema_encode.h"
#include "types/asnber_dom.h"

namespace {

/* 输出缓冲头部：记录所有者上下文，供 asnber_buf_release 校验归属。 */
struct OutputHeader {
    uint32_t magic;
    uint32_t reserved;
    asnber::Context *owner;
};

constexpr uint32_t kOutputMagic = UINT32_C(0x4F555431); /* "OUT1" */

asnber::Context *validContext(asnber_ctx_t *handle) noexcept
{
    if (handle == nullptr) {
        return nullptr;
    }
    asnber::Context *ctx =
        static_cast<asnber::Context *>(static_cast<void *>(handle));
    if (ctx->m_magic != asnber::kContextMagic || ctx->m_dead) {
        return nullptr;
    }
    return ctx;
}

asnber::Document *validDocument(const asnber_doc_t *handle) noexcept
{
    if (handle == nullptr) {
        return nullptr;
    }
    asnber::Document *doc = static_cast<asnber::Document *>(
        const_cast<void *>(static_cast<const void *>(handle)));
    if (doc->magic != asnber::kDocumentMagic) {
        return nullptr;
    }
    return doc;
}

asnber::Schema *schemaOf(const asnber_schema_t *handle) noexcept
{
    if (handle == nullptr) {
        return nullptr;
    }
    return static_cast<asnber::Schema *>(
        const_cast<void *>(static_cast<const void *>(handle)));
}

asnber_err_t validateOptions(asnber::Context *ctx,
                           const asnber_encode_options_t *options,
                           asnber::Schema **outSchema) noexcept
{
    if (outSchema != nullptr) {
        *outSchema = nullptr;
    }
    if (options == nullptr) {
        return ASNBER_OK;
    }

    if (options->struct_size != sizeof(asnber_encode_options_t)) {
        asnber::contextSetError(ctx, ASNBER_E_INVALID_CONFIG, SIZE_MAX, 0);
        return ASNBER_E_INVALID_CONFIG;
    }
    for (size_t i = 0; i < 4; ++i) {
        if (options->reserved[i] != 0) {
            asnber::contextSetError(ctx, ASNBER_E_INVALID_CONFIG, SIZE_MAX, 0);
            return ASNBER_E_INVALID_CONFIG;
        }
    }
    if (options->flags != 0) {
        asnber::contextSetError(ctx, ASNBER_E_INVALID_CONFIG, SIZE_MAX, 0);
        return ASNBER_E_INVALID_CONFIG;
    }
    if (options->encoding != ASNBER_ENCODING_DER) {
        asnber::contextSetError(ctx, ASNBER_E_UNSUPPORTED_ENCODING, SIZE_MAX, 0);
        return ASNBER_E_UNSUPPORTED_ENCODING;
    }

    if (options->schema != nullptr) {
        asnber::Schema *schema = schemaOf(options->schema);
        if (schema->magic != asnber::kSchemaMagic) {
            asnber::contextSetError(ctx, ASNBER_E_INVALID_ARG, SIZE_MAX, 0);
            return ASNBER_E_INVALID_ARG;
        }
        if (!schema->sealed) {
            asnber::contextSetError(ctx, ASNBER_E_INVALID_STATE, SIZE_MAX, 0);
            return ASNBER_E_INVALID_STATE;
        }
        if (schema->rootTypeId == 0) {
            asnber::contextSetError(ctx, ASNBER_E_INVALID_STATE, SIZE_MAX, 0);
            return ASNBER_E_INVALID_STATE;
        }
        if (outSchema != nullptr) {
            *outSchema = schema;
        }
    }

    return ASNBER_OK;
}

asnber_err_t measureWithinBudget(asnber::Context *ctx, const asnber::Document *doc,
                               const asnber::Schema *schema, size_t *outSize) noexcept
{
    size_t size = 0;
    const asnber_err_t rc =
        schema != nullptr
            ? asnber::schemaMeasureDocument(ctx, doc, schema, &size)
            : asnber::derMeasureDocument(ctx, doc, &size);
    if (rc != ASNBER_OK) {
        return rc;
    }
    if (static_cast<uint64_t>(size) > ctx->m_maxOutputBytes) {
        asnber::contextSetError(ctx, ASNBER_E_OUTPUT_LIMIT, SIZE_MAX, 0);
        return ASNBER_E_OUTPUT_LIMIT;
    }
    *outSize = size;
    return ASNBER_OK;
}

asnber_err_t encodeDocument(asnber::Context *ctx, const asnber::Document *doc,
                          const asnber::Schema *schema, uint8_t *dst,
                          size_t capacity) noexcept
{
    if (schema != nullptr) {
        return asnber::schemaEncodeDocument(ctx, doc, schema, dst, capacity);
    }
    return asnber::derEncodeDocument(ctx, doc, dst, capacity);
}

} /* namespace */

extern "C" void asnber_encode_options_init(asnber_encode_options_t *options)
{
    if (options == nullptr) {
        return;
    }
    for (size_t i = 0; i < sizeof(*options); ++i) {
        reinterpret_cast<uint8_t *>(options)[i] = 0;
    }
    options->struct_size = sizeof(asnber_encode_options_t);
    options->encoding = ASNBER_ENCODING_DER;
}

extern "C" asnber_err_t asnber_encode_writer(asnber_ctx_t *ctxHandle,
                                         const asnber_doc_t *docHandle,
                                         const asnber_encode_options_t *options,
                                         const asnber_writer_t *writer)
{
    asnber::Context *ctx = validContext(ctxHandle);
    if (ctx == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }

    asnber::Document *doc = validDocument(const_cast<asnber_doc_t *>(docHandle));
    if (doc == nullptr || doc->ctx != ctx) {
        asnber::contextSetError(ctx, ASNBER_E_INVALID_ARG, SIZE_MAX, 0);
        return ASNBER_E_INVALID_ARG;
    }
    if (!doc->sealed || doc->root == nullptr) {
        asnber::contextSetError(ctx, ASNBER_E_INVALID_STATE, SIZE_MAX, 0);
        return ASNBER_E_INVALID_STATE;
    }
    if (writer == nullptr || writer->write == nullptr) {
        asnber::contextSetError(ctx, ASNBER_E_INVALID_ARG, SIZE_MAX, 0);
        return ASNBER_E_INVALID_ARG;
    }
    if (writer->struct_size != sizeof(asnber_writer_t)) {
        asnber::contextSetError(ctx, ASNBER_E_INVALID_CONFIG, SIZE_MAX, 0);
        return ASNBER_E_INVALID_CONFIG;
    }

    asnber::Schema *schema = nullptr;
    const asnber_err_t optionRc = validateOptions(ctx, options, &schema);
    if (optionRc != ASNBER_OK) {
        return optionRc;
    }

    size_t size = 0;
    const asnber_err_t measureRc = measureWithinBudget(ctx, doc, schema, &size);
    if (measureRc != ASNBER_OK) {
        return measureRc;
    }

    void *raw = nullptr;
    const asnber_err_t allocRc = asnber::contextAllocate(
        ctx, size == 0 ? 1 : size, asnber::AllocationKind::kGeneric, &raw);
    if (allocRc != ASNBER_OK) {
        return allocRc;
    }

    const asnber_err_t encodeRc =
        encodeDocument(ctx, doc, schema, static_cast<uint8_t *>(raw), size);
    if (encodeRc != ASNBER_OK) {
        asnber::contextRelease(ctx, raw);
        return encodeRc;
    }

    const asnber_err_t writeRc =
        writer->write(writer->user, static_cast<const uint8_t *>(raw), size);
    asnber::contextRelease(ctx, raw);
    if (writeRc != ASNBER_OK) {
        /* 单次回调失败：按契约未确认接收任何字节，offset 记 0。 */
        asnber::contextSetError(ctx, ASNBER_E_IO_WRITE, 0, 0);
        ctx->m_callbackCode = writeRc;
        return ASNBER_E_IO_WRITE;
    }
    return ASNBER_OK;
}

extern "C" asnber_err_t asnber_encode_buffer(asnber_ctx_t *ctxHandle,
                                         const asnber_doc_t *docHandle,
                                         const asnber_encode_options_t *options,
                                         asnber_buf_t *out_buf)
{
    if (out_buf == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    out_buf->data = nullptr;
    out_buf->size = 0;
    out_buf->capacity = 0;

    asnber::Context *ctx = validContext(ctxHandle);
    if (ctx == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }

    asnber::Document *doc = validDocument(const_cast<asnber_doc_t *>(docHandle));
    if (doc == nullptr || doc->ctx != ctx) {
        asnber::contextSetError(ctx, ASNBER_E_INVALID_ARG, SIZE_MAX, 0);
        return ASNBER_E_INVALID_ARG;
    }
    if (!doc->sealed || doc->root == nullptr) {
        asnber::contextSetError(ctx, ASNBER_E_INVALID_STATE, SIZE_MAX, 0);
        return ASNBER_E_INVALID_STATE;
    }

    asnber::Schema *schema = nullptr;
    const asnber_err_t optionRc = validateOptions(ctx, options, &schema);
    if (optionRc != ASNBER_OK) {
        return optionRc;
    }

    size_t size = 0;
    const asnber_err_t measureRc = measureWithinBudget(ctx, doc, schema, &size);
    if (measureRc != ASNBER_OK) {
        return measureRc;
    }
    if (size > SIZE_MAX - sizeof(OutputHeader)) {
        asnber::contextSetError(ctx, ASNBER_E_OUTPUT_LIMIT, SIZE_MAX, 0);
        return ASNBER_E_OUTPUT_LIMIT;
    }

    void *raw = nullptr;
    const asnber_err_t allocRc = asnber::contextAllocate(
        ctx, sizeof(OutputHeader) + size, asnber::AllocationKind::kOutputBuffer,
        &raw);
    if (allocRc != ASNBER_OK) {
        return allocRc;
    }

    OutputHeader *header = static_cast<OutputHeader *>(raw);
    header->magic = kOutputMagic;
    header->reserved = 0;
    header->owner = ctx;
    uint8_t *payload = reinterpret_cast<uint8_t *>(header + 1);

    const asnber_err_t encodeRc = encodeDocument(ctx, doc, schema, payload, size);
    if (encodeRc != ASNBER_OK) {
        asnber::contextRelease(ctx, raw);
        return encodeRc;
    }

    out_buf->data = payload;
    out_buf->size = size;
    out_buf->capacity = size;
    return ASNBER_OK;
}

extern "C" asnber_err_t asnber_buf_release(asnber_ctx_t *ctxHandle, asnber_buf_t *buf)
{
    if (buf == nullptr) {
        return ASNBER_OK;
    }
    if (buf->data == nullptr && buf->size == 0 && buf->capacity == 0) {
        return ASNBER_OK;
    }

    asnber::Context *ctx = validContext(ctxHandle);
    if (ctx == nullptr || buf->data == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }

    OutputHeader *header = reinterpret_cast<OutputHeader *>(buf->data) - 1;
    if (header->magic != kOutputMagic || header->owner != ctx) {
        return ASNBER_E_INVALID_ARG;
    }

    asnber::contextRelease(ctx, header);
    buf->data = nullptr;
    buf->size = 0;
    buf->capacity = 0;
    return ASNBER_OK;
}
