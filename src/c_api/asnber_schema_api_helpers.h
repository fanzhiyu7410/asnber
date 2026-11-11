/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * schema C ABI 拆分后的共享句柄校验。两个实现单元各自包含本头，
 * 内部链接避免跨单元依赖。全部标记 inline：拆分后任一单元未必用到
 * 每个助手，-Wall -Wextra -Werror 不为未使用的 inline 函数告警。
 */
#ifndef ASNBER_C_API_ASNBER_SCHEMA_API_HELPERS_H_INCLUDED
#define ASNBER_C_API_ASNBER_SCHEMA_API_HELPERS_H_INCLUDED

#include <asnber/asnber.h>

#include "core/asnber_context.h"
#include "schema/asnber_schema.h"

namespace {

inline asnber::Context *contextOf(asnber_ctx_t *handle) noexcept
{
    return static_cast<asnber::Context *>(static_cast<void *>(handle));
}

inline asnber::Schema *schemaOf(asnber_schema_t *handle) noexcept
{
    return static_cast<asnber::Schema *>(static_cast<void *>(handle));
}

inline asnber::Context *validContext(asnber_ctx_t *handle) noexcept
{
    if (handle == nullptr) {
        return nullptr;
    }
    asnber::Context *ctx = contextOf(handle);
    if (ctx->m_magic != asnber::kContextMagic || ctx->m_dead) {
        return nullptr;
    }
    return ctx;
}

inline asnber::Schema *validSchema(asnber_schema_t *handle) noexcept
{
    if (handle == nullptr) {
        return nullptr;
    }
    asnber::Schema *schema = schemaOf(handle);
    if (schema->magic != asnber::kSchemaMagic ||
        schema->ctx->m_magic != asnber::kContextMagic || schema->ctx->m_dead) {
        return nullptr;
    }
    return schema;
}

inline const asnber::Schema *validSchema(const asnber_schema_t *handle) noexcept
{
    if (handle == nullptr) {
        return nullptr;
    }
    const asnber::Schema *schema =
        static_cast<const asnber::Schema *>(static_cast<const void *>(handle));
    if (schema->magic != asnber::kSchemaMagic ||
        schema->ctx->m_magic != asnber::kContextMagic || schema->ctx->m_dead) {
        return nullptr;
    }
    return schema;
}

} /* namespace */

#endif /* ASNBER_C_API_ASNBER_SCHEMA_API_HELPERS_H_INCLUDED */
