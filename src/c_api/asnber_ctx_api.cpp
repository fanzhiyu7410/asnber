/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 上下文与错误状态 C API 边界。
 *
 * 职责：校验调用方参数、把 C 句柄转换为内部 Context，并填充错误详情。
 * 依赖：core/asnber_context.h。
 * 约束：不新增公共符号；所有失败通过 asnber_err_t 返回。
 */

// ============================================================================
// 依赖与前置声明
// ============================================================================

#include <asnber/asnber.h>

#include "core/asnber_context.h"

#include <cstdlib>
#include <cstring>

namespace {

asnber::Context *contextOf(asnber_ctx_t *handle) noexcept
{
    return static_cast<asnber::Context *>(static_cast<void *>(handle));
}

const asnber::Context *contextOf(const asnber_ctx_t *handle) noexcept
{
    return static_cast<const asnber::Context *>(static_cast<const void *>(handle));
}

void *defaultAlloc(void *user, size_t size) noexcept
{
    (void)user;
    return std::malloc(size);
}

void *defaultRealloc(void *user, void *ptr, size_t size) noexcept
{
    (void)user;
    return std::realloc(ptr, size);
}

void defaultFree(void *user, void *ptr) noexcept
{
    (void)user;
    std::free(ptr);
}

const asnber_allocator_t &defaultAllocator() noexcept
{
    static const asnber_allocator_t allocator = {
        sizeof(asnber_allocator_t), nullptr, defaultAlloc, defaultRealloc,
        defaultFree};
    return allocator;
}

} /* namespace */

// ============================================================================
// 类型定义
// ============================================================================

// 内部类型位于 core/asnber_context.h。

// ============================================================================
// 静态常量 / 内部辅助类型
// ============================================================================

// 默认分配器为函数内静态常量，避免运行期构造顺序依赖。

// ============================================================================
// 构造与析构
// ============================================================================

// 上下文构造在下方公共接口中完成。

// ============================================================================
// 公共接口
// ============================================================================

extern "C" void asnber_ctx_config_init(asnber_ctx_config_t *config)
{
    if (config == nullptr) {
        return;
    }
    std::memset(config, 0, sizeof(asnber_ctx_config_t));
    config->struct_size = sizeof(asnber_ctx_config_t);
}

extern "C" asnber_err_t asnber_ctx_size_for_config(const asnber_ctx_config_t *config,
                                               size_t *out_size)
{
    if (out_size == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_size = 0;

    asnber_err_t error = ASNBER_OK;
    if (asnber::validateConfig(config, &error) != ASNBER_OK) {
        return error;
    }

    const size_t required =
        asnber::alignUp(sizeof(asnber::Context), alignof(std::max_align_t));
    *out_size = required;
    return ASNBER_OK;
}

extern "C" asnber_err_t asnber_ctx_create(const asnber_ctx_config_t *config,
                                      asnber_ctx_t **out_ctx)
{
    if (out_ctx == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_ctx = nullptr;
    if (config == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }

    asnber_err_t error = ASNBER_OK;
    if (asnber::validateConfig(config, &error) != ASNBER_OK) {
        return error;
    }

    const size_t required =
        asnber::alignUp(sizeof(asnber::Context), alignof(std::max_align_t));

    void *memory = nullptr;
    const asnber_allocator_t *allocator = config->allocator;

    if (config->static_pool != nullptr) {
        if (config->static_pool_size < required) {
            return ASNBER_E_INVALID_CONFIG;
        }
        memory = config->static_pool;
    } else {
        const asnber_allocator_t &effective =
            allocator != nullptr ? *allocator : defaultAllocator();
        memory = effective.alloc(effective.user, sizeof(asnber::Context));
        if (memory == nullptr) {
            return ASNBER_E_NOMEM;
        }
    }

    std::memset(memory, 0, sizeof(asnber::Context));
    asnber::Context *ctx = static_cast<asnber::Context *>(memory);
    const asnber_err_t rc = asnber::contextInit(ctx, config);
    if (rc != ASNBER_OK) {
        if (config->static_pool == nullptr) {
            const asnber_allocator_t &effective =
                allocator != nullptr ? *allocator : defaultAllocator();
            effective.free(effective.user, memory);
        }
        return rc;
    }

    *out_ctx = reinterpret_cast<asnber_ctx_t *>(ctx);
    return ASNBER_OK;
}

extern "C" void asnber_ctx_destroy(asnber_ctx_t *handle)
{
    if (handle == nullptr) {
        return;
    }
    asnber::Context *ctx = contextOf(handle);
    if (ctx->m_magic != asnber::kContextMagic) {
        return;
    }

    const bool usesPool = ctx->m_usesStaticPool;
    const asnber_allocator_t allocator = ctx->m_allocator;

    asnber::contextDestroy(ctx);
    if (!usesPool) {
        allocator.free(allocator.user, ctx);
    }
}

extern "C" asnber_err_t asnber_ctx_get_error(const asnber_ctx_t *handle,
                                         asnber_error_info_t *out_info)
{
    if (handle == nullptr || out_info == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (out_info->struct_size != sizeof(asnber_error_info_t)) {
        return ASNBER_E_INVALID_CONFIG;
    }

    const asnber::Context *ctx = contextOf(handle);
    if (ctx->m_magic != asnber::kContextMagic) {
        return ASNBER_E_INVALID_ARG;
    }

    out_info->code = ctx->m_errorCode;
    out_info->callback_code =
        (ctx->m_errorCode == ASNBER_E_IO_READ ||
         ctx->m_errorCode == ASNBER_E_IO_WRITE)
            ? ctx->m_callbackCode
            : 0;
    out_info->message = asnber::errorMessage(ctx->m_errorCode);
    out_info->offset = ctx->m_errorCode == ASNBER_OK ? SIZE_MAX
                                                   : ctx->m_errorOffset;
    out_info->depth = ctx->m_errorCode == ASNBER_OK ? 0 : ctx->m_errorDepth;
    out_info->reserved = 0;
    out_info->path = (ctx->m_errorCode != ASNBER_OK && ctx->m_hasErrorPath)
                         ? ctx->m_errorPath
                         : nullptr;
    return ASNBER_OK;
}

extern "C" void asnber_ctx_clear_error(asnber_ctx_t *handle)
{
    if (handle == nullptr) {
        return;
    }
    asnber::Context *ctx = contextOf(handle);
    if (ctx->m_magic != asnber::kContextMagic) {
        return;
    }
    asnber::contextClearError(ctx);
}

// ============================================================================
// 告警接口（本轮解码不产生告警，记录数恒为 0）
// ============================================================================

extern "C" asnber_err_t asnber_ctx_set_warning_handler(asnber_ctx_t *handle,
                                                   asnber_warning_fn handler,
                                                   void *user)
{
    if (handle == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber::Context *ctx = contextOf(handle);
    if (ctx->m_magic != asnber::kContextMagic) {
        return ASNBER_E_INVALID_ARG;
    }
    ctx->m_warningHandler = handler;
    ctx->m_warningUser = user;
    return ASNBER_OK;
}

extern "C" size_t asnber_ctx_warning_count(const asnber_ctx_t *handle)
{
    if (handle == nullptr) {
        return 0;
    }
    const asnber::Context *ctx = contextOf(handle);
    if (ctx->m_magic != asnber::kContextMagic) {
        return 0;
    }
    return static_cast<size_t>(ctx->m_warningCount);
}

extern "C" asnber_err_t asnber_ctx_get_warning(const asnber_ctx_t *handle,
                                           size_t index,
                                           asnber_warning_t *out_warning)
{
    if (handle == nullptr || out_warning == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (out_warning->struct_size != sizeof(asnber_warning_t)) {
        return ASNBER_E_INVALID_CONFIG;
    }
    const asnber::Context *ctx = contextOf(handle);
    if (ctx->m_magic != asnber::kContextMagic) {
        return ASNBER_E_INVALID_ARG;
    }
    if (index >= static_cast<size_t>(ctx->m_warningCount)) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber::WarningRecord *record = asnber::contextWarningAt(ctx, index);
    if (record == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    out_warning->code = record->code;
    out_warning->offset = record->offset;
    out_warning->depth = record->depth;
    out_warning->field_name = record->fieldName;
    out_warning->message = record->message;
    return ASNBER_OK;
}

extern "C" void asnber_ctx_clear_warnings(asnber_ctx_t *handle)
{
    if (handle == nullptr) {
        return;
    }
    asnber::Context *ctx = contextOf(handle);
    if (ctx->m_magic != asnber::kContextMagic) {
        return;
    }
    asnber::contextClearWarnings(ctx);
}