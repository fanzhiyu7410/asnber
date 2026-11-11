/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 上下文实现：默认堆分配器、静态池、上下文级分配跟踪与错误状态。
 *
 * 分区约定见 docs/08-编码规范.md：依赖、类型、构造/初始化、公共接口、
 * 文件内辅助函数。本文件不使用异常、RTTI、std::string 或全局可变状态。
 */

// ============================================================================
// 依赖与前置声明
// ============================================================================

#include "core/asnber_context.h"

#include <cstdlib>
#include <cstring>

namespace asnber {

namespace {

/* 库内默认堆分配器。 */
void *defaultAlloc(void *user, size_t size) noexcept
{
    (void)user;
    return std::malloc(size);
}

void *defaultRealloc(void *user, void *ptr, size_t size) noexcept
{
    (void)user;
    if (ptr == nullptr) {
        return std::malloc(size);
    }
    return std::realloc(ptr, size);
}

void defaultFree(void *user, void *ptr) noexcept
{
    (void)user;
    std::free(ptr);
}

} /* namespace */

// ============================================================================
// 类型定义
// ============================================================================

// 类型定义位于 asnber_context.h。

// ============================================================================
// 静态常量 / 内部辅助
// ============================================================================

// 默认预算常量位于 asnber_context.h。

// ============================================================================
// 构造与初始化
// ============================================================================

size_t alignUp(size_t value, size_t alignment) noexcept
{
    const size_t mask = alignment - 1;
    return (value + mask) & ~mask;
}

asnber_err_t validateConfig(const asnber_ctx_config_t *config,
                          asnber_err_t *outError) noexcept
{
    if (config == nullptr) {
        if (outError != nullptr) {
            *outError = ASNBER_E_INVALID_ARG;
        }
        return ASNBER_E_INVALID_ARG;
    }

    asnber_err_t error = ASNBER_OK;

    if (config->struct_size != sizeof(asnber_ctx_config_t)) {
        error = ASNBER_E_INVALID_CONFIG;
    } else if (config->reserved_flags != 0 || config->reserved[0] != 0 ||
               config->reserved[1] != 0 || config->reserved[2] != 0 ||
               config->reserved[3] != 0) {
        error = ASNBER_E_INVALID_CONFIG;
    } else if (config->static_pool != nullptr && config->static_pool_size == 0) {
        error = ASNBER_E_INVALID_CONFIG;
    } else if (config->static_pool == nullptr && config->static_pool_size != 0) {
        error = ASNBER_E_INVALID_CONFIG;
    } else if (config->static_pool != nullptr) {
        const size_t alignment = alignof(std::max_align_t);
        const uintptr_t address = reinterpret_cast<uintptr_t>(config->static_pool);
        if ((address & (alignment - 1)) != 0) {
            /* docs/02 8.1：池起始地址未按 max_align_t 对齐返回 INVALID_ARG。 */
            error = ASNBER_E_INVALID_ARG;
        }
    }

    if (error == ASNBER_OK && config->allocator != nullptr) {
        const asnber_allocator_t *allocator = config->allocator;
        if (allocator->struct_size != sizeof(asnber_allocator_t) ||
            allocator->alloc == nullptr || allocator->free == nullptr) {
            error = ASNBER_E_INVALID_CONFIG;
        }
    }

    if (outError != nullptr) {
        *outError = error;
    }
    return error;
}

asnber_err_t contextInit(Context *ctx, const asnber_ctx_config_t *config) noexcept
{
    if (ctx == nullptr || config == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }

    ctx->m_usesStaticPool = config->static_pool != nullptr;
    ctx->m_usesDefaultAllocator = false;
    ctx->m_poolBase = static_cast<unsigned char *>(config->static_pool);
    ctx->m_poolSize = config->static_pool_size;
    ctx->m_allocations = nullptr;

    if (ctx->m_usesStaticPool) {
        ctx->m_allocator.struct_size = sizeof(asnber_allocator_t);
        ctx->m_allocator.user = nullptr;
        ctx->m_allocator.alloc = defaultAlloc;
        ctx->m_allocator.realloc = defaultRealloc;
        ctx->m_allocator.free = defaultFree;
        ctx->m_usesDefaultAllocator = true;
        ctx->m_poolOffset =
            alignUp(sizeof(Context), alignof(std::max_align_t));
        if (ctx->m_poolOffset > ctx->m_poolSize) {
            return ASNBER_E_INVALID_CONFIG;
        }
    } else if (config->allocator != nullptr) {
        ctx->m_allocator = *config->allocator;
    } else {
        ctx->m_allocator.struct_size = sizeof(asnber_allocator_t);
        ctx->m_allocator.user = nullptr;
        ctx->m_allocator.alloc = defaultAlloc;
        ctx->m_allocator.realloc = defaultRealloc;
        ctx->m_allocator.free = defaultFree;
        ctx->m_usesDefaultAllocator = true;
    }

    ctx->m_maxDepth =
        config->max_depth == 0 ? kDefaultMaxDepth : config->max_depth;
    ctx->m_maxWarnings =
        config->max_warnings == 0 ? kDefaultMaxWarnings : config->max_warnings;
    ctx->m_maxNodes =
        config->max_nodes == 0 ? kDefaultMaxNodes : config->max_nodes;
    ctx->m_maxInputBytes = config->max_input_bytes == 0
                               ? kDefaultMaxInputBytes
                               : config->max_input_bytes;
    ctx->m_maxOutputBytes = config->max_output_bytes == 0
                                ? kDefaultMaxOutputBytes
                                : config->max_output_bytes;

    ctx->m_errorCode = ASNBER_OK;
    ctx->m_callbackCode = 0;
    ctx->m_errorOffset = SIZE_MAX;
    ctx->m_errorDepth = 0;
    ctx->m_hasErrorPath = false;
    ctx->m_errorPath[0] = '\0';

    ctx->m_warningHandler = nullptr;
    ctx->m_warningUser = nullptr;
    ctx->m_warningCount = 0;
    ctx->m_warningsReserved = 0;

    ctx->m_dead = false;
    ctx->m_magic = kContextMagic;
    return ASNBER_OK;
}

// ============================================================================
// 公共接口
// ============================================================================

asnber_err_t contextAllocate(Context *ctx, size_t size, AllocationKind kind,
                           void **outPtr) noexcept
{
    if (outPtr == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *outPtr = nullptr;

    if (ctx == nullptr || ctx->m_magic != kContextMagic || ctx->m_dead) {
        return ASNBER_E_INVALID_STATE;
    }
    if (size == 0) {
        return ASNBER_E_INVALID_ARG;
    }

    const size_t alignment = alignof(std::max_align_t);

    if (ctx->m_usesStaticPool) {
        const size_t offset = alignUp(ctx->m_poolOffset, alignment);
        if (offset > ctx->m_poolSize || size > ctx->m_poolSize - offset) {
            contextSetError(ctx, ASNBER_E_STATIC_POOL_EXHAUSTED, SIZE_MAX, 0);
            return ASNBER_E_STATIC_POOL_EXHAUSTED;
        }
        *outPtr = ctx->m_poolBase + offset;
        ctx->m_poolOffset = offset + size;
        return ASNBER_OK;
    }

    if (size > SIZE_MAX - sizeof(AllocHeader)) {
        contextSetError(ctx, ASNBER_E_MEMORY_LIMIT, SIZE_MAX, 0);
        return ASNBER_E_MEMORY_LIMIT;
    }

    const size_t total = sizeof(AllocHeader) + size;
    void *raw = ctx->m_allocator.alloc(ctx->m_allocator.user, total);
    if (raw == nullptr) {
        contextSetError(ctx, ASNBER_E_NOMEM, SIZE_MAX, 0);
        return ASNBER_E_NOMEM;
    }

    AllocHeader *header = static_cast<AllocHeader *>(raw);
    header->prev = nullptr;
    header->next = ctx->m_allocations;
    header->payloadSize = size;
    header->kind = static_cast<uint32_t>(kind);
    header->reserved = 0;
    if (ctx->m_allocations != nullptr) {
        ctx->m_allocations->prev = header;
    }
    ctx->m_allocations = header;

    *outPtr = static_cast<void *>(header + 1);
    return ASNBER_OK;
}

void contextRelease(Context *ctx, void *ptr) noexcept
{
    if (ctx == nullptr || ptr == nullptr) {
        return;
    }
    if (ctx->m_usesStaticPool) {
        /* 静态池只做逻辑归还，由调用方在上下文销毁后统一复用。 */
        return;
    }

    AllocHeader *header = static_cast<AllocHeader *>(ptr) - 1;
    if (header->prev != nullptr) {
        header->prev->next = header->next;
    } else {
        ctx->m_allocations = header->next;
    }
    if (header->next != nullptr) {
        header->next->prev = header->prev;
    }

    ctx->m_allocator.free(ctx->m_allocator.user, header);
}

void contextDestroy(Context *ctx) noexcept
{
    if (ctx == nullptr) {
        return;
    }
    if (ctx->m_magic != kContextMagic) {
        return;
    }

    contextClearWarnings(ctx);

    if (!ctx->m_usesStaticPool) {
        /*
         * 按 docs/02 第 8 节与 docs/04 第 5 节：上下文销毁只兜底回收调用方
         * 未释放的 schema 与输出缓冲；文档与 arena 必须先由调用方销毁。
         */
        AllocHeader *header = ctx->m_allocations;
        while (header != nullptr) {
            AllocHeader *next = header->next;
            const bool ownedByContext =
                header->kind == static_cast<uint32_t>(AllocationKind::kSchema) ||
                header->kind ==
                    static_cast<uint32_t>(AllocationKind::kOutputBuffer) ||
                header->kind == static_cast<uint32_t>(AllocationKind::kGeneric);
            if (ownedByContext) {
                ctx->m_allocator.free(ctx->m_allocator.user, header);
            }
            header = next;
        }
        ctx->m_allocations = nullptr;
    }

    ctx->m_errorCode = ASNBER_OK;
    ctx->m_hasErrorPath = false;
    ctx->m_warningHandler = nullptr;
    ctx->m_warningCount = 0;
    ctx->m_dead = true;
    ctx->m_magic = 0;
}

void contextSetError(Context *ctx, asnber_err_t code, size_t offset,
                     uint32_t depth) noexcept
{
    if (ctx == nullptr) {
        return;
    }
    ctx->m_errorCode = code;
    ctx->m_callbackCode = 0;
    ctx->m_errorOffset = offset;
    ctx->m_errorDepth = depth;
    ctx->m_hasErrorPath = false;
    ctx->m_errorPath[0] = '\0';
}

void contextSetIoError(Context *ctx, asnber_err_t code, int32_t callbackCode,
                       size_t offset, uint32_t depth) noexcept
{
    if (ctx == nullptr) {
        return;
    }
    contextSetError(ctx, code, offset, depth);
    ctx->m_callbackCode = callbackCode;
}

void contextAddWarning(Context *ctx, asnber_err_t code, size_t offset,
                       uint32_t depth, const char *fieldName,
                       const char *message) noexcept
{
    if (ctx == nullptr || ctx->m_magic != kContextMagic) {
        return;
    }
    if (ctx->m_warningCount >= ctx->m_maxWarnings) {
        return;
    }

    void *recordRaw = nullptr;
    if (contextAllocate(ctx, sizeof(WarningRecord),
                        AllocationKind::kGeneric, &recordRaw) != ASNBER_OK) {
        return;
    }
    WarningRecord *record = static_cast<WarningRecord *>(recordRaw);
    std::memset(record, 0, sizeof(*record));
    record->code = code;
    record->offset = offset;
    record->depth = depth;
    record->message = message;

    if (fieldName != nullptr) {
        const size_t length = std::strlen(fieldName) + 1;
        void *nameRaw = nullptr;
        if (contextAllocate(ctx, length, AllocationKind::kGeneric, &nameRaw) !=
            ASNBER_OK) {
            contextRelease(ctx, record);
            return;
        }
        std::memcpy(nameRaw, fieldName, length);
        record->fieldName = static_cast<const char *>(nameRaw);
    }

    if (ctx->m_warningsLast == nullptr) {
        ctx->m_warningsFirst = record;
    } else {
        ctx->m_warningsLast->next = record;
    }
    ctx->m_warningsLast = record;
    ++ctx->m_warningCount;

    if (ctx->m_warningHandler != nullptr) {
        asnber_warning_t warning;
        std::memset(&warning, 0, sizeof(warning));
        warning.struct_size = sizeof(asnber_warning_t);
        warning.code = code;
        warning.offset = offset;
        warning.depth = depth;
        warning.field_name = record->fieldName;
        warning.message = message;
        ctx->m_warningHandler(ctx->m_warningUser, &warning);
    }
}

void contextClearWarnings(Context *ctx) noexcept
{
    if (ctx == nullptr || ctx->m_magic != kContextMagic) {
        return;
    }
    WarningRecord *record = ctx->m_warningsFirst;
    while (record != nullptr) {
        WarningRecord *next = record->next;
        if (record->fieldName != nullptr) {
            contextRelease(ctx, const_cast<char *>(record->fieldName));
        }
        contextRelease(ctx, record);
        record = next;
    }
    ctx->m_warningsFirst = nullptr;
    ctx->m_warningsLast = nullptr;
    ctx->m_warningCount = 0;
}

const WarningRecord *contextWarningAt(const Context *ctx,
                                      size_t index) noexcept
{
    if (ctx == nullptr || ctx->m_magic != kContextMagic) {
        return nullptr;
    }
    const WarningRecord *record = ctx->m_warningsFirst;
    size_t current = 0;
    while (record != nullptr) {
        if (current == index) {
            return record;
        }
        ++current;
        record = record->next;
    }
    return nullptr;
}

void contextSetErrorWithPath(Context *ctx, asnber_err_t code, size_t offset,
                             uint32_t depth, const char *path) noexcept
{
    if (ctx == nullptr) {
        return;
    }
    contextSetError(ctx, code, offset, depth);
    if (path != nullptr) {
        size_t length = 0;
        while (length + 1 < kMaxErrorPathBytes && path[length] != '\0') {
            ++length;
        }
        std::memcpy(ctx->m_errorPath, path, length);
        ctx->m_errorPath[length] = '\0';
        ctx->m_hasErrorPath = true;
    }
}

void contextClearError(Context *ctx) noexcept
{
    if (ctx == nullptr) {
        return;
    }
    ctx->m_errorCode = ASNBER_OK;
    ctx->m_callbackCode = 0;
    ctx->m_errorOffset = SIZE_MAX;
    ctx->m_errorDepth = 0;
    ctx->m_hasErrorPath = false;
    ctx->m_errorPath[0] = '\0';
}

// ============================================================================
// 文件内辅助函数
// ============================================================================

const char *errorMessage(asnber_err_t code) noexcept
{
    switch (code) {
    case ASNBER_OK:
        return nullptr;
    case ASNBER_E_INVALID_ARG:
        return "invalid argument";
    case ASNBER_E_INVALID_CONFIG:
        return "invalid configuration";
    case ASNBER_E_INVALID_STATE:
        return "invalid state";
    case ASNBER_E_UNSUPPORTED:
        return "operation not supported";
    case ASNBER_E_VERSION_MISMATCH:
        return "version mismatch";
    case ASNBER_E_NOMEM:
        return "out of memory";
    case ASNBER_E_MEMORY_LIMIT:
        return "memory budget exceeded";
    case ASNBER_E_STATIC_POOL_EXHAUSTED:
        return "static pool exhausted";
    case ASNBER_E_TRUNCATED:
        return "input truncated";
    case ASNBER_E_MALFORMED_TAG:
        return "malformed tag";
    case ASNBER_E_MALFORMED_LENGTH:
        return "malformed length";
    case ASNBER_E_LENGTH_MISMATCH:
        return "length mismatch";
    case ASNBER_E_INDEFINITE_NOT_ALLOWED:
        return "indefinite length not allowed";
    case ASNBER_E_TRAILING_DATA:
        return "trailing data";
    case ASNBER_E_MALFORMED_VALUE:
        return "malformed value";
    case ASNBER_E_NON_CANONICAL:
        return "non-canonical encoding";
    case ASNBER_E_UNSUPPORTED_ENCODING:
        return "unsupported encoding";
    case ASNBER_E_INVALID_VALUE:
        return "invalid value";
    case ASNBER_E_RANGE:
        return "value out of range";
    case ASNBER_E_CONVERSION:
        return "conversion failed";
    case ASNBER_E_DEPTH_LIMIT:
        return "depth limit exceeded";
    case ASNBER_E_NODE_LIMIT:
        return "node limit exceeded";
    case ASNBER_E_INPUT_LIMIT:
        return "input size limit exceeded";
    case ASNBER_E_OUTPUT_LIMIT:
        return "output size limit exceeded";
    case ASNBER_E_IO_READ:
        return "reader callback failed";
    case ASNBER_E_IO_WRITE:
        return "writer callback failed";
    case ASNBER_E_SCHEMA_FORMAT:
        return "schema table format error";
    case ASNBER_E_SCHEMA_TYPE:
        return "schema type error";
    case ASNBER_E_SCHEMA_FIELD:
        return "schema field error";
    case ASNBER_E_SCHEMA_CONSTRAINT:
        return "schema constraint violation";
    case ASNBER_E_SCHEMA_DEFAULT:
        return "schema default value error";
    case ASNBER_E_INTERNAL:
        return "internal error";
    default:
        return "unknown error";
    }
}

} /* namespace asnber */
