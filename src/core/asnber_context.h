/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 上下文内部实现：分配器、静态池、预算上限与错误状态。
 *
 * 职责：承载 asnber_ctx_t 的全部可变状态，并提供统一的分配/释放与错误记录。
 * 依赖：不依赖 types/ber/schema，仅依赖公共 ABI 与 C 标准库。
 * 所有权：Context 本身由调用方触发创建/销毁；上下文级分配在堆模式下由
 *         本文件跟踪并可在 contextDestroy 中兜底回收。
 */
#ifndef ASNBER_SRC_CORE_CONTEXT_H_INCLUDED
#define ASNBER_SRC_CORE_CONTEXT_H_INCLUDED

#include <asnber/asnber.h>

#include <cstddef>
#include <cstdint>

namespace asnber {

/* 默认预算，与 docs/02-C-API规范.md 第 5 节一致。 */
constexpr uint32_t kDefaultMaxDepth = 64;
constexpr uint32_t kDefaultMaxWarnings = 1024;
constexpr uint64_t kDefaultMaxNodes = UINT64_C(1000000);
constexpr uint64_t kDefaultMaxInputBytes = UINT64_C(64) * 1024 * 1024;
constexpr uint64_t kDefaultMaxOutputBytes = UINT64_C(256) * 1024 * 1024;

/* 错误路径固定缓冲：保证 OOM 时仍可读取错误详情。 */
constexpr size_t kMaxErrorPathBytes = 256;

/* 上下文级分配类别，仅用于调试与兜底回收，不改变所有权。 */
enum class AllocationKind : uint32_t {
    kGeneric = 0,
    kDocument = 1,
    kArenaBlock = 2,
    kSchema = 3,
    kOutputBuffer = 4
};

constexpr uint32_t kContextMagic = UINT32_C(0x41534E31); /* "ASN1" */

/* 上下文级告警记录；fieldName 为上下文分配的副本，message 为静态文本。 */
struct WarningRecord {
    WarningRecord *next;
    asnber_err_t code;
    size_t offset;
    uint32_t depth;
    const char *fieldName;
    const char *message;
};

/*
 * 堆分配块的头部。alignas(max_align_t) 保证头部之后的负载仍满足
 * max_align_t 对齐。
 */
struct alignas(std::max_align_t) AllocHeader {
    AllocHeader *prev;
    AllocHeader *next;
    size_t payloadSize;
    uint32_t kind;
    uint32_t reserved;
};

/*
 * 上下文对象。使用值初始化 + init 函数而非构造/析构，避免在静态池上
 * 引入 placement new 与运行期构造顺序依赖。
 */
struct Context {
    asnber_allocator_t m_allocator;       /* 有效分配器（默认或调用方提供） */
    bool m_usesDefaultAllocator;        /* 是否使用库内默认堆分配器 */
    bool m_usesStaticPool;              /* 是否启用静态池 */
    bool m_dead;                        /* 已销毁标记 */

    unsigned char *m_poolBase;          /* 静态池起始地址 */
    size_t m_poolSize;                  /* 静态池总字节数 */
    size_t m_poolOffset;                /* 已用字节数（含上下文对象） */

    AllocHeader *m_allocations;         /* 堆模式下的上下文级分配链 */

    uint32_t m_maxDepth;
    uint32_t m_maxWarnings;
    uint64_t m_maxNodes;
    uint64_t m_maxInputBytes;
    uint64_t m_maxOutputBytes;

    asnber_err_t m_errorCode;
    int32_t m_callbackCode;
    size_t m_errorOffset;
    uint32_t m_errorDepth;
    bool m_hasErrorPath;
    char m_errorPath[kMaxErrorPathBytes];

    asnber_warning_fn m_warningHandler;
    void *m_warningUser;
    WarningRecord *m_warningsFirst;
    WarningRecord *m_warningsLast;
    uint32_t m_warningCount;
    uint32_t m_warningsReserved;

    uint32_t m_magic;
};

/* 对齐辅助：把 value 向上取整到 alignment（alignment 必须是 2 的幂）。 */
size_t alignUp(size_t value, size_t alignment) noexcept;

/* 校验配置；成功返回 ASNBER_OK，失败写入 *outError（若不为 NULL）。 */
asnber_err_t validateConfig(const asnber_ctx_config_t *config,
                          asnber_err_t *outError) noexcept;

/* 在已清零的内存上初始化上下文状态。pool 模式由 config 决定。 */
asnber_err_t contextInit(Context *ctx, const asnber_ctx_config_t *config) noexcept;

/* 上下文级分配。失败时写入错误状态并返回错误码。 */
asnber_err_t contextAllocate(Context *ctx, size_t size, AllocationKind kind,
                           void **outPtr) noexcept;

/* 释放 contextAllocate 返回的指针；静态池模式为逻辑归还（空操作）。 */
void contextRelease(Context *ctx, void *ptr) noexcept;

/* 回收全部上下文级分配并标记失效（不释放调用方静态池）。 */
void contextDestroy(Context *ctx) noexcept;

/* 记录错误详情；path 为 NULL 时清除路径。 */
void contextSetError(Context *ctx, asnber_err_t code, size_t offset,
                     uint32_t depth) noexcept;

/* 记录 IO 回调失败：错误码按契约包装，原始回调码写入 callback_code。 */
void contextSetIoError(Context *ctx, asnber_err_t code, int32_t callbackCode,
                       size_t offset, uint32_t depth) noexcept;

/*
 * 追加一条告警记录（best-effort）：达到 max_warnings 后静默丢弃；fieldName
 * 复制到上下文级分配，message 使用静态文本；存在回调时同步通知。
 */
void contextAddWarning(Context *ctx, asnber_err_t code, size_t offset,
                       uint32_t depth, const char *fieldName,
                       const char *message) noexcept;

/* 释放并清空全部告警记录。 */
void contextClearWarnings(Context *ctx) noexcept;

/* 按索引读取告警记录；index 越界返回 NULL。 */
const WarningRecord *contextWarningAt(const Context *ctx,
                                      size_t index) noexcept;

/* 记录带路径的错误详情；路径复制进上下文固定缓冲。 */
void contextSetErrorWithPath(Context *ctx, asnber_err_t code, size_t offset,
                             uint32_t depth, const char *path) noexcept;

/* 清除错误状态。 */
void contextClearError(Context *ctx) noexcept;

/* 错误码对应的静态英文消息；未知码返回 "unknown error"。 */
const char *errorMessage(asnber_err_t code) noexcept;

} /* namespace asnber */

#endif /* ASNBER_SRC_CORE_CONTEXT_H_INCLUDED */
