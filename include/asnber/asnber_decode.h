/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 解码选项、reader 与文档生命周期。契约见 docs/02-C-API规范.md 第 5.1、
 * 第 9 节与 docs/04-数据与内存模型.md 第 3 节。
 */
#ifndef ASNBER_ASNBER_DECODE_H_INCLUDED
#define ASNBER_ASNBER_DECODE_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include <asnber/asnber_allocator.h>
#include <asnber/asnber_error.h>
#include <asnber/asnber_export.h>

typedef struct asnber_doc  asnber_doc_t;
typedef struct asnber_node asnber_node_t;
typedef struct asnber_reader asnber_reader_t;

/* 解码/编码规则。基线解码接受 BER 与 DER；CER 与 NONE 不支持解码。 */
typedef enum asnber_encoding {
    ASNBER_ENCODING_BER = 0,   /* 解码可接受；编码不单独提供 */
    ASNBER_ENCODING_DER = 1,   /* 解码严格模式；编码目标 */
    ASNBER_ENCODING_CER = 2,   /* 预留，基线不支持 */
    ASNBER_ENCODING_NONE = 3   /* 无源编码：runtime 构树文档 */
} asnber_encoding_t;

/* ASNBER_DECODE_* 位标志，语义见 docs/02-C-API规范.md 5.1。 */
#define ASNBER_DECODE_COPY_INPUT ((uint32_t)(1u << 0))
#define ASNBER_DECODE_STRICT_SCHEMA ((uint32_t)(1u << 1))
#define ASNBER_DECODE_WARN_UNKNOWN_FIELD ((uint32_t)(1u << 2))
#define ASNBER_DECODE_ALLOW_TRAILING ((uint32_t)(1u << 3))

/*
 * 解码选项。struct_size 必须为 sizeof(asnber_decode_options_t)。
 * options == NULL 等价于默认选项：借用输入、BER、未知字段静默保留、
 * 尾随数据拒绝、不启用 schema 严格校验。
 */
typedef struct asnber_decode_options {
    size_t struct_size;                 /* 必须为 sizeof(asnber_decode_options_t) */
    asnber_encoding_t encoding;           /* BER（默认）或 DER */
    uint32_t flags;                     /* ASNBER_DECODE_* 位标志 */
    uint32_t max_depth;                 /* 0 表示用上下文默认；非 0 只能收紧 */
    uint32_t reserved[3];               /* 必须置零 */
} asnber_decode_options_t;

typedef asnber_err_t (*asnber_read_fn)(void *user, uint8_t *dst,
                                   size_t capacity, size_t *out_size);

struct asnber_reader {
    size_t struct_size;      /* 必须为 sizeof(asnber_reader_t) */
    void *user;
    asnber_read_fn read;       /* out_size == 0 表示输入结束 */
};

#ifdef __cplusplus
extern "C" {
#endif

/* 清零并写入 struct_size；默认 encoding = BER、flags = 0、max_depth = 0。 */
ASNBER_API void asnber_decode_options_init(asnber_decode_options_t *options);

/*
 * 解码一块完整输入并构建文档树。默认借用输入（文档存续期间调用方必须
 * 保证输入有效且不变）；设置 ASNBER_DECODE_COPY_INPUT 时复制进文档 arena。
 *
 * 成功时 *out_doc 非 NULL，consumed 写入从 data 消费的字节数。
 * 失败时 *out_doc 置 NULL，consumed 保持原值，并通过上下文错误状态
 * 提供 code/offset/depth/path。
 */
ASNBER_API asnber_err_t asnber_decode_buffer(asnber_ctx_t *ctx,
                                       const uint8_t *data, size_t size,
                                       const asnber_decode_options_t *options,
                                       asnber_doc_t **out_doc,
                                       size_t *consumed);

/*
 * 从 reader 解码。reader 生命周期由调用方保证：实现会分段拉取直到 EOF，
 * 并把输入复制进文档，ASNBER_DECODE_COPY_INPUT 按忽略处理。
 * 成功时 *out_doc 非 NULL，consumed 写入实际从 reader 拉取的字节数
 * （可能因预读大于顶层 TLV 长度）；失败时 consumed 保持原值。
 * IO 回调返回非零时对外返回 ASNBER_E_IO_READ，原始回调码写入错误详情的
 * callback_code。
 */
ASNBER_API asnber_err_t asnber_decode_reader(asnber_ctx_t *ctx,
                                       const asnber_reader_t *reader,
                                       const asnber_decode_options_t *options,
                                       asnber_doc_t **out_doc,
                                       size_t *consumed);

/* 销毁文档；doc == NULL 为空操作。销毁后所有节点指针立即失效。 */
ASNBER_API void asnber_doc_destroy(asnber_doc_t *doc);

/*
 * 增量 feed 解码器：push 模式，调用方分块推送数据，finalize 时构建 DOM。
 * 不替代 asnber_decode_buffer / asnber_decode_reader；三者解码行为一致。
 */
typedef struct asnber_decoder asnber_decoder_t;

/* 创建解码器并复制选项；options == NULL 用默认选项。失败返回 NULL。 */
ASNBER_API asnber_decoder_t *asnber_decoder_create(
    asnber_ctx_t *ctx, const asnber_decode_options_t *options);

/* 销毁解码器；若尚未 finalize 则丢弃累积数据。 */
ASNBER_API void asnber_decoder_destroy(asnber_decoder_t *decoder);

/* 推送一块输入；可多次调用。返回 ASNBER_OK 或 ASNBER_E_*。 */
ASNBER_API asnber_err_t asnber_decoder_feed(asnber_ctx_t *ctx,
                                      asnber_decoder_t *decoder,
                                      const uint8_t *data, size_t size);

/* 完成解码并返回文档；此后 decoder 不可再 feed。consumed 为总 feed 字节数。 */
ASNBER_API asnber_err_t asnber_decoder_finalize(asnber_ctx_t *ctx,
                                          asnber_decoder_t *decoder,
                                          asnber_doc_t **out_doc,
                                          size_t *consumed);

#ifdef __cplusplus
}
#endif

#endif /* ASNBER_ASNBER_DECODE_H_INCLUDED */
