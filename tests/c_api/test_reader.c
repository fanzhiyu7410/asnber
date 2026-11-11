/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * reader 解码路径：分段拉取、段边界切断 TLV、IO 回调失败包装、
 * consumed 语义、尾随判定、BER 不定长，以及 schema 感知 reader。
 */
#include <asnber/asnber.h>

#include <stddef.h>
#include <string.h>

#include "check.h"
#include "test_compare.h"

/* ---------- 分段 reader ---------- */

typedef struct {
    const uint8_t *data;
    size_t size;
    size_t pos;
    size_t chunk;          /* 每次最多返回的字节数；0 表示一次读满 */
    asnber_err_t fail_code;  /* 非 ASNBER_OK 时在该次回调返回该码 */
    size_t fail_at;        /* 第几次回调失败（从 1 开始） */
    size_t calls;
} stream_t;

static void stream_init(stream_t *stream, const uint8_t *data, size_t size,
                        size_t chunk)
{
    memset(stream, 0, sizeof(*stream));
    stream->data = data;
    stream->size = size;
    stream->chunk = chunk;
}

static asnber_err_t stream_read(void *user, uint8_t *out, size_t capacity,
                              size_t *out_size)
{
    stream_t *stream = (stream_t *)user;
    ++stream->calls;
    if (stream->fail_code != ASNBER_OK && stream->calls == stream->fail_at) {
        *out_size = 0;
        return stream->fail_code;
    }
    if (stream->pos >= stream->size) {
        *out_size = 0;
        return ASNBER_OK;
    }
    size_t take = stream->size - stream->pos;
    if (stream->chunk != 0 && take > stream->chunk) {
        take = stream->chunk;
    }
    if (take > capacity) {
        take = capacity;
    }
    memcpy(out, stream->data + stream->pos, take);
    stream->pos += take;
    *out_size = take;
    return ASNBER_OK;
}

static void reader_init(asnber_reader_t *reader, stream_t *stream)
{
    memset(reader, 0, sizeof(*reader));
    reader->struct_size = sizeof(asnber_reader_t);
    reader->user = stream;
    reader->read = stream_read;
}

static asnber_type_desc_t make_type(const char *name, asnber_type_kind_t kind,
                                  uint32_t tag_number)
{
    asnber_type_desc_t desc;
    memset(&desc, 0, sizeof(desc));
    desc.struct_size = sizeof(desc);
    desc.name = name;
    desc.kind = kind;
    desc.tag_class = ASNBER_TAG_UNIVERSAL;
    desc.tag_number = tag_number;
    desc.tag_mode = ASNBER_TAG_MODE_DEFAULT;
    return desc;
}

static asnber_field_desc_t make_field(const char *name, uint32_t type_id)
{
    asnber_field_desc_t desc;
    memset(&desc, 0, sizeof(desc));
    desc.struct_size = sizeof(desc);
    desc.name = name;
    desc.type_id = type_id;
    return desc;
}

/* 通用路径的分段解码辅助。 */
static int decode_segments(asnber_ctx_t *ctx, const uint8_t *data, size_t size,
                           size_t chunk, size_t expected_consumed)
{
    stream_t stream;
    asnber_reader_t reader;
    stream_init(&stream, data, size, chunk);
    reader_init(&reader, &stream);
    asnber_doc_t *doc = NULL;
    size_t consumed = 0;
    ASNBER_TEST_CHECK(asnber_decode_reader(ctx, &reader, NULL, &doc, &consumed) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(doc != NULL);
    ASNBER_TEST_CHECK(consumed == expected_consumed);
    ASNBER_TEST_CHECK(asnber_doc_root(doc) != NULL);
    ASNBER_TEST_CHECK(asnber_node_child_count(asnber_doc_root(doc)) == 2);
    asnber_doc_destroy(doc);
    return 0;
}

/* ---------- 用例 ---------- */

int main(void)
{
    asnber_ctx_t *ctx = NULL;
    asnber_ctx_config_t config;
    asnber_ctx_config_init(&config);
    ASNBER_TEST_CHECK(asnber_ctx_create(&config, &ctx) == ASNBER_OK);

    /* SEQUENCE { INTEGER 5, OCTET STRING "hi" }。 */
    static const uint8_t kSeq[9] = {0x30, 0x07, 0x02, 0x01, 0x05,
                                    0x04, 0x02, 0x68, 0x69};

    /* 1. 多段流与段边界切断 TLV。 */
    ASNBER_TEST_CHECK(decode_segments(ctx, kSeq, sizeof(kSeq), 1,
                                    sizeof(kSeq)) == 0);
    ASNBER_TEST_CHECK(decode_segments(ctx, kSeq, sizeof(kSeq), 2,
                                    sizeof(kSeq)) == 0);
    ASNBER_TEST_CHECK(decode_segments(ctx, kSeq, sizeof(kSeq), 4,
                                    sizeof(kSeq)) == 0);

    /* 2. 回调中途失败：包装为 IO_READ，原始码进 callback_code。 */
    {
        stream_t stream;
        asnber_reader_t reader;
        stream_init(&stream, kSeq, sizeof(kSeq), 2);
        reader_init(&reader, &stream);
        stream.fail_code = ASNBER_E_IO_WRITE;
        stream.fail_at = 3;
        asnber_doc_t *doc = NULL;
        size_t consumed = 123;
        ASNBER_TEST_CHECK(asnber_decode_reader(ctx, &reader, NULL, &doc,
                                           &consumed) == ASNBER_E_IO_READ);
        ASNBER_TEST_CHECK(doc == NULL);
        ASNBER_TEST_CHECK(consumed == 123);
        asnber_error_info_t info;
        memset(&info, 0, sizeof(info));
        info.struct_size = sizeof(info);
        ASNBER_TEST_CHECK(asnber_ctx_get_error(ctx, &info) == ASNBER_OK);
        ASNBER_TEST_CHECK(info.code == ASNBER_E_IO_READ);
        ASNBER_TEST_CHECK(info.callback_code == ASNBER_E_IO_WRITE);
        ASNBER_TEST_CHECK(info.offset == 4);
    }

    /* 3. 尾随判定与 ALLOW_TRAILING。 */
    {
        static const uint8_t kTrailing[11] = {0x30, 0x07, 0x02, 0x01, 0x05,
                                              0x04, 0x02, 0x68, 0x69,
                                              0x05, 0x00};
        stream_t stream;
        asnber_reader_t reader;
        asnber_doc_t *doc = NULL;
        size_t consumed = 123;
        stream_init(&stream, kTrailing, sizeof(kTrailing), 3);
        reader_init(&reader, &stream);
        ASNBER_TEST_CHECK(asnber_decode_reader(ctx, &reader, NULL, &doc,
                                           &consumed) ==
                        ASNBER_E_TRAILING_DATA);
        ASNBER_TEST_CHECK(doc == NULL);
        ASNBER_TEST_CHECK(consumed == 123);

        stream_init(&stream, kTrailing, sizeof(kTrailing), 3);
        reader_init(&reader, &stream);
        asnber_decode_options_t options;
        asnber_decode_options_init(&options);
        options.flags = ASNBER_DECODE_ALLOW_TRAILING;
        ASNBER_TEST_CHECK(asnber_decode_reader(ctx, &reader, &options, &doc,
                                           &consumed) == ASNBER_OK);
        ASNBER_TEST_CHECK(consumed == sizeof(kTrailing));
        asnber_doc_destroy(doc);
    }

    /* 4. BER 不定长在 reader 路径同样支持。 */
    {
        static const uint8_t kIndefinite[7] = {0x30, 0x80, 0x02,
                                               0x01, 0x05, 0x00, 0x00};
        stream_t stream;
        asnber_reader_t reader;
        stream_init(&stream, kIndefinite, sizeof(kIndefinite), 1);
        reader_init(&reader, &stream);
        asnber_doc_t *doc = NULL;
        size_t consumed = 0;
        ASNBER_TEST_CHECK(asnber_decode_reader(ctx, &reader, NULL, &doc,
                                           &consumed) == ASNBER_OK);
        ASNBER_TEST_CHECK(consumed == sizeof(kIndefinite));
        ASNBER_TEST_CHECK(asnber_node_child_count(asnber_doc_root(doc)) == 1);
        asnber_doc_destroy(doc);
    }

    /* 5. 空流与非法 reader 配置。 */
    {
        stream_t stream;
        asnber_reader_t reader;
        asnber_doc_t *doc = NULL;
        size_t consumed = 123;
        stream_init(&stream, kSeq, 0, 1);
        reader_init(&reader, &stream);
        ASNBER_TEST_CHECK(asnber_decode_reader(ctx, &reader, NULL, &doc,
                                           &consumed) == ASNBER_E_TRUNCATED);
        ASNBER_TEST_CHECK(consumed == 123);

        memset(&reader, 0, sizeof(reader));
        reader.struct_size = sizeof(asnber_reader_t);
        ASNBER_TEST_CHECK(asnber_decode_reader(ctx, &reader, NULL, &doc,
                                           &consumed) ==
                        ASNBER_E_INVALID_CONFIG);
    }

    /* 6. COPY_INPUT 与 reader 同设：按忽略处理。 */
    {
        stream_t stream;
        asnber_reader_t reader;
        stream_init(&stream, kSeq, sizeof(kSeq), 2);
        reader_init(&reader, &stream);
        asnber_decode_options_t options;
        asnber_decode_options_init(&options);
        options.flags = ASNBER_DECODE_COPY_INPUT;
        asnber_doc_t *doc = NULL;
        size_t consumed = 0;
        ASNBER_TEST_CHECK(asnber_decode_reader(ctx, &reader, &options, &doc,
                                           &consumed) == ASNBER_OK);
        ASNBER_TEST_CHECK(consumed == sizeof(kSeq));
        asnber_doc_destroy(doc);
    }

    /* 7. schema 感知 reader：绑定、严格未知字段、consumed。 */
    {
        asnber_schema_t *schema = NULL;
        uint32_t intId = 0;
        uint32_t seqId = 0;
        asnber_type_desc_t intType = make_type("Int", ASNBER_TYPE_KIND_SIMPLE, 2);
        asnber_type_desc_t seqType =
            make_type("Seq", ASNBER_TYPE_KIND_SEQUENCE, 16);
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &intType, &intId) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &seqType, &seqId) ==
                        ASNBER_OK);
        asnber_field_desc_t aField = make_field("a", intId);
        ASNBER_TEST_CHECK(asnber_schema_add_field(schema, seqId, &aField) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_set_root(schema, seqId) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);

        stream_t stream;
        asnber_reader_t reader;
        asnber_doc_t *doc = NULL;
        size_t consumed = 0;
        stream_init(&stream, kSeq, sizeof(kSeq), 2);
        reader_init(&reader, &stream);
        ASNBER_TEST_CHECK(asnber_decode_reader_with_schema(ctx, &reader, schema,
                                                       NULL, &doc,
                                                       &consumed) == ASNBER_OK);
        ASNBER_TEST_CHECK(consumed == sizeof(kSeq));
        const asnber_node_t *root = asnber_doc_root(doc);
        ASNBER_TEST_CHECK(root != NULL);
        ASNBER_TEST_CHECK(asnber_node_child_count(root) == 2);
        const asnber_node_t *child = asnber_node_child_at(root, 0);
        ASNBER_TEST_CHECK(child != NULL);
        ASNBER_TEST_CHECK(asnber_node_field_name(child) != NULL);
        ASNBER_TEST_CHECK(strcmp(asnber_node_field_name(child), "a") == 0);
        asnber_doc_destroy(doc);

        /* 严格路径拒绝未知字段。 */
        static const uint8_t kUnknown[8] = {0x30, 0x06, 0x02, 0x01,
                                            0x05, 0x04, 0x01, 0x00};
        stream_init(&stream, kUnknown, sizeof(kUnknown), 2);
        reader_init(&reader, &stream);
        doc = NULL;
        consumed = 123;
        asnber_decode_options_t options;
        asnber_decode_options_init(&options);
        options.flags = ASNBER_DECODE_STRICT_SCHEMA;
        ASNBER_TEST_CHECK(asnber_decode_reader_with_schema(ctx, &reader, schema,
                                                       &options, &doc,
                                                       &consumed) ==
                        ASNBER_E_SCHEMA_FIELD);
        ASNBER_TEST_CHECK(doc == NULL);
        ASNBER_TEST_CHECK(consumed == 123);

        /* COPY_INPUT 与 reader 同设：忽略。 */
        stream_init(&stream, kSeq, sizeof(kSeq), 1);
        reader_init(&reader, &stream);
        asnber_decode_options_init(&options);
        options.flags = ASNBER_DECODE_COPY_INPUT;
        doc = NULL;
        consumed = 0;
        ASNBER_TEST_CHECK(asnber_decode_reader_with_schema(ctx, &reader, schema,
                                                       &options, &doc,
                                                       &consumed) == ASNBER_OK);
        ASNBER_TEST_CHECK(consumed == sizeof(kSeq));
        asnber_doc_destroy(doc);

        asnber_schema_destroy(schema);
    }

    asnber_ctx_destroy(ctx);
    return 0;
}
