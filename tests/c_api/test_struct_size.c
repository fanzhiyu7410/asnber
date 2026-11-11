/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * 公共结构体 struct_size ABI 守卫。
 *
 * 对 8 个带 struct_size 的公共结构体，分别传入 0、sizeof-1、sizeof 与
 * sizeof+64：前两者与超大值必须被参数校验拒绝，只有精确的 sizeof 被接受。
 * 这能锁住“布局变化时调用方与库不一致”的故障边界，而不是依赖某个字段的
 * 偶然布局。
 */
#include <asnber/asnber.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "check.h"

static const uint8_t kBasic[] = {0x30, 0x03, 0x02, 0x01, 0x05};
static const uint8_t kUtcTime[] = {0x17, 0x0D, '2', '5', '0', '1', '0',
                                   '1', '0', '0', '0', '0', '0', '0', 'Z'};

struct read_state {
    const uint8_t *data;
    size_t size;
    size_t pos;
};

static asnber_err_t read_chunk(void *user, uint8_t *dst, size_t capacity,
                             size_t *out_size)
{
    struct read_state *state = (struct read_state *)user;
    const size_t remaining = state->size - state->pos;
    const size_t n = remaining < capacity ? remaining : capacity;
    if (n != 0) {
        memcpy(dst, state->data + state->pos, n);
    }
    state->pos += n;
    *out_size = n;
    return ASNBER_OK;
}

struct write_state {
    size_t calls;
    size_t bytes;
};

static asnber_err_t write_chunk(void *user, const uint8_t *data, size_t size)
{
    struct write_state *state = (struct write_state *)user;
    (void)data;
    state->calls += 1;
    state->bytes += size;
    return ASNBER_OK;
}

int main(void)
{
    asnber_ctx_config_t config;
    asnber_ctx_config_init(&config);

    /* 1. asnber_ctx_config_t：输入结构体。 */
    {
        static const size_t kBadSizes[] = {
            0, sizeof(asnber_ctx_config_t) - 1,
            sizeof(asnber_ctx_config_t) + 64};
        size_t i;
        for (i = 0; i < sizeof(kBadSizes) / sizeof(kBadSizes[0]); ++i) {
            asnber_ctx_config_t bad;
            asnber_ctx_t *out = NULL;
            asnber_ctx_config_init(&bad);
            bad.struct_size = kBadSizes[i];
            ASNBER_TEST_CHECK(asnber_ctx_create(&bad, &out) ==
                            ASNBER_E_INVALID_CONFIG);
            ASNBER_TEST_CHECK(out == NULL);
        }
    }

    asnber_ctx_t *ctx = NULL;
    ASNBER_TEST_CHECK(asnber_ctx_create(&config, &ctx) == ASNBER_OK);
    ASNBER_TEST_CHECK(ctx != NULL);

    /* 2. asnber_decode_options_t：输入结构体。 */
    {
        static const size_t kBadSizes[] = {
            0, sizeof(asnber_decode_options_t) - 1,
            sizeof(asnber_decode_options_t) + 64};
        size_t i;
        for (i = 0; i < sizeof(kBadSizes) / sizeof(kBadSizes[0]); ++i) {
            asnber_decode_options_t options;
            asnber_doc_t *doc = NULL;
            size_t consumed = 0;
            asnber_decode_options_init(&options);
            options.struct_size = kBadSizes[i];
            ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, kBasic, sizeof(kBasic),
                                               &options, &doc,
                                               &consumed) ==
                            ASNBER_E_INVALID_CONFIG);
            ASNBER_TEST_CHECK(doc == NULL);
        }
    }

    /* 3. asnber_error_info_t：输出结构体。 */
    {
        static const size_t kBadSizes[] = {
            0, sizeof(asnber_error_info_t) - 1,
            sizeof(asnber_error_info_t) + 64};
        size_t i;
        asnber_ctx_clear_error(ctx);
        for (i = 0; i < sizeof(kBadSizes) / sizeof(kBadSizes[0]); ++i) {
            asnber_error_info_t info;
            memset(&info, 0, sizeof(info));
            info.struct_size = kBadSizes[i];
            ASNBER_TEST_CHECK(asnber_ctx_get_error(ctx, &info) ==
                            ASNBER_E_INVALID_CONFIG);
        }
        asnber_error_info_t info;
        memset(&info, 0, sizeof(info));
        info.struct_size = sizeof(info);
        ASNBER_TEST_CHECK(asnber_ctx_get_error(ctx, &info) == ASNBER_OK);
    }

    /* 4. asnber_version_info_t：输出结构体。 */
    {
        static const size_t kBadSizes[] = {
            0, sizeof(asnber_version_info_t) - 1,
            sizeof(asnber_version_info_t) + 64};
        size_t i;
        for (i = 0; i < sizeof(kBadSizes) / sizeof(kBadSizes[0]); ++i) {
            asnber_version_info_t info;
            memset(&info, 0, sizeof(info));
            info.struct_size = kBadSizes[i];
            ASNBER_TEST_CHECK(asnber_version(&info) == ASNBER_E_INVALID_CONFIG);
        }
        asnber_version_info_t info;
        memset(&info, 0, sizeof(info));
        info.struct_size = sizeof(info);
        ASNBER_TEST_CHECK(asnber_version(&info) == ASNBER_OK);
        ASNBER_TEST_CHECK(info.major == ASNBER_VERSION_MAJOR);
        ASNBER_TEST_CHECK(info.minor == ASNBER_VERSION_MINOR);
        ASNBER_TEST_CHECK(info.patch == ASNBER_VERSION_PATCH);
        ASNBER_TEST_CHECK(info.string != NULL);
    }

    /* 5. asnber_encode_options_t：输入结构体。 */
    {
        asnber_doc_t *doc = NULL;
        size_t consumed = 0;
        ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, kBasic, sizeof(kBasic), NULL,
                                           &doc, &consumed) == ASNBER_OK);
        static const size_t kBadSizes[] = {
            0, sizeof(asnber_encode_options_t) - 1,
            sizeof(asnber_encode_options_t) + 64};
        size_t i;
        for (i = 0; i < sizeof(kBadSizes) / sizeof(kBadSizes[0]); ++i) {
            asnber_encode_options_t options;
            asnber_buf_t buf;
            asnber_encode_options_init(&options);
            options.struct_size = kBadSizes[i];
            memset(&buf, 0, sizeof(buf));
            ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, &options, &buf) ==
                            ASNBER_E_INVALID_CONFIG);
            ASNBER_TEST_CHECK(buf.data == NULL && buf.size == 0);
        }
        asnber_encode_options_t options;
        asnber_buf_t buf;
        asnber_encode_options_init(&options);
        memset(&buf, 0, sizeof(buf));
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, &options, &buf) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(buf.data != NULL && buf.size == sizeof(kBasic));
        ASNBER_TEST_CHECK(asnber_buf_release(ctx, &buf) == ASNBER_OK);
        asnber_doc_destroy(doc);
    }

    /* 6. asnber_writer_t：输入结构体。 */
    {
        asnber_doc_t *doc = NULL;
        size_t consumed = 0;
        ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, kBasic, sizeof(kBasic), NULL,
                                           &doc, &consumed) == ASNBER_OK);
        static const size_t kBadSizes[] = {
            0, sizeof(asnber_writer_t) - 1, sizeof(asnber_writer_t) + 64};
        size_t i;
        for (i = 0; i < sizeof(kBadSizes) / sizeof(kBadSizes[0]); ++i) {
            asnber_writer_t writer;
            struct write_state state;
            memset(&writer, 0, sizeof(writer));
            memset(&state, 0, sizeof(state));
            writer.struct_size = kBadSizes[i];
            writer.user = &state;
            writer.write = write_chunk;
            ASNBER_TEST_CHECK(asnber_encode_writer(ctx, doc, NULL, &writer) ==
                            ASNBER_E_INVALID_CONFIG);
            ASNBER_TEST_CHECK(state.calls == 0);
        }
        asnber_writer_t writer;
        struct write_state state;
        memset(&writer, 0, sizeof(writer));
        memset(&state, 0, sizeof(state));
        writer.struct_size = sizeof(writer);
        writer.user = &state;
        writer.write = write_chunk;
        ASNBER_TEST_CHECK(asnber_encode_writer(ctx, doc, NULL, &writer) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(state.calls == 1);
        ASNBER_TEST_CHECK(state.bytes == sizeof(kBasic));
        asnber_doc_destroy(doc);
    }

    /* 7. asnber_reader_t：输入结构体。 */
    {
        static const size_t kBadSizes[] = {
            0, sizeof(asnber_reader_t) - 1, sizeof(asnber_reader_t) + 64};
        size_t i;
        for (i = 0; i < sizeof(kBadSizes) / sizeof(kBadSizes[0]); ++i) {
            asnber_reader_t reader;
            struct read_state state = {kBasic, sizeof(kBasic), 0};
            asnber_doc_t *doc = NULL;
            size_t consumed = 0;
            memset(&reader, 0, sizeof(reader));
            reader.struct_size = kBadSizes[i];
            reader.user = &state;
            reader.read = read_chunk;
            ASNBER_TEST_CHECK(asnber_decode_reader(ctx, &reader, NULL, &doc,
                                               &consumed) ==
                            ASNBER_E_INVALID_CONFIG);
            ASNBER_TEST_CHECK(doc == NULL);
            ASNBER_TEST_CHECK(state.pos == 0);
        }
        asnber_reader_t reader;
        struct read_state state = {kBasic, sizeof(kBasic), 0};
        asnber_doc_t *doc = NULL;
        size_t consumed = 0;
        memset(&reader, 0, sizeof(reader));
        reader.struct_size = sizeof(reader);
        reader.user = &state;
        reader.read = read_chunk;
        ASNBER_TEST_CHECK(asnber_decode_reader(ctx, &reader, NULL, &doc,
                                           &consumed) == ASNBER_OK);
        ASNBER_TEST_CHECK(doc != NULL);
        ASNBER_TEST_CHECK(consumed == sizeof(kBasic));
        asnber_doc_destroy(doc);
    }

    /* 8. asnber_time_t：输出结构体。 */
    {
        asnber_doc_t *doc = NULL;
        size_t consumed = 0;
        ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, kUtcTime, sizeof(kUtcTime),
                                           NULL, &doc, &consumed) == ASNBER_OK);
        const asnber_node_t *root = asnber_doc_root(doc);
        static const size_t kBadSizes[] = {
            0, sizeof(asnber_time_t) - 1, sizeof(asnber_time_t) + 64};
        size_t i;
        for (i = 0; i < sizeof(kBadSizes) / sizeof(kBadSizes[0]); ++i) {
            asnber_time_t time;
            memset(&time, 0, sizeof(time));
            time.struct_size = kBadSizes[i];
            ASNBER_TEST_CHECK(asnber_node_get_time(root, &time) ==
                            ASNBER_E_INVALID_CONFIG);
        }
        asnber_time_t time;
        memset(&time, 0, sizeof(time));
        time.struct_size = sizeof(time);
        ASNBER_TEST_CHECK(asnber_node_get_time(root, &time) == ASNBER_OK);
        ASNBER_TEST_CHECK(time.year == 2025);
        ASNBER_TEST_CHECK(time.month == 1);
        ASNBER_TEST_CHECK(time.day == 1);
        ASNBER_TEST_CHECK(time.hour == 0);
        ASNBER_TEST_CHECK(time.minute == 0);
        ASNBER_TEST_CHECK(time.second == 0);
        asnber_doc_destroy(doc);
    }

    asnber_ctx_destroy(ctx);
    return 0;
}
