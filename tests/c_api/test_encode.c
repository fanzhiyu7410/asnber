/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * 编码器 C API：缓冲与 writer 两种出口、通用 DER 规范化、输出预算、
 * writer 失败包装、输出缓冲所有权与 schema 拒绝路径。
 */
#include <asnber/asnber.h>

#include <stddef.h>
#include <string.h>

#include "check.h"
#include "test_compare.h"

/* ---------- 辅助 ---------- */

typedef struct writer_state {
    uint8_t bytes[256];
    size_t size;
    size_t calls;
    asnber_err_t result;
} writer_state_t;

static asnber_err_t capture_write(void *user, const uint8_t *data, size_t size)
{
    writer_state_t *state = (writer_state_t *)user;
    state->calls += 1;
    if (size > sizeof(state->bytes) - state->size) {
        return (asnber_err_t)99;
    }
    memcpy(state->bytes + state->size, data, size);
    state->size += size;
    return state->result;
}

/* 创建文档并建立根节点。 */
static asnber_err_t open_doc(asnber_ctx_t *ctx, asnber_doc_t **out_doc,
                           asnber_node_t **out_root,
                           asnber_tag_class_t tag_class, uint32_t tag_number,
                           int constructed)
{
    asnber_doc_t *doc = NULL;
    asnber_err_t rc = asnber_doc_create(ctx, &doc);
    if (rc != ASNBER_OK) {
        return rc;
    }
    asnber_node_t *root = NULL;
    rc = asnber_node_create(doc, NULL, tag_class, tag_number, constructed, &root);
    if (rc != ASNBER_OK) {
        asnber_doc_destroy(doc);
        return rc;
    }
    *out_doc = doc;
    *out_root = root;
    return ASNBER_OK;
}

static asnber_err_t add_child(asnber_doc_t *doc, asnber_node_t *parent,
                            asnber_tag_class_t tag_class, uint32_t tag_number,
                            int constructed, asnber_node_t **out_node)
{
    return asnber_node_create(doc, parent, tag_class, tag_number, constructed,
                            out_node);
}

int main(void)
{
    /* ---------- 选项初始化 ---------- */
    asnber_encode_options_t options;
    asnber_encode_options_init(&options);
    ASNBER_TEST_CHECK(options.struct_size == sizeof(asnber_encode_options_t));
    ASNBER_TEST_CHECK(options.encoding == ASNBER_ENCODING_DER);
    ASNBER_TEST_CHECK(options.schema == NULL);
    ASNBER_TEST_CHECK(options.flags == 0);
    ASNBER_TEST_CHECK(options.reserved[0] == 0 && options.reserved[1] == 0 &&
                    options.reserved[2] == 0 && options.reserved[3] == 0);

    asnber_ctx_config_t config;
    asnber_ctx_config_init(&config);
    asnber_ctx_t *ctx = NULL;
    ASNBER_TEST_CHECK(asnber_ctx_create(&config, &ctx) == ASNBER_OK);

    asnber_buf_t buf;
    buf.data = NULL;
    buf.size = 0;
    buf.capacity = 0;

    /* ---------- 空文档 / 未封存 ---------- */
    asnber_doc_t *doc = NULL;
    ASNBER_TEST_CHECK(asnber_doc_create(ctx, &doc) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, NULL, &buf) ==
                    ASNBER_E_INVALID_STATE);
    ASNBER_TEST_CHECK(buf.data == NULL && buf.size == 0 && buf.capacity == 0);
    ASNBER_TEST_CHECK(asnber_doc_seal(doc) == ASNBER_E_INVALID_STATE);
    asnber_doc_destroy(doc);

    /* ---------- 单节点各类型 ---------- */
    {
        static const uint8_t expected[] = {0x02, 0x01, 0x05};
        asnber_node_t *root = NULL;
        ASNBER_TEST_CHECK(open_doc(ctx, &doc, &root, ASNBER_TAG_UNIVERSAL, 2, 0) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_set_int64(root, 5) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_doc_seal(doc) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, NULL, &buf) == ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(buf.data, buf.size, expected,
                                    sizeof(expected)));
        ASNBER_TEST_CHECK(asnber_buf_release(ctx, &buf) == ASNBER_OK);
        ASNBER_TEST_CHECK(buf.data == NULL && buf.size == 0 && buf.capacity == 0);
        asnber_doc_destroy(doc);
    }

    {
        /* INTEGER -1：负值最短补码。 */
        static const uint8_t expected[] = {0x02, 0x01, 0xFF};
        asnber_node_t *root = NULL;
        ASNBER_TEST_CHECK(open_doc(ctx, &doc, &root, ASNBER_TAG_UNIVERSAL, 2, 0) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_set_int64(root, -1) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_doc_seal(doc) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, NULL, &buf) == ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(buf.data, buf.size, expected,
                                    sizeof(expected)));
        ASNBER_TEST_CHECK(asnber_buf_release(ctx, &buf) == ASNBER_OK);
        asnber_doc_destroy(doc);
    }

    {
        /* BOOLEAN FALSE / TRUE：set_bool 写出 0x00 / 0xFF。 */
        static const uint8_t false_bytes[] = {0x01, 0x01, 0x00};
        static const uint8_t true_bytes[] = {0x01, 0x01, 0xFF};
        asnber_node_t *root = NULL;
        ASNBER_TEST_CHECK(open_doc(ctx, &doc, &root, ASNBER_TAG_UNIVERSAL, 1, 0) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_set_bool(root, 0) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_doc_seal(doc) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, NULL, &buf) == ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(buf.data, buf.size, false_bytes,
                                    sizeof(false_bytes)));
        ASNBER_TEST_CHECK(asnber_buf_release(ctx, &buf) == ASNBER_OK);
        asnber_doc_destroy(doc);

        ASNBER_TEST_CHECK(open_doc(ctx, &doc, &root, ASNBER_TAG_UNIVERSAL, 1, 0) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_set_bool(root, 1) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_doc_seal(doc) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, NULL, &buf) == ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(buf.data, buf.size, true_bytes,
                                    sizeof(true_bytes)));
        ASNBER_TEST_CHECK(asnber_buf_release(ctx, &buf) == ASNBER_OK);
        asnber_doc_destroy(doc);
    }

    {
        /* 空 OCTET STRING 与两字节 OCTET STRING。 */
        static const uint8_t empty_bytes[] = {0x04, 0x00};
        static const uint8_t two_bytes[] = {0x04, 0x02, 0xAB, 0xCD};
        static const uint8_t payload[] = {0xAB, 0xCD};
        asnber_node_t *root = NULL;
        ASNBER_TEST_CHECK(open_doc(ctx, &doc, &root, ASNBER_TAG_UNIVERSAL, 4, 0) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_set_content(root, NULL, 0) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_doc_seal(doc) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, NULL, &buf) == ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(buf.data, buf.size, empty_bytes,
                                    sizeof(empty_bytes)));
        ASNBER_TEST_CHECK(asnber_buf_release(ctx, &buf) == ASNBER_OK);
        asnber_doc_destroy(doc);

        ASNBER_TEST_CHECK(open_doc(ctx, &doc, &root, ASNBER_TAG_UNIVERSAL, 4, 0) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_set_content(root, payload,
                                              sizeof(payload)) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_doc_seal(doc) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, NULL, &buf) == ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(buf.data, buf.size, two_bytes,
                                    sizeof(two_bytes)));
        ASNBER_TEST_CHECK(asnber_buf_release(ctx, &buf) == ASNBER_OK);
        asnber_doc_destroy(doc);
    }

    {
        /* BIT STRING：内容首字节为 unused-bits 计数。 */
        static const uint8_t content[] = {0x04, 0xA0};
        static const uint8_t expected[] = {0x03, 0x02, 0x04, 0xA0};
        asnber_node_t *root = NULL;
        ASNBER_TEST_CHECK(open_doc(ctx, &doc, &root, ASNBER_TAG_UNIVERSAL, 3, 0) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_set_content(root, content,
                                              sizeof(content)) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_doc_seal(doc) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, NULL, &buf) == ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(buf.data, buf.size, expected,
                                    sizeof(expected)));
        ASNBER_TEST_CHECK(asnber_buf_release(ctx, &buf) == ASNBER_OK);
        asnber_doc_destroy(doc);
    }

    {
        /* OID 2.5.4.3 与 UTF8String。 */
        static const uint8_t oid_bytes[] = {0x06, 0x03, 0x55, 0x04, 0x03};
        static const uint8_t utf8_bytes[] = {0x0C, 0x03, 0xE4, 0xB8, 0xAD};
        asnber_node_t *root = NULL;
        ASNBER_TEST_CHECK(open_doc(ctx, &doc, &root, ASNBER_TAG_UNIVERSAL, 6, 0) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_set_oid(root, "2.5.4.3") == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_doc_seal(doc) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, NULL, &buf) == ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(buf.data, buf.size, oid_bytes,
                                    sizeof(oid_bytes)));
        ASNBER_TEST_CHECK(asnber_buf_release(ctx, &buf) == ASNBER_OK);
        asnber_doc_destroy(doc);

        ASNBER_TEST_CHECK(open_doc(ctx, &doc, &root, ASNBER_TAG_UNIVERSAL, 12, 0) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_set_utf8(root, "\xE4\xB8\xAD", 3) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_doc_seal(doc) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, NULL, &buf) == ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(buf.data, buf.size, utf8_bytes,
                                    sizeof(utf8_bytes)));
        ASNBER_TEST_CHECK(asnber_buf_release(ctx, &buf) == ASNBER_OK);
        asnber_doc_destroy(doc);
    }

    {
        /* UTCTime：13 字节内容原样写出。 */
        static const char text[] = "990101000000Z";
        static const uint8_t expected[] = {0x17, 0x0D, 0x39, 0x39, 0x30, 0x31,
                                           0x30, 0x31, 0x30, 0x30, 0x30, 0x30,
                                           0x30, 0x30, 0x5A};
        asnber_node_t *root = NULL;
        ASNBER_TEST_CHECK(open_doc(ctx, &doc, &root, ASNBER_TAG_UNIVERSAL, 23, 0) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_set_content(
                            root, (const uint8_t *)text, sizeof(text) - 1) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_doc_seal(doc) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, NULL, &buf) == ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(buf.data, buf.size, expected,
                                    sizeof(expected)));
        ASNBER_TEST_CHECK(asnber_buf_release(ctx, &buf) == ASNBER_OK);
        asnber_doc_destroy(doc);
    }

    /* ---------- 嵌套与 SET 排序 ---------- */
    {
        /* SET 子元素按标签升序：文档顺序 INTEGER(2) 先、BOOLEAN(1) 后。 */
        static const uint8_t expected[] = {0x31, 0x06, 0x01, 0x01,
                                           0xFF, 0x02, 0x01, 0x05};
        asnber_node_t *root = NULL;
        asnber_node_t *child = NULL;
        ASNBER_TEST_CHECK(open_doc(ctx, &doc, &root, ASNBER_TAG_UNIVERSAL, 17, 1) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(add_child(doc, root, ASNBER_TAG_UNIVERSAL, 2, 0,
                                  &child) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_set_int64(child, 5) == ASNBER_OK);
        ASNBER_TEST_CHECK(add_child(doc, root, ASNBER_TAG_UNIVERSAL, 1, 0,
                                  &child) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_set_bool(child, 1) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_doc_seal(doc) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, NULL, &buf) == ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(buf.data, buf.size, expected,
                                    sizeof(expected)));
        ASNBER_TEST_CHECK(asnber_buf_release(ctx, &buf) == ASNBER_OK);
        asnber_doc_destroy(doc);
    }

    {
        /* SET OF 同标签元素按编码字节字典序。 */
        static const uint8_t expected[] = {
            0x31, 0x09, 0x04, 0x01, 0x61, 0x04, 0x01,
            0x62, 0x04, 0x01, 0x63};
        static const uint8_t value_b[] = {0x62};
        static const uint8_t value_a[] = {0x61};
        static const uint8_t value_c[] = {0x63};
        asnber_node_t *root = NULL;
        asnber_node_t *child = NULL;
        ASNBER_TEST_CHECK(open_doc(ctx, &doc, &root, ASNBER_TAG_UNIVERSAL, 17, 1) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(add_child(doc, root, ASNBER_TAG_UNIVERSAL, 4, 0,
                                  &child) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_set_content(child, value_b, 1) == ASNBER_OK);
        ASNBER_TEST_CHECK(add_child(doc, root, ASNBER_TAG_UNIVERSAL, 4, 0,
                                  &child) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_set_content(child, value_a, 1) == ASNBER_OK);
        ASNBER_TEST_CHECK(add_child(doc, root, ASNBER_TAG_UNIVERSAL, 4, 0,
                                  &child) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_set_content(child, value_c, 1) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_doc_seal(doc) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, NULL, &buf) == ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(buf.data, buf.size, expected,
                                    sizeof(expected)));
        ASNBER_TEST_CHECK(asnber_buf_release(ctx, &buf) == ASNBER_OK);
        asnber_doc_destroy(doc);
    }

    {
        /* SET OF 相同元素：比较相等时保持输入顺序。 */
        static const uint8_t expected[] = {0x31, 0x06, 0x04, 0x01, 0x41,
                                           0x04, 0x01, 0x41};
        static const uint8_t value[] = {0x41};
        asnber_node_t *root = NULL;
        asnber_node_t *child = NULL;
        ASNBER_TEST_CHECK(open_doc(ctx, &doc, &root, ASNBER_TAG_UNIVERSAL, 17, 1) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(add_child(doc, root, ASNBER_TAG_UNIVERSAL, 4, 0,
                                  &child) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_set_content(child, value, 1) == ASNBER_OK);
        ASNBER_TEST_CHECK(add_child(doc, root, ASNBER_TAG_UNIVERSAL, 4, 0,
                                  &child) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_set_content(child, value, 1) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_doc_seal(doc) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, NULL, &buf) == ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(buf.data, buf.size, expected,
                                    sizeof(expected)));
        ASNBER_TEST_CHECK(asnber_buf_release(ctx, &buf) == ASNBER_OK);
        asnber_doc_destroy(doc);
    }

    {
        /* 空 SET OF：只写标签与零长度。 */
        static const uint8_t expected[] = {0x31, 0x00};
        asnber_node_t *root = NULL;
        ASNBER_TEST_CHECK(open_doc(ctx, &doc, &root, ASNBER_TAG_UNIVERSAL, 17, 1) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_doc_seal(doc) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, NULL, &buf) == ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(buf.data, buf.size, expected,
                                    sizeof(expected)));
        ASNBER_TEST_CHECK(asnber_buf_release(ctx, &buf) == ASNBER_OK);
        asnber_doc_destroy(doc);
    }

    {
        /* 两层嵌套 SEQUENCE，且高标签号（context 40）按多字节标签写出。 */
        static const uint8_t expected[] = {0x30, 0x08, 0x30, 0x03, 0x02, 0x01,
                                           0x05, 0x9F, 0x28, 0x00};
        asnber_node_t *root = NULL;
        asnber_node_t *inner = NULL;
        asnber_node_t *leaf = NULL;
        ASNBER_TEST_CHECK(open_doc(ctx, &doc, &root, ASNBER_TAG_UNIVERSAL, 16, 1) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(add_child(doc, root, ASNBER_TAG_UNIVERSAL, 16, 1,
                                  &inner) == ASNBER_OK);
        ASNBER_TEST_CHECK(add_child(doc, inner, ASNBER_TAG_UNIVERSAL, 2, 0,
                                  &leaf) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_set_int64(leaf, 5) == ASNBER_OK);
        ASNBER_TEST_CHECK(add_child(doc, root, ASNBER_TAG_CONTEXT, 40, 0,
                                  &leaf) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_set_content(leaf, NULL, 0) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_doc_seal(doc) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, NULL, &buf) == ASNBER_OK);
        ASNBER_TEST_CHECK(bytes_equal(buf.data, buf.size, expected,
                                    sizeof(expected)));
        ASNBER_TEST_CHECK(asnber_buf_release(ctx, &buf) == ASNBER_OK);
        asnber_doc_destroy(doc);
    }

    /* ---------- writer 出口 ---------- */
    {
        writer_state_t state;
        memset(&state, 0, sizeof(state));
        state.result = ASNBER_OK;
        asnber_writer_t writer;
        writer.struct_size = sizeof(asnber_writer_t);
        writer.user = &state;
        writer.write = capture_write;

        asnber_node_t *root = NULL;
        ASNBER_TEST_CHECK(open_doc(ctx, &doc, &root, ASNBER_TAG_UNIVERSAL, 2, 0) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_set_int64(root, 5) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_doc_seal(doc) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_encode_writer(ctx, doc, NULL, &writer) == ASNBER_OK);
        ASNBER_TEST_CHECK(state.calls == 1);
        ASNBER_TEST_CHECK(state.size == 3);
        ASNBER_TEST_CHECK(state.bytes[0] == 0x02 && state.bytes[1] == 0x01 &&
                        state.bytes[2] == 0x05);
        asnber_doc_destroy(doc);
    }

    {
        /* writer 失败：包装为 IO_WRITE，原始码进 callback_code。 */
        writer_state_t state;
        memset(&state, 0, sizeof(state));
        state.result = (asnber_err_t)7;
        asnber_writer_t writer;
        writer.struct_size = sizeof(asnber_writer_t);
        writer.user = &state;
        writer.write = capture_write;

        asnber_node_t *root = NULL;
        ASNBER_TEST_CHECK(open_doc(ctx, &doc, &root, ASNBER_TAG_UNIVERSAL, 2, 0) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_set_int64(root, 5) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_doc_seal(doc) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_encode_writer(ctx, doc, NULL, &writer) ==
                        ASNBER_E_IO_WRITE);
        asnber_error_info_t info;
        info.struct_size = sizeof(info);
        ASNBER_TEST_CHECK(asnber_ctx_get_error(ctx, &info) == ASNBER_OK);
        ASNBER_TEST_CHECK(info.code == ASNBER_E_IO_WRITE);
        ASNBER_TEST_CHECK(info.callback_code == 7);
        /* 单次回调失败：未确认接收任何字节，offset 固定记 0。 */
        ASNBER_TEST_CHECK(info.offset == 0);
        ASNBER_TEST_CHECK(state.calls == 1);
        asnber_doc_destroy(doc);
    }

    {
        /* writer 结构尺寸错误 / 空 writer / 空回调。 */
        writer_state_t state;
        memset(&state, 0, sizeof(state));
        asnber_writer_t writer;
        writer.struct_size = 0;
        writer.user = &state;
        writer.write = capture_write;
        asnber_node_t *root = NULL;
        ASNBER_TEST_CHECK(open_doc(ctx, &doc, &root, ASNBER_TAG_UNIVERSAL, 2, 0) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_set_int64(root, 5) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_doc_seal(doc) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_encode_writer(ctx, doc, NULL, &writer) ==
                        ASNBER_E_INVALID_CONFIG);
        ASNBER_TEST_CHECK(asnber_encode_writer(ctx, doc, NULL, NULL) ==
                        ASNBER_E_INVALID_ARG);
        writer.struct_size = sizeof(asnber_writer_t);
        writer.write = NULL;
        ASNBER_TEST_CHECK(asnber_encode_writer(ctx, doc, NULL, &writer) ==
                        ASNBER_E_INVALID_ARG);
        asnber_doc_destroy(doc);
    }

    /* ---------- 参数与选项校验 ---------- */
    {
        asnber_node_t *root = NULL;
        ASNBER_TEST_CHECK(open_doc(ctx, &doc, &root, ASNBER_TAG_UNIVERSAL, 2, 0) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_set_int64(root, 5) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_doc_seal(doc) == ASNBER_OK);

        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, NULL, NULL) ==
                        ASNBER_E_INVALID_ARG);
        ASNBER_TEST_CHECK(asnber_encode_buffer(NULL, doc, NULL, &buf) ==
                        ASNBER_E_INVALID_ARG);
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, NULL, NULL, &buf) ==
                        ASNBER_E_INVALID_ARG);

        asnber_encode_options_init(&options);
        options.struct_size = 0;
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, &options, &buf) ==
                        ASNBER_E_INVALID_CONFIG);
        asnber_encode_options_init(&options);
        options.reserved[0] = 1;
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, &options, &buf) ==
                        ASNBER_E_INVALID_CONFIG);
        asnber_encode_options_init(&options);
        options.flags = 1;
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, &options, &buf) ==
                        ASNBER_E_INVALID_CONFIG);
        asnber_encode_options_init(&options);
        options.encoding = ASNBER_ENCODING_BER;
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, &options, &buf) ==
                        ASNBER_E_UNSUPPORTED_ENCODING);
        asnber_encode_options_init(&options);
        options.encoding = ASNBER_ENCODING_CER;
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, &options, &buf) ==
                        ASNBER_E_UNSUPPORTED_ENCODING);
        asnber_encode_options_init(&options);
        options.encoding = ASNBER_ENCODING_NONE;
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, &options, &buf) ==
                        ASNBER_E_UNSUPPORTED_ENCODING);

        /* 未封存 schema 明确拒绝；已封存但没有根类型同样拒绝。 */
        asnber_schema_t *schema = NULL;
        ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                           &schema) == ASNBER_OK);
        asnber_encode_options_init(&options);
        options.schema = schema;
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, &options, &buf) ==
                        ASNBER_E_INVALID_STATE);
        ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, &options, &buf) ==
                        ASNBER_E_INVALID_STATE);
        ASNBER_TEST_CHECK(buf.data == NULL && buf.size == 0);
        asnber_schema_destroy(schema);

        /* 其他上下文的文档不可编码。 */
        asnber_ctx_config_t other_config;
        asnber_ctx_config_init(&other_config);
        asnber_ctx_t *other = NULL;
        ASNBER_TEST_CHECK(asnber_ctx_create(&other_config, &other) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_encode_buffer(other, doc, NULL, &buf) ==
                        ASNBER_E_INVALID_ARG);
        ASNBER_TEST_CHECK(asnber_encode_writer(other, doc, NULL, NULL) ==
                        ASNBER_E_INVALID_ARG);
        asnber_ctx_destroy(other);

        asnber_doc_destroy(doc);
    }

    /* ---------- 输出预算 ---------- */
    {
        asnber_ctx_config_t small_config;
        asnber_ctx_config_init(&small_config);
        small_config.max_output_bytes = 5;
        asnber_ctx_t *small = NULL;
        ASNBER_TEST_CHECK(asnber_ctx_create(&small_config, &small) == ASNBER_OK);

        /* 恰好 5 字节：30 03 02 01 05。 */
        asnber_node_t *root = NULL;
        asnber_node_t *leaf = NULL;
        ASNBER_TEST_CHECK(open_doc(small, &doc, &root, ASNBER_TAG_UNIVERSAL, 16,
                                 1) == ASNBER_OK);
        ASNBER_TEST_CHECK(add_child(doc, root, ASNBER_TAG_UNIVERSAL, 2, 0,
                                  &leaf) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_set_int64(leaf, 5) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_doc_seal(doc) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_encode_buffer(small, doc, NULL, &buf) == ASNBER_OK);
        ASNBER_TEST_CHECK(buf.size == 5);
        ASNBER_TEST_CHECK(asnber_buf_release(small, &buf) == ASNBER_OK);
        asnber_doc_destroy(doc);

        /* 两个子节点：8 字节，超过 5 字节预算。 */
        ASNBER_TEST_CHECK(open_doc(small, &doc, &root, ASNBER_TAG_UNIVERSAL, 16,
                                 1) == ASNBER_OK);
        ASNBER_TEST_CHECK(add_child(doc, root, ASNBER_TAG_UNIVERSAL, 2, 0,
                                  &leaf) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_set_int64(leaf, 5) == ASNBER_OK);
        ASNBER_TEST_CHECK(add_child(doc, root, ASNBER_TAG_UNIVERSAL, 2, 0,
                                  &leaf) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_set_int64(leaf, 6) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_doc_seal(doc) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_encode_buffer(small, doc, NULL, &buf) ==
                        ASNBER_E_OUTPUT_LIMIT);
        ASNBER_TEST_CHECK(buf.data == NULL && buf.size == 0 && buf.capacity == 0);
        asnber_error_info_t info;
        info.struct_size = sizeof(info);
        ASNBER_TEST_CHECK(asnber_ctx_get_error(small, &info) == ASNBER_OK);
        ASNBER_TEST_CHECK(info.code == ASNBER_E_OUTPUT_LIMIT);
        asnber_doc_destroy(doc);

        asnber_ctx_destroy(small);
    }

    /* ---------- 输出缓冲所有权 ---------- */
    {
        asnber_node_t *root = NULL;
        ASNBER_TEST_CHECK(open_doc(ctx, &doc, &root, ASNBER_TAG_UNIVERSAL, 2, 0) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_node_set_int64(root, 5) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_doc_seal(doc) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, NULL, &buf) == ASNBER_OK);
        asnber_doc_destroy(doc);

        /* 跨上下文释放：返回 INVALID_ARG 且不修改缓冲。 */
        asnber_ctx_config_t other_config;
        asnber_ctx_config_init(&other_config);
        asnber_ctx_t *other = NULL;
        ASNBER_TEST_CHECK(asnber_ctx_create(&other_config, &other) == ASNBER_OK);
        uint8_t *data_before = buf.data;
        size_t size_before = buf.size;
        size_t capacity_before = buf.capacity;
        ASNBER_TEST_CHECK(asnber_buf_release(other, &buf) == ASNBER_E_INVALID_ARG);
        ASNBER_TEST_CHECK(buf.data == data_before);
        ASNBER_TEST_CHECK(buf.size == size_before);
        ASNBER_TEST_CHECK(buf.capacity == capacity_before);
        ASNBER_TEST_CHECK(asnber_buf_release(NULL, &buf) == ASNBER_E_INVALID_ARG);
        asnber_ctx_destroy(other);

        /* 正确上下文释放后置零；再次释放为空操作。 */
        ASNBER_TEST_CHECK(asnber_buf_release(ctx, &buf) == ASNBER_OK);
        ASNBER_TEST_CHECK(buf.data == NULL && buf.size == 0 && buf.capacity == 0);
        ASNBER_TEST_CHECK(asnber_buf_release(ctx, &buf) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_buf_release(ctx, NULL) == ASNBER_OK);
    }

    asnber_ctx_destroy(ctx);
    return 0;
}
