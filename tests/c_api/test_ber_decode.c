/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * BER 解码最小闭环：合法 TLV、嵌套、截断、长度越界、深度超限、尾随拒绝、
 * COPY_INPUT 生命周期与错误详情。
 */
#include <asnber/asnber.h>

#include <stddef.h>
#include <string.h>

#include "check.h"

int main(void)
{
    asnber_ctx_config_t config;
    asnber_ctx_config_init(&config);
    asnber_ctx_t *ctx = NULL;
    ASNBER_TEST_CHECK(asnber_ctx_create(&config, &ctx) == ASNBER_OK);

    /* 单层 SEQUENCE + INTEGER。 */
    static const uint8_t basic[] = {0x30, 0x03, 0x02, 0x01, 0x05};
    asnber_doc_t *doc = NULL;
    size_t consumed = 0;
    ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, basic, sizeof(basic), NULL, &doc,
                                       &consumed) == ASNBER_OK);
    ASNBER_TEST_CHECK(doc != NULL);
    ASNBER_TEST_CHECK(consumed == sizeof(basic));
    const asnber_node_t *root = asnber_doc_root(doc);
    ASNBER_TEST_CHECK(root != NULL);
    ASNBER_TEST_CHECK(asnber_node_tag_number(root) == 16);
    ASNBER_TEST_CHECK(asnber_node_child_count(root) == 1);
    const asnber_node_t *child = asnber_node_child_at(root, 0);
    ASNBER_TEST_CHECK(child != NULL);
    ASNBER_TEST_CHECK(asnber_node_tag_number(child) == 2);
    ASNBER_TEST_CHECK(asnber_node_parent(child) == root);
    ASNBER_TEST_CHECK(asnber_node_offset(child) == 2);
    size_t tlv_size = 0;
    const uint8_t *tlv = asnber_node_tlv(child, &tlv_size);
    ASNBER_TEST_CHECK(tlv == basic + 2);
    ASNBER_TEST_CHECK(tlv_size == 3);
    const uint8_t *content = NULL;
    size_t content_size = 0;
    ASNBER_TEST_CHECK(asnber_node_content(child, &content, &content_size) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(content_size == 1);
    ASNBER_TEST_CHECK(content == basic + 4);
    int64_t int_value = 0;
    ASNBER_TEST_CHECK(asnber_node_get_int64(child, &int_value) == ASNBER_OK);
    ASNBER_TEST_CHECK(int_value == 5);
    asnber_doc_destroy(doc);

    /* 嵌套两层。 */
    static const uint8_t nested[] = {0x30, 0x05, 0x30, 0x03,
                                     0x02, 0x01, 0x05};
    ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, nested, sizeof(nested), NULL, &doc,
                                       &consumed) == ASNBER_OK);
    ASNBER_TEST_CHECK(consumed == sizeof(nested));
    root = asnber_doc_root(doc);
    child = asnber_node_child_at(root, 0);
    ASNBER_TEST_CHECK(child != NULL);
    const asnber_node_t *grandchild = asnber_node_child_at(child, 0);
    ASNBER_TEST_CHECK(grandchild != NULL);
    ASNBER_TEST_CHECK(asnber_node_tag_number(grandchild) == 2);
    asnber_doc_destroy(doc);

    /* 截断：内容长度越过输入末尾。 */
    static const uint8_t truncated[] = {0x30, 0x05, 0x02, 0x01};
    consumed = 1234;
    doc = NULL;
    ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, truncated, sizeof(truncated), NULL,
                                       &doc, &consumed) == ASNBER_E_TRUNCATED);
    ASNBER_TEST_CHECK(doc == NULL);
    ASNBER_TEST_CHECK(consumed == 1234);

    asnber_error_info_t info;
    info.struct_size = sizeof(info);
    ASNBER_TEST_CHECK(asnber_ctx_get_error(ctx, &info) == ASNBER_OK);
    ASNBER_TEST_CHECK(info.code == ASNBER_E_TRUNCATED);
    ASNBER_TEST_CHECK(info.message != NULL);
    ASNBER_TEST_CHECK(info.callback_code == 0);
    ASNBER_TEST_CHECK(info.offset == 4);
    ASNBER_TEST_CHECK(info.depth == 0);
    ASNBER_TEST_CHECK(info.path == NULL);
    asnber_ctx_clear_error(ctx);
    info.struct_size = sizeof(info);
    ASNBER_TEST_CHECK(asnber_ctx_get_error(ctx, &info) == ASNBER_OK);
    ASNBER_TEST_CHECK(info.code == ASNBER_OK);
    ASNBER_TEST_CHECK(info.offset == SIZE_MAX);

    /* 长度八位组过多。 */
    static const uint8_t bad_length[] = {0x30, 0x89};
    ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, bad_length, sizeof(bad_length),
                                       NULL, &doc, &consumed) ==
                    ASNBER_E_MALFORMED_LENGTH);

    /* 声明长度越界但八位组合法。 */
    static const uint8_t huge_length[] = {0x30, 0x82, 0xFF, 0xFF};
    ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, huge_length, sizeof(huge_length),
                                       NULL, &doc, &consumed) ==
                    ASNBER_E_TRUNCATED);

    /* 多字节 tag number 已支持。 */
    static const uint8_t high_tag[] = {0x9F, 0x28, 0x00};
    ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, high_tag, sizeof(high_tag), NULL,
                                       &doc, &consumed) == ASNBER_OK);
    ASNBER_TEST_CHECK(doc != NULL);
    ASNBER_TEST_CHECK(asnber_node_tag_class(asnber_doc_root(doc)) ==
                    ASNBER_TAG_CONTEXT);
    ASNBER_TEST_CHECK(asnber_node_tag_number(asnber_doc_root(doc)) == 40);
    asnber_doc_destroy(doc);

    /* 5 字节 base-128 tag number 溢出 uint32_t：在首个越界继续字节处报错。
     * 0x9F 后的第 5 个继续字节（下标 5）使 value 超过 UINT32_MAX。 */
    static const uint8_t overflow_tag[] = {0x9F, 0x90, 0x80,
                                           0x80, 0x80, 0x80};
    doc = NULL;
    ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, overflow_tag, sizeof(overflow_tag),
                                       NULL, &doc, &consumed) ==
                    ASNBER_E_MALFORMED_TAG);
    ASNBER_TEST_CHECK(doc == NULL);
    info.struct_size = sizeof(info);
    ASNBER_TEST_CHECK(asnber_ctx_get_error(ctx, &info) == ASNBER_OK);
    ASNBER_TEST_CHECK(info.code == ASNBER_E_MALFORMED_TAG);
    ASNBER_TEST_CHECK(info.offset == 5);
    asnber_ctx_clear_error(ctx);

    /* BER 不定长：单层、嵌套、TLV 含 EOC。 */
    static const uint8_t indefinite[] = {0x30, 0x80, 0x02, 0x01,
                                         0x05, 0x00, 0x00};
    ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, indefinite, sizeof(indefinite),
                                       NULL, &doc, &consumed) == ASNBER_OK);
    ASNBER_TEST_CHECK(doc != NULL);
    ASNBER_TEST_CHECK(asnber_node_is_indefinite(asnber_doc_root(doc)) == 1);
    ASNBER_TEST_CHECK(asnber_node_child_count(asnber_doc_root(doc)) == 1);
    ASNBER_TEST_CHECK(asnber_node_tag_number(asnber_node_child_at(
                        asnber_doc_root(doc), 0)) == 2);
    {
        size_t tlv_size = 0;
        ASNBER_TEST_CHECK(asnber_node_tlv(asnber_doc_root(doc), &tlv_size) != NULL);
        ASNBER_TEST_CHECK(tlv_size == sizeof(indefinite));
    }
    asnber_doc_destroy(doc);

    static const uint8_t nested_indefinite[] = {
        0x30, 0x80, 0x02, 0x01, 0x05, 0x30, 0x80,
        0x02, 0x01, 0x06, 0x00, 0x00, 0x00, 0x00};
    ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, nested_indefinite,
                                       sizeof(nested_indefinite), NULL, &doc,
                                       &consumed) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_node_child_count(asnber_doc_root(doc)) == 2);
    const asnber_node_t *nested_child = asnber_node_child_at(asnber_doc_root(doc), 1);
    ASNBER_TEST_CHECK(nested_child != NULL);
    ASNBER_TEST_CHECK(asnber_node_is_indefinite(nested_child) == 1);
    ASNBER_TEST_CHECK(asnber_node_tag_number(nested_child) == 16);
    asnber_doc_destroy(doc);

    /* 缺少 EOC 的不定长按截断处理。 */
    static const uint8_t missing_eoc[] = {0x30, 0x80, 0x02, 0x01, 0x05};
    ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, missing_eoc, sizeof(missing_eoc),
                                       NULL, &doc, &consumed) ==
                    ASNBER_E_TRUNCATED);
    ASNBER_TEST_CHECK(doc == NULL);

    /* 单层不定长 OCTET STRING 分段合并。 */
    static const uint8_t indefinite_octets[] = {
        0x24, 0x80, 0x04, 0x01, 0x41, 0x04, 0x01, 0x42, 0x00, 0x00};
    ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, indefinite_octets,
                                       sizeof(indefinite_octets), NULL, &doc,
                                       &consumed) == ASNBER_OK);
    {
        const uint8_t *data = NULL;
        size_t size = 0;
        ASNBER_TEST_CHECK(asnber_node_get_octets(asnber_doc_root(doc), &data,
                                             &size) == ASNBER_OK);
        ASNBER_TEST_CHECK(size == 2);
        ASNBER_TEST_CHECK(data[0] == 0x41 && data[1] == 0x42);
    }
    asnber_doc_destroy(doc);

    /* 不定长构造字符串（UTF8String）分段合并。 */
    static const uint8_t indefinite_utf8[] = {
        0x2C, 0x80, 0x0C, 0x02, 0x41, 0x42, 0x0C, 0x02,
        0x43, 0x44, 0x00, 0x00};
    ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, indefinite_utf8,
                                       sizeof(indefinite_utf8), NULL, &doc,
                                       &consumed) == ASNBER_OK);
    {
        const uint8_t *text = NULL;
        size_t size = 0;
        ASNBER_TEST_CHECK(asnber_node_get_raw_string(asnber_doc_root(doc), &text,
                                                 &size) == ASNBER_OK);
        ASNBER_TEST_CHECK(size == 4);
        ASNBER_TEST_CHECK(memcmp(text, "ABCD", 4) == 0);
    }
    asnber_doc_destroy(doc);

    /* 不定长 BIT STRING 分段按位累加（第二段带 4 个 unused bits）。 */
    static const uint8_t indefinite_bits[] = {
        0x23, 0x80, 0x03, 0x02, 0x00, 0xAA, 0x03,
        0x02, 0x04, 0xF0, 0x00, 0x00};
    ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, indefinite_bits,
                                       sizeof(indefinite_bits), NULL, &doc,
                                       &consumed) == ASNBER_OK);
    {
        const uint8_t *data = NULL;
        size_t size = 0;
        size_t bit_length = 0;
        uint8_t unused = 9;
        ASNBER_TEST_CHECK(asnber_node_get_bits(asnber_doc_root(doc), &data, &size,
                                           &bit_length, &unused) == ASNBER_OK);
        ASNBER_TEST_CHECK(size == 2);
        ASNBER_TEST_CHECK(bit_length == 12);
        ASNBER_TEST_CHECK(unused == 4);
        ASNBER_TEST_CHECK(data[0] == 0xAA && data[1] == 0xF0);
    }
    asnber_doc_destroy(doc);

    /* 顶层裸 EOC 始终拒绝。 */
    static const uint8_t eoc[] = {0x00};
    ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, eoc, sizeof(eoc), NULL, &doc,
                                       &consumed) == ASNBER_E_MALFORMED_TAG);

    /* 尾随数据默认拒绝，可显式允许。 */
    static const uint8_t trailing[] = {0x02, 0x01, 0x00, 0x05};
    consumed = 999;
    ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, trailing, sizeof(trailing), NULL,
                                       &doc, &consumed) ==
                    ASNBER_E_TRAILING_DATA);
    ASNBER_TEST_CHECK(doc == NULL);
    ASNBER_TEST_CHECK(consumed == 999);

    asnber_decode_options_t options;
    asnber_decode_options_init(&options);
    options.flags = ASNBER_DECODE_ALLOW_TRAILING;
    consumed = 0;
    ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, trailing, sizeof(trailing),
                                       &options, &doc, &consumed) == ASNBER_OK);
    ASNBER_TEST_CHECK(consumed == 3);
    asnber_doc_destroy(doc);

    /* COPY_INPUT：复制后调用方缓冲可被改写。 */
    uint8_t borrowed[] = {0x02, 0x01, 0x05};
    ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, borrowed, sizeof(borrowed), NULL,
                                       &doc, &consumed) == ASNBER_OK);
    const asnber_node_t *borrowed_node = asnber_doc_root(doc);
    borrowed[2] = 0xFF;
    ASNBER_TEST_CHECK(asnber_node_get_int64(borrowed_node, &int_value) == ASNBER_OK);
    ASNBER_TEST_CHECK(int_value == -1);
    asnber_doc_destroy(doc);

    uint8_t copied[] = {0x02, 0x01, 0x05};
    asnber_decode_options_init(&options);
    options.flags = ASNBER_DECODE_COPY_INPUT;
    ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, copied, sizeof(copied), &options,
                                       &doc, &consumed) == ASNBER_OK);
    copied[2] = 0xFF;
    const asnber_node_t *copied_node = asnber_doc_root(doc);
    ASNBER_TEST_CHECK(asnber_node_get_int64(copied_node, &int_value) == ASNBER_OK);
    ASNBER_TEST_CHECK(int_value == 5);
    asnber_doc_destroy(doc);

    /* 选项校验。 */
    asnber_decode_options_init(&options);
    options.struct_size = 0;
    ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, basic, sizeof(basic), &options,
                                       &doc, &consumed) ==
                    ASNBER_E_INVALID_CONFIG);
    asnber_decode_options_init(&options);
    options.encoding = ASNBER_ENCODING_NONE;
    ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, basic, sizeof(basic), &options,
                                       &doc, &consumed) ==
                    ASNBER_E_UNSUPPORTED_ENCODING);
    asnber_decode_options_init(&options);
    options.flags = ASNBER_DECODE_STRICT_SCHEMA;
    ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, basic, sizeof(basic), &options,
                                       &doc, &consumed) ==
                    ASNBER_E_INVALID_ARG);
    asnber_decode_options_init(&options);
    options.max_depth = 128; /* 大于上下文默认 64 */
    ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, basic, sizeof(basic), &options,
                                       &doc, &consumed) ==
                    ASNBER_E_INVALID_CONFIG);

    /* reserved 与未知 flag 按配置错误拒绝；合法 max_depth 生效。 */
    asnber_decode_options_init(&options);
    options.reserved[2] = 1;
    ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, basic, sizeof(basic), &options,
                                       &doc, &consumed) ==
                    ASNBER_E_INVALID_CONFIG);
    asnber_decode_options_init(&options);
    options.flags = 0x80000000u;
    ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, basic, sizeof(basic), &options,
                                       &doc, &consumed) ==
                    ASNBER_E_INVALID_CONFIG);
    asnber_decode_options_init(&options);
    options.max_depth = 2;
    doc = NULL;
    ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, nested, sizeof(nested), &options,
                                       &doc, &consumed) == ASNBER_OK);
    asnber_doc_destroy(doc);

    /* NULL 参数。 */
    doc = NULL;
    ASNBER_TEST_CHECK(asnber_decode_buffer(NULL, basic, sizeof(basic), NULL, &doc,
                                       &consumed) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(doc == NULL);
    ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, basic, sizeof(basic), NULL, NULL,
                                       &consumed) == ASNBER_E_INVALID_ARG);
    doc = NULL;
    ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, NULL, sizeof(basic), NULL, &doc,
                                       &consumed) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(doc == NULL);

    asnber_ctx_destroy(ctx);

    /* 深度上限：上下文 max_depth = 1。 */
    asnber_ctx_config_init(&config);
    config.max_depth = 1;
    ASNBER_TEST_CHECK(asnber_ctx_create(&config, &ctx) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, nested, sizeof(nested), NULL, &doc,
                                       &consumed) == ASNBER_E_DEPTH_LIMIT);
    ASNBER_TEST_CHECK(doc == NULL);

    /* decode_reader：非法 reader 配置。 */
    asnber_reader_t reader;
    reader.struct_size = sizeof(reader);
    reader.user = NULL;
    reader.read = NULL;
    ASNBER_TEST_CHECK(asnber_decode_reader(ctx, &reader, NULL, &doc, &consumed) ==
                    ASNBER_E_INVALID_CONFIG);
    ASNBER_TEST_CHECK(doc == NULL);
    asnber_ctx_destroy(ctx);

    return 0;
}
