/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * 增量 feed 解码器：push 模式分块推送、单次推送、空推送、finalize 单次性、
 * consumed 语义、尾随判定与错误路径。
 */
#include <asnber/asnber.h>

#include <stddef.h>
#include <string.h>

#include "check.h"

/* SEQUENCE { INTEGER 5, OCTET STRING "hi" }。 */
static const uint8_t kSeq[9] = {0x30, 0x07, 0x02, 0x01, 0x05,
                                0x04, 0x02, 0x68, 0x69};

/* 校验文档根节点为 kSeq 对应的结构。 */
static int check_seq_doc(asnber_doc_t *doc)
{
    const asnber_node_t *root = asnber_doc_root(doc);
    ASNBER_TEST_CHECK(root != NULL);
    ASNBER_TEST_CHECK(asnber_node_tag_number(root) == 16);
    ASNBER_TEST_CHECK(asnber_node_child_count(root) == 2);
    const asnber_node_t *a = asnber_node_child_at(root, 0);
    const asnber_node_t *b = asnber_node_child_at(root, 1);
    ASNBER_TEST_CHECK(a != NULL && b != NULL);
    ASNBER_TEST_CHECK(asnber_node_tag_number(a) == 2);
    ASNBER_TEST_CHECK(asnber_node_tag_number(b) == 4);
    int64_t v = 0;
    ASNBER_TEST_CHECK(asnber_node_get_int64(a, &v) == ASNBER_OK);
    ASNBER_TEST_CHECK(v == 5);
    const uint8_t *content = NULL;
    size_t content_size = 0;
    ASNBER_TEST_CHECK(asnber_node_content(b, &content, &content_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(content_size == 2);
    ASNBER_TEST_CHECK(content[0] == 0x68 && content[1] == 0x69);
    return 0;
}

/* 用 feed 模式按给定块大小推送 kSeq 并 finalize。 */
static int feed_chunks(asnber_ctx_t *ctx, size_t chunk, asnber_doc_t **out_doc,
                       size_t *out_consumed)
{
    asnber_decoder_t *dec = asnber_decoder_create(ctx, NULL);
    ASNBER_TEST_CHECK(dec != NULL);
    size_t off = 0;
    while (off < sizeof(kSeq)) {
        size_t take = sizeof(kSeq) - off;
        if (chunk != 0 && take > chunk) {
            take = chunk;
        }
        ASNBER_TEST_CHECK(asnber_decoder_feed(ctx, dec, kSeq + off, take) ==
                        ASNBER_OK);
        off += take;
    }
    size_t consumed = 0;
    asnber_doc_t *doc = NULL;
    ASNBER_TEST_CHECK(asnber_decoder_finalize(ctx, dec, &doc, &consumed) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(doc != NULL);
    ASNBER_TEST_CHECK(consumed == sizeof(kSeq));
    asnber_decoder_destroy(dec);
    *out_doc = doc;
    if (out_consumed != NULL) {
        *out_consumed = consumed;
    }
    return 0;
}

int main(void)
{
    asnber_ctx_config_t config;
    asnber_ctx_config_init(&config);
    asnber_ctx_t *ctx = NULL;
    ASNBER_TEST_CHECK(asnber_ctx_create(&config, &ctx) == ASNBER_OK);

    /* 1. 单次 feed 与 buffer 解码结果一致。 */
    {
        asnber_doc_t *buf_doc = NULL;
        size_t buf_consumed = 0;
        ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, kSeq, sizeof(kSeq), NULL,
                                           &buf_doc,
                                           &buf_consumed) == ASNBER_OK);
        ASNBER_TEST_CHECK(buf_consumed == sizeof(kSeq));

        asnber_doc_t *feed_doc = NULL;
        ASNBER_TEST_CHECK(feed_chunks(ctx, 0, &feed_doc, NULL) == 0);

        ASNBER_TEST_CHECK(check_seq_doc(buf_doc) == 0);
        ASNBER_TEST_CHECK(check_seq_doc(feed_doc) == 0);
        asnber_doc_destroy(buf_doc);
        asnber_doc_destroy(feed_doc);
    }

    /* 2. 不同块大小的多段 feed 结果一致。 */
    {
        size_t chunks[] = {1, 2, 3, 4, 5, 8};
        for (size_t i = 0; i < sizeof(chunks) / sizeof(chunks[0]); ++i) {
            asnber_doc_t *doc = NULL;
            ASNBER_TEST_CHECK(feed_chunks(ctx, chunks[i], &doc, NULL) == 0);
            ASNBER_TEST_CHECK(check_seq_doc(doc) == 0);
            asnber_doc_destroy(doc);
        }
    }

    /* 3. 空 feed（size==0）为 no-op，仍可正常 finalize。 */
    {
        asnber_decoder_t *dec = asnber_decoder_create(ctx, NULL);
        ASNBER_TEST_CHECK(dec != NULL);
        ASNBER_TEST_CHECK(asnber_decoder_feed(ctx, dec, kSeq, 0) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_decoder_feed(ctx, dec, kSeq, sizeof(kSeq)) ==
                        ASNBER_OK);
        asnber_doc_t *doc = NULL;
        size_t consumed = 0;
        ASNBER_TEST_CHECK(asnber_decoder_finalize(ctx, dec, &doc, &consumed) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(consumed == sizeof(kSeq));
        ASNBER_TEST_CHECK(check_seq_doc(doc) == 0);
        asnber_doc_destroy(doc);
        asnber_decoder_destroy(dec);
    }

    /* 4. finalize 之后再次 finalize / feed 返回 INVALID_ARG。 */
    {
        asnber_decoder_t *dec = asnber_decoder_create(ctx, NULL);
        ASNBER_TEST_CHECK(dec != NULL);
        ASNBER_TEST_CHECK(asnber_decoder_feed(ctx, dec, kSeq, sizeof(kSeq)) ==
                        ASNBER_OK);
        asnber_doc_t *doc = NULL;
        ASNBER_TEST_CHECK(asnber_decoder_finalize(ctx, dec, &doc, NULL) ==
                        ASNBER_OK);
        asnber_doc_destroy(doc);

        ASNBER_TEST_CHECK(asnber_decoder_finalize(ctx, dec, &doc, NULL) ==
                        ASNBER_E_INVALID_ARG);
        ASNBER_TEST_CHECK(asnber_decoder_feed(ctx, dec, kSeq, 1) ==
                        ASNBER_E_INVALID_ARG);
        asnber_decoder_destroy(dec);
    }

    /* 5. 未 finalize 即销毁：安全释放，不泄漏。 */
    {
        asnber_decoder_t *dec = asnber_decoder_create(ctx, NULL);
        ASNBER_TEST_CHECK(dec != NULL);
        ASNBER_TEST_CHECK(asnber_decoder_feed(ctx, dec, kSeq, sizeof(kSeq)) ==
                        ASNBER_OK);
        asnber_decoder_destroy(dec);
    }

    /* 6. 截断输入：finalize 返回 TRUNCATED，doc 为 NULL。 */
    {
        asnber_decoder_t *dec = asnber_decoder_create(ctx, NULL);
        ASNBER_TEST_CHECK(dec != NULL);
        static const uint8_t truncated[4] = {0x30, 0x05, 0x02, 0x01};
        ASNBER_TEST_CHECK(asnber_decoder_feed(ctx, dec, truncated,
                                          sizeof(truncated)) == ASNBER_OK);
        asnber_doc_t *doc = (asnber_doc_t *)0x1;
        ASNBER_TEST_CHECK(asnber_decoder_finalize(ctx, dec, &doc, NULL) ==
                        ASNBER_E_TRUNCATED);
        ASNBER_TEST_CHECK(doc == NULL);
        asnber_decoder_destroy(dec);
    }

    /* 7. 尾随数据：默认拒绝，ALLOW_TRAILING 放行。 */
    {
        static const uint8_t trailing[11] = {0x30, 0x07, 0x02, 0x01, 0x05,
                                             0x04, 0x02, 0x68, 0x69,
                                             0x05, 0x00};
        asnber_decoder_t *dec = asnber_decoder_create(ctx, NULL);
        ASNBER_TEST_CHECK(dec != NULL);
        ASNBER_TEST_CHECK(asnber_decoder_feed(ctx, dec, trailing,
                                          sizeof(trailing)) == ASNBER_OK);
        asnber_doc_t *doc = NULL;
        ASNBER_TEST_CHECK(asnber_decoder_finalize(ctx, dec, &doc, NULL) ==
                        ASNBER_E_TRAILING_DATA);
        ASNBER_TEST_CHECK(doc == NULL);
        asnber_decoder_destroy(dec);

        asnber_decode_options_t options;
        asnber_decode_options_init(&options);
        options.flags = ASNBER_DECODE_ALLOW_TRAILING;
        dec = asnber_decoder_create(ctx, &options);
        ASNBER_TEST_CHECK(dec != NULL);
        ASNBER_TEST_CHECK(asnber_decoder_feed(ctx, dec, trailing,
                                          sizeof(trailing)) == ASNBER_OK);
        doc = NULL;
        size_t consumed = 0;
        ASNBER_TEST_CHECK(asnber_decoder_finalize(ctx, dec, &doc, &consumed) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(consumed == sizeof(trailing));
        ASNBER_TEST_CHECK(check_seq_doc(doc) == 0);
        asnber_doc_destroy(doc);
        asnber_decoder_destroy(dec);
    }

    /* 8. DER 严格模式：feed 路径同样生效。 */
    {
        /* 非最小长度编码的 INTEGER（0x02 0x02 0x00 0x05）在 DER 下非法。 */
        static const uint8_t non_min[5] = {0x30, 0x03, 0x02, 0x02, 0x05};
        asnber_decode_options_t options;
        asnber_decode_options_init(&options);
        options.encoding = ASNBER_ENCODING_DER;
        asnber_decoder_t *dec = asnber_decoder_create(ctx, &options);
        ASNBER_TEST_CHECK(dec != NULL);
        ASNBER_TEST_CHECK(asnber_decoder_feed(ctx, dec, non_min, sizeof(non_min)) ==
                        ASNBER_OK);
        asnber_doc_t *doc = NULL;
        ASNBER_TEST_CHECK(asnber_decoder_finalize(ctx, dec, &doc, NULL) != ASNBER_OK);
        ASNBER_TEST_CHECK(doc == NULL);
        asnber_decoder_destroy(dec);
    }

    /* 9. NULL 参数与非法参数。 */
    {
        ASNBER_TEST_CHECK(asnber_decoder_create(NULL, NULL) == NULL);
        ASNBER_TEST_CHECK(asnber_decoder_feed(ctx, NULL, kSeq, 1) ==
                        ASNBER_E_INVALID_ARG);
        ASNBER_TEST_CHECK(asnber_decoder_feed(ctx, NULL, NULL, 1) ==
                        ASNBER_E_INVALID_ARG);
        ASNBER_TEST_CHECK(asnber_decoder_finalize(ctx, NULL, NULL, NULL) ==
                        ASNBER_E_INVALID_ARG);
        asnber_decoder_destroy(NULL); /* no-op */
    }

    /* 10. feed 的 data==NULL 但 size==0 仍为合法空推送。 */
    {
        asnber_decoder_t *dec = asnber_decoder_create(ctx, NULL);
        ASNBER_TEST_CHECK(dec != NULL);
        ASNBER_TEST_CHECK(asnber_decoder_feed(ctx, dec, NULL, 0) == ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_decoder_feed(ctx, dec, kSeq, sizeof(kSeq)) ==
                        ASNBER_OK);
        asnber_doc_t *doc = NULL;
        ASNBER_TEST_CHECK(asnber_decoder_finalize(ctx, dec, &doc, NULL) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(check_seq_doc(doc) == 0);
        asnber_doc_destroy(doc);
        asnber_decoder_destroy(dec);
    }

    /* 11. 选项校验与 finalize 参数。 */
    {
        asnber_decode_options_t options;
        asnber_decode_options_init(&options);
        options.struct_size = 0;
        ASNBER_TEST_CHECK(asnber_decoder_create(ctx, &options) == NULL);

        asnber_decode_options_init(&options);
        options.encoding = ASNBER_ENCODING_NONE;
        asnber_decoder_t *dec = asnber_decoder_create(ctx, &options);
        ASNBER_TEST_CHECK(dec != NULL);
        ASNBER_TEST_CHECK(asnber_decoder_feed(ctx, dec, kSeq, sizeof(kSeq)) ==
                        ASNBER_OK);
        asnber_doc_t *doc = NULL;
        ASNBER_TEST_CHECK(asnber_decoder_finalize(ctx, dec, &doc, NULL) ==
                        ASNBER_E_UNSUPPORTED_ENCODING);
        ASNBER_TEST_CHECK(doc == NULL);
        asnber_decoder_destroy(dec);

        dec = asnber_decoder_create(ctx, NULL);
        ASNBER_TEST_CHECK(dec != NULL);
        doc = NULL;
        ASNBER_TEST_CHECK(asnber_decoder_finalize(NULL, dec, &doc, NULL) ==
                        ASNBER_E_INVALID_ARG);
        ASNBER_TEST_CHECK(doc == NULL);
        ASNBER_TEST_CHECK(asnber_decoder_feed(ctx, dec, NULL, 1) ==
                        ASNBER_E_INVALID_ARG);
        asnber_decoder_destroy(dec);
    }

    /* 12. 输入超过初始缓冲：分块推送时按需扩容。 */
    {
        uint8_t large[304];
        large[0] = 0x04; /* OCTET STRING，内容 300 字节。 */
        large[1] = 0x82;
        large[2] = 0x01;
        large[3] = 0x2C;
        for (size_t i = 4; i < sizeof(large); ++i) {
            large[i] = (uint8_t)i;
        }
        asnber_decoder_t *dec = asnber_decoder_create(ctx, NULL);
        ASNBER_TEST_CHECK(dec != NULL);
        for (size_t off = 0; off < sizeof(large); off += 100) {
            size_t take = sizeof(large) - off;
            if (take > 100) {
                take = 100;
            }
            ASNBER_TEST_CHECK(asnber_decoder_feed(ctx, dec, large + off, take) ==
                            ASNBER_OK);
        }
        asnber_doc_t *doc = NULL;
        size_t consumed = 0;
        ASNBER_TEST_CHECK(asnber_decoder_finalize(ctx, dec, &doc, &consumed) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(consumed == sizeof(large));
        const uint8_t *content = NULL;
        size_t content_size = 0;
        ASNBER_TEST_CHECK(asnber_node_content(asnber_doc_root(doc), &content,
                                          &content_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(content_size == 300);
        ASNBER_TEST_CHECK(content[299] == (uint8_t)303);
        asnber_doc_destroy(doc);
        asnber_decoder_destroy(dec);
    }

    asnber_ctx_destroy(ctx);
    return 0;
}
