/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * 核心解码参考。输入是内嵌的 DER：
 *   SEQUENCE { INTEGER 1 }
 * 在静态池上按 DER 严格模式解码，读出唯一子节点的整数值，然后销毁上下文。
 * 不链接任何标准模块。
 */
#include <asnber/asnber.h>

#include <stdint.h>
#include <stdio.h>

#define DECODE_POOL ((size_t)8192u)

static const uint8_t kSequenceIntegerOne[] = {0x30, 0x03, 0x02, 0x01, 0x01};

static union {
    long double align_ld;
    void *align_ptr;
    unsigned char bytes[DECODE_POOL];
} g_pool;

int main(void)
{
    asnber_ctx_config_t config;
    asnber_decode_options_t options;
    asnber_ctx_t *ctx = NULL;
    asnber_doc_t *doc = NULL;
    const asnber_node_t *root = NULL;
    const asnber_node_t *child = NULL;
    size_t consumed = 0;
    int64_t value = 0;
    asnber_err_t err;

    asnber_ctx_config_init(&config);
    config.static_pool = g_pool.bytes;
    config.static_pool_size = sizeof(g_pool.bytes);
    err = asnber_ctx_create(&config, &ctx);
    if (err != ASNBER_OK) {
        fprintf(stderr, "asnber_ctx_create: %d\n", (int)err);
        return 1;
    }

    asnber_decode_options_init(&options);
    options.encoding = ASNBER_ENCODING_DER;
    options.flags = ASNBER_DECODE_COPY_INPUT;
    err = asnber_decode_buffer(ctx, kSequenceIntegerOne,
                               sizeof(kSequenceIntegerOne), &options, &doc,
                               &consumed);
    if (err == ASNBER_OK) {
        root = asnber_doc_root(doc);
    }
    if (err == ASNBER_OK &&
        (root == NULL || consumed != sizeof(kSequenceIntegerOne) ||
         asnber_node_tag_class(root) != ASNBER_TAG_UNIVERSAL ||
         asnber_node_tag_number(root) != ASNBER_UNIVERSAL_SEQUENCE ||
         asnber_node_child_count(root) != 1u)) {
        err = ASNBER_E_INVALID_VALUE;
    }
    if (err == ASNBER_OK) {
        child = asnber_node_child_at(root, 0);
        if (child == NULL) {
            err = ASNBER_E_INVALID_VALUE;
        }
    }
    if (err == ASNBER_OK) {
        err = asnber_node_get_int64(child, &value);
    }
    if (err == ASNBER_OK &&
        (asnber_node_tag_number(child) != ASNBER_UNIVERSAL_INTEGER ||
         value != 1)) {
        err = ASNBER_E_INVALID_VALUE;
    }
    asnber_doc_destroy(doc);
    asnber_ctx_destroy(ctx);
    if (err != ASNBER_OK) {
        fprintf(stderr, "decode: %d\n", (int)err);
        return 1;
    }
    printf("SEQUENCE INTEGER=%lld\n", (long long)value);
    return 0;
}
