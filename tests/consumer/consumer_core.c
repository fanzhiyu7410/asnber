/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * 独立消费工程（核心）：只依赖 find_package(asnber)，解码样本并读取根节点字段。
 */
#include <asnber/asnber.h>

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    FILE *file = NULL;
    unsigned char *der = NULL;
    long length = 0;
    asnber_ctx_config_t config;
    asnber_ctx_t *ctx = NULL;
    asnber_doc_t *doc = NULL;
    const asnber_node_t *root = NULL;
    size_t consumed = 0;
    int result = 1;

    if (argc != 2) {
        return 1;
    }
    file = fopen(argv[1], "rb");
    if (file == NULL) {
        return 1;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return 1;
    }
    length = ftell(file);
    if (length <= 0 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return 1;
    }
    der = (unsigned char *)malloc((size_t)length);
    if (der == NULL || fread(der, 1, (size_t)length, file) != (size_t)length) {
        free(der);
        fclose(file);
        return 1;
    }
    fclose(file);

    asnber_ctx_config_init(&config);
    if (asnber_ctx_create(&config, &ctx) != ASNBER_OK) {
        free(der);
        return 1;
    }
    if (asnber_decode_buffer(ctx, der, (size_t)length, NULL, &doc, &consumed) ==
            ASNBER_OK &&
        consumed == (size_t)length && asnber_doc_root(doc) != NULL) {
        root = asnber_doc_root(doc);
        if (asnber_node_tag_class(root) == ASNBER_TAG_UNIVERSAL &&
            asnber_node_tag_number(root) == 16u &&
            asnber_node_child_count(root) >= 1) {
            result = 0;
        }
    }
    asnber_doc_destroy(doc);
    asnber_ctx_destroy(ctx);
    free(der);
    return result;
}
