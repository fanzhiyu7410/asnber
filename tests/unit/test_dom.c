/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * DOM：runtime 构树、内容设置、封存校验与只读访问。
 */
#include <asnber/asnber.h>

#include <stddef.h>

#include "check.h"

int main(void)
{
    asnber_ctx_config_t config;
    asnber_ctx_config_init(&config);
    asnber_ctx_t *ctx = NULL;
    ASNBER_TEST_CHECK(asnber_ctx_create(&config, &ctx) == ASNBER_OK);

    asnber_doc_t *doc = NULL;
    ASNBER_TEST_CHECK(asnber_doc_create(ctx, &doc) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_doc_root(doc) == NULL);
    ASNBER_TEST_CHECK(asnber_doc_source_encoding(doc) == ASNBER_ENCODING_NONE);
    ASNBER_TEST_CHECK(asnber_doc_seal(doc) == ASNBER_E_INVALID_STATE);

    asnber_node_t *root = NULL;
    ASNBER_TEST_CHECK(asnber_node_create(doc, NULL, ASNBER_TAG_UNIVERSAL, 16, 1,
                                     &root) == ASNBER_OK);
    ASNBER_TEST_CHECK(root != NULL);
    asnber_node_t *second_root = NULL;
    ASNBER_TEST_CHECK(asnber_node_create(doc, NULL, ASNBER_TAG_UNIVERSAL, 16, 1,
                                     &second_root) == ASNBER_E_INVALID_STATE);
    ASNBER_TEST_CHECK(second_root == NULL);

    asnber_node_t *integer = NULL;
    ASNBER_TEST_CHECK(asnber_node_create(doc, root, ASNBER_TAG_UNIVERSAL, 2, 0,
                                     &integer) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_node_set_int64(integer, -42) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_node_set_int64(integer, 1) == ASNBER_E_INVALID_STATE);

    asnber_node_t *boolean = NULL;
    ASNBER_TEST_CHECK(asnber_node_create(doc, root, ASNBER_TAG_UNIVERSAL, 1, 0,
                                     &boolean) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_node_set_bool(boolean, 1) == ASNBER_OK);

    asnber_node_t *rejected = NULL;
    ASNBER_TEST_CHECK(asnber_node_create(doc, integer, ASNBER_TAG_UNIVERSAL, 2, 0,
                                     &rejected) == ASNBER_E_INVALID_STATE);
    ASNBER_TEST_CHECK(rejected == NULL);
    ASNBER_TEST_CHECK(asnber_node_create(doc, NULL, ASNBER_TAG_UNIVERSAL, 0, 0,
                                     &rejected) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(rejected == NULL);

    ASNBER_TEST_CHECK(asnber_doc_seal(doc) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_doc_seal(doc) == ASNBER_OK);

    ASNBER_TEST_CHECK(asnber_doc_root(doc) == root);
    ASNBER_TEST_CHECK(asnber_node_tag_class(root) == ASNBER_TAG_UNIVERSAL);
    ASNBER_TEST_CHECK(asnber_node_tag_number(root) == 16);
    ASNBER_TEST_CHECK(asnber_node_encoding_form(root) == ASNBER_FORM_CONSTRUCTED);
    ASNBER_TEST_CHECK(asnber_node_is_indefinite(root) == 0);
    ASNBER_TEST_CHECK(asnber_node_child_count(root) == 2);
    ASNBER_TEST_CHECK(asnber_node_child_at(root, 0) == integer);
    ASNBER_TEST_CHECK(asnber_node_child_at(root, 1) == boolean);
    ASNBER_TEST_CHECK(asnber_node_child_at(root, 2) == NULL);
    ASNBER_TEST_CHECK(asnber_node_parent(integer) == root);
    ASNBER_TEST_CHECK(asnber_node_parent(root) == NULL);
    ASNBER_TEST_CHECK(asnber_node_field_name(integer) == NULL);
    ASNBER_TEST_CHECK(asnber_node_child_by_name(root, "x") == NULL);

    const uint8_t *data = NULL;
    size_t size = 0;
    ASNBER_TEST_CHECK(asnber_node_content(root, &data, &size) ==
                    ASNBER_E_INVALID_STATE);
    ASNBER_TEST_CHECK(asnber_node_content(integer, &data, &size) == ASNBER_OK);
    ASNBER_TEST_CHECK(size == 1);
    ASNBER_TEST_CHECK(data != NULL);
    ASNBER_TEST_CHECK(data[0] == 0xD6); /* -42 的最小二进制补码 */

    size_t tlv_size = 123;
    ASNBER_TEST_CHECK(asnber_node_tlv(integer, &tlv_size) == NULL);
    ASNBER_TEST_CHECK(tlv_size == 0);
    ASNBER_TEST_CHECK(asnber_node_offset(root) == SIZE_MAX);

    int64_t value = 0;
    ASNBER_TEST_CHECK(asnber_node_get_int64(integer, &value) == ASNBER_OK);
    ASNBER_TEST_CHECK(value == -42);
    int bool_value = 0;
    ASNBER_TEST_CHECK(asnber_node_get_bool(boolean, &bool_value) == ASNBER_OK);
    ASNBER_TEST_CHECK(bool_value == 1);

    rejected = NULL;
    ASNBER_TEST_CHECK(asnber_node_create(doc, root, ASNBER_TAG_UNIVERSAL, 2, 0,
                                     &rejected) == ASNBER_E_INVALID_STATE);
    ASNBER_TEST_CHECK(rejected == NULL);
    ASNBER_TEST_CHECK(asnber_node_set_content(integer, data, size) ==
                    ASNBER_E_INVALID_STATE);

    asnber_doc_destroy(doc);
    asnber_doc_destroy(NULL);
    asnber_ctx_destroy(ctx);

    /* 未封存文档中基本节点缺少内容时封存失败。 */
    ASNBER_TEST_CHECK(asnber_ctx_create(&config, &ctx) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_doc_create(ctx, &doc) == ASNBER_OK);
    root = NULL;
    ASNBER_TEST_CHECK(asnber_node_create(doc, NULL, ASNBER_TAG_UNIVERSAL, 16, 1,
                                     &root) == ASNBER_OK);
    integer = NULL;
    ASNBER_TEST_CHECK(asnber_node_create(doc, root, ASNBER_TAG_UNIVERSAL, 2, 0,
                                     &integer) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_doc_seal(doc) == ASNBER_E_INVALID_STATE);
    asnber_doc_destroy(doc);
    asnber_ctx_destroy(ctx);

    return 0;
}
