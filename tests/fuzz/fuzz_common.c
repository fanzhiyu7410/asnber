/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

#include "fuzz_common.h"

#include <string.h>

asnber_ctx_t *fuzz_ctx_create(void)
{
    asnber_ctx_config_t config;
    asnber_ctx_config_init(&config);
    asnber_ctx_t *ctx = NULL;
    if (asnber_ctx_create(&config, &ctx) != ASNBER_OK) {
        return NULL;
    }
    return ctx;
}

void fuzz_walk(const asnber_node_t *node)
{
    if (node == NULL) {
        return;
    }
    (void)asnber_node_tag_class(node);
    (void)asnber_node_tag_number(node);
    (void)asnber_node_encoding_form(node);
    (void)asnber_node_is_indefinite(node);
    (void)asnber_node_field_name(node);
    (void)asnber_node_offset(node);

    {
        const uint8_t *data = NULL;
        size_t size = 0;
        (void)asnber_node_tlv(node, &size);
        (void)asnber_node_content(node, &data, &size);
        (void)data;
    }

    {
        size_t i;
        const size_t count = asnber_node_child_count(node);
        for (i = 0; i < count; ++i) {
            fuzz_walk(asnber_node_child_at(node, i));
        }
        /* 下标边界：首个、越界一个、SIZE_MAX。返回值只用于遍历，不施加断言。 */
        (void)asnber_node_child_at(node, 0);
        (void)asnber_node_child_at(node, count);
        (void)asnber_node_child_at(node, SIZE_MAX);
    }
}

asnber_err_t fuzz_mem_read(void *user, uint8_t *dst, size_t capacity,
                         size_t *out_size)
{
    fuzz_mem_reader_t *reader = (fuzz_mem_reader_t *)user;
    size_t available = reader->size - reader->pos;
    size_t take = (available < capacity) ? available : capacity;

    if (dst != NULL && take > 0) {
        memcpy(dst, reader->data + reader->pos, take);
    }
    reader->pos += take;
    *out_size = take;
    return ASNBER_OK;
}

asnber_schema_t *fuzz_min_schema_create(asnber_ctx_t *ctx)
{
    asnber_schema_t *schema = NULL;
    asnber_type_desc_t type;
    asnber_field_desc_t field;
    uint32_t oid_id = 0;
    uint32_t any_id = 0;
    uint32_t seq_id = 0;

    if (ctx == NULL ||
        asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT, &schema) != ASNBER_OK) {
        return NULL;
    }

    memset(&type, 0, sizeof(type));
    type.struct_size = sizeof(type);
    type.name = "Oid";
    type.kind = ASNBER_TYPE_KIND_SIMPLE;
    type.tag_class = ASNBER_TAG_UNIVERSAL;
    type.tag_number = 6u;
    type.tag_mode = ASNBER_TAG_MODE_DEFAULT;
    if (asnber_schema_add_type(schema, &type, &oid_id) != ASNBER_OK) {
        goto fail;
    }

    memset(&type, 0, sizeof(type));
    type.struct_size = sizeof(type);
    type.name = "AnyType";
    type.kind = ASNBER_TYPE_KIND_ANY;
    type.tag_class = ASNBER_TAG_UNIVERSAL;
    type.tag_number = 0u;
    type.tag_mode = ASNBER_TAG_MODE_DEFAULT;
    if (asnber_schema_add_type(schema, &type, &any_id) != ASNBER_OK) {
        goto fail;
    }

    memset(&type, 0, sizeof(type));
    type.struct_size = sizeof(type);
    type.name = "AlgId";
    type.kind = ASNBER_TYPE_KIND_SEQUENCE;
    type.tag_class = ASNBER_TAG_UNIVERSAL;
    type.tag_number = 16u;
    type.tag_mode = ASNBER_TAG_MODE_DEFAULT;
    if (asnber_schema_add_type(schema, &type, &seq_id) != ASNBER_OK) {
        goto fail;
    }

    memset(&field, 0, sizeof(field));
    field.struct_size = sizeof(field);
    field.name = "algorithm";
    field.type_id = oid_id;
    if (asnber_schema_add_field(schema, seq_id, &field) != ASNBER_OK) {
        goto fail;
    }

    memset(&field, 0, sizeof(field));
    field.struct_size = sizeof(field);
    field.name = "parameters";
    field.type_id = any_id;
    field.flags = ASNBER_FIELD_OPTIONAL;
    if (asnber_schema_add_field(schema, seq_id, &field) != ASNBER_OK) {
        goto fail;
    }

    if (asnber_schema_set_root(schema, seq_id) != ASNBER_OK ||
        asnber_schema_seal(schema) != ASNBER_OK) {
        goto fail;
    }
    return schema;

fail:
    asnber_schema_destroy(schema);
    return NULL;
}