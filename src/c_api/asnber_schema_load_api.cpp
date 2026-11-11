/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * schema 读侧 C ABI：描述表加载、销毁与名称查询。
 */

#include "asnber_schema_api_helpers.h"

#include <cstring>

extern "C" asnber_err_t asnber_schema_load(asnber_ctx_t *ctxHandle,
                                       const asnber_schema_table_t *table,
                                       asnber_schema_t **out_schema)
{
    if (out_schema == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_schema = nullptr;
    asnber::Context *ctx = validContext(ctxHandle);
    if (ctx == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (table == nullptr) {
        asnber::contextSetError(ctx, ASNBER_E_INVALID_ARG, SIZE_MAX, 0);
        return ASNBER_E_INVALID_ARG;
    }

    asnber::Schema *schema = nullptr;
    const asnber_err_t rc = asnber::schemaLoad(ctx, table, &schema);
    if (rc != ASNBER_OK) {
        return rc;
    }
    *out_schema = reinterpret_cast<asnber_schema_t *>(schema);
    return ASNBER_OK;
}

extern "C" asnber_err_t asnber_schema_load_with_root(
    asnber_ctx_t *ctxHandle, const asnber_schema_table_t *table,
    uint32_t root_type_id, asnber_schema_t **out_schema)
{
    if (out_schema == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_schema = nullptr;
    asnber::Context *ctx = validContext(ctxHandle);
    if (ctx == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (table == nullptr) {
        asnber::contextSetError(ctx, ASNBER_E_INVALID_ARG, SIZE_MAX, 0);
        return ASNBER_E_INVALID_ARG;
    }

    asnber::Schema *schema = nullptr;
    const asnber_err_t rc =
        asnber::schemaLoadWithRoot(ctx, table, root_type_id, &schema);
    if (rc != ASNBER_OK) {
        return rc;
    }
    *out_schema = reinterpret_cast<asnber_schema_t *>(schema);
    return ASNBER_OK;
}

extern "C" void asnber_schema_destroy(asnber_schema_t *schemaHandle)
{
    if (schemaHandle == nullptr) {
        return;
    }
    asnber::Schema *schema = schemaOf(schemaHandle);
    if (schema->magic != asnber::kSchemaMagic) {
        return;
    }
    asnber::schemaDestroy(schema);
}

extern "C" asnber_err_t asnber_schema_name_count(const asnber_schema_t *schemaHandle,
                                             uint32_t type_id,
                                             uint32_t *out_count)
{
    if (schemaHandle == nullptr || out_count == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber::Schema *schema = validSchema(schemaHandle);
    if (schema == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (!schema->sealed) {
        return ASNBER_E_INVALID_STATE;
    }
    if (type_id == 0 || type_id > schema->typeCount) {
        return ASNBER_E_INVALID_ARG;
    }

    uint32_t count = 0;
    for (uint32_t i = 0; i < schema->nameCount; ++i) {
        if (schema->names[i].typeId == type_id) {
            ++count;
        }
    }
    *out_count = count;
    return ASNBER_OK;
}

extern "C" asnber_err_t asnber_schema_name_at(const asnber_schema_t *schemaHandle,
                                          uint32_t type_id, uint32_t index,
                                          asnber_schema_name_info_t *out_info)
{
    if (schemaHandle == nullptr || out_info == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (out_info->struct_size != sizeof(asnber_schema_name_info_t)) {
        return ASNBER_E_INVALID_CONFIG;
    }
    const asnber::Schema *schema = validSchema(schemaHandle);
    if (schema == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (!schema->sealed) {
        return ASNBER_E_INVALID_STATE;
    }
    if (type_id == 0 || type_id > schema->typeCount) {
        return ASNBER_E_INVALID_ARG;
    }

    uint32_t seen = 0;
    for (uint32_t i = 0; i < schema->nameCount; ++i) {
        const asnber::SchemaName &entry = schema->names[i];
        if (entry.typeId != type_id) {
            continue;
        }
        if (seen == index) {
            out_info->type_id = entry.typeId;
            out_info->kind = entry.kind;
            out_info->flags = entry.flags;
            out_info->value = entry.value;
            out_info->name = entry.name;
            return ASNBER_OK;
        }
        ++seen;
    }
    return ASNBER_E_INVALID_ARG;
}

extern "C" asnber_err_t asnber_schema_name_for_bit(
    const asnber_schema_t *schemaHandle, uint32_t type_id, uint32_t bit,
    const char **out_name)
{
    if (schemaHandle == nullptr || out_name == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber::Schema *schema = validSchema(schemaHandle);
    if (schema == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (!schema->sealed) {
        return ASNBER_E_INVALID_STATE;
    }
    if (type_id == 0 || type_id > schema->typeCount) {
        return ASNBER_E_INVALID_ARG;
    }

    *out_name = nullptr;
    for (uint32_t i = 0; i < schema->nameCount; ++i) {
        const asnber::SchemaName &entry = schema->names[i];
        if (entry.typeId == type_id &&
            entry.kind == ASNBER_SCHEMA_NAME_KIND_BIT &&
            entry.value == static_cast<int64_t>(bit)) {
            *out_name = entry.name;
            break;
        }
    }
    return ASNBER_OK;
}

extern "C" asnber_err_t asnber_schema_name_for_value(
    const asnber_schema_t *schemaHandle, uint32_t type_id, int64_t value,
    const char **out_name)
{
    if (schemaHandle == nullptr || out_name == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber::Schema *schema = validSchema(schemaHandle);
    if (schema == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (!schema->sealed) {
        return ASNBER_E_INVALID_STATE;
    }
    if (type_id == 0 || type_id > schema->typeCount) {
        return ASNBER_E_INVALID_ARG;
    }

    *out_name = nullptr;
    for (uint32_t i = 0; i < schema->nameCount; ++i) {
        const asnber::SchemaName &entry = schema->names[i];
        if (entry.typeId == type_id &&
            entry.kind == ASNBER_SCHEMA_NAME_KIND_NUMBER &&
            entry.value == value) {
            *out_name = entry.name;
            break;
        }
    }
    return ASNBER_OK;
}

extern "C" asnber_err_t asnber_schema_value_for_name(
    const asnber_schema_t *schemaHandle, uint32_t type_id, const char *name,
    int64_t *out_value, int *out_found)
{
    if (schemaHandle == nullptr || name == nullptr || out_value == nullptr ||
        out_found == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    const asnber::Schema *schema = validSchema(schemaHandle);
    if (schema == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (!schema->sealed) {
        return ASNBER_E_INVALID_STATE;
    }
    if (type_id == 0 || type_id > schema->typeCount) {
        return ASNBER_E_INVALID_ARG;
    }

    for (uint32_t i = 0; i < schema->nameCount; ++i) {
        const asnber::SchemaName &entry = schema->names[i];
        if (entry.typeId == type_id &&
            std::strcmp(entry.name, name) == 0) {
            *out_value = entry.value;
            *out_found = 1;
            return ASNBER_OK;
        }
    }
    *out_value = 0;
    *out_found = 0;
    return ASNBER_OK;
}
