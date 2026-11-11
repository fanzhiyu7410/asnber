/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * schema 构建侧 C ABI：运行时注册类型/字段、设置根与封存。
 * ASNBER_FEATURE_SCHEMA_BUILD_API=0 时本文件不参与编译。
 */

#include "asnber_schema_api_helpers.h"

extern "C" asnber_err_t asnber_schema_create(asnber_ctx_t *ctxHandle,
                                         asnber_tag_mode_t default_tag_mode,
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

    asnber::Schema *schema = nullptr;
    const asnber_err_t rc = asnber::schemaCreate(
        ctx, static_cast<uint32_t>(default_tag_mode), &schema);
    if (rc != ASNBER_OK) {
        return rc;
    }
    *out_schema = reinterpret_cast<asnber_schema_t *>(schema);
    return ASNBER_OK;
}

extern "C" asnber_err_t asnber_schema_add_type(asnber_schema_t *schemaHandle,
                                           const asnber_type_desc_t *desc,
                                           uint32_t *out_type_id)
{
    if (schemaHandle == nullptr || desc == nullptr || out_type_id == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber::Schema *schema = validSchema(schemaHandle);
    if (schema == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return asnber::schemaAddType(schema->ctx, schema, desc, out_type_id, false);
}

extern "C" asnber_err_t asnber_schema_add_field(asnber_schema_t *schemaHandle,
                                            uint32_t parent_type_id,
                                            const asnber_field_desc_t *desc)
{
    if (schemaHandle == nullptr || desc == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber::Schema *schema = validSchema(schemaHandle);
    if (schema == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return asnber::schemaAddField(schema->ctx, schema, parent_type_id, desc);
}

extern "C" asnber_err_t asnber_schema_set_root(asnber_schema_t *schemaHandle,
                                           uint32_t root_type_id)
{
    if (schemaHandle == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber::Schema *schema = validSchema(schemaHandle);
    if (schema == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return asnber::schemaSetRoot(schema->ctx, schema, root_type_id);
}

extern "C" asnber_err_t asnber_schema_seal(asnber_schema_t *schemaHandle)
{
    if (schemaHandle == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber::Schema *schema = validSchema(schemaHandle);
    if (schema == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    return asnber::schemaSeal(schema->ctx, schema);
}
