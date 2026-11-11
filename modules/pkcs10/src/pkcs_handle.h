/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-pkcs10 模块内共享的句柄与字段访问工具（私有）。
 *
 * 只保留 PKCS#10 只读访问所需的“加载 schema → DER 严格解码 → 持有文档”
 * 骨架与字段读取辅助函数。这些符号不导出，只供模块自身编译单元使用。
 */

#ifndef ASNBER_PKCS10_HANDLE_H_INCLUDED
#define ASNBER_PKCS10_HANDLE_H_INCLUDED

#include <asnber/asnber_build.h>
#include <asnber/asnber_node.h>
#include <asnber/asnber_schema.h>

#include "pkcs10_tables.h"

#include <cstdlib>

namespace pkcs10_internal {

constexpr uint32_t kPkcs10FormatVersion = 1u << 16;

/* 所有结构句柄共享的字段；派生句柄以它为第一个成员。 */
struct handle_base {
    asnber_ctx_t *ctx;
    asnber_schema_t *schema;
    asnber_doc_t *doc;
    const asnber_node_t *root;
};

template <typename T>
asnber_err_t openStructure(asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
                         pkcs10_table_view table, uint32_t root_type_id,
                         T **out_object) noexcept
{
    if (ctx == nullptr || der == nullptr || der_size == 0 ||
        out_object == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_object = nullptr;

    asnber_schema_table_t schema_table;
    schema_table.struct_size = sizeof(schema_table);
    schema_table.data = table.data;
    schema_table.size = table.size;
    schema_table.format_version = kPkcs10FormatVersion;
    schema_table.reserved = 0;

    asnber_schema_t *schema = nullptr;
    asnber_err_t status =
        asnber_schema_load_with_root(ctx, &schema_table, root_type_id, &schema);
    if (status != ASNBER_OK) {
        return status;
    }

    asnber_decode_options_t options;
    asnber_decode_options_init(&options);
    options.encoding = ASNBER_ENCODING_DER;
    options.flags = ASNBER_DECODE_COPY_INPUT;

    asnber_doc_t *doc = nullptr;
    size_t consumed = 0;
    status = asnber_decode_buffer_with_schema(ctx, der, der_size, schema,
                                            &options, &doc, &consumed);
    if (status != ASNBER_OK) {
        asnber_schema_destroy(schema);
        return status;
    }

    T *object = static_cast<T *>(std::malloc(sizeof(T)));
    if (object == nullptr) {
        asnber_doc_destroy(doc);
        asnber_schema_destroy(schema);
        return ASNBER_E_NOMEM;
    }

    object->ctx = ctx;
    object->schema = schema;
    object->doc = doc;
    object->root = asnber_doc_root(doc);
    *out_object = object;
    return ASNBER_OK;
}

void closeStructure(handle_base *object) noexcept;

/* 取顶层字段；字段缺省时返回 nullptr。 */
const asnber_node_t *field(const handle_base *object,
                         const char *name) noexcept;

asnber_err_t requireField(const handle_base *object, const char *name,
                        const asnber_node_t **out_node) noexcept;

} // namespace pkcs10_internal

#endif /* ASNBER_PKCS10_HANDLE_H_INCLUDED */
