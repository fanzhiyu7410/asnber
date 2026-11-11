/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-cms 只读句柄与 schema 字段访问的共享设施（模块私有）。
 *
 * ContentInfo / SignedData / EnvelopedData / EncryptedData / CompressedData /
 * AuthenticatedData 六个句柄沿用同一套 open/close 与字段投影逻辑；放在同一
 * 内部头里避免在多个编译单元重复实现。
 */

#ifndef ASNBER_CMS_STRUCTURE_SUPPORT_H_INCLUDED
#define ASNBER_CMS_STRUCTURE_SUPPORT_H_INCLUDED

#include <asnber/asnber_schema.h>
#include <asnber/cms/cms.h>

#include "cms_tables.h"

#include <cstdlib>

namespace cms_detail {

constexpr uint32_t kFormatVersion = 1u << 16;
constexpr uint32_t kTagSequence = 16;

/* 各句柄共享的字段；派生句柄以它为第一个成员。 */
struct handle_base {
    asnber_ctx_t *ctx;
    asnber_schema_t *schema;
    asnber_doc_t *doc;
    const asnber_node_t *root;
};

template <typename T>
asnber_err_t openStructure(asnber_ctx_t *ctx, const uint8_t *der, size_t der_size,
                         cms_table_view table, uint32_t root_type_id,
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
    schema_table.format_version = kFormatVersion;
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

inline void closeStructure(handle_base *object) noexcept
{
    if (object == nullptr) {
        return;
    }
    asnber_doc_destroy(object->doc);
    asnber_schema_destroy(object->schema);
    std::free(object);
}

/* 取顶层字段；不存在时返回 nullptr。 */
inline const asnber_node_t *field(const handle_base *object,
                                const char *name) noexcept
{
    return asnber_node_child_by_name(object->root, name);
}

inline const asnber_node_t *nestedField(const asnber_node_t *parent,
                                      const char *name) noexcept
{
    if (parent == nullptr) {
        return nullptr;
    }
    return asnber_node_child_by_name(parent, name);
}

inline asnber_err_t requireField(const handle_base *object, const char *name,
                               const asnber_node_t **out_node) noexcept
{
    const asnber_node_t *node = field(object, name);
    if (node == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    *out_node = node;
    return ASNBER_OK;
}

/* 可选集合字段：缺省时条目数为 0。 */
inline asnber_err_t optionalCollectionCount(const handle_base *object,
                                          const char *name,
                                          size_t *out_count) noexcept
{
    const asnber_node_t *node = field(object, name);
    *out_count = node == nullptr ? 0 : asnber_node_child_count(node);
    return ASNBER_OK;
}

inline asnber_err_t collectionItem(const handle_base *object, const char *name,
                                 size_t index,
                                 const asnber_node_t **out_node) noexcept
{
    *out_node = nullptr;
    const asnber_node_t *collection = field(object, name);
    if (collection == nullptr || index >= asnber_node_child_count(collection)) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_node = asnber_node_child_at(collection, index);
    return (*out_node == nullptr) ? ASNBER_E_INVALID_ARG : ASNBER_OK;
}

/* AlgorithmIdentifier：algorithm OID + parameters（ANY 原始 TLV）。 */
inline asnber_err_t algorithmFields(const asnber_node_t *algorithm,
                                  const char **out_oid, size_t *out_oid_size,
                                  const uint8_t **out_parameters,
                                  size_t *out_parameters_size) noexcept
{
    if (algorithm == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    const asnber_node_t *oid = nestedField(algorithm, "algorithm");
    if (oid == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    asnber_err_t status = asnber_node_get_oid(oid, out_oid, out_oid_size);
    if (status != ASNBER_OK) {
        return status;
    }

    const asnber_node_t *parameters = nestedField(algorithm, "parameters");
    if (parameters == nullptr) {
        *out_parameters = nullptr;
        *out_parameters_size = 0;
        return ASNBER_OK;
    }
    *out_parameters = asnber_node_tlv(parameters, out_parameters_size);
    return (*out_parameters == nullptr) ? ASNBER_E_INVALID_STATE : ASNBER_OK;
}

} // namespace cms_detail

#endif /* ASNBER_CMS_STRUCTURE_SUPPORT_H_INCLUDED */
