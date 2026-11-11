/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

#include "pkcs_handle.h"

#include <asnber/asnber_node.h>

#include <cstdlib>

namespace pkcs8_internal {

void closeStructure(handle_base *object) noexcept
{
    if (object == nullptr) {
        return;
    }
    asnber_doc_destroy(object->doc);
    asnber_schema_destroy(object->schema);
    std::free(object);
}

const asnber_node_t *field(const handle_base *object,
                         const char *name) noexcept
{
    return asnber_node_child_by_name(object->root, name);
}

const asnber_node_t *nestedField(const handle_base *object,
                               const char *container,
                               const char *name) noexcept
{
    const asnber_node_t *parent = field(object, container);
    if (parent == nullptr) {
        return nullptr;
    }
    return asnber_node_child_by_name(parent, name);
}

asnber_err_t requireField(const handle_base *object, const char *name,
                        const asnber_node_t **out_node) noexcept
{
    const asnber_node_t *node = field(object, name);
    if (node == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    *out_node = node;
    return ASNBER_OK;
}

asnber_err_t algorithmOid(const handle_base *object, const char *container,
                        const char **out_dotted,
                        size_t *out_size) noexcept
{
    const asnber_node_t *node =
        nestedField(object, container, "algorithm");
    if (node == nullptr) {
        return ASNBER_E_SCHEMA_FIELD;
    }
    return asnber_node_get_oid(node, out_dotted, out_size);
}

/*
 * ANY 参数：返回完整原始 TLV；字段缺省时按“无参数”返回 ASNBER_OK + NULL/0，
 * 与 find 语义一致，避免调用方把 OPTIONAL 缺省当错误。
 */
asnber_err_t algorithmParameters(const handle_base *object,
                               const char *container,
                               const uint8_t **out_data,
                               size_t *out_size) noexcept
{
    const asnber_node_t *node = nestedField(object, container, "parameters");
    if (node == nullptr) {
        *out_data = nullptr;
        *out_size = 0;
        return ASNBER_OK;
    }
    *out_data = asnber_node_tlv(node, out_size);
    return (*out_data == nullptr) ? ASNBER_E_INVALID_STATE : ASNBER_OK;
}

asnber_err_t octetsField(const handle_base *object, const char *name,
                       const uint8_t **out_data,
                       size_t *out_size) noexcept
{
    const asnber_node_t *node = nullptr;
    asnber_err_t status = requireField(object, name, &node);
    if (status != ASNBER_OK) {
        return status;
    }
    return asnber_node_get_octets(node, out_data, out_size);
}

asnber_err_t tlvField(const handle_base *object, const char *name,
                    const uint8_t **out_data, size_t *out_size) noexcept
{
    const asnber_node_t *node = nullptr;
    asnber_err_t status = requireField(object, name, &node);
    if (status != ASNBER_OK) {
        return status;
    }
    *out_data = asnber_node_tlv(node, out_size);
    return (*out_data == nullptr) ? ASNBER_E_INVALID_STATE : ASNBER_OK;
}

} // namespace pkcs8_internal
