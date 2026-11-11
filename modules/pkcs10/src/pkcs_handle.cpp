/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

#include "pkcs_handle.h"

#include <asnber/asnber_node.h>

#include <cstdlib>

namespace pkcs10_internal {

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

} // namespace pkcs10_internal
