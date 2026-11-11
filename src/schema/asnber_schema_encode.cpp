/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * schema 感知编码入口：测量文档目标尺寸并写出字节，尺寸与写出实现见
 * 同目录 asnber_schema_encode_size.cpp 与 asnber_schema_encode_write.cpp。
 */

#include "schema/detail/schema_encode_internal.h"

namespace asnber {

using namespace schema_encode_detail;

asnber_err_t schemaMeasureDocument(Context *ctx, const Document *doc,
                                 const Schema *schema, size_t *outSize) noexcept
{
    if (ctx == nullptr || doc == nullptr || doc->root == nullptr ||
        schema == nullptr || !schema->sealed || schema->rootTypeId == 0 ||
        outSize == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    EncState st{};
    st.ctx = ctx;
    st.doc = doc;
    st.schema = schema;
    st.defaultTlv = nullptr;
    st.defaultSize = 0;
    size_t size = 0;
    asnber_err_t error = ASNBER_OK;
    if (!sizeOf(st, schema->rootTypeId, doc->root, false, &size, &error)) {
        contextSetError(ctx, error, SIZE_MAX, 0);
        return error;
    }
    *outSize = size;
    return ASNBER_OK;
}

asnber_err_t schemaEncodeDocument(Context *ctx, const Document *doc,
                                const Schema *schema, uint8_t *dst,
                                size_t capacity) noexcept
{
    if (ctx == nullptr || doc == nullptr || doc->root == nullptr ||
        schema == nullptr || dst == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    EncState st{};
    st.ctx = ctx;
    st.doc = doc;
    st.schema = schema;
    st.defaultTlv = nullptr;
    st.defaultSize = 0;
    size_t total = 0;
    asnber_err_t error = ASNBER_OK;
    size_t used = 0;
    if (!sizeOf(st, schema->rootTypeId, doc->root, false, &total, &error)) {
        contextSetError(ctx, error, SIZE_MAX, 0);
        return error;
    }
    if (total > capacity) {
        contextSetError(ctx, ASNBER_E_OUTPUT_LIMIT, SIZE_MAX, 0);
        return ASNBER_E_OUTPUT_LIMIT;
    }
    if (!writeOf(st, schema->rootTypeId, doc->root, false, dst, capacity, &used,
                 &error)) {
        contextSetError(ctx, error, SIZE_MAX, 0);
        return error;
    }
    if (used != total) {
        contextSetError(ctx, ASNBER_E_INVALID_STATE, SIZE_MAX, 0);
        return ASNBER_E_INVALID_STATE;
    }
    return ASNBER_OK;
}

} /* namespace asnber */
