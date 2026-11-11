/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * schema 感知解码内部共享定义。
 *
 * 只允许 src/schema 同一子系统的 cpp 包含。绑定上下文与跨翻译单元复用
 * 的标签匹配、约束求值、类型绑定入口集中在此。
 */

#ifndef ASNBER_SCHEMA_DECODE_INTERNAL_H_INCLUDED
#define ASNBER_SCHEMA_DECODE_INTERNAL_H_INCLUDED

#include <cstddef>
#include <cstdint>

#include "ber/asnber_ber_decoder.h"
#include "schema/asnber_schema.h"
#include "types/asnber_dom.h"

namespace asnber {
namespace schema_decode_detail {

/* 绑定/校验共用状态；mutate 为 false 时只校验、不修改节点。 */
struct BindContext {
    Context *ctx;
    Schema *schema;
    Document *doc;
    bool strict;
    bool warn;
    bool mutate;
    uint32_t maxDepth;
};

/* 按 1 基类型 id 取类型；越界返回 nullptr。 */
const SchemaType *typeAt(const Schema *schema, uint32_t typeId);
uint32_t effectiveTagMode(const Schema *schema, const SchemaType *type);
bool expectedTag(const Schema *schema, const SchemaType *type, bool unwrapped,
                 uint32_t *outClass, uint32_t *outNumber);
bool tagMatches(const Schema *schema, const SchemaType *type, const Node *node,
                bool unwrapped);

/* 逐条求值约束，第一条失败即返回。 */
int evalConstraints(BindContext &bind,
                    const SchemaConstraint *constraints, uint32_t count,
                    const Node *node, const char *path);

/* 按类型 id 绑定节点；unwrapped 表示外层显式包装已剥离。 */
int bindType(BindContext &bind, uint32_t typeId, Node *node,
             const char *fieldName, bool unwrapped, uint32_t depth,
             const char *path);

} /* namespace schema_decode_detail */
} /* namespace asnber */

#endif /* ASNBER_SCHEMA_DECODE_INTERNAL_H_INCLUDED */
