/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * schema 运行时注册内部共享定义。
 *
 * 只允许 src/schema 同一子系统的 cpp 包含。上下文级分配、类型/字段增长、
 * 约束复制与标签展开接口集中在此。
 */

#ifndef ASNBER_SCHEMA_INTERNAL_H_INCLUDED
#define ASNBER_SCHEMA_INTERNAL_H_INCLUDED

#include <cstddef>
#include <cstdint>

#include "schema/asnber_schema.h"

namespace asnber {
namespace schema_detail {

/* 分配与复制：分配一律计入 AllocationKind::kSchema。 */
asnber_err_t allocateSchema(Context *ctx, size_t size, void **out) noexcept;
bool countOverflowsSize(size_t count, size_t elementSize) noexcept;
asnber_err_t copyText(Context *ctx, const char *src, const char **out,
                    asnber_err_t invalidCode) noexcept;
asnber_err_t copyBytes(Context *ctx, const void *src, size_t size,
                     const uint8_t **out, asnber_err_t invalidCode) noexcept;

/* 类型规则 */
bool validTagMode(uint32_t mode) noexcept;
bool isOfKind(uint32_t kind) noexcept;
asnber_err_t validateTypeCombination(uint32_t kind, uint32_t tagClass,
                                   uint32_t tagNumber, uint32_t tagMode) noexcept;
asnber_err_t growTypes(Context *ctx, Schema *schema) noexcept;
asnber_err_t growFields(Context *ctx, SchemaType *type) noexcept;
asnber_err_t growNames(Context *ctx, Schema *schema) noexcept;
SchemaType *findType(Schema *schema, uint32_t typeId) noexcept;
const SchemaType *findType(const Schema *schema, uint32_t typeId) noexcept;
asnber_err_t appendType(Context *ctx, Schema *schema,
                      const asnber_type_desc_t *desc,
                      bool allowUnregisteredElement,
                      uint32_t *outTypeId) noexcept;
asnber_err_t appendField(Context *ctx, Schema *schema, uint32_t parentTypeId,
                       const asnber_field_desc_t *desc) noexcept;

/* 约束 */
asnber_err_t validateSchemaConstraintArray(Context *ctx,
                                         const SchemaConstraint *array,
                                         uint32_t count) noexcept;
asnber_err_t copyConstraints(Context *ctx, const asnber_constraint_t *src,
                           uint32_t count, SchemaConstraint **out,
                           uint32_t *outCount) noexcept;
void destroyConstraintArray(Context *ctx, SchemaConstraint *constraints,
                            uint32_t count) noexcept;

/* 标签展开 */
struct EffectiveTag {
    uint32_t tagClass;
    uint32_t tagNumber;
};

struct TagSet {
    EffectiveTag tags[kSchemaMaxTagSet];
    uint32_t count;
};

bool collectTags(const Schema &schema, uint32_t typeId, uint32_t depth,
                 TagSet *out) noexcept;
bool tagsIntersect(const TagSet &a, const TagSet &b) noexcept;

} /* namespace schema_detail */
} /* namespace asnber */

#endif /* ASNBER_SCHEMA_INTERNAL_H_INCLUDED */
