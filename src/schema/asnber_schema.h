/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * schema 内部模型：类型树、字段、约束与描述表加载。
 *
 * 职责：定义 docs/11-描述表格式.md 与 docs/02-C-API规范.md 6.2 的
 *       内部类型树，并同时服务运行时注册与描述表加载两条入口。
 * 依赖：core/asnber_context.h 与公共 ABI。
 * 所有权：Schema 及全部名称、数组、默认值字节均为上下文级分配
 *         （AllocationKind::kSchema），随 asnber_schema_destroy 释放；
 *         上下文销毁时由 contextDestroy 兜底回收。
 */
#ifndef ASNBER_SRC_SCHEMA_ASNBER_SCHEMA_H_INCLUDED
#define ASNBER_SRC_SCHEMA_ASNBER_SCHEMA_H_INCLUDED

#include <asnber/asnber.h>

#include <cstddef>
#include <cstdint>

#include "../core/asnber_context.h"

namespace asnber {

constexpr uint32_t kSchemaMagic = UINT32_C(0x53434831); /* "SCH1" */

/* 描述表格式版本与固定布局，与 docs/11-描述表格式.md 一致。 */
constexpr uint32_t kSchemaFormatMajor = 1;
constexpr uint32_t kSchemaFormatMinor = 0;
constexpr uint32_t kSchemaHeaderSize = 96;         /* 可接受的最小头部 */
constexpr uint32_t kSchemaHeaderLegacyBaseSize = 100; /* 旧基线（root_type_id） */
constexpr uint32_t kSchemaHeaderBaseSize = 108; /* 当前基线（含名称表字段） */
constexpr uint32_t kSchemaTypeRecordSize = 48;
constexpr uint32_t kSchemaFieldRecordSize = 32;
constexpr uint32_t kSchemaConstraintRecordSize = 48;
constexpr uint32_t kSchemaDefaultRecordSize = 8;
constexpr uint32_t kSchemaNameRecordSize = 24;

/* 标签展开的上限；无法在有限展开内确定集合时按 schema 类型错误处理。 */
constexpr uint32_t kSchemaMaxTagDepth = 32;
constexpr uint32_t kSchemaMaxTagSet = 128;

struct SchemaBound {
    bool unbounded;
    bool hasDecimal;
    int64_t value;
    const char *decimal;
    size_t decimalSize;
};

struct SchemaConstraint {
    uint32_t kind;              /* asnber_constraint_kind_t */
    bool lowerUnbounded;
    bool upperUnbounded;
    SchemaBound lower;
    SchemaBound upper;
    const int64_t *enumValues;
    uint32_t enumCount;
};

struct SchemaField {
    const char *name;
    uint32_t typeId;            /* 1-based */
    uint32_t flags;
    const uint8_t *defaultTlv;
    size_t defaultSize;
    SchemaConstraint *constraints;
    uint32_t constraintCount;
};

struct SchemaType {
    const char *name;
    uint32_t kind;              /* asnber_type_kind_t */
    uint32_t tagClass;          /* asnber_tag_class_t */
    uint32_t tagNumber;
    uint32_t tagMode;           /* asnber_tag_mode_t */
    uint32_t elementTypeId;     /* 仅 OF 有效，1-based；否则 0 */
    uint32_t flags;
    SchemaField *fields;
    uint32_t fieldCount;
    uint32_t fieldCapacity;
    SchemaConstraint *constraints;
    uint32_t constraintCount;
};

/* 命名位 / 名值。name 为 schema 级分配，随 schema 释放。 */
struct SchemaName {
    uint32_t typeId;            /* 1-based */
    const char *name;
    uint32_t kind;              /* 0 BIT_NAME / 1 NUMBER_NAME */
    uint32_t flags;             /* 位 0 = EXTENSION */
    int64_t value;
};

struct Schema {
    Context *ctx;
    uint32_t moduleTagMode;     /* asnber_tag_mode_t */
    uint32_t rootTypeId;        /* 0 = 无单一根；否则 1-based */
    bool sealed;
    SchemaType *types;
    uint32_t typeCount;
    uint32_t typeCapacity;
    SchemaName *names;
    uint32_t nameCount;
    uint32_t nameCapacity;
    uint32_t magic;
};

/* 创建空 schema；defaultTagMode 只接受 DEFAULT/EXPLICIT/IMPLICIT。 */
asnber_err_t schemaCreate(Context *ctx, uint32_t defaultTagMode,
                        Schema **outSchema) noexcept;

/* 从描述表构建并封存；失败时不返回部分类型树。 */
asnber_err_t schemaLoad(Context *ctx, const asnber_schema_table_t *table,
                      Schema **outSchema) noexcept;

/*
 * 同 schemaLoad，但根类型由调用方指定：rootTypeId == 0 沿用表头，
 * 非 0 覆盖表头且必须落在 1..typeCount（越界返回 ASNBER_E_INVALID_ARG）。
 */
asnber_err_t schemaLoadWithRoot(Context *ctx, const asnber_schema_table_t *table,
                              uint32_t rootTypeId,
                              Schema **outSchema) noexcept;

asnber_err_t schemaAddType(Context *ctx, Schema *schema,
                         const asnber_type_desc_t *desc, uint32_t *outTypeId,
                         bool allowUnregisteredElement) noexcept;

asnber_err_t schemaAddField(Context *ctx, Schema *schema,
                          uint32_t parentTypeId,
                          const asnber_field_desc_t *desc) noexcept;

/*
 * 追加一条命名位/名值记录（仅描述表加载路径使用）；name 复制进上下文。
 * 调用方负责描述表层面的语义校验。
 */
asnber_err_t schemaAddName(Context *ctx, Schema *schema, uint32_t typeId,
                         const char *name, uint32_t kind, uint32_t flags,
                         int64_t value) noexcept;

asnber_err_t schemaSeal(Context *ctx, Schema *schema) noexcept;

/* 设置/清除根类型；0 表示清除。 */
asnber_err_t schemaSetRoot(Context *ctx, Schema *schema,
                         uint32_t rootTypeId) noexcept;

void schemaDestroy(Schema *schema) noexcept;

/* 比较两个规范十进制文本：-1/0/1；非法文本返回 false。 */
bool schemaCompareDecimal(const char *left, size_t leftSize,
                          const char *right, size_t rightSize,
                          int *outOrder) noexcept;

/* CRC32C（Castagnoli），zeroOffset/zeroLength 指定的字节按 0 参与计算。 */
uint32_t schemaCrc32c(const uint8_t *data, size_t size, size_t zeroOffset,
                      size_t zeroLength) noexcept;

/* 校验默认值为结构自洽的 DER TLV（最短长度、无不定长、无尾随字节）。 */
bool schemaValidateDefaultTlv(const uint8_t *data, size_t size) noexcept;

} /* namespace asnber */

#endif /* ASNBER_SRC_SCHEMA_ASNBER_SCHEMA_H_INCLUDED */
