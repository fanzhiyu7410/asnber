/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 语义模型：符号表、类型/字段记录、匿名与标签克隆类型、默认值 DER 编码、
 * 结构检查。类型编号规则见 docs/11-描述表格式.md §4：具名类型先按源码顺序
 * 占 1..N，合成类型随后按确定遍历顺序分配。
 */
#ifndef ASNBERC_SEMANTIC_H_INCLUDED
#define ASNBERC_SEMANTIC_H_INCLUDED

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "ast.h"
#include "diag.h"
#include "module_set.h"

namespace asnberc {

enum class TypeKind : uint32_t {
    Simple = 0,
    Sequence = 1,
    Set = 2,
    Choice = 3,
    SequenceOf = 4,
    SetOf = 5,
    Any = 6
};

struct Constraint {
    uint16_t kind = 0; /* 0 RANGE、1 SIZE、2 ENUM、3 MAX */
    bool lowerUnbounded = false;
    bool upperUnbounded = false;
    int64_t lower = 0;
    int64_t upper = 0;
    std::vector<int64_t> enumValues;
};

struct NamedValue {
    std::string name;
    int64_t value = 0;
    bool extension = false; /* ENUMERATED 中位于 `...` 之后的命名值 */
    Pos pos;
};

struct TypeNode;

struct Field {
    std::string name;
    uint32_t line = 0;
    uint32_t column = 0;
    TypeNode *type = nullptr;
    uint16_t flags = 0;
    bool hasDefault = false;
    std::vector<uint8_t> defaultTlv;
    std::vector<Constraint> constraints;
};

struct TypeNode {
    std::string name;
    bool synthetic = false;
    /* 参数化模板：不直接展开，不出现在最终描述表中，仅供实例化使用。 */
    bool isTemplate = false;
    TypeKind kind = TypeKind::Simple;
    uint8_t tagMode = 0;  /* 0 DEFAULT、1 EXPLICIT、2 IMPLICIT */
    uint8_t tagClass = 0; /* 0 UNIVERSAL、2 CONTEXT */
    uint32_t tagNumber = 0;
    uint32_t baseTagNumber = 0; /* 通用标签号，用于显式包装内层与默认值编码 */
    uint32_t flags = 0;
    TypeNode *element = nullptr;
    std::vector<Field> fields;
    std::vector<Constraint> constraints;
    std::vector<NamedValue> namedValues;
    uint32_t id = 0;
    /* 定义所在模块单元下标：多模块合并后诊断要回到正确的源文件。 */
    uint32_t unit = 0;
};

struct SchemaModel {
    std::vector<std::unique_ptr<TypeNode>> nodes;
    std::vector<TypeNode *> named;
    std::vector<TypeNode *> synthetic;
    TypeNode *anyNode = nullptr;
    uint32_t moduleTagMode = 3;
    uint32_t rootTypeId = 0;
};

/*
 * rootName 为空表示不设置根类型。返回的模型在存在诊断错误时可能不完整，
 * 调用方应先检查 diagnostics.hasError()。
 */
std::unique_ptr<SchemaModel> analyzeModules(const ModuleSet &modules,
                                            const std::string &rootName,
                                            Diagnostics &diagnostics);

} /* namespace asnberc */

#endif /* ASNBERC_SEMANTIC_H_INCLUDED */
