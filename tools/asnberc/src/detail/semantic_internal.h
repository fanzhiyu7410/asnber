/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 语义分析器内部定义。
 *
 * 只允许 tools/asnberc/src 同一子系统的 cpp 包含。类的数据成员与布局
 * 与拆分前完全一致，成员函数按语法区在各自编译单元定义。
 */

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "ast.h"
#include "diag.h"
#include "semantic.h"

#ifndef ASNBERC_SEMANTIC_INTERNAL_H_INCLUDED
#define ASNBERC_SEMANTIC_INTERNAL_H_INCLUDED

namespace asnberc {
namespace semantic_detail {

constexpr uint32_t kTypeFlagExtensible = 1u;
constexpr uint16_t kFieldFlagOptional = 1u;
constexpr uint16_t kFieldFlagExtension = 2u;

constexpr uint8_t kTagModeDefault = 0;
constexpr uint8_t kTagModeExplicit = 1;
constexpr uint8_t kTagModeImplicit = 2;
constexpr uint8_t kTagClassUniversal = 0;
constexpr uint8_t kTagClassContext = 2;

class Analyzer {
public:
    Analyzer(const ModuleSet &modules, Diagnostics &diagnostics, SchemaModel *model);

    void run(const std::string &rootName);

private:
    struct ValueSymbol {
        bool isOid = false;
        bool isInteger = false;
        std::vector<uint64_t> oid;
        int64_t integer = 0;
    };

    struct BoundValue {
        bool unbounded = false;
        int64_t value = 0;
    };

    enum class ValueClass { Oid, Integer, Other, Undefined };

    void error(const Pos &pos, DiagCode code, const std::string &message);

    void errorAt(uint32_t unit, const Pos &pos, DiagCode code,
                 const std::string &message);

    const std::string &fileFor(uint32_t unit) const;

    const ModuleUnit &unitAt(uint32_t index) const;

    static std::string symbolKey(uint32_t unit, const std::string &name);

    /* 解析未限定名：先本模块定义，再本模块导入。命中时给出定义模块与本地名。 */
    bool findTypeBinding(uint32_t unit, const std::string &name,
                         uint32_t &outUnit, std::string &outLocal) const;

    bool findValueBinding(uint32_t unit, const std::string &name,
                          uint32_t &outUnit, std::string &outLocal) const;

    const TypeAst *findTypeAst(uint32_t unit, const std::string &name) const;

    /* 返回命名类型的形参列表；非模板类型返回空向量。 */
    const std::vector<std::string> *findParams(uint32_t unit,
                                               const std::string &name) const;

    uint32_t mergedTagMode() const;

    void registerNamedTypes();

    ValueClass classifyValueType(const TypeAst *ast) const;

    void processValues();

    bool lookupInteger(const std::string &name, int64_t &out) const;

    bool tryEvaluateOid(const ValueAst &value, std::vector<uint64_t> &arcs);

    bool evaluateOid(const ValueAst &value, std::vector<uint64_t> &arcs,
                     DiagCode unresolvedCode);

    TypeNode *resolveNamed(uint32_t index);

    TypeNode *ensureNamed(const std::string &name, const Pos &pos);

    TypeNode *newSynthetic(const std::string &hint);

    static std::string sanitize(const std::string &hint);

    TypeNode *sharedAny();

    static void copyNode(const TypeNode *source, TypeNode *target);

    bool applyTag(TypeNode *node, const TagSpec &tag);

    bool fillNode(TypeNode *node, const TypeAst &ast);

    /* 参数化实例化展开：把模板形参替换为实参，返回合成 TypeNode。 */
    TypeNode *instantiate(const std::string &templateName, const Pos &pos,
                          const std::vector<std::unique_ptr<TypeAst>> &args);

    static std::unique_ptr<TypeAst> cloneTypeAst(const TypeAst &source);
    static void substituteParams(TypeAst &ast,
                                 const std::map<std::string, const TypeAst *> &args);

    bool addEnumConstraint(TypeNode *node, const TypeAst &ast);

    bool resolveFields(TypeNode *owner, const TypeAst &ast);

    bool resolveFieldType(const FieldAst &fieldAst, const std::string &owner,
                          Field &field);

    TypeNode *resolveExprToNode(const TypeAst &ast, const std::string &hint);

    bool resolveElement(const TypeAst &ast, const std::string &hint,
                        TypeNode *&out);

    bool buildConstraints(const std::vector<ConstraintAst> &source,
                          std::vector<Constraint> &target,
                          const Pos &pos);

    bool resolveBound(const ConstraintBoundAst &bound, bool lowerBound,
                      BoundValue &out, const Pos &pos);

    bool resolveInteger(const TypeNode *type, const ValueAst &value,
                        const Pos &pos, int64_t &out);

    bool encodeSimpleContent(const TypeNode *type, const ValueAst &value,
                             const Pos &pos, std::vector<uint8_t> &content);

    bool encodeDefault(Field &field, const ValueAst &value, const Pos &pos);

    static void noteFiniteSize(const std::vector<Constraint> &list,
                               bool &found, int64_t &upper);

    bool finiteSizeUpperBound(const TypeNode &type, int64_t &upper) const;

    /* 0 = BIT_NAME、1 = NUMBER_NAME；无法由名称表表达时返回 2。 */
    uint32_t namedKindFor(const TypeNode &node) const;

    void checkNamedValues();

    void checkStructure();

    void checkDuplicateFields(const TypeNode &node);

    void checkTagConflicts(const TypeNode &node);

    void reportUnresolvedTag(const Field &field, uint32_t unit);

    void assignIds();

    const ModuleSet &modules_;
    Diagnostics &diagnostics_;
    SchemaModel *model_;
    std::vector<const TypeAst *> namedAsts_;
    std::vector<std::vector<std::string>> namedParams_;
    std::vector<uint32_t> namedUnits_;
    std::vector<uint8_t> namedState_;
    std::map<std::string, uint32_t> typeIndex_;
    std::map<std::string, ValueSymbol> values_;
    std::map<std::string, TypeNode *> instantiationCache_;
    uint32_t currentUnit_ = 0;
    uint32_t syntheticCounter_ = 0;
};

} /* namespace semantic_detail */
} /* namespace asnberc */

#endif /* ASNBERC_SEMANTIC_INTERNAL_H_INCLUDED */
