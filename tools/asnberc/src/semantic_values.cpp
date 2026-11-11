/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "detail/semantic_internal.h"

namespace asnberc {
namespace semantic_detail {

Analyzer::ValueClass Analyzer::classifyValueType(const TypeAst *ast) const
{
    const TypeAst *current = ast;
    for (uint32_t depth = 0; depth < 32 && current != nullptr; ++depth) {
        if (current->cls == TypeAst::Class::ObjectIdentifier) {
            return ValueClass::Oid;
        }
        if (current->cls == TypeAst::Class::Integer) {
            return ValueClass::Integer;
        }
        if (current->cls != TypeAst::Class::Reference) {
            return ValueClass::Other;
        }
        current = findTypeAst(currentUnit_, current->refName);
        if (current == nullptr) {
            return ValueClass::Undefined;
        }
    }
    return ValueClass::Other;
}

void Analyzer::processValues()
{
    const std::vector<std::unique_ptr<ModuleUnit>> &units = modules_.units();

    /*
     * 跨模块后值赋值可以引用另一模块的值，且模块顺序不等于依赖顺序。
     * 用不动点迭代：能算的立即登记，算不了的留到下一轮；值数量很小。
     */
    bool progress = true;
    while (progress) {
        progress = false;
        for (size_t unitIndex = 0; unitIndex < units.size(); ++unitIndex) {
            currentUnit_ = static_cast<uint32_t>(unitIndex);
            for (const ValueAssignment &assignment :
                 units[unitIndex]->ast.values) {
                const std::string key =
                    symbolKey(currentUnit_, assignment.name);
                if (values_.count(key) != 0) {
                    continue;
                }
                if (classifyValueType(assignment.type.get()) ==
                    ValueClass::Undefined) {
                    continue;
                }
                ValueSymbol symbol;
                if (assignment.value->kind == ValueAst::Kind::Oid) {
                    if (!tryEvaluateOid(*assignment.value, symbol.oid)) {
                        continue;
                    }
                    symbol.isOid = true;
                } else if (assignment.value->kind ==
                           ValueAst::Kind::Integer) {
                    symbol.isInteger = true;
                    symbol.integer = assignment.value->intValue;
                } else if (assignment.value->kind ==
                           ValueAst::Kind::Reference) {
                    if (!lookupInteger(assignment.value->text,
                                       symbol.integer)) {
                        continue;
                    }
                    symbol.isInteger = true;
                }
                values_[key] = symbol;
                progress = true;
            }
        }
    }

    /* 仍未解析的按失败报出，位置与消息沿用单模块行为。 */
    for (size_t unitIndex = 0; unitIndex < units.size(); ++unitIndex) {
        currentUnit_ = static_cast<uint32_t>(unitIndex);
        for (const ValueAssignment &assignment :
             units[unitIndex]->ast.values) {
            if (values_.count(symbolKey(currentUnit_, assignment.name)) !=
                0) {
                continue;
            }
            if (classifyValueType(assignment.type.get()) ==
                ValueClass::Undefined) {
                /* 类型仍不存在时，通常来自被裁剪的信息对象类（如
                 * ATTRIBUTE），按不支持构造报出。 */
                error(assignment.type->pos,
                      DiagCode::UnsupportedConstruct,
                      "information object/object set or CLASS-based type "
                      "reference '" +
                          assignment.type->refName +
                          "' is not supported");
                continue;
            }
            if (assignment.value->kind == ValueAst::Kind::Oid) {
                std::vector<uint64_t> discarded;
                evaluateOid(*assignment.value, discarded,
                            DiagCode::ConstraintInvalid);
            } else if (assignment.value->kind ==
                       ValueAst::Kind::Reference) {
                error(assignment.value->pos, DiagCode::UndefinedType,
                      "undefined integer value '" +
                          assignment.value->text + "'");
            }
        }
    }
}

bool Analyzer::lookupInteger(const std::string &name, int64_t &out) const
{
    uint32_t boundUnit = 0;
    std::string local;
    if (!findValueBinding(currentUnit_, name, boundUnit, local)) {
        return false;
    }
    std::map<std::string, ValueSymbol>::const_iterator it = values_.find(
        symbolKey(boundUnit, local));
    if (it == values_.end() || !it->second.isInteger) {
        return false;
    }
    out = it->second.integer;
    return true;
}

bool Analyzer::tryEvaluateOid(const ValueAst &value,
                              std::vector<uint64_t> &arcs)
{
    for (const BracePartAst &part : value.parts) {
        if (part.hasNumber) {
            arcs.push_back(part.number);
            continue;
        }
        uint32_t boundUnit = 0;
        std::string local;
        if (!findValueBinding(currentUnit_, part.name, boundUnit, local)) {
            return false;
        }
        std::map<std::string, ValueSymbol>::const_iterator it = values_.find(
            symbolKey(boundUnit, local));
        if (it == values_.end() || !it->second.isOid) {
            return false;
        }
        for (uint64_t arc : it->second.oid) {
            arcs.push_back(arc);
        }
    }
    return true;
}

bool Analyzer::evaluateOid(const ValueAst &value, std::vector<uint64_t> &arcs,
                 DiagCode unresolvedCode)
{
    for (const BracePartAst &part : value.parts) {
        if (part.hasNumber) {
            arcs.push_back(part.number);
            continue;
        }
        uint32_t boundUnit = 0;
        std::string local;
        std::map<std::string, ValueSymbol>::const_iterator it = values_.end();
        if (findValueBinding(currentUnit_, part.name, boundUnit, local)) {
            it = values_.find(symbolKey(boundUnit, local));
        }
        if (it == values_.end() || !it->second.isOid) {
            error(part.pos, unresolvedCode,
                  "undefined OBJECT IDENTIFIER value '" + part.name +
                      "'");
            return false;
        }
        for (uint64_t arc : it->second.oid) {
            arcs.push_back(arc);
        }
    }
    return true;
}

} /* namespace semantic_detail */
} /* namespace asnberc */
