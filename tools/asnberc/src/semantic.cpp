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

Analyzer::Analyzer(const ModuleSet &modules, Diagnostics &diagnostics,
                   SchemaModel *model)
    : modules_(modules), diagnostics_(diagnostics), model_(model)
{
}

void Analyzer::run(const std::string &rootName)
{
    model_->moduleTagMode = mergedTagMode();
    registerNamedTypes();
    processValues();
    for (size_t i = 0; i < model_->named.size(); ++i) {
        resolveNamed(static_cast<uint32_t>(i));
    }
    checkNamedValues();
    checkStructure();
    assignIds();
    if (rootName.empty()) {
        return;
    }
    RootRef root;
    if (!modules_.resolveRoot(rootName, diagnostics_, root)) {
        return;
    }
    const size_t unitIndex = modules_.indexOf(root.unit);
    if (unitIndex == modules_.units().size()) {
        errorAt(0, Pos{0, 0}, DiagCode::UndefinedType,
                "root type '" + rootName + "' is not defined");
        return;
    }
    std::map<std::string, uint32_t>::const_iterator it = typeIndex_.find(
        symbolKey(static_cast<uint32_t>(unitIndex), root.localName));
    if (it == typeIndex_.end()) {
        errorAt(static_cast<uint32_t>(unitIndex), Pos{0, 0},
                DiagCode::UndefinedType,
                "root type '" + rootName + "' is not defined");
        return;
    }
    model_->rootTypeId = resolveNamed(it->second)->id;
}

uint32_t Analyzer::mergedTagMode() const
{
    const std::vector<std::unique_ptr<ModuleUnit>> &units = modules_.units();
    if (units.empty()) {
        return 3;
    }
    const uint32_t first = static_cast<uint32_t>(units[0]->ast.tagMode);
    for (const std::unique_ptr<ModuleUnit> &unit : units) {
        if (static_cast<uint32_t>(unit->ast.tagMode) != first) {
            /* 模块标注方式不一致时没有单一继承来源，写“未声明”。 */
            return 3;
        }
    }
    return first;
}

void Analyzer::error(const Pos &pos, DiagCode code, const std::string &message)
{
    errorAt(currentUnit_, pos, code, message);
}

void Analyzer::errorAt(uint32_t unit, const Pos &pos, DiagCode code,
                       const std::string &message)
{
    diagnostics_.add(fileFor(unit), pos.line, pos.column, Severity::Error, code,
                     message);
}

const std::string &Analyzer::fileFor(uint32_t unit) const
{
    const std::vector<std::unique_ptr<ModuleUnit>> &units = modules_.units();
    if (unit < units.size()) {
        return units[unit]->file;
    }
    static const std::string empty;
    return empty;
}

const ModuleUnit &Analyzer::unitAt(uint32_t index) const
{
    return *modules_.units()[index];
}

std::string Analyzer::symbolKey(uint32_t unit, const std::string &name)
{
    return std::to_string(unit) + "/" + name;
}

bool Analyzer::findTypeBinding(uint32_t unit, const std::string &name,
                               uint32_t &outUnit, std::string &outLocal) const
{
    const ModuleUnit &current = unitAt(unit);
    if (current.typeIndex.count(name) != 0) {
        outUnit = unit;
        outLocal = name;
        return true;
    }
    std::map<std::string, const ModuleUnit *>::const_iterator it =
        current.importedTypes.find(name);
    if (it == current.importedTypes.end()) {
        return false;
    }
    const size_t target = modules_.indexOf(it->second);
    if (target == modules_.units().size()) {
        return false;
    }
    outUnit = static_cast<uint32_t>(target);
    outLocal = name;
    return true;
}

bool Analyzer::findValueBinding(uint32_t unit, const std::string &name,
                                uint32_t &outUnit, std::string &outLocal) const
{
    const ModuleUnit &current = unitAt(unit);
    if (current.valueIndex.count(name) != 0) {
        outUnit = unit;
        outLocal = name;
        return true;
    }
    std::map<std::string, const ModuleUnit *>::const_iterator it =
        current.importedValues.find(name);
    if (it == current.importedValues.end()) {
        return false;
    }
    const size_t target = modules_.indexOf(it->second);
    if (target == modules_.units().size()) {
        return false;
    }
    outUnit = static_cast<uint32_t>(target);
    outLocal = name;
    return true;
}

const TypeAst *Analyzer::findTypeAst(uint32_t unit, const std::string &name) const
{
    uint32_t boundUnit = 0;
    std::string local;
    if (!findTypeBinding(unit, name, boundUnit, local)) {
        return nullptr;
    }
    std::map<std::string, uint32_t>::const_iterator it = typeIndex_.find(
        symbolKey(boundUnit, local));
    if (it == typeIndex_.end()) {
        return nullptr;
    }
    return namedAsts_[it->second];
}

const std::vector<std::string> *Analyzer::findParams(uint32_t unit,
                                                      const std::string &name) const
{
    uint32_t boundUnit = 0;
    std::string local;
    if (!findTypeBinding(unit, name, boundUnit, local)) {
        return nullptr;
    }
    std::map<std::string, uint32_t>::const_iterator it = typeIndex_.find(
        symbolKey(boundUnit, local));
    if (it == typeIndex_.end()) {
        return nullptr;
    }
    return &namedParams_[it->second];
}

void Analyzer::registerNamedTypes()
{
    const std::vector<std::unique_ptr<ModuleUnit>> &units = modules_.units();
    for (size_t unitIndex = 0; unitIndex < units.size(); ++unitIndex) {
        const ModuleUnit &unit = *units[unitIndex];
        for (const TypeAssignment &assignment : unit.ast.types) {
            std::unique_ptr<TypeNode> node = std::make_unique<TypeNode>();
            std::map<std::string, std::string>::const_iterator name =
                unit.tableNames.find(assignment.name);
            node->name = name == unit.tableNames.end() ? assignment.name
                                                       : name->second;
            node->unit = static_cast<uint32_t>(unitIndex);
            node->synthetic = false;
            node->isTemplate = !assignment.params.empty();
            model_->nodes.push_back(std::move(node));
            TypeNode *pointer = model_->nodes.back().get();
            const uint32_t index =
                static_cast<uint32_t>(model_->named.size());
            model_->named.push_back(pointer);
            namedAsts_.push_back(assignment.type.get());
            namedParams_.push_back(assignment.params);
            namedUnits_.push_back(static_cast<uint32_t>(unitIndex));
            namedState_.push_back(0);
            typeIndex_[symbolKey(static_cast<uint32_t>(unitIndex),
                                 assignment.name)] = index;
        }
    }
}

} /* namespace semantic_detail */

using namespace semantic_detail;

std::unique_ptr<SchemaModel> analyzeModules(const ModuleSet &modules,
                                            const std::string &rootName,
                                            Diagnostics &diagnostics)
{
    std::unique_ptr<SchemaModel> model = std::make_unique<SchemaModel>();
    Analyzer analyzer(modules, diagnostics, model.get());
    analyzer.run(rootName);
    return model;
}

} /* namespace asnberc */
