/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

#include "module_set.h"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <set>
#include <string>
#include <vector>

#include "parser.h"

namespace asnberc {

const char *const ModuleSet::kExtension = ".asn1";

namespace {

bool readFile(const std::string &path, std::string &out)
{
    std::ifstream stream(path.c_str(), std::ios::binary);
    /* 某些 MinGW/libstdc++ 组合在 open 失败时不置 failbit，is_open 仍需检查。 */
    if (!stream || !stream.is_open()) {
        return false;
    }
    std::string data;
    char ch = 0;
    while (stream.get(ch)) {
        data.push_back(ch);
    }
    if (stream.bad()) {
        return false;
    }
    out = std::move(data);
    return true;
}

/* 返回父目录；无分隔符时返回空串（表示当前目录）。 */
std::string dirName(const std::string &path)
{
    const size_t slash = path.find_last_of("/\\");
    if (slash == std::string::npos) {
        return std::string();
    }
    if (slash == 0) {
        return path.substr(0, 1);
    }
    return path.substr(0, slash);
}

std::string joinPath(const std::string &dir, const std::string &name)
{
    if (dir.empty()) {
        return name;
    }
    if (dir.back() == '/' || dir.back() == '\\') {
        return dir + name;
    }
    return dir + "/" + name;
}

bool fileExists(const std::string &path)
{
    std::ifstream stream(path.c_str(), std::ios::binary);
    return stream.is_open();
}

} /* namespace */

ModuleUnit *ModuleSet::find(const std::string &name)
{
    std::map<std::string, ModuleUnit *>::iterator it = byName_.find(name);
    return it == byName_.end() ? nullptr : it->second;
}

const ModuleUnit *ModuleSet::find(const std::string &name) const
{
    std::map<std::string, ModuleUnit *>::const_iterator it =
        byName_.find(name);
    return it == byName_.end() ? nullptr : it->second;
}

size_t ModuleSet::indexOf(const ModuleUnit *unit) const
{
    for (size_t i = 0; i < units_.size(); ++i) {
        if (units_[i].get() == unit) {
            return i;
        }
    }
    return units_.size();
}

bool ModuleSet::addSource(const std::string &path, const std::string &source,
                          bool explicitInput, Diagnostics &diagnostics)
{
    std::unique_ptr<ModuleUnit> unit = std::make_unique<ModuleUnit>();
    unit->file = path;
    unit->explicitInput = explicitInput;
    if (!parseModule(path, source, unit->ast, diagnostics)) {
        return false;
    }
    const ModuleUnit *existing = find(unit->ast.name);
    if (existing != nullptr) {
        diagnostics.add(path, unit->ast.namePos.line,
                        unit->ast.namePos.column, Severity::Error,
                        DiagCode::DuplicateType,
                        "duplicate module name '" + unit->ast.name +
                            "' (also declared in '" + existing->file + "')");
        return false;
    }
    unit->name = unit->ast.name;
    byName_[unit->name] = unit.get();
    units_.push_back(std::move(unit));
    return true;
}

bool ModuleSet::loadFile(const std::string &path, bool explicitInput,
                         Diagnostics &diagnostics)
{
    std::string source;
    if (!readFile(path, source)) {
        return false;
    }
    return addSource(path, source, explicitInput, diagnostics);
}

void ModuleSet::sortMergeOrder()
{
    std::stable_sort(
        units_.begin(), units_.end(),
        [](const std::unique_ptr<ModuleUnit> &a,
           const std::unique_ptr<ModuleUnit> &b) {
            if (a->explicitInput != b->explicitInput) {
                return a->explicitInput;
            }
            if (a->explicitInput) {
                /* 显式输入保持命令行顺序。 */
                return false;
            }
            return a->name < b->name;
        });
}

ModuleSet::LoadResult ModuleSet::load(
    const std::vector<std::string> &inputs,
    const std::vector<std::string> &includeDirs, Diagnostics &diagnostics)
{
    searchDirs_.clear();
    for (const std::string &input : inputs) {
        const std::string dir = dirName(input);
        if (std::find(searchDirs_.begin(), searchDirs_.end(), dir) ==
            searchDirs_.end()) {
            searchDirs_.push_back(dir);
        }
    }
    for (const std::string &dir : includeDirs) {
        if (std::find(searchDirs_.begin(), searchDirs_.end(), dir) ==
            searchDirs_.end()) {
            searchDirs_.push_back(dir);
        }
    }

    for (const std::string &input : inputs) {
        if (!loadFile(input, true, diagnostics)) {
            if (!diagnostics.hasError()) {
                diagnostics.add(input, 0, 0, Severity::Error,
                                DiagCode::OutputIo, "cannot read input file");
                return LoadResult::IoError;
            }
            return LoadResult::ParseError;
        }
    }

    /* 按需装载：循环遍历增长中的 units_，把 IMPORTS 引用的模块补齐。 */
    for (size_t i = 0; i < units_.size(); ++i) {
        const std::vector<ImportGroupAst> &groups = units_[i]->ast.imports;
        for (const ImportGroupAst &group : groups) {
            if (find(group.moduleName) != nullptr) {
                continue;
            }
            std::string path;
            if (!locateModuleFile(group.moduleName, path)) {
                /* 留给绑定阶段报“模块不存在”。 */
                continue;
            }
            if (!loadFile(path, false, diagnostics)) {
                if (!diagnostics.hasError()) {
                    diagnostics.add(path, 0, 0, Severity::Error,
                                    DiagCode::OutputIo,
                                    "cannot read module file");
                    return LoadResult::IoError;
                }
                return LoadResult::ParseError;
            }
        }
    }

    sortMergeOrder();
    return LoadResult::Ok;
}

bool ModuleSet::locateModuleFile(const std::string &moduleName,
                                 std::string &path) const
{
    const std::string fileName = moduleName + kExtension;
    for (const std::string &dir : searchDirs_) {
        const std::string candidate = joinPath(dir, fileName);
        if (fileExists(candidate)) {
            path = candidate;
            return true;
        }
    }
    return false;
}

void ModuleSet::buildIndices(Diagnostics &diagnostics)
{
    for (const std::unique_ptr<ModuleUnit> &unit : units_) {
        for (size_t i = 0; i < unit->ast.types.size(); ++i) {
            const TypeAssignment &assignment = unit->ast.types[i];
            if (!unit->typeIndex.emplace(assignment.name, i).second) {
                diagnostics.add(unit->file, assignment.pos.line,
                                assignment.pos.column, Severity::Error,
                                DiagCode::DuplicateType,
                                "duplicate type name '" + assignment.name +
                                    "'");
            }
        }
        for (size_t i = 0; i < unit->ast.values.size(); ++i) {
            unit->valueIndex[unit->ast.values[i].name] = i;
        }
    }
}

void ModuleSet::validateExports(Diagnostics &diagnostics)
{
    for (const std::unique_ptr<ModuleUnit> &unit : units_) {
        if (!unit->ast.exports.present || unit->ast.exports.all) {
            unit->exportsAll = true;
            continue;
        }
        unit->exportsAll = false;
        for (const ImportSymbolAst &symbol : unit->ast.exports.symbols) {
            const bool isType = unit->typeIndex.count(symbol.name) != 0;
            const bool isValue = unit->valueIndex.count(symbol.name) != 0;
            if (!isType && !isValue) {
                diagnostics.add(unit->file, symbol.pos.line,
                                symbol.pos.column, Severity::Error,
                                DiagCode::UndefinedType,
                                "exported symbol '" + symbol.name +
                                    "' is not defined in module '" +
                                    unit->name + "'");
                continue;
            }
            if (isType) {
                unit->exportedTypes.insert(symbol.name);
            }
            if (isValue) {
                unit->exportedValues.insert(symbol.name);
            }
        }
    }
}

bool ModuleSet::bindImports(Diagnostics &diagnostics)
{
    bool ok = true;
    for (const std::unique_ptr<ModuleUnit> &unit : units_) {
        for (const ImportGroupAst &group : unit->ast.imports) {
            const ModuleUnit *target = find(group.moduleName);
            if (target == nullptr) {
                diagnostics.add(unit->file, group.pos.line,
                                group.pos.column, Severity::Error,
                                DiagCode::UndefinedType,
                                "imported module '" + group.moduleName +
                                    "' is not found");
                ok = false;
                continue;
            }
            if (target == unit.get()) {
                diagnostics.add(unit->file, group.pos.line,
                                group.pos.column, Severity::Error,
                                DiagCode::UndefinedType,
                                "module '" + unit->name +
                                    "' cannot import from itself");
                ok = false;
                continue;
            }
            for (const ImportSymbolAst &symbol : group.symbols) {
                const bool hasType =
                    target->typeIndex.count(symbol.name) != 0;
                const bool hasValue =
                    target->valueIndex.count(symbol.name) != 0;
                const bool typeOk = hasType && target->exportsType(symbol.name);
                const bool valueOk =
                    hasValue && target->exportsValue(symbol.name);
                if (!typeOk && !valueOk) {
                    diagnostics.add(
                        unit->file, symbol.pos.line, symbol.pos.column,
                        Severity::Error, DiagCode::UndefinedType,
                        hasType || hasValue
                            ? "symbol '" + symbol.name +
                                  "' is not exported by module '" +
                                  target->name + "'"
                            : "symbol '" + symbol.name +
                                  "' is not defined in module '" +
                                  target->name + "'");
                    ok = false;
                    continue;
                }
                if (typeOk) {
                    std::map<std::string, size_t>::const_iterator local =
                        unit->typeIndex.find(symbol.name);
                    if (local != unit->typeIndex.end()) {
                        diagnostics.add(
                            unit->file, symbol.pos.line, symbol.pos.column,
                            Severity::Error, DiagCode::DuplicateType,
                            "imported name '" + symbol.name +
                                "' conflicts with a local definition in "
                                "module '" +
                                unit->name + "'");
                        ok = false;
                    } else {
                        std::pair<std::map<std::string,
                                            const ModuleUnit *>::iterator,
                                  bool>
                            inserted = unit->importedTypes.emplace(
                                symbol.name, target);
                        if (!inserted.second &&
                            inserted.first->second != target) {
                            diagnostics.add(
                                unit->file, symbol.pos.line,
                                symbol.pos.column, Severity::Error,
                                DiagCode::DuplicateType,
                                "name '" + symbol.name +
                                    "' is imported from both '" +
                                    inserted.first->second->name + "' and '" +
                                    target->name + "'");
                            ok = false;
                        }
                    }
                }
                if (valueOk) {
                    std::map<std::string, size_t>::const_iterator local =
                        unit->valueIndex.find(symbol.name);
                    if (local != unit->valueIndex.end()) {
                        diagnostics.add(
                            unit->file, symbol.pos.line, symbol.pos.column,
                            Severity::Error, DiagCode::DuplicateType,
                            "imported name '" + symbol.name +
                                "' conflicts with a local definition in "
                                "module '" +
                                unit->name + "'");
                        ok = false;
                    } else {
                        std::pair<std::map<std::string,
                                            const ModuleUnit *>::iterator,
                                  bool>
                            inserted = unit->importedValues.emplace(
                                symbol.name, target);
                        if (!inserted.second &&
                            inserted.first->second != target) {
                            diagnostics.add(
                                unit->file, symbol.pos.line,
                                symbol.pos.column, Severity::Error,
                                DiagCode::DuplicateType,
                                "name '" + symbol.name +
                                    "' is imported from both '" +
                                    inserted.first->second->name + "' and '" +
                                    target->name + "'");
                            ok = false;
                        }
                    }
                }
            }
        }
    }
    return ok;
}

bool ModuleSet::visitModule(size_t index, std::vector<int> &state,
                            std::vector<size_t> &stack,
                            Diagnostics &diagnostics)
{
    state[index] = 1;
    stack.push_back(index);
    const ModuleUnit &unit = *units_[index];
    for (const ImportGroupAst &group : unit.ast.imports) {
        const ModuleUnit *target = find(group.moduleName);
        if (target == nullptr || target == &unit) {
            continue;
        }
        const size_t next = indexOf(target);
        if (next == units_.size()) {
            continue;
        }
        if (state[next] == 1) {
            std::string path;
            size_t start = 0;
            for (size_t i = 0; i < stack.size(); ++i) {
                if (stack[i] == next) {
                    start = i;
                    break;
                }
            }
            for (size_t i = start; i < stack.size(); ++i) {
                path += units_[stack[i]]->name + " -> ";
            }
            path += target->name;
            diagnostics.add(unit.file, group.pos.line, group.pos.column,
                            Severity::Error, DiagCode::UndefinedType,
                            "cyclic import: " + path);
            return false;
        }
        if (state[next] == 0 && !visitModule(next, state, stack,
                                             diagnostics)) {
            return false;
        }
    }
    stack.pop_back();
    state[index] = 2;
    return true;
}

bool ModuleSet::checkCycles(Diagnostics &diagnostics)
{
    std::vector<int> state(units_.size(), 0);
    std::vector<size_t> stack;
    for (size_t i = 0; i < units_.size(); ++i) {
        if (state[i] == 0 && !visitModule(i, state, stack, diagnostics)) {
            return false;
        }
    }
    return true;
}

void ModuleSet::assignTableNames()
{
    std::set<std::string> used;
    for (const std::unique_ptr<ModuleUnit> &unit : units_) {
        for (const TypeAssignment &assignment : unit->ast.types) {
            std::string name = assignment.name;
            if (!used.insert(name).second) {
                for (uint32_t suffix = 1;; ++suffix) {
                    std::string candidate =
                        assignment.name + "-" + unit->name;
                    if (suffix > 1) {
                        candidate += "-" + std::to_string(suffix);
                    }
                    if (used.insert(candidate).second) {
                        name = candidate;
                        break;
                    }
                }
            }
            unit->tableNames[assignment.name] = name;
        }
    }
}

bool ModuleSet::resolve(Diagnostics &diagnostics)
{
    buildIndices(diagnostics);
    validateExports(diagnostics);
    const bool bound = bindImports(diagnostics);
    const bool acyclic = checkCycles(diagnostics);
    assignTableNames();
    return bound && acyclic && !diagnostics.hasError();
}

bool ModuleSet::resolveRoot(const std::string &rootName,
                            Diagnostics &diagnostics, RootRef &out) const
{
    const std::string atFile = units_.empty() ? std::string() : units_[0]->file;
    const size_t dot = rootName.find('.');
    if (dot != std::string::npos) {
        const std::string moduleName = rootName.substr(0, dot);
        const std::string localName = rootName.substr(dot + 1);
        const ModuleUnit *unit = find(moduleName);
        if (unit == nullptr || localName.empty() ||
            unit->typeIndex.count(localName) == 0) {
            diagnostics.add(atFile, 0, 0, Severity::Error,
                            DiagCode::UndefinedType,
                            "root type '" + rootName + "' is not defined");
            return false;
        }
        out.unit = unit;
        out.localName = localName;
        return true;
    }

    const ModuleUnit *found = nullptr;
    std::string modules;
    for (const std::unique_ptr<ModuleUnit> &unit : units_) {
        if (unit->typeIndex.count(rootName) == 0) {
            continue;
        }
        if (found == nullptr) {
            found = unit.get();
        } else {
            modules += (modules.empty() ? "'" : ", '") + unit->name + "'";
        }
    }
    if (found == nullptr) {
        diagnostics.add(atFile, 0, 0, Severity::Error,
                        DiagCode::UndefinedType,
                        "root type '" + rootName + "' is not defined");
        return false;
    }
    if (!modules.empty()) {
        diagnostics.add(atFile, 0, 0, Severity::Error,
                        DiagCode::DuplicateType,
                        "root type '" + rootName +
                            "' is ambiguous: defined in modules '" +
                            found->name + "' and " + modules +
                            "; use 'Module.Type'");
        return false;
    }
    out.unit = found;
    out.localName = rootName;
    return true;
}

} /* namespace asnberc */
