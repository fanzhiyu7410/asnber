/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 多模块装载与符号表：把多个 `.asn1` 文件（以及按 `-I` 搜索到的模块）变成
 * 一组带导入绑定的模块单元，并给出合并进单张描述表时的类型名。
 * 语义规则见 docs/specs/a-multimodule-imports/spec.md。
 */
#ifndef ASNBERC_MODULE_SET_H_INCLUDED
#define ASNBERC_MODULE_SET_H_INCLUDED

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "ast.h"
#include "diag.h"

namespace asnberc {

struct ModuleUnit {
    std::string name;
    std::string file;
    ModuleAst ast;
    bool explicitInput = false;

    /* 本地名 -> ast.types / ast.values 下标。 */
    std::map<std::string, size_t> typeIndex;
    std::map<std::string, size_t> valueIndex;

    /* 导入绑定：本地名 -> 定义模块。 */
    std::map<std::string, const ModuleUnit *> importedTypes;
    std::map<std::string, const ModuleUnit *> importedValues;

    /* 合并进描述表后的类型名（跨模块同名时按 §3.3 改名）。 */
    std::map<std::string, std::string> tableNames;

    bool exportsAll = true;
    std::set<std::string> exportedTypes;
    std::set<std::string> exportedValues;

    bool exportsType(const std::string &symbol) const
    {
        return exportsAll || exportedTypes.count(symbol) != 0;
    }
    bool exportsValue(const std::string &symbol) const
    {
        return exportsAll || exportedValues.count(symbol) != 0;
    }
};

struct RootRef {
    const ModuleUnit *unit = nullptr;
    std::string localName;
};

class ModuleSet {
public:
    /* IO 失败（输入文件读不到）与语义/语法失败需要不同的退出码。 */
    enum class LoadResult { Ok, ParseError, IoError };

    LoadResult load(const std::vector<std::string> &inputs,
                    const std::vector<std::string> &includeDirs,
                    Diagnostics &diagnostics);

    /* 以内存文本装载单个模块，走与 load() 相同的解析与登记路径。
     * 供测试与模糊测试在无磁盘 IO 的情况下驱动语义分析与描述表生成。 */
    bool addSource(const std::string &path, const std::string &source,
                   bool explicitInput, Diagnostics &diagnostics);

    /* 建索引、校验 EXPORTS、绑定 IMPORTS、检测环、分配表内名称。 */
    bool resolve(Diagnostics &diagnostics);

    const std::vector<std::unique_ptr<ModuleUnit>> &units() const noexcept
    {
        return units_;
    }

    size_t indexOf(const ModuleUnit *unit) const;

    /* 解析 `TYPE` 或 `MODULE.TYPE`；失败时写入诊断并返回 false。 */
    bool resolveRoot(const std::string &rootName, Diagnostics &diagnostics,
                     RootRef &out) const;

private:
    ModuleUnit *find(const std::string &name);
    const ModuleUnit *find(const std::string &name) const;

    bool loadFile(const std::string &path, bool explicitInput,
                  Diagnostics &diagnostics);
    bool locateModuleFile(const std::string &moduleName, std::string &path) const;

    void buildIndices(Diagnostics &diagnostics);
    void validateExports(Diagnostics &diagnostics);
    bool bindImports(Diagnostics &diagnostics);
    bool checkCycles(Diagnostics &diagnostics);
    bool visitModule(size_t index, std::vector<int> &state,
                     std::vector<size_t> &stack, Diagnostics &diagnostics);
    void assignTableNames();
    void sortMergeOrder();

    std::vector<std::unique_ptr<ModuleUnit>> units_;
    std::map<std::string, ModuleUnit *> byName_;
    std::vector<std::string> searchDirs_;

    static const char *const kExtension;
};

} /* namespace asnberc */

#endif /* ASNBERC_MODULE_SET_H_INCLUDED */
