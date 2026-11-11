/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * libFuzzer harness：asnberc 词法/语法/语义/描述表生成入口。
 * 任意 .asn1 文本；返回错误码/诊断属正常行为。仅崩溃/泄漏/超时算失败。
 */
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include "module_set.h"
#include "semantic.h"
#include "table.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const std::string source(reinterpret_cast<const char *>(data), size);
    asnberc::Diagnostics diag;
    asnberc::ModuleSet modules;

    if (!modules.addSource("fuzz.asn1", source, true, diag)) {
        return 0;
    }
    if (!modules.resolve(diag) || diag.hasError()) {
        return 0;
    }

    std::unique_ptr<asnberc::SchemaModel> model =
        asnberc::analyzeModules(modules, "", diag);
    if (!diag.hasError() && model) {
        const asnberc::TableOutput output =
            asnberc::buildTable(*model, modules.units()[0]->name);
        (void)asnberc::renderCArray(output);
    }

    return 0;
}
