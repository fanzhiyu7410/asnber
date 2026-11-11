/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnberc 命令行入口：只做 CLI 编排，具体工作委托给词法/语法/语义/表生成模块。
 * 退出码：0 成功，1 存在 error 诊断，2 命令行用法错误，3 IO 失败。
 */

#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include "asnberc_version.h"

#include "diag.h"
#include "module_set.h"
#include "parser.h"
#include "semantic.h"
#include "trim.h"
#include "table.h"

namespace {

void printUsage(std::FILE *out)
{
    std::fprintf(
        out,
        "Usage: asnberc [OPTIONS] <input.asn1>...\n"
        "  -o, --output-bin <PATH>   写二进制描述表\n"
        "  -c, --output-c <PATH>     写 C 数组源文件\n"
        "  -I, --include <DIR>       追加模块搜索目录（可重复）\n"
        "      --root <TYPE-NAME>    设置根类型，可写 MODULE.TYPE（默认不设）\n"
        "      --trim-schema         从 --root 出发裁剪不可达类型（需配合 --root）\n"
        "      --diagnostics <LEVEL> minimal|normal|verbose（默认 normal）\n"
        "      --version             打印版本\n"
        "  -h, --help                打印本帮助\n");
}

bool startsWith(const std::string &text, const char *prefix)
{
    const size_t length = std::strlen(prefix);
    return text.size() >= length &&
           text.compare(0, length, prefix) == 0;
}

bool writeBinary(const std::string &path, const std::vector<uint8_t> &bytes)
{
    std::ofstream stream(path.c_str(),
                         std::ios::binary | std::ios::trunc);
    if (!stream) {
        return false;
    }
    stream.write(reinterpret_cast<const char *>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    stream.flush();
    if (!stream.good()) {
        stream.close();
        std::remove(path.c_str());
        return false;
    }
    stream.close();
    return true;
}

bool writeText(const std::string &path, const std::string &text)
{
    std::ofstream stream(path.c_str(),
                         std::ios::binary | std::ios::trunc);
    if (!stream) {
        return false;
    }
    stream.write(text.data(), static_cast<std::streamsize>(text.size()));
    stream.flush();
    if (!stream.good()) {
        stream.close();
        std::remove(path.c_str());
        return false;
    }
    stream.close();
    return true;
}

int usageError(const std::string &message)
{
    std::fprintf(stderr, "asnberc: %s\n", message.c_str());
    printUsage(stderr);
    return 2;
}

} /* namespace */

int main(int argc, char **argv)
{
    std::vector<std::string> inputs;
    std::vector<std::string> includeDirs;
    std::string outputBin;
    std::string outputC;
    std::string rootName;
    bool trimSchema = false;
    bool haveMinimal = false;
    bool haveNormal = false;
    bool haveVerbose = false;

    for (int i = 1; i < argc; ++i) {
        const std::string argument = argv[i];
        if (argument == "--version") {
            std::printf("asnberc %s\n", ASNBERC_VERSION_STRING);
            return 0;
        }
        if (argument == "-h" || argument == "--help") {
            printUsage(stdout);
            return 0;
        }
        if (argument == "-o" || argument == "--output-bin") {
            if (i + 1 >= argc) {
                return usageError("missing value for " + argument);
            }
            outputBin = argv[++i];
        } else if (startsWith(argument, "--output-bin=")) {
            outputBin = argument.substr(std::strlen("--output-bin="));
        } else if (argument == "-c" || argument == "--output-c") {
            if (i + 1 >= argc) {
                return usageError("missing value for " + argument);
            }
            outputC = argv[++i];
        } else if (startsWith(argument, "--output-c=")) {
            outputC = argument.substr(std::strlen("--output-c="));
        } else if (argument == "--trim-schema") {
            trimSchema = true;
        } else if (argument == "--root") {
            if (i + 1 >= argc) {
                return usageError("missing value for --root");
            }
            rootName = argv[++i];
        } else if (startsWith(argument, "--root=")) {
            rootName = argument.substr(std::strlen("--root="));
        } else if (argument == "--diagnostics") {
            if (i + 1 >= argc) {
                return usageError("missing value for --diagnostics");
            }
            const std::string level = argv[++i];
            if (level == "minimal") {
                haveMinimal = true;
            } else if (level == "normal") {
                haveNormal = true;
            } else if (level == "verbose") {
                haveVerbose = true;
            } else {
                return usageError("invalid --diagnostics level '" + level +
                                  "'");
            }
        } else if (startsWith(argument, "--diagnostics=")) {
            const std::string level =
                argument.substr(std::strlen("--diagnostics="));
            if (level == "minimal") {
                haveMinimal = true;
            } else if (level == "normal") {
                haveNormal = true;
            } else if (level == "verbose") {
                haveVerbose = true;
            } else {
                return usageError("invalid --diagnostics level '" + level +
                                  "'");
            }
        } else if (argument == "-I" || argument == "--include") {
            if (i + 1 >= argc) {
                return usageError("missing value for " + argument);
            }
            includeDirs.push_back(argv[++i]);
        } else if (startsWith(argument, "--include=")) {
            includeDirs.push_back(argument.substr(std::strlen("--include=")));
        } else if (!argument.empty() && argument[0] == '-') {
            return usageError("unknown option '" + argument + "'");
        } else {
            inputs.push_back(argument);
        }
    }

    if (inputs.empty()) {
        return usageError("missing input file");
    }
    if (trimSchema && rootName.empty()) {
        return usageError("--trim-schema requires --root");
    }
    if (outputBin.empty() && outputC.empty()) {
        return usageError("at least one of -o/--output-bin or -c/--output-c "
                          "is required");
    }
    if (haveMinimal && (haveNormal || haveVerbose)) {
        return usageError("conflicting --diagnostics levels");
    }
    if (haveNormal && haveVerbose) {
        return usageError("conflicting --diagnostics levels");
    }
    const asnberc::DiagLevel level =
        haveMinimal ? asnberc::DiagLevel::Minimal
                    : (haveVerbose ? asnberc::DiagLevel::Verbose
                                   : asnberc::DiagLevel::Normal);

    asnberc::Diagnostics diagnostics;
    asnberc::ModuleSet modules;
    const asnberc::ModuleSet::LoadResult loaded =
        modules.load(inputs, includeDirs, diagnostics);
    if (loaded != asnberc::ModuleSet::LoadResult::Ok) {
        asnberc::printDiagnostics(diagnostics, level, stderr);
        return loaded == asnberc::ModuleSet::LoadResult::IoError ? 3 : 1;
    }
    if (!modules.resolve(diagnostics) || diagnostics.hasError()) {
        asnberc::printDiagnostics(diagnostics, level, stderr);
        return 1;
    }

    std::unique_ptr<asnberc::SchemaModel> model =
        asnberc::analyzeModules(modules, rootName, diagnostics);
    if (diagnostics.hasError()) {
        asnberc::printDiagnostics(diagnostics, level, stderr);
        return 1;
    }

    if (trimSchema) {
        asnberc::trimToRootType(*model);
    }

    const asnberc::TableOutput output =
        asnberc::buildTable(*model, modules.units()[0]->name);

    bool ioFailed = false;
    if (!outputBin.empty() && !writeBinary(outputBin, output.bytes)) {
        diagnostics.add(outputBin, 0, 0, asnberc::Severity::Error,
                        asnberc::DiagCode::OutputIo,
                        "cannot write output file");
        ioFailed = true;
    }
    if (!outputC.empty() && !ioFailed) {
        const std::string text = asnberc::renderCArray(output);
        if (!writeText(outputC, text)) {
            diagnostics.add(outputC, 0, 0, asnberc::Severity::Error,
                            asnberc::DiagCode::OutputIo,
                            "cannot write output file");
            ioFailed = true;
        }
    }
    if (ioFailed) {
        asnberc::printDiagnostics(diagnostics, level, stderr);
        return 3;
    }

    if (level == asnberc::DiagLevel::Verbose) {
        std::fprintf(stderr, "asnberc: %u types (%u named, %u synthesized), "
                             "%zu bytes\n",
                     static_cast<unsigned>(output.typeCount),
                     static_cast<unsigned>(output.namedTypeCount),
                     static_cast<unsigned>(output.typeCount -
                                           output.namedTypeCount),
                     output.bytes.size());
    }
    asnberc::printDiagnostics(diagnostics, level, stderr);
    return 0;
}
