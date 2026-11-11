/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 诊断收集、稳定排序与输出。
 * 单行格式严格为：<file>:<line>:<column>: <severity>: <code>: <message>
 * 错误码取自 docs/11-描述表格式.md §16.2。
 */
#ifndef ASNBERC_DIAG_H_INCLUDED
#define ASNBERC_DIAG_H_INCLUDED

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace asnberc {

enum class Severity { Error, Warning };

enum class DiagCode : uint32_t {
    Syntax = 9001,
    UndefinedType = 9002,
    DuplicateType = 9003,
    DuplicateField = 9004,
    TagConflict = 9005,
    UnsupportedConstruct = 9006,
    ParamInstantiation = 9008,
    ConstraintInvalid = 9009,
    OutputIo = 9010,
    Internal = 9099,
    UnusedImport = 9101,
    DeprecatedSyntax = 9102
};

enum class DiagLevel { Minimal, Normal, Verbose };

struct Diagnostic {
    std::string file;
    uint32_t line = 0;
    uint32_t column = 0;
    Severity severity = Severity::Error;
    DiagCode code = DiagCode::Internal;
    std::string message;
};

class Diagnostics {
public:
    void add(const std::string &file, uint32_t line, uint32_t column,
             Severity severity, DiagCode code, const std::string &message);
    bool hasError() const noexcept;
    size_t size() const noexcept;
    const std::vector<Diagnostic> &items() const noexcept;

private:
    std::vector<Diagnostic> items_;
};

const char *codeName(DiagCode code) noexcept;
const char *severityName(Severity severity) noexcept;

/* 按 file/line/column/code 升序稳定输出；minimal 只输出 error。 */
void printDiagnostics(const Diagnostics &diagnostics, DiagLevel level,
                      std::FILE *out);

} /* namespace asnberc */

#endif /* ASNBERC_DIAG_H_INCLUDED */
