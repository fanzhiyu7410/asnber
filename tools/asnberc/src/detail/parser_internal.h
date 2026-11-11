/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 递归下降解析器内部定义。
 *
 * 只允许 tools/asnberc/src 同一子系统的 cpp 包含。类的数据成员与布局
 * 与拆分前完全一致，成员函数按语法区在各自编译单元定义。
 */

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "ast.h"
#include "diag.h"
#include "lexer.h"

#ifndef ASNBERC_PARSER_INTERNAL_H_INCLUDED
#define ASNBERC_PARSER_INTERNAL_H_INCLUDED

namespace asnberc {
namespace parser_detail {

class Parser {

public:
    Parser(const std::string &file, const std::vector<Token> &tokens, Diagnostics &diagnostics);

    bool run(ModuleAst &out);

private:
    const Token &peek(size_t offset = 0) const;

    void advance();

    void syntaxError(const Pos &pos, const std::string &message);

    void unsupported(const Pos &pos, const std::string &message);

    bool expectKeyword(const char *keyword, const std::string &message);

    bool expectToken(TokenKind kind, const std::string &message);

    bool skipBalancedBraces();

    /* 顶层错误恢复：跳过到分号或 END，括号深度归零。 */
    void skipToSync();

    bool parseDeclaration(ModuleAst &out);

    bool parseImports(ModuleAst &out);

    bool parseExports(ModuleAst &out);

    bool parseSymbolList(std::vector<ImportSymbolAst> &out);

    bool parseTypeExpr(TypeAst &out);

    bool parseTag(TagSpec &out);

    bool parseBase(TypeAst &out);

    bool parseFieldList(TypeAst &out);

    bool parseNamedNumbers(TypeAst &out, bool allowEllipsis);

    bool parseConstraintList(std::vector<ConstraintAst> &out);

    bool parseBounds(ConstraintAst &constraint);

    bool parseBound(ConstraintBoundAst &bound);

    bool parseValue(ValueAst &out);

    bool parseBraceParts(std::vector<BracePartAst> &out);

    bool parseUnsigned(const Token &token, uint64_t &out) const;

    bool parseSigned(const Token &token, bool negated, int64_t &out) const;

    const std::string &file_;
    const std::vector<Token> &tokens_;
    Diagnostics &diagnostics_;
    size_t index_ = 0;
};

} /* namespace parser_detail */
} /* namespace asnberc */

#endif /* ASNBERC_PARSER_INTERNAL_H_INCLUDED */
