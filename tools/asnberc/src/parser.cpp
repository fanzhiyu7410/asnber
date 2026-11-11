/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

#include <memory>
#include <string>
#include <vector>

#include "detail/parser_internal.h"

namespace asnberc {
namespace parser_detail {

Parser::Parser(const std::string &file, const std::vector<Token> &tokens,
       Diagnostics &diagnostics)
    : file_(file), tokens_(tokens), diagnostics_(diagnostics)
{
}

bool Parser::run(ModuleAst &out)
{
    if (peek().kind != TokenKind::Identifier) {
        syntaxError(peek().pos, "expected module name");
        return false;
    }
    out.name = peek().text;
    out.namePos = peek().pos;
    advance();

    /* 可选的模块 OID `{ ... }`，本轮不进入描述表。 */
    if (peek().kind == TokenKind::LBrace) {
        if (!skipBalancedBraces()) {
            return false;
        }
    }

    if (!expectKeyword("DEFINITIONS", "expected DEFINITIONS")) {
        return false;
    }
    if (keywordEquals(peek(), "EXPLICIT")) {
        advance();
        out.tagMode = 1;
        if (!expectKeyword("TAGS", "expected TAGS")) {
            return false;
        }
    } else if (keywordEquals(peek(), "IMPLICIT")) {
        advance();
        out.tagMode = 2;
        if (!expectKeyword("TAGS", "expected TAGS")) {
            return false;
        }
    } else if (keywordEquals(peek(), "AUTOMATIC")) {
        advance();
        out.tagMode = 0;
        if (!expectKeyword("TAGS", "expected TAGS")) {
            return false;
        }
    } else {
        out.tagMode = 3;
    }

    if (!expectToken(TokenKind::Assign, "expected '::='")) {
        return false;
    }
    if (!expectKeyword("BEGIN", "expected BEGIN")) {
        return false;
    }

    while (true) {
        if (peek().kind == TokenKind::End) {
            syntaxError(peek().pos, "missing END");
            return false;
        }
        if (keywordEquals(peek(), "END")) {
            advance();
            break;
        }
        if (keywordEquals(peek(), "IMPORTS")) {
            if (!parseImports(out)) {
                if (peek().kind == TokenKind::End) {
                    syntaxError(peek().pos, "missing END");
                    return false;
                }
                skipToSync();
            }
            continue;
        }
        if (keywordEquals(peek(), "EXPORTS")) {
            if (!parseExports(out)) {
                if (peek().kind == TokenKind::End) {
                    syntaxError(peek().pos, "missing END");
                    return false;
                }
                skipToSync();
            }
            continue;
        }
        if (!parseDeclaration(out)) {
            if (peek().kind == TokenKind::End) {
                syntaxError(peek().pos, "missing END");
                return false;
            }
            skipToSync();
        }
    }

    if (peek().kind != TokenKind::End) {
        syntaxError(peek().pos, "unexpected token after END");
        return false;
    }
    return !diagnostics_.hasError();
}

const Token &Parser::peek(size_t offset) const
{
    const size_t at = index_ + offset;
    return at < tokens_.size() ? tokens_[at] : tokens_.back();
}

void Parser::advance()
{
    if (index_ + 1 < tokens_.size()) {
        ++index_;
    }
}

void Parser::syntaxError(const Pos &pos, const std::string &message)
{
    diagnostics_.add(file_, pos.line, pos.column, Severity::Error,
                     DiagCode::Syntax, message);
}

void Parser::unsupported(const Pos &pos, const std::string &message)
{
    diagnostics_.add(file_, pos.line, pos.column, Severity::Error,
                     DiagCode::UnsupportedConstruct, message);
}

bool Parser::expectKeyword(const char *keyword, const std::string &message)
{
    if (!keywordEquals(peek(), keyword)) {
        syntaxError(peek().pos, message);
        return false;
    }
    advance();
    return true;
}

bool Parser::expectToken(TokenKind kind, const std::string &message)
{
    if (peek().kind != kind) {
        syntaxError(peek().pos, message);
        return false;
    }
    advance();
    return true;
}

bool Parser::skipBalancedBraces()
{
    if (peek().kind != TokenKind::LBrace) {
        syntaxError(peek().pos, "expected '{'");
        return false;
    }
    uint32_t depth = 0;
    while (peek().kind != TokenKind::End) {
        if (peek().kind == TokenKind::LBrace) {
            ++depth;
        } else if (peek().kind == TokenKind::RBrace) {
            --depth;
            if (depth == 0) {
                advance();
                return true;
            }
        }
        advance();
    }
    syntaxError(peek().pos, "unterminated '{'");
    return false;
}

void Parser::skipToSync()
{
    uint32_t depth = 0;
    while (peek().kind != TokenKind::End) {
        if (depth == 0 && keywordEquals(peek(), "END")) {
            return;
        }
        if (peek().kind == TokenKind::LBrace) {
            ++depth;
        } else if (peek().kind == TokenKind::RBrace) {
            if (depth > 0) {
                --depth;
            }
        } else if (peek().kind == TokenKind::Semicolon && depth == 0) {
            advance();
            return;
        }
        advance();
    }
}

bool Parser::parseSymbolList(std::vector<ImportSymbolAst> &out)
{
    bool needSymbol = true;
    while (true) {
        if (peek().kind == TokenKind::Comma) {
            advance();
            needSymbol = true;
            continue;
        }
        if (peek().kind == TokenKind::Identifier &&
            !keywordEquals(peek(), "FROM")) {
            ImportSymbolAst symbol;
            symbol.name = peek().text;
            symbol.pos = peek().pos;
            out.push_back(std::move(symbol));
            advance();
            needSymbol = false;
            continue;
        }
        break;
    }
    if (out.empty() || needSymbol) {
        syntaxError(peek().pos, "expected symbol name");
        return false;
    }
    return true;
}

bool Parser::parseImports(ModuleAst &out)
{
    const Pos clausePos = peek().pos;
    advance(); /* IMPORTS */
    if (!out.imports.empty()) {
        syntaxError(clausePos, "duplicate IMPORTS clause");
        return false;
    }
    while (true) {
        ImportGroupAst group;
        if (!parseSymbolList(group.symbols)) {
            return false;
        }
        if (!expectKeyword("FROM", "expected FROM in IMPORTS")) {
            return false;
        }
        if (peek().kind != TokenKind::Identifier) {
            syntaxError(peek().pos, "expected module name after FROM");
            return false;
        }
        group.moduleName = peek().text;
        group.pos = peek().pos;
        advance();
        /* 可选的模块 OID `{ ... }`，与模块头一致，不进入描述表。 */
        if (peek().kind == TokenKind::LBrace && !skipBalancedBraces()) {
            return false;
        }
        out.imports.push_back(std::move(group));
        if (peek().kind == TokenKind::Comma) {
            advance();
            continue;
        }
        break;
    }
    return expectToken(TokenKind::Semicolon, "expected ';' after IMPORTS");
}

bool Parser::parseExports(ModuleAst &out)
{
    const Pos clausePos = peek().pos;
    advance(); /* EXPORTS */
    if (out.exports.present) {
        syntaxError(clausePos, "duplicate EXPORTS clause");
        return false;
    }
    out.exports.present = true;
    if (keywordEquals(peek(), "ALL")) {
        advance();
        out.exports.all = true;
        return expectToken(TokenKind::Semicolon, "expected ';' after EXPORTS");
    }
    if (peek().kind == TokenKind::Semicolon) {
        /* `EXPORTS;` 显式声明不导出任何符号。 */
        advance();
        return true;
    }
    if (!parseSymbolList(out.exports.symbols)) {
        return false;
    }
    return expectToken(TokenKind::Semicolon, "expected ';' after EXPORTS");
}

bool Parser::parseDeclaration(ModuleAst &out)
{
    if (peek().kind != TokenKind::Identifier) {
        syntaxError(peek().pos, "expected type or value name");
        return false;
    }
    const Token nameToken = peek();
    advance();

    std::vector<std::string> params;
    if (peek().kind == TokenKind::LBrace) {
        /* 参数化定义：`Foo { Type1, Type2 } ::= ...`。B1 只支持类型参数
           （纯标识符）；值参数（`n INTEGER`）与其他形态报 9006。 */
        advance();
        while (peek().kind != TokenKind::RBrace) {
            if (peek().kind == TokenKind::End) {
                syntaxError(peek().pos, "missing '}' in parameter list");
                return false;
            }
            if (peek().kind != TokenKind::Identifier) {
                unsupported(peek().pos,
                            "only type parameters (identifiers) are "
                            "supported in parameterized type definitions");
                return false;
            }
            params.push_back(peek().text);
            advance();
            if (peek().kind == TokenKind::Comma) {
                advance();
            }
        }
        advance(); /* RBrace */
    }

    if (peek().kind == TokenKind::Assign) {
        advance();
        std::unique_ptr<TypeAst> type = std::make_unique<TypeAst>();
        if (!parseTypeExpr(*type)) {
            return false;
        }
        TypeAssignment assignment;
        assignment.name = nameToken.text;
        assignment.pos = nameToken.pos;
        assignment.type = std::move(type);
        assignment.params = std::move(params);
        out.types.push_back(std::move(assignment));
        return true;
    }
    if (!params.empty()) {
        /* 参数化列表只允许出现在类型赋值中，不允许在值赋值中。 */
        syntaxError(nameToken.pos,
                    "parameter list is only allowed in type assignments");
        return false;
    }

    std::unique_ptr<TypeAst> type = std::make_unique<TypeAst>();
    if (!parseTypeExpr(*type)) {
        return false;
    }
    if (!expectToken(TokenKind::Assign, "expected '::='")) {
        return false;
    }
    std::unique_ptr<ValueAst> value = std::make_unique<ValueAst>();
    if (!parseValue(*value)) {
        return false;
    }
    ValueAssignment assignment;
    assignment.name = nameToken.text;
    assignment.pos = nameToken.pos;
    assignment.type = std::move(type);
    assignment.value = std::move(value);
    out.values.push_back(std::move(assignment));
    return true;
}

} /* namespace parser_detail */

using namespace parser_detail;

bool parseModule(const std::string &file, const std::string &source,
                 ModuleAst &out, Diagnostics &diagnostics)
{
    std::vector<Token> tokens;
    if (!tokenize(file, source, tokens, diagnostics)) {
        return false;
    }
    Parser parser(file, tokens, diagnostics);
    return parser.run(out);
}

} /* namespace asnberc */
