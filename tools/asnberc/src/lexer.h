/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 词法分析：标识符（允许内部连字符）、数字、字符串、`::=`、`...`、
 * 括号与分隔符，以及 `--` 注释（到行尾或下一个 `--`）。
 */
#ifndef ASNBERC_LEXER_H_INCLUDED
#define ASNBERC_LEXER_H_INCLUDED

#include <cstdint>
#include <string>
#include <vector>

#include "ast.h"
#include "diag.h"

namespace asnberc {

enum class TokenKind {
    End,
    Identifier,
    Number,
    String,
    Assign,
    Ellipsis,
    LBrace,
    RBrace,
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
    Semicolon,
    Pipe,
    Dot,
    DotDot,
    Star,
    Minus,
    At
};

struct Token {
    TokenKind kind = TokenKind::End;
    std::string text;
    Pos pos;
};

/*
 * 把源码切成 token 序列，末尾总是追加 End token。
 * 非法字符与未闭合字符串产生 ASNBERC_E_SYNTAX 诊断并跳过。
 */
bool tokenize(const std::string &file, const std::string &source,
              std::vector<Token> &out, Diagnostics &diagnostics);

/* 大小写不敏感的关键字/标识符比较。 */
bool keywordEquals(const Token &token, const char *keyword) noexcept;

} /* namespace asnberc */

#endif /* ASNBERC_LEXER_H_INCLUDED */
