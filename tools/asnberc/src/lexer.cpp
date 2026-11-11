/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

#include "lexer.h"

#include <cctype>

namespace asnberc {
namespace {

bool isIdentStart(char c) noexcept
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

bool isIdentChar(char c) noexcept
{
    return isIdentStart(c) || (c >= '0' && c <= '9') || c == '-';
}

bool equalsIgnoreCase(const std::string &text, const char *keyword) noexcept
{
    size_t i = 0;
    for (; i < text.size(); ++i) {
        if (keyword[i] == '\0') {
            return false;
        }
        const char a = static_cast<char>(std::tolower(
            static_cast<unsigned char>(text[i])));
        const char b = static_cast<char>(std::tolower(
            static_cast<unsigned char>(keyword[i])));
        if (a != b) {
            return false;
        }
    }
    return keyword[i] == '\0';
}

class Lexer {
public:
    Lexer(const std::string &file, const std::string &source,
          Diagnostics &diagnostics, std::vector<Token> &tokens)
        : file_(file), source_(source), diagnostics_(diagnostics),
          tokens_(tokens)
    {
    }

    bool run()
    {
        while (pos_ < source_.size()) {
            skipWhitespaceAndComments();
            if (pos_ >= source_.size()) {
                break;
            }
            scanToken();
        }
        Token end;
        end.kind = TokenKind::End;
        end.pos.line = line_;
        end.pos.column = col_;
        tokens_.push_back(end);
        return !diagnostics_.hasError();
    }

private:
    char peek(size_t offset = 0) const noexcept
    {
        const size_t index = pos_ + offset;
        return index < source_.size() ? source_[index] : '\0';
    }

    void advance()
    {
        if (pos_ >= source_.size()) {
            return;
        }
        const char c = source_[pos_];
        ++pos_;
        if (c == '\r') {
            if (pos_ < source_.size() && source_[pos_] == '\n') {
                ++pos_;
            }
            ++line_;
            col_ = 1;
        } else if (c == '\n') {
            ++line_;
            col_ = 1;
        } else {
            ++col_;
        }
    }

    void skipWhitespaceAndComments()
    {
        bool again = true;
        while (again) {
            again = false;
            while (pos_ < source_.size() &&
                   std::isspace(static_cast<unsigned char>(peek())) != 0) {
                advance();
            }
            if (peek() == '-' && peek(1) == '-') {
                advance();
                advance();
                /* 注释到行尾或下一个 `--`。 */
                while (pos_ < source_.size()) {
                    const char c = peek();
                    if (c == '\r' || c == '\n') {
                        break;
                    }
                    if (c == '-' && peek(1) == '-') {
                        advance();
                        advance();
                        break;
                    }
                    advance();
                }
                again = true;
            }
        }
    }

    void error(const Pos &pos, const std::string &message)
    {
        diagnostics_.add(file_, pos.line, pos.column, Severity::Error,
                         DiagCode::Syntax, message);
    }

    void push(TokenKind kind, const std::string &text, const Pos &pos)
    {
        Token token;
        token.kind = kind;
        token.text = text;
        token.pos = pos;
        tokens_.push_back(token);
    }

    void scanToken()
    {
        Pos start;
        start.line = line_;
        start.column = col_;
        const char c = peek();

        if (isIdentStart(c)) {
            std::string text;
            while (pos_ < source_.size() && isIdentChar(peek())) {
                text.push_back(source_[pos_]);
                advance();
            }
            push(TokenKind::Identifier, text, start);
            return;
        }
        if (c >= '0' && c <= '9') {
            std::string text;
            while (pos_ < source_.size() && peek() >= '0' && peek() <= '9') {
                text.push_back(source_[pos_]);
                advance();
            }
            push(TokenKind::Number, text, start);
            return;
        }
        if (c == '"') {
            scanString(start);
            return;
        }
        switch (c) {
        case ':':
            advance();
            if (peek() == ':') {
                advance();
                if (peek() == '=') {
                    advance();
                    push(TokenKind::Assign, "::=", start);
                    return;
                }
            }
            error(start, "expected '::='");
            return;
        case '.':
            advance();
            if (peek() == '.') {
                advance();
                if (peek() == '.') {
                    advance();
                    push(TokenKind::Ellipsis, "...", start);
                } else {
                    push(TokenKind::DotDot, "..", start);
                }
            } else {
                push(TokenKind::Dot, ".", start);
            }
            return;
        case '{':
            advance();
            push(TokenKind::LBrace, "{", start);
            return;
        case '}':
            advance();
            push(TokenKind::RBrace, "}", start);
            return;
        case '(':
            advance();
            push(TokenKind::LParen, "(", start);
            return;
        case ')':
            advance();
            push(TokenKind::RParen, ")", start);
            return;
        case '[':
            advance();
            push(TokenKind::LBracket, "[", start);
            return;
        case ']':
            advance();
            push(TokenKind::RBracket, "]", start);
            return;
        case ',':
            advance();
            push(TokenKind::Comma, ",", start);
            return;
        case ';':
            advance();
            push(TokenKind::Semicolon, ";", start);
            return;
        case '|':
            advance();
            push(TokenKind::Pipe, "|", start);
            return;
        case '*':
            advance();
            push(TokenKind::Star, "*", start);
            return;
        case '@':
            advance();
            push(TokenKind::At, "@", start);
            return;
        case '-':
            advance();
            push(TokenKind::Minus, "-", start);
            return;
        default:
            advance();
            error(start, "unexpected character in input");
            return;
        }
    }

    void scanString(const Pos &start)
    {
        advance();
        std::string text;
        while (pos_ < source_.size()) {
            if (peek() == '"') {
                advance();
                if (peek() == '"') {
                    advance();
                    text.push_back('"');
                    continue;
                }
                push(TokenKind::String, text, start);
                return;
            }
            text.push_back(peek());
            advance();
        }
        error(start, "unterminated string literal");
    }

    const std::string &file_;
    const std::string &source_;
    Diagnostics &diagnostics_;
    std::vector<Token> &tokens_;
    size_t pos_ = 0;
    uint32_t line_ = 1;
    uint32_t col_ = 1;
};

} /* namespace */

bool keywordEquals(const Token &token, const char *keyword) noexcept
{
    return token.kind == TokenKind::Identifier &&
           equalsIgnoreCase(token.text, keyword);
}

bool tokenize(const std::string &file, const std::string &source,
              std::vector<Token> &out, Diagnostics &diagnostics)
{
    out.clear();
    Lexer lexer(file, source, diagnostics, out);
    return lexer.run();
}

} /* namespace asnberc */
