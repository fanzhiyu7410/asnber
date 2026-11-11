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

bool Parser::parseValue(ValueAst &out)
{
    out.pos = peek().pos;
    if (peek().kind == TokenKind::LBrace) {
        out.kind = ValueAst::Kind::Oid;
        return parseBraceParts(out.parts);
    }
    if (keywordEquals(peek(), "TRUE") ||
        keywordEquals(peek(), "FALSE")) {
        out.kind = ValueAst::Kind::Boolean;
        out.boolValue = keywordEquals(peek(), "TRUE");
        advance();
        return true;
    }
    if (keywordEquals(peek(), "NULL")) {
        out.kind = ValueAst::Kind::Null;
        advance();
        return true;
    }
    if (peek().kind == TokenKind::String) {
        out.kind = ValueAst::Kind::String;
        out.text = peek().text;
        advance();
        return true;
    }
    bool negated = false;
    if (peek().kind == TokenKind::Minus) {
        negated = true;
        advance();
    }
    if (peek().kind == TokenKind::Number) {
        out.kind = ValueAst::Kind::Integer;
        if (!parseSigned(peek(), negated, out.intValue)) {
            syntaxError(peek().pos, "integer value out of range");
            return false;
        }
        advance();
        return true;
    }
    if (peek().kind == TokenKind::Identifier && !negated) {
        out.kind = ValueAst::Kind::Reference;
        out.text = peek().text;
        advance();
        return true;
    }
    syntaxError(peek().pos, "expected value");
    return false;
}

bool Parser::parseBraceParts(std::vector<BracePartAst> &out)
{
    if (!expectToken(TokenKind::LBrace, "expected '{'")) {
        return false;
    }
    while (true) {
        if (peek().kind == TokenKind::RBrace) {
            advance();
            return true;
        }
        if (peek().kind == TokenKind::End) {
            syntaxError(peek().pos, "missing '}'");
            return false;
        }
        BracePartAst part;
        part.pos = peek().pos;
        if (peek().kind == TokenKind::Number) {
            part.hasNumber = true;
            uint64_t number = 0;
            if (!parseUnsigned(peek(), number)) {
                syntaxError(peek().pos, "arc value out of range");
                return false;
            }
            part.number = number;
            advance();
        } else if (peek().kind == TokenKind::Identifier) {
            part.hasName = true;
            part.name = peek().text;
            advance();
            if (peek().kind == TokenKind::LParen) {
                advance();
                if (peek().kind != TokenKind::Number) {
                    syntaxError(peek().pos, "expected number");
                    return false;
                }
                uint64_t number = 0;
                if (!parseUnsigned(peek(), number)) {
                    syntaxError(peek().pos, "arc value out of range");
                    return false;
                }
                part.hasNumber = true;
                part.number = number;
                advance();
                if (!expectToken(TokenKind::RParen, "expected ')'")) {
                    return false;
                }
            }
        } else {
            syntaxError(peek().pos, "expected value component");
            return false;
        }
        out.push_back(part);
        if (peek().kind == TokenKind::Comma) {
            advance();
        }
    }
}

bool Parser::parseUnsigned(const Token &token, uint64_t &out) const
{
    uint64_t value = 0;
    for (char c : token.text) {
        if (c < '0' || c > '9') {
            return false;
        }
        const uint64_t digit = static_cast<uint64_t>(c - '0');
        if (value > (UINT64_MAX - digit) / 10u) {
            return false;
        }
        value = value * 10u + digit;
    }
    out = value;
    return true;
}

bool Parser::parseSigned(const Token &token, bool negated, int64_t &out) const
{
    uint64_t magnitude = 0;
    if (!parseUnsigned(token, magnitude)) {
        return false;
    }
    if (negated) {
        if (magnitude > static_cast<uint64_t>(INT64_MAX) + 1u) {
            return false;
        }
        if (magnitude == static_cast<uint64_t>(INT64_MAX) + 1u) {
            out = INT64_MIN;
        } else {
            out = -static_cast<int64_t>(magnitude);
        }
    } else {
        if (magnitude > static_cast<uint64_t>(INT64_MAX)) {
            return false;
        }
        out = static_cast<int64_t>(magnitude);
    }
    return true;
}

} /* namespace parser_detail */
} /* namespace asnberc */
