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

bool Parser::parseConstraintList(std::vector<ConstraintAst> &out)
{
    while (true) {
        if (peek().kind == TokenKind::LParen) {
            ConstraintAst constraint;
            constraint.pos = peek().pos;
            advance();
            if (keywordEquals(peek(), "SIZE")) {
                constraint.kind = ConstraintAst::Kind::Size;
                advance();
                if (!expectToken(TokenKind::LParen,
                                 "expected '(' after SIZE")) {
                    return false;
                }
                if (!parseBounds(constraint)) {
                    return false;
                }
                if (!expectToken(TokenKind::RParen, "expected ')'")) {
                    return false;
                }
            } else {
                constraint.kind = ConstraintAst::Kind::Range;
                if (!parseBounds(constraint)) {
                    return false;
                }
            }
            if (!expectToken(TokenKind::RParen, "expected ')'")) {
                return false;
            }
            out.push_back(constraint);
            continue;
        }
        if (keywordEquals(peek(), "SIZE")) {
            ConstraintAst constraint;
            constraint.pos = peek().pos;
            constraint.kind = ConstraintAst::Kind::Size;
            advance();
            if (!expectToken(TokenKind::LParen,
                             "expected '(' after SIZE")) {
                return false;
            }
            if (!parseBounds(constraint)) {
                return false;
            }
            if (!expectToken(TokenKind::RParen, "expected ')'")) {
                return false;
            }
            out.push_back(constraint);
            continue;
        }
        if (keywordEquals(peek(), "PATTERN")) {
            unsupported(peek().pos, "PATTERN constraints are not supported");
            return false;
        }
        break;
    }
    return true;
}

bool Parser::parseBounds(ConstraintAst &constraint)
{
    if (!parseBound(constraint.lower)) {
        return false;
    }
    if (peek().kind == TokenKind::DotDot) {
        advance();
        if (!parseBound(constraint.upper)) {
            return false;
        }
    } else {
        constraint.single = true;
        constraint.upper = constraint.lower;
    }
    return true;
}

bool Parser::parseBound(ConstraintBoundAst &bound)
{
    bound.pos = peek().pos;
    if (keywordEquals(peek(), "MAX")) {
        bound.isMax = true;
        advance();
        return true;
    }
    if (keywordEquals(peek(), "MIN")) {
        bound.isMin = true;
        advance();
        return true;
    }
    bool negated = false;
    if (peek().kind == TokenKind::Minus) {
        negated = true;
        advance();
    }
    if (peek().kind == TokenKind::Number) {
        bound.hasValue = true;
        if (!parseSigned(peek(), negated, bound.value)) {
            syntaxError(peek().pos, "constraint value out of range");
            return false;
        }
        advance();
        return true;
    }
    if (peek().kind == TokenKind::Identifier) {
        if (negated) {
            syntaxError(peek().pos, "expected number");
            return false;
        }
        bound.refName = peek().text;
        advance();
        return true;
    }
    syntaxError(peek().pos, "expected constraint bound");
    return false;
}

} /* namespace parser_detail */
} /* namespace asnberc */
