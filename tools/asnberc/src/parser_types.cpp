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

bool Parser::parseTypeExpr(TypeAst &out)
{
    out.pos = peek().pos;
    if (peek().kind == TokenKind::LBracket) {
        if (!parseTag(out.tag)) {
            return false;
        }
    }
    if (!parseBase(out)) {
        return false;
    }
    if (!parseConstraintList(out.constraints)) {
        return false;
    }
    if (keywordEquals(peek(), "CONTAINING")) {
        unsupported(peek().pos, "CONTAINING is not supported");
        return false;
    }
    if (keywordEquals(peek(), "CONSTRAINED")) {
        unsupported(peek().pos, "CONSTRAINED BY is not supported");
        return false;
    }
    if (keywordEquals(peek(), "WITH")) {
        unsupported(peek().pos, "WITH COMPONENTS is not supported");
        return false;
    }
    if (keywordEquals(peek(), "PATTERN")) {
        unsupported(peek().pos, "PATTERN constraints are not supported");
        return false;
    }
    return true;
}

bool Parser::parseTag(TagSpec &out)
{
    out.pos = peek().pos;
    if (!expectToken(TokenKind::LBracket, "expected '['")) {
        return false;
    }
    if (peek().kind == TokenKind::LBracket) {
        unsupported(peek().pos,
                    "extension marker groups '[[...]]' are not supported");
        return false;
    }
    if (keywordEquals(peek(), "APPLICATION") ||
        keywordEquals(peek(), "PRIVATE") ||
        keywordEquals(peek(), "UNIVERSAL")) {
        unsupported(peek().pos,
                    "APPLICATION/PRIVATE/UNIVERSAL tag classes are not "
                    "supported");
        return false;
    }
    if (peek().kind != TokenKind::Number) {
        syntaxError(peek().pos, "expected tag number");
        return false;
    }
    uint64_t number = 0;
    if (!parseUnsigned(peek(), number) || number > UINT32_MAX) {
        syntaxError(peek().pos, "tag number out of range");
        return false;
    }
    out.number = static_cast<uint32_t>(number);
    advance();
    if (!expectToken(TokenKind::RBracket, "expected ']'")) {
        return false;
    }
    if (keywordEquals(peek(), "EXPLICIT")) {
        out.mode = TagModeSpec::Explicit;
        advance();
    } else if (keywordEquals(peek(), "IMPLICIT")) {
        out.mode = TagModeSpec::Implicit;
        advance();
    } else {
        out.mode = TagModeSpec::Bare;
    }
    out.present = true;
    return true;
}

bool Parser::parseBase(TypeAst &out)
{
    const Token token = peek();
    if (token.kind != TokenKind::Identifier) {
        syntaxError(token.pos, "expected type expression");
        return false;
    }

    if (keywordEquals(token, "BOOLEAN")) {
        out.cls = TypeAst::Class::Boolean;
        advance();
    } else if (keywordEquals(token, "INTEGER")) {
        out.cls = TypeAst::Class::Integer;
        advance();
        if (peek().kind == TokenKind::LBrace) {
            if (!parseNamedNumbers(out, false)) {
                return false;
            }
        }
    } else if (keywordEquals(token, "ENUMERATED")) {
        out.cls = TypeAst::Class::Enumerated;
        advance();
        if (peek().kind != TokenKind::LBrace) {
            syntaxError(peek().pos, "expected '{' after ENUMERATED");
            return false;
        }
        if (!parseNamedNumbers(out, true)) {
            return false;
        }
    } else if (keywordEquals(token, "BIT")) {
        out.cls = TypeAst::Class::BitString;
        advance();
        if (!expectKeyword("STRING", "expected STRING after BIT")) {
            return false;
        }
        if (peek().kind == TokenKind::LBrace) {
            if (!parseNamedNumbers(out, false)) {
                return false;
            }
        }
    } else if (keywordEquals(token, "OCTET")) {
        out.cls = TypeAst::Class::OctetString;
        advance();
        if (!expectKeyword("STRING", "expected STRING after OCTET")) {
            return false;
        }
    } else if (keywordEquals(token, "OBJECT")) {
        out.cls = TypeAst::Class::ObjectIdentifier;
        advance();
        if (!expectKeyword("IDENTIFIER",
                            "expected IDENTIFIER after OBJECT")) {
            return false;
        }
    } else if (keywordEquals(token, "NULL")) {
        out.cls = TypeAst::Class::Null;
        advance();
    } else if (keywordEquals(token, "UTF8String")) {
        out.cls = TypeAst::Class::Utf8String;
        advance();
    } else if (keywordEquals(token, "PrintableString")) {
        out.cls = TypeAst::Class::PrintableString;
        advance();
    } else if (keywordEquals(token, "IA5String")) {
        out.cls = TypeAst::Class::Ia5String;
        advance();
    } else if (keywordEquals(token, "VisibleString")) {
        out.cls = TypeAst::Class::VisibleString;
        advance();
    } else if (keywordEquals(token, "NumericString")) {
        out.cls = TypeAst::Class::NumericString;
        advance();
    } else if (keywordEquals(token, "TeletexString") ||
               keywordEquals(token, "T61String")) {
        out.cls = TypeAst::Class::TeletexString;
        advance();
    } else if (keywordEquals(token, "BMPString")) {
        out.cls = TypeAst::Class::BmpString;
        advance();
    } else if (keywordEquals(token, "UniversalString")) {
        out.cls = TypeAst::Class::UniversalString;
        advance();
    } else if (keywordEquals(token, "UTCTime")) {
        out.cls = TypeAst::Class::UtcTime;
        advance();
    } else if (keywordEquals(token, "GeneralizedTime")) {
        out.cls = TypeAst::Class::GeneralizedTime;
        advance();
    } else if (keywordEquals(token, "ANY")) {
        out.cls = TypeAst::Class::Any;
        advance();
        if (keywordEquals(peek(), "DEFINED")) {
            unsupported(peek().pos, "ANY DEFINED BY is not supported");
            return false;
        }
    } else if (keywordEquals(token, "SEQUENCE")) {
        out.cls = TypeAst::Class::Sequence;
        advance();
        if (!parseConstraintList(out.constraints)) {
            return false;
        }
        if (keywordEquals(peek(), "OF")) {
            out.cls = TypeAst::Class::SequenceOf;
            advance();
            out.element = std::make_unique<TypeAst>();
            if (!parseTypeExpr(*out.element)) {
                return false;
            }
        } else if (peek().kind == TokenKind::LBrace) {
            if (!parseFieldList(out)) {
                return false;
            }
        } else {
            syntaxError(peek().pos, "expected OF or '{' after SEQUENCE");
            return false;
        }
    } else if (keywordEquals(token, "SET")) {
        out.cls = TypeAst::Class::Set;
        advance();
        if (!parseConstraintList(out.constraints)) {
            return false;
        }
        if (keywordEquals(peek(), "OF")) {
            out.cls = TypeAst::Class::SetOf;
            advance();
            out.element = std::make_unique<TypeAst>();
            if (!parseTypeExpr(*out.element)) {
                return false;
            }
        } else if (peek().kind == TokenKind::LBrace) {
            if (!parseFieldList(out)) {
                return false;
            }
        } else {
            syntaxError(peek().pos, "expected OF or '{' after SET");
            return false;
        }
    } else if (keywordEquals(token, "CHOICE")) {
        out.cls = TypeAst::Class::Choice;
        advance();
        if (peek().kind != TokenKind::LBrace) {
            syntaxError(peek().pos, "expected '{' after CHOICE");
            return false;
        }
        if (!parseFieldList(out)) {
            return false;
        }
    } else if (keywordEquals(token, "CLASS")) {
        unsupported(token.pos, "CLASS definitions are not supported");
        return false;
    } else if (keywordEquals(token, "INSTANCE")) {
        unsupported(token.pos, "INSTANCE OF is not supported");
        return false;
    } else if (keywordEquals(token, "COMPONENTS")) {
        unsupported(token.pos, "COMPONENTS OF is not supported");
        return false;
    } else if (keywordEquals(token, "WITH")) {
        unsupported(token.pos, "WITH SYNTAX is not supported");
        return false;
    } else {
        out.cls = TypeAst::Class::Reference;
        out.refName = token.text;
        advance();
        if (peek().kind == TokenKind::LBrace) {
            /* 参数化实例化：`Foo { Type1, Type2 }`。实参是完整的
               TypeExpr，可以是内联类型或带实例化的引用。 */
            advance();
            while (peek().kind != TokenKind::RBrace) {
                if (peek().kind == TokenKind::End) {
                    syntaxError(peek().pos,
                                "missing '}' in type instantiation");
                    return false;
                }
                auto arg = std::make_unique<TypeAst>();
                if (!parseTypeExpr(*arg)) {
                    return false;
                }
                out.instanceArgs.push_back(std::move(arg));
                if (peek().kind == TokenKind::Comma) {
                    advance();
                }
            }
            advance(); /* RBrace */
        }
    }

    if (keywordEquals(peek(), "COMPONENTS")) {
        unsupported(peek().pos, "COMPONENTS OF is not supported");
        return false;
    }
    return true;
}

bool Parser::parseFieldList(TypeAst &out)
{
    if (!expectToken(TokenKind::LBrace, "expected '{'")) {
        return false;
    }
    bool inExtension = false;
    while (true) {
        if (peek().kind == TokenKind::RBrace) {
            advance();
            break;
        }
        if (peek().kind == TokenKind::End) {
            syntaxError(peek().pos, "missing '}'");
            return false;
        }
        if (peek().kind == TokenKind::Ellipsis) {
            out.extensible = true;
            inExtension = true;
            advance();
            if (peek().kind == TokenKind::Comma) {
                advance();
            }
            continue;
        }
        if (peek().kind == TokenKind::LBracket &&
            peek(1).kind == TokenKind::LBracket) {
            unsupported(peek().pos,
                        "extension marker groups '[[...]]' are not "
                        "supported");
            return false;
        }
        if (keywordEquals(peek(), "COMPONENTS")) {
            unsupported(peek().pos, "COMPONENTS OF is not supported");
            return false;
        }
        if (peek().kind != TokenKind::Identifier) {
            syntaxError(peek().pos, "expected field name");
            return false;
        }
        FieldAst field;
        field.name = peek().text;
        field.pos = peek().pos;
        advance();

        field.type = std::make_unique<TypeAst>();
        if (!parseTypeExpr(*field.type)) {
            return false;
        }
        if (keywordEquals(peek(), "OPTIONAL")) {
            field.optional = true;
            advance();
        } else if (keywordEquals(peek(), "DEFAULT")) {
            advance();
            field.defaultValue = std::make_unique<ValueAst>();
            if (!parseValue(*field.defaultValue)) {
                return false;
            }
        }
        field.extension = inExtension;
        out.fields.push_back(std::move(field));

        if (peek().kind == TokenKind::Comma) {
            advance();
            continue;
        }
        if (peek().kind == TokenKind::RBrace) {
            advance();
            break;
        }
        syntaxError(peek().pos, "expected ',' or '}'");
        return false;
    }

    if (out.cls == TypeAst::Class::Choice) {
        for (const FieldAst &field : out.fields) {
            if (field.optional || field.defaultValue != nullptr) {
                syntaxError(field.pos,
                            "CHOICE alternatives cannot be OPTIONAL or "
                            "have DEFAULT");
                return false;
            }
        }
    }
    return true;
}

bool Parser::parseNamedNumbers(TypeAst &out, bool allowEllipsis)
{
    if (!expectToken(TokenKind::LBrace, "expected '{'")) {
        return false;
    }
    while (true) {
        if (peek().kind == TokenKind::RBrace) {
            advance();
            break;
        }
        if (peek().kind == TokenKind::End) {
            syntaxError(peek().pos, "missing '}'");
            return false;
        }
        if (peek().kind == TokenKind::Ellipsis) {
            if (!allowEllipsis) {
                unsupported(peek().pos,
                            "extension marker is not supported here");
                return false;
            }
            out.extensible = true;
            advance();
            if (peek().kind == TokenKind::Comma) {
                advance();
            }
            continue;
        }
        if (peek().kind != TokenKind::Identifier) {
            syntaxError(peek().pos, "expected named number");
            return false;
        }
        NamedNumberAst named;
        named.name = peek().text;
        named.pos = peek().pos;
        advance();
        if (!expectToken(TokenKind::LParen, "expected '('")) {
            return false;
        }
        bool valueNegated = false;
        if (peek().kind == TokenKind::Minus) {
            valueNegated = true;
            advance();
        }
        if (peek().kind != TokenKind::Number) {
            syntaxError(peek().pos, "expected number");
            return false;
        }
        if (!parseSigned(peek(), valueNegated, named.value)) {
            syntaxError(peek().pos, "named number value out of range");
            return false;
        }
        advance();
        if (!expectToken(TokenKind::RParen, "expected ')'")) {
            return false;
        }
        if (!out.extensible) {
            ++out.rootNamedCount;
        }
        out.namedNumbers.push_back(named);

        if (peek().kind == TokenKind::Comma) {
            advance();
        } else if (peek().kind != TokenKind::RBrace) {
            syntaxError(peek().pos, "expected ',' or '}'");
            return false;
        }
    }
    return true;
}

} /* namespace parser_detail */
} /* namespace asnberc */
