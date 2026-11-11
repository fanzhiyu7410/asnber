/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

#include <algorithm>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "detail/semantic_internal.h"

namespace asnberc {
namespace semantic_detail {

namespace {

void appendTag(std::vector<uint8_t> &out, uint8_t tagClass, uint32_t number,
               bool constructed)
{
    uint8_t first = static_cast<uint8_t>((tagClass & 0x03u) << 6);
    if (constructed) {
        first = static_cast<uint8_t>(first | 0x20u);
    }
    if (number < 31) {
        first = static_cast<uint8_t>(first | static_cast<uint8_t>(number));
        out.push_back(first);
        return;
    }
    out.push_back(static_cast<uint8_t>(first | 0x1Fu));
    uint32_t value = number;
    uint8_t parts[5];
    uint32_t count = 0;
    parts[count++] = static_cast<uint8_t>(value & 0x7Fu);
    value >>= 7;
    while (value != 0) {
        parts[count++] = static_cast<uint8_t>((value & 0x7Fu) | 0x80u);
        value >>= 7;
    }
    while (count > 0) {
        --count;
        out.push_back(parts[count]);
    }
}

void appendLength(std::vector<uint8_t> &out, size_t length)
{
    if (length < 128) {
        out.push_back(static_cast<uint8_t>(length));
        return;
    }
    uint8_t bytes[8];
    uint32_t count = 0;
    size_t value = length;
    while (value != 0) {
        bytes[count++] = static_cast<uint8_t>(value & 0xFFu);
        value >>= 8;
    }
    out.push_back(static_cast<uint8_t>(0x80u | count));
    while (count > 0) {
        --count;
        out.push_back(bytes[count]);
    }
}

std::vector<uint8_t> encodeIntegerContent(int64_t value)
{
    std::vector<uint8_t> little;
    int64_t current = value;
    while (true) {
        little.push_back(static_cast<uint8_t>(
            static_cast<uint64_t>(current) & UINT64_C(0xFF)));
        current >>= 8;
        const uint8_t last = little.back();
        if ((current == 0 && (last & 0x80u) == 0) ||
            (current == -1 && (last & 0x80u) != 0)) {
            break;
        }
    }
    std::reverse(little.begin(), little.end());
    return little;
}

bool encodeOidContent(const std::vector<uint64_t> &arcs,
                      std::vector<uint8_t> &out)
{
    if (arcs.size() < 2 || arcs[0] > 2) {
        return false;
    }
    std::vector<uint64_t> numbers;
    numbers.push_back(arcs[0] * 40u + arcs[1]);
    for (size_t i = 2; i < arcs.size(); ++i) {
        numbers.push_back(arcs[i]);
    }
    for (uint64_t number : numbers) {
        uint8_t chunks[10];
        uint32_t count = 0;
        chunks[count++] = static_cast<uint8_t>(number & 0x7Fu);
        number >>= 7;
        while (number != 0) {
            chunks[count++] =
                static_cast<uint8_t>((number & 0x7Fu) | 0x80u);
            number >>= 7;
        }
        while (count > 0) {
            --count;
            out.push_back(chunks[count]);
        }
    }
    return true;
}

} /* namespace */


bool Analyzer::encodeSimpleContent(const TypeNode *type, const ValueAst &value,
                         const Pos &pos, std::vector<uint8_t> &content)
{
    switch (type->baseTagNumber) {
    case 1: { /* BOOLEAN */
        bool flag = false;
        if (value.kind == ValueAst::Kind::Boolean) {
            flag = value.boolValue;
        } else if (value.kind == ValueAst::Kind::Integer &&
                   (value.intValue == 0 || value.intValue == 1)) {
            flag = value.intValue == 1;
        } else {
            error(pos, DiagCode::ConstraintInvalid,
                  "DEFAULT value is not a BOOLEAN");
            return false;
        }
        content.push_back(flag ? 0xFFu : 0x00u);
        return true;
    }
    case 2:   /* INTEGER */
    case 10: { /* ENUMERATED */
        int64_t number = 0;
        if (!resolveInteger(type, value, pos, number)) {
            return false;
        }
        content = encodeIntegerContent(number);
        return true;
    }
    case 3: { /* BIT STRING */
        if (value.kind == ValueAst::Kind::Oid) {
            uint64_t highest = 0;
            bool any = false;
            for (const BracePartAst &part : value.parts) {
                uint64_t bit = 0;
                if (part.hasName) {
                    bool found = false;
                    for (const NamedValue &named : type->namedValues) {
                        if (named.name == part.name && named.value >= 0) {
                            bit = static_cast<uint64_t>(named.value);
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                        error(part.pos, DiagCode::ConstraintInvalid,
                              "unknown named bit '" + part.name +
                                  "'");
                        return false;
                    }
                } else {
                    bit = part.number;
                }
                any = true;
                if (bit > highest) {
                    highest = bit;
                }
            }
            if (any) {
                const size_t bytes =
                    static_cast<size_t>(highest / 8u) + 1u;
                content.assign(bytes, 0u);
                for (const BracePartAst &part : value.parts) {
                    uint64_t bit = part.number;
                    if (part.hasName) {
                        for (const NamedValue &named : type->namedValues) {
                            if (named.name == part.name) {
                                bit = static_cast<uint64_t>(named.value);
                                break;
                            }
                        }
                    }
                    content[static_cast<size_t>(bit / 8u)] |=
                        static_cast<uint8_t>(0x80u >> (bit % 8u));
                }
            }
            return true;
        }
        error(pos, DiagCode::ConstraintInvalid,
              "DEFAULT value is not a BIT STRING");
        return false;
    }
    case 4: /* OCTET STRING */
    case 12:
    case 18:
    case 19:
    case 20:
    case 22:
    case 23:
    case 24:
    case 26:
    case 28:
    case 30: {
        if (value.kind != ValueAst::Kind::String) {
            error(pos, DiagCode::ConstraintInvalid,
                  "DEFAULT value is not a string");
            return false;
        }
        content.assign(value.text.begin(), value.text.end());
        return true;
    }
    case 5: { /* NULL */
        if (value.kind != ValueAst::Kind::Null) {
            error(pos, DiagCode::ConstraintInvalid,
                  "DEFAULT value is not NULL");
            return false;
        }
        return true;
    }
    case 6: { /* OBJECT IDENTIFIER */
        if (value.kind != ValueAst::Kind::Oid) {
            error(pos, DiagCode::ConstraintInvalid,
                  "DEFAULT value is not an OBJECT IDENTIFIER");
            return false;
        }
        std::vector<uint64_t> arcs;
        if (!evaluateOid(value, arcs, DiagCode::ConstraintInvalid)) {
            return false;
        }
        return encodeOidContent(arcs, content);
    }
    default:
        error(pos, DiagCode::ConstraintInvalid,
              "DEFAULT is not supported for this type");
        return false;
    }
}

bool Analyzer::encodeDefault(Field &field, const ValueAst &value, const Pos &pos)
{
    const TypeNode *type = field.type;
    if (type == nullptr) {
        return false;
    }
    if (type->kind != TypeKind::Simple) {
        error(pos, DiagCode::ConstraintInvalid,
              "DEFAULT is not supported for this type");
        return false;
    }
    std::vector<uint8_t> content;
    if (!encodeSimpleContent(type, value, pos, content)) {
        return false;
    }

    std::vector<uint8_t> tlv;
    const uint32_t innerTag = type->baseTagNumber;
    if (type->tagMode == kTagModeImplicit) {
        appendTag(tlv, type->tagClass, type->tagNumber, false);
        appendLength(tlv, content.size());
        tlv.insert(tlv.end(), content.begin(), content.end());
    } else if (type->tagMode == kTagModeExplicit) {
        std::vector<uint8_t> inner;
        appendTag(inner, kTagClassUniversal, innerTag, false);
        appendLength(inner, content.size());
        inner.insert(inner.end(), content.begin(), content.end());
        appendTag(tlv, type->tagClass, type->tagNumber, true);
        appendLength(tlv, inner.size());
        tlv.insert(tlv.end(), inner.begin(), inner.end());
    } else {
        appendTag(tlv, kTagClassUniversal, innerTag, false);
        appendLength(tlv, content.size());
        tlv.insert(tlv.end(), content.begin(), content.end());
    }

    field.hasDefault = true;
    field.defaultTlv = std::move(tlv);
    return true;
}

} /* namespace semantic_detail */
} /* namespace asnberc */
