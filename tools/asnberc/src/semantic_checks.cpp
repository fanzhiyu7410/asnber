/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "detail/semantic_internal.h"

namespace asnberc {
namespace semantic_detail {

namespace {

struct TagId {
    uint32_t tagClass = 0;
    uint32_t tagNumber = 0;
};

bool collectTags(const TypeNode *node, std::vector<TagId> &out,
                 uint32_t depth)
{
    if (node == nullptr || depth > 32) {
        return false;
    }
    if (node->kind == TypeKind::Any) {
        if (node->tagMode == kTagModeExplicit) {
            out.push_back(TagId{node->tagClass, node->tagNumber});
            return true;
        }
        return false;
    }
    if (node->kind == TypeKind::Choice) {
        if (node->tagMode == kTagModeExplicit) {
            out.push_back(TagId{node->tagClass, node->tagNumber});
            return true;
        }
        if (node->tagMode != kTagModeDefault) {
            return false;
        }
        bool any = false;
        for (const Field &field : node->fields) {
            std::vector<TagId> branch;
            if (!collectTags(field.type, branch, depth + 1u)) {
                return false;
            }
            for (const TagId &tag : branch) {
                out.push_back(tag);
            }
            any = true;
        }
        return any;
    }
    uint32_t tagClass = node->tagClass;
    uint32_t tagNumber = node->tagNumber;
    if (tagClass == kTagClassUniversal && tagNumber == 0) {
        if (node->kind == TypeKind::Simple ||
            node->kind == TypeKind::Any) {
            return false;
        }
        tagNumber = (node->kind == TypeKind::Sequence ||
                     node->kind == TypeKind::SequenceOf)
                        ? 16u
                        : 17u;
    }
    out.push_back(TagId{tagClass, tagNumber});
    return true;
}

} /* namespace */


uint32_t Analyzer::namedKindFor(const TypeNode &node) const
{
    if (node.kind != TypeKind::Simple ||
        node.tagClass != kTagClassUniversal) {
        return 2;
    }
    if (node.tagNumber == 3 && node.baseTagNumber == 3) {
        return 0;
    }
    if ((node.tagNumber == 2 || node.tagNumber == 10) &&
        node.tagNumber == node.baseTagNumber) {
        return 1;
    }
    return 2;
}

void Analyzer::checkNamedValues()
{
    for (const std::unique_ptr<TypeNode> &node : model_->nodes) {
        if (node->namedValues.empty()) {
            continue;
        }
        const uint32_t kind = namedKindFor(*node);
        if (kind == 2) {
            /* 带标签的克隆类型无法由名称表表达（核心要求 UNIVERSAL），
             * 名称仍由基础类型拥有；只有语法上不可能的组合才报内部错误。 */
            const bool primitive =
                node->baseTagNumber == 2 || node->baseTagNumber == 3 ||
                node->baseTagNumber == 10;
            if (node->kind != TypeKind::Simple || !primitive) {
                errorAt(node->unit, node->namedValues[0].pos,
                        DiagCode::Internal,
                        "internal error: cannot classify named values for "
                        "type '" +
                            node->name + "'");
            }
            continue;
        }
        int64_t upper = 0;
        const bool hasUpper = kind == 0 &&
                              finiteSizeUpperBound(*node, upper);
        std::set<std::string> names;
        std::set<int64_t> values;
        for (const NamedValue &named : node->namedValues) {
            if (!names.insert(named.name).second) {
                errorAt(node->unit, named.pos, DiagCode::DuplicateField,
                        "duplicate named value '" + named.name +
                            "' in type '" + node->name + "'");
            }
            if (!values.insert(named.value).second) {
                errorAt(node->unit, named.pos, DiagCode::DuplicateField,
                        "duplicate named value number " +
                            std::to_string(named.value) + " in type '" +
                            node->name + "'");
            }
            if (kind == 0) {
                const bool outOfRange =
                    named.value < 0 || named.value > 65535 ||
                    (hasUpper && named.value >= upper);
                if (outOfRange) {
                    errorAt(node->unit, named.pos,
                            DiagCode::ConstraintInvalid,
                            "named bit '" + named.name +
                                "' is out of range for BIT STRING type '" +
                                node->name + "'");
                }
            } else if (named.extension &&
                       (node->baseTagNumber != 10 ||
                        (node->flags & kTypeFlagExtensible) == 0u)) {
                errorAt(node->unit, named.pos,
                        DiagCode::ConstraintInvalid,
                        "extension named value '" + named.name +
                            "' requires an EXTENSIBLE ENUMERATED type");
            }
        }
    }
}

void Analyzer::checkStructure()
{
    for (const std::unique_ptr<TypeNode> &node : model_->nodes) {
        checkDuplicateFields(*node);
        if (node->kind == TypeKind::Set ||
            node->kind == TypeKind::Choice) {
            checkTagConflicts(*node);
        }
    }
}

void Analyzer::checkDuplicateFields(const TypeNode &node)
{
    for (size_t i = 0; i < node.fields.size(); ++i) {
        for (size_t j = i + 1; j < node.fields.size(); ++j) {
            if (node.fields[i].name == node.fields[j].name) {
                diagnostics_.add(
                    fileFor(node.unit), node.fields[j].line,
                    node.fields[j].column, Severity::Error,
                    DiagCode::DuplicateField,
                    "duplicate field name '" + node.fields[j].name +
                        "'");
            }
        }
    }
}

void Analyzer::checkTagConflicts(const TypeNode &node)
{
    for (size_t i = 0; i < node.fields.size(); ++i) {
        std::vector<TagId> first;
        if (!collectTags(node.fields[i].type, first, 0)) {
            reportUnresolvedTag(node.fields[i], node.unit);
            continue;
        }
        for (size_t j = i + 1; j < node.fields.size(); ++j) {
            std::vector<TagId> second;
            if (!collectTags(node.fields[j].type, second, 0)) {
                reportUnresolvedTag(node.fields[j], node.unit);
                return;
            }
            bool conflict = false;
            for (const TagId &a : first) {
                for (const TagId &b : second) {
                    if (a.tagClass == b.tagClass &&
                        a.tagNumber == b.tagNumber) {
                        conflict = true;
                    }
                }
            }
            if (conflict) {
                diagnostics_.add(
                    fileFor(node.unit), node.fields[j].line,
                    node.fields[j].column, Severity::Error,
                    DiagCode::TagConflict,
                    "effective tag of field '" +
                        node.fields[j].name +
                        "' conflicts with field '" +
                        node.fields[i].name + "'");
                return;
            }
        }
    }
}

void Analyzer::reportUnresolvedTag(const Field &field, uint32_t unit)
{
    diagnostics_.add(fileFor(unit), field.line, field.column, Severity::Error,
                     DiagCode::TagConflict,
                     "cannot determine effective tag for field '" +
                         field.name + "'");
}

} /* namespace semantic_detail */
} /* namespace asnberc */
