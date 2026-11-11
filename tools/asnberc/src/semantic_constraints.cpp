/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "detail/semantic_internal.h"

namespace asnberc {
namespace semantic_detail {

bool Analyzer::buildConstraints(const std::vector<ConstraintAst> &source,
                      std::vector<Constraint> &target,
                      const Pos &pos)
{
    for (const ConstraintAst &item : source) {
        BoundValue lower;
        BoundValue upper;
        if (!resolveBound(item.lower, true, lower, pos)) {
            return false;
        }
        if (!resolveBound(item.upper, false, upper, pos)) {
            return false;
        }
        if (item.single && item.lower.isMax) {
            error(pos, DiagCode::ConstraintInvalid,
                  "constraint cannot have a single MAX bound");
            return false;
        }
        Constraint constraint;
        if (item.kind == ConstraintAst::Kind::Size) {
            if (lower.unbounded) {
                error(pos, DiagCode::ConstraintInvalid,
                      "SIZE lower bound must be finite");
                return false;
            }
            if (lower.value < 0) {
                error(pos, DiagCode::ConstraintInvalid,
                      "SIZE lower bound must be non-negative");
                return false;
            }
            constraint.kind = 1;
            constraint.lower = lower.value;
            if (upper.unbounded) {
                constraint.upperUnbounded = true;
            } else {
                if (upper.value < lower.value) {
                    error(pos, DiagCode::ConstraintInvalid,
                          "SIZE upper bound is below lower bound");
                    return false;
                }
                constraint.upper = upper.value;
            }
            target.push_back(std::move(constraint));
            continue;
        }
        constraint.kind = 0;
        if (lower.unbounded) {
            constraint.lowerUnbounded = true;
        } else {
            constraint.lower = lower.value;
        }
        if (upper.unbounded) {
            constraint.upperUnbounded = true;
        } else {
            constraint.upper = upper.value;
        }
        if (!constraint.lowerUnbounded &&
            !constraint.upperUnbounded &&
            constraint.lower > constraint.upper) {
            error(pos, DiagCode::ConstraintInvalid,
                  "constraint lower bound exceeds upper bound");
            return false;
        }
        if (!constraint.lowerUnbounded && constraint.lower == 0 &&
            constraint.upperUnbounded) {
            constraint.kind = 3; /* MAX */
        }
        target.push_back(std::move(constraint));
    }
    return true;
}

bool Analyzer::resolveBound(const ConstraintBoundAst &bound, bool lowerBound,
                  BoundValue &out, const Pos &pos)
{
    out = BoundValue();
    if (bound.isMax) {
        if (lowerBound) {
            error(pos, DiagCode::ConstraintInvalid,
                  "lower bound cannot be MAX");
            return false;
        }
        out.unbounded = true;
        return true;
    }
    if (bound.isMin) {
        if (!lowerBound) {
            error(pos, DiagCode::ConstraintInvalid,
                  "upper bound cannot be MIN");
            return false;
        }
        out.unbounded = true;
        return true;
    }
    if (bound.hasValue) {
        out.value = bound.value;
        return true;
    }
    if (!bound.refName.empty()) {
        /* 值引用：先确认值是否定义，再确认其是否为整数。 */
        uint32_t boundUnit = 0;
        std::string local;
        if (!findValueBinding(currentUnit_, bound.refName, boundUnit,
                              local)) {
            error(bound.pos, DiagCode::UndefinedType,
                  "undefined value '" + bound.refName + "' in constraint");
            return false;
        }
        std::map<std::string, ValueSymbol>::const_iterator it = values_.find(
            symbolKey(boundUnit, local));
        if (it == values_.end()) {
            error(bound.pos, DiagCode::UndefinedType,
                  "undefined value '" + bound.refName + "' in constraint");
            return false;
        }
        if (!it->second.isInteger) {
            error(bound.pos, DiagCode::ConstraintInvalid,
                  "constraint bound '" + bound.refName +
                      "' must be an integer value");
            return false;
        }
        out.value = it->second.integer;
        return true;
    }
    error(pos, DiagCode::ConstraintInvalid,
          "missing constraint bound");
    return false;
}

bool Analyzer::resolveInteger(const TypeNode *type, const ValueAst &value,
                    const Pos &pos, int64_t &out)
{
    if (value.kind == ValueAst::Kind::Integer) {
        out = value.intValue;
        return true;
    }
    if (value.kind == ValueAst::Kind::Reference) {
        for (const NamedValue &named : type->namedValues) {
            if (named.name == value.text) {
                out = named.value;
                return true;
            }
        }
        if (lookupInteger(value.text, out)) {
            return true;
        }
        error(pos, DiagCode::ConstraintInvalid,
              "cannot resolve DEFAULT value '" + value.text + "'");
        return false;
    }
    error(pos, DiagCode::ConstraintInvalid,
          "DEFAULT value is not an integer");
    return false;
}

void Analyzer::noteFiniteSize(const std::vector<Constraint> &list,
                           bool &found, int64_t &upper)
{
    for (const Constraint &constraint : list) {
        if (constraint.kind != 1 || constraint.upperUnbounded) {
            continue;
        }
        if (!found || constraint.upper < upper) {
            upper = constraint.upper;
            found = true;
        }
    }
}

bool Analyzer::finiteSizeUpperBound(const TypeNode &type, int64_t &upper) const
{
    bool found = false;
    upper = 0;
    noteFiniteSize(type.constraints, found, upper);
    for (const std::unique_ptr<TypeNode> &owner : model_->nodes) {
        for (const Field &field : owner->fields) {
            if (field.type == &type) {
                noteFiniteSize(field.constraints, found, upper);
            }
        }
    }
    return found;
}

} /* namespace semantic_detail */
} /* namespace asnberc */
