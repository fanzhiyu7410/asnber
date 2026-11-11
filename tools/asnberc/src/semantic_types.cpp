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

uint32_t universalTagForClass(TypeAst::Class cls) noexcept
{
    switch (cls) {
    case TypeAst::Class::Boolean:
        return 1;
    case TypeAst::Class::Integer:
        return 2;
    case TypeAst::Class::Enumerated:
        return 10;
    case TypeAst::Class::BitString:
        return 3;
    case TypeAst::Class::OctetString:
        return 4;
    case TypeAst::Class::Null:
        return 5;
    case TypeAst::Class::ObjectIdentifier:
        return 6;
    case TypeAst::Class::Utf8String:
        return 12;
    case TypeAst::Class::NumericString:
        return 18;
    case TypeAst::Class::PrintableString:
        return 19;
    case TypeAst::Class::TeletexString:
        return 20;
    case TypeAst::Class::Ia5String:
        return 22;
    case TypeAst::Class::UtcTime:
        return 23;
    case TypeAst::Class::GeneralizedTime:
        return 24;
    case TypeAst::Class::VisibleString:
        return 26;
    case TypeAst::Class::UniversalString:
        return 28;
    case TypeAst::Class::BmpString:
        return 30;
    default:
        return 0;
    }
}

} /* namespace */


TypeNode *Analyzer::resolveNamed(uint32_t index)
{
    TypeNode *node = model_->named[index];
    /* 合成节点（参数化实例化产物）已在 instantiate 中完成 fillNode，
       且不在 namedAsts_ 中，直接跳过。 */
    if (node->synthetic) {
        return node;
    }
    if (namedState_[index] == 2) {
        return node;
    }
    if (namedState_[index] == 1) {
        error(namedAsts_[index]->pos, DiagCode::UndefinedType,
              "cyclic type alias involving '" + node->name + "'");
        return node;
    }
    /* 参数化模板（形参非空）不在此展开：其体内含形参引用，必须经
       instantiate() 替换实参后才能 fillNode。直接跳过，避免把形参当作
       未定义类型。 */
    if (!namedParams_[index].empty()) {
        namedState_[index] = 2;
        return node;
    }
    namedState_[index] = 1;
    const uint32_t saved = currentUnit_;
    currentUnit_ = namedUnits_[index];
    fillNode(node, *namedAsts_[index]);
    currentUnit_ = saved;
    namedState_[index] = 2;
    return node;
}

TypeNode *Analyzer::ensureNamed(const std::string &name, const Pos &pos)
{
    uint32_t boundUnit = 0;
    std::string local;
    if (!findTypeBinding(currentUnit_, name, boundUnit, local)) {
        error(pos, DiagCode::UndefinedType, "undefined type '" + name +
                                                 "'");
        return nullptr;
    }
    std::map<std::string, uint32_t>::const_iterator it = typeIndex_.find(
        symbolKey(boundUnit, local));
    if (it == typeIndex_.end()) {
        error(pos, DiagCode::UndefinedType, "undefined type '" + name +
                                                 "'");
        return nullptr;
    }
    return resolveNamed(it->second);
}

TypeNode *Analyzer::newSynthetic(const std::string &hint)
{
    std::unique_ptr<TypeNode> node = std::make_unique<TypeNode>();
    node->synthetic = true;
    node->unit = currentUnit_;
    node->name = "$" + sanitize(hint) + "_" +
                 std::to_string(syntheticCounter_);
    ++syntheticCounter_;
    model_->nodes.push_back(std::move(node));
    TypeNode *pointer = model_->nodes.back().get();
    model_->synthetic.push_back(pointer);
    return pointer;
}

std::string Analyzer::sanitize(const std::string &hint)
{
    std::string result;
    for (char c : hint) {
        const bool keep = (c >= 'A' && c <= 'Z') ||
                          (c >= 'a' && c <= 'z') ||
                          (c >= '0' && c <= '9');
        result.push_back(keep ? c : '_');
    }
    if (result.empty()) {
        result = "anon";
    }
    return result;
}

TypeNode *Analyzer::sharedAny()
{
    if (model_->anyNode == nullptr) {
        TypeNode *node = newSynthetic("ANY");
        node->kind = TypeKind::Any;
        node->tagMode = kTagModeDefault;
        node->tagClass = kTagClassUniversal;
        node->tagNumber = 0;
        node->baseTagNumber = 0;
        node->flags = 0;
        model_->anyNode = node;
    }
    return model_->anyNode;
}

void Analyzer::copyNode(const TypeNode *source, TypeNode *target)
{
    if (source == target) {
        return;
    }
    target->kind = source->kind;
    target->tagMode = source->tagMode;
    target->tagClass = source->tagClass;
    target->tagNumber = source->tagNumber;
    target->baseTagNumber = source->baseTagNumber;
    target->flags = source->flags;
    target->element = source->element;
    target->fields = source->fields;
    target->constraints = source->constraints;
    target->namedValues = source->namedValues;
    /* 位置信息来自定义所在模块，诊断随之回到该模块的源文件。 */
    target->unit = source->unit;
}

bool Analyzer::applyTag(TypeNode *node, const TagSpec &tag)
{
    uint8_t mode = kTagModeDefault;
    if (tag.mode == TagModeSpec::Explicit) {
        mode = kTagModeExplicit;
    } else if (tag.mode == TagModeSpec::Implicit) {
        mode = kTagModeImplicit;
    } else {
        /* 未加关键字时按定义所在模块的标注方式解析：多模块合并后各模块可以不同。 */
        const uint32_t moduleMode =
            static_cast<uint32_t>(unitAt(currentUnit_).ast.tagMode);
        if (moduleMode == 1) {
            mode = kTagModeExplicit;
        } else if (moduleMode == 2 || moduleMode == 0) {
            mode = kTagModeImplicit;
        } else {
            mode = kTagModeExplicit;
        }
    }

    if (node->kind == TypeKind::Choice && mode == kTagModeImplicit) {
        if (tag.mode == TagModeSpec::Implicit) {
            error(tag.pos, DiagCode::TagConflict,
                  "IMPLICIT tagging cannot be applied to CHOICE");
            return false;
        }
        /* 自动标注时 CHOICE 必须显式包装。 */
        mode = kTagModeExplicit;
    }
    if (node->kind == TypeKind::Any && mode == kTagModeImplicit) {
        error(tag.pos, DiagCode::TagConflict,
              "IMPLICIT tagging cannot be applied to ANY");
        return false;
    }
    node->tagMode = mode;
    node->tagClass = kTagClassContext;
    node->tagNumber = tag.number;
    return true;
}

bool Analyzer::fillNode(TypeNode *node, const TypeAst &ast)
{
    if (ast.cls == TypeAst::Class::Reference) {
        if (!ast.instanceArgs.empty()) {
            TypeNode *target = instantiate(ast.refName, ast.pos,
                                           ast.instanceArgs);
            if (target == nullptr) {
                return false;
            }
            copyNode(target, node);
            if (ast.tag.present && !applyTag(node, ast.tag)) {
                return false;
            }
            return buildConstraints(ast.constraints, node->constraints,
                                    ast.pos);
        }
        const std::vector<std::string> *params =
            findParams(currentUnit_, ast.refName);
        if (params != nullptr && !params->empty()) {
            error(ast.pos, DiagCode::ParamInstantiation,
                  "parameterized type '" + ast.refName +
                      "' requires instantiation");
            return false;
        }
        TypeNode *target = ensureNamed(ast.refName, ast.pos);
        if (target == nullptr) {
            return false;
        }
        if (target == node) {
            error(ast.pos, DiagCode::UndefinedType,
                  "cyclic type alias involving '" + ast.refName + "'");
            return false;
        }
        copyNode(target, node);
        if (ast.tag.present && !applyTag(node, ast.tag)) {
            return false;
        }
        return buildConstraints(ast.constraints, node->constraints,
                                ast.pos);
    }

    if (ast.cls == TypeAst::Class::Any) {
        TypeNode *source = sharedAny();
        copyNode(source, node);
    } else if (ast.cls == TypeAst::Class::Sequence ||
               ast.cls == TypeAst::Class::Set ||
               ast.cls == TypeAst::Class::Choice) {
        node->tagMode = kTagModeDefault;
        node->tagClass = kTagClassUniversal;
        node->tagNumber = 0;
        node->baseTagNumber = 0;
        if (ast.cls == TypeAst::Class::Sequence) {
            node->kind = TypeKind::Sequence;
            node->baseTagNumber = 16;
        } else if (ast.cls == TypeAst::Class::Set) {
            node->kind = TypeKind::Set;
            node->baseTagNumber = 17;
        } else {
            node->kind = TypeKind::Choice;
        }
        node->flags = ast.extensible ? kTypeFlagExtensible : 0u;
        if (!resolveFields(node, ast)) {
            return false;
        }
    } else if (ast.cls == TypeAst::Class::SequenceOf ||
               ast.cls == TypeAst::Class::SetOf) {
        node->tagMode = kTagModeDefault;
        node->tagClass = kTagClassUniversal;
        node->tagNumber = 0;
        node->baseTagNumber =
            ast.cls == TypeAst::Class::SequenceOf ? 16u : 17u;
        node->kind = ast.cls == TypeAst::Class::SequenceOf
                         ? TypeKind::SequenceOf
                         : TypeKind::SetOf;
        node->flags = ast.extensible ? kTypeFlagExtensible : 0u;
        if (ast.element == nullptr ||
            !resolveElement(*ast.element, node->name + ".element",
                            node->element)) {
            return false;
        }
    } else {
        const uint32_t tag = universalTagForClass(ast.cls);
        if (tag == 0) {
            error(ast.pos, DiagCode::Internal,
                  "internal error: unknown primitive type");
            return false;
        }
        node->kind = TypeKind::Simple;
        node->tagMode = kTagModeDefault;
        node->tagClass = kTagClassUniversal;
        node->tagNumber = tag;
        node->baseTagNumber = tag;
        node->flags = ast.extensible ? kTypeFlagExtensible : 0u;
        node->namedValues.clear();
        for (size_t i = 0; i < ast.namedNumbers.size(); ++i) {
            const NamedNumberAst &named = ast.namedNumbers[i];
            node->namedValues.push_back(
                NamedValue{named.name, named.value,
                           i >= ast.rootNamedCount, named.pos});
        }
        if ((ast.cls == TypeAst::Class::Integer ||
             ast.cls == TypeAst::Class::Enumerated) &&
            ast.rootNamedCount > 0) {
            if (!addEnumConstraint(node, ast)) {
                return false;
            }
        }
    }

    if (!buildConstraints(ast.constraints, node->constraints, ast.pos)) {
        return false;
    }
    if (ast.cls == TypeAst::Class::Any && !ast.constraints.empty()) {
        error(ast.pos, DiagCode::ConstraintInvalid,
              "ANY cannot carry constraints");
        return false;
    }
    if (ast.tag.present && !applyTag(node, ast.tag)) {
        return false;
    }
    return true;
}

bool Analyzer::addEnumConstraint(TypeNode *node, const TypeAst &ast)
{
    Constraint constraint;
    constraint.kind = 2;
    for (size_t i = 0; i < ast.rootNamedCount &&
                        i < ast.namedNumbers.size();
         ++i) {
        constraint.enumValues.push_back(ast.namedNumbers[i].value);
    }
    if (!constraint.enumValues.empty()) {
        node->constraints.push_back(std::move(constraint));
    }
    return true;
}

bool Analyzer::resolveFields(TypeNode *owner, const TypeAst &ast)
{
    for (const FieldAst &fieldAst : ast.fields) {
        Field field;
        field.name = fieldAst.name;
        field.line = fieldAst.pos.line;
        field.column = fieldAst.pos.column;
        if (fieldAst.optional) {
            field.flags = static_cast<uint16_t>(
                field.flags | kFieldFlagOptional);
        }
        if (fieldAst.extension && owner->kind != TypeKind::Choice) {
            field.flags = static_cast<uint16_t>(
                field.flags | kFieldFlagExtension);
        }
        if (!resolveFieldType(fieldAst, owner->name, field)) {
            return false;
        }
        if (fieldAst.defaultValue != nullptr) {
            if (!encodeDefault(field, *fieldAst.defaultValue,
                               fieldAst.pos)) {
                return false;
            }
        }
        owner->fields.push_back(std::move(field));
    }
    return true;
}

bool Analyzer::resolveFieldType(const FieldAst &fieldAst, const std::string &owner,
                      Field &field)
{
    const TypeAst &ast = *fieldAst.type;
    if (ast.cls == TypeAst::Class::Reference && !ast.tag.present) {
        if (!ast.instanceArgs.empty()) {
            TypeNode *target = instantiate(ast.refName, ast.pos,
                                           ast.instanceArgs);
            if (target == nullptr) {
                return false;
            }
            field.type = target;
            if (!ast.constraints.empty()) {
                return buildConstraints(ast.constraints, field.constraints,
                                        ast.pos);
            }
            return true;
        }
        TypeNode *target = ensureNamed(ast.refName, ast.pos);
        if (target == nullptr) {
            return false;
        }
        field.type = target;
        if (!ast.constraints.empty()) {
            return buildConstraints(ast.constraints, field.constraints,
                                    ast.pos);
        }
        return true;
    }
    if (ast.cls == TypeAst::Class::Any && !ast.tag.present) {
        if (!ast.constraints.empty()) {
            error(ast.pos, DiagCode::ConstraintInvalid,
                  "ANY cannot carry constraints");
            return false;
        }
        field.type = sharedAny();
        return true;
    }
    TypeNode *node =
        resolveExprToNode(ast, owner + "." + fieldAst.name);
    if (node == nullptr) {
        return false;
    }
    field.type = node;
    return true;
}

TypeNode *Analyzer::resolveExprToNode(const TypeAst &ast, const std::string &hint)
{
    TypeNode *node = newSynthetic(hint);
    if (!fillNode(node, ast)) {
        return nullptr;
    }
    return node;
}

bool Analyzer::resolveElement(const TypeAst &ast, const std::string &hint,
                    TypeNode *&out)
{
    if (ast.cls == TypeAst::Class::Reference && !ast.tag.present &&
        ast.constraints.empty()) {
        if (!ast.instanceArgs.empty()) {
            out = instantiate(ast.refName, ast.pos, ast.instanceArgs);
            return out != nullptr;
        }
        out = ensureNamed(ast.refName, ast.pos);
        return out != nullptr;
    }
    if (ast.cls == TypeAst::Class::Any && !ast.tag.present) {
        if (!ast.constraints.empty()) {
            error(ast.pos, DiagCode::ConstraintInvalid,
                  "ANY cannot carry constraints");
            return false;
        }
        out = sharedAny();
        return true;
    }
    out = resolveExprToNode(ast, hint);
    return out != nullptr;
}

void Analyzer::assignIds()
{
    /* 检测是否存在参数化模板：只有模板存在时才需要调整 id 分配顺序，
       否则保持原有行为（按 model.nodes 顺序），确保非参数化路径不变。 */
    bool hasTemplate = false;
    for (const std::unique_ptr<TypeNode> &node : model_->nodes) {
        if (node->isTemplate) {
            hasTemplate = true;
            break;
        }
    }

    uint32_t id = 1;
    if (hasTemplate) {
        /* id 分配顺序需与人工展平版本一致：
           1. 参数化合成节点（有确定名称，如 Foo-INTEGER）—— 对应展平中的命名类型，
              按名称排序使顺序与人工展平的定义顺序一致。
           2. 命名节点
           3. 普通合成节点（$ 开头，如字段内联类型） */
        std::vector<TypeNode *> paramSynth;
        std::vector<TypeNode *> plainSynth;
        for (const std::unique_ptr<TypeNode> &node : model_->nodes) {
            if (node->isTemplate || !node->synthetic) {
                continue;
            }
            if (!node->name.empty() && node->name[0] != '$') {
                paramSynth.push_back(node.get());
            } else {
                plainSynth.push_back(node.get());
            }
        }
        std::sort(paramSynth.begin(), paramSynth.end(),
                  [](const TypeNode *a, const TypeNode *b) {
                      return a->name < b->name;
                  });
        for (TypeNode *node : paramSynth) {
            node->id = id;
            ++id;
        }
        for (const std::unique_ptr<TypeNode> &node : model_->nodes) {
            if (node->isTemplate || node->synthetic) {
                continue;
            }
            node->id = id;
            ++id;
        }
        for (TypeNode *node : plainSynth) {
            node->id = id;
            ++id;
        }
    } else {
        for (const std::unique_ptr<TypeNode> &node : model_->nodes) {
            node->id = id;
            ++id;
        }
    }
}

TypeNode *Analyzer::instantiate(
    const std::string &templateName, const Pos &pos,
    const std::vector<std::unique_ptr<TypeAst>> &args)
{
    const std::vector<std::string> *params =
        findParams(currentUnit_, templateName);
    if (params == nullptr) {
        error(pos, DiagCode::UndefinedType,
              "undefined type '" + templateName + "'");
        return nullptr;
    }
    if (params->empty()) {
        error(pos, DiagCode::ParamInstantiation,
              "type '" + templateName + "' is not parameterized");
        return nullptr;
    }
    if (args.size() != params->size()) {
        error(pos, DiagCode::ParamInstantiation,
              "parameterized type '" + templateName + "' expects " +
                  std::to_string(params->size()) + " argument(s), got " +
                  std::to_string(args.size()));
        return nullptr;
    }

    /* 缓存键：模板名 + 实参数量 + 每个实参的文本表示。
       实参文本用其 refName（若是引用）或类名（若是内联类型）拼接。
       同一实例化只展开一次。 */
    std::string cacheKey = templateName + "<";
    for (size_t i = 0; i < args.size(); ++i) {
        if (i > 0) {
            cacheKey += ",";
        }
        if (args[i]->cls == TypeAst::Class::Reference) {
            cacheKey += args[i]->refName;
            if (!args[i]->instanceArgs.empty()) {
                cacheKey += "{inst}";
            }
        } else {
            cacheKey += "inline_" +
                        std::to_string(static_cast<int>(args[i]->cls));
        }
    }
    cacheKey += ">";

    std::map<std::string, TypeNode *>::const_iterator cached =
        instantiationCache_.find(cacheKey);
    if (cached != instantiationCache_.end()) {
        return cached->second;
    }

    /* 查找模板 AST。 */
    uint32_t boundUnit = 0;
    std::string local;
    if (!findTypeBinding(currentUnit_, templateName, boundUnit, local)) {
        error(pos, DiagCode::UndefinedType,
              "undefined type '" + templateName + "'");
        return nullptr;
    }
    std::map<std::string, uint32_t>::const_iterator it = typeIndex_.find(
        symbolKey(boundUnit, local));
    if (it == typeIndex_.end()) {
        error(pos, DiagCode::UndefinedType,
              "undefined type '" + templateName + "'");
        return nullptr;
    }
    const TypeAst *templateAst = namedAsts_[it->second];

    /* 深拷贝模板 AST，替换形参为实参。 */
    std::unique_ptr<TypeAst> substituted = cloneTypeAst(*templateAst);
    std::map<std::string, const TypeAst *> argMap;
    for (size_t i = 0; i < params->size(); ++i) {
        argMap[(*params)[i]] = args[i].get();
    }
    substituteParams(*substituted, argMap);

    /* 合成类型名：用 '-' 分隔模板名与实参，如 Foo<INTEGER> → "Foo-INTEGER"。
       名称只含字母、数字、'-'，且不以 '-' 开头/结尾，既是合法 ASN.1 标识符
       也是合法 C 标识符，使参数化输出可与人工展平版本逐字节一致。 */
    std::string instName = templateName;
    for (size_t i = 0; i < args.size(); ++i) {
        instName += "-";
        std::string argName;
        if (args[i]->cls == TypeAst::Class::Reference) {
            argName = args[i]->refName;
        } else {
            switch (args[i]->cls) {
            case TypeAst::Class::Boolean: argName = "BOOLEAN"; break;
            case TypeAst::Class::Integer: argName = "INTEGER"; break;
            case TypeAst::Class::Enumerated: argName = "ENUMERATED"; break;
            case TypeAst::Class::BitString: argName = "BIT-STRING"; break;
            case TypeAst::Class::OctetString: argName = "OCTET-STRING"; break;
            case TypeAst::Class::Null: argName = "NULL"; break;
            case TypeAst::Class::ObjectIdentifier: argName = "OID"; break;
            case TypeAst::Class::Utf8String: argName = "UTF8String"; break;
            case TypeAst::Class::PrintableString: argName = "PrintableString"; break;
            case TypeAst::Class::Ia5String: argName = "IA5String"; break;
            case TypeAst::Class::VisibleString: argName = "VisibleString"; break;
            case TypeAst::Class::NumericString: argName = "NumericString"; break;
            case TypeAst::Class::TeletexString: argName = "TeletexString"; break;
            case TypeAst::Class::BmpString: argName = "BMPString"; break;
            case TypeAst::Class::UniversalString: argName = "UniversalString"; break;
            case TypeAst::Class::UtcTime: argName = "UTCTime"; break;
            case TypeAst::Class::GeneralizedTime: argName = "GeneralizedTime"; break;
            case TypeAst::Class::Any: argName = "ANY"; break;
            case TypeAst::Class::Sequence: argName = "SEQUENCE"; break;
            case TypeAst::Class::Set: argName = "SET"; break;
            case TypeAst::Class::Choice: argName = "CHOICE"; break;
            case TypeAst::Class::SequenceOf: argName = "SEQUENCE-OF"; break;
            case TypeAst::Class::SetOf: argName = "SET-OF"; break;
            default: argName = "TYPE"; break;
            }
        }
        /* 实参名中的非字母数字字符（如空格）替换为 '-'。 */
        for (char c : argName) {
            const bool keep = (c >= 'A' && c <= 'Z') ||
                              (c >= 'a' && c <= 'z') ||
                              (c >= '0' && c <= '9') || c == '-';
            instName.push_back(keep ? c : '-');
        }
    }
    /* 去掉尾部可能的 '-'。 */
    while (!instName.empty() && instName.back() == '-') {
        instName.pop_back();
    }

    /* 切换到模板定义所在模块进行展开，保证标签模式与诊断位置正确。 */
    const uint32_t savedUnit = currentUnit_;
    currentUnit_ = boundUnit;
    /* 直接创建合成节点，不调用 newSynthetic（避免消耗 syntheticCounter_，
       使后续普通合成节点的后缀编号与人工展平版本一致）。 */
    std::unique_ptr<TypeNode> nodePtr = std::make_unique<TypeNode>();
    nodePtr->synthetic = true;
    nodePtr->unit = currentUnit_;
    nodePtr->name = instName;
    TypeNode *node = nodePtr.get();
    model_->nodes.push_back(std::move(nodePtr));
    model_->synthetic.push_back(node);
    const bool ok = fillNode(node, *substituted);
    currentUnit_ = savedUnit;

    if (!ok) {
        return nullptr;
    }
    /* 参数化合成类型有确定名称，与人工展平的命名类型等价，
       计入 named 列表使 namedTypeCount 与展平版本一致。 */
    model_->named.push_back(node);
    instantiationCache_[cacheKey] = node;
    return node;
}

std::unique_ptr<TypeAst> Analyzer::cloneTypeAst(const TypeAst &source)
{
    auto result = std::make_unique<TypeAst>();
    result->cls = source.cls;
    result->pos = source.pos;
    result->refName = source.refName;
    result->rootNamedCount = source.rootNamedCount;
    result->tag = source.tag;
    result->extensible = source.extensible;

    for (const FieldAst &field : source.fields) {
        FieldAst copy;
        copy.name = field.name;
        copy.pos = field.pos;
        copy.optional = field.optional;
        copy.extension = field.extension;
        if (field.type != nullptr) {
            copy.type = cloneTypeAst(*field.type);
        }
        if (field.defaultValue != nullptr) {
            /* DEFAULT 值在参数化展开中不涉及形参替换，浅拷贝共享即可。 */
            copy.defaultValue = std::make_unique<ValueAst>(*field.defaultValue);
        }
        result->fields.push_back(std::move(copy));
    }
    if (source.element != nullptr) {
        result->element = cloneTypeAst(*source.element);
    }
    result->constraints = source.constraints;
    result->namedNumbers = source.namedNumbers;
    for (const auto &arg : source.instanceArgs) {
        result->instanceArgs.push_back(cloneTypeAst(*arg));
    }
    return result;
}

void Analyzer::substituteParams(
    TypeAst &ast, const std::map<std::string, const TypeAst *> &args)
{
    if (ast.cls == TypeAst::Class::Reference) {
        std::map<std::string, const TypeAst *>::const_iterator it =
            args.find(ast.refName);
        if (it != args.end() && ast.instanceArgs.empty()) {
            /* 用实参替换形参引用：把实参的内容拷贝到当前节点。
               实参自身是 Reference 时直接改 refName；内联类型需要整体替换。 */
            const TypeAst *arg = it->second;
            if (arg->cls == TypeAst::Class::Reference &&
                arg->instanceArgs.empty()) {
                ast.refName = arg->refName;
                ast.constraints = arg->constraints;
                ast.tag = arg->tag;
            } else {
                /* 内联实参：深拷贝整个实参 AST 覆盖当前节点。 */
                std::unique_ptr<TypeAst> copy = cloneTypeAst(*arg);
                ast = std::move(*copy);
            }
            return;
        }
        /* 非形参引用或带实例化的引用：递归其实参。 */
        for (auto &arg : ast.instanceArgs) {
            substituteParams(*arg, args);
        }
        return;
    }

    for (FieldAst &field : ast.fields) {
        if (field.type != nullptr) {
            substituteParams(*field.type, args);
        }
    }
    if (ast.element != nullptr) {
        substituteParams(*ast.element, args);
    }
}

} /* namespace semantic_detail */
} /* namespace asnberc */
