/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

#include "table.h"

#include "crc32c.h"

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <map>

namespace asnberc {
namespace {

constexpr size_t kHeaderSize = 108;
constexpr size_t kTypeRecordSize = 48;
constexpr size_t kFieldRecordSize = 32;
constexpr size_t kConstraintRecordSize = 48;
constexpr size_t kDefaultRecordSize = 8;
constexpr size_t kNameRecordSize = 24;
constexpr uint32_t kFieldFlagOptional = 1u;
constexpr uint32_t kFieldFlagExtension = 2u;
constexpr uint16_t kNameFlagExtension = 1u;

size_t align8(size_t value) { return (value + 7u) & ~static_cast<size_t>(7u); }

/*
 * 与 std::vector<uint8_t> 的默认 "operator<"（字典序）等价的显式比较器：
 * 先按两键的公共长度逐字节 memcmp，前缀完全相同再按长度比较。
 * 这样 GCC 16 + -O3 不会把键比较内联进 std::lexicographical_compare_three_way
 * 的 __builtin_memcmp 快速路径，避免 -Wstringop-overread 误报；
 * 比较结果与默认字典序完全一致，map 的键顺序与生成的表字节不受影响。
 */
struct ByteVectorLess {
    bool operator()(const std::vector<uint8_t> &lhs,
                    const std::vector<uint8_t> &rhs) const
    {
        const size_t common =
            lhs.size() < rhs.size() ? lhs.size() : rhs.size();
        if (common != 0) {
            const int cmp = std::memcmp(lhs.data(), rhs.data(), common);
            if (cmp != 0) {
                return cmp < 0;
            }
        }
        return lhs.size() < rhs.size();
    }
};

void putU8(std::vector<uint8_t> &buffer, size_t offset, uint8_t value)
{
    buffer[offset] = value;
}

void putU16(std::vector<uint8_t> &buffer, size_t offset, uint16_t value)
{
    buffer[offset] = static_cast<uint8_t>(value & 0xFFu);
    buffer[offset + 1] = static_cast<uint8_t>((value >> 8) & 0xFFu);
}

void putU32(std::vector<uint8_t> &buffer, size_t offset, uint32_t value)
{
    for (uint32_t i = 0; i < 4; ++i) {
        buffer[offset + i] =
            static_cast<uint8_t>((value >> (8u * i)) & 0xFFu);
    }
}

void putU64(std::vector<uint8_t> &buffer, size_t offset, uint64_t value)
{
    for (uint32_t i = 0; i < 8; ++i) {
        buffer[offset + i] =
            static_cast<uint8_t>((value >> (8u * i)) & 0xFFu);
    }
}

void putI64(std::vector<uint8_t> &buffer, size_t offset, int64_t value)
{
    putU64(buffer, offset, static_cast<uint64_t>(value));
}

std::string makeSymbol(const std::string &moduleName)
{
    std::string cleaned;
    for (char c : moduleName) {
        const bool keep = (c >= 'A' && c <= 'Z') ||
                          (c >= 'a' && c <= 'z') ||
                          (c >= '0' && c <= '9');
        if (keep) {
            cleaned.push_back(c);
        }
    }
    return "k" + cleaned + "Schema";
}

struct FieldEntry {
    const Field *field = nullptr;
    uint32_t typeId = 0;
    uint32_t constraintStart = 0;
    uint32_t constraintCount = 0;
    uint32_t defaultIndex = 0;
};

struct NodeLayout {
    uint32_t fieldStart = 0;
    uint32_t fieldCount = 0;
    uint32_t constraintStart = 0;
    uint32_t constraintCount = 0;
};

/* 名称表可表达的命名位 / 数值名；无法表达的标签克隆不在其中。 */
struct NameEntry {
    uint32_t typeId = 0;
    std::string name;
    uint16_t kind = 0;
    uint16_t flags = 0;
    int64_t value = 0;
};

uint16_t nameKindForNode(const TypeNode &node)
{
    if (node.kind != TypeKind::Simple || node.tagClass != 0) {
        return 2;
    }
    if (node.tagNumber == 3 && node.baseTagNumber == 3) {
        return 0; /* BIT_NAME */
    }
    if ((node.tagNumber == 2 || node.tagNumber == 10) &&
        node.tagNumber == node.baseTagNumber) {
        return 1; /* NUMBER_NAME */
    }
    return 2;
}

} /* namespace */

TableOutput buildTable(const SchemaModel &model,
                       const std::string &moduleName)
{
    TableOutput output;
    output.symbol = makeSymbol(moduleName);
    output.sizeSymbol = output.symbol + "_size";
    output.typeCount = static_cast<uint32_t>(model.nodes.size());
    output.namedTypeCount = static_cast<uint32_t>(model.named.size());

    std::vector<const TypeNode *> ordered;
    ordered.reserve(model.nodes.size());
    for (const std::unique_ptr<TypeNode> &node : model.nodes) {
        if (node->isTemplate) {
            continue;
        }
        ordered.push_back(node.get());
    }
    /* 按 id 升序排列，保证类型表第 i 项的 id == i+1，与字段引用一致。 */
    std::sort(ordered.begin(), ordered.end(),
              [](const TypeNode *a, const TypeNode *b) {
                  return a->id < b->id;
              });
    output.typeCount = static_cast<uint32_t>(ordered.size());

    std::vector<TypeNode *> namedNonTemplate;
    namedNonTemplate.reserve(model.named.size());
    for (TypeNode *node : model.named) {
        if (node->isTemplate) {
            continue;
        }
        namedNonTemplate.push_back(node);
    }
    output.namedTypeCount = static_cast<uint32_t>(namedNonTemplate.size());

    std::vector<NodeLayout> layouts(ordered.size());
    std::vector<FieldEntry> fieldEntries;
    std::vector<const Constraint *> constraintEntries;

    for (size_t i = 0; i < ordered.size(); ++i) {
        NodeLayout &layout = layouts[i];
        const TypeNode &node = *ordered[i];

        layout.constraintStart =
            static_cast<uint32_t>(constraintEntries.size());
        for (const Constraint &constraint : node.constraints) {
            constraintEntries.push_back(&constraint);
        }
        layout.constraintCount =
            static_cast<uint32_t>(constraintEntries.size()) -
            layout.constraintStart;

        layout.fieldStart = static_cast<uint32_t>(fieldEntries.size());
        for (const Field &field : node.fields) {
            FieldEntry entry;
            entry.field = &field;
            entry.typeId = field.type != nullptr ? field.type->id : 0;
            entry.constraintStart =
                static_cast<uint32_t>(constraintEntries.size());
            for (const Constraint &constraint : field.constraints) {
                constraintEntries.push_back(&constraint);
            }
            entry.constraintCount =
                static_cast<uint32_t>(constraintEntries.size()) -
                entry.constraintStart;
            fieldEntries.push_back(entry);
        }
        layout.fieldCount =
            static_cast<uint32_t>(fieldEntries.size()) - layout.fieldStart;
    }

    std::map<std::vector<uint8_t>, uint32_t, ByteVectorLess> defaultIndices;
    std::vector<std::vector<uint8_t>> defaults;
    for (FieldEntry &entry : fieldEntries) {
        if (!entry.field->hasDefault) {
            continue;
        }
        std::map<std::vector<uint8_t>, uint32_t, ByteVectorLess>::const_iterator
            it = defaultIndices.find(entry.field->defaultTlv);
        if (it == defaultIndices.end()) {
            defaults.push_back(entry.field->defaultTlv);
            const uint32_t index = static_cast<uint32_t>(defaults.size());
            defaultIndices[entry.field->defaultTlv] = index;
            entry.defaultIndex = index;
        } else {
            entry.defaultIndex = it->second;
        }
    }

    std::map<std::string, uint32_t> stringOffsets;
    uint32_t stringCursor = 1; /* 首字节 0x00 为哨兵 */
    for (const TypeNode *node : ordered) {
        if (stringOffsets.find(node->name) == stringOffsets.end()) {
            stringOffsets[node->name] = stringCursor;
            stringCursor +=
                static_cast<uint32_t>(node->name.size()) + 1u;
        }
    }
    for (const FieldEntry &entry : fieldEntries) {
        if (stringOffsets.find(entry.field->name) ==
            stringOffsets.end()) {
            stringOffsets[entry.field->name] = stringCursor;
            stringCursor +=
                static_cast<uint32_t>(entry.field->name.size()) + 1u;
        }
    }
    std::vector<NameEntry> nameEntries;
    for (const TypeNode *node : ordered) {
        if (node->namedValues.empty()) {
            continue;
        }
        const uint16_t kind = nameKindForNode(*node);
        if (kind == 2) {
            continue; /* 带标签的克隆类型：名称仍由基础类型拥有 */
        }
        for (const NamedValue &named : node->namedValues) {
            NameEntry entry;
            entry.typeId = node->id;
            entry.name = named.name;
            entry.kind = kind;
            entry.flags = kind == 1 && named.extension
                              ? kNameFlagExtension
                              : 0u;
            entry.value = named.value;
            nameEntries.push_back(entry);
        }
    }
    for (const NameEntry &entry : nameEntries) {
        if (stringOffsets.find(entry.name) == stringOffsets.end()) {
            stringOffsets[entry.name] = stringCursor;
            stringCursor += static_cast<uint32_t>(entry.name.size()) + 1u;
        }
    }
    const size_t stringPoolSize = static_cast<size_t>(stringCursor);

    size_t position = kHeaderSize;
    const size_t stringPoolOffset = align8(position);
    position = stringPoolOffset + stringPoolSize;
    const size_t typeTableOffset = align8(position);
    position = typeTableOffset + kTypeRecordSize * ordered.size();
    const size_t fieldTableOffset = align8(position);
    position = fieldTableOffset + kFieldRecordSize * fieldEntries.size();
    const size_t constraintTableOffset = align8(position);
    position =
        constraintTableOffset + kConstraintRecordSize * constraintEntries.size();
    const size_t defaultTableOffset = align8(position);
    position = defaultTableOffset + kDefaultRecordSize * defaults.size();

    const size_t defaultDataOffset = align8(position);
    std::vector<size_t> defaultOffsets(defaults.size());
    for (size_t i = 0; i < defaults.size(); ++i) {
        position = align8(position);
        defaultOffsets[i] = position;
        position += defaults[i].size();
    }

    position = align8(position);
    std::vector<size_t> enumOffsets(constraintEntries.size(), 0u);
    for (size_t i = 0; i < constraintEntries.size(); ++i) {
        const Constraint &constraint = *constraintEntries[i];
        if (constraint.kind != 2 || constraint.enumValues.empty()) {
            continue;
        }
        position = align8(position);
        enumOffsets[i] = position;
        position += 8u * constraint.enumValues.size();
    }
    /* 名称表追加在现有全部区间之后。 */
    position = align8(position);
    const size_t nameTableOffset = position;
    position = nameTableOffset + kNameRecordSize * nameEntries.size();
    const size_t totalSize = align8(position);
    (void)defaultDataOffset;

    std::vector<uint8_t> buffer(totalSize, 0u);

    /* 字符串池 */
    buffer[stringPoolOffset] = 0u;
    for (const std::pair<const std::string, uint32_t> &entry :
         stringOffsets) {
        const size_t at = stringPoolOffset + entry.second;
        std::memcpy(&buffer[at], entry.first.data(), entry.first.size());
        buffer[at + entry.first.size()] = 0u;
    }
    const uint32_t poolOffset32 = static_cast<uint32_t>(stringPoolOffset);

    /* 类型表 */
    for (size_t i = 0; i < ordered.size(); ++i) {
        const TypeNode &node = *ordered[i];
        const size_t record = typeTableOffset + i * kTypeRecordSize;
        const uint32_t nameOffset = poolOffset32 + stringOffsets[node.name];
        putU32(buffer, record, nameOffset);
        putU16(buffer, record + 4,
               static_cast<uint16_t>(node.kind));
        putU8(buffer, record + 6, node.tagMode);
        putU8(buffer, record + 7, static_cast<uint8_t>(node.flags));
        putU8(buffer, record + 8, node.tagClass);
        putU8(buffer, record + 9, 0u);
        putU16(buffer, record + 10, 0u);
        putU32(buffer, record + 12, node.tagNumber);
        const bool isOf = node.kind == TypeKind::SequenceOf ||
                          node.kind == TypeKind::SetOf;
        const uint32_t elementId =
            isOf && node.element != nullptr ? node.element->id : 0u;
        putU32(buffer, record + 16, elementId);
        putU32(buffer, record + 20, layouts[i].fieldStart);
        putU32(buffer, record + 24, layouts[i].fieldCount);
        putU32(buffer, record + 28, layouts[i].constraintStart);
        putU32(buffer, record + 32, layouts[i].constraintCount);
        putU32(buffer, record + 36, 0u);
        putU32(buffer, record + 40, 0u);
        putU32(buffer, record + 44, 0u);
    }

    /* 字段表 */
    for (size_t i = 0; i < fieldEntries.size(); ++i) {
        const FieldEntry &entry = fieldEntries[i];
        const size_t record = fieldTableOffset + i * kFieldRecordSize;
        const uint32_t nameOffset =
            poolOffset32 + stringOffsets[entry.field->name];
        putU32(buffer, record, nameOffset);
        putU32(buffer, record + 4, entry.typeId);
        uint32_t flags = 0;
        if ((entry.field->flags & 0x0001u) != 0) {
            flags |= kFieldFlagOptional;
        }
        if ((entry.field->flags & 0x0002u) != 0) {
            flags |= kFieldFlagExtension;
        }
        putU16(buffer, record + 8, static_cast<uint16_t>(flags));
        putU16(buffer, record + 10, 0u);
        putU32(buffer, record + 12, entry.defaultIndex);
        putU32(buffer, record + 16, entry.constraintStart);
        putU32(buffer, record + 20, entry.constraintCount);
        putU32(buffer, record + 24, 0u);
        putU32(buffer, record + 28, 0u);
    }

    /* 约束表 */
    for (size_t i = 0; i < constraintEntries.size(); ++i) {
        const Constraint &constraint = *constraintEntries[i];
        const size_t record = constraintTableOffset + i * kConstraintRecordSize;
        putU16(buffer, record, constraint.kind);
        uint16_t flags = 0;
        if (constraint.lowerUnbounded) {
            flags = static_cast<uint16_t>(flags | 0x0001u);
        }
        if (constraint.upperUnbounded) {
            flags = static_cast<uint16_t>(flags | 0x0002u);
        }
        putU16(buffer, record + 2, flags);
        const bool isEnum = constraint.kind == 2;
        putU32(buffer, record + 4,
               isEnum ? static_cast<uint32_t>(enumOffsets[i]) : 0u);
        putU32(buffer, record + 8,
               isEnum ? static_cast<uint32_t>(constraint.enumValues.size())
                      : 0u);
        putU32(buffer, record + 12, 0u);
        putU32(buffer, record + 16, 0u);
        putU32(buffer, record + 20, 0u);
        putU32(buffer, record + 24, 0u);
        putI64(buffer, record + 28, constraint.lower);
        putI64(buffer, record + 36, constraint.upper);
        putU32(buffer, record + 44, 0u);
    }

    /* 默认值表与数据 */
    for (size_t i = 0; i < defaults.size(); ++i) {
        const size_t record = defaultTableOffset + i * kDefaultRecordSize;
        putU32(buffer, record, static_cast<uint32_t>(defaultOffsets[i]));
        putU32(buffer, record + 4,
               static_cast<uint32_t>(defaults[i].size()));
        std::memcpy(&buffer[defaultOffsets[i]], defaults[i].data(),
                    defaults[i].size());
    }

    /* ENUM 取值数组（int64 小端） */
    for (size_t i = 0; i < constraintEntries.size(); ++i) {
        const Constraint &constraint = *constraintEntries[i];
        if (constraint.kind != 2 || constraint.enumValues.empty()) {
            continue;
        }
        for (size_t j = 0; j < constraint.enumValues.size(); ++j) {
            putI64(buffer, enumOffsets[i] + 8u * j,
                   constraint.enumValues[j]);
        }
    }

    /* 名称表 */
    for (size_t i = 0; i < nameEntries.size(); ++i) {
        const NameEntry &entry = nameEntries[i];
        const size_t record = nameTableOffset + i * kNameRecordSize;
        const uint32_t nameOffset =
            poolOffset32 + stringOffsets[entry.name];
        putU32(buffer, record, entry.typeId);
        putU32(buffer, record + 4, nameOffset);
        putU16(buffer, record + 8, entry.kind);
        putU16(buffer, record + 10, entry.flags);
        putU32(buffer, record + 12, 0u);
        putI64(buffer, record + 16, entry.value);
    }

    /* 文件头 */
    static const uint8_t kMagic[8] = {0x41u, 0x53u, 0x4Eu, 0x31u,
                                      0x53u, 0x43u, 0x48u, 0x1Au};
    std::memcpy(&buffer[0], kMagic, sizeof(kMagic));
    putU32(buffer, 8, UINT32_C(1) << 16);
    putU32(buffer, 12, static_cast<uint32_t>(kHeaderSize));
    putU32(buffer, 16, UINT32_C(0x01020304));
    putU32(buffer, 20, model.moduleTagMode);
    putU32(buffer, 24, 1u); /* flags：位 0 必须为 1 */
    putU32(buffer, 28, 1u); /* checksum_alg = CRC32C */
    putU64(buffer, 32, static_cast<uint64_t>(totalSize));
    putU32(buffer, 40, poolOffset32);
    putU32(buffer, 44, static_cast<uint32_t>(stringPoolSize));
    putU32(buffer, 48, static_cast<uint32_t>(typeTableOffset));
    putU32(buffer, 52, output.typeCount);
    putU32(buffer, 56, static_cast<uint32_t>(fieldTableOffset));
    putU32(buffer, 60, static_cast<uint32_t>(fieldEntries.size()));
    putU32(buffer, 64, static_cast<uint32_t>(constraintTableOffset));
    putU32(buffer, 68, static_cast<uint32_t>(constraintEntries.size()));
    putU32(buffer, 72, static_cast<uint32_t>(defaultTableOffset));
    putU32(buffer, 76, static_cast<uint32_t>(defaults.size()));
    putU32(buffer, 80, 0u);
    putU32(buffer, 84, 0u);
    putU32(buffer, 88, 0u);
    putU32(buffer, 92, 0u);
    putU32(buffer, 96, model.rootTypeId);
    putU32(buffer, 100,
           nameEntries.empty() ? 0u
                               : static_cast<uint32_t>(nameTableOffset));
    putU32(buffer, 104, static_cast<uint32_t>(nameEntries.size()));

    const uint32_t checksum =
        crc32c(buffer.data(), buffer.size(), 80u, 4u);
    putU32(buffer, 80, checksum);

    output.bytes = std::move(buffer);
    return output;
}

std::string renderCArray(const TableOutput &output)
{
    std::string text;
    text += "/* 由 asnberc 生成，请勿手工修改。 */\n";
    text += "#include <stddef.h>\n";
    text += "#include <stdint.h>\n\n";
    text += "const uint8_t " + output.symbol + "[] = {\n";
    for (size_t i = 0; i < output.bytes.size(); ++i) {
        if (i % 12u == 0u) {
            text += "    ";
        }
        char token[8];
        std::snprintf(token, sizeof(token), "0x%02X,",
                      static_cast<unsigned>(output.bytes[i]));
        text += token;
        if (i + 1u == output.bytes.size()) {
            text += '\n';
        } else if ((i + 1u) % 12u == 0u) {
            text += '\n';
        } else {
            text += ' ';
        }
    }
    text += "};\n\n";
    text += "const size_t " + output.sizeSymbol + " = sizeof(" +
            output.symbol + ");\n";
    return text;
}

} /* namespace asnberc */
