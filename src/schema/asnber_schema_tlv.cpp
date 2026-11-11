/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * schema 运行时注册：默认值 TLV 校验与标签展开。
 *
 * 职责：解析默认值 DER TLV（最短长度、无不定长、无尾随），并把类型树
 *       展开成有限标签集合供封存期 CHOICE 分支重叠检查。
 * 依赖：schema/asnber_schema.h。
 */

#include "schema/detail/schema_internal.h"

namespace asnber {
namespace schema_detail {

/* ===== 默认值 DER 校验 ===== */

bool parseTlv(const uint8_t *data, size_t limit, size_t *pos,
              uint32_t depth) noexcept;

bool parseTlvChildren(const uint8_t *data, size_t limit, size_t *pos,
                      uint32_t depth) noexcept
{
    while (*pos < limit) {
        if (!parseTlv(data, limit, pos, depth)) {
            return false;
        }
    }
    return true;
}

bool canonicalPrimitiveValue(uint32_t tagNumber, const uint8_t *content,
                             size_t size, bool constructed) noexcept
{
    switch (tagNumber) {
    case 0: /* EOC 不允许作为默认值内容 */
        return false;
    case 1: /* BOOLEAN */
        return !constructed && size == 1 &&
               (content[0] == 0x00 || content[0] == 0xFF);
    case 2: /* INTEGER */
    case 10: /* ENUMERATED */
        if (constructed || size == 0) {
            return false;
        }
        if (size >= 2) {
            if (content[0] == 0x00 && (content[1] & 0x80) == 0) {
                return false;
            }
            if (content[0] == 0xFF && (content[1] & 0x80) != 0) {
                return false;
            }
        }
        return true;
    case 3: { /* BIT STRING */
        if (constructed || size < 1) {
            return false;
        }
        const uint32_t unused = content[0];
        if (unused > 7) {
            return false;
        }
        if (unused != 0 && size >= 2) {
            const uint8_t mask =
                static_cast<uint8_t>((1u << unused) - 1u);
            if ((content[size - 1] & mask) != 0) {
                return false;
            }
        }
        return true;
    }
    case 4:  /* OCTET STRING */
    case 6:  /* OBJECT IDENTIFIER */
    case 7:  /* ObjectDescriptor */
    case 9:  /* REAL */
    case 12: /* UTF8String */
    case 13: /* RELATIVE-OID */
    case 14: /* TIME */
    case 18: /* NumericString */
    case 19: /* PrintableString */
    case 20: /* TeletexString */
    case 21: /* VideotexString */
    case 22: /* IA5String */
    case 23: /* UTCTime */
    case 24: /* GeneralizedTime */
    case 25: /* GraphicString */
    case 26: /* VisibleString */
    case 27: /* GeneralString */
    case 28: /* UniversalString */
    case 30: /* BMPString */
        return !constructed;
    case 5: /* NULL */
        return !constructed && size == 0;
    case 16: /* SEQUENCE */
    case 17: /* SET */
        return constructed;
    default:
        return true;
    }
}

bool parseTlv(const uint8_t *data, size_t limit, size_t *pos,
              uint32_t depth) noexcept
{
    if (depth > kSchemaMaxTagDepth || *pos >= limit) {
        return false;
    }

    const uint8_t first = data[(*pos)++];
    const uint32_t tagClass = static_cast<uint32_t>(first >> 6);
    const bool constructed = (first & 0x20u) != 0;
    uint32_t tagNumber = static_cast<uint32_t>(first & 0x1Fu);

    if (tagNumber == 0x1Fu) {
        tagNumber = 0;
        bool firstContinuation = true;
        while (true) {
            if (*pos >= limit) {
                return false;
            }
            const uint8_t b = data[(*pos)++];
            if (firstContinuation && b == 0x80) {
                return false;
            }
            firstContinuation = false;
            if (tagNumber > (UINT32_MAX >> 7)) {
                return false;
            }
            tagNumber = (tagNumber << 7) | static_cast<uint32_t>(b & 0x7Fu);
            if ((b & 0x80u) == 0) {
                break;
            }
        }
        if (tagNumber < 0x1Fu) {
            return false;
        }
    }

    if (*pos >= limit) {
        return false;
    }
    const uint8_t lengthFirst = data[(*pos)++];
    size_t contentSize = 0;
    if (lengthFirst < 0x80u) {
        contentSize = lengthFirst;
    } else {
        const uint32_t count = static_cast<uint32_t>(lengthFirst & 0x7Fu);
        if (count == 0 || count > sizeof(size_t)) {
            return false;
        }
        if (*pos + count > limit) {
            return false;
        }
        if (data[*pos] == 0x00) {
            return false;
        }
        for (uint32_t i = 0; i < count; ++i) {
            contentSize = (contentSize << 8) | data[(*pos)++];
        }
        if (contentSize < 0x80u) {
            return false;
        }
    }

    if (contentSize > limit - *pos) {
        return false;
    }
    const size_t contentStart = *pos;
    const size_t contentEnd = contentStart + contentSize;

    if (constructed) {
        size_t inner = contentStart;
        if (!parseTlvChildren(data, contentEnd, &inner, depth + 1)) {
            return false;
        }
        if (inner != contentEnd) {
            return false;
        }
    }

    if (tagClass == static_cast<uint32_t>(ASNBER_TAG_UNIVERSAL) &&
        !canonicalPrimitiveValue(tagNumber, data + contentStart, contentSize,
                                 constructed)) {
        return false;
    }

    *pos = contentEnd;
    return true;
}

/* ===== 标签展开 ===== */


bool tagSetAdd(TagSet *set, uint32_t tagClass, uint32_t tagNumber) noexcept
{
    for (uint32_t i = 0; i < set->count; ++i) {
        if (set->tags[i].tagClass == tagClass &&
            set->tags[i].tagNumber == tagNumber) {
            return true;
        }
    }
    if (set->count >= kSchemaMaxTagSet) {
        return false;
    }
    set->tags[set->count].tagClass = tagClass;
    set->tags[set->count].tagNumber = tagNumber;
    ++set->count;
    return true;
}

bool tagsIntersect(const TagSet &a, const TagSet &b) noexcept
{
    for (uint32_t i = 0; i < a.count; ++i) {
        for (uint32_t j = 0; j < b.count; ++j) {
            if (a.tags[i].tagClass == b.tags[j].tagClass &&
                a.tags[i].tagNumber == b.tags[j].tagNumber) {
                return true;
            }
        }
    }
    return false;
}

bool collectTags(const Schema &schema, uint32_t typeId, uint32_t depth,
                 TagSet *out) noexcept
{
    if (depth > kSchemaMaxTagDepth) {
        return false;
    }
    const SchemaType *type = findType(&schema, typeId);
    if (type == nullptr) {
        return false;
    }
    if (type->kind == static_cast<uint32_t>(ASNBER_TYPE_KIND_ANY)) {
        /* 无包装的 ANY 不承诺标签；EXPLICIT ANY 以确定的外层标签参与判定。 */
        if (type->tagMode == static_cast<uint32_t>(ASNBER_TAG_MODE_EXPLICIT)) {
            return tagSetAdd(out, type->tagClass, type->tagNumber);
        }
        return false;
    }

    const uint32_t choice = static_cast<uint32_t>(ASNBER_TYPE_KIND_CHOICE);
    const uint32_t universal = static_cast<uint32_t>(ASNBER_TAG_UNIVERSAL);
    const uint32_t defaultMode = static_cast<uint32_t>(ASNBER_TAG_MODE_DEFAULT);
    const uint32_t explicitMode = static_cast<uint32_t>(ASNBER_TAG_MODE_EXPLICIT);

    if (type->kind == choice) {
        if (type->tagMode == explicitMode) {
            return tagSetAdd(out, type->tagClass, type->tagNumber);
        }
        if (type->tagMode != defaultMode) {
            return false;
        }
        const uint32_t before = out->count;
        for (uint32_t i = 0; i < type->fieldCount; ++i) {
            if (!collectTags(schema, type->fields[i].typeId, depth + 1, out)) {
                return false;
            }
        }
        /* 分支全部无法给出标签相当于无可判定外层标签。 */
        return out->count > before;
    }

    uint32_t tagNumber = type->tagNumber;
    if (type->tagClass == universal) {
        if (tagNumber == 0) {
            if (type->kind == static_cast<uint32_t>(ASNBER_TYPE_KIND_SIMPLE)) {
                return false;
            }
            tagNumber =
                (type->kind ==
                     static_cast<uint32_t>(ASNBER_TYPE_KIND_SEQUENCE) ||
                 type->kind ==
                     static_cast<uint32_t>(ASNBER_TYPE_KIND_SEQUENCE_OF))
                    ? 16
                    : 17;
        }
    }
    return tagSetAdd(out, type->tagClass, tagNumber);
}

} /* namespace schema_detail */
} /* namespace asnber */

namespace asnber {

using namespace schema_detail;


bool schemaValidateDefaultTlv(const uint8_t *data, size_t size) noexcept
{
    if (data == nullptr || size == 0) {
        return false;
    }
    size_t pos = 0;
    if (!parseTlv(data, size, &pos, 0)) {
        return false;
    }
    return pos == size;
}

} /* namespace asnber */
