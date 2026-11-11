/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 模块共享构造支撑（源码级，不安装、不导出，ADR-0014 恢复）。
 *
 * CMS 的五个 builder 需要同一套“单 TLV 校验、子节点形状规则、基础构树、
 * 描述表加载”动作，后续 PKCS#8 等模块的 builder 复用同一套设施。这些动作
 * 只依赖核心公共 C ABI，不含任何具体结构定义；集中在此避免跨多个模块、
 * 多个翻译单元复制实现。
 *
 * 约束：
 * - 只允许模块构建单元包含；不得进入公共头或安装产物。
 * - 全部函数 `inline`，不产生新的导出符号；命名空间不带 `asnber_` 前缀。
 * - 这里只放领域无关的构造动作；句柄、结构体、OID 与具体形状规则留在
 *   各模块自己的内部头中。X.509 通用编码原语（Name/RDN、证书侧时间、
 *   BIT STRING）见同目录 x509_primitives.h。
 * - 不实现 DER SET/SET OF 排序：排序由核心 schema 感知编码完成。
 * - 大整数原语（createBigIntegerNode）也只做“无符号幅值 → 规范 DER
 *   INTEGER 内容”的编码，不做定宽/补码解释，不做模幂等数学运算。
 */

#ifndef ASNBER_MODULE_DETAIL_BUILDER_SUPPORT_H_INCLUDED
#define ASNBER_MODULE_DETAIL_BUILDER_SUPPORT_H_INCLUDED

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include <asnber/asnber.h>

namespace asnber {
namespace module_detail {

/* 字节切片：data 由 malloc 分配，size 为 0 时 data 为 nullptr。 */
struct byte_span {
    uint8_t *data;
    size_t size;
};

/* 用核心 DER 解码校验输入是恰好一个完整、规范的 DER TLV 时的根标签。 */
struct der_root {
    asnber_tag_class_t tag_class;
    uint32_t tag_number;
    int constructed;
};

/* 单个子节点的标签形状；constructed 为 -1 表示不检查构造位。 */
struct tag_pattern {
    asnber_tag_class_t tag_class;
    uint32_t tag_number;
    int constructed;
};

/*
 * 描述式校验：一个 child_rule 对应“按顺序出现的一组子节点”，组内每个
 * 子节点都要匹配 patterns 之一（any_tag 为真时匹配任意单 TLV），出现次数
 * 落在 [min_count, max_count]；nested_rules 用于校验组内元素（如
 * SEQUENCE OF 的每个元素）的内部形状。
 */
struct child_rule {
    const tag_pattern *patterns;
    size_t pattern_count;
    bool any_tag;
    size_t min_count;
    size_t max_count;
    const child_rule *nested_rules;
    size_t nested_rule_count;
};

/* 描述表格式版本（与核心 asnber_schema_table_t 契约一致）。 */
constexpr uint32_t kTableFormatVersion = 1u << 16;

constexpr uint32_t kTagSequence = 16;
constexpr uint32_t kTagSet = 17;
constexpr uint32_t kTagOid = 6;
constexpr uint32_t kTagInteger = 2;
constexpr uint32_t kTagOctetString = 4;
constexpr uint32_t kTagGeneralizedTime = 24;
constexpr uint32_t kTagContext0 = 0;
constexpr uint32_t kTagContext1 = 1;
constexpr uint32_t kTagContext2 = 2;
constexpr uint32_t kTagContext3 = 3;

/* 通用子结构形状规则。 */
inline const tag_pattern kPatternSequence[] = {
    {ASNBER_TAG_UNIVERSAL, kTagSequence, 1}};
inline const tag_pattern kPatternOctetString[] = {
    {ASNBER_TAG_UNIVERSAL, kTagOctetString, 0}};
inline const tag_pattern kPatternOid[] = {{ASNBER_TAG_UNIVERSAL, kTagOid, 0}};
inline const tag_pattern kPatternGeneralizedTime[] = {
    {ASNBER_TAG_UNIVERSAL, kTagGeneralizedTime, 0}};
inline const tag_pattern kPatternContext0Constructed[] = {
    {ASNBER_TAG_CONTEXT, kTagContext0, 1}};
inline const tag_pattern kPatternContext1Constructed[] = {
    {ASNBER_TAG_CONTEXT, kTagContext1, 1}};

template <typename T, size_t N>
constexpr size_t arraySize(const T (&)[N])
{
    return N;
}

/* 确保动态数组能容纳 count + 1 个元素；容量按 4/8/16… 增长。 */
template <typename T>
inline bool ensureCapacity(T **array, size_t count, size_t *capacity)
{
    if (count < *capacity) {
        return true;
    }
    const size_t next = *capacity == 0 ? 4 : *capacity * 2;
    if (next <= *capacity || next > SIZE_MAX / sizeof(T)) {
        return false;
    }
    void *grown = std::realloc(*array, next * sizeof(T));
    if (grown == nullptr) {
        return false;
    }
    *array = static_cast<T *>(grown);
    *capacity = next;
    return true;
}

inline uint8_t *copyBytes(const uint8_t *data, size_t size)
{
    if (size == 0) {
        return nullptr;
    }
    uint8_t *copy = static_cast<uint8_t *>(std::malloc(size));
    if (copy == nullptr) {
        return nullptr;
    }
    std::memcpy(copy, data, size);
    return copy;
}

inline char *copyText(const char *text)
{
    if (text == nullptr) {
        return nullptr;
    }
    const size_t length = std::strlen(text);
    if (length == SIZE_MAX) {
        return nullptr;
    }
    char *copy = static_cast<char *>(std::malloc(length + 1));
    if (copy == nullptr) {
        return nullptr;
    }
    std::memcpy(copy, text, length + 1);
    return copy;
}

/* 追加一个字节切片到动态数组；返回 false 表示分配失败。 */
inline bool appendSpan(byte_span **array, size_t *count, size_t *capacity,
                       const uint8_t *data, size_t size)
{
    if (!ensureCapacity(array, *count, capacity)) {
        return false;
    }
    uint8_t *copy = copyBytes(data, size);
    if (copy == nullptr) {
        return false;
    }
    (*array)[*count].data = copy;
    (*array)[*count].size = size;
    ++*count;
    return true;
}

inline void freeSpans(byte_span *array, size_t count)
{
    if (array == nullptr) {
        return;
    }
    for (size_t i = 0; i < count; ++i) {
        std::free(array[i].data);
    }
    std::free(array);
}

/* 校验输入是单个完整、规范的 DER TLV，并输出根标签。 */
inline asnber_err_t validateSingleDer(asnber_ctx_t *ctx, const uint8_t *tlv,
                                    size_t size, der_root *out_root)
{
    if (ctx == nullptr || tlv == nullptr || size == 0) {
        return ASNBER_E_INVALID_ARG;
    }

    asnber_decode_options_t options;
    asnber_decode_options_init(&options);
    options.encoding = ASNBER_ENCODING_DER;
    options.flags = ASNBER_DECODE_COPY_INPUT;

    asnber_doc_t *doc = nullptr;
    size_t consumed = 0;
    asnber_err_t rc =
        asnber_decode_buffer(ctx, tlv, size, &options, &doc, &consumed);
    if (rc != ASNBER_OK) {
        return rc;
    }
    if (consumed != size) {
        asnber_doc_destroy(doc);
        return ASNBER_E_TRAILING_DATA;
    }

    if (out_root != nullptr) {
        const asnber_node_t *root = asnber_doc_root(doc);
        out_root->tag_class = asnber_node_tag_class(root);
        out_root->tag_number = asnber_node_tag_number(root);
        out_root->constructed =
            asnber_node_encoding_form(root) == ASNBER_FORM_CONSTRUCTED ? 1 : 0;
    }
    asnber_doc_destroy(doc);
    return ASNBER_OK;
}

inline bool rootMatches(const der_root &root, asnber_tag_class_t tag_class,
                        uint32_t tag_number, int constructed)
{
    return root.tag_class == tag_class && root.tag_number == tag_number &&
           root.constructed == constructed;
}

/* 校验输入是单个规范 DER TLV，且根标签符合预期。 */
inline asnber_err_t validateSingleDerRoot(asnber_ctx_t *ctx, const uint8_t *tlv,
                                        size_t size,
                                        asnber_tag_class_t tag_class,
                                        uint32_t tag_number, int constructed)
{
    der_root root;
    asnber_err_t rc = validateSingleDer(ctx, tlv, size, &root);
    if (rc != ASNBER_OK) {
        return rc;
    }
    return rootMatches(root, tag_class, tag_number, constructed)
               ? ASNBER_OK
               : ASNBER_E_INVALID_VALUE;
}

/* 校验点分十进制 OID：借一次构树调用，保持与核心一致的判定。 */
inline asnber_err_t validateOid(asnber_ctx_t *ctx, const char *oid)
{
    if (ctx == nullptr || oid == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber_doc_t *doc = nullptr;
    asnber_err_t rc = asnber_doc_create(ctx, &doc);
    if (rc != ASNBER_OK) {
        return rc;
    }
    asnber_node_t *node = nullptr;
    rc = asnber_node_create(doc, nullptr, ASNBER_TAG_UNIVERSAL, kTagOid, 0, &node);
    if (rc == ASNBER_OK) {
        rc = asnber_node_set_oid(node, oid);
    }
    asnber_doc_destroy(doc);
    return rc;
}

/*
 * 校验输入为完整 SET OF Attribute，并把外层 0x31 改写成 rewrittenTag。
 * 属性集合按 SIZE (1..MAX) 处理，因此空集合与元素不是 SEQUENCE 的输入
 * 按结构错误拒绝。
 */
inline asnber_err_t validateAndRewriteSet(asnber_ctx_t *ctx, const uint8_t *tlv,
                                        size_t size, uint8_t rewrittenTag,
                                        byte_span *out)
{
    der_root root;
    asnber_err_t rc = validateSingleDer(ctx, tlv, size, &root);
    if (rc != ASNBER_OK) {
        return rc;
    }
    if (root.tag_class != ASNBER_TAG_UNIVERSAL || root.tag_number != kTagSet ||
        root.constructed == 0) {
        return ASNBER_E_INVALID_VALUE;
    }

    asnber_decode_options_t options;
    asnber_decode_options_init(&options);
    options.encoding = ASNBER_ENCODING_DER;
    options.flags = ASNBER_DECODE_COPY_INPUT;
    asnber_doc_t *doc = nullptr;
    size_t consumed = 0;
    rc = asnber_decode_buffer(ctx, tlv, size, &options, &doc, &consumed);
    if (rc != ASNBER_OK) {
        return rc;
    }
    const asnber_node_t *root_node = asnber_doc_root(doc);
    const size_t child_count = asnber_node_child_count(root_node);
    if (child_count == 0) {
        rc = ASNBER_E_INVALID_VALUE;
    }
    for (size_t i = 0; rc == ASNBER_OK && i < child_count; ++i) {
        const asnber_node_t *child = asnber_node_child_at(root_node, i);
        if (child == nullptr ||
            asnber_node_tag_class(child) != ASNBER_TAG_UNIVERSAL ||
            asnber_node_tag_number(child) != kTagSequence ||
            asnber_node_encoding_form(child) != ASNBER_FORM_CONSTRUCTED) {
            rc = ASNBER_E_INVALID_VALUE;
        }
    }
    asnber_doc_destroy(doc);
    if (rc != ASNBER_OK) {
        return rc;
    }

    uint8_t *copy = copyBytes(tlv, size);
    if (copy == nullptr) {
        return ASNBER_E_NOMEM;
    }
    copy[0] = rewrittenTag;
    out->data = copy;
    out->size = size;
    return ASNBER_OK;
}

inline bool nodeMatchesPattern(const asnber_node_t *node,
                               const tag_pattern &pattern)
{
    if (node == nullptr) {
        return false;
    }
    if (asnber_node_tag_class(node) != pattern.tag_class ||
        asnber_node_tag_number(node) != pattern.tag_number) {
        return false;
    }
    if (pattern.constructed >= 0) {
        const bool constructed =
            asnber_node_encoding_form(node) == ASNBER_FORM_CONSTRUCTED;
        if (constructed != (pattern.constructed != 0)) {
            return false;
        }
    }
    return true;
}

inline bool nodeMatchesRule(const asnber_node_t *node, const child_rule &rule)
{
    if (rule.any_tag) {
        return node != nullptr;
    }
    for (size_t i = 0; i < rule.pattern_count; ++i) {
        if (nodeMatchesPattern(node, rule.patterns[i])) {
            return true;
        }
    }
    return false;
}

inline asnber_err_t validateNodeChildRules(const asnber_node_t *parent,
                                         const child_rule *rules,
                                         size_t rule_count)
{
    const size_t child_count = asnber_node_child_count(parent);
    size_t index = 0;
    for (size_t r = 0; r < rule_count; ++r) {
        const child_rule &rule = rules[r];
        size_t matched = 0;
        while (matched < rule.max_count && index < child_count) {
            const asnber_node_t *child = asnber_node_child_at(parent, index);
            if (!nodeMatchesRule(child, rule)) {
                break;
            }
            if (rule.nested_rules != nullptr &&
                validateNodeChildRules(child, rule.nested_rules,
                                       rule.nested_rule_count) != ASNBER_OK) {
                return ASNBER_E_INVALID_VALUE;
            }
            ++index;
            ++matched;
        }
        if (matched < rule.min_count) {
            return ASNBER_E_INVALID_VALUE;
        }
    }
    return index == child_count ? ASNBER_OK : ASNBER_E_INVALID_VALUE;
}

/* 校验输入是单个规范 DER TLV，根标签匹配，且直接子节点符合 rules。 */
inline asnber_err_t validateTlvChildRules(asnber_ctx_t *ctx, const uint8_t *tlv,
                                        size_t size,
                                        asnber_tag_class_t tag_class,
                                        uint32_t tag_number, int constructed,
                                        const child_rule *rules,
                                        size_t rule_count)
{
    der_root root;
    asnber_err_t rc = validateSingleDer(ctx, tlv, size, &root);
    if (rc != ASNBER_OK) {
        return rc;
    }
    if (!rootMatches(root, tag_class, tag_number, constructed)) {
        return ASNBER_E_INVALID_VALUE;
    }

    asnber_decode_options_t options;
    asnber_decode_options_init(&options);
    options.encoding = ASNBER_ENCODING_DER;
    options.flags = ASNBER_DECODE_COPY_INPUT;
    asnber_doc_t *doc = nullptr;
    size_t consumed = 0;
    rc = asnber_decode_buffer(ctx, tlv, size, &options, &doc, &consumed);
    if (rc != ASNBER_OK) {
        return rc;
    }
    rc = validateNodeChildRules(asnber_doc_root(doc), rules, rule_count);
    asnber_doc_destroy(doc);
    return rc;
}

/*
 * 加载一张模块描述表：调用方给出表字节、长度与根类型编号（0 表示沿用
 * 表头默认根）。
 */
inline asnber_err_t loadTable(asnber_ctx_t *ctx, const uint8_t *data, size_t size,
                            uint32_t root_type_id, asnber_schema_t **out_schema)
{
    if (ctx == nullptr || data == nullptr || size == 0 ||
        out_schema == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber_schema_table_t table;
    table.struct_size = sizeof(table);
    table.data = data;
    table.size = size;
    table.format_version = kTableFormatVersion;
    table.reserved = 0;
    return asnber_schema_load_with_root(ctx, &table, root_type_id, out_schema);
}

/* ---------- 构树辅助 ---------- */

inline asnber_err_t createNode(asnber_doc_t *doc, asnber_node_t *parent,
                             uint32_t tag_class, uint32_t tag_number,
                             int constructed, asnber_node_t **out_node)
{
    return asnber_node_create(doc, parent, static_cast<asnber_tag_class_t>(tag_class),
                            tag_number, constructed, out_node);
}

inline asnber_err_t createOidNode(asnber_doc_t *doc, asnber_node_t *parent,
                                const char *oid, asnber_node_t **out_node)
{
    asnber_node_t *node = nullptr;
    asnber_err_t rc = createNode(doc, parent, ASNBER_TAG_UNIVERSAL, kTagOid, 0,
                               &node);
    if (rc != ASNBER_OK) {
        return rc;
    }
    rc = asnber_node_set_oid(node, oid);
    if (rc != ASNBER_OK) {
        return rc;
    }
    *out_node = node;
    return ASNBER_OK;
}

inline asnber_err_t createIntegerNode(asnber_doc_t *doc, asnber_node_t *parent,
                                    int64_t value, asnber_node_t **out_node)
{
    asnber_node_t *node = nullptr;
    asnber_err_t rc = createNode(doc, parent, ASNBER_TAG_UNIVERSAL, kTagInteger, 0,
                               &node);
    if (rc != ASNBER_OK) {
        return rc;
    }
    rc = asnber_node_set_int64(node, value);
    if (rc != ASNBER_OK) {
        return rc;
    }
    *out_node = node;
    return ASNBER_OK;
}

/*
 * 任意长度无符号 INTEGER 的上限（字节）。超过时返回 ASNBER_E_INPUT_LIMIT，
 * 避免调用方用超大输入触发不必要的大块分配。
 */
constexpr size_t kMaxBigIntegerBytes = 8192;

/*
 * 由大端无符号幅值（magnitude）追加一个规范 DER INTEGER 节点。
 *
 * 规范化规则（规整而非拒绝）：
 *   - magnitude == NULL 或 size == 0 返回 ASNBER_E_INVALID_ARG；
 *   - size > kMaxBigIntegerBytes 返回 ASNBER_E_INPUT_LIMIT；
 *   - 去掉冗余前导 0x00，取最小幅值；
 *   - 幅值全为 0 时内容为单字节 0x00；
 *   - 首个有效字节最高位为 1 时补一个前导 0x00，保证按正数解释；
 *   - 其余情况内容即最小幅值。
 *
 * 输出始终非空，满足 DER INTEGER 的最小长度要求。
 */
inline asnber_err_t createBigIntegerNode(asnber_doc_t *doc, asnber_node_t *parent,
                                       const uint8_t *magnitude, size_t size,
                                       asnber_node_t **out_node)
{
    if (doc == nullptr || magnitude == nullptr || size == 0) {
        return ASNBER_E_INVALID_ARG;
    }
    if (size > kMaxBigIntegerBytes) {
        return ASNBER_E_INPUT_LIMIT;
    }

    size_t first = 0;
    while (first < size && magnitude[first] == 0x00u) {
        ++first;
    }
    const size_t magnitude_size = size - first;

    asnber_node_t *node = nullptr;
    asnber_err_t rc = createNode(doc, parent, ASNBER_TAG_UNIVERSAL, kTagInteger, 0,
                               &node);
    if (rc != ASNBER_OK) {
        return rc;
    }

    if (magnitude_size == 0) {
        const uint8_t zero = 0x00u;
        rc = asnber_node_set_content(node, &zero, 1);
    } else if ((magnitude[first] & 0x80u) != 0) {
        /* 最高位为 1：补前导 0x00，避免被解释为负数。 */
        uint8_t *padded = static_cast<uint8_t *>(
            std::malloc(magnitude_size + 1));
        if (padded == nullptr) {
            return ASNBER_E_NOMEM;
        }
        padded[0] = 0x00u;
        std::memcpy(padded + 1, magnitude + first, magnitude_size);
        rc = asnber_node_set_content(node, padded, magnitude_size + 1);
        std::free(padded);
    } else {
        rc = asnber_node_set_content(node, magnitude + first, magnitude_size);
    }
    if (rc != ASNBER_OK) {
        return rc;
    }
    *out_node = node;
    return ASNBER_OK;
}

inline asnber_err_t createOctetStringNode(asnber_doc_t *doc, asnber_node_t *parent,
                                        const uint8_t *data, size_t size,
                                        asnber_node_t **out_node)
{
    asnber_node_t *node = nullptr;
    asnber_err_t rc = createNode(doc, parent, ASNBER_TAG_UNIVERSAL, kTagOctetString,
                               0, &node);
    if (rc != ASNBER_OK) {
        return rc;
    }
    rc = asnber_node_set_content(node, data, size);
    if (rc != ASNBER_OK) {
        return rc;
    }
    *out_node = node;
    return ASNBER_OK;
}

/* 追加 AlgorithmIdentifier: SEQUENCE { algorithm OID, parameters ANY OPTIONAL }。 */
inline asnber_err_t addAlgorithmIdentifier(asnber_doc_t *doc, asnber_node_t *parent,
                                         const char *oid,
                                         const byte_span &params)
{
    asnber_node_t *sequence = nullptr;
    asnber_err_t rc = createNode(doc, parent, ASNBER_TAG_UNIVERSAL, kTagSequence, 1,
                               &sequence);
    if (rc != ASNBER_OK) {
        return rc;
    }
    asnber_node_t *ignored = nullptr;
    rc = createOidNode(doc, sequence, oid, &ignored);
    if (rc != ASNBER_OK) {
        return rc;
    }
    if (params.size != 0) {
        rc = asnber_node_create_any(doc, sequence, params.data, params.size,
                                  &ignored);
    }
    return rc;
}

} /* namespace module_detail */
} /* namespace asnber */

#endif /* ASNBER_MODULE_DETAIL_BUILDER_SUPPORT_H_INCLUDED */
