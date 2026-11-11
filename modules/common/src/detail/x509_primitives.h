/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * X.509 通用编码原语（源码级，不安装、不导出，ADR-0014）。
 *
 * PKCS#10 与 PKIX 的 builder 都需要构造 Name/RDN、证书侧时间与 BIT STRING。
 * 这些动作只依赖核心公共 C ABI，与具体结构定义无关，集中在此避免在两个
 * 模块里各写一份。约束与 module_builder_support.h 相同：
 *
 * - 只允许模块构建单元包含；不得进入公共头或安装产物。
 * - 全部函数 `inline`，不产生新的导出符号。
 * - 不实现 DER SET/SET OF 排序：RDN 内部顺序交给核心 schema 感知编码。
 * - 不做时区归一：只接受可精确写成证书 `Z` 形式的时间。
 */

#ifndef ASNBER_MODULE_DETAIL_X509_PRIMITIVES_H_INCLUDED
#define ASNBER_MODULE_DETAIL_X509_PRIMITIVES_H_INCLUDED

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include <asnber/asnber.h>

#include "module_builder_support.h"

namespace asnber {
namespace module_detail {

constexpr uint32_t kTagBoolean = 1;
constexpr uint32_t kTagBitString = 3;
constexpr uint32_t kTagUtf8String = 12;
constexpr uint32_t kTagPrintableString = 19;
constexpr uint32_t kTagIa5String = 22;
constexpr uint32_t kTagUtcTime = 23;

/* 单字节通用标签 + 内容的 DER 头长度。 */
inline size_t derHeaderSize(size_t content_size)
{
    if (content_size < 0x80) {
        return 2;
    }
    size_t bytes = 0;
    for (size_t value = content_size; value != 0; value >>= 8) {
        ++bytes;
    }
    return 2 + bytes;
}

inline void writeDerHeader(uint8_t *dst, uint8_t tag, size_t content_size)
{
    dst[0] = tag;
    if (content_size < 0x80) {
        dst[1] = static_cast<uint8_t>(content_size);
        return;
    }
    size_t bytes = 0;
    for (size_t value = content_size; value != 0; value >>= 8) {
        ++bytes;
    }
    dst[1] = static_cast<uint8_t>(0x80 | bytes);
    for (size_t i = 0; i < bytes; ++i) {
        dst[2 + i] =
            static_cast<uint8_t>(content_size >> (8 * (bytes - 1 - i)));
    }
}

/*
 * 用完整 TLV 创建 ANY 子节点。
 *
 * 开放类型字段（如 AttributeTypeAndValue.value）在 schema 感知编码下只有
 * ANY 节点会原样写回；运行期普通节点没有输入切片，无法在非 EXPLICIT 模式
 * 写出。tag 只支持单字节通用标签（<= 30）。
 */
inline asnber_err_t createTlvAnyNode(asnber_doc_t *doc, asnber_node_t *parent,
                                   uint32_t tag, const uint8_t *content,
                                   size_t content_size,
                                   asnber_node_t **out_node)
{
    if (doc == nullptr || out_node == nullptr || tag > 30 ||
        (content == nullptr && content_size != 0)) {
        return ASNBER_E_INVALID_ARG;
    }
    const size_t header = derHeaderSize(content_size);
    const size_t total = header + content_size;
    uint8_t *tlv = static_cast<uint8_t *>(std::malloc(total));
    if (tlv == nullptr) {
        return ASNBER_E_NOMEM;
    }
    writeDerHeader(tlv, static_cast<uint8_t>(tag), content_size);
    if (content_size != 0) {
        std::memcpy(tlv + header, content, content_size);
    }
    asnber_err_t rc = asnber_node_create_any(doc, parent, tlv, total, out_node);
    std::free(tlv);
    return rc;
}

/* ---------- Name / RDN ---------- */

/*
 * 字符串类型选择规则（OpenSSL 3.5.9 asn1parse 实测）：
 * - countryName / serialNumber / dnQualifier -> PrintableString；
 * - domainComponent / emailAddress -> IA5String；
 * - 其余属性 -> UTF8String。
 */
inline uint32_t selectNameStringTag(const char *oid)
{
    if (oid == nullptr) {
        return 0;
    }
    if (std::strcmp(oid, "2.5.4.6") == 0 || std::strcmp(oid, "2.5.4.5") == 0 ||
        std::strcmp(oid, "2.5.4.46") == 0) {
        return kTagPrintableString;
    }
    if (std::strcmp(oid, "0.9.2342.19200300.100.1.25") == 0 ||
        std::strcmp(oid, "1.2.840.113549.1.9.1") == 0) {
        return kTagIa5String;
    }
    return kTagUtf8String;
}

/* PrintableString 字符集：字母、数字、空格与 '()+,-./:=? 。 */
inline bool isPrintableStringByte(uint8_t c)
{
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
        (c >= '0' && c <= '9')) {
        return true;
    }
    switch (c) {
    case ' ':
    case '\'':
    case '(':
    case ')':
    case '+':
    case ',':
    case '-':
    case '.':
    case '/':
    case ':':
    case '=':
    case '?':
        return true;
    default:
        return false;
    }
}

inline bool nameStringValid(uint32_t tag, const uint8_t *data, size_t size)
{
    if (size == 0) {
        return false;
    }
    if (tag == kTagIa5String) {
        for (size_t i = 0; i < size; ++i) {
            if (data[i] > 0x7F) {
                return false;
            }
        }
        return true;
    }
    if (tag == kTagPrintableString) {
        for (size_t i = 0; i < size; ++i) {
            if (!isPrintableStringByte(data[i])) {
                return false;
            }
        }
        return true;
    }
    /* UTF8String：只要求非空，字符集边界与 asnber_node_set_utf8 一致。 */
    return tag == kTagUtf8String;
}

/*
 * 一个 RDN 属性。string_tag 为 0 时按 OID 选择，否则必须显式给出
 * 12/19/22 之一。
 */
struct name_attribute {
    const char *oid;
    const uint8_t *value;
    size_t value_size;
    uint32_t string_tag;
};

/* 一个 RelativeDistinguishedName；count 必须 >= 1。 */
struct name_rdn {
    const name_attribute *attributes;
    size_t count;
};

/*
 * 追加 AttributeTypeAndValue：SEQUENCE { type OID, value ANY }。
 * value 以完整字符串 TLV 的 ANY 形式承载。
 */
inline asnber_err_t createNameValueNode(asnber_doc_t *doc, asnber_node_t *parent,
                                      const name_attribute &attribute,
                                      asnber_node_t **out_node)
{
    if (doc == nullptr || out_node == nullptr || attribute.oid == nullptr ||
        (attribute.value == nullptr && attribute.value_size != 0)) {
        return ASNBER_E_INVALID_ARG;
    }
    const uint32_t string_tag = attribute.string_tag == 0
                                    ? selectNameStringTag(attribute.oid)
                                    : attribute.string_tag;
    if (string_tag != kTagUtf8String &&
        string_tag != kTagPrintableString && string_tag != kTagIa5String) {
        return ASNBER_E_INVALID_ARG;
    }
    if (!nameStringValid(string_tag, attribute.value, attribute.value_size)) {
        return ASNBER_E_INVALID_VALUE;
    }

    asnber_node_t *sequence = nullptr;
    asnber_err_t rc = createNode(doc, parent, ASNBER_TAG_UNIVERSAL, kTagSequence, 1,
                               &sequence);
    if (rc != ASNBER_OK) {
        return rc;
    }

    asnber_node_t *type = nullptr;
    rc = createNode(doc, sequence, ASNBER_TAG_UNIVERSAL, kTagOid, 0, &type);
    if (rc == ASNBER_OK) {
        rc = asnber_node_set_oid(type, attribute.oid);
    }
    if (rc != ASNBER_OK) {
        return rc;
    }

    asnber_node_t *value = nullptr;
    rc = createTlvAnyNode(doc, sequence, string_tag, attribute.value,
                          attribute.value_size, &value);
    if (rc != ASNBER_OK) {
        return rc;
    }
    *out_node = sequence;
    return ASNBER_OK;
}

/*
 * 追加 Name：SEQUENCE OF RelativeDistinguishedName。
 *
 * RDN 之间的顺序保持调用方数组顺序；RDN 内部属性顺序不做排序，最终 SET OF
 * 字节序由核心 DER 编码完成。rdn_count 为 0 时产出空 RDNSequence。
 */
inline asnber_err_t createNameNode(asnber_doc_t *doc, asnber_node_t *parent,
                                 const name_rdn *rdns, size_t rdn_count,
                                 asnber_node_t **out_node)
{
    if (doc == nullptr || out_node == nullptr ||
        (rdns == nullptr && rdn_count != 0)) {
        return ASNBER_E_INVALID_ARG;
    }

    asnber_node_t *name = nullptr;
    asnber_err_t rc = createNode(doc, parent, ASNBER_TAG_UNIVERSAL, kTagSequence, 1,
                               &name);
    if (rc != ASNBER_OK) {
        return rc;
    }

    for (size_t i = 0; i < rdn_count; ++i) {
        if (rdns[i].attributes == nullptr || rdns[i].count == 0) {
            return ASNBER_E_INVALID_ARG;
        }
        asnber_node_t *rdn = nullptr;
        rc = createNode(doc, name, ASNBER_TAG_UNIVERSAL, kTagSet, 1, &rdn);
        if (rc != ASNBER_OK) {
            return rc;
        }
        for (size_t j = 0; j < rdns[i].count; ++j) {
            asnber_node_t *ignored = nullptr;
            rc = createNameValueNode(doc, rdn, rdns[i].attributes[j], &ignored);
            if (rc != ASNBER_OK) {
                return rc;
            }
        }
    }
    *out_node = name;
    return ASNBER_OK;
}

/* ---------- 时间 ---------- */

inline bool isLeapYear(int32_t year)
{
    return (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
}

inline uint8_t daysInMonth(int32_t year, uint8_t month)
{
    static const uint8_t kDays[12] = {31, 28, 31, 30, 31, 30,
                                      31, 31, 30, 31, 30, 31};
    if (month == 2 && isLeapYear(year)) {
        return 29;
    }
    return kDays[month - 1];
}

inline void writeTwoDigits(uint8_t *dst, uint32_t value)
{
    dst[0] = static_cast<uint8_t>('0' + (value / 10) % 10);
    dst[1] = static_cast<uint8_t>('0' + value % 10);
}

inline void writeFourDigits(uint8_t *dst, uint32_t value)
{
    dst[0] = static_cast<uint8_t>('0' + (value / 1000) % 10);
    dst[1] = static_cast<uint8_t>('0' + (value / 100) % 10);
    dst[2] = static_cast<uint8_t>('0' + (value / 10) % 10);
    dst[3] = static_cast<uint8_t>('0' + value % 10);
}

/* 只校验时间结构，不依赖文档；createTimeNode 与 builder 的 set 阶段共用。 */
inline asnber_err_t validateTime(const asnber_time_t *time)
{
    if (time == nullptr || time->struct_size != sizeof(asnber_time_t) ||
        time->reserved_flags != 0) {
        return ASNBER_E_INVALID_ARG;
    }
    if ((time->flags & (ASNBER_TIME_HAS_OFFSET | ASNBER_TIME_LOCAL |
                        ASNBER_TIME_FRACTIONAL)) != 0) {
        return ASNBER_E_INVALID_VALUE;
    }
    if (time->year < 0 || time->year > 9999 || time->month < 1 ||
        time->month > 12) {
        return ASNBER_E_INVALID_VALUE;
    }
    if (time->day < 1 ||
        time->day > daysInMonth(time->year, time->month) ||
        time->hour > 23 || time->minute > 59 || time->second > 59) {
        return ASNBER_E_INVALID_VALUE;
    }
    return ASNBER_OK;
}

/*
 * 追加证书侧 Time：
 * - 1950..2049 -> UTCTime（YYMMDDHHMMSSZ）；
 * - 其余年份 -> GeneralizedTime（YYYYMMDDHHMMSSZ）。
 *
 * 只接受可精确表示的输入：不再做时区归一，带偏移/本地时间/小数秒的输入
 * 直接拒绝。ASNBER_TIME_UTC / GENERALIZED 仅作来源提示，不影响选择。
 */
inline asnber_err_t createTimeNode(asnber_doc_t *doc, asnber_node_t *parent,
                                 const asnber_time_t *time,
                                 asnber_node_t **out_node)
{
    if (doc == nullptr || out_node == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber_err_t rc = validateTime(time);
    if (rc != ASNBER_OK) {
        return rc;
    }

    const bool utc = time->year >= 1950 && time->year <= 2049;
    uint8_t text[15];
    size_t size = 0;
    if (utc) {
        writeTwoDigits(text, static_cast<uint32_t>(time->year % 100));
        size = 2;
    } else {
        writeFourDigits(text, static_cast<uint32_t>(time->year));
        size = 4;
    }
    writeTwoDigits(text + size, time->month);
    writeTwoDigits(text + size + 2, time->day);
    writeTwoDigits(text + size + 4, time->hour);
    writeTwoDigits(text + size + 6, time->minute);
    writeTwoDigits(text + size + 8, time->second);
    size += 10;
    text[size++] = 'Z';

    asnber_node_t *node = nullptr;
    rc = createNode(doc, parent, ASNBER_TAG_UNIVERSAL,
                    utc ? kTagUtcTime : kTagGeneralizedTime, 0, &node);
    if (rc != ASNBER_OK) {
        return rc;
    }
    rc = asnber_node_set_content(node, text, size);
    if (rc != ASNBER_OK) {
        return rc;
    }
    *out_node = node;
    return ASNBER_OK;
}

/* ---------- BIT STRING ---------- */

/*
 * BIT STRING 输入校验：
 * - data 为空但长度非 0、unused_bits > 7、空位串带未用位 -> INVALID_ARG；
 * - 非空且末字节填充位非零 -> INVALID_VALUE。
 */
inline asnber_err_t validateBitString(const uint8_t *bits, size_t size,
                                    uint8_t unused_bits)
{
    if ((bits == nullptr && size != 0) || unused_bits > 7) {
        return ASNBER_E_INVALID_ARG;
    }
    if (size == 0) {
        return unused_bits == 0 ? ASNBER_OK : ASNBER_E_INVALID_ARG;
    }
    if (unused_bits != 0) {
        const uint8_t mask = static_cast<uint8_t>((1u << unused_bits) - 1u);
        if ((bits[size - 1] & mask) != 0) {
            return ASNBER_E_INVALID_VALUE;
        }
    }
    return ASNBER_OK;
}

/* 追加 BOOLEAN；DER 真值为 0xFF。 */
inline asnber_err_t createBooleanNode(asnber_doc_t *doc, asnber_node_t *parent,
                                    bool value, asnber_node_t **out_node)
{
    if (doc == nullptr || out_node == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber_node_t *node = nullptr;
    asnber_err_t rc = createNode(doc, parent, ASNBER_TAG_UNIVERSAL, kTagBoolean, 0,
                               &node);
    if (rc != ASNBER_OK) {
        return rc;
    }
    const uint8_t content = value ? 0xFF : 0x00;
    rc = asnber_node_set_content(node, &content, 1);
    if (rc != ASNBER_OK) {
        return rc;
    }
    *out_node = node;
    return ASNBER_OK;
}

/*
 * 追加 BIT STRING：内容首字节记录未用位数。
 *
 * - 空位串必须 unused_bits == 0，内容为单字节 0x00；
 * - 非空且 unused_bits > 0 时，末字节对应的填充位必须为零（DER 规范），
 *   否则拒绝而不是静默清零，未用位属于调用方语义。
 */
inline asnber_err_t createBitStringNodeImpl(asnber_doc_t *doc, asnber_node_t *parent,
                                          uint8_t tag_class, uint32_t tag_number,
                                          const uint8_t *bits, size_t size,
                                          uint8_t unused_bits,
                                          asnber_node_t **out_node)
{
    if (doc == nullptr || out_node == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber_err_t rc = validateBitString(bits, size, unused_bits);
    if (rc != ASNBER_OK) {
        return rc;
    }
    if (size == 0) {
        asnber_node_t *node = nullptr;
        rc = createNode(doc, parent, tag_class, tag_number, 0, &node);
        if (rc != ASNBER_OK) {
            return rc;
        }
        const uint8_t empty = 0;
        rc = asnber_node_set_content(node, &empty, 1);
        if (rc != ASNBER_OK) {
            return rc;
        }
        *out_node = node;
        return ASNBER_OK;
    }

    uint8_t *content = static_cast<uint8_t *>(std::malloc(size + 1));
    if (content == nullptr) {
        return ASNBER_E_NOMEM;
    }
    content[0] = unused_bits;
    std::memcpy(content + 1, bits, size);

    asnber_node_t *node = nullptr;
    rc = createNode(doc, parent, tag_class, tag_number, 0, &node);
    if (rc == ASNBER_OK) {
        rc = asnber_node_set_content(node, content, size + 1);
    }
    std::free(content);
    if (rc != ASNBER_OK) {
        return rc;
    }
    *out_node = node;
    return ASNBER_OK;
}

inline asnber_err_t createBitStringNode(asnber_doc_t *doc, asnber_node_t *parent,
                                      const uint8_t *bits, size_t size,
                                      uint8_t unused_bits,
                                      asnber_node_t **out_node)
{
    return createBitStringNodeImpl(doc, parent, ASNBER_TAG_UNIVERSAL,
                                   kTagBitString, bits, size, unused_bits,
                                   out_node);
}

/* TBSCertificate 的 issuerUniqueID / subjectUniqueID：[n] IMPLICIT BIT STRING。 */
inline asnber_err_t createImplicitBitStringNode(asnber_doc_t *doc,
                                              asnber_node_t *parent,
                                              uint32_t tag_number,
                                              const uint8_t *bits, size_t size,
                                              uint8_t unused_bits,
                                              asnber_node_t **out_node)
{
    return createBitStringNodeImpl(doc, parent, ASNBER_TAG_CONTEXT, tag_number,
                                   bits, size, unused_bits, out_node);
}

/* ---------- Extension / Extensions ---------- */

/*
 * 一条扩展。critical == false 时完全省略 BOOLEAN（DEFAULT FALSE）；
 * value 是 extnValue OCTET STRING 的内容（内层 DER TLV），本层不解析。
 */
struct extension_entry {
    const char *oid;
    bool critical;
    const uint8_t *value;
    size_t value_size;
};

/* 追加 Extension ::= SEQUENCE { extnID, critical DEFAULT FALSE, extnValue }。 */
inline asnber_err_t createExtensionNode(asnber_doc_t *doc, asnber_node_t *parent,
                                      const extension_entry &ext,
                                      asnber_node_t **out_node)
{
    if (doc == nullptr || out_node == nullptr || ext.oid == nullptr ||
        ext.value == nullptr || ext.value_size == 0) {
        return ASNBER_E_INVALID_ARG;
    }

    asnber_node_t *extension = nullptr;
    asnber_err_t rc = createNode(doc, parent, ASNBER_TAG_UNIVERSAL, kTagSequence, 1,
                               &extension);
    if (rc != ASNBER_OK) {
        return rc;
    }
    asnber_node_t *type = nullptr;
    rc = createNode(doc, extension, ASNBER_TAG_UNIVERSAL, kTagOid, 0, &type);
    if (rc == ASNBER_OK) {
        rc = asnber_node_set_oid(type, ext.oid);
    }
    if (rc == ASNBER_OK && ext.critical) {
        asnber_node_t *critical = nullptr;
        rc = createBooleanNode(doc, extension, true, &critical);
    }
    if (rc == ASNBER_OK) {
        asnber_node_t *value = nullptr;
        rc = createOctetStringNode(doc, extension, ext.value, ext.value_size,
                                   &value);
    }
    if (rc != ASNBER_OK) {
        return rc;
    }
    *out_node = extension;
    return ASNBER_OK;
}

/*
 * 追加 Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension。
 * 同一集合内扩展 OID 不得重复，重复返回 ASNBER_E_INVALID_VALUE。
 */
inline asnber_err_t createExtensionsNode(asnber_doc_t *doc, asnber_node_t *parent,
                                       const extension_entry *exts,
                                       size_t count, asnber_node_t **out_node)
{
    if (doc == nullptr || out_node == nullptr || exts == nullptr ||
        count == 0) {
        return ASNBER_E_INVALID_ARG;
    }
    for (size_t i = 0; i < count; ++i) {
        if (exts[i].oid == nullptr) {
            return ASNBER_E_INVALID_ARG;
        }
        for (size_t j = i + 1; j < count; ++j) {
            if (exts[j].oid != nullptr &&
                std::strcmp(exts[i].oid, exts[j].oid) == 0) {
                return ASNBER_E_INVALID_VALUE;
            }
        }
    }

    asnber_node_t *extensions = nullptr;
    asnber_err_t rc = createNode(doc, parent, ASNBER_TAG_UNIVERSAL, kTagSequence, 1,
                               &extensions);
    if (rc != ASNBER_OK) {
        return rc;
    }
    for (size_t i = 0; i < count; ++i) {
        asnber_node_t *ignored = nullptr;
        rc = createExtensionNode(doc, extensions, exts[i], &ignored);
        if (rc != ASNBER_OK) {
            return rc;
        }
    }
    *out_node = extensions;
    return ASNBER_OK;
}

/* 把 Extensions 编成独立 DER TLV（供 extensionRequest 的 ANY 值使用）。 */
inline asnber_err_t encodeExtensions(asnber_ctx_t *ctx,
                                   const extension_entry *exts, size_t count,
                                   asnber_buf_t *out)
{
    if (ctx == nullptr || out == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    out->data = nullptr;
    out->size = 0;
    out->capacity = 0;

    asnber_doc_t *doc = nullptr;
    asnber_err_t rc = asnber_doc_create(ctx, &doc);
    if (rc != ASNBER_OK) {
        return rc;
    }
    asnber_node_t *node = nullptr;
    rc = createExtensionsNode(doc, nullptr, exts, count, &node);
    if (rc == ASNBER_OK) {
        rc = asnber_doc_seal(doc);
    }
    if (rc == ASNBER_OK) {
        asnber_encode_options_t options;
        asnber_encode_options_init(&options);
        rc = asnber_encode_buffer(ctx, doc, &options, out);
    }
    asnber_doc_destroy(doc);
    return rc;
}

} /* namespace module_detail */
} /* namespace asnber */

#endif /* ASNBER_MODULE_DETAIL_X509_PRIMITIVES_H_INCLUDED */
