/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-cms 构造侧内部共享定义（模块私有）。
 *
 * 只允许 modules/cms 构造侧同一子系统的 cpp 包含；不对外暴露，也不进入
 * 安装产物。句柄结构与 CMS 专属形状规则集中在此；领域无关的单 TLV 校验、
 * 构树与描述表加载来自同目录的构造支撑头 module_builder_support.h。
 */

#ifndef ASNBER_CMS_BUILDER_INTERNAL_H_INCLUDED
#define ASNBER_CMS_BUILDER_INTERNAL_H_INCLUDED

#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include <asnber/asnber.h>
#include <asnber/cms/cms.h>

#include "detail/module_builder_support.h"

#include "../cms_tables.h"

/* 构造支撑的字节切片；CMS 句柄结构直接复用它。 */
using asnber::module_detail::byte_span;

struct alg_entry {
    char *oid;
    byte_span params;
};

struct signer_entry {
    int64_t version;
    int32_t sid_kind;
    byte_span sid1;
    byte_span sid2;
    char *digest_oid;
    byte_span digest_params;
    byte_span signed_attrs;
    char *signature_oid;
    byte_span signature_params;
    byte_span signature;
    byte_span unsigned_attrs;
};

/*
 * EnvelopedData 的一条 RecipientInfo。字段按分支复用：
 * - ktri：version/rid_kind/rid1/rid2/key_encryption_algorithm/encrypted_key
 * - kari：version/originator/ukm/recipient_encrypted_keys/key_encryption_algorithm
 * - kekri：version/kekid/key_encryption_algorithm/encrypted_key
 * - pwri：version/key_derivation_algorithm/key_encryption_algorithm/encrypted_key
 * - ori：ori_type/ori_value
 */
struct recipient_entry {
    int32_t kind;
    int64_t version;
    int32_t rid_kind;
    byte_span rid1;
    byte_span rid2;
    byte_span originator;
    byte_span ukm;
    byte_span recipient_encrypted_keys;
    byte_span kekid;
    byte_span key_derivation_algorithm;
    char *key_encryption_oid;
    byte_span key_encryption_params;
    byte_span encrypted_key;
    char *ori_type;
    byte_span ori_value;
};

/* 与 cms.h 的前向声明同名同域：内部状态对构造侧翻译单元可见。 */
struct asnber_cms_builder {
    asnber_ctx_t *ctx;
    bool version_set;
    int64_t version;
    alg_entry *digests;
    size_t digest_count;
    size_t digest_capacity;
    bool econtent_type_set;
    char *econtent_type;
    bool econtent_set;
    byte_span econtent;
    byte_span *certs;
    size_t cert_count;
    size_t cert_capacity;
    byte_span *crls;
    size_t crl_count;
    size_t crl_capacity;
    signer_entry *signers;
    size_t signer_count;
    size_t signer_capacity;
};

/* 与 cms.h 的前向声明同名同域：内部状态对构造侧翻译单元可见。 */
struct asnber_cms_enveloped_builder {
    asnber_ctx_t *ctx;
    bool version_set;
    int64_t version;
    bool originator_info_set;
    byte_span originator_info;
    recipient_entry *recipients;
    size_t recipient_count;
    size_t recipient_capacity;
    bool content_type_set;
    char *content_type;
    bool content_alg_set;
    char *content_alg_oid;
    byte_span content_alg_params;
    bool encrypted_content_set;
    byte_span encrypted_content;
    bool unprotected_attrs_set;
    byte_span unprotected_attrs; /* 已改写为 0xA1 */
};

/* 与 cms.h 的前向声明同名同域：内部状态对构造侧翻译单元可见。 */
struct asnber_cms_encrypted_builder {
    asnber_ctx_t *ctx;
    bool version_set;
    int64_t version;
    bool content_type_set;
    char *content_type;
    bool content_alg_set;
    char *content_alg_oid;
    byte_span content_alg_params;
    bool encrypted_content_set;
    byte_span encrypted_content;
    bool unprotected_attrs_set;
    byte_span unprotected_attrs; /* 已改写为 0xA1 */
};

/* 与 cms.h 的前向声明同名同域：内部状态对构造侧翻译单元可见。 */
struct asnber_cms_compressed_builder {
    asnber_ctx_t *ctx;
    bool version_set;
    int64_t version;
    bool compression_alg_set;
    char *compression_alg_oid;
    byte_span compression_alg_params;
    bool econtent_type_set;
    char *econtent_type;
    bool econtent_set;
    byte_span econtent;
};

/* 与 cms.h 的前向声明同名同域：内部状态对构造侧翻译单元可见。 */
struct asnber_cms_content_info_builder {
    asnber_ctx_t *ctx;
    bool content_type_set;
    char *content_type;
    bool content_set;
    bool content_is_octets;
    byte_span content; /* content_is_octets 时为原始字节，否则为完整 TLV。 */
};

/* 与 cms.h 的前向声明同名同域：内部状态对构造侧翻译单元可见。 */
struct asnber_cms_authenticated_builder {
    asnber_ctx_t *ctx;
    bool version_set;
    int64_t version;
    bool originator_info_set;
    byte_span originator_info;
    byte_span *recipients;
    size_t recipient_count;
    size_t recipient_capacity;
    bool mac_alg_set;
    char *mac_alg_oid;
    byte_span mac_alg_params;
    bool digest_alg_set;
    byte_span digest_alg;
    bool econtent_type_set;
    char *econtent_type;
    bool econtent_set;
    byte_span econtent;
    bool auth_attrs_set;
    byte_span auth_attrs; /* 已改写为 0xA2 */
    bool mac_set;
    byte_span mac;
    bool unauth_attrs_set;
    byte_span unauth_attrs; /* 已改写为 0xA3 */
};

namespace asnber_cms_detail {

/* 领域无关的构造设施统一从同目录构造支撑头引入，调用点保持不变。 */
using asnber::module_detail::addAlgorithmIdentifier;
using asnber::module_detail::appendSpan;
using asnber::module_detail::arraySize;
using asnber::module_detail::child_rule;
using asnber::module_detail::copyBytes;
using asnber::module_detail::copyText;
using asnber::module_detail::createIntegerNode;
using asnber::module_detail::createNode;
using asnber::module_detail::createOctetStringNode;
using asnber::module_detail::createOidNode;
using asnber::module_detail::der_root;
using asnber::module_detail::ensureCapacity;
using asnber::module_detail::freeSpans;
using asnber::module_detail::kPatternContext0Constructed;
using asnber::module_detail::kPatternContext1Constructed;
using asnber::module_detail::kPatternGeneralizedTime;
using asnber::module_detail::kPatternOctetString;
using asnber::module_detail::kPatternOid;
using asnber::module_detail::kPatternSequence;
using asnber::module_detail::kTagContext0;
using asnber::module_detail::kTagContext1;
using asnber::module_detail::kTagContext2;
using asnber::module_detail::kTagContext3;
using asnber::module_detail::kTagGeneralizedTime;
using asnber::module_detail::kTagInteger;
using asnber::module_detail::kTagOctetString;
using asnber::module_detail::kTagOid;
using asnber::module_detail::kTagSequence;
using asnber::module_detail::kTagSet;
using asnber::module_detail::rootMatches;
using asnber::module_detail::tag_pattern;
using asnber::module_detail::validateAndRewriteSet;
using asnber::module_detail::validateOid;
using asnber::module_detail::validateSingleDer;
using asnber::module_detail::validateSingleDerRoot;
using asnber::module_detail::validateTlvChildRules;

/*
 * id-signedData (…1.7.2) / id-envelopedData (…1.7.3) /
 * id-encryptedData (…1.7.6) / id-data (…1.7.1) /
 * id-ct-compressedData (…9.16.1.9) / id-ct-authData (…9.16.1.2)。
 */
constexpr const char *kSignedDataOid = "1.2.840.113549.1.7.2";
constexpr const char *kEnvelopedDataOid = "1.2.840.113549.1.7.3";
constexpr const char *kEncryptedDataOid = "1.2.840.113549.1.7.6";
constexpr const char *kDataOid = "1.2.840.113549.1.7.1";
constexpr const char *kCompressedDataOid = "1.2.840.113549.1.9.16.1.9";
constexpr const char *kAuthDataOid = "1.2.840.113549.1.9.16.1.2";

/* OriginatorIdentifierOrKey 的三支：issuerAndSerialNumber、SKI、originatorKey。 */
inline const tag_pattern kPatternOriginator[] = {
    {ASNBER_TAG_UNIVERSAL, kTagSequence, 1},
    {ASNBER_TAG_CONTEXT, kTagContext0, 0},
    {ASNBER_TAG_CONTEXT, kTagContext1, 1}};

/* KeyAgreeRecipientIdentifier 的两支：issuerAndSerialNumber、rKeyId。 */
inline const tag_pattern kPatternRecipientId[] = {
    {ASNBER_TAG_UNIVERSAL, kTagSequence, 1},
    {ASNBER_TAG_CONTEXT, kTagContext0, 1}};

/* OriginatorInfo ::= SEQUENCE { certs [0] OPTIONAL, crls [1] OPTIONAL }。 */
inline const child_rule kOriginatorInfoRules[] = {
    {kPatternContext0Constructed, 1, false, 0, 1, nullptr, 0},
    {kPatternContext1Constructed, 1, false, 0, 1, nullptr, 0},
};

/* originator [0] EXPLICIT OriginatorIdentifierOrKey：恰一个 CHOICE 分支。 */
inline const child_rule kOriginatorRules[] = {
    {kPatternOriginator, 3, false, 1, 1, nullptr, 0},
};

/* ukm [1] EXPLICIT UserKeyingMaterial：包一个 OCTET STRING。 */
inline const child_rule kUkmRules[] = {
    {kPatternOctetString, 1, false, 1, 1, nullptr, 0},
};

/* KEKIdentifier ::= SEQUENCE { keyIdentifier, date OPTIONAL, other OPTIONAL }。 */
inline const child_rule kKekIdentifierRules[] = {
    {kPatternOctetString, 1, false, 1, 1, nullptr, 0},
    {kPatternGeneralizedTime, 1, false, 0, 1, nullptr, 0},
    {kPatternSequence, 1, false, 0, 1, nullptr, 0},
};

/* keyDerivationAlgorithm [0] IMPLICIT AlgorithmIdentifier：OID + 可选 parameters。 */
inline const child_rule kKeyDerivationRules[] = {
    {kPatternOid, 1, false, 1, 1, nullptr, 0},
    {nullptr, 0, true, 0, 1, nullptr, 0},
};

/* RecipientEncryptedKey ::= SEQUENCE { rid, encryptedKey }。 */
inline const child_rule kRecipientEncryptedKeyRules[] = {
    {kPatternRecipientId, 2, false, 1, 1, nullptr, 0},
    {kPatternOctetString, 1, false, 1, 1, nullptr, 0},
};

/* RecipientEncryptedKeys ::= SEQUENCE OF RecipientEncryptedKey（RFC 允许空）。 */
inline const child_rule kRecipientEncryptedKeysRules[] = {
    {kPatternSequence, 1, false, 0, SIZE_MAX, kRecipientEncryptedKeyRules,
     arraySize(kRecipientEncryptedKeyRules)},
};

void freeSigner(signer_entry *signer);
void freeRecipient(recipient_entry *recipient);

/*
 * 描述表加载的 CMS 入口：cms_table_view 是模块内类型，共享层只接受
 * 表字节、长度与根类型编号。
 */
inline asnber_err_t loadTable(asnber_ctx_t *ctx, cms_table_view view,
                            uint32_t root_type_id, asnber_schema_t **out_schema)
{
    return asnber::module_detail::loadTable(ctx, view.data, view.size,
                                          root_type_id, out_schema);
}

asnber_err_t encodeExplicitWrapper(asnber_ctx_t *ctx, const uint8_t *inner,
                                 size_t inner_size, asnber_buf_t *out_buf);
asnber_err_t encodeContentInfo(asnber_ctx_t *ctx, const char *content_type_oid,
                             const uint8_t *content, size_t content_size,
                             asnber_buf_t *out_buf);

} /* namespace asnber_cms_detail */

#endif /* ASNBER_CMS_BUILDER_INTERNAL_H_INCLUDED */
