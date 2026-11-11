/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * asnber-cms 只读结构访问与构造：AuthenticatedData（RFC 5652 第 9 节）。
 * 本结构没有外部生成器样本：用例基于手工构造的 DER，以及三份由脚本
 * 固定写出的**合成样本**（不是外部实现产物）：
 * `cms_authenticated_data.der`（主样本，version 0 的干净形态，不含
 * `originatorInfo`）、`cms_authenticated_data_v1.der`（version 1，
 * `originatorInfo` 只含 `certs [0]`）、`cms_authenticated_data_v3.der`
 * （version 3，`certs [0]` + 最小合法 `crls [1]`）。证书取
 * `tests/data/cert_rsa_selfsigned.der`——一份合成自签证书，不是生产证书。
 * 覆盖最小形态、完整形态（digestAlgorithm/authAttrs + unauthAttrs）、
 * version 1/3、两种 RecipientInfo 分支、originatorInfo 的 certs/crls 组合，
 * 以及参数/状态/边界负例。open 不校验 MAC，不展开 RecipientInfo 分支内部字段。
 */

#include <asnber/asnber.h>
#include <asnber/cms/cms.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../data/cert_rsa_selfsigned.h"
#include "../data/cms_authenticated_data.h"
#include "../data/cms_authenticated_data_v1.h"
#include "../data/cms_authenticated_data_v3.h"
#include "check.h"
#include "test_compare.h"

static const char kAuthDataOid[] = "1.2.840.113549.1.9.16.1.2";
static const char kDataOid[] = "1.2.840.113549.1.7.1";
static const char kHmacSha256Oid[] = "1.2.840.113549.2.9";
static const char kSha256Oid[] = "2.16.840.1.101.3.4.2.1";

/*
 * RecipientInfo：ktri
 *   SEQUENCE {
 *     version 0,
 *     issuerAndSerialNumber { CN=test, 1 },
 *     AlgorithmIdentifier { rsaEncryption },
 *     encryptedKey 01020304 }
 */
static const uint8_t kKtri[] = {
    0x30, 0x2C, 0x02, 0x01, 0x00, 0x30, 0x14, 0x30, 0x0F, 0x31, 0x0D, 0x30,
    0x0B, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x04, 0x74, 0x65, 0x73, 0x74,
    0x02, 0x01, 0x01, 0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7,
    0x0D, 0x01, 0x01, 0x01, 0x04, 0x04, 0x01, 0x02, 0x03, 0x04,
};

/*
 * RecipientInfo：kekri
 *   [2] IMPLICIT SEQUENCE {
 *     version 0,
 *     kekid { keyIdentifier 0102030405060708 },
 *     AlgorithmIdentifier { id-aes256-wrap },
 *     encryptedKey AABBCCDD }
 */
static const uint8_t kKekri[] = {
    0xA2, 0x22, 0x02, 0x01, 0x00, 0x30, 0x0A, 0x04, 0x08, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07, 0x08, 0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48,
    0x01, 0x65, 0x03, 0x04, 0x01, 0x2D, 0x04, 0x04, 0xAA, 0xBB, 0xCC, 0xDD,
};

/* Attribute { 1.2.3.4, SET { INTEGER 1 } }，SET OF 的输入形态为 0x31。 */
static const uint8_t kAttrs[] = {
    0x31, 0x0C, 0x30, 0x0A, 0x06, 0x03, 0x2A,
    0x03, 0x04, 0x31, 0x03, 0x02, 0x01, 0x01,
};

/* 最小形态：version 0 + 一条 ktri + hmacWithSHA256 + id-data + mac。 */
static const uint8_t kMinimalInner[] = {
    0x30, 0x52, 0x02, 0x01, 0x00, 0x31, 0x2E, 0x30, 0x2C, 0x02, 0x01, 0x00,
    0x30, 0x14, 0x30, 0x0F, 0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0C, 0x04, 0x74, 0x65, 0x73, 0x74, 0x02, 0x01, 0x01, 0x30, 0x0B,
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x04,
    0x04, 0x01, 0x02, 0x03, 0x04, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48,
    0x86, 0xF7, 0x0D, 0x02, 0x09, 0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48,
    0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01, 0x04, 0x04, 0x11, 0x22, 0x33, 0x44,
};

/* 最小形态外层的 ContentInfo(id-ct-authData)。 */
static const uint8_t kMinimalContentInfo[] = {
    0x30, 0x63, 0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09,
    0x10, 0x01, 0x02, 0xA0, 0x54, 0x30, 0x52, 0x02, 0x01, 0x00, 0x31, 0x2E,
    0x30, 0x2C, 0x02, 0x01, 0x00, 0x30, 0x14, 0x30, 0x0F, 0x31, 0x0D, 0x30,
    0x0B, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x04, 0x74, 0x65, 0x73, 0x74,
    0x02, 0x01, 0x01, 0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7,
    0x0D, 0x01, 0x01, 0x01, 0x04, 0x04, 0x01, 0x02, 0x03, 0x04, 0x30, 0x0A,
    0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x09, 0x30, 0x0B,
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01, 0x04,
    0x04, 0x11, 0x22, 0x33, 0x44,
};

/*
 * 完整形态（version 0，无 originatorInfo）：ktri/kekri 两个收件人 +
 * hmacWithSHA256 + digestAlgorithm [1] sha256 + id-data + authAttrs [2] +
 * mac + unauthAttrs [3]。
 */
static const uint8_t kFullInner[] = {
    0x30, 0x81, 0x9F, 0x02, 0x01, 0x00, 0x31, 0x52, 0x30, 0x2C, 0x02, 0x01,
    0x00, 0x30, 0x14, 0x30, 0x0F, 0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55,
    0x04, 0x03, 0x0C, 0x04, 0x74, 0x65, 0x73, 0x74, 0x02, 0x01, 0x01, 0x30,
    0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
    0x04, 0x04, 0x01, 0x02, 0x03, 0x04, 0xA2, 0x22, 0x02, 0x01, 0x00, 0x30,
    0x0A, 0x04, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x30,
    0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2D,
    0x04, 0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86,
    0x48, 0x86, 0xF7, 0x0D, 0x02, 0x09, 0xA1, 0x0B, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x30, 0x0B, 0x06, 0x09, 0x2A,
    0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01, 0xA2, 0x0C, 0x30, 0x0A,
    0x06, 0x03, 0x2A, 0x03, 0x04, 0x31, 0x03, 0x02, 0x01, 0x01, 0x04, 0x04,
    0x11, 0x22, 0x33, 0x44, 0xA3, 0x0C, 0x30, 0x0A, 0x06, 0x03, 0x2A, 0x03,
    0x04, 0x31, 0x03, 0x02, 0x01, 0x01,
};

/* 完整形态外层的 ContentInfo(id-ct-authData)，version 0。 */
static const uint8_t kFullContentInfo[] = {
    0x30, 0x81, 0xB2, 0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01,
    0x09, 0x10, 0x01, 0x02, 0xA0, 0x81, 0xA2, 0x30, 0x81, 0x9F, 0x02, 0x01,
    0x00, 0x31, 0x52, 0x30, 0x2C, 0x02, 0x01, 0x00, 0x30, 0x14, 0x30, 0x0F,
    0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x04, 0x74,
    0x65, 0x73, 0x74, 0x02, 0x01, 0x01, 0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86,
    0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x04, 0x04, 0x01, 0x02, 0x03,
    0x04, 0xA2, 0x22, 0x02, 0x01, 0x00, 0x30, 0x0A, 0x04, 0x08, 0x01, 0x02,
    0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x30, 0x0B, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2D, 0x04, 0x04, 0xAA, 0xBB, 0xCC,
    0xDD, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02,
    0x09, 0xA1, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
    0x02, 0x01, 0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
    0x01, 0x07, 0x01, 0xA2, 0x0C, 0x30, 0x0A, 0x06, 0x03, 0x2A, 0x03, 0x04,
    0x31, 0x03, 0x02, 0x01, 0x01, 0x04, 0x04, 0x11, 0x22, 0x33, 0x44, 0xA3,
    0x0C, 0x30, 0x0A, 0x06, 0x03, 0x2A, 0x03, 0x04, 0x31, 0x03, 0x02, 0x01,
    0x01,
};

/* 完整形态中 version 与 originatorInfo 之后的部分（供拼装 version 3 样本）。 */
static const uint8_t kFullTail[] = {
    0x31, 0x52, 0x30, 0x2C, 0x02, 0x01, 0x00, 0x30, 0x14, 0x30, 0x0F, 0x31,
    0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x04, 0x74, 0x65,
    0x73, 0x74, 0x02, 0x01, 0x01, 0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48,
    0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x04, 0x04, 0x01, 0x02, 0x03, 0x04,
    0xA2, 0x22, 0x02, 0x01, 0x00, 0x30, 0x0A, 0x04, 0x08, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07, 0x08, 0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48,
    0x01, 0x65, 0x03, 0x04, 0x01, 0x2D, 0x04, 0x04, 0xAA, 0xBB, 0xCC, 0xDD,
    0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x09,
    0xA1, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
    0x01, 0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01,
    0x07, 0x01, 0xA2, 0x0C, 0x30, 0x0A, 0x06, 0x03, 0x2A, 0x03, 0x04, 0x31,
    0x03, 0x02, 0x01, 0x01, 0x04, 0x04, 0x11, 0x22, 0x33, 0x44, 0xA3, 0x0C,
    0x30, 0x0A, 0x06, 0x03, 0x2A, 0x03, 0x04, 0x31, 0x03, 0x02, 0x01, 0x01,
};

/* 最小形态 + 空 authAttrs（`A2 00`，位于 mac 之前）。 */
static const uint8_t kEmptyAuthAttrs[] = {
    0x30, 0x54, 0x02, 0x01, 0x00, 0x31, 0x2E, 0x30, 0x2C, 0x02, 0x01, 0x00,
    0x30, 0x14, 0x30, 0x0F, 0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0C, 0x04, 0x74, 0x65, 0x73, 0x74, 0x02, 0x01, 0x01, 0x30, 0x0B,
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x04,
    0x04, 0x01, 0x02, 0x03, 0x04, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48,
    0x86, 0xF7, 0x0D, 0x02, 0x09, 0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48,
    0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01, 0xA2, 0x00, 0x04, 0x04, 0x11, 0x22,
    0x33, 0x44,
};

/* 最小形态 + 尾随的未知错标签 `A2 00`（本应在 mac 之前）：读侧静默忽略。 */
static const uint8_t kUnknownA2Tail[] = {
    0x30, 0x54, 0x02, 0x01, 0x00, 0x31, 0x2E, 0x30, 0x2C, 0x02, 0x01, 0x00,
    0x30, 0x14, 0x30, 0x0F, 0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0C, 0x04, 0x74, 0x65, 0x73, 0x74, 0x02, 0x01, 0x01, 0x30, 0x0B,
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x04,
    0x04, 0x01, 0x02, 0x03, 0x04, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48,
    0x86, 0xF7, 0x0D, 0x02, 0x09, 0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48,
    0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01, 0x04, 0x04, 0x11, 0x22, 0x33, 0x44,
    0xA2, 0x00,
};

/* 最小形态 + 空 unauthAttrs（`A3 00`）。 */
static const uint8_t kEmptyUnauthAttrs[] = {
    0x30, 0x54, 0x02, 0x01, 0x00, 0x31, 0x2E, 0x30, 0x2C, 0x02, 0x01, 0x00,
    0x30, 0x14, 0x30, 0x0F, 0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0C, 0x04, 0x74, 0x65, 0x73, 0x74, 0x02, 0x01, 0x01, 0x30, 0x0B,
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x04,
    0x04, 0x01, 0x02, 0x03, 0x04, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48,
    0x86, 0xF7, 0x0D, 0x02, 0x09, 0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48,
    0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01, 0x04, 0x04, 0x11, 0x22, 0x33, 0x44,
    0xA3, 0x00,
};

/* recipientInfos 为空 SET（`31 00`），预期触发描述表的 SET SIZE (1..MAX)。 */
static const uint8_t kEmptyRecipients[] = {
    0x30, 0x24, 0x02, 0x01, 0x00, 0x31, 0x00, 0x30, 0x0A, 0x06, 0x08, 0x2A,
    0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x09, 0x30, 0x0B, 0x06, 0x09, 0x2A,
    0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01, 0x04, 0x04, 0x11, 0x22,
    0x33, 0x44,
};

/* 最小形态 + authAttrs（非空）但缺 digestAlgorithm：读侧接受。 */
static const uint8_t kAuthAttrsNoDigest[] = {
    0x30, 0x60, 0x02, 0x01, 0x00, 0x31, 0x2E, 0x30, 0x2C, 0x02, 0x01, 0x00,
    0x30, 0x14, 0x30, 0x0F, 0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0C, 0x04, 0x74, 0x65, 0x73, 0x74, 0x02, 0x01, 0x01, 0x30, 0x0B,
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x04,
    0x04, 0x01, 0x02, 0x03, 0x04, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48,
    0x86, 0xF7, 0x0D, 0x02, 0x09, 0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48,
    0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01, 0xA2, 0x0C, 0x30, 0x0A, 0x06, 0x03,
    0x2A, 0x03, 0x04, 0x31, 0x03, 0x02, 0x01, 0x01, 0x04, 0x04, 0x11, 0x22,
    0x33, 0x44,
};

/* version 5：读侧原样返回，不做 0/1/3 范围校验。 */
static const uint8_t kVersion5[] = {
    0x30, 0x52, 0x02, 0x01, 0x05, 0x31, 0x2E, 0x30, 0x2C, 0x02, 0x01, 0x00,
    0x30, 0x14, 0x30, 0x0F, 0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0C, 0x04, 0x74, 0x65, 0x73, 0x74, 0x02, 0x01, 0x01, 0x30, 0x0B,
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x04,
    0x04, 0x01, 0x02, 0x03, 0x04, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48,
    0x86, 0xF7, 0x0D, 0x02, 0x09, 0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48,
    0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01, 0x04, 0x04, 0x11, 0x22, 0x33, 0x44,
};

/* 字段间插入未知 TLV（`05 00`）：读侧按未知字段静默忽略。 */
static const uint8_t kUnknownBetween[] = {
    0x30, 0x54, 0x02, 0x01, 0x00, 0x05, 0x00, 0x31, 0x2E, 0x30, 0x2C, 0x02,
    0x01, 0x00, 0x30, 0x14, 0x30, 0x0F, 0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x0C, 0x04, 0x74, 0x65, 0x73, 0x74, 0x02, 0x01, 0x01,
    0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01,
    0x01, 0x04, 0x04, 0x01, 0x02, 0x03, 0x04, 0x30, 0x0A, 0x06, 0x08, 0x2A,
    0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x09, 0x30, 0x0B, 0x06, 0x09, 0x2A,
    0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01, 0x04, 0x04, 0x11, 0x22,
    0x33, 0x44,
};

/* 根 SEQUENCE 之后还有两个字节：读侧拒绝尾随数据。 */
static const uint8_t kTrailingData[] = {
    0x30, 0x52, 0x02, 0x01, 0x00, 0x31, 0x2E, 0x30, 0x2C, 0x02, 0x01, 0x00,
    0x30, 0x14, 0x30, 0x0F, 0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0C, 0x04, 0x74, 0x65, 0x73, 0x74, 0x02, 0x01, 0x01, 0x30, 0x0B,
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x04,
    0x04, 0x01, 0x02, 0x03, 0x04, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48,
    0x86, 0xF7, 0x0D, 0x02, 0x09, 0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48,
    0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01, 0x04, 0x04, 0x11, 0x22, 0x33, 0x44,
    0xDE, 0xAD,
};

static size_t der_len_bytes(size_t value)
{
    if (value < 0x80u) {
        return 1;
    }
    if (value < 0x100u) {
        return 2;
    }
    return 3;
}

static size_t der_put_len(uint8_t *out, size_t value)
{
    if (value < 0x80u) {
        out[0] = (uint8_t)value;
        return 1;
    }
    if (value < 0x100u) {
        out[0] = 0x81u;
        out[1] = (uint8_t)value;
        return 2;
    }
    out[0] = 0x82u;
    out[1] = (uint8_t)(value >> 8);
    out[2] = (uint8_t)value;
    return 3;
}

/*
 * originatorInfo 字段（`[0] IMPLICIT OriginatorInfo`）：外层 A0 替代
 * OriginatorInfo 的 SEQUENCE 标签，内部 certs [0] IMPLICIT CertificateSet
 * 再一层 A0，最后是证书 SEQUENCE；`crls` 非空时追加 `crls [1]` 的完整 TLV
 * （调用方按 DER 顺序放在 certs 之后）。
 * 证书取 `tests/data/cert_rsa_selfsigned.der`（openssl 生成的自签证书，
 * 仅用于测试，不是生产证书）。
 */
static size_t build_originator_info(uint8_t *out, size_t capacity,
                                    const uint8_t *crls, size_t crls_size)
{
    size_t cert_size = kCertRsaSelfsignedSize;
    size_t certs_size = 1u + der_len_bytes(cert_size) + cert_size;
    size_t body_size = certs_size + (crls != NULL ? crls_size : 0u);
    size_t seq_size = 1u + der_len_bytes(body_size) + body_size;
    size_t pos = 0;

    if (seq_size > capacity) {
        return 0;
    }
    out[pos++] = 0xA0u;
    pos += der_put_len(out + pos, body_size);
    out[pos++] = 0xA0u;
    pos += der_put_len(out + pos, cert_size);
    memcpy(out + pos, kCertRsaSelfsigned, cert_size);
    pos += cert_size;
    if (crls != NULL) {
        memcpy(out + pos, crls, crls_size);
        pos += crls_size;
    }
    return pos;
}

/* 拼装 version 3 + 真实 certs/crls 的完整 AuthenticatedData（不含 ContentInfo）。 */
static size_t build_v3_inner(uint8_t *out, size_t capacity,
                             const uint8_t *crls, size_t crls_size)
{
    uint8_t originator[1024];
    size_t originator_size;
    size_t content_size;
    size_t pos = 0;

    originator_size = build_originator_info(originator, sizeof(originator),
                                            crls, crls_size);
    if (originator_size == 0) {
        return 0;
    }
    content_size = 3u + originator_size + sizeof(kFullTail);
    if (1u + der_len_bytes(content_size) + content_size > capacity) {
        return 0;
    }
    out[pos++] = 0x30u;
    pos += der_put_len(out + pos, content_size);
    out[pos++] = 0x02u;
    out[pos++] = 0x01u;
    out[pos++] = 0x03u;
    memcpy(out + pos, originator, originator_size);
    pos += originator_size;
    memcpy(out + pos, kFullTail, sizeof(kFullTail));
    pos += sizeof(kFullTail);
    return pos;
}

static const uint8_t kDigestAlgorithm[] = {
    0xA1, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
    0x01,
};

static const uint8_t kMac[] = {0x11, 0x22, 0x33, 0x44};

/*
 * `crls [1] IMPLICIT RevocationInfoChoices`：单个最小合法 CertificateList
 * （SHA-256 with RSA、空 issuer Name、单个 UTCTime thisUpdate、空签名）。
 * 只验证结构路径，不代表任何真实吊销信息。
 */
static const uint8_t kCrls[] = {
    0xA1, 0x36, 0x30, 0x34, 0x30, 0x20, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86,
    0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x30, 0x00, 0x17,
    0x0D, 0x32, 0x36, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x5A, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
    0x01, 0x01, 0x0B, 0x05, 0x00, 0x03, 0x01, 0x00,
};

/* 最小形态 + 空 eContent（显式存在的 `A0 02 04 00`）。 */
static const uint8_t kEmptyEcontent[] = {
    0x30, 0x56, 0x02, 0x01, 0x00, 0x31, 0x2E, 0x30, 0x2C, 0x02, 0x01, 0x00,
    0x30, 0x14, 0x30, 0x0F, 0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0C, 0x04, 0x74, 0x65, 0x73, 0x74, 0x02, 0x01, 0x01, 0x30, 0x0B,
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x04,
    0x04, 0x01, 0x02, 0x03, 0x04, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48,
    0x86, 0xF7, 0x0D, 0x02, 0x09, 0x30, 0x0F, 0x06, 0x09, 0x2A, 0x86, 0x48,
    0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01, 0xA0, 0x02, 0x04, 0x00, 0x04, 0x04,
    0x11, 0x22, 0x33, 0x44,
};

/* 最小形态 + 空 mac（`04 00`）。 */
static const uint8_t kEmptyMac[] = {
    0x30, 0x4E, 0x02, 0x01, 0x00, 0x31, 0x2E, 0x30, 0x2C, 0x02, 0x01, 0x00,
    0x30, 0x14, 0x30, 0x0F, 0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0C, 0x04, 0x74, 0x65, 0x73, 0x74, 0x02, 0x01, 0x01, 0x30, 0x0B,
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x04,
    0x04, 0x01, 0x02, 0x03, 0x04, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48,
    0x86, 0xF7, 0x0D, 0x02, 0x09, 0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48,
    0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01, 0x04, 0x00,
};

/* 最小形态 + digestAlgorithm（`A1`）但缺 authAttrs：读侧同样接受。 */
static const uint8_t kDigestNoAuthAttrs[] = {
    0x30, 0x5F, 0x02, 0x01, 0x00, 0x31, 0x2E, 0x30, 0x2C, 0x02, 0x01, 0x00,
    0x30, 0x14, 0x30, 0x0F, 0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0C, 0x04, 0x74, 0x65, 0x73, 0x74, 0x02, 0x01, 0x01, 0x30, 0x0B,
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x04,
    0x04, 0x01, 0x02, 0x03, 0x04, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48,
    0x86, 0xF7, 0x0D, 0x02, 0x09, 0xA1, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48,
    0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86,
    0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01, 0x04, 0x04, 0x11, 0x22, 0x33,
    0x44,
};

static asnber_ctx_t *make_ctx(void)
{
    asnber_ctx_config_t config;
    asnber_ctx_config_init(&config);
    asnber_ctx_t *ctx = NULL;
    if (asnber_ctx_create(&config, &ctx) != ASNBER_OK) {
        return NULL;
    }
    return ctx;
}

static int check_mac(asnber_cms_authenticated_data_t *authenticated)
{
    const uint8_t *mac = NULL;
    size_t mac_size = 0;
    const uint8_t *tlv = NULL;
    size_t tlv_size = 0;

    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_mac(
                        authenticated, &mac, &mac_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_mac_tlv(
                        authenticated, &tlv, &tlv_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(bytes_equal(mac, mac_size, kMac, sizeof(kMac)));
    ASNBER_TEST_CHECK(tlv != NULL && tlv_size == mac_size + 2);
    ASNBER_TEST_CHECK(tlv[0] == 0x04 && tlv[1] == (uint8_t)mac_size);
    return 0;
}

/* ---------- 最小形态 ---------- */

static int test_minimal(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_cms_authenticated_data_t *authenticated = NULL;
    int64_t version = -1;
    const uint8_t *tlv = NULL;
    size_t tlv_size = 0;
    const char *oid = NULL;
    size_t oid_size = 0;
    const uint8_t *parameters = NULL;
    size_t parameters_size = 0;
    const uint8_t *data = NULL;
    size_t data_size = 0;
    size_t count = 0;
    int kind = -1;

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_open(
                        ctx, kMinimalInner, sizeof(kMinimalInner),
                        &authenticated) == ASNBER_OK);

    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_version(authenticated,
                                                        &version) == ASNBER_OK);
    ASNBER_TEST_CHECK(version == 0);

    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_originator_info_tlv(
                        authenticated, &tlv, &tlv_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(tlv == NULL && tlv_size == 0);

    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_recipient_count(
                        authenticated, &count) == ASNBER_OK);
    ASNBER_TEST_CHECK(count == 1);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_recipient_at(
                        authenticated, 0, &kind, &tlv, &tlv_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(kind == ASNBER_CMS_RECIPIENT_KTRI);
    ASNBER_TEST_CHECK(bytes_equal(tlv, tlv_size, kKtri, sizeof(kKtri)));
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_recipient_at(
                        authenticated, 1, &kind, &tlv, &tlv_size) ==
                    ASNBER_E_INVALID_ARG);

    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_mac_algorithm(
                        authenticated, &oid, &oid_size, &parameters,
                        &parameters_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(text_equals(oid, oid_size, kHmacSha256Oid));
    ASNBER_TEST_CHECK(parameters == NULL && parameters_size == 0);

    /* digestAlgorithm 与 authAttrs 缺省：返回 NULL/0，而不是错误。 */
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_digest_algorithm(
                        authenticated, &oid, &oid_size, &parameters,
                        &parameters_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(oid == NULL && oid_size == 0);
    ASNBER_TEST_CHECK(parameters == NULL && parameters_size == 0);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_auth_attrs_tlv(
                        authenticated, &tlv, &tlv_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(tlv == NULL && tlv_size == 0);

    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_econtent_type(
                        authenticated, &oid, &oid_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(text_equals(oid, oid_size, kDataOid));
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_econtent(
                        authenticated, &data, &data_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(data == NULL && data_size == 0);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_econtent_tlv(
                        authenticated, &tlv, &tlv_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(tlv == NULL && tlv_size == 0);

    ASNBER_TEST_CHECK(check_mac(authenticated) == 0);

    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_unauth_attrs_tlv(
                        authenticated, &tlv, &tlv_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(tlv == NULL && tlv_size == 0);

    asnber_cms_authenticated_data_close(authenticated);
    asnber_ctx_destroy(ctx);
    return 0;
}

/* ContentInfo(id-ct-authData) 剥壳：content 即裸 AuthenticatedData。 */
static int test_content_info_wrapping(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_cms_content_info_t *info = NULL;
    const char *oid = NULL;
    size_t oid_size = 0;
    const uint8_t *content = NULL;
    size_t content_size = 0;
    asnber_cms_authenticated_data_t *authenticated = NULL;
    int64_t version = -1;

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(asnber_cms_content_info_open(ctx, kMinimalContentInfo,
                                               sizeof(kMinimalContentInfo),
                                               &info) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_content_info_content_type(info, &oid,
                                                       &oid_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(text_equals(oid, oid_size, kAuthDataOid));
    ASNBER_TEST_CHECK(asnber_cms_content_info_content(info, &content,
                                                  &content_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(bytes_equal(content, content_size, kMinimalInner,
                                sizeof(kMinimalInner)));

    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_open(ctx, content, content_size,
                                                     &authenticated) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_version(authenticated,
                                                        &version) == ASNBER_OK);
    ASNBER_TEST_CHECK(version == 0);

    asnber_cms_authenticated_data_close(authenticated);
    asnber_cms_content_info_close(info);
    asnber_ctx_destroy(ctx);
    return 0;
}

/* ---------- 固定的合成样本 ---------- */

/*
 * 外层 ContentInfo(id-ct-authData) 内的版本 0 完整形态由
 * `scripts/gen_test_data.py --cms-authenticated` 固定写出，不是外部实现
 * 产物（OpenSSL 的 cms 子命令没有 authData 入口）。本用例只验证本库能
 * 稳定读取这份快照，不声称它被外部生产方接受。version 0 不带
 * originatorInfo：非 0 版本才要求该字段出现。
 */
static int test_synthetic_sample(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_cms_content_info_t *info = NULL;
    asnber_cms_authenticated_data_t *authenticated = NULL;
    const char *oid = NULL;
    size_t oid_size = 0;
    const uint8_t *content = NULL;
    size_t content_size = 0;
    const uint8_t *tlv = NULL;
    size_t tlv_size = 0;
    const uint8_t *parameters = NULL;
    size_t parameters_size = 0;
    const uint8_t *data = NULL;
    size_t data_size = 0;
    size_t count = 0;
    int kind = -1;
    int64_t version = -1;

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(asnber_cms_content_info_open(ctx, kCmsAuthenticatedData,
                                               kCmsAuthenticatedDataSize,
                                               &info) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_content_info_content_type(info, &oid,
                                                       &oid_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(text_equals(oid, oid_size, kAuthDataOid));
    ASNBER_TEST_CHECK(asnber_cms_content_info_content(info, &content,
                                                  &content_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(content != NULL && content_size > 0);
    /* 主样本就是 version 0 的完整形态，与手写常量一致。 */
    ASNBER_TEST_CHECK(bytes_equal(content, content_size, kFullInner,
                                sizeof(kFullInner)));
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_open(ctx, content, content_size,
                                                     &authenticated) == ASNBER_OK);

    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_version(authenticated,
                                                        &version) == ASNBER_OK);
    ASNBER_TEST_CHECK(version == 0);

    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_originator_info_tlv(
                        authenticated, &tlv, &tlv_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(tlv == NULL && tlv_size == 0);

    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_recipient_count(
                        authenticated, &count) == ASNBER_OK);
    ASNBER_TEST_CHECK(count == 2);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_recipient_at(
                        authenticated, 0, &kind, &tlv, &tlv_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(kind == ASNBER_CMS_RECIPIENT_KTRI);
    ASNBER_TEST_CHECK(bytes_equal(tlv, tlv_size, kKtri, sizeof(kKtri)));
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_recipient_at(
                        authenticated, 1, &kind, &tlv, &tlv_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(kind == ASNBER_CMS_RECIPIENT_KEKRI);
    ASNBER_TEST_CHECK(bytes_equal(tlv, tlv_size, kKekri, sizeof(kKekri)));

    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_mac_algorithm(
                        authenticated, &oid, &oid_size, &parameters,
                        &parameters_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(text_equals(oid, oid_size, kHmacSha256Oid));
    ASNBER_TEST_CHECK(parameters == NULL && parameters_size == 0);

    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_digest_algorithm(
                        authenticated, &oid, &oid_size, &parameters,
                        &parameters_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(text_equals(oid, oid_size, kSha256Oid));
    ASNBER_TEST_CHECK(parameters == NULL && parameters_size == 0);

    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_econtent_type(
                        authenticated, &oid, &oid_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(text_equals(oid, oid_size, kDataOid));
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_econtent(
                        authenticated, &data, &data_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(data == NULL && data_size == 0);

    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_auth_attrs_tlv(
                        authenticated, &tlv, &tlv_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(tlv != NULL && tlv_size == sizeof(kAttrs));
    ASNBER_TEST_CHECK(tlv[0] == 0xA2);
    ASNBER_TEST_CHECK(memcmp(tlv + 1, kAttrs + 1, tlv_size - 1) == 0);

    ASNBER_TEST_CHECK(check_mac(authenticated) == 0);

    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_unauth_attrs_tlv(
                        authenticated, &tlv, &tlv_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(tlv != NULL && tlv_size == sizeof(kAttrs));
    ASNBER_TEST_CHECK(tlv[0] == 0xA3);
    ASNBER_TEST_CHECK(memcmp(tlv + 1, kAttrs + 1, tlv_size - 1) == 0);

    asnber_cms_authenticated_data_close(authenticated);
    asnber_cms_content_info_close(info);
    asnber_ctx_destroy(ctx);
    return 0;
}

/* ---------- 完整形态（version 3 + 真实 certs [0]） ---------- */

/*
 * version 3 要求 originatorInfo 出现；这里把它装成
 * `certificates [0]`（一份合成自签证书）。样本在运行时拼装，
 * 避免把 865 字节证书再抄成常量。
 */
static int test_full(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_cms_authenticated_data_t *authenticated = NULL;
    uint8_t sample[2048];
    uint8_t originator[1024];
    size_t sample_size = 0;
    size_t originator_size = 0;
    int64_t version = -1;
    const uint8_t *tlv = NULL;
    size_t tlv_size = 0;
    const char *oid = NULL;
    size_t oid_size = 0;
    const uint8_t *parameters = NULL;
    size_t parameters_size = 0;
    size_t count = 0;
    int kind = -1;

    ASNBER_TEST_CHECK(ctx != NULL);
    sample_size = build_v3_inner(sample, sizeof(sample), kCrls, sizeof(kCrls));
    ASNBER_TEST_CHECK(sample_size > 0);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_open(ctx, sample, sample_size,
                                                     &authenticated) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_version(authenticated,
                                                        &version) == ASNBER_OK);
    ASNBER_TEST_CHECK(version == 3);

    originator_size = build_originator_info(originator, sizeof(originator),
                                            kCrls, sizeof(kCrls));
    ASNBER_TEST_CHECK(originator_size > 0);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_originator_info_tlv(
                        authenticated, &tlv, &tlv_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(tlv != NULL && tlv_size == originator_size);
    ASNBER_TEST_CHECK(bytes_equal(tlv, tlv_size, originator, originator_size));

    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_recipient_count(
                        authenticated, &count) == ASNBER_OK);
    ASNBER_TEST_CHECK(count == 2);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_recipient_at(
                        authenticated, 0, &kind, &tlv, &tlv_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(kind == ASNBER_CMS_RECIPIENT_KTRI);
    ASNBER_TEST_CHECK(bytes_equal(tlv, tlv_size, kKtri, sizeof(kKtri)));
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_recipient_at(
                        authenticated, 1, &kind, &tlv, &tlv_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(kind == ASNBER_CMS_RECIPIENT_KEKRI);
    ASNBER_TEST_CHECK(bytes_equal(tlv, tlv_size, kKekri, sizeof(kKekri)));

    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_mac_algorithm(
                        authenticated, &oid, &oid_size, &parameters,
                        &parameters_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(text_equals(oid, oid_size, kHmacSha256Oid));

    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_digest_algorithm(
                        authenticated, &oid, &oid_size, &parameters,
                        &parameters_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(text_equals(oid, oid_size, kSha256Oid));
    ASNBER_TEST_CHECK(parameters == NULL && parameters_size == 0);

    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_econtent_type(
                        authenticated, &oid, &oid_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(text_equals(oid, oid_size, kDataOid));

    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_auth_attrs_tlv(
                        authenticated, &tlv, &tlv_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(tlv != NULL && tlv_size == sizeof(kAttrs));
    /* [2] IMPLICIT SET OF：外层标签为 0xA2。 */
    ASNBER_TEST_CHECK(tlv[0] == 0xA2);
    ASNBER_TEST_CHECK(memcmp(tlv + 1, kAttrs + 1, tlv_size - 1) == 0);

    ASNBER_TEST_CHECK(check_mac(authenticated) == 0);

    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_unauth_attrs_tlv(
                        authenticated, &tlv, &tlv_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(tlv != NULL && tlv_size == sizeof(kAttrs));
    ASNBER_TEST_CHECK(tlv[0] == 0xA3);
    ASNBER_TEST_CHECK(memcmp(tlv + 1, kAttrs + 1, tlv_size - 1) == 0);

    asnber_cms_authenticated_data_close(authenticated);
    asnber_ctx_destroy(ctx);
    return 0;
}

/* ---------- builder ---------- */

static int check_builder_output(asnber_ctx_t *ctx, const asnber_buf_t *encoded,
                                const uint8_t *expected, size_t expected_size)
{
    asnber_cms_content_info_t *info = NULL;
    const uint8_t *content = NULL;
    size_t content_size = 0;
    asnber_cms_authenticated_data_t *authenticated = NULL;

    ASNBER_TEST_CHECK(bytes_equal(encoded->data, encoded->size, expected,
                                expected_size));
    ASNBER_TEST_CHECK(asnber_cms_content_info_open(ctx, encoded->data,
                                               encoded->size, &info) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_content_info_content(info, &content,
                                                  &content_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_open(ctx, content, content_size,
                                                     &authenticated) == ASNBER_OK);
    ASNBER_TEST_CHECK(check_mac(authenticated) == 0);
    asnber_cms_authenticated_data_close(authenticated);
    asnber_cms_content_info_close(info);
    return 0;
}

/* 最小 builder：逐字节等于手写的最小形态。 */
static int test_builder_minimal(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_cms_authenticated_builder_t *builder = NULL;
    asnber_buf_t encoded;
    memset(&encoded, 0, sizeof(encoded));

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_create(ctx, &builder) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_version(builder, 0) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_add_recipient(
                        builder, kKtri, sizeof(kKtri)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_mac_algorithm(
                        builder, kHmacSha256Oid, NULL, 0) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_econtent_type(
                        builder, kDataOid) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_mac(
                        builder, kMac, sizeof(kMac)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_encode(builder, &encoded) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(check_builder_output(ctx, &encoded, kMinimalContentInfo,
                                         sizeof(kMinimalContentInfo)) == 0);

    asnber_buf_release(ctx, &encoded);
    asnber_cms_authenticated_builder_destroy(builder);
    asnber_ctx_destroy(ctx);
    return 0;
}

/* 完整 builder（version 0）：除 originatorInfo 外可选字段全部出现。 */
static int test_builder_full(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_cms_authenticated_builder_t *builder = NULL;
    asnber_buf_t encoded;
    memset(&encoded, 0, sizeof(encoded));

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_create(ctx, &builder) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_version(builder, 0) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_add_recipient(
                        builder, kKtri, sizeof(kKtri)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_add_recipient(
                        builder, kKekri, sizeof(kKekri)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_mac_algorithm(
                        builder, kHmacSha256Oid, NULL, 0) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_digest_algorithm(
                        builder, kDigestAlgorithm,
                        sizeof(kDigestAlgorithm)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_econtent_type(
                        builder, kDataOid) == ASNBER_OK);
    /* set_auth_attrs / set_unauth_attrs 接受 SET 的 0x31 外形。 */
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_auth_attrs(
                        builder, kAttrs, sizeof(kAttrs)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_mac(
                        builder, kMac, sizeof(kMac)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_unauth_attrs(
                        builder, kAttrs, sizeof(kAttrs)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_encode(builder, &encoded) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(check_builder_output(ctx, &encoded, kFullContentInfo,
                                         sizeof(kFullContentInfo)) == 0);

    asnber_buf_release(ctx, &encoded);
    asnber_cms_authenticated_builder_destroy(builder);
    asnber_ctx_destroy(ctx);
    return 0;
}

/* version 1：只要求 originatorInfo 存在；digest/authAttrs 可同时缺省。
 * originatorInfo 使用合成自签证书，避免出现非法的空 `A0 00` 形态。 */
static int test_builder_version1(void)
{
    uint8_t originator[1024];
    size_t originator_size;
    asnber_ctx_t *ctx = make_ctx();
    asnber_cms_authenticated_builder_t *builder = NULL;
    asnber_buf_t encoded;
    memset(&encoded, 0, sizeof(encoded));

    ASNBER_TEST_CHECK(ctx != NULL);
    originator_size = build_originator_info(originator, sizeof(originator),
                                            NULL, 0);
    ASNBER_TEST_CHECK(originator_size > 0);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_create(ctx, &builder) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_version(builder, 1) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_originator_info(
                        builder, originator,
                        originator_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_add_recipient(
                        builder, kKtri, sizeof(kKtri)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_mac_algorithm(
                        builder, kHmacSha256Oid, NULL, 0) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_econtent_type(
                        builder, kDataOid) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_mac(
                        builder, kMac, sizeof(kMac)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_encode(builder, &encoded) ==
                    ASNBER_OK);
    /* builder 输出与入库的 v1 静态样本逐字节一致。 */
    ASNBER_TEST_CHECK(bytes_equal(encoded.data, encoded.size,
                                kCmsAuthenticatedDataV1,
                                kCmsAuthenticatedDataV1Size));

    {
        asnber_cms_content_info_t *info = NULL;
        const uint8_t *content = NULL;
        size_t content_size = 0;
        asnber_cms_authenticated_data_t *authenticated = NULL;
        int64_t version = -1;
        const uint8_t *tlv = NULL;
        size_t tlv_size = 0;

        ASNBER_TEST_CHECK(asnber_cms_content_info_open(ctx, encoded.data,
                                                   encoded.size, &info) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_content_info_content(info, &content,
                                                      &content_size) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_authenticated_data_open(
                            ctx, content, content_size, &authenticated) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_authenticated_data_version(authenticated,
                                                            &version) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(version == 1);
        ASNBER_TEST_CHECK(asnber_cms_authenticated_data_originator_info_tlv(
                            authenticated, &tlv, &tlv_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(tlv != NULL && tlv_size == originator_size);
        ASNBER_TEST_CHECK(bytes_equal(tlv, tlv_size, originator,
                                    originator_size));
        asnber_cms_authenticated_data_close(authenticated);
        asnber_cms_content_info_close(info);
    }

    asnber_buf_release(ctx, &encoded);
    asnber_cms_authenticated_builder_destroy(builder);
    asnber_ctx_destroy(ctx);
    return 0;
}

/* ---------- 读侧静态样本（v1 / v3）与 crls [1] 正例 ---------- */

/* v1 静态样本：version 1 + 真实 certs [0]，无 digestAlgorithm/authAttrs。 */
static int test_static_v1_sample(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_cms_content_info_t *info = NULL;
    asnber_cms_authenticated_data_t *authenticated = NULL;
    const uint8_t *content = NULL;
    size_t content_size = 0;
    uint8_t originator[1024];
    size_t originator_size = 0;
    int64_t version = -1;
    const uint8_t *tlv = NULL;
    size_t tlv_size = 0;
    const char *oid = NULL;
    size_t oid_size = 0;
    size_t count = 0;

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(asnber_cms_content_info_open(ctx, kCmsAuthenticatedDataV1,
                                               kCmsAuthenticatedDataV1Size,
                                               &info) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_content_info_content(info, &content,
                                                  &content_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(content != NULL && content_size > 0);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_open(ctx, content, content_size,
                                                     &authenticated) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_version(authenticated,
                                                        &version) == ASNBER_OK);
    ASNBER_TEST_CHECK(version == 1);

    originator_size = build_originator_info(originator, sizeof(originator),
                                            NULL, 0);
    ASNBER_TEST_CHECK(originator_size > 0);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_originator_info_tlv(
                        authenticated, &tlv, &tlv_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(tlv != NULL && tlv_size == originator_size);
    ASNBER_TEST_CHECK(bytes_equal(tlv, tlv_size, originator, originator_size));

    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_recipient_count(
                        authenticated, &count) == ASNBER_OK);
    ASNBER_TEST_CHECK(count == 1);

    /* v1 语义：不带 digestAlgorithm 与 authAttrs，eContent 为 detached。 */
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_digest_algorithm(
                        authenticated, &oid, &oid_size, &tlv, &tlv_size) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(oid == NULL && oid_size == 0);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_auth_attrs_tlv(
                        authenticated, &tlv, &tlv_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(tlv == NULL && tlv_size == 0);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_econtent(authenticated, &tlv,
                                                         &tlv_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(tlv == NULL && tlv_size == 0);

    asnber_cms_authenticated_data_close(authenticated);
    asnber_cms_content_info_close(info);
    asnber_ctx_destroy(ctx);
    return 0;
}

/* v3 静态样本：version 3 + certs [0] + crls [1]，供差分与读侧留档。 */
static int test_static_v3_sample(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_cms_content_info_t *info = NULL;
    asnber_cms_authenticated_data_t *authenticated = NULL;
    const uint8_t *content = NULL;
    size_t content_size = 0;
    uint8_t inner[2048];
    uint8_t originator[1024];
    size_t inner_size = 0;
    size_t originator_size = 0;
    int64_t version = -1;
    const uint8_t *tlv = NULL;
    size_t tlv_size = 0;
    size_t count = 0;

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(asnber_cms_content_info_open(ctx, kCmsAuthenticatedDataV3,
                                               kCmsAuthenticatedDataV3Size,
                                               &info) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_content_info_content(info, &content,
                                                  &content_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(content != NULL && content_size > 0);

    /* 静态样本与测试内拼装结果逐字节一致（gen_test_data.py 同一构造）。 */
    inner_size = build_v3_inner(inner, sizeof(inner), kCrls, sizeof(kCrls));
    ASNBER_TEST_CHECK(inner_size > 0);
    ASNBER_TEST_CHECK(bytes_equal(content, content_size, inner, inner_size));

    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_open(ctx, content, content_size,
                                                     &authenticated) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_version(authenticated,
                                                        &version) == ASNBER_OK);
    ASNBER_TEST_CHECK(version == 3);

    originator_size = build_originator_info(originator, sizeof(originator),
                                            kCrls, sizeof(kCrls));
    ASNBER_TEST_CHECK(originator_size > 0);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_originator_info_tlv(
                        authenticated, &tlv, &tlv_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(tlv != NULL && tlv_size == originator_size);
    ASNBER_TEST_CHECK(bytes_equal(tlv, tlv_size, originator, originator_size));
    /* originatorInfo 末尾即 crls [1] 的完整 TLV。 */
    ASNBER_TEST_CHECK(bytes_equal(tlv + tlv_size - sizeof(kCrls), sizeof(kCrls),
                                kCrls, sizeof(kCrls)));

    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_recipient_count(
                        authenticated, &count) == ASNBER_OK);
    ASNBER_TEST_CHECK(count == 2);

    asnber_cms_authenticated_data_close(authenticated);
    asnber_cms_content_info_close(info);
    asnber_ctx_destroy(ctx);
    return 0;
}

/* builder：version 3 + certs [0] + crls [1]，编码后读回。 */
static int test_builder_v3_crls(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_cms_authenticated_builder_t *builder = NULL;
    asnber_buf_t encoded;
    uint8_t originator[1024];
    size_t originator_size;
    memset(&encoded, 0, sizeof(encoded));

    ASNBER_TEST_CHECK(ctx != NULL);
    originator_size = build_originator_info(originator, sizeof(originator),
                                            kCrls, sizeof(kCrls));
    ASNBER_TEST_CHECK(originator_size > 0);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_create(ctx, &builder) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_version(builder, 3) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_originator_info(
                        builder, originator, originator_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_add_recipient(
                        builder, kKtri, sizeof(kKtri)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_add_recipient(
                        builder, kKekri, sizeof(kKekri)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_mac_algorithm(
                        builder, kHmacSha256Oid, NULL, 0) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_digest_algorithm(
                        builder, kDigestAlgorithm,
                        sizeof(kDigestAlgorithm)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_econtent_type(
                        builder, kDataOid) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_auth_attrs(
                        builder, kAttrs, sizeof(kAttrs)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_mac(
                        builder, kMac, sizeof(kMac)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_unauth_attrs(
                        builder, kAttrs, sizeof(kAttrs)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_encode(builder, &encoded) ==
                    ASNBER_OK);

    {
        asnber_cms_content_info_t *info = NULL;
        const uint8_t *content = NULL;
        size_t content_size = 0;
        asnber_cms_authenticated_data_t *authenticated = NULL;
        int64_t version = -1;
        const uint8_t *tlv = NULL;
        size_t tlv_size = 0;
        size_t count = 0;
        const char *oid = NULL;
        size_t oid_size = 0;

        ASNBER_TEST_CHECK(asnber_cms_content_info_open(ctx, encoded.data,
                                                   encoded.size, &info) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_content_info_content(info, &content,
                                                      &content_size) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_authenticated_data_open(
                            ctx, content, content_size, &authenticated) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(asnber_cms_authenticated_data_version(authenticated,
                                                            &version) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(version == 3);
        ASNBER_TEST_CHECK(asnber_cms_authenticated_data_originator_info_tlv(
                            authenticated, &tlv, &tlv_size) == ASNBER_OK);
        ASNBER_TEST_CHECK(tlv != NULL && tlv_size == originator_size);
        ASNBER_TEST_CHECK(bytes_equal(tlv, tlv_size, originator,
                                    originator_size));
        ASNBER_TEST_CHECK(asnber_cms_authenticated_data_recipient_count(
                            authenticated, &count) == ASNBER_OK);
        ASNBER_TEST_CHECK(count == 2);
        ASNBER_TEST_CHECK(asnber_cms_authenticated_data_digest_algorithm(
                            authenticated, &oid, &oid_size, &tlv, &tlv_size) ==
                        ASNBER_OK);
        ASNBER_TEST_CHECK(text_equals(oid, oid_size, kSha256Oid));
        asnber_cms_authenticated_data_close(authenticated);
        asnber_cms_content_info_close(info);
    }

    asnber_buf_release(ctx, &encoded);
    asnber_cms_authenticated_builder_destroy(builder);
    asnber_ctx_destroy(ctx);
    return 0;
}

/* ---------- 读侧边界分支 ---------- */

static int test_read_edge_cases(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_cms_authenticated_data_t *authenticated = NULL;
    const uint8_t *data = NULL;
    size_t data_size = 0;
    const char *oid = NULL;
    size_t oid_size = 0;
    const uint8_t *parameters = NULL;
    size_t parameters_size = 0;
    int kind = 0;
    const uint8_t *tlv = NULL;
    size_t tlv_size = 0;
    size_t count = 0;

    ASNBER_TEST_CHECK(ctx != NULL);

    /* 空 eContent：显式 `A0 02 04 00`，内容为非 NULL 指针、长度 0。 */
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_open(
                        ctx, kEmptyEcontent, sizeof(kEmptyEcontent),
                        &authenticated) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_econtent(authenticated, &data,
                                                         &data_size) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(data != NULL && data_size == 0);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_econtent_tlv(
                        authenticated, &data, &data_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(data != NULL && data_size == 2);
    ASNBER_TEST_CHECK(data[0] == 0x04 && data[1] == 0x00);
    asnber_cms_authenticated_data_close(authenticated);

    /* 空 mac：`04 00`，同样返回非 NULL 指针、长度 0。 */
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_open(
                        ctx, kEmptyMac, sizeof(kEmptyMac), &authenticated) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_mac(authenticated, &data,
                                                    &data_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(data != NULL && data_size == 0);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_mac_tlv(authenticated, &data,
                                                        &data_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(data != NULL && data_size == 2);
    ASNBER_TEST_CHECK(data[0] == 0x04 && data[1] == 0x00);
    asnber_cms_authenticated_data_close(authenticated);

    /* digestAlgorithm 有、authAttrs 无：读侧不校验二者耦合，照常打开。 */
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_open(
                        ctx, kDigestNoAuthAttrs, sizeof(kDigestNoAuthAttrs),
                        &authenticated) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_digest_algorithm(
                        authenticated, &oid, &oid_size, &parameters,
                        &parameters_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(text_equals(oid, oid_size, kSha256Oid));
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_auth_attrs_tlv(
                        authenticated, &tlv, &tlv_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(tlv == NULL && tlv_size == 0);
    asnber_cms_authenticated_data_close(authenticated);

    /* recipient_at 越界：返回 ASNBER_E_INVALID_ARG，且输出参数被复位。 */
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_open(
                        ctx, kFullInner, sizeof(kFullInner), &authenticated) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_recipient_count(
                        authenticated, &count) == ASNBER_OK);
    ASNBER_TEST_CHECK(count == 2);
    kind = 0;
    tlv = kKtri;
    tlv_size = sizeof(kKtri);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_recipient_at(
                        authenticated, count, &kind, &tlv, &tlv_size) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(kind == -1 && tlv == NULL && tlv_size == 0);
    kind = 0;
    tlv = kKtri;
    tlv_size = sizeof(kKtri);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_recipient_at(
                        authenticated, (size_t)-1, &kind, &tlv, &tlv_size) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(kind == -1 && tlv == NULL && tlv_size == 0);
    /* 越界调用不污染句柄：合法下标仍可读。 */
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_recipient_at(
                        authenticated, 0, &kind, &tlv, &tlv_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(kind == ASNBER_CMS_RECIPIENT_KTRI);
    asnber_cms_authenticated_data_close(authenticated);

    asnber_ctx_destroy(ctx);
    return 0;
}

/* ---------- 负例 ---------- */

static int test_read_negative(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_cms_authenticated_data_t *authenticated = NULL;
    int64_t version = 0;
    size_t count = 0;
    int kind = -1;
    const uint8_t *tlv = NULL;
    size_t tlv_size = 0;
    const char *oid = NULL;
    size_t oid_size = 0;

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_open(
                        NULL, kMinimalInner, sizeof(kMinimalInner),
                        &authenticated) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_open(
                        ctx, NULL, 0, &authenticated) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_open(
                        ctx, kMinimalInner, sizeof(kMinimalInner), NULL) ==
                    ASNBER_E_INVALID_ARG);
    /* ContentInfo 整段不是裸 AuthenticatedData。 */
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_open(
                        ctx, kMinimalContentInfo, sizeof(kMinimalContentInfo),
                        &authenticated) != ASNBER_OK);
    /* 截断。 */
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_open(
                        ctx, kMinimalInner, sizeof(kMinimalInner) - 1,
                        &authenticated) != ASNBER_OK);
    /* 缺 mac。 */
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_open(
                        ctx, kMinimalInner, sizeof(kMinimalInner) - 6,
                        &authenticated) != ASNBER_OK);

    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_version(NULL, &version) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_originator_info_tlv(
                        NULL, &tlv, &tlv_size) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_recipient_count(NULL, &count) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_recipient_at(
                        NULL, 0, &kind, &tlv, &tlv_size) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_mac_algorithm(
                        NULL, &oid, &oid_size, &tlv, &tlv_size) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_digest_algorithm(
                        NULL, &oid, &oid_size, &tlv, &tlv_size) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_econtent_type(
                        NULL, &oid, &oid_size) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_econtent(
                        NULL, &tlv, &tlv_size) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_econtent_tlv(
                        NULL, &tlv, &tlv_size) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_auth_attrs_tlv(
                        NULL, &tlv, &tlv_size) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_mac(NULL, &tlv, &tlv_size) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_mac_tlv(NULL, &tlv,
                                                        &tlv_size) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_unauth_attrs_tlv(
                        NULL, &tlv, &tlv_size) == ASNBER_E_INVALID_ARG);
    asnber_cms_authenticated_data_close(NULL);

    asnber_ctx_destroy(ctx);
    return 0;
}

static int test_builder_negative(void)
{
    /* 非 RecipientInfo 根：OCTET STRING。 */
    static const uint8_t kOctetRoot[4] = {0x04, 0x02, 0x11, 0x22};
    /* 结构合法但根标签不是 [0] / [1]。 */
    static const uint8_t kWrongOriginator[4] = {0xA1, 0x02, 0x05, 0x00};
    static const uint8_t kWrongDigest[4] = {0xA2, 0x02, 0x05, 0x00};
    static const uint8_t kNotSet[4] = {0xA0, 0x02, 0x30, 0x00};
    /* 空 SET：Attributes 至少要有一个 Attribute。 */
    static const uint8_t kEmptySet[2] = {0x31, 0x00};
    asnber_ctx_t *ctx = make_ctx();
    asnber_cms_authenticated_builder_t *builder = NULL;
    asnber_buf_t encoded;
    memset(&encoded, 0, sizeof(encoded));

    ASNBER_TEST_CHECK(ctx != NULL);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_create(NULL, &builder) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_create(ctx, NULL) ==
                    ASNBER_E_INVALID_ARG);

    /* 未设置必填字段：encode 返回状态错误。 */
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_create(ctx, &builder) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_encode(builder, &encoded) ==
                    ASNBER_E_INVALID_STATE);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_encode(builder, NULL) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_encode(NULL, &encoded) ==
                    ASNBER_E_INVALID_ARG);

    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_version(NULL, 0) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_version(builder, 2) ==
                    ASNBER_E_INVALID_VALUE);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_version(builder, 0) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_version(builder, 0) ==
                    ASNBER_E_INVALID_STATE);

    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_add_recipient(
                        builder, NULL, 0) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_add_recipient(
                        builder, kOctetRoot, sizeof(kOctetRoot)) ==
                    ASNBER_E_INVALID_VALUE);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_add_recipient(
                        builder, kKtri, sizeof(kKtri)) == ASNBER_OK);

    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_originator_info(
                        builder, NULL, 0) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_originator_info(
                        builder, kWrongOriginator,
                        sizeof(kWrongOriginator)) == ASNBER_E_INVALID_VALUE);

    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_mac_algorithm(
                        builder, NULL, NULL, 0) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_mac_algorithm(
                        builder, kHmacSha256Oid, NULL, 1) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_mac_algorithm(
                        builder, "1.2.840.113549..2", NULL, 0) != ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_mac_algorithm(
                        builder, kHmacSha256Oid, NULL, 0) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_mac_algorithm(
                        builder, kHmacSha256Oid, NULL, 0) ==
                    ASNBER_E_INVALID_STATE);

    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_digest_algorithm(
                        builder, NULL, 0) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_digest_algorithm(
                        builder, kWrongDigest, sizeof(kWrongDigest)) ==
                    ASNBER_E_INVALID_VALUE);

    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_econtent_type(
                        builder, NULL) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_econtent_type(
                        builder, "1.2.840.113549..1") != ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_econtent_type(
                        builder, kDataOid) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_econtent_type(
                        builder, kDataOid) == ASNBER_E_INVALID_STATE);

    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_auth_attrs(
                        builder, NULL, 0) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_auth_attrs(
                        builder, kNotSet, sizeof(kNotSet)) ==
                    ASNBER_E_INVALID_VALUE);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_unauth_attrs(
                        builder, kNotSet, sizeof(kNotSet)) ==
                    ASNBER_E_INVALID_VALUE);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_auth_attrs(
                        builder, kEmptySet, sizeof(kEmptySet)) ==
                    ASNBER_E_INVALID_VALUE);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_unauth_attrs(
                        builder, kEmptySet, sizeof(kEmptySet)) ==
                    ASNBER_E_INVALID_VALUE);

    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_mac(
                        builder, NULL, 1) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_mac(
                        builder, NULL, 0) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_mac(
                        builder, NULL, 0) == ASNBER_E_INVALID_STATE);

    /* 必填字段齐备、无可选字段：编码成功。 */
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_encode(builder, &encoded) ==
                    ASNBER_OK);
    asnber_buf_release(ctx, &encoded);

    /* version 非 0 但缺 originatorInfo。 */
    asnber_buf_t encoded_v1;
    memset(&encoded_v1, 0, sizeof(encoded_v1));
    asnber_cms_authenticated_builder_destroy(builder);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_create(ctx, &builder) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_version(builder, 1) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_add_recipient(
                        builder, kKtri, sizeof(kKtri)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_mac_algorithm(
                        builder, kHmacSha256Oid, NULL, 0) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_econtent_type(
                        builder, kDataOid) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_mac(
                        builder, kMac, sizeof(kMac)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_encode(builder,
                                                          &encoded_v1) ==
                    ASNBER_E_INVALID_VALUE);
    /* digestAlgorithm 与 authAttrs 必须成对。 */
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_digest_algorithm(
                        builder, kDigestAlgorithm,
                        sizeof(kDigestAlgorithm)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_encode(builder,
                                                          &encoded_v1) ==
                    ASNBER_E_INVALID_VALUE);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_auth_attrs(
                        builder, kAttrs, sizeof(kAttrs)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_encode(builder,
                                                          &encoded_v1) ==
                    ASNBER_E_INVALID_VALUE);

    /* 非 id-data 内容类型必须带 authAttrs。 */
    asnber_buf_release(ctx, &encoded_v1);
    asnber_cms_authenticated_builder_destroy(builder);

    memset(&encoded_v1, 0, sizeof(encoded_v1));
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_create(ctx, &builder) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_version(builder, 0) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_add_recipient(
                        builder, kKtri, sizeof(kKtri)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_mac_algorithm(
                        builder, kHmacSha256Oid, NULL, 0) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_econtent_type(
                        builder, "1.2.840.113549.1.7.2") == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_mac(
                        builder, kMac, sizeof(kMac)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_encode(builder,
                                                          &encoded_v1) ==
                    ASNBER_E_INVALID_VALUE);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_digest_algorithm(
                        builder, kDigestAlgorithm,
                        sizeof(kDigestAlgorithm)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_set_auth_attrs(
                        builder, kAttrs, sizeof(kAttrs)) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_builder_encode(builder,
                                                          &encoded_v1) ==
                    ASNBER_OK);

    asnber_buf_release(ctx, &encoded_v1);
    asnber_cms_authenticated_builder_destroy(builder);
    asnber_cms_authenticated_builder_destroy(NULL);
    asnber_ctx_destroy(ctx);
    return 0;
}

/* ---------- 空集合与读侧标签容忍 ---------- */

static int test_read_semantics(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_cms_authenticated_data_t *authenticated = NULL;
    int64_t version = -1;
    const uint8_t *tlv = NULL;
    size_t tlv_size = 0;
    const char *oid = NULL;
    size_t oid_size = 0;
    const uint8_t *parameters = NULL;
    size_t parameters_size = 0;
    size_t count = 0;

    ASNBER_TEST_CHECK(ctx != NULL);

    /* authAttrs 有、digestAlgorithm 无：读侧不校验两者的耦合。 */
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_open(
                        ctx, kAuthAttrsNoDigest, sizeof(kAuthAttrsNoDigest),
                        &authenticated) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_version(authenticated,
                                                        &version) == ASNBER_OK);
    ASNBER_TEST_CHECK(version == 0);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_auth_attrs_tlv(
                        authenticated, &tlv, &tlv_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(tlv != NULL && tlv_size == sizeof(kAttrs));
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_digest_algorithm(
                        authenticated, &oid, &oid_size, &parameters,
                        &parameters_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(oid == NULL && oid_size == 0);
    ASNBER_TEST_CHECK(parameters == NULL && parameters_size == 0);
    asnber_cms_authenticated_data_close(authenticated);
    authenticated = NULL;

    /* version 5：读侧原样返回，不按 0/1/3 拒绝。 */
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_open(
                        ctx, kVersion5, sizeof(kVersion5),
                        &authenticated) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_version(authenticated,
                                                        &version) == ASNBER_OK);
    ASNBER_TEST_CHECK(version == 5);
    asnber_cms_authenticated_data_close(authenticated);
    authenticated = NULL;

    /* 字段间未知 TLV 静默忽略，其余字段照常投影。 */
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_open(
                        ctx, kUnknownBetween, sizeof(kUnknownBetween),
                        &authenticated) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_recipient_count(
                        authenticated, &count) == ASNBER_OK);
    ASNBER_TEST_CHECK(count == 1);
    asnber_cms_authenticated_data_close(authenticated);
    authenticated = NULL;

    /* 尾随数据：拒绝。 */
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_open(
                        ctx, kTrailingData, sizeof(kTrailingData),
                        &authenticated) == ASNBER_E_TRAILING_DATA);
    ASNBER_TEST_CHECK(authenticated == NULL);

    asnber_ctx_destroy(ctx);
    return 0;
}

static int test_empty_sets(void)
{
    asnber_ctx_t *ctx = make_ctx();
    asnber_cms_authenticated_data_t *authenticated = NULL;
    const uint8_t *tlv = NULL;
    size_t tlv_size = 0;

    ASNBER_TEST_CHECK(ctx != NULL);

    /* recipientInfos 为空 SET：描述表 `SET SIZE (1..MAX)` 生效。 */
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_open(
                        ctx, kEmptyRecipients, sizeof(kEmptyRecipients),
                        &authenticated) == ASNBER_E_SCHEMA_CONSTRAINT);
    ASNBER_TEST_CHECK(authenticated == NULL);

    /* authAttrs 为空（`A2 00`）：`AuthAttributes ::= SET SIZE (1..MAX)` 生效。 */
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_open(
                        ctx, kEmptyAuthAttrs, sizeof(kEmptyAuthAttrs),
                        &authenticated) == ASNBER_E_SCHEMA_CONSTRAINT);
    ASNBER_TEST_CHECK(authenticated == NULL);

    /* unauthAttrs 为空（`A3 00`）：`UnauthAttributes ::= SET SIZE (1..MAX)` 生效。 */
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_open(
                        ctx, kEmptyUnauthAttrs, sizeof(kEmptyUnauthAttrs),
                        &authenticated) == ASNBER_E_SCHEMA_CONSTRAINT);
    ASNBER_TEST_CHECK(authenticated == NULL);

    /*
     * 错标签：`A2 00` 出现在 mac 之后（unauthAttrs 的位置），按未知字段
     * 静默忽略，打开成功且 authAttrs 投影为空。读侧不启用
     * `ASNBER_DECODE_STRICT_SCHEMA`。
     */
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_open(
                        ctx, kUnknownA2Tail, sizeof(kUnknownA2Tail),
                        &authenticated) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_authenticated_data_auth_attrs_tlv(
                        authenticated, &tlv, &tlv_size) == ASNBER_OK);
    ASNBER_TEST_CHECK(tlv == NULL && tlv_size == 0);
    asnber_cms_authenticated_data_close(authenticated);

    asnber_ctx_destroy(ctx);
    return 0;
}

int main(void)
{
    if (test_read_semantics() != 0) {
        return 1;
    }
    if (test_empty_sets() != 0) {
        return 1;
    }
    if (test_minimal() != 0) {
        return 1;
    }
    if (test_content_info_wrapping() != 0) {
        return 1;
    }
    if (test_synthetic_sample() != 0) {
        return 1;
    }
    if (test_full() != 0) {
        return 1;
    }
    if (test_builder_minimal() != 0) {
        return 1;
    }
    if (test_builder_full() != 0) {
        return 1;
    }
    if (test_builder_version1() != 0) {
        return 1;
    }
    if (test_static_v1_sample() != 0) {
        return 1;
    }
    if (test_static_v3_sample() != 0) {
        return 1;
    }
    if (test_builder_v3_crls() != 0) {
        return 1;
    }
    if (test_read_edge_cases() != 0) {
        return 1;
    }
    if (test_read_negative() != 0) {
        return 1;
    }
    if (test_builder_negative() != 0) {
        return 1;
    }
    return 0;
}
