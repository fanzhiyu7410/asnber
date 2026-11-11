# asnber-cms

CMS / PKCS#7 标准结构模块（RFC 5652），以 `.asn1` 描述表驱动，提供**只读结构访问**与**结构构造（写）**两类能力。

## 模块范围

当前切片覆盖 4 个顶层结构：`ContentInfo`、`SignedData`、`EnvelopedData`、`EncryptedData` 均支持只读打开；后三者另提供结构构造（写）：

| 结构 | 标准 | 说明 |
| --- | --- | --- |
| `ContentInfo` | RFC 5652 §3 | `contentType` + `content [0] EXPLICIT ANY` |
| `SignedData` | RFC 5652 §5 | 版本、摘要算法、封装内容、证书、CRL、签名者信息 |
| `EnvelopedData` | RFC 5652 §6 | 只读 + 写：版本、originatorInfo、recipientInfos 五分支、加密内容信息、unprotectedAttrs |
| `EncryptedData` | RFC 5652 §8 | 只读 + 写：版本、加密内容信息、unprotectedAttrs |

**不包含**：签名生成/验签、摘要计算、加解密、证书链校验、吊销状态查询、属性语义解析。结构构造只按 RFC 5652 组装节点并输出 DER；`CMSVersion`、算法 OID、eContent、签名值与证书/CRL 原始 DER 全部由调用方给值并原样承载，模块不推导、不校验业务范围。`ANY` 与属性集合只读写原始 TLV，密码学语义由调用方按 OID 二次解析。

后续规划：`AuthenticatedData`、`CompressedData` 后置，不在 0.2.0 实现。

## 公共头与链接

- 公共头：`asnber/cms/cms.h`
- 链接目标：`asnber::cms::shared` 或 `asnber::cms::static`
- 构建开关：`-DASNBER_BUILD_MODULE_CMS=ON`

`asnber-cms` 是独立包，可独立安装后用 `find_package(asnber-cms CONFIG REQUIRED)` 消费。只依赖核心公共 C ABI，**不依赖 asnber-pkix**（ADR-0012）。

## 句柄与生命周期

4 个只读不透明句柄各由 `open` 创建、`close` 销毁：

- `asnber_cms_content_info_open` / `asnber_cms_content_info_close`
- `asnber_cms_signed_data_open` / `asnber_cms_signed_data_close`
- `asnber_cms_enveloped_data_open` / `asnber_cms_enveloped_data_close`
- `asnber_cms_encrypted_data_open` / `asnber_cms_encrypted_data_close`

约束：

- `open` 接收 DER 字节并复制进内部文档 arena，返回后调用方可释放输入缓冲。
- 句柄借用调用方的 `asnber_ctx_t`，**ctx 必须比句柄存活更久**。
- 每次 `open` 加载一次描述表并构建上下文级 schema，生命周期到 `close`；无全局缓存、无进程级单例。
- 所有访问器返回的指针（OID 文本、大整数十进制文本、字节/TLV）均**借用句柄**，`close` 后立即失效，不得释放。
- `close(NULL)` 为空操作；`open` 失败时 `*out_*` 置 `NULL` 并返回核心错误码。
- 构造侧句柄 `asnber_cms_builder_t` / `asnber_cms_enveloped_builder_t` / `asnber_cms_encrypted_builder_t` 各由对应 `*_create` 创建、`*_destroy` 销毁；`destroy(NULL)` 为空操作，**同一句柄只能 destroy 一次**（重复 destroy 或使用已销毁指针为未定义行为；句柄指针归调用方所有，库无法置空）。builder 借用 `ctx`，须在 `ctx` 销毁前 destroy，跨 `ctx` 使用未定义。输入字节在设置/追加调用返回时已复制，调用方可立即释放原缓冲。
- 模块无全局可变状态；不同句柄互不影响。同一 `ctx` 的并发使用需由调用方加锁。

## API 概览

### ContentInfo

| 访问器 | 返回 |
| --- | --- |
| `asnber_cms_content_info_content_type` | `contentType` OID 点分十进制文本 |
| `asnber_cms_content_info_content` | `content` 内层 ANY 的完整原始 TLV（不含 `[0]` 包装），可直接交给 `asnber_cms_signed_data_open` |

### SignedData

| 访问器 | 返回 |
| --- | --- |
| `asnber_cms_signed_data_version` | `CMSVersion` 原值，不做范围校验 |
| `asnber_cms_signed_data_digest_algorithm_count` / `_at` | 摘要算法条目数；每项 `algorithm` OID + `parameters` 原始 TLV |
| `asnber_cms_signed_data_encap_content_type` | `eContentType` OID |
| `asnber_cms_signed_data_encap_content` / `_tlv` | `eContent` 的 OCTET STRING 内容字节 / 完整 TLV |
| `asnber_cms_signed_data_certificate_count` / `_at` | 证书条目数；每项分支判别（`ASNBER_CMS_CERT_CHOICE_*`）+ 原始 TLV |
| `asnber_cms_signed_data_certificate_subject` / `_issuer` / `_serial` | 仅证书分支：`TBSCertificate` 的 subject/issuer 原始 TLV、serialNumber 十进制文本；扩展证书、AttributeCertificate v1/v2 与 other 分支返回 `ASNBER_E_UNSUPPORTED`（`certificate_at` 仍给分支与完整原始 TLV） |
| `asnber_cms_signed_data_crl_count` / `_at` | CRL 条目数；每项分支判别（`ASNBER_CMS_REVOCATION_CHOICE_*`）+ 原始 TLV |
| `asnber_cms_signed_data_signer_count` | `signerInfos` 条目数 |
| `asnber_cms_signed_data_signer_version` | `SignerInfo.version` 原值 |
| `asnber_cms_signed_data_signer_sid_choice` / `_sid_issuer` / `_sid_serial` / `_sid_subject_key_identifier` | `sid` 分支判别与对应字段 |
| `asnber_cms_signed_data_signer_digest_algorithm` | `digestAlgorithm` OID + `parameters` 原始 TLV |
| `asnber_cms_signed_data_signer_signed_attrs` / `_unsigned_attrs` | `[0]` / `[1]` IMPLICIT 属性集合的完整 TLV（含标签） |
| `asnber_cms_signed_data_signer_signature_algorithm` | `signatureAlgorithm` OID + `parameters` 原始 TLV |
| `asnber_cms_signed_data_signer_signature` / `_tlv` | `signature` OCTET STRING 内容字节 / 完整 TLV |

缺省字段（detached 的 `eContent`、无证书/CRL、无 `signedAttrs`/`unsignedAttrs`）返回 `ASNBER_OK` 且 `NULL/0`；下标越界返回 `ASNBER_E_INVALID_ARG`。

### EnvelopedData（只读，0.2.0 第一块）

`asnber_cms_enveloped_data_open` 只接受**裸 `EnvelopedData`**：先用 `asnber_cms_content_info_open` + `asnber_cms_content_info_content` 取 `[0]` 内层 TLV 再传入。`recipientInfos` 的 `SET SIZE (1..MAX)` 由描述表生效，空集合返回 `ASNBER_E_SCHEMA_CONSTRAINT`。

| 访问器 | 返回 |
| --- | --- |
| `_version` | `CMSVersion` 原值，不做范围校验 |
| `_originator_info_tlv` | `[0]` 完整原始 TLV；缺省 `NULL/0` |
| `_recipient_count` / `_recipient_choice` / `_recipient_tlv` | 条目数；分支判别 `ASNBER_CMS_RECIPIENT_*`；该分支完整原始 TLV |
| `_recipient_version` / `_recipient_key_encryption_algorithm` | `ktri`/`kari`/`kekri`/`pwri` 的版本与算法（OID + parameters 原始 TLV）；`ori` 返回 `ASNBER_E_UNSUPPORTED` |
| `_recipient_encrypted_key` | `ktri`/`kekri`/`pwri` 的 `encryptedKey` 内容字节 |
| `_recipient_kekri_key_identifier` | `kekri` 的 `kekid.keyIdentifier` 内容字节 |
| `_recipient_pwri_key_derivation_algorithm_tlv` | `pwri` 的 `[0] IMPLICIT` 完整 TLV；字段缺省 `NULL/0` |
| `_recipient_ori_type` / `_recipient_ori_value_tlv` | `ori` 的 OID 文本与 `oriValue` 完整原始 TLV |
| `_recipient_rid_choice` / `_rid_issuer_tlv` / `_rid_serial_tlv` / `_rid_serial_decimal` / `_rid_subject_key_id` | `ktri.rid` 分支判别与字段；issuer 不解析 RDN，serial 给严格十进制文本 |
| `_recipient_originator_choice` / `_recipient_originator_tlv` | `kari.originator` 判别（`ASNBER_CMS_ORIGINATOR_*`）与 `[0] EXPLICIT` 完整 TLV |
| `_recipient_kari_encrypted_key_count` | `kari.recipientEncryptedKeys` 元素个数 |
| `_content_type` / `_content_encryption_algorithm` | `EncryptedContentInfo.contentType` 与内容加密算法（OID + parameters 原始 TLV） |
| `_encrypted_content` / `_encrypted_content_tlv` | `[0] IMPLICIT OCTET STRING` 的合并内容字节 / 完整 TLV（不分段） |
| `_unprotected_attrs_tlv` | `[1] IMPLICIT` 属性集合完整原始 TLV；缺省 `NULL/0` |

分支不适用统一返回 `ASNBER_E_UNSUPPORTED`，下标越界 `ASNBER_E_INVALID_ARG`。只读边界：不解密、不做密钥协商、不做 KEK/口令派生、不校验 MAC。

### EncryptedData（只读，0.2.0 第三块）

`asnber_cms_encrypted_data_open` 只接受**裸 `EncryptedData`**：先用 `asnber_cms_content_info_open` + `asnber_cms_content_info_content` 取 `[0]` 内层 TLV 再传入。`version` 原样返回；RFC 5652 的版本配对约束（无 `unprotectedAttrs` 时为 0、有时为 2）不在 `open` 阶段校验，由调用方断言。

| 访问器 | 返回 |
| --- | --- |
| `_version` | `CMSVersion` 原值，不做范围校验 |
| `_content_type` / `_content_encryption_algorithm` | `EncryptedContentInfo.contentType` 与内容加密算法（OID + parameters 原始 TLV） |
| `_encrypted_content` / `_encrypted_content_tlv` | `[0] IMPLICIT OCTET STRING` 的内容字节 / 完整 TLV（不分段）；空内容 `80 00` 返回非 `NULL` 指针且 `size == 0`，字段缺省返回 `NULL/0` |
| `_unprotected_attrs_tlv` | `[1] IMPLICIT` 属性集合完整原始 TLV；缺省 `NULL/0` |

只读边界：不解密、不派生密钥、不校验 MAC、不展开算法参数或属性内容。

### 结构构造（写）

| 接口 | 说明 |
| --- | --- |
| `asnber_cms_builder_create` / `asnber_cms_builder_destroy` | 创建/销毁 builder；`destroy(NULL)` 为空操作，同一句柄只能 destroy 一次 |
| `asnber_cms_builder_set_version` | `CMSVersion`，必填；显式给值，不推导、不校验范围；重复设置 `ASNBER_E_INVALID_STATE` |
| `asnber_cms_builder_add_digest_algorithm` | 追加 `digestAlgorithm`（至少一条）；`params` 为空表示 parameters 缺省 |
| `asnber_cms_builder_set_econtent_type` | `eContentType` OID，必填；重复设置 `ASNBER_E_INVALID_STATE` |
| `asnber_cms_builder_set_econtent` | 设置 `eContent`（完整 DER OCTET STRING TLV）；不设置即 detached |
| `asnber_cms_builder_add_certificate` / `add_crl` | 追加证书/CRL 原始 DER；校验单 TLV 与分支根标签，输出按 DER `SET OF` 排序 |
| `asnber_cms_builder_add_signer` | 追加 `SignerInfo`（至少一条）；两种 `sid`、可选 `signedAttrs`/`unsignedAttrs` |
| `asnber_cms_builder_encode` | 组装并编码 `ContentInfo`（`contentType = id-signedData`）到调用方缓冲 |

`EnvelopedData` 使用独立句柄 `asnber_cms_enveloped_builder_t`：

| 接口 | 说明 |
| --- | --- |
| `asnber_cms_enveloped_builder_create` / `_destroy` | 创建/销毁 builder；`destroy(NULL)` 为空操作，同一句柄只能 destroy 一次 |
| `asnber_cms_enveloped_builder_set_version` | `EnvelopedData.version`，必填；重复设置 `ASNBER_E_INVALID_STATE` |
| `asnber_cms_enveloped_builder_set_originator_info` | 设置 `[0] IMPLICIT OriginatorInfo` 完整 TLV（0xA0）；可含 0..2 个子 TLV（`certs`、`crls` 均可选） |
| `asnber_cms_enveloped_builder_add_ktri` | 追加 `ktri`；`rid` 支持 issuerAndSerialNumber 与 subjectKeyIdentifier |
| `asnber_cms_enveloped_builder_add_kari` | 追加 `kari`；`originator [0] EXPLICIT`、可选 `ukm [1] EXPLICIT`、`recipientEncryptedKeys` 均以完整 TLV 传入 |
| `asnber_cms_enveloped_builder_add_kekri` | 追加 `kekri`；`KEKIdentifier` 以完整 SEQUENCE TLV 传入 |
| `asnber_cms_enveloped_builder_add_pwri` | 追加 `pwri`；可选 `[0] IMPLICIT AlgorithmIdentifier` KDF TLV |
| `asnber_cms_enveloped_builder_add_ori` | 追加 `ori`；`oriType` OID + `oriValue` 完整 TLV |
| `asnber_cms_enveloped_builder_set_content_type` | `EncryptedContentInfo.contentType`，必填 |
| `asnber_cms_enveloped_builder_set_content_encryption_algorithm` | 内容加密算法，必填 |
| `asnber_cms_enveloped_builder_set_encrypted_content` | `encryptedContent` 内容字节；不设置即 detached，允许空内容 |
| `asnber_cms_enveloped_builder_set_unprotected_attrs` | `[1] IMPLICIT SET OF Attribute`；输入 0x31，模块改写为 0xA1 |
| `asnber_cms_enveloped_builder_encode` | 组装并编码 `ContentInfo`（`contentType = id-envelopedData`）到调用方缓冲 |

`EncryptedData` 使用独立句柄 `asnber_cms_encrypted_builder_t`：

| 接口 | 说明 |
| --- | --- |
| `asnber_cms_encrypted_builder_create` / `_destroy` | 创建/销毁 builder；`destroy(NULL)` 为空操作，同一句柄只能 destroy 一次 |
| `asnber_cms_encrypted_builder_set_version` | `EncryptedData.version`，必填；只接受 `0`/`2`，其他值立即返回 `ASNBER_E_INVALID_VALUE`；与 `unprotectedAttrs` 的配对在 `encode` 校验 |
| `asnber_cms_encrypted_builder_set_content_type` | `EncryptedContentInfo.contentType`，必填 |
| `asnber_cms_encrypted_builder_set_content_encryption_algorithm` | 内容加密算法，必填 |
| `asnber_cms_encrypted_builder_set_encrypted_content` | `encryptedContent` 内容字节；不设置即 detached，允许空内容 |
| `asnber_cms_encrypted_builder_set_unprotected_attrs` | `[1] IMPLICIT SET OF Attribute`；输入 `0x31`，模块改写为 `0xA1` |
| `asnber_cms_encrypted_builder_encode` | 校验必填项与版本配对，编码 `ContentInfo`（`contentType = id-encryptedData`）到调用方缓冲 |

`EncryptedData` 的 `set_version` 只接受 `0`/`2`，其他值立即返回 `ASNBER_E_INVALID_VALUE`；`encode` 再强制配对：有 `unprotectedAttrs` 必须 `version == 2`，无 `unprotectedAttrs` 必须 `version == 0`，不一致返回 `ASNBER_E_INVALID_VALUE`。这与 `SignedData.version` 故意不同：后者取决于证书分支/`eContent` 等语义组合，交给调用方；`EncryptedData` 只有两档且与属性是否出现一一绑定，属于机械规则。模块不推导、不改写版本。detached 与空密文严格区分：不调用 `set_encrypted_content` 输出中无 `[0]` 字段，调用且 `size == 0` 输出 `80 00`。

语义约定：

- **版本**：`CMSVersion` 与 `SignerInfo.version` 由调用方显式给值，模块不推导、不校验范围。
- **signedAttrs 原样承载**：输入必须是完整、规范的 `SET OF Attribute`（外层 `0x31`，非空且元素为 `SEQUENCE`）；模块只把外层标签改写为 `0xA0`（`unsignedAttrs` 为 `0xA1`），长度字节与内容逐字节不变，不重建、不排序。签名覆盖的是 `SET OF` 编码，调用方必须对同一份字节签名，否则验签失败。非规范输入返回 `ASNBER_E_NON_CANONICAL`，空集合或元素不是 `SEQUENCE` 返回 `ASNBER_E_INVALID_VALUE`。
- **证书/CRL 不解析**：除“恰好一个完整规范 DER TLV”外，只检查分支根标签——证书须为 `Certificate` 的 `SEQUENCE` 或 `CertificateChoices` 的 `[0..3]` 备选，CRL 须为 `CertificateList` 的 `SEQUENCE` 或 `RevocationInfoChoice` 的 `other [1]`；不解析内部、不做信任判断；输出按 DER `SET OF` 规则排序。
- **sid 根标签**：`issuerAndSerialNumber` 形式的 `issuer` 须为 `SEQUENCE`、`serialNumber` 须为 `INTEGER`；不符返回 `ASNBER_E_INVALID_VALUE`。
- **`signerInfos` / `recipientInfos`**：SignedData 没有签名者时必须至少有一张证书或一份 CRL，此时 `digestAlgorithms` 可以为空（certificates-only / CRL-only）。有签名者时仍要求至少一条 digestAlgorithm。EnvelopedData 的 `encode` 仍要求至少一条 recipient。只读侧空 `signerInfos` 可成功 `open` 且 `signer_count` 返回 0。
- **EnvelopedData 写侧不推导版本**：`version` 与各 `RecipientInfo.version` 均显式给值；不做密钥协商、KEK/口令派生、内容加密或 MAC 计算，`encryptedKey` / `encryptedContent` 由调用方给值并原样承载。
- **错误模型**：必填缺失、重复设置单值字段返回 `ASNBER_E_INVALID_STATE`；OID 非法、根标签/分支不符返回 `ASNBER_E_INVALID_VALUE`；非单一合法 TLV 返回 `ASNBER_E_TRUNCATED` / `ASNBER_E_MALFORMED_LENGTH` / `ASNBER_E_TRAILING_DATA` / `ASNBER_E_NON_CANONICAL` 等核心错误码。失败不产出半成品缓冲。
- **输出所有权**：成功时 `asnber_buf_t` 由上下文分配，调用方用 `asnber_buf_release` 归还。

## 最小示例

```c
#include <asnber/asnber.h>
#include <asnber/cms/cms.h>

asnber_ctx_config_t config;
asnber_ctx_config_init(&config);
asnber_ctx_t *ctx = NULL;
asnber_ctx_create(&config, &ctx);

asnber_cms_content_info_t *info = NULL;
if (asnber_cms_content_info_open(ctx, der, der_size, &info) == ASNBER_OK) {
    const char *type = NULL;
    size_t type_size = 0;
    asnber_cms_content_info_content_type(info, &type, &type_size);

    const uint8_t *content = NULL;
    size_t content_size = 0;
    /* content 是被封装结构的完整 TLV，可直接打开 SignedData */
    asnber_cms_content_info_content(info, &content, &content_size);

    asnber_cms_signed_data_t *signed_data = NULL;
    asnber_cms_signed_data_open(ctx, content, content_size, &signed_data);

    /* ... 读取 signerInfos / certificates ... */

    asnber_cms_signed_data_close(signed_data);
    asnber_cms_content_info_close(info);
}
asnber_ctx_destroy(ctx);
```

构造侧示例（detached，最小字段）：

```c
asnber_cms_builder_t *builder = NULL;
if (asnber_cms_builder_create(ctx, &builder) == ASNBER_OK) {
    asnber_cms_builder_set_version(builder, 1);
    asnber_cms_builder_add_digest_algorithm(
        builder, "2.16.840.1.101.3.4.2.1", NULL, 0);
    asnber_cms_builder_set_econtent_type(builder, "1.2.840.113549.1.7.1");
    /* 不调用 set_econtent 即 detached */
    asnber_cms_builder_add_signer(
        builder, 1, ASNBER_CMS_SID_ISSUER_AND_SERIAL,
        issuer_tlv, issuer_size, serial_tlv, serial_size,
        "2.16.840.1.101.3.4.2.1", NULL, 0,
        NULL, 0, "1.2.840.113549.1.1.1", NULL, 0,
        signature, signature_size, NULL, 0);

    asnber_buf_t der;
    if (asnber_cms_builder_encode(builder, &der) == ASNBER_OK) {
        /* 使用 der.data / der.size */
        asnber_buf_release(ctx, &der);
    }
    asnber_cms_builder_destroy(builder);
}
```

## 证书分支与原始 TLV

`certificates` 是 `[0] IMPLICIT SET OF CertificateChoices`，模块按实际标签判别分支：

| 分支 | DER 标签 | 常量 |
| --- | --- | --- |
| `certificate` | `0x30`（SEQUENCE） | `ASNBER_CMS_CERT_CHOICE_CERTIFICATE` |
| `extendedCertificate` | `0xA0` | `ASNBER_CMS_CERT_CHOICE_EXTENDED` |
| `v1AttrCert` | `0xA1` | `ASNBER_CMS_CERT_CHOICE_V1_ATTR_CERT` |
| `v2AttrCert` | `0xA2` | `ASNBER_CMS_CERT_CHOICE_V2_ATTR_CERT` |
| `other` | `0xA3` | `ASNBER_CMS_CERT_CHOICE_OTHER` |

属性证书分支在展平模块中是 `SEQUENCE { ... }` 不透明占位：可取得完整原始 TLV，但不能结构化读取内部字段。`subject`/`issuer`/`serial` 访问器只对 `certificate` 分支有效。

## 描述表来源与重生成

展平 ASN.1 源在 `modules/cms/asn1/CMS-Flattened-5652.asn1`，**整个文件只生成一张表** `cms_schema`（19,024 字节，头部默认根 `ContentInfo`），产物检入 `modules/cms/generated/`（`.bin` + 描述头 `.h`）。默认构建不依赖 `asnberc`。

同一文件的其余顶层结构通过 `asnber_schema_load_with_root` 在加载期指定根类型编号：`SignedData=3`、`EnvelopedData=48`、`EncryptedData=72`、`CompressedData=73`、`AuthenticatedData=75`。编号取自原多表产物 `.bin` 头部偏移 96（小端 `uint32`），登记在 `src/cms_tables.h`，并由 `scripts/refactor_baseline.py` 复核“登记根 ≤ type_count”。

**类型 id 是描述表内部引用，会随模块类型增长而重排；逐字节不变不是回归契约。** 回归依据是 `ctest` 全绿，以及 `-DASNBER_CMS_REGENERATE_TABLE=ON` 下 `asnber_cms_table_verify` 对单表的逐字节自校验。2026-11-07 追加 `EnvelopedData` 时合成类型 id +24、字符串池插入点变化，见 `asnber/reconciliation.md` 第 7 节；2026-11-08 追加 `EncryptedData` 时合成类型 id +1、新增一个合成类型，见第 8 节。

```powershell
cmake -G Ninja -B build-cms-regen -DASNBER_BUILD_TOOLS=ON -DASNBER_CMS_REGENERATE_TABLE=ON
cmake --build build-cms-regen --target asnber_cms_table_verify
```

来源、复制范围、逐类型对账与勘误核对见 `modules/cms/asn1/README.md` 与 `modules/cms/asn1/reconciliation.md`。

## 测试

- 样本：`tests/data/cms_rsa_attached.der`（attached，证书 + signedAttrs）、`cms_rsa_detached.der`（detached，证书 + signedAttrs）、`cms_rsa_minimal.der`（无证书、无 signedAttrs）、`cms_rsa_ec_multicert.der`（RSA + ECDSA 多证书多签名者）、`cms_rsa_keyid.der`（sid 为 subjectKeyIdentifier），`cms_enveloped_ktri.der` / `cms_enveloped_ktri_multi.der` / `cms_enveloped_kari.der` / `cms_enveloped_kekri.der` / `cms_enveloped_pwri.der`（`openssl cms -encrypt` 真实生成），以及 `cms_encrypted_data.der`（`openssl cms -EncryptedData_encrypt` 生成，version 0、AES-256-CBC）。由 `python scripts/gen_test_data.py --cms --cms-enveloped --cms-encrypted` 生成。
- 用例：`tests/cms/test_cms_structures.c`，覆盖正例字段读取、detached 无 `eContent`、多证书逐项、SignerInfo 各字段（含两种 sid 分支）、空参/非 CMS/截断负例。
- 用例：`tests/cms/test_cms_enveloped.c`（ktri/多收件人/kari/kekri/pwri 真实样本字段、构造级 `ori` 正例、空 `recipientInfos` 与截断负例）与 `test_cms_enveloped_roundtrip.c`（5 份样本 ContentInfo 整段与内层裸 TLV 的 decode→encode 逐字节往返）。`kekri`/`pwri` 使用真实 openssl 样本；`ori` 无 openssl 生成选项，仅构造级正例 + 截断负例，**该分支未用真实样本验证**。
- 构造用例：`tests/cms/test_cms_builder.c`，覆盖 attached/detached、单/多证书、两种 `sid`、带 `signedAttrs`、无证书最小样本、v1/v2 `AttributeCertificate` 分支（`certificate_at` 保留判别与原始 TLV，结构化访问器返回 `ASNBER_E_UNSUPPORTED`）、必填缺失/重复设置/非法 TLV 负例；5 份样本做 decode → builder 重建 → 编码，规范 DER 源逐字节一致。
- `EncryptedData` 用例：`tests/cms/test_cms_encrypted.c`，覆盖 detached / 空密文 `80 00` / version 2 + `unprotectedAttrs` / 缺少 `encryptedContentInfo` 负例，OpenSSL version 0 真实样本，builder 46 字节 detached 与 62 字节 version 2 输出的逐字节断言、带内容往返、版本配对与必填/重复设置负例。
- 同时纳入差分（OpenSSL `asn1parse` 逐样本对照）与 fuzz 语料。

## 状态

0.1.0：ContentInfo / SignedData 只读字段访问与结构构造（builder + DER 编码）；只读与构造 C 用例在 MinGW（GCC 13.2，`-Werror`）、MSVC 与 ASan/UBSan 构建下 ctest 通过，5 份样本构造往返逐字节一致。证书集合覆盖 `certificate`/`extendedCertificate`/`v1AttrCert`/`v2AttrCert`/`other` 全部分支：`certificate_at` 一律返回判别与完整原始 TLV，结构化访问器只对 `certificate` 生效，其余分支返回 `ASNBER_E_UNSUPPORTED`。构造侧不生成签名/摘要、不做加解密、不校验证书链。没有签名者时可以输出 certificates-only 或 CRL-only，`digestAlgorithms` 允许为空；三者全空仍然拒绝。有签名者时仍要求至少一条 digestAlgorithm。

0.2.0 第一块（未发版，`Unreleased`）：新增 `EnvelopedData` 只读句柄与 27 个导出符号；五份真实样本 + `ori` 构造级用例 + 空 `recipientInfos` 负例 + 整段往返。MinGW GCC 13 Release（共享/静态）全量 ctest 36/36 通过，`-DASNBER_CMS_REGENERATE_TABLE=ON` 下三表逐字节自校验通过。

0.2.0 第二块（未发版）：新增 `EnvelopedData` 写侧 builder 与 14 个导出符号；六份真实样本重建逐字节一致，子结构按描述式规则校验标签/构造位/顺序/重复，空密文与 detached 区分。MinGW 与 ASan/UBSan 全量 ctest 37/37 通过。

0.2.0 第三、四块（未发版）：新增 `EncryptedData` 只读句柄与写侧 builder，共 16 个导出符号；OpenSSL version 0 真实样本、version 2 + `unprotectedAttrs` 构造级逐字节断言、版本配对校验、空密文与 detached 区分、属性集合 `0x31`→`0xA1` 改写。MinGW GCC 13 Release（共享/静态）与 ASan/UBSan 全量 ctest 38/38 通过，`asnber-cms` 导出 100/100 与基线一致，`-DASNBER_CMS_REGENERATE_TABLE=ON` 下四表逐字节自校验通过。
