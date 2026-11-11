# CMS 展平模块对账表（RFC 5652 → CMS-Flattened-5652）

本表逐类型记录 [CMS-Flattened-5652.asn1](CMS-Flattened-5652.asn1) 的来源、处理方式与代价。
对账基准：

- 结构来源：[reference/rfc5652/rfc5652.txt](reference/rfc5652/rfc5652.txt) 第 12.1 节（CryptographicMessageSyntax2004）。
- PKIX 类型来源：[../pkix/asn1/PKIX-Flattened-2009.asn1](../../pkix/asn1/PKIX-Flattened-2009.asn1)（由 RFC 5912 第 2、3、14 节展平）。
- 复制范围判据：**只复制从 `SignedData` 可达的类型**，不做整表搬运。

## 1. 总体处理

| 项 | 处理 | 代价 |
| --- | --- | --- |
| `IMPORTS` | 不保留任何 `IMPORTS`；把 `AlgorithmIdentifier`、`Certificate`、`CertificateList`、`CertificateSerialNumber`、`Name` 及其可达依赖复制进本模块 | 类型定义在 `asnber-pkix` 与 `asnber-cms` 中重复出现；两模块需各自维护，修改时须同步核对 |
| PKIX 类型范围 | 只带出 `SignedData` 可达子集（见第 3 节“未复制”清单） | `Certificate` 的结构化访问（subject/issuer/serial）可用；其余 PKIX 类型不进入本模块 |
| `CertificateChoices` 属性证书分支 | `v1AttrCert`、`v2AttrCert` 不展开 RFC 3281 结构，改为 `SEQUENCE { ... }` 不透明占位 | 调用方可按分支判别并取得完整原始 TLV，但不能结构化读取属性证书内部字段 |
| 开放类型 | `content`、`parameters`、`otherCert`、`otherRevInfo`、`attrValues`、`AttributeValue` 使用裸 `ANY` | 保留完整原始 TLV、原样写回；不能按 OID/类型自动展开，需调用方二次解析 |
| `CMSVersion` | 原版 `INTEGER { v0(0) ... v5(5) }` 改为无约束 `INTEGER` | 值名不参与结构访问；非 RFC 定义值也能按原值返回，不在解码期被值名约束拒绝 |
| 描述表粒度 | 同一模块按根 `ContentInfo`、`SignedData`、`EnvelopedData`、`EncryptedData` 各生成一张表 | 四张表都包含整模块的类型记录（当前各 17304 字节），存在重复；换取四个顶层结构可直接 open |

## 2. 逐类型对账

“原样”表示名称、字段、顺序、`OPTIONAL`/`DEFAULT`、标签与约束均与来源一致（仅去除来源模块的 `IMPORTS` 依赖）。

| # | 类型 | 来源 | 处理 | 说明 |
| --- | --- | --- | --- | --- |
| 1 | `ContentInfo` | RFC 5652 §12.1 | 原样 | `content [0] EXPLICIT ANY` 保留显式标签 |
| 2 | `ContentType` | RFC 5652 §12.1 | 原样 | `OBJECT IDENTIFIER` |
| 3 | `SignedData` | RFC 5652 §12.1 | 原样 | `certificates [0] IMPLICIT`、`crls [1] IMPLICIT` 保留隐式标签 |
| 4 | `DigestAlgorithmIdentifiers` | RFC 5652 §12.1 | 原样 | `SET OF DigestAlgorithmIdentifier` |
| 5 | `DigestAlgorithmIdentifier` | RFC 5652 §12.1 | 原样 | 指向复制的 `AlgorithmIdentifier` |
| 6 | `EncapsulatedContentInfo` | RFC 5652 §12.1 | 原样 | `eContent [0] EXPLICIT OCTET STRING OPTIONAL` |
| 7 | `SignerInfos` | RFC 5652 §12.1 | 原样 | `SET OF SignerInfo` |
| 8 | `SignerInfo` | RFC 5652 §12.1 | 原样 | `signedAttrs [0] IMPLICIT`、`unsignedAttrs [1] IMPLICIT` 保留隐式标签 |
| 9 | `SignerIdentifier` | RFC 5652 §12.1 | 原样 | CHOICE：`issuerAndSerialNumber` / `subjectKeyIdentifier [0]` |
| 10 | `SignedAttributes` | RFC 5652 §12.1 | 原样 | `SET SIZE (1..MAX) OF Attribute` |
| 11 | `UnsignedAttributes` | RFC 5652 §12.1 | 原样 | 同上 |
| 12 | `Attribute` | RFC 5652 §12.1 | 原样 | `attrType` + `attrValues SET OF ANY` |
| 13 | `AttributeValue` | RFC 5652 §12.1 | 原样 | 裸 `ANY` |
| 14 | `SignatureValue` | RFC 5652 §12.1 | 原样 | `OCTET STRING` |
| 15 | `SignatureAlgorithmIdentifier` | RFC 5652 §12.1 | 原样 | 指向复制的 `AlgorithmIdentifier` |
| 16 | `SubjectKeyIdentifier` | RFC 5652 §12.1 | 原样 | `OCTET STRING`；PKIX1Implicit-2009 有同义类型，本模块只保留这一份 |
| 17 | `RevocationInfoChoices` | RFC 5652 §12.1 | 原样 | `SET OF RevocationInfoChoice` |
| 18 | `RevocationInfoChoice` | RFC 5652 §12.1 | 原样 | CHOICE：`crl` / `other [1] IMPLICIT` |
| 19 | `OtherRevocationInfoFormat` | RFC 5652 §12.1 | 原样 | `otherRevInfo ANY` |
| 20 | `CertificateChoices` | RFC 5652 §12.1 | 原样 | 5 个分支标签：`certificate` 0x30、`extendedCertificate` 0xA0、`v1AttrCert` 0xA1、`v2AttrCert` 0xA2、`other` 0xA3 |
| 21 | `CertificateSet` | RFC 5652 §12.1 | 原样 | `SET OF CertificateChoices` |
| 22 | `IssuerAndSerialNumber` | RFC 5652 §12.1 | 原样 | `issuer Name` + `serialNumber` |
| 23 | `CMSVersion` | RFC 5652 §12.1 | 语法调整 | 去值名与约束，改为无约束 `INTEGER`；见第 1 节 |
| 24 | `OtherCertificateFormat` | RFC 5652 §12.1 | 原样 | `otherCert ANY` |
| 25 | `AttributeCertificateV1` | RFC 5652 §12.1（引用 RFC 3281） | 占位 | `SEQUENCE { ... }`；不透明，仅原始 TLV 可用 |
| 26 | `AttributeCertificateV2` | RFC 5652 §12.1（引用 RFC 3281） | 占位 | 同上；源码中类型名为 `AttributeCertificateV2`，对应 RFC 5652 的 `AttributeCertificate` |
| 27 | `ExtendedCertificate` | RFC 5652 §12.1（废弃 PKCS #6） | 原样 | 结构完整保留（含内嵌 `Certificate`） |
| 28 | `ExtendedCertificateInfo` | RFC 5652 §12.1 | 原样 | `version` + `certificate` + `attributes` |
| 29 | `AlgorithmIdentifier` | PKIX 展平（RFC 5912） | 原样 | `parameters ANY OPTIONAL` |
| 30 | `Name` | PKIX 展平 | 原样 | 单分支 CHOICE `rdnSequence` |
| 31 | `RDNSequence` | PKIX 展平 | 原样 | `SEQUENCE OF RelativeDistinguishedName` |
| 32 | `RelativeDistinguishedName` | PKIX 展平 | 原样 | `SET SIZE (1..MAX) OF SingleAttribute` |
| 33 | `SingleAttribute` | PKIX 展平 | 原样 | `type` + `value ANY` |
| 34 | `Certificate` | PKIX 展平 | 原样 | `SIGNED-TBSCertificate` |
| 35 | `SIGNED-TBSCertificate` | PKIX 展平 | 原样 | RFC 5912 的 `SIGNED{TBSCertificate}` 已展开 |
| 36 | `TBSCertificate` | PKIX 展平 | 原样 | 含 `[0] EXPLICIT Version DEFAULT v1`、`[3] EXPLICIT Extensions` |
| 37 | `Version` | PKIX 展平 | 原样 | 命名 `INTEGER { v1(0), v2(1), v3(2) }`；解码期约束为 0..2 |
| 38 | `CertificateSerialNumber` | PKIX 展平 | 原样 | `INTEGER` |
| 39 | `Validity` | PKIX 展平 | 原样 | `notBefore` + `notAfter` |
| 40 | `Time` | RFC 5652 §12.1 与 PKIX 展平同名同构 | 保留一份 | RFC 5652 本地定义与 PKIX 定义逐字段相同；取 PKIX 版本，避免重名 |
| 41 | `UniqueIdentifier` | PKIX 展平 | 原样 | `BIT STRING` |
| 42 | `SubjectPublicKeyInfo` | PKIX 展平 | 原样 | `algorithm` + `subjectPublicKey` |
| 43 | `Extensions` | PKIX 展平 | 原样 | `SEQUENCE SIZE (1..MAX) OF Extension` |
| 44 | `Extension` | PKIX 展平 | 原样 | `extnID` + `critical DEFAULT FALSE` + `extnValue` |
| 45 | `CertificateList` | PKIX 展平 | 原样 | `SIGNED-TBSCertList` |
| 46 | `SIGNED-TBSCertList` | PKIX 展平 | 原样 | RFC 5912 的 `SIGNED{TBSCertList}` 已展开 |
| 47 | `TBSCertList` | PKIX 展平 | 原样 | 含匿名 `revokedCertificates` 与 `[0] EXPLICIT Extensions` |

合计 47 个类型级声明。

### 2.1 未复制（不在 `SignedData` 可达范围）

以下 PKIX 展平模块中的类型**没有**进入本模块，因此不能通过本模块 API 结构化读取：

`AttributeType`、`AttributeSet`、`DirectoryString`、`X520name`、`X520CommonName`、`X520LocalityName`、`X520StateOrProvinceName`、`X520OrganizationName`、`X520OrganizationalUnitName`、`X520Pseudonym`、`X520SerialNumber`、`X520Title`、`X520dnQualifier`、`X520countryName`、`EmailAddress`、`DomainComponent`、`EDIPartyName`、`OtherName`、`ORAddress`、`GeneralName`、`GeneralNames`、`AnotherName`、`CountryName`、`AdministrationDomainName`、`NetworkAddress`、`BuiltInStandardAttributes`、`BuiltInDomainDefinedAttributes`、`BuiltInDomainDefinedAttribute`、`ExtensionAttributes`、`ExtensionAttribute`、`PDSParameter`、`PresentationAddress`、`TeletexTerminalIdentifier`、`TeletexString`、`KeyUsage`、`KeyIdentifier`、`SubjectKeyIdentifier`（PKIX1Implicit 版本）、`AuthorityKeyIdentifier`、`PrivateKeyUsagePeriod`、`CertificatePolicies`、`PolicyInformation`、`PolicyMappings`、`SubjectAltName`、`IssuerAltName`、`SubjectDirectoryAttributes`、`BasicConstraints`、`NameConstraints`、`PolicyConstraints`、`ExtendedKeyUsage`、`CRLDistributionPoints`、`CRLNumber`、`CRLReason`、`FreshestCRL`、`InhibitAnyPolicy`、`AuthorityInfoAccessSyntax`、`SubjectInfoAccessSyntax`、`AttributeCertificate`、`AttributeCertificateInfo`、`Holder`、`AttCertIssuer`、`AttCertValidityPeriod`、`IssuingDistributionPoint`、`SecurityCategory`、`OTHER-NAME` 等。

这些类型的原始字节仍可能出现在 `certificates`、`crls`、`attributes` 等位置，但本模块按原始 TLV 返回，不做结构展开。`Name` 的 RDN `value ANY` 也不展开为 `DirectoryString`。

## 3. ANY 与标签模型

| 位置 | 标签模型 | 原始 TLV 含义 |
| --- | --- | --- |
| `ContentInfo.content [0] EXPLICIT ANY` | 显式：节点是 `[0]` 包装，内层是 ANY | API 返回内层 ANY 的完整 TLV（可直接交给 `SignedData` open） |
| `EncapsulatedContentInfo.eContent [0] EXPLICIT OCTET STRING` | 显式：节点是 `[0]` 包装，内层是 OCTET STRING | API 的 `_tlv` 返回 OCTET STRING 的完整 TLV，`_content` 返回其内容字节 |
| `SignerInfo.signedAttrs [0] IMPLICIT SET OF Attribute` | 隐式：节点本身就是 SET，标签 0xA0 | API 返回含 0xA0 的完整 TLV |
| `SignerInfo.unsignedAttrs [1] IMPLICIT SET OF Attribute` | 隐式：节点本身就是 SET，标签 0xA1 | API 返回含 0xA1 的完整 TLV |
| `SignedData.certificates [0] IMPLICIT SET OF CertificateChoices` | 隐式：节点本身就是 SET，标签 0xA0 | 逐项返回选择分支的完整 TLV |
| `SignedData.crls [1] IMPLICIT RevocationInfoChoices` | 隐式：节点本身就是 SET，标签 0xA1 | 逐项返回选择分支的完整 TLV |
| `AlgorithmIdentifier.parameters ANY OPTIONAL` | 无标签：节点就是 ANY 值 | API 返回 ANY 完整 TLV；缺省 NULL/0 |
| `Attribute.attrValues SET OF ANY` | 无标签：元素就是 ANY 值 | 本模块 API 不逐属性展开，调用方按 signedAttrs 原始 TLV 二次解析 |

所有隐式/显式标签均通过模块级 `DEFINITIONS IMPLICIT TAGS` 与源码中的显式 `EXPLICIT` 标注表达，没有为绕过 seal/标签校验新增临时特例。

## 4. 勘误核对

对 [reference/rfc5652/errata.html](reference/rfc5652/errata.html) 中的 6 条记录逐条核对：

| Errata ID | 状态 | 位置 | 是否影响本产出 | 处理 |
| --- | --- | --- | --- | --- |
| 6250 | Verified | §9.2 | 否 | 只涉及 MAC 输入/AuthAttributes 的文字说明，`SignedData` 结构不受影响 |
| 6546 | Verified | §12.1 | 否（说明性） | 指出 `AttributeCertificateV1` 的导入来源应为 §12.2；本产出不含 `IMPORTS`，属性证书分支本就是占位 |
| 7863 | Held for Document Update | §5.2 | 否 | `SignedData` 版本语义文字，不影响字段/标签 |
| 2026 | Held for Document Update | §5.3 | 否 | `SignerInfo` 文字说明，不影响字段/标签 |
| 3867 | Held for Document Update | §5.3 | 否 | 同上 |
| 5331 | Rejected | §6.1 | 否 | 未采纳 |

结论：没有需要改写的结构级勘误。

## 5. 校验方式

- `asnberc -o <bin> -c <h> --root ContentInfo|SignedData|EnvelopedData|EncryptedData CMS-Flattened-5652.asn1` 均生成成功。
- 四张表由 `tests/cms/test_cms_structures.c` 等在 Windows/MinGW 本地实测加载并解码 openssl 生成的 CMS 样本。
- `-DASNBER_CMS_REGENERATE_TABLE=ON` 重新生成并与检入产物逐字节比对（目标 `asnber_cms_table_verify`，覆盖四张表）。
- 差分测试将 CMS 样本纳入 OpenSSL `asn1parse` 的偏移/层级/TLV 边界对照。

## 6. EnvelopedData 闭包（RFC 5652 §6，0.2.0 第一块）

在 `SignedData` 闭包之后**追加** 24 个类型，单一模块、无 `IMPORTS`。共享类型（`CMSVersion`、`AlgorithmIdentifier`、`IssuerAndSerialNumber`、`SubjectKeyIdentifier`、`CertificateSet`、`RevocationInfoChoices`、`Attribute`、`ContentType` 等）直接复用前文定义，不复制。

| # | 类型 | 来源 | 处理 | 说明 |
| --- | --- | --- | --- | --- |
| 48 | `EnvelopedData` | RFC 5652 §6.1 | 原样 | `originatorInfo [0] IMPLICIT`、`unprotectedAttrs [1] IMPLICIT` 保留隐式标签 |
| 49 | `OriginatorInfo` | RFC 5652 §6.1 | 原样 | `certs [0] IMPLICIT CertificateSet`、`crls [1] IMPLICIT RevocationInfoChoices`，均 OPTIONAL |
| 50 | `RecipientInfos` | RFC 5652 §6.1 | 原样 | `SET SIZE (1..MAX) OF RecipientInfo` |
| 51 | `RecipientInfo` | RFC 5652 §6.2.1 | 原样 | CHOICE 五分支；**`ktri` 无标签**（裸 `SEQUENCE`），`kari [1]`/`kekri [2]`/`pwri [3]`/`ori [4]` 均 `IMPLICIT` |
| 52 | `KeyTransRecipientInfo` | RFC 5652 §6 | 原样 | `version` + `rid` + `keyEncryptionAlgorithm` + `encryptedKey` |
| 53 | `RecipientIdentifier` | RFC 5652 §6 | 原样 | CHOICE：`issuerAndSerialNumber` / `subjectKeyIdentifier [0] IMPLICIT` |
| 54 | `KeyAgreeRecipientInfo` | RFC 5652 §6 | 原样 | `originator [0] EXPLICIT`、`ukm [1] EXPLICIT` OPTIONAL |
| 55 | `OriginatorIdentifierOrKey` | RFC 5652 §6 | 原样 | CHOICE 三分支：`issuerAndSerialNumber` / `[0] IMPLICIT` / `originatorKey [1] IMPLICIT` |
| 56 | `OriginatorPublicKey` | RFC 5652 §6 | 原样 | `algorithm` + `publicKey BIT STRING` |
| 57 | `RecipientEncryptedKeys` | RFC 5652 §6 | 原样 | `SEQUENCE OF RecipientEncryptedKey` |
| 58 | `RecipientEncryptedKey` | RFC 5652 §6 | 原样 | `rid` + `encryptedKey` |
| 59 | `KeyAgreeRecipientIdentifier` | RFC 5652 §6 | 原样 | CHOICE：`issuerAndSerialNumber` / `rKeyId [0] IMPLICIT` |
| 60 | `RecipientKeyIdentifier` | RFC 5652 §6 | 原样 | `subjectKeyIdentifier` + `date`/`other` OPTIONAL |
| 61 | `KEKRecipientInfo` | RFC 5652 §6 | 原样 | `version` + `kekid` + `keyEncryptionAlgorithm` + `encryptedKey` |
| 62 | `KEKIdentifier` | RFC 5652 §6 | 原样 | `keyIdentifier OCTET STRING` + `date`/`other` OPTIONAL |
| 63 | `PasswordRecipientInfo` | RFC 5652 §6 | 原样 | `keyDerivationAlgorithm [0] IMPLICIT` OPTIONAL |
| 64 | `OtherRecipientInfo` | RFC 5652 §6 | 原样 | `oriType` + `oriValue ANY` |
| 65 | `OtherKeyAttribute` | RFC 5652 §6 | 原样 | `keyAttrId` + `keyAttr ANY` OPTIONAL |
| 66 | `EncryptedContentInfo` | RFC 5652 §6 | 原样 | `encryptedContent [0] IMPLICIT EncryptedContent` OPTIONAL |
| 67 | `ContentEncryptionAlgorithmIdentifier` | RFC 5652 §6 | 原样 | 指向复用的 `AlgorithmIdentifier` |
| 68 | `EncryptedContent` | RFC 5652 §6 | 原样 | `OCTET STRING` 别名 |
| 69 | `EncryptedKey` | RFC 5652 §6 | 原样 | `OCTET STRING` 别名 |
| 70 | `UserKeyingMaterial` | RFC 5652 §6 | 原样 | `OCTET STRING` 别名 |
| 71 | `UnprotectedAttributes` | RFC 5652 §6 | 原样 | `SET SIZE (1..MAX) OF Attribute` |

合计新增 24 个类型级声明；模块总声明数 47 → 71。

### 6.1 openssl 生成能力实测（2026-11-07，OpenSSL 3.5.9）

| 分支 | 尝试的选项 | 结果 | 样本策略 |
| --- | --- | --- | --- |
| `ktri` | `openssl cms -encrypt -in msg -out ktri.der -aes256 -recip rsacert.pem`；另加 `-keyid` 生成 `cms_enveloped_ktri_keyid.der` | 成功，`recipientInfo` 为裸 `SEQUENCE`（无 `[0]` 标签，实测首字节 `0x30`）；`-keyid` 样本 `rid` 为 `[0]` 20 字节 SKI，`ktri` 与 `EnvelopedData` version 均为 2 | 真实样本（rid 两分支均覆盖） |
| `kari` | 同上，`-recip eccert.pem -keyid`（EC 证书） | 成功，分支 `[1]` | 真实样本 |
| `kekri` | `openssl cms -encrypt -secretkeyid 0102030405060708 -secretkey 000102...1E1F -aes256 ...` | 成功，分支 `[2]` | 真实样本 |
| `pwri` | `openssl cms -encrypt -pwri_password secret -aes256 ...` | 成功，分支 `[3]` | 真实样本 |
| `ori` | `cms -encrypt` 无对应生成选项（帮助中无 `OtherRecipientInfo`/`-ori`）；`asn1parse -genconf` 只能造裸 TLV，不能产出 `CMS` 容器语义 | 不可生成 | **未用真实样本验证**：构造级正例 + 截断负例 |
| `kek` / `pwri`（错误选项名） | `openssl cms -encrypt -kek ...`、`-pwri ...` | `Unknown option or cipher` | 记录为无效尝试，正确入口是 `-secretkeyid`/`-pwri_password` |

结论：`ktri`/`kari`/`kekri`/`pwri` 使用真实 openssl 样本；仅 `ori` 为构造级，`docs/03` 能力矩阵须标注“该分支未用真实样本验证”。

### 6.2 空 `recipientInfos` 结论

`RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo` 的 `SIZE` 约束**已进入描述表**：类型 `RecipientInfos`（新表 id 50）带一条类型级 `SIZE` 约束（`flags = 0x2` 表示上界无界，下界 1）。因此空 `SET` 在 schema 解码期由核心约束检查拒绝，返回 `ASNBER_E_SCHEMA_CONSTRAINT`；模块 `open` 不额外做兜底检查，也不会出现“解码成功但语义非法”。负例在 `tests/cms` 中固定断言该错误码（节点 3）。另外两条负例按实测固定：整段 `ContentInfo` 喂给裸 `open` 返回 `ASNBER_E_SCHEMA_FIELD`（根 `SEQUENCE` 可解析，但 version 之后接 OID 而非 `recipientInfos`），截断到 8 字节返回 `ASNBER_E_TRUNCATED`。

### 6.3 勘误：`ktri` 无标签、`unprotectedAttrs` 为 `[1]`（2026-11-07）

节点 2 生成真实 openssl 样本时发现两处展平错误。两处均源于规格初稿按 RFC 3852（`ktri [0]`、`unprotectedAttrs [2]`）书写，而 RFC 5652 已改动：

| 项 | 初稿 | RFC 5652 原文 | 实测证据 |
| --- | --- | --- | --- |
| `RecipientInfo.ktri` | `[0] IMPLICIT KeyTransRecipientInfo` | 无标签（`ktri KeyTransRecipientInfo`），`kari [1]` 起才有 context 标签 | 真实 ktri 样本 `recipientInfos` 首字节 `0x30`（UNIVERSAL SEQUENCE），kari 为 `0xA1`、pwri 为 `0xA3` |
| `EnvelopedData.unprotectedAttrs` | `[2] IMPLICIT` | `[1] IMPLICIT` | RFC 5652 §6.1 原文；本切片样本均未携带该可选字段，按原文修正 |

影响与处理：`ktri` 带 `[0]` 时真实样本在 CHOICE 分派阶段无分支匹配（`ASNBER_E_SCHEMA_TYPE`），是确定性失败，必须在本切片内修正。修正后重新生成三张表，表体由 17216 降为 17016 字节：显式 `[0]` 曾产生一个合成的 tagged 克隆类型及其 4 条字段记录（`version`/`rid`/`keyEncryptionAlgorithm`/`encryptedKey`），改为直接引用后消失。修正只涉及 EnvelopedData 闭包，具名类型 1..47 的记录仍逐字节未变（§7 数字已按修正后基线重算）。

## 7. 旧两表重生成的逐项归因（2026-11-07）

追加 24 个具名类型后，`cms_content_info_schema.*` 与 `cms_signed_data_schema.*` 不再逐字节一致。已逐区对比旧表（10488 字节）与新表（**17016 字节**，按 §6.3 修正后）归因如下：

| 项 | 实测 |
| --- | --- |
| 具名类型记录 | 旧表 id 1..47 的 48 字节记录**逐字节未变**（含 `name_off`、`kind`、标签、`field_start`、约束下标） |
| 合成类型 id | **35 条全部后移 +24**：旧 48..82 → 新 72..106（首条 `$ContentInfo_content_0` 48→72，末条 `$SignerInfo_unsignedAttrs_34` 82→106）；新增合成类型 22 条 |
| 字段记录 | 旧 97 条中 **48 条的 `type_id` 指向旧合成类型**，按 +24 改写；后 10 条（旧合成类型的字段）在字段表中的**下标整体 +55**（新增具名类型的 55 条字段插在其前）。按字节核对 `name_off`：所有旧字段名均位于字符串池内偏移 1874 之后（即池偏移 808 之后），其中 **59 个旧字段名整体 +1213**（483 字节新类型名 + 730 字节新字段名插在其前），**3 个位于旧池末尾的字段名（`userCertificate`/`revocationDate`/`crlEntryExtensions`）整体 +1548**（再叠加尾部 335 字节插入）。记录内容（`type_id` 改写除外）、`flags` 与语义不变。注：按字节核对存在 +1213 与 +1548 两组，不能概括为“旧字段名整体 +1548” |
| 元素类型引用 | 旧 82 条类型记录中 **1 条**（`$TBSCertList_revokedCertificates_26_element_27`）的 `element_type_id` 指向旧合成类型（75→99） |
| 字符串池 | 池大小 2655 → 4203（+1548）：新增 24 个具名类型名 **483 字节**插入到池内偏移 **808**（旧具名区之后、旧合成区之前），新增具名类型的字段名 **730 字节**插在旧字段名之前，其余 335 字节为新增合成类型相关字符串、插在旧合成类型字段名（`userCertificate` 等 3 个）之前；前 808 字节内的旧具名类型名偏移不变，旧合成类型名 `name_off` 整体 +483 |
| 子表偏移 | 随字符串池顺移：`type_table_offset` +1552、`field_table_offset` +3760、`constraint_table_offset` +6384、`default_table_offset` +6528、`name_table_offset` +6528 |
| 头部 | `type_count` 82→128、`field_count` 97→179、`constraint_count` 11→14、`total_size` 10488→17016、`checksum` 相应变化 |
| 根编号 | `root_type_id` 不变（ContentInfo=1、SignedData=3）；`EnvelopedData` 新 id 48 |

**结论**：除“合成类型 id 整体后移 +24”与“字符串池在 808 处插入新串”及其连带的偏移/长度/校验和变化外，没有其他变更原因。三张新表除 `checksum`(@80) 与 `root_type_id`(@96) 外完全相同（各 17016 字节，`checksum_alg = 1`，存储的 CRC32C 校验和分别为 `55A1CA32`/`8B288D3B`/`859A368D`，按 `docs/11 §2.1` 以 `checksum` 字段置 0 参与计算；脚本直接读表并重算核对），因为 asnberc 的 `--root` 只设置 `root_type_id`，描述表始终包含整模块类型池。

回归证据（2026-11-08 复核修复后复跑）：

- 三张表由 asnberc 生成，退出码 0；`-DASNBER_CMS_REGENERATE_TABLE=ON` 下 `asnber_cms_table_verify` 通过。
- 替入新表后 Release/GCC 全量构建 + `ctest`：**36/36 通过**（含全部 CMS 用例）。
- 类型 id 仅是描述表内部引用，模块 ABI 与错误码无变化。

## 8. EncryptedData 闭包与四表重生成（2026-11-08）

在 §6 的 EnvelopedData 闭包之后追加 1 个具名类型，仍为单一模块、无 `IMPORTS`：

```asnber
EncryptedData ::= SEQUENCE {
    version               CMSVersion,
    encryptedContentInfo  EncryptedContentInfo,
    unprotectedAttrs      [1] IMPLICIT UnprotectedAttributes OPTIONAL }
```

`CMSVersion`、`EncryptedContentInfo`、`UnprotectedAttributes` 直接复用前文定义。版本语义（无 `unprotectedAttrs` 时必须为 0，带该字段时必须为 2）由 builder 在写入时校验，不进入描述表。

### 8.1 类型编号位移（不是“ID 稳定”）

asnberc 先按源码顺序排具名类型、再排合成类型。追加具名类型会插在**具名区末尾、合成区之前**，而不是表尾，因此：

| 项 | 旧表（§6.3 后） | 新表 | 变化 |
| --- | --- | --- | --- |
| 具名类型 id 1..71 | 不变 | 不变 | 0 |
| `EncryptedData` | 不存在 | **id 72** | 新增 |
| 旧合成类型 id 72..128 | 72..128 | **73..129** | **+1** |
| 新合成类型 `$EncryptedData_unprotectedAttrs_57` | 不存在 | **id 130** | 新增 |
| `type_count` | 128 | 130 | +2 |

上一轮粗略估计的 `48..106 → 49..107` 不成立：实际插入点在全部 71 个具名类型之后，受影响的只有原合成区。至少修正一处内部引用：旧 id 98 `$TBSCertList_revokedCertificates_26` 的 `element_type_id` 由 99 改为 100；其余引用随目标编号同步。

### 8.2 字段、约束与字符串池

| 项 | 旧表 | 新表 | 变化 |
| --- | --- | --- | --- |
| `field_count` | 179 | 182 | +3 |
| 字段插入点 | — | 下标 **142..144** | `EncryptedData` 的 `version`（`CMSVersion` id 26）、`encryptedContentInfo`（id 66）、`unprotectedAttrs`（合成包装 id 130） |
| 旧字段下标 >=142 | 142..178 | **145..181** | **+3** |
| 旧字段 `type_id >= 72` | 87 条 | — | 引用编号 **+1**（其中 69 条位于下标 <142，18 条位于 >=142） |
| `constraint_count` | 14 | 15 | +1：下标 14 为 `unprotectedAttrs` 的 `SIZE (1..MAX)`；旧约束 0..13 不变 |
| 字符串池大小（头字段 `string_pool_size`） | 4203 | 4252 | **+49** |
| 池区间（`type_table_offset - string_pool_offset`，含对齐填充） | 4208 | 4256 | +48 |
| 字段名偏移 | — | — | 旧字段名全部 **+49** |

字符串池新增两段：

- `EncryptedData\0`（14 字节）插在池内偏移 **1291**（绝对偏移 1403），即旧合成类型名之前；旧 id 72 的 `$ContentInfo_content_0` 顺移到池内 1305。
- `$EncryptedData_unprotectedAttrs_57\0`（35 字节）插在 `$EnvelopedData_unprotectedAttrs_56` 之后、普通字段名区之前。

两段合计 49 字节，对应头字段 `string_pool_size` 由 **4203** 增至 **4252（+49）**。池区间由 4208 增至 4256（+48）：池后对齐填充由 5 字节降为 4 字节，吸收了 1 字节。两个数口径不同，不要混算。各子表随字符串池顺移：

| 偏移字段 | 旧值 | 新值 | 变化 |
| --- | --- | --- | --- |
| `type_table_offset` | 4320 | 4368 | +48 |
| `field_table_offset` | 10464 | 10608 | +144 |
| `constraint_table_offset` | 16192 | 16432 | +240 |
| `total_size` | 17016 | 17304 | +288 |

### 8.3 四张表的实测校验和

四张表均为 **17304 字节**，`header_size = 108`、`checksum_alg = 1`（CRC32C）、`string_pool_offset = 112`、`type_count = 130`、`field_count = 182`、`constraint_count = 15`。除 `checksum`(@80) 与 `root_type_id`(@96) 外完全相同。

| 表 | `root_type_id` | 存储 CRC32C |
| --- | --- | --- |
| `cms_content_info_schema` | 1 (`ContentInfo`) | `191898BF` |
| `cms_signed_data_schema` | 3 (`SignedData`) | `2C0D89A4` |
| `cms_enveloped_data_schema` | 48 (`EnvelopedData`) | `73455FC0` |
| `cms_encrypted_data_schema` | 72 (`EncryptedData`) | `EBFB7A60` |

校验和按 `docs/11 §2.1` 将 `checksum` 字段（偏移 80..83）置 0 后对整个 `[0, total_size)` 重算 CRC32C，四个值均与存储值一致；不是 zlib CRC32。

### 8.4 验收与设计债

- `asnberc` 对四个根均生成成功；`-DASNBER_CMS_REGENERATE_TABLE=ON` 下 `asnber_cms_table_verify` 对四张 `.bin` 与四个 `.h` 逐字节比对通过。
- MinGW Release 全量构建 + `ctest`：**37/37 通过**；Clang ASan/UBSan 全量构建 + `ctest`：**37/37 通过**（该轮为 Phase 1 记录；四块合并后的最终全量为 38/38，见 `docs/07` §9.7）。
- 验收标准是“重生成后逐字节自校验通过 + 本节记录的新 CRC32C 与编号位移”，**不是**“既有类型 ID 稳定”，也**不是**“检入表字节不变”。类型编号是描述表内部引用，不是公共契约；模块回归依据是测试全绿。
- 设计债：每次追加具名类型都会重排合成区、重写四张表的字符串池/子表偏移/CRC。0.3.0 继续增大结构面后，这种全表抖动会越来越明显。可选方向是让 asnberc 使用与追加顺序无关的确定性编号，或明确接受“每次追加都 churn”；0.2.0 不做，仅在此记录，避免其悄然成为惯例。

## 9. CompressedData 与 AuthenticatedData 闭包与六表重生成（2026-11-08）

在 §8 的 EncryptedData 闭包之后追加两个内容类型，仍为单一模块、无 `IMPORTS`：

```asnber
CompressedData ::= SEQUENCE {
    version               CMSVersion,
    compressionAlgorithm  CompressionAlgorithmIdentifier,
    encapContentInfo      EncapsulatedContentInfo }

CompressionAlgorithmIdentifier ::= AlgorithmIdentifier

AuthenticatedData ::= SEQUENCE {
    version          CMSVersion,
    originatorInfo   [0] IMPLICIT OriginatorInfo OPTIONAL,
    recipientInfos   RecipientInfos,
    macAlgorithm     MessageAuthenticationCodeAlgorithm,
    digestAlgorithm  [1] IMPLICIT DigestAlgorithmIdentifier OPTIONAL,
    encapContentInfo EncapsulatedContentInfo,
    authAttrs        [2] IMPLICIT AuthAttributes OPTIONAL,
    mac              MessageAuthenticationCode,
    unauthAttrs      [3] IMPLICIT UnauthAttributes OPTIONAL }
```

`AuthAttributes`、`UnauthAttributes` 均为 `SET SIZE (1..MAX) OF Attribute`；`MessageAuthenticationCode` 为 `OCTET STRING`。RFC 3274 的版本必须为 0，RFC 5652 §9.1 的版本只允许 0/1/3，这些语义由 builder 校验，不进入描述表。

### 9.1 类型编号位移

本轮追加 **7 个具名类型**（源码顺序紧接 `EncryptedData`），再追加 **4 个合成类型**：

| 项 | §8 后 | 本轮后 | 变化 |
| --- | --- | --- | --- |
| 具名类型 id 1..72 | 不变 | 不变 | 0 |
| `CompressedData` | 不存在 | **id 73** | 新增 |
| `CompressionAlgorithmIdentifier` | 不存在 | **id 74** | 新增 |
| `AuthenticatedData` | 不存在 | **id 75** | 新增 |
| `MessageAuthenticationCodeAlgorithm` | 不存在 | **id 76** | 新增 |
| `AuthAttributes` | 不存在 | **id 77** | 新增 |
| `UnauthAttributes` | 不存在 | **id 78** | 新增 |
| `MessageAuthenticationCode` | 不存在 | **id 79** | 新增 |
| 旧合成类型 id 73..130 | 73..130 | **80..137** | **+7** |
| `$AuthenticatedData_originatorInfo_58` | 不存在 | **id 138** | 新增 |
| `$AuthenticatedData_digestAlgorithm_59` | 不存在 | **id 139** | 新增 |
| `$AuthenticatedData_authAttrs_60` | 不存在 | **id 140** | 新增 |
| `$AuthenticatedData_unauthAttrs_61` | 不存在 | **id 141** | 新增 |
| `type_count` | 130 | 141 | +11 |

`CompressedData` 没有可选字段的显式包装，因此不产生新的合成类型。§8 记录的 `$EncryptedData_unprotectedAttrs_57` 由 id 130 顺移到 **137**；所有引用旧合成类型的 `element_type_id`、字段 `type_id` 同步 **+7**。

### 9.2 字段、约束与字符串池

| 项 | §8 后 | 本轮后 | 变化 |
| --- | --- | --- | --- |
| `field_count` | 182 | 202 | +20 |
| 新具名字段插入点 | — | 下标 **145..160** | 16 条：`CompressedData` 3、`CompressionAlgorithmIdentifier` 2、`AuthenticatedData` 9、`MessageAuthenticationCodeAlgorithm` 2 |
| 旧字段下标 >=145 | 145..181 | **161..197** | **+16** |
| 新合成类型字段 | — | **198..201** | 4 条（两个 OPTIONAL 包装各 2 条） |
| `constraint_count` | 15 | 19 | +4 |
| 约束插入点 | — | 下标 **7、8** | `AuthAttributes`、`UnauthAttributes` 的 `SIZE (1..MAX)` |
| 旧约束下标 7..14 | 7..14 | **9..16** | **+2** |
| 新合成包装约束 | — | **17、18** | `authAttrs`、`unauthAttrs` 的 `SIZE (1..MAX)` |

`CompressedData` 不引入新约束。`constraint_start` 随类型/字段记录同步重排，没有通过 `if` 特判绕过。

字符串池由 **4252** 增至 **4610（+358）**，新增 16 个字符串，无删除：

- 具名类型名 7 个：`CompressedData`(15)、`CompressionAlgorithmIdentifier`(31)、`AuthenticatedData`(18)、`MessageAuthenticationCodeAlgorithm`(35)、`AuthAttributes`(15)、`UnauthAttributes`(17)、`MessageAuthenticationCode`(26)，合计 157 字节。
- 合成类型名 4 个：`$AuthenticatedData_originatorInfo_58`(37)、`$AuthenticatedData_digestAlgorithm_59`(38)、`$AuthenticatedData_authAttrs_60`(32)、`$AuthenticatedData_unauthAttrs_61`(34)，合计 141 字节。
- 新字段名 5 个：`compressionAlgorithm`(21)、`macAlgorithm`(13)、`authAttrs`(10)、`mac`(4)、`unauthAttrs`(12)，合计 60 字节。

池区间（`type_table_offset - string_pool_offset`）由 4256 增至 4616（+360）：池后对齐填充由 4 字节增至 6 字节，吸收了 +2。各子表随字符串池顺移：

| 偏移字段 | §8 后 | 本轮后 | 变化 |
| --- | --- | --- | --- |
| `type_table_offset` | 4368 | 4728 | +360 |
| `field_table_offset` | 10608 | 11496 | +888 |
| `constraint_table_offset` | 16432 | 17960 | +1528 |
| `default_table_offset` | 17152 | 18872 | +1720 |
| `name_table_offset` | 17232 | 18952 | +1720 |
| `total_size` | 17304 | 19024 | +1720 |

增量闭合：+360（池区间） + 528（11 个类型记录） + 640（20 个字段记录） + 192（4 个约束记录） = +1720；默认值表与名称表大小不变。

### 9.3 六张表的实测校验和

六张表均为 **19024 字节**，`header_size = 108`、`checksum_alg = 1`（CRC32C）、`string_pool_offset = 112`、`type_count = 141`、`field_count = 202`、`constraint_count = 19`。逐字节比较确认：六张表仅在 `checksum`(@80) 与 `root_type_id`(@96) 两处不同。

| 表 | `root_type_id` | 存储 CRC32C |
| --- | --- | --- |
| `cms_content_info_schema` | 1 (`ContentInfo`) | `C6A8A9C8` |
| `cms_signed_data_schema` | 3 (`SignedData`) | `7FA5E77E` |
| `cms_enveloped_data_schema` | 48 (`EnvelopedData`) | `F19A11ED` |
| `cms_encrypted_data_schema` | 72 (`EncryptedData`) | `132820AE` |
| `cms_compressed_data_schema` | 73 (`CompressedData`) | `4FAE87F5` |
| `cms_authenticated_data_schema` | 75 (`AuthenticatedData`) | `F6A3C943` |

校验和按 `docs/11 §2.1` 将 `checksum` 字段（偏移 80..83）置 0 后对整个 `[0, total_size)` 重算 CRC32C，六个值均与存储值一致；不是 zlib CRC32。

### 9.4 验收与证据边界

- `asnberc` 对六个根均生成成功；`-DASNBER_CMS_REGENERATE_TABLE=ON` 构建时对六张 `.bin` 与六个 `.h` 逐字节自校验通过，随后 `ctest` **40/40 通过**（2026-11-08 本地 MinGW/GCC Release）。
- `CompressedData` 有外部生成器样本：`tests/data/cms_compressed_data.der` 由 OpenSSL `cms -compress` 产生，差分测试 24/24 通过（含往返逐字节一致）。
- `AuthenticatedData` **没有外部生成器样本**。测试证据只到“手写 DER 可被本库打开”与“builder 输出可被本库重新打开并往返”，属于构造级验证；不声称被 OpenSSL 或其他生产方接受，也不声称覆盖 MAC 计算/校验语义。
- 验收标准仍是“重生成后逐字节自校验通过 + 本节记录的新 CRC32C 与编号位移”，不是“既有类型 ID 稳定”。类型编号是描述表内部引用，不是公共契约。
- 设计债与 §8.4 相同，且本轮一次追加 11 个类型使全表抖动更明显；0.3.0 仍只记录，不改编号策略。
