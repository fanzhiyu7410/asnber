# PKIX 展平模块类型级对账表

对账口径：以 RFC 5912（2010-06）原文第 2、3、14 节为基准，按 `docs/11-描述表格式.md` §15.2 的 8 条 Verified 勘误核对后，逐类型比对。

- 输出文件：`PKIX-Flattened-2009.asn1`（下表中“输出文件”列均为此文件）。
- 输出模块名：`PKIX-Flattened-2009`。
- 统计：原声明 68 行（三目标模块 67 + 支持的 `AlgorithmIdentifier` 1），输出 69 个类型定义。
- 状态含义：
  - **原样**：名称、字段、顺序、标签、约束均不变。
  - **展开**：参数化实例展开为具体类型，名称保留。
  - **替换**：类字段/导入类型改为目标子集内的具体类型；开放类型字段改写为 `ANY`（保留完整原始 TLV）。
  - **去类化**：`CLASS` 别名改为具体 `SEQUENCE`。
  - **裁剪**：删除 `WITH COMPONENTS`、`CONTAINING` 等非结构约束，结构不变。
  - **新增**：为展开参数化类型而新增的具体类型。

## 1. `PKIX-CommonTypes-2009`（RFC 5912 §2，6 项）

| # | 原类型名 | 输出类型名 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| 1 | `AttributeSet{ATTRIBUTE:AttrSet}` | `AttributeSet` | 展开 | 去参数化；`type` → `OBJECT IDENTIFIER`，`values` → `SET SIZE (1..MAX) OF ANY`（开放类型，保留完整 TLV） |
| 2 | `SingleAttribute{ATTRIBUTE:AttrSet}` | `SingleAttribute` | 展开 | 去参数化；`type` → `OBJECT IDENTIFIER`，`value` → `ANY`（开放类型，保留完整 TLV） |
| 3 | `Extensions{EXTENSION:ExtensionSet}` | `Extensions` | 展开 | 去参数化；对象集成员约束删除，结构不变 |
| 4 | `Extension{EXTENSION:ExtensionSet}` | `Extension` | 展开 | 去参数化；`extnID` → `OBJECT IDENTIFIER`，`extnValue` 的 `CONTAINING` 约束删除 |
| 5 | `SECURITY-CATEGORY`（`::= TYPE-IDENTIFIER`） | `SECURITY-CATEGORY` | 去类化 | 类别名改为具体 `SEQUENCE { type [0] IMPLICIT OBJECT IDENTIFIER, value [1] EXPLICIT ANY }`；显式标签保留，内层由 `OCTET STRING` 占位改为 `ANY` |
| 6 | `SecurityCategory{SECURITY-CATEGORY:Supported}` | `SecurityCategory` | 展开 | 别名到去类化后的 `SECURITY-CATEGORY` |

## 2. `AlgorithmInformation-2009`（RFC 5912 §3，仅带出 1 项）

| # | 原类型名 | 输出类型名 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| 7 | `AlgorithmIdentifier{ALGORITHM-TYPE, ALGORITHM-TYPE:AlgorithmSet}` | `AlgorithmIdentifier` | 展开 | 去参数化；`algorithm` → `OBJECT IDENTIFIER`，`parameters` → `ANY OPTIONAL`（开放类型，保留完整 TLV；不再按 `OCTET STRING` 解释，见 README 第 7 节第 1 项） |

`AlgorithmInformation-2009` 中的 `ParamOptions`、`DIGEST-ALGORITHM`、`SIGNATURE-ALGORITHM`、`PUBLIC-KEY`、`ALGORITHM`、`SMIME-CAPS`、`SMIMECapability` 等未带出：它们只服务于被删除的算法信息对象/对象集，三个目标模块的保留类型不引用其结构。

## 3. `PKIX1Explicit-2009`（RFC 5912 §14，23 项）

| # | 原类型名 | 输出类型名 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| 8 | `AttributeType`（`::= ATTRIBUTE.&id`） | `AttributeType` | 替换 | 类字段改为 `OBJECT IDENTIFIER` |
| 9 | `DirectoryString{INTEGER:maxSize}` | `DirectoryString` | 展开 | 参数化基类型改为 `SIZE (1..MAX)` 的 `CHOICE` |
| 10 | `X520name`（`DirectoryString{ub-name}`，32768） | `X520name` | 展开 | 展开为独立 `CHOICE`，5 个备选项均 `SIZE (1..32768)` |
| 11 | `X520CommonName`（`ub-common-name`，64） | `X520CommonName` | 展开 | 展开为独立 `CHOICE`，`SIZE (1..64)` |
| 12 | `X520LocalityName`（`ub-locality-name`，128） | `X520LocalityName` | 展开 | 展开为独立 `CHOICE`，`SIZE (1..128)` |
| 13 | `X520StateOrProvinceName`（`ub-state-name`，128） | `X520StateOrProvinceName` | 展开 | 展开为独立 `CHOICE`，`SIZE (1..128)`；勘误 4244 只影响对应 `at-*` 对象，对象已删除 |
| 14 | `X520OrganizationName`（`ub-organization-name`，64） | `X520OrganizationName` | 展开 | 展开为独立 `CHOICE`，`SIZE (1..64)`；勘误 4244 同上 |
| 15 | `X520OrganizationalUnitName`（`ub-organizational-unit-name`，64） | `X520OrganizationalUnitName` | 展开 | 展开为独立 `CHOICE`，`SIZE (1..64)`；勘误 4244 同上 |
| 16 | `Name` | `Name` | 原样 | `CHOICE { rdnSequence RDNSequence }` |
| 17 | `RDNSequence` | `RDNSequence` | 原样 | `SEQUENCE OF RelativeDistinguishedName` |
| 18 | `DistinguishedName` | `DistinguishedName` | 原样 | 类型别名 `RDNSequence` |
| 19 | `RelativeDistinguishedName` | `RelativeDistinguishedName` | 展开 | 删除 `{{SupportedAttributes}}` 参数；`SET SIZE (1..MAX) OF SingleAttribute` |
| 20 | `Certificate`（`SIGNED{TBSCertificate}`） | `Certificate` → `SIGNED-TBSCertificate` | 展开 | 类型名保留，右侧改为具体实例类型 |
| 21 | `TBSCertificate` | `TBSCertificate` | 替换/裁剪 | `signature` 改为具体 `AlgorithmIdentifier`；`extensions` 去掉 `{{CertExtensions}}`；`[[2:]]`/`[[3:]]` 扩展组展开；`version`/`extensions` 标注 `[n] EXPLICIT` |
| 22 | `Version` | `Version` | 原样 | `INTEGER { v1(0), v2(1), v3(2) }` |
| 23 | `CertificateSerialNumber` | `CertificateSerialNumber` | 原样 | `INTEGER` |
| 24 | `Validity` | `Validity` | 原样 | `SEQUENCE { notBefore Time, notAfter Time }` |
| 25 | `Time` | `Time` | 原样 | `CHOICE { utcTime UTCTime, generalTime GeneralizedTime }` |
| 26 | `UniqueIdentifier` | `UniqueIdentifier` | 原样 | `BIT STRING` |
| 27 | `SubjectPublicKeyInfo` | `SubjectPublicKeyInfo` | 替换 | `algorithm` 改为具体 `AlgorithmIdentifier` |
| 28 | `CertificateList`（`SIGNED{TBSCertList}`） | `CertificateList` → `SIGNED-TBSCertList` | 展开 | 类型名保留，右侧改为具体实例类型 |
| 29 | `TBSCertList` | `TBSCertList` | 替换/裁剪 | `signature` 改为具体 `AlgorithmIdentifier`；`crlEntryExtensions` 去掉对象集参数；`[[2:]]` 扩展组展开；`crlExtensions` 标注 `[0] EXPLICIT` |
| 30 | `SIGNED{ToBeSigned}` | 无同名基类型 | 展开 | 参数化基类型不保留；按实参生成 #31、#32 |
| 31 | —（由 #30 展开） | `SIGNED-TBSCertificate` | 新增 | `toBeSigned TBSCertificate`、`algorithmIdentifier AlgorithmIdentifier`、`signature BIT STRING`；`CONTAINING` 删除 |
| 32 | —（由 #30 展开） | `SIGNED-TBSCertList` | 新增 | `toBeSigned TBSCertList`、`algorithmIdentifier AlgorithmIdentifier`、`signature BIT STRING`；`CONTAINING` 删除 |

## 4. `PKIX1Implicit-2009`（RFC 5912 §14，38 项）

| # | 原类型名 | 输出类型名 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| 33 | `AuthorityKeyIdentifier` | `AuthorityKeyIdentifier` | 裁剪 | 删除 `WITH COMPONENTS` 的“两字段同时出现/同时缺席”约束；字段与标签不变 |
| 34 | `KeyIdentifier` | `KeyIdentifier` | 原样 | `OCTET STRING` |
| 35 | `KeyUsage` | `KeyUsage` | 原样 | `BIT STRING` 及 9 个命名位 |
| 36 | `PrivateKeyUsagePeriod` | `PrivateKeyUsagePeriod` | 裁剪 | 删除 `WITH COMPONENTS` 的“至少一个字段出现”约束 |
| 37 | `CertificatePolicies` | `CertificatePolicies` | 原样 | `SEQUENCE SIZE (1..MAX) OF PolicyInformation` |
| 38 | `PolicyInformation` | `PolicyInformation` | 原样 | 字段与顺序不变 |
| 39 | `CertPolicyId` | `CertPolicyId` | 原样 | `OBJECT IDENTIFIER` |
| 40 | `CERT-POLICY-QUALIFIER`（`::= TYPE-IDENTIFIER`） | `CERT-POLICY-QUALIFIER` | 去类化 | 改为具体 `SEQUENCE { policyQualifierId OBJECT IDENTIFIER, qualifier ANY }`（开放类型，保留完整 TLV） |
| 41 | `PolicyQualifierInfo` | `PolicyQualifierInfo` | 替换 | 改为别名 `CERT-POLICY-QUALIFIER`；字段名/顺序不变，`qualifier` 由 `OCTET STRING` 占位改为 `ANY`，不可按 `policyQualifierId` 自动展开 |
| 42 | `CPSuri` | `CPSuri` | 原样 | `IA5String` |
| 43 | `UserNotice` | `UserNotice` | 原样 | 原文约束为注释，未生效；字段不变 |
| 44 | `NoticeReference` | `NoticeReference` | 原样 | 字段不变 |
| 45 | `DisplayText` | `DisplayText` | 原样 | 4 个备选项及 `SIZE (1..200)` 不变 |
| 46 | `PolicyMappings` | `PolicyMappings` | 原样 | 内联 `SEQUENCE` 结构不变 |
| 47 | `GeneralNames` | `GeneralNames` | 原样 | `SEQUENCE SIZE (1..MAX) OF GeneralName` |
| 48 | `GeneralName` | `GeneralName` | 替换 | `otherName` → `[0] OTHER-NAME`；`x400Address` → `[3] OCTET STRING`（`ORAddress` 的占位，**非开放类型**，一期不可结构化读取）；其余 7 个备选项不变 |
| 49 | `OTHER-NAME`（`::= TYPE-IDENTIFIER`） | `OTHER-NAME` | 去类化 | 改为具体 `SEQUENCE { type-id OBJECT IDENTIFIER, value [0] EXPLICIT ANY }`（与 RFC 5280 `OtherName` 的必选 `value` 一致；开放值保留完整 TLV） |
| 50 | `EDIPartyName` | `EDIPartyName` | 替换 | `DirectoryString{ubMax}` → 基类型 `DirectoryString`（`SIZE (1..MAX)`）；`[0]`/`[1]` 标签不变 |
| 51 | `SubjectDirectoryAttributes` | `SubjectDirectoryAttributes` | 展开 | `AttributeSet{{SupportedAttributes}}` → 具体 `AttributeSet` |
| 52 | `BasicConstraints` | `BasicConstraints` | 原样 | 字段、`DEFAULT FALSE`、`INTEGER (0..MAX)` 不变 |
| 53 | `NameConstraints` | `NameConstraints` | 原样 | 字段与 `[0]`/`[1]` 标签不变 |
| 54 | `GeneralSubtrees` | `GeneralSubtrees` | 原样 | 不变 |
| 55 | `GeneralSubtree` | `GeneralSubtree` | 原样 | `minimum [0] DEFAULT 0` 不变 |
| 56 | `BaseDistance` | `BaseDistance` | 原样 | `INTEGER (0..MAX)` |
| 57 | `PolicyConstraints` | `PolicyConstraints` | 原样 | 字段与标签不变 |
| 58 | `SkipCerts` | `SkipCerts` | 原样 | `INTEGER (0..MAX)` |
| 59 | `CRLDistributionPoints` | `CRLDistributionPoints` | 原样 | 不变 |
| 60 | `DistributionPoint` | `DistributionPoint` | 原样 | 字段与标签不变 |
| 61 | `DistributionPointName` | `DistributionPointName` | 原样 | CHOICE 与 `[0]`/`[1]` 标签不变 |
| 62 | `ReasonFlags` | `ReasonFlags` | 原样 | `BIT STRING` 及 9 个命名位 |
| 63 | `ExtKeyUsageSyntax` | `ExtKeyUsageSyntax` | 原样 | `SEQUENCE SIZE (1..MAX) OF KeyPurposeId` |
| 64 | `KeyPurposeId` | `KeyPurposeId` | 原样 | `OBJECT IDENTIFIER` |
| 65 | `AuthorityInfoAccessSyntax` | `AuthorityInfoAccessSyntax` | 原样 | `SEQUENCE SIZE (1..MAX) OF AccessDescription`（原文第 5973 行） |
| 66 | `AccessDescription` | `AccessDescription` | 原样 | 字段不变（原文第 5976 行） |
| 67 | `SubjectInfoAccessSyntax` | `SubjectInfoAccessSyntax` | 原样 | 不变（原文第 5986 行） |
| 68 | `CRLNumber` | `CRLNumber` | 原样 | `INTEGER (0..MAX)`；勘误 3626 不影响类型本身 |
| 69 | `IssuingDistributionPoint` | `IssuingDistributionPoint` | 原样 | 字段、标签、`DEFAULT FALSE` 不变 |
| 70 | `CRLReason` | `CRLReason` | 原样 | `ENUMERATED` 及 10 个命名值不变；未采用 OCSP 模块的错误重定义（勘误 3259） |

## 5. 被删除的信息对象 / 信息对象集 / 类

这些定义不是类型，未进入上表；删除属于展平策略的一部分，不是静默丢弃。

| 来源模块 | 定义 | 数量 | 处理理由 |
| --- | --- | --- | --- |
| `PKIX-CommonTypes-2009` | `ATTRIBUTE`、`MATCHING-RULE`、`EXTENSION` 类 | 3 | 目标语法无 `CLASS`；其字段用途已逐项改写为具体类型 |
| `PKIX1Explicit-2009` | `at-*` 信息对象 | 17 | 目标语法无信息对象；对应 OID 值赋值已保留，结构由具体类型覆盖 |
| `PKIX1Explicit-2009` | `SupportedAttributes`、`SignatureAlgorithms`、`PublicKeyAlgorithms` 对象集 | 3 | 目标语法无对象集；参数化类型已去参数化 |
| `PKIX1Implicit-2009` | `ext-*` 信息对象 | 25 | 同上；对应 `id-ce-*`、`id-pe-*` OID 值赋值已保留 |
| `PKIX1Implicit-2009` | `CertExtensions`、`CrlExtensions`、`CrlEntryExtensions`、`PolicyQualifierId` 对象集 | 4 | 同上；`CrlExtensions` 勘误 3692 只影响该对象集，已随对象集删除 |
| `PKIX1Implicit-2009` | `pqid-cps`、`pqid-unotice` 信息对象 | 2 | 同上 |
| `PKIX-X400Address-2009` | `EXTENSION-ATTRIBUTE` 类、`ea-*` 信息对象、`SupportedExtensionAttributes` 对象集、全部 X.400 类型 | 整体 | 该模块不在三个目标模块内；仅 `GeneralName.x400Address` 需要，已用 `[3] OCTET STRING` 占位（不是开放类型，一期不可结构化读取） |

## 6. 值赋值保留情况

以下值赋值全部保留（未因信息对象删除而删除）：

- `PKIX1Explicit-2009`：`id-pkix`、`id-pe`、`id-qt`、`id-kp`、`id-ad`、`id-qt-cps`、`id-qt-unotice`、`id-ad-ocsp`、`id-ad-caIssuers`、`id-ad-timeStamping`、`id-ad-caRepository`、`id-at`、`id-at-name`、`id-at-surname`、`id-at-givenName`、`id-at-initials`、`id-at-generationQualifier`、`id-at-commonName`、`id-at-localityName`、`id-at-stateOrProvinceName`、`id-at-organizationName`、`id-at-organizationalUnitName`、`id-at-title`、`id-at-dnQualifier`、`id-at-countryName`、`id-at-serialNumber`、`id-at-pseudonym`、`id-domainComponent`、`pkcs-9`、`id-emailAddress`，以及 `ub-*` 上界。
- `PKIX1Implicit-2009`：`id-ce`、`id-ce-authorityKeyIdentifier`、`id-ce-subjectKeyIdentifier`、`id-ce-keyUsage`、`id-ce-privateKeyUsagePeriod`、`id-ce-certificatePolicies`、`id-ce-policyMappings`、`id-ce-subjectAltName`、`id-ce-issuerAltName`、`id-ce-subjectDirectoryAttributes`、`id-ce-basicConstraints`、`id-ce-nameConstraints`、`id-ce-policyConstraints`、`id-ce-cRLDistributionPoints`、`id-ce-extKeyUsage`、`anyExtendedKeyUsage`、`id-kp-serverAuth`、`id-kp-clientAuth`、`id-kp-codeSigning`、`id-kp-emailProtection`、`id-kp-timeStamping`、`id-kp-OCSPSigning`、`id-ce-inhibitAnyPolicy`、`id-ce-freshestCRL`、`id-pe-authorityInfoAccess`、`id-pe-subjectInfoAccess`、`id-ce-cRLNumber`、`id-ce-issuingDistributionPoint`、`id-ce-deltaCRLIndicator`、`id-ce-cRLReasons`、`id-ce-certificateIssuer`、`id-ce-holdInstructionCode`、`holdInstruction`、`id-holdinstruction-none`、`id-holdinstruction-callissuer`、`id-holdinstruction-reject`、`id-ce-invalidityDate`、`ubMax`。

## 7. 对账结论

1. 三个目标模块的 67 个类型级声明，除 `SIGNED` 被两个具体类型替换外，均在输出中恰好存在一个同名类型。
2. `SIGNED` 的展开额外产生 1 个类型（净 +1）；`AlgorithmIdentifier` 作为唯一支持类型额外产生 1 个类型；输出总计 69。
3. 所有字段名、顺序、`OPTIONAL`、`DEFAULT`、标签和约束均按原文保留，例外均在上表“说明”与 README 第 7 节中逐条登记。
4. 未发现需要新增、删除或改名的其他类型。
5. 开放类型字段统一改为 `ANY`，作为字段类型共 6 处（`AttributeSet.values`、`SingleAttribute.value`、`SECURITY-CATEGORY.value`、`AlgorithmIdentifier.parameters`、`CERT-POLICY-QUALIFIER.qualifier`、`OTHER-NAME.value`）；核心按 `ASNBER_TYPE_KIND_ANY` 保留完整原始 TLV、编码原样写回、不结构化展开、子节点数为 0。
6. 仍保留 `OCTET STRING` 作为字段类型的只有 4 处，均为非开放类型：`Extension.extnValue`、`GeneralName.x400Address`、`GeneralName.iPAddress`、`KeyIdentifier`。其中仅 `x400Address` 因 `ORAddress` 未带出而一期不可结构化读取。
