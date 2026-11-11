# PKIX 展平 ASN.1 模块输入目录

本目录是 `asnberc` 一期的输入目录，不是 `asnber-pkix` 的公共头文件目录，也不参与 C++ 编译或安装。

## 1. 状态

**已完成。** 本目录已产出可直接交给 `asnberc` 的展平模块 [PKIX-Flattened-2009.asn1](PKIX-Flattened-2009.asn1)，并保留 RFC 5912 原文与勘误页作对照。产出覆盖 RFC 5912 的以下三个模块：

- `PKIX-CommonTypes-2009`（RFC 5912 第 2 节）
- `PKIX1Explicit-2009`（RFC 5912 第 14 节）
- `PKIX1Implicit-2009`（RFC 5912 第 14 节）

`asnberc` 本轮 MVP 已可用：`asnberc -o <PATH> -c <PATH> --root Certificate PKIX-Flattened-2009.asn1` 生成描述表并通过核心 `asnber_schema_load` 加载验证（69 个具名类型 / 173 条类型记录 / 6 处 ANY 字段）。`IMPORTS` 与参数化展开尚未实现，本文件已提前展开、不含这两类构造。

## 2. 输入来源

| 项 | 内容 |
| --- | --- |
| 规范 | RFC 5912, *New ASN.1 Modules for the Public Key Infrastructure Using X.509 (PKIX)*, June 2010 |
| 原文文件 | [reference/rfc5912/rfc5912.txt](reference/rfc5912/rfc5912.txt)（取自 `https://www.rfc-editor.org/rfc/rfc5912.txt`） |
| 勘误页 | [reference/rfc5912/errata.html](reference/rfc5912/errata.html)（取自 `https://www.rfc-editor.org/errata/rfc5912`） |
| 核验日期 | 2026-11-04 |
| 原文完整性 | 216,154 字节；第 2、3、14 节完整可读 |

本产出**没有**凭记忆手写任何模块内容；所有类型、字段、约束、OID 均从上述原文逐段比对后转录。

## 3. 模块映射

按依赖关系合并为一个自包含输出文件，避免跨文件 `IMPORTS` 与重复定义：

| 原模块 | 原位置 | 输出文件 | 输出模块名 | 说明 |
| --- | --- | --- | --- | --- |
| `PKIX-CommonTypes-2009` | RFC 5912 §2 | `PKIX-Flattened-2009.asn1` | `PKIX-Flattened-2009` | 全部 6 个类型级声明均保留名称 |
| `AlgorithmInformation-2009` | RFC 5912 §3 | `PKIX-Flattened-2009.asn1` | 同上 | 仅带出实际使用的具体 `AlgorithmIdentifier`；其余算法类不进入产出 |
| `PKIX1Explicit-2009` | RFC 5912 §14 | `PKIX-Flattened-2009.asn1` | 同上 | 23 个类型级声明；`SIGNED` 展开为 2 个具体类型 |
| `PKIX1Implicit-2009` | RFC 5912 §14 | `PKIX-Flattened-2009.asn1` | 同上 | 38 个类型级声明全部保留名称 |
| `PKIX-X400Address-2009` | RFC 5912 §14 | 不单独带出 | 无 | 仅 `GeneralName.x400Address` 需要 `ORAddress`；以 `[3] OCTET STRING` 占位（非开放类型），一期不可结构化读取，见第 7 节第 6 项 |

合并原因：

1. `PKIX1Explicit-2009` 依赖 `PKIX-CommonTypes-2009` 与 `AlgorithmInformation-2009` 的 `AlgorithmIdentifier`。
2. `PKIX1Implicit-2009` 依赖 `PKIX1Explicit-2009` 的 `Name`、`RelativeDistinguishedName`、`CertificateSerialNumber`、`DirectoryString`、`id-pe`、`id-kp`、`id-qt-*`，以及 `PKIX-CommonTypes-2009` 的 `AttributeSet`。
3. 若按原模块拆成三个文件且要求各自无 `IMPORTS`，同一类型必须在多个文件中重复定义，违背 `docs/11-描述表格式.md` §14.2 的“每个类型恰好存在一个同名类型”检查。合并为单文件后每个类型只定义一次。

输出模块使用 `DEFINITIONS IMPLICIT TAGS`。原 `PKIX1Explicit-2009` 的裸 `[n]` 标签已逐处改写为 `[n] EXPLICIT`，以保持原 EXPLICIT 默认语义；原 `PKIX1Implicit-2009` 的裸 `[n]` 保持隐式语义。

**与冻结文档的冲突需裁决：** `docs/09-里程碑与分期.md` §3.1 要求“每个模块一个文件”，而本任务书要求“每个输出文件自包含、不留 `IMPORTS`”。两者与 `docs/11-描述表格式.md` §14.2 的“每个类型恰好一个同名类型”不能同时满足：三文件方案必须在各文件重复定义依赖类型，单文件方案才能保证类型唯一。本轮按任务书“允许按依赖关系合并成较少的文件”执行单文件方案；`docs/09` 与 `docs/03`（`IMPORTS` 一期必须支持）的表述需由文档维护方同步。

## 4. 类型总数

计数口径：类型级声明（含参数化基类型与 `TYPE-IDENTIFIER` 类别名），不含信息对象、信息对象集和值赋值。

| 来源 | 原声明数 | 输出类型数 | 差异 |
| --- | --- | --- | --- |
| `PKIX-CommonTypes-2009` | 6 | 6 | 无（全部去参数化/去类化） |
| `PKIX1Explicit-2009` | 23 | 24 | `SIGNED` 删除，新增 `SIGNED-TBSCertificate`、`SIGNED-TBSCertList`，净 +1 |
| `PKIX1Implicit-2009` | 38 | 38 | 无（`CERT-POLICY-QUALIFIER`、`OTHER-NAME` 去类化为具体类型，名称不变） |
| `AlgorithmInformation-2009`（仅支持类型） | 1（`AlgorithmIdentifier`） | 1 | 去参数化为具体类型 |
| **合计** | **68** | **69** | 净 +1 |

其中三目标模块包含 7 个参数化类型（`AttributeSet`、`SingleAttribute`、`Extensions`、`Extension`、`SecurityCategory`、`DirectoryString`、`SIGNED`），支持的 `AlgorithmIdentifier` 也是参数化类型；另有 3 个 `TYPE-IDENTIFIER` 类别名（`SECURITY-CATEGORY`、`CERT-POLICY-QUALIFIER`、`OTHER-NAME`）。逐类型对账见 [reconciliation.md](reconciliation.md)。

开放类型字段由 `OCTET STRING` 占位改为 `ANY` 属于**字段类型替换**，不新增、不删除、不改名任何类型，类型总数仍为 69。

## 5. 勘误核对

对 `docs/11-描述表格式.md` §15.2 登记的 8 条 Verified 勘误逐条核对，结论如下。

| Errata ID | 位置 | 是否影响本产出 | 处理 |
| --- | --- | --- | --- |
| 2649 | §7 `AttributeCertificateVersion1-2009` | 否 | 该模块不在本次三个模块范围内；未改动 |
| 2839 | §14 `anyPolicy` | 否（说明性勘误） | 勘误本身说明 `anyPolicy` 不出现在 `PKIX1Implicit-2009`；原文该模块确实没有该定义，产出中也没有 |
| 3130 | 全文 `CONTENT-TYPE` | 否 | 涉及其他模块的 `CONTENT-TYPE` 信息对象；本产出不含该类对象 |
| 3259 | §4 OCSP 的 `CRLReason` | 否 | 该模块不在范围内；本产出保留 §14 的 `CRLReason ::= ENUMERATED`，未采用 OCSP 错误重定义 |
| 3626 | §14 `ext-CRLNumber` | 否（对象已删除） | 该勘误只影响 `ext-CRLNumber` 信息对象；该对象按展平策略删除，`CRLNumber ::= INTEGER (0..MAX)` 类型已保留 |
| 3692 | §14 `crlExtensions` 对象集 | 否（对象集已删除） | `CrlExtensions` 信息对象集按策略删除；不影响任何保留类型的结构 |
| 4244 | §14 三个 X520 `ATTRIBUTE` 对象 | 否（对象已删除） | 该勘误只改 `at-x520*` 信息对象的 `TYPE` 引用；这些对象已删除，`X520StateOrProvinceName`、`X520OrganizationName`、`X520OrganizationalUnitName` 类型本身已保留 |
| 6806 | §6 `pk-rsa` | 否 | 该模块不在范围内；本次未带出算法对象 |

补充：RFC Editor 页面上另有一条 **Reported（未 Verified）** 勘误 9255（2026-11-02），指出 2649 修正后的 OID 仍把 `dod(6)` 挂在 `member-body(2)` 下。它不在 `docs/11` 的 8 条 Verified 清单内，且涉及 §7 的非目标模块，本产出不采用。

结论：**对最终保留的类型，没有需要改写的正文级勘误。** 3626/3692/4244 的语义已记录，但其载体信息对象按展平策略删除，因此不改变输出类型。

另核对 `docs/11` §15.1 列出的后续更新：RFC 6960 只更新第 4 节 OCSP 模块，RFC 9480 与 RFC 9810 只更新第 9 节 CMP 模块，均不触及第 2、3、14 节，因此不影响本产出。

## 6. 展平策略逐条记录

所有处理均按类型/构造逐条执行，未静默丢弃。完整类型级映射见 [reconciliation.md](reconciliation.md)。

### 6.1 信息对象类 `CLASS` / `WITH SYNTAX`

| 原构造 | 处理 | 影响范围 |
| --- | --- | --- |
| `ATTRIBUTE ::= CLASS {...}` | 删除类定义；`ATTRIBUTE.&id` 统一改写为 `OBJECT IDENTIFIER`，`ATTRIBUTE.&Type` 改写为 `ANY`（开放类型，保留完整原始 TLV） | `AttributeType`、`AttributeSet`、`SingleAttribute` |
| `MATCHING-RULE ::= CLASS {...}` | 删除；本次三个模块中的保留类型未使用该字段 | 无保留类型 |
| `EXTENSION ::= CLASS {...}` | 删除类定义；`EXTENSION.&id` → `OBJECT IDENTIFIER`，`&ExtnType` → `OCTET STRING`（原文 `extnValue` 本身即 `OCTET STRING (CONTAINING ...)`，不是开放类型） | `Extension`、`Extensions` |
| `TYPE-IDENTIFIER` 类别名 | 改写为具体 `SEQUENCE`，字段取该类实例的编码结构 | `SECURITY-CATEGORY`、`CERT-POLICY-QUALIFIER`、`OTHER-NAME` |
| `AlgorithmInformation-2009` 中的算法类 | 不进入产出；只保留实例化后的 `AlgorithmIdentifier` | `SIGNED*`、`TBSCertificate`、`TBSCertList`、`SubjectPublicKeyInfo` |

### 6.2 参数化类型展开

| 原参数化类型 | 实参 | 处理 | 输出类型 |
| --- | --- | --- | --- |
| `DirectoryString{INTEGER:maxSize}` | 无（基类型） | 保留名称，`SIZE (1..MAX)` | `DirectoryString` |
| `DirectoryString{maxSize}` | `ub-name` 等 6 个实例 | 每个实例展开为独立 `CHOICE`，写入具体上界 | `X520name`、`X520CommonName`、`X520LocalityName`、`X520StateOrProvinceName`、`X520OrganizationName`、`X520OrganizationalUnitName` |
| `DirectoryString{ubMax}` | `EDIPartyName` | 直接用基类型 `DirectoryString`（`ubMax = 32768` 与基类型 `MAX` 在本结构中不构成更严约束） | `EDIPartyName` |
| `AttributeSet{ATTRIBUTE:AttrSet}` | `{SupportedAttributes}` | 展开为单一具体类型；对象集约束删除 | `AttributeSet` |
| `SingleAttribute{ATTRIBUTE:AttrSet}` | `{SupportedAttributes}` | 展开为单一具体类型 | `SingleAttribute` |
| `Extensions{EXTENSION:ExtensionSet}` | `CertExtensions`、`CrlExtensions`、`CrlEntryExtensions` | 三个对象集的结构相同，合并为一个具体类型；对象集成员约束删除 | `Extensions` |
| `Extension{EXTENSION:ExtensionSet}` | 同上 | 展开为单一具体类型 | `Extension` |
| `SecurityCategory{SECURITY-CATEGORY:Supported}` | `Supported` | 展开为单一具体类型 | `SecurityCategory` |
| `SIGNED{ToBeSigned}` | `TBSCertificate`、`TBSCertList` | 每个实参生成独立具体类型；基类型 `SIGNED` 不保留 | `SIGNED-TBSCertificate`、`SIGNED-TBSCertList` |
| `AlgorithmIdentifier{ALGORITHM-TYPE, ALGORITHM-TYPE:AlgorithmSet}` | 多处 | 展开为单一具体类型，`parameters` 改写为 `ANY OPTIONAL` | `AlgorithmIdentifier` |

参数化类型不再出现在输出中；实例化后的类型重新参与字段与标签检查。

### 6.3 信息对象与信息对象集

以下定义**全部删除**，其 OID 值赋值（`id-*`、`id-at-*`、`id-ce-*` 等）保留：

- `PKIX1Explicit-2009`：`at-name`、`at-surname`、`at-givenName`、`at-initials`、`at-generationQualifier`、`at-x520CommonName`、`at-x520LocalityName`、`at-x520StateOrProvinceName`、`at-x520OrganizationName`、`at-x520OrganizationalUnitName`、`at-x520Title`、`at-x520dnQualifier`、`at-x520countryName`、`at-x520SerialNumber`、`at-x520Pseudonym`、`at-domainComponent`、`at-emailAddress`；对象集 `SupportedAttributes`、`SignatureAlgorithms`、`PublicKeyAlgorithms`。
- `PKIX1Implicit-2009`：`ext-*` 信息对象（共 25 个）、`CertExtensions`、`CrlExtensions`、`CrlEntryExtensions`、`PolicyQualifierId`、`pqid-cps`、`pqid-unotice`。
- `PKIX-X400Address-2009`：`ea-*`、`SupportedExtensionAttributes`（该模块整体未带出）。

理由：目标语法不支持 `CLASS`/信息对象/对象集；这些对象只承担“OID → 类型/约束”的绑定，实际结构已由具体类型和 OID 值赋值覆盖。删除后不会改变任何保留类型的字段、标签或编码。

### 6.4 标签与约束

| 原构造 | 处理 |
| --- | --- |
| 模块级 `DEFINITIONS EXPLICIT TAGS` | 合并模块选 `IMPLICIT TAGS`；`TBSCertificate.version`、`TBSCertificate.extensions`、`TBSCertList.crlExtensions` 显式改写为 `[n] EXPLICIT` |
| 模块级 `DEFINITIONS IMPLICIT TAGS` | 保持隐式；裸 `[n]` 不变 |
| `[[n: ... ]]` 扩展组 | 展开为普通可选字段，组号与版本约束删除；字段名、顺序、标签保留 |
| `WITH COMPONENTS {...}` | 删除约束（`AuthorityKeyIdentifier`、`PrivateKeyUsagePeriod`） |
| `CONTAINING ...` | 删除约束，类型本身不变（`Extension.extnValue`、`SIGNED*.signature`） |
| `INSTANCE OF OTHER-NAME` | 改为 `[0] OTHER-NAME`，`OTHER-NAME` 为具体 `SEQUENCE` |
| `[APPLICATION n]` | 未出现在三个目标模块；`PKIX-X400Address-2009` 整体未带出 |
| `COMPONENTS OF` | 三个模块正文中未实际使用（仅出现在 `SIGNED` 注释示例中）；无需展开 |

### 6.5 值赋值

- 保留所有 `OBJECT IDENTIFIER` 值赋值（`id-pkix`、`id-pe`、`id-qt`、`id-kp`、`id-ad`、`id-at*`、`id-ce*`、`id-kp-*`、`id-ad-*`、`holdInstruction`、`id-holdinstruction-*`、`pkcs-9` 等）。
- 保留所有 `INTEGER` 常量（`ub-*`、`ubMax`）。
- `id-* AttributeType ::= {...}` 保留，`AttributeType` 已改写为 `OBJECT IDENTIFIER`。
- 不保留信息对象定义（`at-*`、`ext-*`、`pqid-*`、`ea-*`）。

## 7. 无法无损展平、必须裁剪或替换的项

以下各项均会改变“按 schema 自动解码”的能力，消费方必须知悉。逐类型状态见 [reconciliation.md](reconciliation.md)。

**开放类型统一约定：** 下列 `ANY` 字段在核心中对应 `ASNBER_TYPE_KIND_ANY`——解码时保留完整原始 TLV，编码时原样写回，不结构化展开，子节点数为 0。本节列出的任何 `ANY` 字段都**不能**按同类 OID（算法 OID、属性 OID、`type-id`、`policyQualifierId`）自动分派到具体结构；需要结构化的消费方须自行按 OID 二次解析保留的 TLV。

1. **`AlgorithmIdentifier.parameters`：`OCTET STRING OPTIONAL` → `ANY OPTIONAL`**
   原字段是随算法 OID 变化的开放类型（`ALGORITHM-TYPE.&Params`）。上一版用 `OCTET STRING` 占位，现改为 `ANY`。
   影响：真证书可正常解码——`sha256WithRSAEncryption` 的 `NULL` 参数、`RSASSA-PSS` 的 `SEQUENCE` 参数都能原样保留并写回。仍不能结构化展开 `parameters`，也不能据 `algorithm` 自动解出参数内容。

2. **`AttributeSet.values` / `SingleAttribute.value`：`OCTET STRING` 占位 → `ANY`**
   原字段是 `ATTRIBUTE.&Type` 开放类型，现为 `SET SIZE (1..MAX) OF ANY` / `ANY`。
   影响：属性值保留完整原始 TLV，可原样写回；但仍不能按属性 OID 自动展开为具体结构。

3. **`SecurityCategory.value` / `SECURITY-CATEGORY.value`：`[1] EXPLICIT OCTET STRING` → `[1] EXPLICIT ANY`**
   原字段是 `SECURITY-CATEGORY.&Type` 开放类型。显式标签 `[1] EXPLICIT` 保留，只替换内层类型。
   影响：类别值保留完整 TLV 并可原样写回；内容不可结构化解码。

4. **`GeneralName.otherName` 的 `INSTANCE OF OTHER-NAME` → `[0] OTHER-NAME`**
   `OTHER-NAME` 被改写为 `SEQUENCE { type-id OBJECT IDENTIFIER, value [0] EXPLICIT ANY }`。
   影响：`type-id` 可正常解码；`value` 保留完整 TLV 并可原样写回，但不能按 `type-id` 自动展开。

5. **`PolicyQualifierInfo.qualifier`：`OCTET STRING` 占位 → `ANY`**
   原字段是 `CERT-POLICY-QUALIFIER.&Type` 开放类型。
   影响：CPS URI 与 `UserNotice` 等 qualifier 都能原样保留和写回；但仍不能据 `policyQualifierId` 自动展开为 `CPSuri` 或 `UserNotice`。

6. **`GeneralName.x400Address` 的 `ORAddress` → `[3] OCTET STRING`（保持 OCTET STRING）**
   该字段**不是开放类型**：原文语义是固定的 `ORAddress` 结构，只因 `PKIX-X400Address-2009` 整体未带出（该模块还含 `[APPLICATION n]` 标签，超出目标子集）而无法结构化表达。
   影响：X.400 地址一期**不可结构化读取**；`[3]` 隐式标签保留，内容按 `OCTET STRING` 读取，仅能原样写回。PKIX/Web PKI 中该分支极少使用。

7. **`SIGNED{ToBeSigned}` → `SIGNED-TBSCertificate` / `SIGNED-TBSCertList`**
   参数化基类型 `SIGNED` 名称不再存在。影响：下游按类型名引用时必须使用两个具体名；`Certificate`、`CertificateList` 已指向新名。

8. **`DirectoryString{INTEGER:maxSize}` 基类型 → `SIZE (1..MAX)`**
   6 个具名实例已按具体上界展开；基类型本身无法在无参数语法中保留 `maxSize`。影响：直接引用 `DirectoryString` 的 `EDIPartyName` 使用 `MAX`，不再显式写 `32768`。

9. **`Extensions{ExtensionSet}` → 单一 `Extensions`**
   `CertExtensions`、`CrlExtensions`、`CrlEntryExtensions` 的成员集合约束被删除。影响：解码器不会拒绝不在对应集合中的扩展 OID；结构仍正确。

10. **`SIGNED*` 的 `signature BIT STRING (CONTAINING ...)` 与 `Extension.extnValue OCTET STRING (CONTAINING ...)`**
    约束删除。影响：类型与编码不变，仅失去“内容应与算法/扩展类型对应”的编译期约束。

11. **`WITH COMPONENTS` 约束删除**
    `AuthorityKeyIdentifier` 的“issuer 与 serial 同时出现/同时缺席”约束；`PrivateKeyUsagePeriod` 的“至少一个字段出现”约束。影响：结构不变，语义约束不再由 schema 表达。

12. **`[[n: ... ]]` 扩展组展开**
    影响：扩展组号与“版本必须为 v2/v3”的语义约束丢失；字段标签、顺序、可选性不变。

13. **`PKIX-X400Address-2009` 未带出**
    除第 6 项外，`ORAddress`、`CountryName`、`AdministrationDomainName`、`BuiltInStandardAttributes`、`PDSParameter`、`PresentationAddress` 等类型均不进入产出。影响：无 X.400 结构支持。

## 8. 给 asnberc 的语法子集需求清单

### 8.1 必须支持（否则无法解析本产出）

| 类别 | 具体要求 | 本产出中的例子 |
| --- | --- | --- |
| 模块头 | 名称可含连字符；`DEFINITIONS IMPLICIT TAGS ::= BEGIN`；允许无模块 OID | `PKIX-Flattened-2009 DEFINITIONS IMPLICIT TAGS ::= BEGIN` |
| 类型引用 | 同模块前向/后向引用；名称可含连字符 | `SIGNED-TBSCertificate`、`CERT-POLICY-QUALIFIER`、`OTHER-NAME` |
| 基本类型 | `BOOLEAN`、`INTEGER`（含命名值）、`ENUMERATED`、`BIT STRING`（含命名位）、`OCTET STRING`、`OBJECT IDENTIFIER`、`UTF8String`、`PrintableString`、`IA5String`、`VisibleString`、`BMPString`、`UniversalString`、`UTCTime`、`GeneralizedTime`、`TeletexString` | `Version`、`KeyUsage`、`CRLReason`、`DirectoryString` |
| 开放类型 | **裸 `ANY`**（映射到核心的 `ASNBER_TYPE_KIND_ANY`：解码保留完整原始 TLV、编码原样写回、不结构化展开、子节点数为 0） | `AlgorithmIdentifier.parameters`、`AttributeSet.values`、`SingleAttribute.value`、`SECURITY-CATEGORY.value`、`CERT-POLICY-QUALIFIER.qualifier`、`OTHER-NAME.value` |
| 构造类型 | `SEQUENCE`、`SET`、`CHOICE`、`SEQUENCE OF`、`SET OF`；允许匿名内联 `SEQUENCE` | `TBSCertList.revokedCertificates`、`PolicyMappings` |
| 字段修饰 | `OPTIONAL`、`DEFAULT`（`BOOLEAN FALSE`、`INTEGER 0`、命名整数 `v1`） | `critical DEFAULT FALSE`、`version DEFAULT v1`、`minimum DEFAULT 0` |
| 标签 | 模块级默认标签模式；`[n]`、`[n] IMPLICIT`、`[n] EXPLICIT`；CHOICE 备选项标签 | `[0] EXPLICIT Version`、`[1] IMPLICIT UniqueIdentifier`、`[3] OCTET STRING` |
| 约束 | `SIZE (a..b)`、值域 `(a..b)`、`MAX`；可用于基本类型和 `SET/SEQUENCE OF` | `SIZE (1..MAX)`、`INTEGER (0..MAX)`、`SIZE (1..200)` |
| 扩展标记 | `...` 出现在 `SEQUENCE`、`ENUMERATED` 中 | `TBSCertificate`、`CRLReason` |
| 值赋值 | `OBJECT IDENTIFIER` 值（含名称/数字形式）；`INTEGER` 常量；被约束与 `DEFAULT` 引用的值 | `id-pkix`、`ub-name`、`ubMax`、`v1` |
| 类型别名 | `T2 ::= T1` | `DistinguishedName ::= RDNSequence`、`SecurityCategory ::= SECURITY-CATEGORY` |
| 注释 | `--` 行注释 | 文件头与逐段说明 |

**特别提示：`TeletexString` 是必须支持的基本类型。** `DirectoryString` 的第一个备选项就是 `TeletexString`；`docs/11-描述表格式.md` §13.1 的基本类型清单未列出它，属于文档缺口，`asnberc` 实现时需补齐。

**当前实现状态：除 `IMPORTS`/参数化外均通过。** 本轮 `asnberc` 以本文件为真实输入完成端到端回归：解析、语义校验、描述表生成与核心加载全部通过。

### 8.2 明确不支持 / 本产出已避免

| 构造 | 状态 |
| --- | --- |
| `CLASS`、`WITH SYNTAX`、信息对象、信息对象集 | 不支持；本产出已全部删除/改写 |
| 参数化类型及实参实例化 | 不支持；本产出已全部展开 |
| `INSTANCE OF`、`TYPE-IDENTIFIER` | 不支持；本产出已改写为具体 `SEQUENCE` |
| `COMPONENTS OF` | 不支持；本产出未使用 |
| `WITH COMPONENTS` | 不支持；本产出已删除 |
| `CONTAINING`、`CONSTRAINED BY` | 不支持；本产出已删除 |
| `ANY DEFINED BY`（带类型约束的开放类型） | 一期不支持。解析器遇到时必须给出**明确诊断**（报错并指明位置与构造），**不得静默当作裸 `ANY`** 处理；本产出未使用该构造 |
| `APPLICATION`/`PRIVATE`/`UNIVERSAL` 标签类 | 不支持；本产出未使用 |
| `[[n: ... ]]` 扩展组、同类型多个 `...` | 不支持；本产出已展开为普通字段与单个 `...` |
| `PATTERN`、通用值集合运算 | 不支持；本产出未使用 |
| 宏定义、用户自定义编码规则 | 不支持；本产出未使用 |

## 9. 校验与局限

- 已逐段比对 RFC 5912 第 2、3、14 节，逐类型核对名称、字段、顺序、`OPTIONAL`/`DEFAULT`、标签与约束。
- 已做文本级自检：文件中不存在 `::= CLASS`、`WITH SYNTAX`、`IMPORTS`、参数化实例、`COMPONENTS OF`、`WITH COMPONENTS`、`INSTANCE OF`、`CONTAINING`、`ANY DEFINED BY`、`[[` 等构造，连说明性注释中也未出现这些关键字（`ANY` 本身已是允许的语法，不再计入禁用词）。
- 开放类型自检：`ANY` 作为字段类型共 6 处，分别位于 `AttributeSet.values`、`SingleAttribute.value`、`SECURITY-CATEGORY.value`、`AlgorithmIdentifier.parameters`、`CERT-POLICY-QUALIFIER.qualifier`、`OTHER-NAME.value`；另有 3 处说明性注释提及 `ANY`。
- 剩余 `OCTET STRING` 作为字段类型共 4 处，均为非开放类型：`Extension.extnValue`（原文即 `OCTET STRING`）、`GeneralName.x400Address`（ORAddress 替代）、`GeneralName.iPAddress`（原文即 `OCTET STRING`）、`KeyIdentifier`（原文即 `OCTET STRING`）；另有 3 处说明性注释提及。
- 类型总数保持 69；括号 `()`/`{}` 与 `BEGIN`/`END` 均平衡。
- **编译器级校验**：本机没有可用的外部 ASN.1 语法检查工具；本轮已用 `asnberc` 以本文件为首个真实输入完成解析、语义校验与描述表加载回归。
- `docs/11-描述表格式.md` §14.1 已同步记录本目录已产出展平模块 `PKIX-Flattened-2009.asn1`。

### 9.1 与 `docs/11` §14.2 展平等价性 CI 的冲突

按当前冻结的 §14.2 五条检查，本产出**无法全部通过**，原因均是目标语法子集缺少开放类型/参数化/对象集，而非转录错误：

| §14.2 检查 | 本产出结果 | 具体项 |
| --- | --- | --- |
| 1. 类型集合逐一对应，不得增删改名 | 不通过 | 删除 `SIGNED`；新增 `SIGNED-TBSCertificate`、`SIGNED-TBSCertList`（参数化展开所必需）；新增支持类型 `AlgorithmIdentifier`（自包含所必需） |
| 2. 字段与顺序一致 | 基本通过 | 字段名/顺序/`OPTIONAL`/`DEFAULT`/扩展位置均保留；例外是扩展组展开为普通字段 |
| 3. 标签一致（有效标签） | 通过 | 合并为 IMPLICIT 默认后，原 EXPLICIT 的 3 处裸标签已显式标注 `EXPLICIT`，有效标签不变 |
| 4. 约束一致 | 不通过 | `DirectoryString` 基类型 `MAX`、对象集成员约束删除、`WITH COMPONENTS`/`CONTAINING` 删除 |
| 5. 抽样 DER 编码等价 | 通过（编码字节层面） | 6 个开放类型字段改为 `ANY` 后保留完整原始 TLV、原样写回；`x400Address` 在 `[3]` 隐式标签下按 `OCTET STRING` 读写的字节与 `ORAddress` 内容字节相同。差异只体现在“能否结构化读取”，不影响编码字节 |

结论：若 §14.2 保持原文，CI 仍会在第 1、4 条上失败。需文档维护方在“展平等价性”中为参数化展开、约束裁剪以及“`ANY` 字段不能结构化展开”建立例外清单；本文件与 [reconciliation.md](reconciliation.md) 可直接作为例外清单的输入。编码字节层面（第 3、5 条）已不再因开放类型而失败。

## 10. 目录内容

| 文件 | 用途 |
| --- | --- |
| `PKIX-Flattened-2009.asn1` | 展平模块，`asnberc` 一期输入 |
| `README.md` | 本说明：来源、勘误、策略、映射、类型总数、语法需求 |
| `reconciliation.md` | 类型级对账表 |
| `reference/rfc5912/rfc5912.txt` | RFC 5912 原文，仅作对照 |
| `reference/rfc5912/errata.html` | RFC 5912 勘误页快照，仅作对照 |

原版模块不参与构建，也不得被核心或模块公共头引用。
