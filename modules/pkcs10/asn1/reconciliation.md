# PKCS#10 展平模块类型级对账表

对账口径：以 RFC 2986（2000-11，PKCS#10）原文为基准，逐类型比对展平模块中的定义。

- 输出文件：`PKCS10-Flattened-2986.asn1`。
- 统计：11 个类型定义，其中 6 个来自 RFC 2986，5 个为展平补齐的引用类型。
- 状态含义：
  - **原样**：名称、字段、顺序、标签、约束均不变。
  - **补齐**：原模块通过 `IMPORTS` 引用，展平后写入本模块的类型。
  - **替换**：开放类型字段改写为 `ANY`（保留完整原始 TLV），结构位置不变。
  - **语法调整**：仅消除 DER 等价的语法包装或约束标记。
- 本模块不做密码学语义：不验签、不解析 SPKI 内部的密钥。

## RFC 2986（PKCS#10）

| # | 原类型名 | 输出类型名 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| 1 | `CertificationRequest` | `CertificationRequest` | 原样 | `certificationRequestInfo`、`signatureAlgorithm`、`signature` 字段顺序不变 |
| 2 | `CertificationRequestInfo` | `CertificationRequestInfo` | 原样 | `version`、`subject`、`subjectPKInfo`、`[0] IMPLICIT attributes` 不变 |
| 3 | `Version` | `Version` | 语法调整 | 原版 `INTEGER { v1(0) } (v1,...)`；扩展标记不影响 DER，省略值名与扩展标记，展平为无约束 `INTEGER`，使非 0 版本按原值返回、不被解码期拒绝 |
| 4 | `Name`（X.501/PKCS#9 导入） | `Name` | 补齐 + 语法调整 | 原版为 `CHOICE { rdnSequence RDNSequence }`，只有单一选择项，展平为 `Name ::= RDNSequence`，DER 等价 |
| 5 | `RDNSequence`（X.501） | `RDNSequence` | 补齐 | `SEQUENCE OF RelativeDistinguishedName` |
| 6 | `RelativeDistinguishedName`（X.501） | `RelativeDistinguishedName` | 补齐 | `SET SIZE (1..MAX) OF AttributeTypeAndValue` |
| 7 | `AttributeTypeAndValue`（X.501） | `AttributeTypeAndValue` | 补齐 + 替换 | 值字段为开放类型，展平为 `value ANY`（完整原始 TLV） |
| 8 | `SubjectPublicKeyInfo` | `SubjectPublicKeyInfo` | 原样 | `algorithm`、`subjectPublicKey` 不变 |
| 9 | `Attributes` | `Attributes` | 原样 | `SET OF Attribute` |
| 10 | `Attribute` | `Attribute` | 替换 | `values SET SIZE (1..MAX) OF ANY`（成员类型为开放类型） |
| 11 | `AlgorithmIdentifier`（RFC 5280 导入） | `AlgorithmIdentifier` | 补齐 + 替换 | `parameters` 改为 `ANY OPTIONAL` |

## 未纳入的类型与理由

| 类型/内容 | 理由 |
| --- | --- |
| PKCS#10 的具体属性值语义（`extensionRequest` 等 PKCS#9 属性） | CSR 只读通用 `Attribute` 结构；具体属性值由调用方按 `type` OID 从 `values` 的 ANY 二次解析 |
| PKCS#10 的签名校验与公钥算法语义 | 模块只读结构，不验签、不做密码学运算；`subjectPublicKey` 的算法解释由调用方完成 |

## 验证

- 1 张描述表由 `asnberc` 从上述展平模块生成，`--root` 为 `CertificationRequest`；`CertificationRequestInfo` 由模块在加载期以根编号 `2` 指定。
- `-DASNBER_PKCS10_REGENERATE_TABLE=ON` 重新生成后与检入产物逐字节比对；差异即构建失败。
- 真实样本覆盖：RSA CSR 与 EC CSR。
