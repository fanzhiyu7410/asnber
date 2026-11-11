# PKCS#12 展平模块类型级对账表

对账口径：以 RFC 7292（2014-07，PKCS#12 附录 D）原文为基准，逐类型比对展平模块中的定义；`ContentInfo`、`DigestInfo`、`AlgorithmIdentifier` 以 RFC 5652 4.1/5.2 为准。

- 输出文件：`PKCS12-Flattened-7292.asn1`。
- 统计：13 个类型定义（RFC 7292 附录 D 9 个，RFC 5652 借入 4 个）。
- 状态含义：**原样**表示名称、字段、顺序、标签、约束均不变；**展平**表示去掉了 `IMPORTS`/信息对象类或参数化，DER 结构不变。
- 本模块不做密码学语义：不解密、不验 MAC、不做口令密钥派生。

## RFC 7292 附录 D（PKCS#12）

| # | 原类型名 | 输出类型名 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| 1 | `PFX` | `PFX` | 展平 | `version` 原文为 `INTEGER { v3(3) }(v3,...)`，展平为无约束 `INTEGER`；值名不影响 DER，非 3 的值按原值返回 |
| 2 | `MacData` | `MacData` | 原样 | `iterations INTEGER DEFAULT 1` 保留 |
| 3 | `AuthenticatedSafe` | `AuthenticatedSafe` | 原样 | `SEQUENCE OF ContentInfo` |
| 4 | `SafeContents` | `SafeContents` | 原样 | `SEQUENCE OF SafeBag` |
| 5 | `SafeBag` | `SafeBag` | 展平 | `bagValue [0] EXPLICIT ANY`（原为 `BAG-TYPE.&Type`）；`bagAttributes SET OF PKCS12Attribute OPTIONAL` 保留 |
| 6 | `PKCS12Attribute` | `PKCS12Attribute` | 展平 | `attrValues SET OF ANY`（原为 `ATTRIBUTE.&Type`） |
| 7 | `CertBag` | `CertBag` | 展平 | `certId` + `certValue [0] EXPLICIT ANY` |
| 8 | `CRLBag` | `CRLBag` | 展平 | `crlId` + `crltValue [0] EXPLICIT ANY` |
| 9 | `SecretBag` | `SecretBag` | 展平 | `secretTypeId` + `secretValue [0] EXPLICIT ANY` |

## RFC 5652 借入类型

| # | 原类型名 | 输出类型名 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| 10 | `ContentInfo`（RFC 5652 4.1） | `ContentInfo` | 展平 | `content [0] EXPLICIT ANY OPTIONAL`；`parameters ANY OPTIONAL` 随算法 OID 变化 |
| 11 | `DigestInfo`（RFC 5652 5.2） | `DigestInfo` | 原样 | `digestAlgorithm` + `digest OCTET STRING` |
| 12 | `AlgorithmIdentifier`（RFC 5652 4.1） | `AlgorithmIdentifier` | 原样 | `algorithm` + `parameters ANY OPTIONAL` |
| 13 | `ContentType`（RFC 5652 4.1） | `ContentType` | 原样 | `OBJECT IDENTIFIER` 别名 |

## 未纳入的内容与理由

| 类型/内容 | 理由 |
| --- | --- |
| 信息对象类 `BAG-TYPE` 的实例（`keyBag`、`pkcs8ShroudedKeyBag`、`safeContentsBag` 等） | 只由 `bagId` 区分，不在结构层单独建模；内层值由调用方按 `bagId` 从 `ANY` 原始 TLV 二次解析 |
| 信息对象类 `ATTRIBUTE` 的实例 | 同上，按 `attrId` 从 `SET OF ANY` 二次解析 |
| `PrivateKeyInfo` / `EncryptedPrivateKeyInfo` | 属于 PKCS#8，见 `modules/pkcs8/asn1/PKCS8-Flattened-5208.asn1`；本模块只在 `keyBag` / `pkcs8ShroudedKeyBag` 中把它们作为 `ANY` 透传 |
| `x509Certificate` / `x509CRL` 结构 | 属于 PKIX；`CertBag` / `CRLBag` 只暴露完整原始 TLV，不解析证书或 CRL 内层 |
| 口令派生、MAC 校验、加解密 | 本库无密码学语义；`MacData` 只做结构访问 |

## 验证

- 1 张描述表由 `asnberc` 从上述展平模块生成，`--root PFX`；其余根（`AuthenticatedSafe` 7、`SafeContents` 8、`CertBag` 11）由模块在加载期指定，编号取自原多表产物头部偏移 96。
- `-DASNBER_PKCS12_REGENERATE_TABLE=ON` 重新生成后与检入产物逐字节比对；差异即构建失败。
- 真实样本覆盖：明文 PFX、口令加密 PFX、仅证书 PFX；静态池、独立安装消费见 `tests/pkcs12`、`tests/embedded`、`tests/consumer`。
