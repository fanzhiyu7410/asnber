# PKCS#8 展平模块类型级对账表

对账口径：以 RFC 5208（2008-05，PKCS#8）原文为基准，逐类型比对展平模块中的定义。

- 输出文件：`PKCS8-Flattened-5208.asn1`。
- 统计：8 个类型定义，其中 6 个来自 RFC 5208，2 个为展平补齐的引用类型。
- 状态含义：
  - **原样**：名称、字段、顺序、标签、约束均不变。
  - **补齐**：原模块通过 `IMPORTS` 引用，展平后写入本模块的类型。
  - **替换**：开放类型字段改写为 `ANY`（保留完整原始 TLV），结构位置不变。
- 本模块不做密码学语义：不解密、不做口令密钥派生。

## RFC 5208（PKCS#8）

| # | 原类型名 | 输出类型名 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| 1 | `PrivateKeyInfo` | `PrivateKeyInfo` | 原样 | `version`、`privateKeyAlgorithm`、`privateKey`、`[0] IMPLICIT attributes OPTIONAL` 均不变 |
| 2 | `Version` | `Version` | 原样 | `INTEGER` |
| 3 | `PrivateKey` | `PrivateKey` | 原样 | `OCTET STRING` |
| 4 | `Attributes` | `Attributes` | 原样 | `SET OF Attribute` |
| 5 | `EncryptedPrivateKeyInfo` | `EncryptedPrivateKeyInfo` | 原样 | `encryptionAlgorithm`、`encryptedData` 不变 |
| 6 | `EncryptedData` | `EncryptedData` | 原样 | `OCTET STRING` |
| 7 | `AlgorithmIdentifier`（RFC 5280 导入） | `AlgorithmIdentifier` | 补齐 + 替换 | 补齐为本模块 `SEQUENCE`；`parameters` 由随算法变化的开放类型改为 `ANY OPTIONAL` |
| 8 | `Attribute`（RFC 2985/PKCS#9 导入） | `Attribute` | 补齐 + 替换 | 补齐为 `SEQUENCE { type OBJECT IDENTIFIER, values SET SIZE (1..MAX) OF ANY }`；`values` 的成员类型改为 `ANY` |

## 未纳入的类型与理由

| 类型/内容 | 理由 |
| --- | --- |
| RFC 5208 中的 `Attributes` 之外的 PKCS#9 属性定义（`PKCS9Attribute` 等） | 本模块只读 `Attributes` 的通用结构，不展开具体属性值；`values` 以 `ANY` 保留原始 TLV |
| PKCS#8 v2（RFC 5958）的版本语义 | 不改变 `PrivateKeyInfo`/`EncryptedPrivateKeyInfo` 字段结构；本切片按 RFC 5208 生成，后续需要时单独评估 |

## 验证

- 1 张描述表由 `asnberc` 从上述展平模块生成，`--root` 为 `PrivateKeyInfo`；`EncryptedPrivateKeyInfo` 由模块在加载期以根编号 `5` 指定。
- `-DASNBER_PKCS8_REGENERATE_TABLE=ON` 重新生成后与检入产物逐字节比对；差异即构建失败。
- 真实样本覆盖：PKCS#8 RSA 明文、PKCS#8 RSA-PSS（参数为 `SEQUENCE`）、加密 PKCS#8（PBES2）。
