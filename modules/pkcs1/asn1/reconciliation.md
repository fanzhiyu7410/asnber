# PKCS#1 展平模块类型级对账表

对账口径：以 RFC 8017（2016-11，PKCS#1 Appendix A）原文为基准，逐类型比对展平模块中的定义。

- 输出文件：`PKCS1-Flattened-8017.asn1`。
- 统计：3 个类型定义，全部来自 RFC 8017。
- 状态含义：**原样**表示名称、字段、顺序、标签、约束均不变。
- 本模块不做密码学语义：不做 RSA 运算与填充。

## RFC 8017 Appendix A（PKCS#1）

| # | 原类型名 | 输出类型名 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| 1 | `RSAPublicKey` | `RSAPublicKey` | 原样 | `modulus INTEGER`、`publicExponent INTEGER` |
| 2 | `RSAPrivateKey` | `RSAPrivateKey` | 原样 | `version`、`modulus`、`publicExponent`、`privateExponent`、`prime1`、`prime2`、`exponent1`、`exponent2`、`coefficient` 字段顺序不变 |
| 3 | `Version` | `Version` | 原样 | `INTEGER { two-prime(0), multi(1) }` |

## 未纳入的类型与理由

| 类型/内容 | 理由 |
| --- | --- |
| RFC 8017 中的算法标识、填充参数结构、`AlgorithmIdentifier` 的算法特定参数 | PKCS#1 模块只读密钥结构；填充参数如需读取，由调用方按 OID 从 `ANY` 原始 TLV 二次解析 |

## 验证

- 1 张描述表由 `asnberc` 从上述展平模块生成，`--root` 为 `RSAPublicKey`；`RSAPrivateKey` 由模块在加载期以根编号 `2` 指定。
- `-DASNBER_PKCS1_REGENERATE_TABLE=ON` 重新生成后与检入产物逐字节比对；差异即构建失败。
- 真实样本覆盖：PKCS#1 公钥与私钥。
