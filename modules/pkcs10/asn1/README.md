# asnber-pkcs10 展平 ASN.1 模块

本目录存放 `asnber-pkcs10` 使用的**自包含展平模块**。`asnberc` 只接受这类输入，不使用 `IMPORTS`，也不做参数化实例化。

## 文件

| 文件 | 对应标准 | 内容 |
| --- | --- | --- |
| `PKCS10-Flattened-2986.asn1` | RFC 2986（PKCS#10） | `CertificationRequest`、`CertificationRequestInfo` 及其引用类型 |
| `reconciliation.md` | — | 与原版模块的逐类型对账表 |
| `reference/rfc2986/rfc2986.txt` | RFC 2986 原文 | 只作参考，不参与构建 |

原文下载自 `https://www.rfc-editor.org/rfc/rfc2986.txt`，获取日期 2026-11-06。

## 展平规则

1. 去掉 `IMPORTS`：`Attribute`（RFC 2985/X.501）与 `Name`/`AttributeTypeAndValue`（X.501）直接写入对应模块。
2. 开放类型字段改为 `ANY`，只保留完整原始 TLV：`AlgorithmIdentifier.parameters`、`Attribute.values`、`AttributeTypeAndValue.value`。
3. 不改字段顺序、`OPTIONAL` 与标签模式；模块默认 `IMPLICIT TAGS`，`attributes` 显式写为 `[0] IMPLICIT`。
4. 两处纯语法展平：`Name ::= CHOICE { rdnSequence RDNSequence }` 只有单一选择项，直接写为 `Name ::= RDNSequence`；`Version` 的扩展标记 `(v1,...)` 不影响 DER 结构，省略不写。
5. 不做密码学语义：本模块不验签、不解析 SPKI 内部的密钥。

## 版本说明

- RFC 2986 未被废止，PKCS#10 结构仍为现行定义；未发现改变上述类型结构的已确认勘误。
- 如后续核对到勘误，先在 `reconciliation.md` 登记再改模块。

## 描述表生成

0.4.0 起一个 ASN.1 文件只生成 1 张表，头部写默认根 `CertificationRequest`；`CertificationRequestInfo` 由模块在 `asnber_schema_load_with_root` 加载时指定根编号 `2`：

| 表 | 输入 | `--root` |
| --- | --- | --- |
| `pkcs10_schema.bin/.h` | `PKCS10-Flattened-2986.asn1` | `CertificationRequest` |

命令示例：

```powershell
asnberc -o modules/pkcs10/generated/pkcs10_schema.bin `
      -c modules/pkcs10/generated/pkcs10_schema.h `
      --root CertificationRequest modules/pkcs10/asn1/PKCS10-Flattened-2986.asn1
```

产物检入 `modules/pkcs10/generated/`，默认构建不需要 `asnberc`。`-DASNBER_PKCS10_REGENERATE_TABLE=ON` 时构建期重新生成并逐字节比对，差异即构建失败。

生成头中的数组符号由模块名派生，在 C++ 中为内部链接；模块只有 1 个表格编译单元。

## 对账

类型级对账见 [reconciliation.md](reconciliation.md)。修改展平模块或重新生成表时，必须同时更新对账表并保持两者一致。
