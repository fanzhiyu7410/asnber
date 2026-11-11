# asnber-pkcs8 展平 ASN.1 模块

本目录存放 `asnber-pkcs8` 使用的**自包含展平模块**。`asnberc` 只接受这类输入，不使用 `IMPORTS`，也不做参数化实例化。

## 文件

| 文件 | 对应标准 | 内容 |
| --- | --- | --- |
| `PKCS8-Flattened-5208.asn1` | RFC 5208（PKCS#8） | `PrivateKeyInfo`、`EncryptedPrivateKeyInfo` 及其引用类型 |
| `reconciliation.md` | — | 与原版模块的逐类型对账表 |
| `reference/rfc5208/rfc5208.txt` | RFC 5208 原文 | 只作参考，不参与构建 |

原文下载自 `https://www.rfc-editor.org/rfc/rfc5208.txt`，获取日期 2026-11-06。

## 展平规则

1. 去掉 `IMPORTS`：`AlgorithmIdentifier`（RFC 5280）与 `Attribute`（RFC 2985/X.501）直接写入对应模块。
2. 开放类型字段改为 `ANY`，只保留完整原始 TLV：`AlgorithmIdentifier.parameters`、`Attribute.values`。
3. 不改字段顺序、`OPTIONAL` 与标签模式；模块默认 `IMPLICIT TAGS`，`attributes` 显式写为 `[0] IMPLICIT`。
4. 不做密码学语义：本模块不解密、不做口令密钥派生。

## 版本说明

- RFC 5208 已被 RFC 5958 更新；RFC 5958 把 `Version` 明确为 `v1(0)`/`v2(1)`，`PrivateKeyInfo`/`EncryptedPrivateKeyInfo` 的字段结构不变。本切片按 RFC 5208 原文结构生成，后续需要 v2 语义时单独评估。

## 描述表生成

0.4.0 起一个 ASN.1 文件只生成 1 张表，头部写默认根 `PrivateKeyInfo`；`EncryptedPrivateKeyInfo` 由模块在 `asnber_schema_load_with_root` 加载时指定根编号 `5`：

| 表 | 输入 | `--root` |
| --- | --- | --- |
| `pkcs8_schema.bin/.h` | `PKCS8-Flattened-5208.asn1` | `PrivateKeyInfo` |

命令示例：

```powershell
asnberc -o modules/pkcs8/generated/pkcs8_schema.bin `
      -c modules/pkcs8/generated/pkcs8_schema.h `
      --root PrivateKeyInfo modules/pkcs8/asn1/PKCS8-Flattened-5208.asn1
```

产物检入 `modules/pkcs8/generated/`，默认构建不需要 `asnberc`。`-DASNBER_PKCS8_REGENERATE_TABLE=ON` 时构建期重新生成并逐字节比对，差异即构建失败。

生成头中的数组符号由模块名派生，在 C++ 中为内部链接；模块只有 1 个表格编译单元。

## 对账

类型级对账见 [reconciliation.md](reconciliation.md)。修改展平模块或重新生成表时，必须同时更新对账表并保持两者一致。
