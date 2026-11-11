# asnber-pkcs1 展平 ASN.1 模块

本目录存放 `asnber-pkcs1` 使用的**自包含展平模块**。`asnberc` 只接受这类输入，不使用 `IMPORTS`，也不做参数化实例化。

## 文件

| 文件 | 对应标准 | 内容 |
| --- | --- | --- |
| `PKCS1-Flattened-8017.asn1` | RFC 8017 Appendix A（PKCS#1） | `RSAPublicKey`、`RSAPrivateKey` |
| `reconciliation.md` | — | 与原版模块的逐类型对账表 |
| `reference/rfc8017/rfc8017.txt` | RFC 8017 原文 | 只作参考，不参与构建 |

原文下载自 `https://www.rfc-editor.org/rfc/rfc8017.txt`，获取日期 2026-11-06。

## 展平规则

1. 不改字段顺序、`OPTIONAL` 与标签模式；模块默认 `IMPLICIT TAGS`。
2. 不做密码学语义：不解密、不做 RSA 运算、不做填充/签名/加密。
3. PKCS#1 原文无 `IMPORTS`，本文件仅保留 `RSAPublicKey`、`RSAPrivateKey` 及 `Version`。

## 描述表生成

0.4.0 起一个 ASN.1 文件只生成 1 张表，头部写默认根 `RSAPublicKey`；`RSAPrivateKey` 由模块在 `asnber_schema_load_with_root` 加载时指定根编号 `2`：

| 表 | 输入 | `--root` |
| --- | --- | --- |
| `pkcs1_schema.bin/.h` | `PKCS1-Flattened-8017.asn1` | `RSAPublicKey` |

命令示例：

```powershell
asnberc -o modules/pkcs1/generated/pkcs1_schema.bin `
      -c modules/pkcs1/generated/pkcs1_schema.h `
      --root RSAPublicKey modules/pkcs1/asn1/PKCS1-Flattened-8017.asn1
```

产物检入 `modules/pkcs1/generated/`，默认构建不需要 `asnberc`。`-DASNBER_PKCS1_REGENERATE_TABLE=ON` 时构建期重新生成并逐字节比对，差异即构建失败。

生成头中的数组符号由模块名派生，在 C++ 中为内部链接；模块只有 1 个表格编译单元，不再存在同符号冲突。

## 对账

类型级对账见 [reconciliation.md](reconciliation.md)。修改展平模块或重新生成表时，必须同时更新对账表并保持两者一致。
