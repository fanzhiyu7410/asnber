# asnber-pkcs12 展平 ASN.1 模块

本目录存放 `asnber-pkcs12` 使用的**自包含展平模块**。`asnberc` 只接受这类输入，不使用 `IMPORTS`，也不做参数化实例化。

## 文件

| 文件 | 对应标准 | 内容 |
| --- | --- | --- |
| `PKCS12-Flattened-7292.asn1` | RFC 7292 附录 D（PKCS#12） | `PFX`、`MacData`、`AuthenticatedSafe`、`SafeContents`、`SafeBag`、`CertBag` 及各 `*Bag` |
| `reconciliation.md` | — | 与原版模块的逐类型对账表 |
| `reference/rfc7292/rfc7292.txt` | RFC 7292 原文 | 只作参考，不参与构建 |

原文下载自 `https://www.rfc-editor.org/rfc/rfc7292.txt`，获取日期 2026-11-06。

## 展平规则

1. 不改字段顺序、`OPTIONAL`、`DEFAULT` 与标签模式；模块默认 `IMPLICIT TAGS`。
2. 去掉 `IMPORTS` 与信息对象类（`BAG-TYPE`、`ATTRIBUTE`），`ContentInfo`、`DigestInfo`、`AlgorithmIdentifier` 按 RFC 5652 定义就地展开；`PrivateKeyInfo` / `EncryptedPrivateKeyInfo` 见 `modules/pkcs8/asn1/`，本模块只以 `ANY` 承接。
3. 参数化类型全部展开；开放类型字段（`bagValue`、`certValue`、`crltValue`、`secretValue`、`content`）改为 `ANY`，保留完整原始 TLV。
4. `bagId` 只校验为 `OBJECT IDENTIFIER`，不按 bag 类型约束内层值——未知 `bagId` 与未来扩展 bag 仍可原样访问。
5. 不做密码学语义：不解密、不验 MAC、不做口令密钥派生，也不校验任何签名。

## 描述表生成

0.4.0 起一个 ASN.1 文件只生成 1 张表，头部写默认根 `PFX`；`AuthenticatedSafe`、`SafeContents`、`CertBag` 由模块在 `asnber_schema_load_with_root` 加载时分别指定根编号 `7`、`8`、`11`：

| 表 | 输入 | `--root` |
| --- | --- | --- |
| `pkcs12_schema.bin/.h` | `PKCS12-Flattened-7292.asn1` | `PFX` |

根编号取自原多表产物 `.bin` 头部偏移 96（小端 `uint32`），与模块内 `kPkcs12Root*` 常量一一对应；复核命令：

```powershell
python -c "print(int.from_bytes(open('pkcs12_schema.bin','rb').read()[96:100],'little'))"
```

命令示例：

```powershell
asnberc -o modules/pkcs12/generated/pkcs12_schema.bin `
      -c modules/pkcs12/generated/pkcs12_schema.h `
      --root PFX modules/pkcs12/asn1/PKCS12-Flattened-7292.asn1
```

产物检入 `modules/pkcs12/generated/`，默认构建不需要 `asnberc`。`-DASNBER_PKCS12_REGENERATE_TABLE=ON` 时构建期重新生成并逐字节比对，差异即构建失败。

生成头中的数组符号由模块名派生，在 C++ 中为内部链接；模块只有 1 个表格编译单元，不再存在同符号冲突。

## 对账

类型级对账见 [reconciliation.md](reconciliation.md)。修改展平模块或重新生成表时，必须同时更新对账表并保持两者一致。
