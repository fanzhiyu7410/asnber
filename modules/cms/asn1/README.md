# CMS 展平 ASN.1 模块输入目录

本目录是 `asnberc` 的输入目录，不是 `asnber-cms` 的公共头文件目录，也不参与 C++ 编译或安装。

## 1. 状态

**已完成（只读切片）。** 产出 [CMS-Flattened-5652.asn1](CMS-Flattened-5652.asn1)，可直接交给 `asnberc`：

```powershell
asnberc -o cms_schema.bin -c cms_schema.h --root ContentInfo CMS-Flattened-5652.asn1
```

产出共 72 个具名类型声明，覆盖 RFC 5652 第 12.1 节 `CryptographicMessageSyntax2004` 的 `ContentInfo` / `SignedData` / `EnvelopedData` / `EncryptedData` 可达范围，并自包含复制所需的 PKIX 类型。产出不含 `IMPORTS`，不含参数化类型、信息对象与信息对象集。

## 2. 输入来源

| 项 | 内容 |
| --- | --- |
| 规范 | RFC 5652, *Cryptographic Message Syntax (CMS)*, September 2009 |
| 原文文件 | [reference/rfc5652/rfc5652.txt](reference/rfc5652/rfc5652.txt)（取自 `https://www.rfc-editor.org/rfc/rfc5652.txt`） |
| 勘误页 | [reference/rfc5652/errata.html](reference/rfc5652/errata.html)（取自 `https://www.rfc-editor.org/errata/rfc5652`） |
| PKIX 类型来源 | [../pkix/asn1/PKIX-Flattened-2009.asn1](../../pkix/asn1/PKIX-Flattened-2009.asn1)（由 RFC 5912 第 2、3、14 节展平） |
| 核验日期 | 2026-11-06 |

模块内容逐段比对原文转录，没有凭记忆手写。逐类型来源、处理与代价见 [reconciliation.md](reconciliation.md)。

## 3. 依赖策略

`asnber-cms` 按 ADR-0012 保持自包含，**不新增 `asnber-cms → asnber-pkix` 依赖**：

1. RFC 5652 第 12.1 节的 `IMPORTS`（`AlgorithmIdentifier`、`Certificate`、`CertificateList`、`CertificateSerialNumber`、`Name`、`AttributeCertificate`）全部删除。
2. 上述类型及其从 `SignedData` / `EnvelopedData` / `EncryptedData` 可达的依赖复制进本模块（`AlgorithmIdentifier`、`Name`/`RDNSequence`、`Certificate`/`TBSCertificate`、`Validity`/`Time`、`Extensions`、`CertificateList` 等，共 18 个 PKIX 类型，另有 54 个 RFC 5652 原类型，其中 24 个是 0.2.0 第一块追加的 `EnvelopedData` 类型、1 个是 `EncryptedData`；`EnvelopedData` 复用既有 `CertificateChoices`，`EncryptedData` 复用 `EncryptedContentInfo` 与 `UnprotectedAttributes`，均未新增 PKIX 依赖）。
3. 复制范围严格以“从 `SignedData` / `EnvelopedData` / `EncryptedData` 可达”为判据，不整表搬运；未复制清单见 `reconciliation.md` 第 2.1 节。

代价：同一批类型在 `asnber-pkix` 与 `asnber-cms` 中各有一份，两模块需同步维护；描述表包含整模块类型池（0.4.0 起每个 ASN.1 文件只保留一张表，当前 19,024 字节）。

## 4. 模块映射与标签

| 原构造 | 输出 | 说明 |
| --- | --- | --- |
| `CryptographicMessageSyntax2004` | `CMS-Flattened-5652`（单文件） | 单文件避免 `IMPORTS` 与类型重名 |
| 模块级 `DEFINITIONS IMPLICIT TAGS` | 保留 | 原模块即隐式；`ContentInfo.content`、`EncapsulatedContentInfo.eContent`、`TBSCertificate.version`/`extensions`、`TBSCertList.crlExtensions` 显式标注 `EXPLICIT` |
| `certificates [0] IMPLICIT CertificateSet` | 原样 | 节点是 0xA0 SET，枚举子项得到 `CertificateChoices` 分支 |
| `crls [1] IMPLICIT RevocationInfoChoices` | 原样 | 节点是 0xA1 SET |
| `signedAttrs [0] IMPLICIT` / `unsignedAttrs [1] IMPLICIT` | 原样 | 节点分别为 0xA0 / 0xA1 SET |
| `CMSVersion` | 无约束 `INTEGER` | 原版值名 `v0..v5`；去值名避免解码期约束，非定义值原样返回 |
| `AttributeCertificateV1/V2` | `SEQUENCE { ... }` 占位 | 结构属 RFC 3281，不在本切片范围；外层仍是正常 `[n] IMPLICIT` 构造标签，原始 TLV 可取 |
| `AttributeCertificateV1/V2` 的 `[1] IMPLICIT ANY` | 未使用 | `asnberc` 不支持 `[n] IMPLICIT ANY`；改用上述可扩展 `SEQUENCE` 占位，未新增标签特例 |

所有标签均由模块级默认值与源码显式标注表达，没有为绕过 seal/标签校验新增临时特例。

## 5. 开放类型（ANY）

`content`、`parameters`、`otherCert`、`otherRevInfo`、`attrValues`、`AttributeValue` 使用裸 `ANY`：

- 解码时保留完整原始 TLV，编码原样写回，不结构化展开，子节点数为 0；
- 不能按算法 OID / 属性 OID 自动分派到具体结构；
- `asnber-cms` API 只返回原始 TLV，调用方按 OID 二次解析。

## 6. 勘误核对

对勘误页 6 条记录逐条核对（6250、6546 Verified；7863、2026、3867 Held for Document Update；5331 Rejected），均无结构级影响：6250 只涉及 MAC 输入文字，6546 只涉及 `AttributeCertificateV1` 的导入来源，其余为版本语义文字或已拒绝。详见 `reconciliation.md` 第 4 节。

## 7. 描述表重生成与校验

检入产物在 `modules/cms/generated/`（`cms_schema.{bin,h}`）。默认构建不依赖 `asnberc`。同一文件的 `SignedData` / `EnvelopedData` / `EncryptedData` / `CompressedData` / `AuthenticatedData` 不再单独出表，由模块加载期指定根类型编号（见 `src/cms_tables.h`）。

```powershell
cmake -G Ninja -B build-cms-regen -DASNBER_BUILD_TOOLS=ON -DASNBER_CMS_REGENERATE_TABLE=ON
cmake --build build-cms-regen --target asnber_cms_table_verify
```

`ASNBER_CMS_REGENERATE_TABLE=ON` 时用 `asnberc` 重新生成；`asnber_cms_table_verify` 与检入产物逐字节比对，任一差异或缺失即构建失败。生成头只用于编译表格 TU（`src/cms_schema_table.cpp`），不安装、不进入公共头。
