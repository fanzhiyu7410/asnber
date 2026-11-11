# asnber-pkcs10

PKCS#10（RFC 2986）结构模块，以 `.asn1` 描述表驱动，提供**只读结构访问**与
`CertificationRequest` **结构构造**。

## 模块范围

| 结构 | 说明 |
| --- | --- |
| `CertificationRequest` | 证书请求（CSR）：`CertificationRequestInfo`、签名算法、`signatureValue` |
| `CertificationRequestInfo` | 请求信息：版本、subject、`SubjectPublicKeyInfo`、属性 |

**不包含**：签名与验签。只读侧把 `signatureValue` 作为 BIT STRING 返回，
builder 只接受调用方给出的签名值，模块不计算也不验证请求签名。

## 公共头与链接

- 公共头：`asnber/pkcs10/pkcs10.h`（末尾包含 `pkcs10_builder.h`）
- 链接目标：`asnber::pkcs10::shared` 或 `asnber::pkcs10::static`（`find_package(asnber-pkcs10 CONFIG REQUIRED)`）
- 构建开关：`-DASNBER_BUILD_MODULE_PKCS10=ON`
- 导出宏：`ASNBER_PKCS10_API`；静态消费定义 `ASNBER_PKCS10_STATIC`
- 符号：25 个（只读 14 + builder 11），前缀 `asnber_pkcs_*`

## builder 语义

`asnber_pkcs_certification_request_builder_*` 共 11 个函数：
create/destroy、`set_version`、`set_subject`、`set_subject_public_key_algorithm`、
`set_subject_public_key`、`set_signature_algorithm`、`set_signature`、
`add_attribute`、`add_extension`、`encode`。

- subject 以结构化 RDN 数组传入，模块深拷贝；字符串类型按 OID 选择（C/
  serialNumber/dnQualifier → PrintableString，DC/emailAddress → IA5String，
  其余 UTF8String），也可显式指定 12/19/22。
- `attributes` 恒写 `[0] IMPLICIT`，无属性时编码为 `A0 00`；通用 Attribute
  按调用顺序累积，`SET OF` 排序交给核心 DER 编码。
- `add_extension` 累积为单个 `extensionRequest`（1.2.840.113549.1.9.14）；
  `critical == 0` 时完全省略 BOOLEAN（DEFAULT FALSE），同一 builder 内扩展
  OID 不得重复。
- 模块不推导 version、不解析 SPKI 内部密钥、不解释 Attribute/Extension 语义。

## 版本语义

`asnber_pkcs_certification_request_version` 采取“返回成功、原样给值”：

- RFC 2986 只定义 `v1 = 0`，但非 0 是合法 DER 输入，不视为解析错误；
- 模块不做范围校验，也不静默改写；
- 需要断言 v1 的调用方自行比较 `*out_version == 0`。

## 描述表

一个 ASN.1 文件一张表，独占一个翻译单元：

| 表 | 源文件 | 字节 | 头部默认根 |
| --- | --- | --- | --- |
| `pkcs10_schema` | `src/pkcs10_schema_table.cpp` | 2,160 | `CertificationRequest`(1) |

`CertificationRequestInfo` 由 `asnber_schema_load_with_root` 在加载期指定根编号 `2`（登记在 `src/pkcs10_tables.h`）。

展平源在 `asn1/PKCS10-Flattened-2986.asn1`，产物检入 `generated/`。重生成：

```powershell
cmake -G Ninja -B build-regen -DASNBER_BUILD_TOOLS=ON -DASNBER_PKCS10_REGENERATE_TABLE=ON
cmake --build build-regen --target asnber_pkcs10_table_verify
```

## 依赖约束

只依赖核心公共 C ABI 与标准 C 库；不依赖其他 PKCS 包、`asnber-pkix` 或 `asnber-cms`。源码不使用 `<asnber/asnber.h>` 伞头，便于静态链接裁表。

## 状态

0.4.0：从 `asnber-pkcs` 拆出，2 张表；P4 起新增 `CertificationRequest` builder，
符号 14 → 25；`tests/pkcs10` 覆盖 RSA/EC CSR、非 0 版本与负例，以及三份
OpenSSL CSR 夹具的 builder 逐字节对拍。
