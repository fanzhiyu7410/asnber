# asnber-pkcs12

PKCS#12（RFC 7292）结构模块，以 `.asn1` 描述表驱动，做**只读结构访问**与
`PFX` / `AuthenticatedSafe` 的**结构构造**。

## 模块范围

| 结构 | 说明 |
| --- | --- |
| `PFX` | 个人交换格式：版本、`authSafe`（`ContentInfo`）、可选 `MacData`；支持 builder 构造 |
| `AuthenticatedSafe` | `SEQUENCE OF ContentInfo`；支持 builder 构造 `data` / `encryptedData` 两种条目 |
| `SafeContents` | `SEQUENCE OF SafeBag`，含属性 |
| `CertBag` | 证书 bag（X.509 / SDSI） |

**不包含**：解密、口令处理/密钥派生、MAC 计算与校验。`EncryptedData` 与 `pkcs8ShroudedKeyBag` 只返回密文；builder 的 `MacData` 只写调用方给值。

## 公共头与链接

- 公共头：`asnber/pkcs12/pkcs12.h`（含 `pkcs12_builder.h`）
- 链接目标：`asnber::pkcs12::shared` 或 `asnber::pkcs12::static`（`find_package(asnber-pkcs12 CONFIG REQUIRED)`）
- 构建开关：`-DASNBER_BUILD_MODULE_PKCS12=ON`
- 导出宏：`ASNBER_PKCS12_API`；静态消费定义 `ASNBER_PKCS12_STATIC`
- 符号：37 个，前缀 `asnber_pkcs12_*`（自 0.1.0 冻结的例外，不重命名）

## 结构语义

- `PFX.authSafe` 是 `ContentInfo`；`content` 的完整原始 TLV 由 `asnber_pkcs12_pfx_auth_safe_content_tlv` 返回。`contentType` 为 `data` 时内层是 `OCTET STRING`，其内容才是 `AuthenticatedSafe` 的 DER；模块不替调用方拆 OCTET STRING，也不解密 `encryptedData`。
- `asnber_pkcs12_authenticated_safe_content_at` 返回每个 `ContentInfo` 的 `contentType` OID 与内容内层完整 TLV；`encryptedData` 分支原样返回。
- `asnber_pkcs12_safe_contents_bag_at` 返回 `bagId` OID、`bagValue` 内层完整 TLV 与属性数量；`bag_attribute_at` 返回属性 OID 与 `attrValues` 节点。调用方按 `bagId` 自行解码内层（例如交给 `asnber-pkcs8`）。
- `asnber_pkcs12_cert_bag_certificate` 只在 `certId` 为 `x509Certificate`（`1.2.840.113549.1.9.22.1`）时返回证书 DER；`sdsiCertificate` 等分支返回 `ASNBER_E_UNSUPPORTED`。`cert_value_tlv` 始终返回原始内层 TLV。
- `MacData.iterations` 缺省时按 RFC 7292 的 `DEFAULT 1` 返回 `1`；`macData` 整段缺省时 MAC 访问器返回 `ASNBER_E_SCHEMA_FIELD`，`mac_present` 返回 `0`。模块不校验 MAC。
- `PFX.version` 原样返回，不做范围校验。

由于展平模块去掉了 `BAG-TYPE` / `CERT-TYPE` 等信息对象集约束，`SafeBag`、`CertBag` 与 `ContentInfo` 的形状在结构上相似：模块只校验 `bagId` / `certId` 是 `OBJECT IDENTIFIER`，不强制取值；`SafeContents` 也可能接受结构上匹配的 `AuthenticatedSafe` 输入，这是只读结构访问的已知边界。

## 构造接口

`create(ctx, &builder)` → 若干 `set_*` / `add_*` → `encode(builder, &out)` → `destroy(builder)`；输入在设置时复制，重复设置返回 `ASNBER_E_INVALID_STATE`，`encode` 失败时清零 `out_buf`，成功时由 ctx 分配、用 `asnber_buf_release` 释放。

| API | 语义 |
| --- | --- |
| `asnber_pkcs12_authenticated_safe_builder_add_data(builder, safe_contents, size)` | 添加 `ContentInfo`：`contentType = data`，builder 把传入的 SafeContents DER 套进 `OCTET STRING` |
| `asnber_pkcs12_authenticated_safe_builder_add_encrypted_data(builder, content_tlv, size)` | 添加 `ContentInfo`：`contentType = encryptedData`，content 原样放入 `[0]` |
| `asnber_pkcs12_authenticated_safe_builder_encode(builder, &out)` | 输出 `AuthenticatedSafe` DER，即 `authSafe` 的 `OCTET STRING` 内容，也是 `MacData` 摘要输入 |
| `asnber_pkcs12_pfx_builder_set_version(builder, version)` | 默认 3；负值 `ASNBER_E_INVALID_VALUE` |
| `asnber_pkcs12_pfx_builder_set_auth_safe(builder, content_type_oid, content_tlv, size)` | 按**方案 A**由调用方给出 `ContentInfo` 的 type 与 content TLV，本模块不拼 `ContentInfo` |
| `asnber_pkcs12_pfx_builder_auth_safe_content_octets(builder, &data, &size)` | 仅 `contentType = data` 且 content 为 `OCTET STRING` 时返回其内容（供计算 MAC） |
| `asnber_pkcs12_pfx_builder_set_mac_data(...)` | `digestAlgorithm` OID/参数、digest、salt、iterations；`iterations = 1` 按 DEFAULT 完全省略 |
| `asnber_pkcs12_pfx_builder_encode(builder, &out)` | 未设 `authSafe` 返回 `ASNBER_E_INVALID_STATE` |



## 描述表

一个 ASN.1 文件一张表，独占一个翻译单元：

| 表 | 源文件 | 字节 | 头部默认根 |
| --- | --- | --- | --- |
| `pkcs12_schema` | `src/pkcs12_schema_table.cpp` | 3,112 | `PFX`(1) |

`AuthenticatedSafe` / `SafeContents` / `CertBag` 由 `asnber_schema_load_with_root` 在加载期分别指定根编号 `7` / `8` / `11`（登记在 `src/pkcs12_tables.h`）。

展平源在 `asn1/PKCS12-Flattened-7292.asn1`，产物检入 `generated/`。重生成：

```powershell
cmake -G Ninja -B build-regen -DASNBER_BUILD_TOOLS=ON -DASNBER_PKCS12_REGENERATE_TABLE=ON
cmake --build build-regen --target asnber_pkcs12_table_verify
```

## 依赖约束

只依赖核心公共 C ABI 与标准 C 库。**不依赖 `asnber-cms`（已确认，禁止回退）**：`authSafe` / `bagValue` 一律按完整原始 TLV 暴露，需要组装 `ContentInfo` 的调用方同时链接 `asnber-cms`，使用 `asnber_cms_content_info_builder_*` 在应用层组合，无需也不得新增包间依赖（见 [ADR-0015](../../docs/adr/0015-PKCS按标准拆分模块.md)）。

## 状态

P6（未发版）：37 个符号、1 张表（默认根 PFX，加载期可指定 AuthenticatedSafe/SafeContents/CertBag 三个根）；`tests/pkcs12/test_pkcs12_builder.c` 用 `pfx_rsa_unencrypted.der` 与 `pfx_certs_only.der` 验证 `AuthenticatedSafe` / `PFX` builder 逐字节重建、`auth_safe_content_octets`、`MacData` DEFAULT 1 省略与负例。0.4.0 时 `tests/pkcs12` 覆盖明文/加密/仅证书样本遍历、`MacData` DEFAULT 与 SDSI/负例，`tests/embedded/test_pkcs12_pool.c` 覆盖静态池，`tests/consumer/consumer_pkcs12.c` 覆盖独立安装消费。
