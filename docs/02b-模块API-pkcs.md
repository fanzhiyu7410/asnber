# PKCS 模块 API（asnber-pkcs1 / pkcs8 / pkcs10 / pkcs12 与聚合包 asnber-pkcs）

本节原为 [C API 设计规范](02-C-API规范.md) 6.9；模块 API 单独成页，核心规范只保留索引。

0.4.0 起 PKCS 按标准拆为四个独立包，`asnber-pkcs` 退化为不产库的 INTERFACE 聚合包（[ADR-0015](adr/0015-PKCS按标准拆分模块.md)）：

| 包 | 公共头 | 导出宏 | 符号前缀 | 符号数 |
| --- | --- | --- | --- | --- |
| `asnber-pkcs1` | `<asnber/pkcs1/pkcs1.h>`（含 `pkcs1_builder.h`） | `ASNBER_PKCS1_API` / `ASNBER_PKCS1_STATIC` | `asnber_pkcs_` | 31 |
| `asnber-pkcs8` | `<asnber/pkcs8/pkcs8.h>`（含 `pkcs8_builder.h`） | `ASNBER_PKCS8_API` / `ASNBER_PKCS8_STATIC` | `asnber_pkcs_` | 22 |
| `asnber-pkcs10` | `<asnber/pkcs10/pkcs10.h>`（含 `pkcs10_builder.h`） | `ASNBER_PKCS10_API` / `ASNBER_PKCS10_STATIC` | `asnber_pkcs_` | 25 |
| `asnber-pkcs12` | `<asnber/pkcs12/pkcs12.h>`（含 `pkcs12_builder.h`） | `ASNBER_PKCS12_API` / `ASNBER_PKCS12_STATIC` | `asnber_pkcs12_` | 37 |
| `asnber-pkcs`（聚合包） | `<asnber/pkcs/pkcs.h>` | — | — | 0（不产库、不导符号） |

- 四个实现包各自 `find_package(asnber-pkcs1 CONFIG)` 等，只依赖核心公共 C ABI，互不依赖。
- `find_package(asnber-pkcs CONFIG)` 仍可用：`pkcs.h` 聚合四个实现包的公共头，`asnber::pkcs`（INTERFACE）以依赖方式转发四个包，既有调用代码不需要改 include；链接目标由 `asnber::pkcs::shared/static` 改为单一的 `asnber::pkcs`。
- 函数名不随拆包变化：PKCS#1/#8/#10 仍用 `asnber_pkcs_*`，PKCS#12 仍用 `asnber_pkcs12_*`。

9 个不透明句柄各由 `open` 创建、`close` 销毁（`close(NULL)` 为空操作）：`PrivateKeyInfo`、`EncryptedPrivateKeyInfo`、`RSAPublicKey`、`RSAPrivateKey`、`CertificationRequest`（分别属 `asnber-pkcs8`、`asnber-pkcs8`、`asnber-pkcs1`、`asnber-pkcs1`、`asnber-pkcs10`），以及 PKCS#12 的 `PFX`、`AuthenticatedSafe`、`SafeContents`、`CertBag`（`asnber-pkcs12`）。

语义：

- `open` 用本包随包发布的描述表加载 schema，再以 `ASNBER_ENCODING_DER` + `ASNBER_DECODE_COPY_INPUT` 解码；输入被复制进文档，调用方可在返回后释放。空参 `ASNBER_E_INVALID_ARG`，分配失败 `ASNBER_E_NOMEM`，截断/尾随/语法错误/结构不符由核心错误码直接返回。
- 句柄借用调用方的 `asnber_ctx_t`，ctx 必须比句柄存活更久；访问器返回的指针（OID 文本、大整数十进制文本、字节/TLV、节点）借用句柄，`close` 后失效。
- 只读边界：PKCS#8 不解密，PKCS#1 不做 RSA 运算/填充/签名/加密，PKCS#10 不验证签名，PKCS#12 不解密 `EncryptedData`/`pkcs8ShroudedKeyBag`、不做口令派生、不计算也不校验 MAC；`AlgorithmIdentifier.parameters`、`Attribute.values`、`ContentInfo.content`、`SafeBag.bagValue`、`CertBag.certValue` 只返回完整原始 TLV（或 `SET OF ANY` 节点），可选字段缺省时返回 `ASNBER_OK` 且 `NULL/0`。
- PKCS#8 的 `privateKey` 内容是 PKCS#1 `RSAPrivateKey` 的完整 DER；需要字段级访问时，调用方把该 TLV 交给 `asnber-pkcs1`，两个包之间不建立链接依赖。
- PKCS#12 的 `bagValue` 同理只返回原始 TLV：`pkcs8ShroudedKeyBag` 需先由应用解密，再交给 `asnber-pkcs8`；模块不做自动衔接，也不建立跨包链接依赖。
- **`asnber-pkcs12` 不依赖 `asnber-cms`（已确认，禁止回退）**：`PFX.authSafe` 与 `SafeBag.bagValue` 以完整原始 TLV 暴露；需要组装或改写 `ContentInfo` 的调用方同时链接 `asnber-cms`，使用 `asnber_cms_content_info_builder_*` 在应用层组合。PKCS#12 的 CMake 只链接核心，安装配置只 `find_dependency(asnber)`；不得加回 `asnber-cms` 依赖（见 [ADR-0015](adr/0015-PKCS按标准拆分模块.md)）。
- PKCS#12 的 `MacData.iterations` 省略时按 `DEFAULT 1` 返回 `1`；`macData` 整体缺省时 MAC 访问器返回 `ASNBER_E_SCHEMA_FIELD`。`CertBag.certificate` 仅在 `certId` 为 `x509Certificate` 时返回证书 DER，SDSI 等分支返回 `ASNBER_E_UNSUPPORTED`。展平表不强制 `bagId`/`certId` 的取值，只校验其为 `OBJECT IDENTIFIER`。
- `asnber_pkcs_certification_request_version` 对 RFC 2986 的 `version` 采取**返回成功、原样给值**：非 0 是合法 DER 输入，不做范围校验，不静默改写为 0，不发告警、不新增错误码；需要断言 v1 的调用方自行比较 `*out_version == 0`。
- 模块不新增错误码，全部复用核心 1000–8999 错误空间；模块无全局可变状态，同一 ctx 的并发使用需调用方加锁。
- 描述表发布机制：各包把 `.bin` + 描述头检入 `modules/pkcs1|pkcs8|pkcs10|pkcs12/generated/`，默认构建不依赖 `asnberc`；对应 `-DASNBER_PKCS1_REGENERATE_TABLE=ON` 等选项在构建期重新生成并与检入产物逐字节比对，差异即失败。每张表一个编译单元，静态链接可按 `.o` 裁表。

### 构造接口（builder）

`asnber-pkcs1`、`asnber-pkcs8`、`asnber-pkcs10` 与 `asnber-pkcs12` 在只读接口之外提供结构构造：

| 包 | builder | 数量 |
| --- | --- | --- |
| `asnber-pkcs1` | `asnber_pkcs_rsa_public_key_builder_*` | 5 |
| `asnber-pkcs1` | `asnber_pkcs_rsa_private_key_builder_*` | 11 |
| `asnber-pkcs8` | `asnber_pkcs_private_key_info_builder_*` | 7 |
| `asnber-pkcs10` | `asnber_pkcs_certification_request_builder_*` | 11 |
| `asnber-pkcs12` | `asnber_pkcs12_pfx_builder_*` | 7 |
| `asnber-pkcs12` | `asnber_pkcs12_authenticated_safe_builder_*` | 5 |

统一形态为 `create(ctx, &builder)` → 若干 `set_*` → `encode(builder, &out)` → `destroy(builder)`：

- builder 借用调用方的 `ctx`，`ctx` 必须比 builder 存活更久；所有输入在 set 时复制。
- 每个字段只允许成功设置一次，重复设置返回 `ASNBER_E_INVALID_STATE`。
- `encode` 前校验必填字段，缺失返回 `ASNBER_E_INVALID_STATE`；失败时清零 `out_buf`，成功时由 ctx 分配，调用方用 `asnber_buf_release` 释放。
- PKCS#1 的大整数字段以**大端无符号幅值**传入，模块统一规整为规范 DER（去冗余前导零、最高位为 1 时补 `00`、零值编码为 `00`；空输入 `ASNBER_E_INVALID_ARG`，超过 8192 字节 `ASNBER_E_INPUT_LIMIT`）。`RSAPrivateKey.version` 固定写 0。
- 构造侧不做密码学语义：不校验 `n = p·q`，不验证签名，不解密。字段与错误码细节见各模块 README。
- `asnber-pkcs12` 的 `AuthenticatedSafe` builder 用 `add_data`（builder 把 SafeContents DER 套进 OCTET STRING）与 `add_encrypted_data`（content 原样 TLV）添加条目，`encode` 输出 AuthenticatedSafe DER，即 `authSafe` 的 OCTET STRING 内容，也是 `MacData` 摘要的输入。
- `PFX` builder 不拼 `ContentInfo`：调用方用 `set_auth_safe(content_type_oid, content_tlv, size)` 给出完整 ContentInfo 的 type 与 content TLV（content 原样放入 `[0]`）；`auth_safe_content_octets` 仅在 type 为 `data` 且 content 为 OCTET STRING 时返回其内容，专供调用方计算 `MacData`。`version` 默认 3，`MacData.iterations` 为 1 时按 DEFAULT 完全省略。

### 裁剪场景的头文件与链接约定

- **禁用伞头**：需要最小体积的固件只包含解码子头（`asnber/asnber_allocator.h`、`asnber/asnber_error.h`、`asnber/asnber_export.h`、`asnber/asnber_tag.h`、`asnber/asnber_warning.h`、`asnber/asnber_node.h`、`asnber/asnber_schema.h`、`asnber/asnber_decode.h`）与目标模块头（如 `<asnber/pkcs1/pkcs1.h>`），不包含 `<asnber/asnber.h>`。包含伞头本身不会把编码器链进静态产物（静态链接按 `.o` 裁剪），但会让“只读”在源码层不明确；该约定由 `tests/headers/decode_only.c` 编译用例守护。
- **只链接需要的实现包**：只读取 PKCS#8 时链接 `asnber::pkcs8::static`，不要链接聚合包 `asnber::pkcs`——后者会把四个实现包一并带入。需要“一行 include 全部 PKCS 结构”时才用聚合包。
- **编码符号闭包**：`asnber-pkcs1/8/10/12` 均自各期 builder 落地起提供构造能力（#1 为 P2、#8 为 P1、#10 为 P4、#12 为 P6），静态库会合法引用 `asnber_encode_*`/`asnber_node_create*` 等写侧符号，因此 `scripts/refactor_baseline.py` 的 `PKCS_STATIC_MODULES` 现为空元组，不再对任何 PKCS 包做“只解码”未定义符号断言。
