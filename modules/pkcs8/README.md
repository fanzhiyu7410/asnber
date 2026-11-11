# asnber-pkcs8

PKCS#8（RFC 5208）结构模块，以 `.asn1` 描述表驱动，提供**只读结构访问**与
`PrivateKeyInfo` 的**结构构造（DER 编码）**。

## 模块范围

| 结构 | 读 | 写 |
| --- | --- | --- |
| `PrivateKeyInfo` | 版本、`AlgorithmIdentifier`、`privateKey` OCTET STRING、属性 | builder 组装后输出 DER |
| `EncryptedPrivateKeyInfo` | 加密算法、密文字节 | 组装算法标识与密文字节，不加密 |

**不包含**：解密、口令处理、密钥派生。`EncryptedPrivateKeyInfo` 只暴露加密算法与密文，不尝试解密；`PrivateKeyInfo.privateKey` 的内容（通常是 PKCS#1 `RSAPrivateKey`）原样返回，由调用方交给 `asnber-pkcs1` 或自己的解析器。构造侧只负责把调用方给出的字段拼成规范 DER，不生成密钥、不做算法推断、不补默认版本。

## 公共头与链接

- 公共头：`asnber/pkcs8/pkcs8.h`（只读）与 `asnber/pkcs8/pkcs8_builder.h`（构造，已由 `pkcs8.h` 引入）
- 链接目标：`asnber::pkcs8::shared` 或 `asnber::pkcs8::static`（`find_package(asnber-pkcs8 CONFIG REQUIRED)`）
- 构建开关：`-DASNBER_BUILD_MODULE_PKCS8=ON`
- 导出宏：`ASNBER_PKCS8_API`；静态消费定义 `ASNBER_PKCS8_STATIC`
- 符号：22 个，前缀 `asnber_pkcs_*`（只读 15 个 + `PrivateKeyInfo` builder 7 个）
- 能力位：`decode+encode`

## `PrivateKeyInfo` builder

| 函数 | 说明 |
| --- | --- |
| `asnber_pkcs_private_key_info_builder_create(ctx, &builder)` | 创建 builder，借用 `ctx` |
| `asnber_pkcs_private_key_info_builder_destroy(builder)` | 销毁；可传 `NULL` |
| `_set_version(builder, version)` | 设置版本 `INTEGER` |
| `_set_algorithm(builder, oid, parameters_tlv, size)` | `AlgorithmIdentifier`；`parameters_tlv` 为完整原始 TLV（含 tag/len），缺省时传 `NULL`/`0` |
| `_set_private_key(builder, data, size)` | `privateKey` OCTET STRING 的内容字节 |
| `_set_attributes(builder, set_tlv, size)` | 传入 `SET OF Attribute` 的完整 TLV（`0x31`），编码时改写为 `[0] IMPLICIT` 的 `0xA0`，内容不变 |
| `_encode(builder, &out)` | 校验必填字段后输出 DER；失败时 `out` 清零 |

约束：

- `version`、`privateKey` 必填；`algorithm` 必填（OID 做点分文本校验，参数必须是**单个**完整 TLV）。
- 每个 setter 只允许成功设置一次，重复设置或参数非法返回 `ASNBER_E_INVALID_ARG` / `ASNBER_E_SCHEMA_FIELD`，且不会把字段置为已设置，可随后用合法值重试。
- `attributes` 的空集合与非 `SET` 根标签被拒绝；`SET OF Attribute` 的 DER 排序由核心 schema 感知编码完成，模块不自行排序。
- `encode` 输出的字段顺序固定为 `version`、`privateKeyAlgorithm`、`privateKey`、`attributes`（可选）。

## ANY 字段语义

`AlgorithmIdentifier.parameters` 是开放类型，模块只返回**完整原始 TLV（含 tag/len）**，不按 OID 解释：

- 缺省时返回 `ASNBER_OK` 且 `*out_data = NULL`、`*out_size = 0`，不是错误。
- `attribute_at` 返回属性 OID 与 `values` 节点（`SET OF ANY`），节点借用句柄。

## 描述表

一个 ASN.1 文件一张表，独占一个翻译单元：

| 表 | 源文件 | 字节 | 头部默认根 |
| --- | --- | --- | --- |
| `pkcs8_schema` | `src/pkcs8_schema_table.cpp` | 1,448 | `PrivateKeyInfo`(1) |

`EncryptedPrivateKeyInfo` 由 `asnber_schema_load_with_root` 在加载期指定根编号 `5`（登记在 `src/pkcs8_tables.h`）。

展平源在 `asn1/PKCS8-Flattened-5208.asn1`，产物检入 `generated/`。重生成：

```powershell
cmake -G Ninja -B build-regen -DASNBER_BUILD_TOOLS=ON -DASNBER_PKCS8_REGENERATE_TABLE=ON
cmake --build build-regen --target asnber_pkcs8_table_verify
```

## 依赖约束

只依赖核心公共 C ABI 与标准 C 库；不依赖其他 PKCS 包、`asnber-pkix` 或 `asnber-cms`。源码不使用 `<asnber/asnber.h>` 伞头，便于静态链接裁表。构造侧通过 `modules/common/src/detail/module_builder_support.h`（INTERFACE 目标 `asnber::module_support`）复用领域无关的编码原语；该支撑层不安装、不导出，不构成包之间的链接依赖。

## 状态

0.4.0：从 `asnber-pkcs` 拆出，15 个符号、2 张表；`tests/pkcs8` 覆盖明文、RSA-PSS 参数缺省、加密结构与负例。

P1（2026-11-10，未发版）：能力位由 `decode-only` 改为 `decode+encode`，新增 `PrivateKeyInfo` builder 7 个符号（共 22 个）；`tests/pkcs8/test_pkcs8_builder.c` 覆盖 RSA/PSS 逐字节往返、EC 命名曲线参数、attributes `0x31`→`0xA0` 改写与读回，以及参数/重复设置/必填缺失/非法 TLV 负例。
