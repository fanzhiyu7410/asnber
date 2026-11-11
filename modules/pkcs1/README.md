# asnber-pkcs1

PKCS#1（RFC 8017 附录 A）结构模块，以 `.asn1` 描述表驱动，提供**只读结构访问**与
`RSAPublicKey` / `RSAPrivateKey` 的**结构构造（DER 编码）**。

## 模块范围

| 结构 | 读 | 写 |
| --- | --- | --- |
| `RSAPublicKey` | `modulus`、`publicExponent`（十进制文本） | builder 组装后输出 DER |
| `RSAPrivateKey` | 版本、模数、公私指数、两个素数、两个指数与系数 | builder 组装后输出 DER；`version` 固定为 0 |

**不包含**：RSA 运算、填充、签名/验签、加解密。所有整数以只读大整数视图或十进制文本返回。
构造侧只负责把调用方给出的无符号幅值组装成规范 DER，不校验 `n = p·q` 等数学关系，
也不推导 `version`（`RSAPrivateKey` 恒写 two-prime 的 0）。

## 公共头与链接

- 公共头：`asnber/pkcs1/pkcs1.h`（只读）与 `asnber/pkcs1/pkcs1_builder.h`（构造，已由 `pkcs1.h` 引入）
- 链接目标：`asnber::pkcs1::shared` 或 `asnber::pkcs1::static`（`find_package(asnber-pkcs1 CONFIG REQUIRED)`）
- 构建开关：`-DASNBER_BUILD_MODULE_PKCS1=ON`
- 导出宏：`ASNBER_PKCS1_API`；静态消费定义 `ASNBER_PKCS1_STATIC`
- 符号：31 个，前缀 `asnber_pkcs_*`（只读 15 + `RSAPublicKey` builder 5 + `RSAPrivateKey` builder 11）
- 能力位：`decode+encode`

## 大整数输入约定

builder 的所有 INTEGER 字段都以**大端无符号幅值字节**传入，模块统一规整为规范 DER：

- `NULL` 或 `size == 0` 返回 `ASNBER_E_INVALID_ARG`；超过 8192 字节返回 `ASNBER_E_INPUT_LIMIT`；
- 冗余前导 `0x00` 被去掉，取最小幅值；
- 幅值全为 0 时内容编码为单字节 `0x00`；
- 首个有效字节最高位为 1 时补一个前导 `0x00`，保证按正数解释。

因此定宽缓冲或带符号补零的字节串可以直接传入，无需调用方预先裁剪。

## `RSAPublicKey` builder

| 函数 | 说明 |
| --- | --- |
| `asnber_pkcs_rsa_public_key_builder_create(ctx, &builder)` | 创建 builder，借用 `ctx` |
| `asnber_pkcs_rsa_public_key_builder_destroy(builder)` | 销毁；可传 `NULL` |
| `_set_modulus(builder, magnitude, size)` | `modulus`，必填，只允许设置一次 |
| `_set_public_exponent(builder, magnitude, size)` | `publicExponent`，必填，只允许设置一次 |
| `_encode(builder, &out)` | 校验必填字段后输出 DER；失败时 `out` 清零 |

## `RSAPrivateKey` builder

| 函数 | 说明 |
| --- | --- |
| `asnber_pkcs_rsa_private_key_builder_create(ctx, &builder)` | 创建 builder，借用 `ctx` |
| `asnber_pkcs_rsa_private_key_builder_destroy(builder)` | 销毁；可传 `NULL` |
| `_set_modulus` / `_set_public_exponent` / `_set_private_exponent` | 模数、公指数、私指数，必填 |
| `_set_prime1` / `_set_prime2` | 两个素数，必填 |
| `_set_exponent1` / `_set_exponent2` / `_set_coefficient` | 两个 CRT 指数与系数，必填 |
| `_encode(builder, &out)` | 校验 8 个字段均设置后输出 DER；失败时 `out` 清零 |

约束：

- 8 个字段均必填，缺任一返回 `ASNBER_E_INVALID_STATE`；`version` 由模块写 0，不暴露 setter。
- 每个 setter 只允许成功设置一次，重复设置返回 `ASNBER_E_INVALID_STATE`；失败不会把字段置为已设置。
- `encode` 输出的字段顺序固定为 RFC 8017 的 `version`、`modulus`、`publicExponent`、
  `privateExponent`、`prime1`、`prime2`、`exponent1`、`exponent2`、`coefficient`。

## 描述表

一个 ASN.1 文件一张表，独占一个翻译单元（静态链接可按 `.o` 裁切）：

| 表 | 源文件 | 字节 | 头部默认根 |
| --- | --- | --- | --- |
| `pkcs1_schema` | `src/pkcs1_schema_table.cpp` | 1,624 | `RSAPublicKey`(1) |

`RSAPrivateKey` 不再单独出表，由 `asnber_schema_load_with_root` 在加载期指定根编号 `2`（登记在 `src/pkcs1_tables.h`）。
读写两侧共用同一张表。

展平 ASN.1 源在 `asn1/PKCS1-Flattened-8017.asn1`，生成产物检入 `generated/`。重新生成并逐字节校验：

```powershell
cmake -G Ninja -B build-regen -DASNBER_BUILD_TOOLS=ON -DASNBER_PKCS1_REGENERATE_TABLE=ON
cmake --build build-regen --target asnber_pkcs1_table_verify
```

## 句柄与生命周期

`open` 接收 DER 字节并复制进内部文档 arena；句柄借用调用方的 `asnber_ctx_t`，ctx 必须比句柄存活更久。访问器返回的指针借用句柄，`close` 后失效。`close(NULL)` 为空操作。builder 同样借用 `ctx`，所有输入在 set 时复制，`ctx` 必须比 builder 存活更久。

## 用于裁剪的编译约定

读侧源码不使用 `<asnber/asnber.h>` 伞头，只包含本包头与解码子头；构造侧集中在独立的
`src/pkcs1_builder.cpp`。需要按 `.o` 裁表的场景，调用方直接包含
`asnber/pkcs1/pkcs1.h` 即可，链接器只会拉入实际使用的读侧或写侧对象。

## 依赖约束

只依赖核心公共 C ABI 与标准 C 库；不依赖其他 PKCS 包、`asnber-pkix` 或 `asnber-cms`。
构造侧通过 `modules/common/src/detail/module_builder_support.h`（INTERFACE 目标
`asnber::module_support`）复用领域无关的编码原语（含任意长度 INTEGER 规整）；
该支撑层不安装、不导出，不构成包之间的链接依赖。

## 状态

0.4.0：从 `asnber-pkcs` 拆出，15 个符号、2 张表；`tests/pkcs1` 覆盖公私钥与负例，`tests/consumer` 有独立的 `asnber-pkcs1` 消费与安装重定位验证。

P2（2026-11-10，未发版）：能力位由 `decode-only` 改为 `decode+encode`，新增
`RSAPublicKey` builder 5 个 + `RSAPrivateKey` builder 11 个符号（共 31 个）；
`tests/pkcs1/test_pkcs1_builder.c` 覆盖公私钥 fixture 逐字节重建与十进制对拍、
零值/冗余前导零/最高位为 1/8192 字节边界，以及空输入、超限、重复设置和私钥
逐一缺字段负例。
