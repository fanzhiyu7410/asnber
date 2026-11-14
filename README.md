# asnber

通用 ASN.1 解析/编解码库，配以一组独立的标准化结构模块。

核心库 `asnber` 只处理标签、节点、文档、值、模板描述与编码规则，**不包含任何领域知识**，也不内置标准结构表。X.509/PKIX、CMS/PKCS#7、PKCS#10/#12/#1/#8、OCSP 等标准结构由独立模块包提供（`asnber-pkix`、`asnber-cms`、`asnber-pkcs1/8/10/12` 与 `asnber-ocsp`；`asnber-pkcs` 为聚合包），每个模块拥有自己的包名、版本、公共头文件与符号前缀。依赖方向严格单向：模块 → 核心，核心不反向引用任何模块。

对外只提供 C ABI，内部使用 C++ 实现；标准结构的 ASN.1 定义直接复用公开 RFC 模块，不自创描述格式。`asnberc` 与核心之间共享一份固定的描述表字节契约（`uint8_t[]`、显式小端读取），见[描述表格式](docs/11-描述表格式.md)。

核心能力：BER/DER 解码、DER 编码、DOM 值树、schema 模板（描述表加载与运行时注册）、schema 感知解码/编码、增量 feed 解码，以及 `asnberc` 描述表生成工具；X.509/PKIX、CMS、PKCS#1/#8/#10/#12 的结构访问与构造由独立模块提供。当前不含密码学语义（不验签、不摘要、不解密、不校验证书链），尚不构成生产级认证。实现状态与测试覆盖见[测试与验证](docs/07-测试与验证.md)，版本变更见 [CHANGELOG](CHANGELOG.md)。

## 分层

| 层 | 内容 | 说明 |
| --- | --- | --- |
| 核心 `asnber` | 通用 BER 解码、DER 解码/编码、DOM 值树、runtime 构树、内存与错误模型、模板机制 | 零领域知识；不解析 `.asn1` 文本 |
| 标准模块 | `asnber-pkix`（RFC 5912）、`asnber-cms`（RFC 6268）、`asnber-pkcs1/8/10/12`（RFC 8017/5208/2986/7292，`asnber-pkcs` 为门面）、`asnber-ocsp`（RFC 6960） | 各自独立 CMake 包与版本；依赖核心 |
| 工具 `asnberc` | 解析 `.asn1` 文本、语义校验、生成描述表（C 数组或二进制） | 独立可执行文件；支持单模块展平输入与多模块 `IMPORTS`（单表合并），单类型参数化展开 |

模板机制是核心一期能力：核心接受**已编译描述表**（C 源数组或二进制资源），也提供运行时注册 C API，两条入口构建同一棵类型树，用于字段命名、结构化约束校验与 `CHOICE` 分支、`SEQUENCE OF`/`SET OF`、`OPTIONAL`、`DEFAULT`、扩展标记判定。类型构造性由类型种类 `kind` 派生，标签行为由 `tag_mode` 与模块默认标注方式决定，`DEFAULT` 以规范 DER TLV 存放，`BIT STRING` 命名位与 `ENUMERATED`/`INTEGER` 数值名由名称表表达。把 `.asn1` 文本解析成描述表的工作只属于 `asnberc`；输入可以是自包含展平模块或多模块 `IMPORTS`（合并为一张表），单类型参数化展开已支持，值参数、多参数参数化与信息对象直接解析仍为后续任务。

## 目录结构

```text
.
├─ CMakeLists.txt          根，编排核心与模块、工具
├─ include/asnber/           核心公共 C ABI
├─ src/                    核心实现（core/ 上下文/错误/版本，types/ DOM 与值处理，
│                          ber/ BER 解码（含不定长），der/ DER 严格校验与编码，
│                          schema/ 模板注册/描述表，c_api/ C ABI）
├─ modules/
│  ├─ pkix/                asnber-pkix：include + src + 独立导出包
│  │  └─ asnber/             RFC 5912 展平模块（PKIX-Flattened-2009.asn1；对账见 reconciliation.md）
│  ├─ cms/                 asnber-cms
│  ├─ ocsp/                asnber-ocsp（OCSP 结构读写，不依赖 pkix）
│  ├─ pkcs1/               asnber-pkcs1（PKCS#1 读写，含公/私钥 builder）
│  ├─ pkcs8/               asnber-pkcs8（PKCS#8 读写，含 PrivateKeyInfo builder）
│  ├─ pkcs10/              asnber-pkcs10（PKCS#10 读写，含 CertificationRequest builder）
│  ├─ pkcs12/              asnber-pkcs12（PKCS#12 结构读写）
│  └─ pkcs/                asnber-pkcs 聚合包（不产库：聚合头 + INTERFACE 转发四包）
├─ tools/asnberc/            `.asn1` → 描述表 1.0 生成工具（C 数组/二进制）
├─ tests/                  unit / c_api / asnberc / conformance / support / fuzz / bench
├─ examples/c              C 消费示例（核心占位，以及证书 / CSR / CMS / PKCS 集成）
├─ examples/cpp            C++ 消费示例（占位）
├─ cmake/                  构建选项、编译检查、安装导出、包配置模板
├─ docs/                   设计文档体系（入口：docs/文档索引.md）
├─ scripts/                辅助脚本（第三方依赖检查等）
├─ .screenshots/           浏览器/工具临时截图目录（已 gitignore，不随仓库分发）
├─ THIRD_PARTY_NOTICES.md  第三方组件分发声明（当前空模板）
└─ LICENSE
```

## 构建

要求：CMake ≥ 3.20、C++17 编译器（GCC/Clang/MSVC/MinGW 均可）。库本身不依赖第三方运行时；测试与工具依赖限定宽松许可，登记与检查见[第三方依赖与许可证清单](docs/第三方依赖与许可证清单.md)。

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

启用示例、测试与严格告警：

```bash
cmake -S . -B build \
  -DASNBER_BUILD_EXAMPLES=ON \
  -DASNBER_BUILD_TESTS=ON \
  -DASNBER_WARNINGS_AS_ERRORS=ON \
  -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build --output-on-failure
```

安装与消费：

```bash
cmake --install build --prefix out/install
```

```cmake
find_package(asnber CONFIG REQUIRED)          # 核心
find_package(asnber-pkix CONFIG REQUIRED)     # 模块，自动依赖 asnber

target_link_libraries(app PRIVATE asnber::shared asnber::pkix::shared)
```

模块用法（打开一张 DER 证书并按路径访问字段）：

```c
#include <asnber/pkix/pkix.h>

asnber_ctx_config_t config;
asnber_ctx_t *ctx;
asnber_pkix_certificate_t *cert;
asnber_ctx_config_init(&config);
asnber_ctx_create(&config, &ctx);

if (asnber_pkix_certificate_open(ctx, der, der_size, &cert) == ASNBER_OK) {
    const asnber_node_t *subject;
    uint32_t version;
    asnber_pkix_certificate_version(cert, &version);          /* 2 = v3 */
    asnber_pkix_certificate_find(cert, "tbsCertificate.subject", &subject);
    /* 后续用核心 asnber_node_* 读取 subject 下的值 */
    asnber_pkix_certificate_close(cert);
}
asnber_ctx_destroy(ctx);
```

ANY 字段（如 `algorithmIdentifier.parameters`）只返回原始 TLV，模块不做算法参数展开。

静态池上的集成示例，每步用完即 `asnber_ctx_destroy`，用 `-DASNBER_BUILD_EXAMPLES=ON` 编译：

| 文件 | 内容 |
| --- | --- |
| `examples/c/example_cert_decode.c` | 打开证书 |
| `examples/c/example_cert_csr.c` | 打开证书、编证书、编 CSR、读回 CSR |
| `examples/c/example_pkcs1.c` | RSA 公钥与私钥 |
| `examples/c/example_pkcs8.c` | PrivateKeyInfo 与 EncryptedPrivateKeyInfo |
| `examples/c/example_pkcs12.c` | PFX 与 AuthenticatedSafe |
| `examples/c/example_cms.c` | SignedData、data ContentInfo、EnvelopedData |

`<asnber/pkcs/pkcs.h>` 只聚合上述 PKCS 头，不另产库。

主要选项：

| 选项 | 默认 | 说明 |
| --- | --- | --- |
| `ASNBER_BUILD_SHARED` | `ON` | 构建 `asnber::shared` |
| `ASNBER_BUILD_STATIC` | `ON` | 构建 `asnber::static` |
| `ASNBER_BUILD_MODULES` | `ON` | 构建 `modules/` 下的独立标准模块 |
| `ASNBER_BUILD_MODULE_PKIX` | `ON` | 构建 `asnber-pkix`；仅 `ASNBER_BUILD_MODULES=ON` 时生效 |
| `ASNBER_BUILD_MODULE_CMS` | `ON` | 构建 `asnber-cms`；仅 `ASNBER_BUILD_MODULES=ON` 时生效 |
| `ASNBER_BUILD_MODULE_PKCS1` / `PKCS8` / `PKCS10` / `PKCS12` | `ON` | 构建四个 PKCS 实现包；仅 `ASNBER_BUILD_MODULES=ON` 时生效 |
| `ASNBER_BUILD_MODULE_PKCS` | `ON` | 构建 `asnber-pkcs` 聚合包（INTERFACE，无库产物）；启用时四个实现包必须同时启用 |
| `ASNBER_BUILD_MODULE_OCSP` | `ON` | 构建 `asnber-ocsp`；仅 `ASNBER_BUILD_MODULES=ON` 时生效。裁剪配置必须关闭它 |
| `ASNBER_BUILD_TOOLS` | `ON` | 构建 `tools/asnberc` |
| `ASNBER_PKIX_REGENERATE_TABLE` / `ASNBER_PKCS*_REGENERATE_TABLE` / `ASNBER_CMS_*` / `ASNBER_OCSP_*` | `OFF` | 构建期用 `asnberc` 重新生成描述表，并与检入产物逐字节比对（差异即构建失败）；默认直接用检入产物 |
| `ASNBER_BUILD_EXAMPLES` | `OFF` | 构建 C/C++ 消费示例 |
| `ASNBER_BUILD_TESTS` | `OFF` | 构建测试并注册 CTest |
| `ASNBER_BUILD_EMBEDDED_TEST` | `OFF` | 构建嵌入式最小用例（可脱离 CTest，交叉编译时只构建不运行） |
| `ASNBER_BUILD_BENCHMARKS` | `OFF` | 构建批量基准（不进 CTest 主流程） |
| `ASNBER_FREESTANDING` | `OFF` | 裁剪为 freestanding 子集 |
| `ASNBER_WARNINGS_AS_ERRORS` | `OFF` | 告警视为错误 |
| `ASNBER_ENABLE_SANITIZERS` | `OFF` | ASan + UBSan（宿主调试）；开关同时注入编译与链接标志，库、`asnberc`、测试与独立消费工程一并覆盖，无需另传 `CMAKE_*_FLAGS`。MSVC 下未接入 |
| `ASNBER_TRIM_PROFILE` | `full` | `full`、`cert-decode` 或 `cert-and-csr`。后两者使用 certificate 描述表；`cert-and-csr` 同时打开证书编解码与 CSR 编解码，并只允许 PKIX 与 PKCS#10。 |
| `ASNBER_ENABLE_ENCODE` / `ASNBER_ENABLE_BUILD_API` / `ASNBER_ENABLE_SCHEMA_BUILD_API` | `ON` | 核心特性开关；任一关闭时禁止共享库 |
| `ASNBER_PKIX_ENABLE_BUILDER` | `ON` | asnber-pkix 证书构造实现；关闭后只保留只读访问器 |
| `ASNBER_PKIX_SCHEMA_VARIANT` | `full` | `full` 或 `certificate`；后者使用 `--trim-schema` 生成的证书表 |

异常与 RTTI 固定禁用（`-fno-exceptions -fno-rtti`；MSVC `/EHs-c- /GR-`），不提供开关。

## 文档入口

- [文档索引与阅读顺序](docs/文档索引.md)
- [总体架构](docs/01-架构设计.md)
- [C API 设计规范](docs/02-C-API规范.md)
- [描述表格式（asnberc 与核心共享契约）](docs/11-描述表格式.md)
- [ASN.1 能力范围](docs/03-ASN1能力范围.md)
- [数据表示与内存模型](docs/04-数据与内存模型.md)
- [错误模型](docs/05-错误模型.md)
- [构建与移植](docs/06-构建与移植.md)
- [测试与验证策略](docs/07-测试与验证.md)
- [编码规范与工程约定](docs/08-编码规范.md)
- [里程碑与分期](docs/09-里程碑与分期.md)
- [术语表](docs/10-术语表.md)
- [发版说明规范](docs/12-发版说明规范.md)
- [基线覆盖度清单](docs/基线覆盖度清单.md)
- [未决问题清单](docs/待确认问题.md)
- [第三方依赖与许可证清单](docs/第三方依赖与许可证清单.md)
- [ADR 目录](docs/adr/ADR索引.md)

## 依赖与许可证

- 运行库零第三方依赖：核心与模块的发版产物只链接 C 运行库与平台系统库。
- 测试与工具依赖限定宽松许可（MIT、BSD-2/3-Clause、Apache-2.0 含 LLVM 例外）；禁止 GPL/LGPL/AGPL 或许可不明代码。
- 仓库当前无第三方源码；doctest（测试框架）与 libFuzzer（fuzz 驱动）登记于[第三方依赖与许可证清单](docs/第三方依赖与许可证清单.md)，均不随产物分发。
- 发版随包提供 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)（当前为空模板）；`python scripts/check_third_party.py` 检查未登记依赖。
- 项目许可证：MIT，见 [LICENSE](LICENSE)。策略细节见 [ADR-0011](docs/adr/0011-第三方依赖与许可证策略.md)。

## 版本与 ABI

- 核心与各模块各自声明版本，安装到 `lib/cmake/<包名>`；模块配置通过 `find_dependency(asnber <最低版本> CONFIG)` 表达对核心的依赖。
- 版本宏由 CMake 从 `project(... VERSION ...)` 生成到构建目录（`include/asnber/asnber_version.h`、`include/asnber/<模块>/<模块>_version.h`），源码树中不手写；消费者只需包含公共头即可获得版本宏。
- 基线承诺核心 ABI 向后兼容：公共头文件只增不改，结构体带 `struct_size`，核心符号统一 `asnber_` 前缀。
- 共享库 SONAME 固定为主版本；破坏性变更只能升主版本。
- 核心 ABI 稳定期内，模块可独立升级版本，不要求与核心同版本。
- 运行时 `asnber_version_check` 只对**主版本不一致**报错，次版本差异视为兼容；可选能力通过 `asnber_version_info_t.capabilities` 与 `asnber_has_capability()` 查询，不按次版本号推断。
- 版本一致性机制见 [ADR-0010](docs/adr/0010-版本一致性机制.md)。

## 许可证

MIT，见 [LICENSE](LICENSE)。运行库不含第三方组件；随产物分发的第三方声明见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)（当前为空模板）。

Copyright (c) 2026 asnber project contributors
