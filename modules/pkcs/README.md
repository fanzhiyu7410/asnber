# asnber-pkcs（INTERFACE 聚合包）

`asnber-pkcs` 自 0.4.0 起是**不产库的聚合包**：本目录只保留伞头与版本头，PKCS#1/#8/#10/#12 的实现、描述表、符号与 ABI 已按标准拆到独立包：

| 包 | 标准 | 公共头 | 符号前缀 |
| --- | --- | --- | --- |
| [`asnber-pkcs1`](../pkcs1/README.md) | RFC 8017 附录 A | `asnber/pkcs1/pkcs1.h` | `asnber_pkcs_*`（31） |
| [`asnber-pkcs8`](../pkcs8/README.md) | RFC 5208 | `asnber/pkcs8/pkcs8.h` | `asnber_pkcs_*`（22） |
| [`asnber-pkcs10`](../pkcs10/README.md) | RFC 2986 | `asnber/pkcs10/pkcs10.h` | `asnber_pkcs_*`（25） |
| [`asnber-pkcs12`](../pkcs12/README.md) | RFC 7292 | `asnber/pkcs12/pkcs12.h` | `asnber_pkcs12_*`（37） |

拆分动机、备选方案与后果见 [ADR-0015](../../docs/adr/0015-PKCS按标准拆分模块.md)。

## 聚合包内容

- 公共头 `asnber/pkcs/pkcs.h`：包含 `pkcs_version.h` 与上述四个实现包头，函数声明全部来自实现包。
- **不产库、不导符号**：没有 `.dll`/`.so`/`.a` 产物，也没有 `abi/asnber-pkcs.symbols.txt` 基线；ABI 基线因此从 8 包降为 7 包。
- 链接目标：`asnber::pkcs`（INTERFACE），以依赖方式转发四个实现包，消费者无需逐个 `find_package`。两种形态同时构建时转发静态实现包（静态链接无需分发 DLL）；只构建共享时转发共享实现包。需要另一种形态时直接链接对应实现包的 `asnber::pkcsN::shared/static`。
- 构建开关：`-DASNBER_BUILD_MODULE_PKCS=ON`；启用时四个实现包必须同时启用（配置期校验）。

```cmake
find_package(asnber-pkcs CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE asnber::pkcs)
```

`asnber-pkcs` 的 Config 会 `find_dependency(asnber-pkcs1/8/10/12)`，安装时必须同时安装四个实现包。

## 与 0.3.0 的差异

- 源码、描述表与业务 API 已迁出，本目录不再保留 `pkcs_handle` / `pkcs_tables`、`.asn1` 文件或任何实现源文件。
- 函数名未变（`asnber_pkcs_*` / `asnber_pkcs12_*`），调用方代码无需修改；链接目标从 `asnber::pkcs::shared/static` 改为 `asnber::pkcs`。
- 需要最小体积时直接链接实现包：例如只用到 PKCS#8 时 `find_package(asnber-pkcs8)`，静态链接不会带入其他包的表。

## 依赖约束

- 聚合包依赖核心与四个实现包；四个实现包彼此独立、只依赖核心，均不依赖 `asnber-pkix` 或 `asnber-cms`。
- 核心库不反向引用任何 PKCS 包。

## 状态

0.4.0：聚合包落地（原门面包 1 个符号删除，ABI 基线 8 包 → 7 包），四个实现包各自独立安装/导出，`find_package(asnber-pkcs)` 用法保持不变。
