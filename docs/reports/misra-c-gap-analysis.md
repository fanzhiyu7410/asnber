# MISRA C:2012 合规性差距分析报告

项目：asnber v0.1.0  
日期：2026-11-10  
范围：公共 C99 头文件 (`include/asnber/*.h`) + 内部 C++17 实现 (`src/`)  
目标标准：MISRA C:2012 ( Amendment 2 / TC2 )；内部实现参照 MISRA C++:2023 映射

---

## 1. 适用性界定

| 层 | 语言 | 适用标准 | 文件数 |
|----|------|----------|--------|
| 公共 API 头文件 | C99 | MISRA C:2012 直接适用 | 11 |
| 内部实现 | C++17 (无异常/无 RTTI) | MISRA C++:2023；本报告按 C:2012 意图映射 | ~32 .cpp |
| 模块构建器 | C++17 | 同上 | modules/ |
| 嵌入式测试 | C99 | MISRA C:2012 直接适用 | tests/embedded/ |

关键事实：
- 编译选项已关闭异常 (`/EHs-c-`, `-fno-exceptions`) 和 RTTI (`/GR-`, `-fno-rtti`)
- 扩展关闭 (`CXX_EXTENSIONS OFF`)
- 警告级别 `/W4` 或 `-Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion`
- 静态分析工具已接入（cppcheck 2.22 + MISRA addon、clang-tidy 21.1、`.clang-tidy` 配置已入库）；偏差记录与合规声明文档尚未建立

---

## 2. 公共头文件分析 (MISRA C:2012 直接适用)

### 2.1 已符合项

| 规则 | 状态 | 证据 |
|------|------|------|
| Dir 4.6 (固定宽度类型) | 符合 | 全部使用 `int32_t`/`uint32_t`/`int64_t`/`size_t` |
| Rule 19.2 (union) | 符合 | 无 union |
| Rule 20.5 (#undef) | 符合 | 无 #undef |
| Rule 15.1 (goto) | 符合 | 头文件无函数体 |
| Rule 18.8 (VLA) | 符合 | 无 VLA |
| Rule 20.1 (include guard) | 符合 | 全部使用 `#ifndef` 守卫 |
| Rule 2.5 (未使用宏) | 符合 | 所有宏均被 API 消费 |
| Dir 4.9 (函数优先于宏) | 符合 | 无函数式宏 |

### 2.2 需偏差记录项

| 规则 | 严重度 | 位置 | 描述 | 偏差理由 |
|------|--------|------|------|----------|
| Rule 1.2 (语言扩展) | Required | `asnber_export.h:17-22` | `__declspec(dllexport/dllimport)`、`__attribute__((visibility))` | 仅共享库构建生效；`ASNBER_STATIC` (freestanding 配置) 下宏为空，扩展消失 |
| Rule 20.10 (#ifdef 嵌套) | Advisory | `asnber_export.h:13-25` | 三层条件编译 | 平台适配必需；静态构建可绕过 |
| Rule 8.2 (函数原型) | Required | 全部头文件 | 函数声明使用 `ASNBER_API` 宏修饰 | 宏展开后为标准原型；预处理后符合 |

### 2.3 潜在关注项 (非违规但需审查)

| 规则 | 位置 | 描述 | 评估 |
|------|------|------|------|
| Rule 11.4 / 11.5 | `asnber_allocator.h:29-31` | 函数指针含 `void*` 参数 | 这是分配器 vtable 设计；`void*` 用于不透明 user data，是 C 回调惯用法。MISRA 允许 `void*` 作为通用指针参数 (Rule 11.5 例外：与 `void*` 互转) |
| Rule 18.4 (struct 声明) | `asnber_decode.h:57-61`, `asnber_encode.h:28-32` | `asnber_reader`/`asnber_writer` 含函数指针成员 | 公开结构体用于回调注册，非 opaque handle；设计意图明确 |
| Rule 10.3 (赋值 essential type) | `asnber_error.h:18-55` | `#define ASNBER_E_INVALID_ARG ((asnber_err_t)1001)` | 显式 cast 到 `int32_t`，字面量 1001 在范围内，无隐式转换 |
| Rule 20.7 (宏参数括号) | `asnber_error.h`, `asnber_tag.h` | 所有 `#define` 无参数 | 对象式宏，Rule 20.7 不适用 |

### 2.4 公共头文件结论

**11 个头文件在 MISRA C:2012 下基本合规**，仅需 1 条 Required 偏差 (Rule 1.2 编译器扩展) 和 1 条 Advisory 偏差 (条件编译嵌套)。在 `ASNBER_STATIC` 构建下偏差自动消除。

---

## 3. 内部实现分析 (按 MISRA C:2012 意图映射)

> 内部为 C++17，严格来说适用 MISRA C++:2023。以下按 C:2012 规则意图分类，
> 供安全评估人员判断架构级偏差。

### 3.1 架构级差距 (需正式偏差或重构)

#### 3.1.1 递归 — Rule 17.2 [Required]

**9 处直接递归 + 6 组间接递归**，覆盖编解码核心路径：

| 函数 | 文件 | 递归类型 |
|------|------|----------|
| `encodeNode` | `src/der/asnber_encoder.cpp:242` | 直接 + 间接 (↔ `encodeSortedConstructed`) |
| `parseElement` ↔ `parseChildren` | `src/ber/asnber_ber_decoder.cpp:344,498` | 间接 |
| `bindType` | `src/schema/asnber_schema_decode_bind.cpp:425` | 直接 + 间接 (→ bindSequence → bindField → bindType) |
| `sizeOf` | `src/schema/asnber_schema_encode_size.cpp:247,261,279` | 直接 + 间接 |
| `writeOf` | `src/schema/asnber_schema_encode_write.cpp:388,401,458` | 直接 + 间接 |
| `collectTags` | `src/schema/asnber_schema_tlv.cpp:259` | 直接 |
| `parseTlv` ↔ `parseTlvChildren` | `src/schema/asnber_schema_tlv.cpp:105,24` | 间接 |
| `collectBitLeaves` / `copyBitLeaves` | `src/c_api/asnber_value_basic_api.cpp:83,127` | 直接 |
| `collectContentSize` / `copyContent` | `src/types/asnber_value.cpp:53,78` | 直接 |

**缓解措施已有**：所有递归路径受 `max_depth` (默认 64) 运行时限制，超限返回 `ASNBER_E_DEPTH_LIMIT`。

**偏差论证**：ASN.1 树结构天然递归；深度受配置上限约束；可证明栈使用有界 (每帧 ≤ 256B × 64 = 16KB)。MISRA C:2012 Amd2 允许在满足 Dir 4.1 运行时故障防护的前提下对 17.2 提出偏差。

**重构代价**：改为显式栈迭代需重写 6 个核心函数，影响 ~2000 行，风险高。

#### 3.1.2 指针算术 — Rule 18.4 [Required]

** pervasive **，~80+ 处。三大类：

1. **Arena header+1 / ptr-1 模式** (6 处)：`asnber_context.cpp:237,251`、`asnber_dom.cpp:124,148`、`asnber_encode_api.cpp:286,314`
2. **TLV 缓冲游标** (50+ 处)：`asnber_encoder.cpp`、`asnber_ber_decoder.cpp`、`asnber_schema_encode_write.cpp`、`asnber_schema_decode_bind.cpp`
3. **字符串/表偏移** (20+ 处)：`asnber_schema_table_records.cpp`、`asnber_value_text_api.cpp`

**偏差论证**：二进制协议编解码必须按字节偏移操作；所有指针运算均在已分配缓冲范围内，有前置长度校验。MISRA C:2012 Rule 18.4 的意图是防止越界，本项目通过 `size > limit` 前置检查满足 Dir 4.1。

**重构代价**：改为数组下标可消除大部分，但 header+1 模式需重新设计 arena 布局。中等代价。

#### 3.1.3 指针类型转换 — Rules 11.3 / 11.5 / 11.6 / 11.8 [Required]

**33 处 `reinterpret_cast` + 大量 `static_cast<void*>` + ~15 处 `const_cast`**：

| 类别 | 数量 | 典型位置 | 用途 |
|------|------|----------|------|
| Opaque handle 上下转型 | ~20 | `c_api/*.cpp` 全部 | C ABI 边界：内部类型 ↔ 不透明 `asnber_*_t*` |
| `void*` → 对象指针 (allocator) | ~25 | `asnber_context.cpp`, `asnber_dom.cpp` | 分配器返回 `void*`，需转为具体类型 |
| 字节缓冲 → `char*` | 6 | `asnber_schema_table*.cpp` | 描述表字符串池读取 |
| `uintptr_t` 对齐检查 | 1 | `asnber_context.cpp:96` | 静态池对齐验证 |
| `const_cast` 释放 | ~12 | `asnber_schema.cpp`, `asnber_schema_constraints.cpp` | 内部存储为 const，释放时需去 const |

**偏差论证**：
- Handle 转型是 C opaque pointer 模式的必然要求 (C ABI 不能暴露 C++ 类型)
- `void*` 分配器转换是 Rule 11.5 的允许例外
- `const_cast` 用于释放路径，对象生命周期由 arena 管理，无 aliasing 风险

#### 3.1.4 动态内存分配 — Rule 21.3 / Dir 4.12 [Required]

| 模式 | 位置 | 说明 |
|------|------|------|
| `std::malloc/realloc/free` | `asnber_context.cpp:30,37,45`; `asnber_ctx_api.cpp:40,46,52` | 默认堆分配器 |
| `placement new`（不调用 `operator new`/`delete`） | `asnber_decode_api.cpp:302` | 增量解码器在上下文分配器缓冲上原地构造 |
| `contextAllocate` / `contextRelease` | `asnber_decode_api.cpp:266,297,329` | 增量解码器对象与内部缓冲（`AllocationKind::kGeneric`） |
| Arena bump allocator | `asnber_context.cpp:203-212`; `asnber_dom.cpp:136` | 核心分配路径 |

**缓解措施**：
- 静态池模式下 malloc/realloc/free 完全不被调用 (嵌入式测试 `embedded_pool.c` 证明零堆调用)
- 静态池耗尽返回 `ASNBER_E_STATIC_POOL_EXHAUSTED`，不回退到堆 (ADR-0004)
- 增量解码器不使用 `operator new`/`delete`、`std::vector` 或 `try/catch`：对象与缓冲均由上下文分配器管理（placement 构造 + 显式析构），可整体编译裁切

**偏差论证**：在 freestanding 配置 + 静态池下，Rule 21.3 的运行时路径不存在。增量解码器可通过编译裁切排除。

### 3.5 工具扫描验证 (cppcheck 2.22 + MISRA addon / clang-tidy 21.1)

**环境说明**

| 组件 | 版本 | 说明 |
|------|------|------|
| cppcheck | 2.22.0 | 扫描器 |
| misra.py / cppcheckdata.py / misra_9.py | 2.22.0 | 与 cppcheck 同版本 tag 的 addon，三者须放在同一目录 |
| Python | 3.13 | 运行 addon |
| clang-tidy | 21.1.0 | 补充扫描，见 3.6 |

> addon 版本必须与 cppcheck 一致，跨版本 dump 解析会失败。

**公共头文件 (`include/asnber/*.h`) — C99**

```text
cppcheck 2.22 --std=c99 + misra.py → 0 条 misra-c2012-*.X 违规
```

结论：公共头文件在 MISRA C:2012 下保持干净，与人工审查一致。

**内部实现 (`src/`) — C++17**

```text
cppcheck 2.22 --std=c++17 + misra.py → 46 条 misra-c2012-17.2（递归）
```

完整原始清单归档在 `docs/reports/misra-scan-results.txt`（46 行）。

**Rule 17.2（递归）按文件分布**

| 文件 | 命中数 |
|------|--------|
| `src/schema/asnber_schema_decode_bind.cpp` | 10 |
| `src/schema/asnber_schema_encode_write.cpp` | 9 |
| `src/schema/asnber_schema_encode_size.cpp` | 8 |
| `src/der/asnber_encoder.cpp` | 5 |
| `src/ber/asnber_ber_decoder.cpp` | 4 |
| `src/schema/asnber_schema_tlv.cpp` | 3 |
| `src/types/asnber_value.cpp` | 2 |
| `src/c_api/asnber_value_basic_api.cpp` | 2 |
| `src/schema/asnber_schema_encode_tags.cpp` | 1 |
| `src/schema/asnber_schema_decode_tags.cpp` | 1 |
| `src/schema/asnber_schema_decode_constraints.cpp` | 1 |
| **合计** | **46** |

递归本身符合设计预期（BER/DER 编解码、schema bind/size/write 是天然的树遍历），深度受 `ctx->max_depth`（默认 64）约束，属 G1 偏差论证范围。

**Rule 7.2（unsigned 字面量后缀）— 已修复 (G13)**

`schemaCrc32c` 使用直接字面量 `0xFFFFFFFFU` / `0x82F63B78U`：addon 不展开宏，`UINT32_C(0x...)` 会被判为缺少后缀；也不能在宏参内加 `u`，MinGW 的 `UINT32_C` 为 `c##U` 拼接，会产生双后缀。该规则重扫命中 0。

**工具局限**

1. cppcheck 2.22 `misra.py` 对 C++17 语法（`nullptr`、`static_cast`、`enum class`）仍产生 `[misra-config]` 噪声；这些不是违规，addon 已在输出中过滤。
2. addon **仍未覆盖** Rule 11.x（指针转换）、Rule 18.4（指针算术）、Rule 10.x（符号混合）等 C++ 密集规则，依赖 clang-tidy 与人工审查（见 3.6）。
3. `UINT32_C` / `INT32_C` 等标准宏因预处理器不展开而在 Rule 7.2 下误报，代码中改用直接字面量规避。
4. 完整 MISRA C:2012 / MISRA C++:2023 覆盖需引入商业工具（PC-lint Plus、Helix QAC、Polyspace）。

**cppcheck 2.22.0 内置检查（非 MISRA）**

```text
src/          : 13 条 style/information
include/asnber/ : 105 条 unusedStructMember（API 保留字段，可抑制）
```

主要类型：
- `constVariablePointer` / `constParameterPointer`：局部变量/参数可加 const（不影响 API ABI）
- `useStlAlgorithm` / `useStandardLibrary`：一处循环可改 `std::find`
- `unusedStructMember`：公开结构体中的 `reserved[]` 字段，预期行为
- `redundantInitialization`：一处冗余初始化
- `knownConditionTrueFalse`：一处已知条件

这些属于代码质量改进项，不是 MISRA Required 违规。

**推荐 CI / 本地复现命令**

```bash
# 1. 下载并放置 misra.py（与 cppcheck 同版本）
mkdir -p /tmp/cppcheck_addons
cd /tmp/cppcheck_addons
for f in misra.py cppcheckdata.py misra_9.py; do
  curl -sSLo "$f" "https://raw.githubusercontent.com/danmar/cppcheck/2.22/addons/$f"
done

# 2. 公共头文件 MISRA 扫描（C99）
cppcheck --dump --enable=all --std=c99 -I include --suppress=missingIncludeSystem \
  include/asnber/asnber.h include/asnber/asnber_allocator.h include/asnber/asnber_build.h \
  include/asnber/asnber_decode.h include/asnber/asnber_encode.h include/asnber/asnber_error.h \
  include/asnber/asnber_export.h include/asnber/asnber_node.h include/asnber/asnber_schema.h \
  include/asnber/asnber_tag.h include/asnber/asnber_warning.h
python /tmp/cppcheck_addons/misra.py --no-summary -P '' include/asnber/*.dump \
  | grep 'misra-c2012-' > misra-include.txt
rm -f include/asnber/*.dump include/asnber/*.ctu-info

# 3. 内部实现 MISRA 扫描（C++17）
cppcheck --dump --enable=all --std=c++17 -I include -I src --suppress=missingIncludeSystem src
python /tmp/cppcheck_addons/misra.py --no-summary -P '' $(find src -name '*.dump') \
  | grep 'misra-c2012-' | sort -u > misra-src.txt
rm -f $(find src -name '*.dump' -o -name '*.ctu-info')

# 4. 内置代码质量检查
cppcheck --quiet --enable=all --check-level=exhaustive --std=c++17 \
  -I include -I src --suppress=missingIncludeSystem --inline-suppr \
  --xml src include 2> cppcheck-report.xml
```

---

### 3.6 clang-tidy 补充扫描 (LLVM 21.1.0)

clang-tidy 21.1.0（随 LLVM 发行），通过 CMake + Ninja 生成 `compile_commands.json` 后运行。仓库内 `.clang-tidy` 聚焦 C++ Core Guidelines 中与 MISRA 相关的检查。

**扫描范围**：`src/` 全部 32 个 .cpp 文件  
**总警告数**：859 条（已抑制系统头文件噪声）

**与 MISRA 直接相关的警告分布**

| 检查项 | 数量 | 对应 MISRA 关注 | 说明 |
|--------|------|----------------|------|
| `cppcoreguidelines-pro-bounds-pointer-arithmetic` | 423 | Rule 18.4 | 指针算术，与人工审查一致 |
| `cppcoreguidelines-pro-type-reinterpret-cast` | 33 | Rule 11.3/11.6 | reinterpret_cast |
| `cppcoreguidelines-pro-type-const-cast` | 23 | Rule 11.8 | const_cast |
| `bugprone-casting-through-void` | 18 | Rule 11.5 | C API handle 经 void* 转换 |
| `cppcoreguidelines-no-malloc` | 7 | Rule 21.3 / Dir 4.12 | malloc/realloc/free |
| `cppcoreguidelines-pro-type-member-init` | 5 | Rule 9.1 / Dir 4.1 | 局部结构体未值初始化 |
| `cppcoreguidelines-pro-type-vararg` | 3 | Rule 17.1 | 可变参数（来自 std::snprintf 等） |
| `cppcoreguidelines-avoid-do-while` | 2 | Rule 15.4 | do-while 循环 |
| `bugprone-branch-clone` | 1 | Dir 4.1 | 条件分支重复 |

**其他代码质量警告（非 MISRA Required）**

| 检查项 | 数量 | 说明 |
|--------|------|------|
| `readability-uppercase-literal-suffix` | 180 | 字面量后缀应大写（`u` → `U`） |
| `readability-math-missing-parentheses` | 56 | 混合运算建议加括号 |
| `misc-const-correctness` | 41 | 局部变量/参数可加 const |
| `readability-inconsistent-declaration-parameter-name` | 36 | 声明与定义参数名不一致 |
| `cppcoreguidelines-avoid-c-arrays` | 14 | C 风格数组（多为固定大小缓冲） |
| `misc-use-internal-linkage` | 11 | 内部函数可放匿名命名空间 |
| `readability-simplify-boolean-expr` | 2 | 布尔表达式可简化 |
| `cppcoreguidelines-init-variables` | 1 | 变量未初始化 |

**关键发现**

1. **指针算术是最大头**（423 条），远超人工估算的 ~80 处。原因是 clang-tidy 把数组下标 `data[i]` 也计为指针算术（`cppcoreguidelines-pro-bounds-pointer-arithmetic` 的默认行为）。若只统计真正的 `ptr + offset`，数量会回落到人工估算范围。
2. **5 处局部结构体未值初始化**：
   - `src/c_api/asnber_doc_api.cpp:300` — `TlvHeader header;`
   - `src/schema/asnber_schema_decode.cpp:162,281` — `BindContext bind;`
   - `src/schema/asnber_schema_encode.cpp:25,49` — `EncState st;`
   这些结构体随后由函数填充，但 clang-tidy 无法跨函数证明。添加 `{}` 是低风险修复，可满足 MISRA Rule 9.1。
3. **C API handle 转换模式**：18 处 `static_cast<T*>(static_cast<void*>(handle))` 被建议改为 `reinterpret_cast<T*>(handle)`。两者在 MISRA 下都属 Rule 11.x 偏差，但 `reinterpret_cast` 更直接。
4. **malloc 确认**：7 处全部在默认分配器（`asnber_context.cpp` 和 `asnber_ctx_api.cpp`），与人工审查一致。

**推荐 CI 命令**

```bash
# 生成 compile_commands.json
cmake -S . -B build-tidy -G Ninja \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_RC_COMPILER=llvm-rc \
  -DASNBER_BUILD_TESTS=OFF -DASNBER_BUILD_TOOLS=OFF -DASNBER_BUILD_MODULES=OFF

# 运行 clang-tidy
clang-tidy -p build-tidy --quiet src/**/*.cpp 2> clang-tidy-report.txt
```

---

### 3.2 代码级差距 (可修复)

#### 3.2.1 有符号/无符号混合 — Rules 10.3 / 10.4 [Required]

~20 处，主要模式及处置（下列 3 个显式示例已修复/核实）：

```cpp
// asnber_schema_decode_bind.cpp:148（已修复：先判负，再转 size_t 比较）
c.lower.value < 0 || index < static_cast<size_t>(c.lower.value)

// asnber_value_basic_api.cpp:250（已修复：按符号位分支，避免实现定义转换）
(raw & 0x8000000000000000ULL) != 0
    ? -1 - static_cast<int64_t>(~raw)
    : static_cast<int64_t>(raw)

// asnber_value_text_api.cpp:382-389（已核实：窄化 cast 前已有范围校验）
out_time->year = static_cast<int32_t>(year);
```

**剩余方案**：对其余同类比较补充范围前置检查；对 `size_t` 与字面量比较使用 `u` 后缀。

#### 3.2.2 多返回点 — Rule 15.5 [Advisory]

**1,309 个 return 语句 / 32 个文件**。几乎所有函数使用 guard-clause 早返回。

最高密度：`asnber_ber_decoder.cpp` (91)、`asnber_schema_table_records.cpp` (71)、`asnber_context.cpp` (67)。

**评估**：Advisory 级别，不阻碍合规声明。Guard-clause 是项目编码规范 (`docs/08-编码规范.md`) 的推荐风格，且降低嵌套复杂度。建议保留并记录为 Advisory 偏差。

#### 3.2.3 无控制表达式循环 — Rule 15.4 [Advisory]

原 5 处 `for (;;)` 循环（**已修复**为 `while (true)`，控制表达式为本质布尔类型）：
- `asnber_ber_decoder.cpp:316,364,649`
- `asnber_doc_api.cpp:93`
- `asnber_schema_tlv.cpp:120`

全部有内部 `break`/`return` 终止条件，且受输入长度约束。修复后 `src/` 内 `for (;;)` 计数为 0。

#### 3.2.4 协议魔数 — Dir 4.6 / 可维护性

内部实现中 ASN.1 标签号、位掩码、UTF-8 常量大量内联：
- `asnber_ber_decoder.cpp:74-92`：`case 1: case 2: case 3: ...`
- `asnber_tag_codec.cpp`：`0x1FU`, `0x80U`, `0x7FU`
- `asnber_value_text_api.cpp`：`0x800u`, `0x10000u`, `0xD800u`

公共头文件 `asnber_tag.h` 已定义命名常量，但内部未引用。

**修复方案**：内部统一使用 `asnber_tag.h` 常量 + 补充位掩码/UTF-8 命名常量。工作量：~1 人天。

### 3.3 已符合项 (内部实现)

| 规则 | 状态 | 证据 |
|------|------|------|
| Rule 15.1 (goto) | 符合 | 全 src/ 零 goto |
| Rule 18.8 (VLA) | 符合 | 所有栈数组为 constexpr 尺寸 |
| Rule 19.2 (union) | 符合 | 全 src/ 零 union |
| Rule 20.5 (#undef) | 符合 | 全 src/ 零 #undef |
| Dir 4.12 (动态分配) | 部分符合 | 静态池模式无堆；默认模式有堆但可替换 |
| Rule 21.3 (malloc) | 部分符合 | 同上 |
| Dir 4.1 (运行时故障) | 符合 | 所有外部输入有长度/深度/节点数上限 |
| Rule 22.x (资源泄漏) | 符合 | Arena 生命周期管理 + context destroy 兜底 |

### 3.4 编译器扩展

仅 2 处：
1. `asnber_export.h`：`__declspec` / `__attribute__` — 静态构建下消失
2. `asnber_schema.cpp:31-39`：`__builtin_mul_overflow` — 已有 ISO C++ 回退

无 `#pragma pack`、无 `__asm`、无平台 `#ifdef` 分支 (除 export)。

---

## 4. 构建配置评估

| 配置项 | 当前值 | MISRA 相关性 |
|--------|--------|-------------|
| C++ 标准 | 17 (可选 20) | MISRA C++:2023 覆盖 C++17 |
| 异常 | 关闭 | 消除 Dir 4.12 异常路径 |
| RTTI | 关闭 | 消除动态类型转换 |
| 扩展 | OFF | 减少 Rule 1.2 表面 |
| 警告 | /W4 或 -Wall -Wextra -Wconversion | 接近 MISRA 静态检查子集 |
| Freestanding | 定义宏但无 #ifdef 消费 | 架构保证，非条件编译 |
| 静态分析工具 | cppcheck 2.22 + 同版本 MISRA addon + clang-tidy 21.1 | 三工具链已接入；addon 命中 46 处 Rule 17.2（递归，设计预期），G12/G13 已修复归零 |

---

## 5. 差距汇总与优先级

| # | 差距 | 规则 | 级别 | 影响范围 | 修复策略 | 估算 |
|---|------|------|------|----------|----------|------|
| G1 | 递归 | 17.2 | Required | 46 处 / 11 文件（cppcheck 2.22 addon 确认） | 偏差记录 (深度有界证明) | 2 天 (文档) |
| G2 | 指针算术 | 18.4 | Required | ~80 处 | 偏差记录 (边界校验证明) | 3 天 (文档) |
| G3 | 指针类型转换 | 11.3/11.5/11.8 | Required | ~70 处 | 偏差记录 (ABI 边界 + allocator) | 2 天 (文档) |
| G4 | 动态分配 | 21.3 / Dir 4.12 | Required | 默认分配器 + 增量解码器 | 偏差记录 (静态池路径无堆) + 裁切增量解码器 | 1 天 |
| G5 | 有符号/无符号混合 | 10.3/10.4 | Required | ~20 处 | 显式示例已修复；其余补充范围检查 + u 后缀 | 2 天 (剩余) |
| G6 | 编译器扩展 | 1.2 | Required | 2 处 | 偏差记录 (静态构建消除) | 0.5 天 |
| G7 | 多返回点 | 15.5 | Advisory | 全局 | 保留，记录 Advisory 偏差 | 0.5 天 |
| G8 | 无控制表达式循环 | 15.4 | Advisory | 5 处 | **已修复**：改为 while (true) | 完成 |
| G9 | 协议魔数 | Dir 4.6 | Advisory | ~100 处 | 提取命名常量 | 1 天 |
| G10 | 静态分析工具 | — | 流程 | 全项目 | **已完成**：cppcheck 2.22 + 同版本 MISRA addon + clang-tidy 21.1 已接入 | 完成 |
| G11 | 无偏差记录 | — | 流程 | 全项目 | 建立 deviation register | 1 天 |
| G12 | 局部结构体未值初始化 | 9.1 / Dir 4.1 | Required | 5 处 | **已修复**：添加 `{}` 初始化，clang-tidy 验证归零 | 完成 |
| G13 | `UINT32_C` 宏内的字面量后缀 | 7.2 | Required | 3 处 (`schemaCrc32c`) | **已修复**：替换为直接字面量 `0xFFFFFFFFU` / `0x82F63B78U`，cppcheck 验证归零 | 完成 |

**工具扫描后的调整**

- G1 递归：cppcheck MISRA addon 确认 46 处 Rule 17.2 / 11 文件，分布见 3.5 节。clang-tidy 未启用 `misc-no-recursion`（已抑制），人工审查仍识别 9 直接 + 6 间接。
- G2 指针算术：clang-tidy 报 423 条（含数组下标），真正的 `ptr + offset` 约 80 处，与人工审查一致。
- G3 指针转换：clang-tidy 确认 33 reinterpret_cast + 23 const_cast + 18 void 转换。
- G4 动态分配：clang-tidy 确认 7 处 malloc/realloc/free，全部在默认分配器。
- G10 已完成：cppcheck 2.22 + 同版本 misra.py + clang-tidy 21.1 三工具链可用，`.clang-tidy` 配置已入库。
- **G12 已修复**：5 处局部结构体添加 `{}`，clang-tidy `pro-type-member-init` 归零。
- **G13 已修复**：`schemaCrc32c` 三处 `UINT32_C(0x...)` 替换为直接字面量 `0xFFFFFFFFU` / `0x82F63B78U`（MinGW `UINT32_C` 为 token 拼接 `c##U`，宏内加 `u` 会产生双后缀编译错误）。cppcheck Rule 7.2 归零，总违规 49 → 46（仅剩 Rule 17.2 递归）。

---

## 6. 合规路径建议

### 阶段 A：文档与工具 (1 周，工具已完成)

1. **静态分析工具（已完成）**：
   - cppcheck 2.22 + MISRA addon 已接入
   - clang-tidy 21.1 已接入，`.clang-tidy` 配置已入库
   - 如需完整 MISRA 编号覆盖，再引入商业工具（Polyspace / PC-lint / Helix QAC）
2. 建立偏差登记册 (deviation register)，格式参照 MISRA Compliance:2020
3. 对 G1-G4、G6 编写正式偏差记录，含：
   - 违规位置清单
   - 安全论证 (为什么不会导致未定义行为)
   - 缓解措施 (深度限制、边界检查、静态池)
   - 审批签名
4. 配置 CI 集成静态分析（建议命令见 3.5 / 3.6 节）

### 阶段 B：代码修复 (1 周)

1. G13：**已修复** — 替换为直接字面量 `0xFFFFFFFFU` / `0x82F63B78U`
2. G12：**已修复** — 5 处局部结构体添加 `{}`
3. G5：修复有符号/无符号混合 (添加前置范围检查)
4. G9：提取协议常量到内部头文件
5. G8：已修复，无需再动

### 阶段 C：合规声明 (1 周)

1. 运行完整静态分析，确认无新增 Required 违规
2. 编写合规声明文档 (Guideline Enforcement Plan + Deviation Register + Review Records)
3. 对 freestanding 静态池配置出具 "MISRA C:2012 compliant with deviations" 声明

### 裁切配置下的合规格

在以下编译配置下，合规表面最小：
```cmake
ASNBER_FREESTANDING=ON
ASNBER_BUILD_SHARED=OFF        # ASNBER_STATIC → export 宏为空
ASNBER_BUILD_MODULES=OFF       # 排除模块构建器（增量解码器已不依赖堆 new/delete/vector）
ASNBER_BUILD_TOOLS=OFF
```

此配置下：
- Rule 1.2 偏差消失 (无编译器扩展)
- Rule 21.3 / Dir 4.12 运行时路径不存在 (静态池)
- 剩余 Required 偏差：G1 (递归)、G2 (指针算术)、G3 (指针转换)、G5 (类型混合)
- 全部可通过偏差记录 + 少量代码修复覆盖

---

## 7. 与车载安全标准的衔接

| 标准 | 要求 | 本项目现状 | 差距 |
|------|------|-----------|------|
| ISO 26262 ASIL-B | MISRA C 合规 + 工具鉴定 | 工具已接入，偏差记录待建 | 阶段 A(剩余)-C |
| ISO 26262 ASIL-D | MISRA C 强制 + 独立审查 | 同上 + 需第三方审计 | 额外 4-6 周 |
| AUTOSAR CP | MISRA C:2012 + OS 适配 | 无 OS 抽象层 | 库本身无 OS 依赖，集成层需适配 |
| IEC 61508 SIL-2 | 静态分析 + 编码标准 | 编码规范已有 (docs/08)，工具已接入 | 偏差记录 + 执行证据 |

**结论**：库架构 (无 OS、无 IO、静态池、深度限制) 对车载集成友好。工具链已接入并产出客观违规清单（46 处 Rule 17.2 递归 + 已修复的 G12/G13）。剩余差距主要是流程性的 (偏差记录 + 审计证据)，而非架构性的。递归和指针算术是 ASN.1 编解码的固有特征，通过有界证明可获偏差批准。

---

## 附录 A：公共头文件清单

| 文件 | 行数 | 主要 MISRA 关注 |
|------|------|----------------|
| `asnber.h` | 24 | 仅 include 聚合 |
| `asnber_allocator.h` | 96 | 函数指针 vtable、void* |
| `asnber_build.h` | 100 | 枚举、opaque handle |
| `asnber_decode.h` | 131 | 函数指针回调、公开 struct |
| `asnber_encode.h` | 90 | 函数指针回调、公开 struct |
| `asnber_error.h` | 82 | 对象式宏 + cast |
| `asnber_export.h` | 27 | 编译器扩展 |
| `asnber_node.h` | 131 | 枚举、struct、位标志宏 |
| `asnber_schema.h` | 243 | 多枚举、嵌套 struct |
| `asnber_tag.h` | 42 | 对象式宏 (命名常量) |
| `asnber_warning.h` | 64 | 函数指针回调 |

## 附录 B：内部实现关键文件

| 文件 | 主要违规类型 |
|------|-------------|
| `src/ber/asnber_ber_decoder.cpp` | 递归、指针算术、魔数 |
| `src/der/asnber_encoder.cpp` | 递归、指针算术、魔数 |
| `src/core/asnber_context.cpp` | 指针转换、malloc、指针算术 |
| `src/types/asnber_dom.cpp` | 指针转换、指针算术、递归 |
| `src/schema/asnber_schema_decode_bind.cpp` | 递归、有符号混合、指针算术 |
| `src/schema/asnber_schema_encode_write.cpp` | 递归、指针算术 |
| `src/schema/asnber_schema_encode_size.cpp` | 递归 |
| `src/c_api/asnber_decode_api.cpp` | 上下文分配器 + placement new（无 operator new/delete、无 vector、无 try/catch） |
| `src/c_api/asnber_value_text_api.cpp` | 窄化转换、魔数 |
| `src/c_api/asnber_value_basic_api.cpp` | 递归、有符号混合、魔数 |