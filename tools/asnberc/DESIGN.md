# asnberc 设计文档

asnberc 是 ASN.1 模块描述表编译工具，将 `.asn1` 文本编译为核心库可加载的二进制描述表或 C 数组。

## 1. 架构概览

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              asnberc 工具                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  input.asn1 ──► Lexer ──► Parser ──► AST ──► Semantic ──► Model         │
│                                                                          │
│                                          Model ──► TableBuilder ──► bytes│
│                                                                          │
│                                          bytes ──► renderCArray ──► .h   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 处理流水线

| 阶段 | 输入 | 输出 | 源文件 |
|------|------|------|--------|
| 词法分析 | `.asn1` 文本 | `Token[]` | `lexer.cpp` |
| 语法解析 | `Token[]` | `ModuleAst` | `parser.cpp` |
| 模块装载 | 多个 `.asn1` + `-I` | `ModuleSet`（导入绑定/合并顺序） | `module_set.cpp` |
| 语义分析 | `ModuleSet` | `SchemaModel` | `semantic*.cpp` |
| 表生成 | `SchemaModel` | `TableOutput` | `table.cpp` |
| C 数组渲染 | `TableOutput` | `.h` 源文件 | `table.cpp` |

## 2. 模块职责

### 2.1 词法分析器 (lexer)

把源文本切成 token 序列。

**Token 类型**：

```cpp
enum class TokenKind {
    End,           // 文件结束
    Identifier,    // 标识符（允许内部连字符，如 TBSCertificate）
    Number,        // 数字字面量
    String,        // 双引号字符串（"" 转义为 "）
    Assign,        // ::=
    Ellipsis,      // ...
    LBrace/RBrace, // { }
    LParen/RParen, // ( )
    LBracket/RBracket, // [ ]
    Comma, Semicolon, Pipe, Dot, DotDot, Star, Minus, At
};
```

**ASN.1 标识符规则**：
- 首字符：`A-Z` 或 `a-z`
- 后续字符：`A-Z`、`a-z`、`0-9`、`-`
- 关键字比较大小写不敏感

**注释处理**：
- `--` 开始，到行尾或下一个 `--` 结束
- 词法分析阶段跳过，不产生 token

### 2.2 语法解析器 (parser)

递归下降解析器，把 token 序列转换为 AST。

**解析目标**：

```
Module ::= ModuleName ModuleBody END

ModuleName ::= identifier [ '{' ... '}' ]

ModuleBody ::= DEFINITIONS TagMode '::=' BEGIN
               Declaration*
               
TagMode ::= EXPLICIT TAGS | IMPLICIT TAGS | AUTOMATIC TAGS | ε

Declaration ::= TypeAssignment | ValueAssignment | Imports | Exports

TypeAssignment ::= identifier '::=' Type

ValueAssignment ::= identifier Type '::=' Value

Imports ::= IMPORTS SymbolsFromModule { ',' SymbolsFromModule } ';'
SymbolsFromModule ::= SymbolList FROM ModuleName [ '{' ... '}' ]
SymbolList ::= identifier { [','] identifier }
Exports ::= EXPORTS [ ALL | SymbolList ] ';'
```

**支持的语法**：

| 类别 | 支持 |
|------|------|
| 基本类型 | BOOLEAN、INTEGER、ENUMERATED、BIT STRING、OCTET STRING、NULL、OBJECT IDENTIFIER、各字符串类型、时间类型 |
| 构造类型 | SEQUENCE、SET、CHOICE、SEQUENCE OF、SET OF、ANY |
| 标签 | `[n]`、`[n] IMPLICIT`、`[n] EXPLICIT` |
| 约束 | 单值、值域 `(a..b)`、`SIZE(...)`、`MAX`、`MIN`、扩展标记 `...` |
| 值 | OID 字面量、整数字面量、布尔字面量、命名值引用 |
| 模块 | `IMPORTS ... FROM Module`（多组、多模块）与 `EXPORTS`（`ALL`/列表/空） |

**仍不支持的语法**（报 `ASNBERC_E_UNSUPPORTED_CONSTRUCT`）：

- 参数化类型定义与实例化
- `CLASS` / `WITH SYNTAX` / 信息对象集
- `COMPONENTS OF`
- `WITH COMPONENTS` / `PATTERN`

### 2.2.1 模块装载与导入绑定

`module_set` 负责多文件输入：

- 输入：`1..N` 个显式 `.asn1` 文件 + 可重复的 `-I/--include` 目录。
- 发现：模块 `M` 对应 `M.asn1`（完全同名）；搜索顺序为显式输入文件所在目录（命令行顺序）→ `-I` 目录（给出顺序），首个命中生效；已加载模块不重复解析。
- 合并顺序：显式输入保持命令行顺序在前，按需发现模块随后按模块名 ASCII 升序。
- 索引：每个模块维护 `类型名 -> 定义`、`值名 -> 定义`、导入绑定 `本地名 -> 目标模块`。
- `EXPORTS`：缺省与 `ALL` 均为全导出；空列表为不导出；显式列表须在模块内有定义（否则 9002）。
- 绑定失败：缺模块、缺符号/未导出、自导入、循环导入报 9002；本地同名冲突、同一名称从两个模块导入、重复模块名报 9003。循环导入用 DFS 检测，只报第一个环并停止。
- 名称唯一性：合并后单表名称空间内，后出现同名类型改名为 `Foo-<Module>`（仍冲突追加 `-2`…）。

### 2.3 AST 结构

```cpp
// 模块
struct ModuleAst {
    std::string name;
    Pos namePos;
    int tagMode;  // 0=AUTOMATIC, 1=EXPLICIT, 2=IMPLICIT, 3=未声明
    std::vector<ImportGroupAst> imports;  // 多组 “符号 FROM 模块”
    ExportsAst exports;                   // present/all/symbols
    std::vector<TypeAssignment> types;
    std::vector<ValueAssignment> values;
};

// 类型赋值
struct TypeAssignment {
    std::string name;
    Pos pos;
    std::unique_ptr<TypeAst> type;
};

// 类型表达式
struct TypeAst {
    enum class Class {
        Reference,      // 引用其他类型
        Boolean, Integer, Enumerated, BitString, OctetString,
        Null, ObjectIdentifier,
        Utf8String, PrintableString, Ia5String, ...
        Any,
        Sequence, Set, Choice, SequenceOf, SetOf
    };
    
    Class cls;
    std::string refName;           // Reference 时有效
    std::vector<FieldAst> fields;  // Sequence/Set/Choice 的字段
    std::unique_ptr<TypeAst> element;  // SequenceOf/SetOf 的元素类型
    std::vector<ConstraintAst> constraints;
    std::vector<NamedNumberAst> namedNumbers;  // ENUMERATED/INTEGER 命名值
    TagSpec tag;
    bool extensible;  // 是否有扩展标记 ...
};

// 字段
struct FieldAst {
    std::string name;
    std::unique_ptr<TypeAst> type;
    bool optional;
    bool extension;  // 是否在 ... 之后
    std::unique_ptr<ValueAst> defaultValue;
};
```

### 2.4 语义分析器 (semantic)

把 AST 转换为内部语义模型 `SchemaModel`，执行类型检查与结构验证。

**核心任务**：

1. **模块合并**：按合并顺序注册全部模块的具名类型；引用解析先查本模块定义、再查导入绑定；每个 `TypeNode` 记录定义模块 `unit`，用于按该模块标注方式算标签并定位诊断文件
2. **类型注册**：遍历所有具名类型，建立名称到索引的映射（键为 `unit/名称`）
3. **类型解析**：递归解析类型引用，创建 `TypeNode` 树
4. **合成类型**：为匿名内联结构生成合成类型（名称以 `$` 开头）
5. **标签计算**：根据**定义模块**的标注方式和显式标签计算最终标签
6. **约束处理**：解析并验证约束表达式
7. **默认值编码**：把 `DEFAULT` 值编码为规范 DER TLV
8. **结构检查**：重复标签、重复字段、CHOICE 分支冲突
9. **根类型**：`--root` 未限定名要求跨模块唯一，`Module.Type` 精确定位

**语义模型**：

```cpp
struct TypeNode {
    std::string name;
    bool synthetic;  // 是否为合成类型
    TypeKind kind;   // Simple/Sequence/Set/Choice/SequenceOf/SetOf/Any
    uint8_t tagMode; // 0=DEFAULT, 1=EXPLICIT, 2=IMPLICIT
    uint8_t tagClass; // 0=UNIVERSAL, 2=CONTEXT
    uint32_t tagNumber;
    uint32_t baseTagNumber;  // 通用标签号（用于 ANY 和显式包装）
    uint32_t flags;
    TypeNode *element;  // SequenceOf/SetOf 的元素类型
    std::vector<Field> fields;
    std::vector<Constraint> constraints;
    std::vector<NamedValue> namedValues;
    uint32_t id;  // 最终分配的类型编号
};

struct Field {
    std::string name;
    TypeNode *type;
    uint16_t flags;  // OPTIONAL/EXTENSION
    bool hasDefault;
    std::vector<uint8_t> defaultTlv;  // 默认值的 DER 编码
    std::vector<Constraint> constraints;
};

struct SchemaModel {
    std::vector<std::unique_ptr<TypeNode>> nodes;
    std::vector<TypeNode *> named;      // 具名类型（按源码顺序）
    std::vector<TypeNode *> synthetic;  // 合成类型
    TypeNode *anyNode;  // 共享的 ANY 节点
    uint32_t moduleTagMode;
    uint32_t rootTypeId;
};
```

**类型编号规则**：

- 具名类型按源码顺序占 `1..N`
- 合成类型追加在具名类型之后
- `0` 表示无效引用

**合成类型生成**：

以下情况会生成合成类型：

1. 匿名内联 SEQUENCE/SET/CHOICE
2. 标签克隆（`[0] SomeType`）
3. 共享裸 ANY 引用

合成类型名称格式：`$<hint>$<counter>`，如 `$Sequence$3`

### 2.5 表生成器 (table)

把 `SchemaModel` 序列化为二进制描述表。

**输出布局**：

```
┌─────────────────────────────────────┐
│ Header (108 bytes)                  │
├─────────────────────────────────────┤
│ String Pool                         │
├─────────────────────────────────────┤
│ Type Table (48 bytes × type_count)  │
├─────────────────────────────────────┤
│ Field Table (32 bytes × field_count)│
├─────────────────────────────────────┤
│ Constraint Table                    │
├─────────────────────────────────────┤
│ Default Table + Default Data        │
├─────────────────────────────────────┤
│ Name Table (24 bytes × name_count)  │
└─────────────────────────────────────┘
```

**生成步骤**：

1. **字符串池构建**：收集所有类型名、字段名、约束文本，去重后按偏移排列
2. **表布局计算**：确定各表的起始偏移，按 8 字节对齐
3. **记录写入**：按小端序写入各表记录
4. **默认值数据**：写入 DEFAULT 值的 DER 编码
5. **CRC32C 计算**：对整个表计算校验和
6. **头部写入**：填充头部各字段

**C 数组渲染**：

```c
/* 由 asnberc 生成，请勿手工修改。 */
#include <stddef.h>
#include <stdint.h>

const uint8_t kModuleNameSchema[] = {
    0x41, 0x53, 0x4E, 0x31, ...
};

const size_t kModuleNameSchema_size = sizeof(kModuleNameSchema);
```

符号名派生规则：去掉模块名中所有非字母数字字符，前缀 `k`，后缀 `Schema`。多模块输入使用**第一个显式输入模块**的模块名，`-I` 发现模块不参与命名。合并后的表头 `module_tag_mode` 仅在全部模块标注方式一致时取该值，否则写 3（未声明），因为各类型的实际标注已在生成期按定义模块解析。

## 3. 诊断系统

### 3.1 诊断格式

```
<file>:<line>:<column>: <severity>: <code>: <message>
```

示例：

```
test.asn1:12:5: error: 9002: undefined type 'Foo'
test.asn1:20:10: warning: 9101: unused import 'Bar'
```

### 3.2 错误码

| 错误码 | 值 | 含义 |
|--------|-----|------|
| `ASNBERC_E_SYNTAX` | 9001 | 词法/语法错误 |
| `ASNBERC_E_UNDEFINED_TYPE` | 9002 | 引用了未定义类型 |
| `ASNBERC_E_DUPLICATE_TYPE` | 9003 | 类型重名 |
| `ASNBERC_E_DUPLICATE_FIELD` | 9004 | 字段重名 |
| `ASNBERC_E_TAG_CONFLICT` | 9005 | 重复标签或 CHOICE 分支冲突 |
| `ASNBERC_E_UNSUPPORTED_CONSTRUCT` | 9006 | 一期不支持的语法构造 |
| `ASNBERC_E_PARAM_INSTANTIATION` | 9008 | 参数化实例化失败 |
| `ASNBERC_E_CONSTRAINT_INVALID` | 9009 | 约束非法或不可满足 |
| `ASNBERC_E_OUTPUT_IO` | 9010 | 输出写入失败 |
| `ASNBERC_E_INTERNAL` | 9099 | 工具内部不变量破坏 |

### 3.3 诊断级别

| 级别 | 输出 |
|------|------|
| `minimal` | 只输出 error |
| `normal` | 输出 error 和 warning |
| `verbose` | 额外输出生成摘要 |

### 3.4 诊断排序

按 `file`、`line`、`column`、`code` 升序稳定排序后输出。

## 4. 标签处理

### 4.1 模块级标注方式

| 声明 | 含义 |
|------|------|
| `EXPLICIT TAGS` | 默认显式标签 |
| `IMPLICIT TAGS` | 默认隐式标签 |
| `AUTOMATIC TAGS` | 自动分配标签（按字段顺序） |
| 未声明 | 无默认标注 |

### 4.2 标签计算规则

**显式标签 (`[n] EXPLICIT`)**：

```
原始类型: INTEGER (tag = 0x02)
包装后: [0] EXPLICIT INTEGER → 外层 tag = 0xA0, 内层 tag = 0x02
```

**隐式标签 (`[n] IMPLICIT`)**：

```
原始类型: INTEGER (tag = 0x02)
替换后: [0] IMPLICIT INTEGER → tag = 0x80
```

**自动标签 (`AUTOMATIC TAGS`)**：

```
SEQUENCE {
    foo INTEGER,        → [0] IMPLICIT INTEGER
    bar OCTET STRING,   → [1] IMPLICIT OCTET STRING
    baz BOOLEAN         → [2] IMPLICIT BOOLEAN
}
```

### 4.3 标签冲突检查

| 容器类型 | 规则 |
|----------|------|
| `SET` | 所有字段标签必须两两不同 |
| `CHOICE` | 所有分支标签集合必须两两不相交 |
| `SEQUENCE` | 允许重复标签，但 OPTIONAL/DEFAULT 字段的标签不得与后继字段相同 |

## 5. 约束处理

### 5.1 约束类型

| 类型 | 语法 | 适用 |
|------|------|------|
| RANGE | `(a..b)` | INTEGER、ENUMERATED |
| SIZE | `SIZE(a..b)` | 字符串、BIT STRING、OCTET STRING、SEQUENCE OF、SET OF |
| ENUM | `{name1(val1), name2(val2), ...}` | ENUMERATED、带命名的 INTEGER |
| MAX | `(0..MAX)` | 非负 INTEGER |
| BIGINT_RANGE | 十进制文本表示的大整数区间 | INTEGER |

### 5.2 约束存储

约束表每条记录 48 字节：

```c
struct ConstraintRecord {
    uint16_t kind;           // 0=RANGE, 1=SIZE, 2=ENUM, 3=MAX, 4=BIGINT_RANGE
    uint16_t flags;          // 位0=下界无界, 位1=上界无界
    uint32_t enum_off;       // ENUM 取值数组偏移
    uint32_t enum_count;     // ENUM 取值个数
    uint32_t lower_decimal_off;   // 下界十进制文本偏移
    uint32_t lower_decimal_size;  // 下界十进制文本长度
    uint32_t upper_decimal_off;
    uint32_t upper_decimal_size;
    int64_t lower_value;     // 下界小整数
    int64_t upper_value;     // 上界小整数
    uint32_t reserved;
};
```

## 6. 默认值处理

### 6.1 编码规则

默认值必须是**可规范化的完整 DER TLV**（含标签与长度）。

示例：

```asnber
MyInt INTEGER DEFAULT 42
-- 编码为: 02 01 2A (INTEGER, length=1, value=42)

MySeq SEQUENCE {
    flag BOOLEAN DEFAULT TRUE
}
-- flag 的默认值: 01 01 FF (BOOLEAN, length=1, value=TRUE)
```

### 6.2 存储方式

默认值表每条记录 8 字节：

```c
struct DefaultRecord {
    uint32_t data_offset;  // DER TLV 在文件中的偏移
    uint32_t data_size;    // DER TLV 字节数
};
```

默认值数据区与表区间不重叠，位于字符串池之后。

## 7. 名称表

名称表用于 `BIT STRING` 的命名位和 `ENUMERATED`/`INTEGER` 的数值名。

### 7.1 记录格式

每条 24 字节：

```c
struct NameRecord {
    uint32_t type_id;    // 所属类型编号 (1-based)
    uint32_t name_off;   // 名称在字符串池的偏移
    uint16_t kind;       // 0=BIT_NAME, 1=NUMBER_NAME
    uint16_t flags;      // 位0=EXTENSION
    uint32_t reserved0;
    int64_t value;       // BIT_NAME: 位号; NUMBER_NAME: 数值
};
```

### 7.2 适用类型

| kind | 所属类型要求 |
|------|-------------|
| BIT_NAME | `kind=SIMPLE`, `tag_class=UNIVERSAL`, `tag_number=3` (BIT STRING) |
| NUMBER_NAME | `kind=SIMPLE`, `tag_number=2` (INTEGER) 或 `10` (ENUMERATED) |

## 8. 退出码

| 退出码 | 含义 |
|--------|------|
| 0 | 成功 |
| 1 | 存在 error 诊断 |
| 2 | 命令行用法错误 |
| 3 | 输入/输出 IO 失败 |

### --trim-schema

`--trim-schema` 必须与 `--root` 同时使用：从根类型出发，只保留沿
`TypeNode::element` 与 `Field::type` 可达的类型，并在 `buildTable` 前按原
类型编号顺序连续重编为 `1..N`（具名类型在前、合成类型在后）。描述表格式
仍为 1.0，CRC、偏移与对齐由现有生成器重算。

- 缺少 `--root`：用法错误，退出码 2；
- 根类型不存在：诊断 `ASNBERC_E_UNDEFINED_TYPE`（9002），退出码 1；
- 跨模块同名根：诊断 `ASNBERC_E_DUPLICATE_TYPE`（9003），退出码 1；
- 同一输入重复生成逐字节一致；不加 `--trim-schema` 时输出与既有规则一致。

## 9. 可复现性

相同输入与相同 asnberc 版本必须生成**逐字节相同**的输出。

保证措施：

- 不写入时间戳、绝对路径、随机数
- 字符串池按确定顺序排列
- 类型编号按源码顺序分配
- 表间填充字节固定为 `0x00`
- CRC32C 校验和覆盖整个文件

## 10. 文件结构

```
tools/asnberc/
├── CMakeLists.txt
└── src/
    ├── main.cpp              # CLI 入口
    ├── lexer.h/cpp           # 词法分析
    ├── parser.h/cpp          # 语法解析
    ├── ast.h                 # AST 结构定义
    ├── semantic.h/cpp        # 语义分析入口
    ├── semantic_types.cpp    # 类型解析
    ├── semantic_constraints.cpp  # 约束处理
    ├── semantic_values.cpp   # 值处理
    ├── semantic_defaults.cpp # 默认值编码
    ├── semantic_checks.cpp   # 结构检查
    ├── table.h/cpp           # 描述表生成
    ├── diag.h/cpp            # 诊断系统
    ├── crc32c.h/cpp          # CRC32C 校验和
    └── detail/
        ├── parser_internal.h
        └── semantic_internal.h
```

## 11. 依赖

- C++17 标准库
- 核心库的 `asnber_version.h`（版本信息）
- 无第三方依赖

## 12. 与核心库的契约

asnberc 与核心库通过 `docs/11-描述表格式.md` 定义的**二进制描述表格式**交互：

- asnberc 负责生成描述表
- 核心库通过 `asnber_schema_load()` 加载描述表
- 任何一方修改格式都必须先修订文档并提升 `format_version`

当前版本：`format_version = (1 << 16) | 0 = 0x00010000`
