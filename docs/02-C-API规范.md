# C API 设计规范

本文件定义对外 C ABI 的设计基线。签名在实现阶段落地为公共头文件；实现若需偏离，必须先修订本文件并补 ADR。

## 1. 设计原则

1. **唯一公共边界是 C ABI**。公共头文件使用 C99 语法，C 与 C++ 调用方完全等价。
2. **不透明句柄**。公共头文件只声明 `struct asnber_ctx;`、`struct asnber_doc;`、`struct asnber_node;` 等不完整类型，定义只存在于 `src/` 内部。
3. **不泄漏 C++**。公共头文件不得包含 `<string>`、`<vector>`、`<memory>` 等 C++ 头，不得出现模板、引用、类、`bool`（使用 `int`）、异常规格。
4. **错误码优先**。所有可能失败的操作返回 `asnber_err_t`；不使用 `errno` 作为主错误通道，不抛出异常。
5. **显式所有权**。谁创建、谁释放、借用引用何时失效，必须在函数注释中写明。
6. **可演进的结构体**。所有跨 ABI 的配置/信息结构体首字段为 `size_t struct_size`，调用方必须初始化为 `sizeof(...)`；预留字段必须置零。
7. **核心零领域知识**。核心公共头文件与符号不得出现 X.509、PKIX、CMS、PKCS、证书、密钥、签名算法等领域概念；标准结构由独立模块包提供。
8. **模块独立**。模块拥有自己的头文件、包名、符号前缀和版本，只依赖核心 ABI；核心头文件不包含模块头文件。

## 2. 命名约定

| 类别 | 规则 | 示例 |
| --- | --- | --- |
| 核心函数 | `asnber_` + 动作，全小写下划线 | `asnber_decode_buffer`、`asnber_schema_load` |
| 模块函数 | `asnber_<模块>_` + 动作 | `asnber_pkix_cert_get_subject`、`asnber_cms_content_type` |
| 核心不透明类型 | `asnber_` + 名词 + `_t` | `asnber_ctx_t`、`asnber_doc_t`、`asnber_schema_t` |
| 模块类型 | `asnber_<模块>_` + 名词 + `_t` | `asnber_pkix_cert_t` |
| 核心枚举值 | `ASNBER_` + 枚举组 + 值 | `ASNBER_ENCODING_DER`、`ASNBER_TAG_CONTEXT` |
| 模块枚举值 | `ASNBER_<模块>_` + 枚举组 + 值 | `ASNBER_PKIX_FIELD_SUBJECT` |
| 核心错误码 | `ASNBER_E_` + 分类 + 名称 | `ASNBER_E_TRUNCATED`、`ASNBER_E_NOMEM` |
| 模块错误码 | `ASNBER_<模块>_E_` + 名称 | `ASNBER_PKIX_E_FIELD_MISSING` |
| 导出宏 | 核心 `ASNBER_API`；模块 `ASNBER_<模块>_API` | `ASNBER_PKIX_API` |
| 预留接口 | 统一使用 `_reserved` 字段，不占用公共符号 | — |

禁止使用双下划线或下划线开头的标识符，避免与实现保留命名冲突。C++ 命名空间只用于内部实现：核心 `asnber`，模块 `asnber::pkix`、`asnber::cms`、`asnber::pkcs1`、`asnber::pkcs8`、`asnber::pkcs10`、`asnber::pkcs12`，门面包 `asnber::pkcs`。

## 3. 头文件组织

计划拆分（实现阶段落地）：

| 头文件 | 内容 |
| --- | --- |
| `asnber/asnber.h` | 伞头文件，按阶段收拢下列公共主题头 |
| `asnber/asnber_export.h` | `ASNBER_API` 导出宏；静态构建与静态消费时为空，Windows 共享消费时为 `dllimport` |
| `asnber/asnber_version.h` | 由 CMake 生成：版本宏、能力位、`asnber_version_info_t`、版本查询与自检函数 |
| `asnber/asnber_error.h` | `asnber_err_t`、错误码、`asnber_error_info_t` |
| `asnber/asnber_allocator.h` | 分配器 vtable、上下文配置 |
| `asnber/asnber_decode.h` | 解码选项、reader、文档生命周期 |
| `asnber/asnber_build.h` | runtime 构树：创建文档、创建节点、设置内容、封存 |
| `asnber/asnber_tag.h` | UNIVERSAL 标签号常量与 `ASNBER_PRIMITIVE` / `ASNBER_CONSTRUCTED` 编码形态常量 |
| `asnber/asnber_schema.h` | 模板：类型种类/标注方式/约束、描述表加载、运行时注册、schema 生命周期、schema 感知解码 |
| `asnber/asnber_node.h` | 只读节点访问与语义读取（含 BIT STRING、字符串、大整数、时间、OID、字段名） |
| `asnber/asnber_warning.h` | 告警结构、告警回调注册、计数/读取/重置 |
| `asnber/asnber_encode.h` | 编码选项（含 schema）、writer、输出缓冲 |

核心伞头 `asnber/asnber.h` 按阶段收拢：只包含当前已落地并冻结的公共主题头，不包含任何模块头文件。`asnber_schema.h` 与 `asnber_encode.h` 已加入伞头；不得以空声明占位。调用方可直接包含各主题头，不得依赖伞头覆盖上表全部文件。

模块头文件独立提供，例如：

| 头文件 | 所属包 | 符号前缀 |
| --- | --- | --- |
| `asnber/pkix/pkix.h` | `asnber-pkix` | `asnber_pkix_` / `ASNBER_PKIX_` |
| `asnber/cms/cms.h` | `asnber-cms` | `asnber_cms_` / `ASNBER_CMS_` |
| `asnber/pkcs1/pkcs1.h` | `asnber-pkcs1` | `asnber_pkcs_` / `ASNBER_PKCS1_` |
| `asnber/pkcs8/pkcs8.h` | `asnber-pkcs8` | `asnber_pkcs_` / `ASNBER_PKCS8_` |
| `asnber/pkcs10/pkcs10.h` | `asnber-pkcs10` | `asnber_pkcs_` / `ASNBER_PKCS10_` |
| `asnber/pkcs12/pkcs12.h` | `asnber-pkcs12` | `asnber_pkcs12_` / `ASNBER_PKCS12_` |
| `asnber/pkcs/pkcs.h` | `asnber-pkcs`（聚合包，不产库） | 无导出宏；聚合上述四个头文件 |

**PKCS 函数前缀（0.4.0 起）**：包拆分不改变函数名。PKCS#1/#8/#10 的函数仍为 `asnber_pkcs_*`（31/22/25），PKCS#12 仍为 `asnber_pkcs12_*`（37）；聚合包 `asnber-pkcs` 不产库、不导符号。导出/声明宏按包独立（`ASNBER_PKCS1_*`、`ASNBER_PKCS8_*`、`ASNBER_PKCS10_*`、`ASNBER_PKCS12_*`）。仓库中不存在 `asnber_pkcs1_*`、`asnber_pkcs8_*`、`asnber_pkcs10_*` 三组函数前缀（见 [ADR-0015](adr/0015-PKCS按标准拆分模块.md)）。

消费者通过 `find_package(asnber-pkix CONFIG REQUIRED)` 获取模块目标；模块包自动声明对 `asnber` 的依赖。公共头文件统一使用 `extern "C"` 包裹（仅 C++ 编译时生效），并使用传统 include guard。

## 4. 句柄与生命周期

```mermaid
flowchart LR
  C1["asnber_ctx_create"] --> C2["解码 / 编码调用"]
  C2 --> C3["asnber_doc_t 使用节点"]
  C3 --> C4["asnber_doc_destroy"]
  C4 --> C5["asnber_ctx_destroy"]
```

- `asnber_ctx_t`：一次创建，持有分配器、错误状态、资源上限与静态池。必须先于其创建的所有文档与 schema 销毁。
- `asnber_doc_t`：一次解码的结果，拥有节点树与 arena。销毁后所有 `asnber_node_t*` 立即失效。
- `asnber_node_t`：**借用引用**，不是独立对象，不能销毁，生命周期不超过所属文档。
- `asnber_schema_t`：模板类型树，可由描述表加载或运行时注册创建；封存后只读，可跨解码复用。schema 只需在解码调用期间有效；字段名复制到文档 arena，文档不保留 schema 指针。
- 句柄传入 `NULL` 时：`*_destroy` 为空操作；其他函数返回 `ASNBER_E_INVALID_ARG`。
- 同一句柄不得在多个线程中并发调用会写入状态的接口；详见第 9 节。

上下文销毁时若仍有文档未销毁，库不负责猜测调用方意图；文档契约要求“先销毁文档，再销毁上下文”。调试构建可对未销毁文档发出告警，但不改变所有权规则。

## 5. 基础类型与配置结构

```c
#include <stddef.h>
#include <stdint.h>

typedef struct asnber_ctx  asnber_ctx_t;
typedef struct asnber_doc  asnber_doc_t;
typedef struct asnber_node asnber_node_t;
typedef struct asnber_reader asnber_reader_t;
typedef struct asnber_writer asnber_writer_t;
typedef struct asnber_buf    asnber_buf_t;

typedef int32_t asnber_err_t;

typedef enum asnber_encoding {
    ASNBER_ENCODING_BER = 0,   /* 解码可接受；编码不单独提供 */
    ASNBER_ENCODING_DER = 1,   /* 解码严格模式；编码目标 */
    ASNBER_ENCODING_CER = 2,   /* 预留，基线不支持 */
    ASNBER_ENCODING_NONE = 3   /* 无源编码：runtime 构树文档 */
} asnber_encoding_t;

typedef enum asnber_type_kind {
    ASNBER_TYPE_KIND_SIMPLE = 0,      /* 单一基本类型，内容为原始值字节 */
    ASNBER_TYPE_KIND_SEQUENCE = 1,    /* 有序构造类型，字段按声明顺序 */
    ASNBER_TYPE_KIND_SET = 2,         /* 无序构造类型，字段按标签区分 */
    ASNBER_TYPE_KIND_CHOICE = 3,      /* 备选类型，无自身基本标签，按分支标签选择 */
    ASNBER_TYPE_KIND_SEQUENCE_OF = 4, /* 同构元素的有序集合，元素由 element_type_id 指定 */
    ASNBER_TYPE_KIND_SET_OF = 5,      /* 同构元素的无序集合，元素由 element_type_id 指定 */
    ASNBER_TYPE_KIND_ANY = 6          /* 开放类型：保留完整原始 TLV，不展开，不使用自身 tag */
} asnber_type_kind_t;

typedef enum asnber_tag_mode {
    ASNBER_TAG_MODE_DEFAULT = 0,  /* 继承模块级默认标注方式 */
    ASNBER_TAG_MODE_EXPLICIT = 1, /* 外层显式标签 */
    ASNBER_TAG_MODE_IMPLICIT = 2  /* 替换底层标签 */
} asnber_tag_mode_t;

typedef enum asnber_tag_class {
    ASNBER_TAG_UNIVERSAL = 0,
    ASNBER_TAG_APPLICATION = 1,
    ASNBER_TAG_CONTEXT = 2,
    ASNBER_TAG_PRIVATE = 3
} asnber_tag_class_t;

typedef enum asnber_encoding_form {
    ASNBER_FORM_PRIMITIVE = 0,    /* 源编码中的基本形式 */
    ASNBER_FORM_CONSTRUCTED = 1   /* 源编码中的构造形式（含 BER 构造字符串） */
} asnber_encoding_form_t;

typedef struct asnber_allocator {
    size_t struct_size;                 /* 必须为 sizeof(asnber_allocator_t) */
    void  *user;                        /* 原样回传给回调 */
    void *(*alloc)(void *user, size_t size);
    void *(*realloc)(void *user, void *ptr, size_t size);
    void  (*free)(void *user, void *ptr);
} asnber_allocator_t;

typedef struct asnber_ctx_config {
    size_t struct_size;                 /* 必须为 sizeof(asnber_ctx_config_t) */
    const asnber_allocator_t *allocator;  /* NULL 表示默认堆分配器 */
    void  *static_pool;                 /* 可选静态池起始地址 */
    size_t static_pool_size;            /* 0 表示不使用静态池 */
    uint32_t max_depth;                 /* 0 表示默认值 64 */
    uint32_t max_warnings;              /* 0 表示默认值 1024；达到上限后不再追加告警记录 */
    uint32_t reserved_flags;
    uint64_t max_nodes;                 /* 0 表示默认值 1,000,000 */
    uint64_t max_input_bytes;           /* 0 表示默认值 64 MiB */
    uint64_t max_output_bytes;          /* 0 表示默认值 256 MiB */
    uint32_t reserved[4];               /* 必须置零 */
} asnber_ctx_config_t;

typedef struct asnber_decode_options {
    size_t struct_size;                 /* 必须为 sizeof(asnber_decode_options_t) */
    asnber_encoding_t encoding;           /* BER（默认）或 DER */
    uint32_t flags;                     /* ASNBER_DECODE_* 位标志，见 5.1 */
    uint32_t max_depth;                 /* 0 表示用上下文默认；非 0 只能收紧 */
    uint32_t reserved[3];               /* 必须置零 */
} asnber_decode_options_t;

typedef struct asnber_schema asnber_schema_t;

typedef struct asnber_encode_options {
    size_t struct_size;                 /* 必须为 sizeof(asnber_encode_options_t) */
    asnber_encoding_t encoding;           /* 基线只接受 DER */
    const asnber_schema_t *schema;        /* NULL 表示无 schema 编码 */
    uint32_t flags;                     /* ASNBER_ENCODE_*，基线必须为 0 */
    uint32_t reserved[4];               /* 必须置零 */
} asnber_encode_options_t;

typedef struct asnber_schema_table {
    size_t struct_size;                 /* 必须为 sizeof(asnber_schema_table_t) */
    const void *data;                   /* 已编译描述表（C 数组或二进制资源） */
    size_t size;                        /* data 的字节数 */
    uint32_t format_version;            /* 调用方期望版本，必须与头部完全相等 */
    uint32_t reserved;                  /* 必须置零 */
} asnber_schema_table_t;

typedef struct asnber_bound {
    size_t struct_size;                 /* 必须为 sizeof(asnber_bound_t) */
    int32_t is_unbounded;               /* 1 表示 MAX/无界，忽略 value/decimal */
    int32_t reserved;                   /* 必须置零 */
    int64_t value;                      /* 小整数边界；SIZE 时表示字节数 */
    const char *decimal;                /* 大整数边界，十进制文本；无则 NULL */
    size_t decimal_size;
} asnber_bound_t;

typedef enum asnber_constraint_kind {
    ASNBER_CONSTRAINT_RANGE = 0,          /* 值域上下界，含大整数边界 */
    ASNBER_CONSTRAINT_SIZE = 1,           /* SIZE 约束，单位为字节/元素数 */
    ASNBER_CONSTRAINT_ENUM = 2,           /* 枚举取值集合 */
    ASNBER_CONSTRAINT_MAX = 3,            /* 无界上限 */
    ASNBER_CONSTRAINT_BIGINT_RANGE = 4    /* 明确使用十进制大整数边界 */
} asnber_constraint_kind_t;

typedef struct asnber_constraint {
    size_t struct_size;                 /* 必须为 sizeof(asnber_constraint_t) */
    asnber_constraint_kind_t kind;
    uint32_t flags;                     /* 必须为 0 */
    asnber_bound_t lower;
    asnber_bound_t upper;
    const int64_t *enum_values;         /* kind == ENUM 时有效 */
    uint32_t enum_count;
    uint32_t reserved[2];               /* 必须置零 */
} asnber_constraint_t;

typedef struct asnber_type_desc {
    size_t struct_size;                 /* 必须为 sizeof(asnber_type_desc_t) */
    const char *name;                   /* 类型名，最长由实现定义 */
    asnber_type_kind_t kind;              /* 类型种类，构造性由它派生 */
    asnber_tag_class_t tag_class;         /* CHOICE 在 DEFAULT 时必须为 UNIVERSAL；EXPLICIT 时为外层标签类 */
    uint32_t tag_number;                /* CHOICE 在 DEFAULT 时必须为 0；EXPLICIT 时为外层标签号 */
    asnber_tag_mode_t tag_mode;           /* DEFAULT 继承模块级默认标注方式 */
    uint32_t element_type_id;           /* 0 = 无元素类型；仅 SEQUENCE_OF/SET_OF 使用 1..type_count */
    uint32_t flags;                     /* ASNBER_TYPE_*，见 5.2 */
    const asnber_constraint_t *constraints;
    uint32_t constraint_count;
    uint32_t reserved[2];               /* 必须置零 */
} asnber_type_desc_t;

typedef struct asnber_field_desc {
    size_t struct_size;                 /* 必须为 sizeof(asnber_field_desc_t) */
    const char *name;                   /* 字段名 */
    uint32_t type_id;                   /* asnber_schema_add_type 返回的类型编号；有效值从 1 开始，0 无效 */
    uint32_t flags;                     /* ASNBER_FIELD_OPTIONAL / ASNBER_FIELD_EXTENSION */
    const void *default_value;          /* 规范 DER TLV 字节，可为 NULL */
    size_t default_value_size;          /* default_value 的字节数；非 0 即表示有 DEFAULT */
    const asnber_constraint_t *field_constraints; /* 可选字段级约束 */
    uint32_t field_constraint_count;
    uint32_t reserved[2];               /* 必须置零 */
} asnber_field_desc_t;

typedef struct asnber_time {
    size_t struct_size;                 /* 必须为 sizeof(asnber_time_t) */
    int32_t year;
    uint8_t month;
    uint8_t day;
    uint8_t hour;
    uint8_t minute;
    uint8_t second;
    uint8_t reserved_flags;
    int16_t utc_offset_minutes;         /* 仅 HAS_OFFSET 时有效；Z 与 LOCAL 时为 0 */
    uint32_t nanosecond;                /* 0..999,999,999；仅 FRACTIONAL 时有效 */
    uint32_t flags;                     /* ASNBER_TIME_*，见 5.3 */
} asnber_time_t;

typedef struct asnber_version_info {
    size_t struct_size;                 /* 输入：必须为 sizeof(asnber_version_info_t) */
    uint32_t major;                     /* 实际链接库的主版本 */
    uint32_t minor;
    uint32_t patch;
    uint32_t reserved;                  /* 必须置零 */
    const char *string;                 /* 静态存储，随库生命周期有效，永不释放 */
    uint64_t capabilities;              /* ASNBER_CAP_* 位集合，见 6.5 */
} asnber_version_info_t;

typedef struct asnber_warning {
    size_t struct_size;                 /* 输入：必须为 sizeof(asnber_warning_t) */
    asnber_err_t code;                    /* 告警类错误码（稳定） */
    size_t offset;                      /* 输入字节偏移；无意义时为 SIZE_MAX */
    uint32_t depth;                     /* 嵌套深度；无意义时为 0 */
    const char *field_name;             /* schema 字段名；无则为 NULL；上下文持有，直到下一次解码或上下文销毁 */
    const char *message;                /* 上下文持有的英文短消息；生命周期与 field_name 相同 */
} asnber_warning_t;
```

约定：

- 所有 `*_init` 函数把结构体清零并写入正确的 `struct_size` 与默认值；调用方不得手工猜测默认值。
- `struct_size` 错误或未识别的非零预留字段返回 `ASNBER_E_INVALID_CONFIG`，避免未来语义被静默误用。
- 枚举在 ABI 中是 `int` 大小；不得随意重排既有枚举值。
- 描述表与运行时注册产生的约束、默认值与名称由调用方保证在注册/加载调用期间有效；加载完成后复制进 schema 对象（上下文级分配）。
- 公共头文件不出现 schema 级的构造布尔字段，也不出现旧的 OF/CHOICE/DEFAULT 标志位；构造性与 OF/CHOICE 语义只由 `kind` 表达，DEFAULT 只由 `default_value_size != 0` 派生。运行期 `asnber_node_create` 的 `constructed` 形参只描述输出编码形态，不属于 schema。

### 5.1 解码选项与位标志

`asnber_decode_options_init` 清零并设置 `encoding = ASNBER_ENCODING_BER`、`flags = 0`、`max_depth = 0`。`flags = 0` 的默认行为：**借用输入、按 BER、未知字段静默保留、尾随数据拒绝**。

| 标志 | 值 | 含义 | 默认 |
| --- | --- | --- | --- |
| `ASNBER_DECODE_COPY_INPUT` | `1u << 0` | 解码时把输入复制进文档 arena；文档不再借用调用方缓冲区 | 关闭 |
| `ASNBER_DECODE_STRICT_SCHEMA` | `1u << 1` | schema 解码遇到未知字段立即失败（`ASNBER_E_SCHEMA_FIELD`） | 关闭 |
| `ASNBER_DECODE_WARN_UNKNOWN_FIELD` | `1u << 2` | schema 解码遇到未知字段时保留并产生告警 | 关闭 |
| `ASNBER_DECODE_ALLOW_TRAILING` | `1u << 3` | 允许顶层 TLV 之后存在未消费字节 | 关闭 |

规则：

- `STRICT_SCHEMA` 与 `WARN_UNKNOWN_FIELD` 同时设置时**严格优先**：未知字段返回错误，不产生告警。
- `COPY_INPUT` 与 reader 数据源同时使用时**按忽略处理**：reader 的数据本来就会复制进 arena，没有可借用的调用方缓冲区；不因此报错。
- `max_depth` 为 0 时使用上下文默认；非 0 时只能小于或等于上下文默认，否则返回 `ASNBER_E_INVALID_CONFIG`，不允许借解码选项放宽。
- 未设置 `ALLOW_TRAILING` 时，顶层 TLV 后仍有字节返回 `ASNBER_E_TRAILING_DATA`；设置后允许尾随，剩余字节由 `consumed` 计算。
- `options == NULL` 对全部带 `const asnber_decode_options_t *options` 的接口（`asnber_decode_buffer`、`asnber_decode_reader`、`asnber_decode_buffer_with_schema`、`asnber_decode_reader_with_schema`、`asnber_doc_validate`）等同于传入默认选项：**借用输入、BER、未知字段静默保留、尾随数据拒绝、不启用 schema 严格校验**（`flags = 0`、`max_depth = 0`）。与 `asnber_encode_*` 的 `options == NULL` 写法对齐。
- 选项结构中任何未定义标志位、非零 `reserved` 字段或大于上下文默认值的 `max_depth` 返回 `ASNBER_E_INVALID_CONFIG`；解码时 `encoding` 为 `ASNBER_ENCODING_NONE`、`ASNBER_ENCODING_CER` 或未知值返回 `ASNBER_E_UNSUPPORTED_ENCODING`（本轮接受 `BER` 与 `DER`）。
- 未提供 schema 的 `asnber_decode_buffer` / `asnber_decode_reader` 设置 `STRICT_SCHEMA` 返回 `ASNBER_E_INVALID_ARG`；`WARN_UNKNOWN_FIELD` 在无 schema 时被忽略（无字段可告警）。
- 当前解码实现边界：多字节 tag number 已支持（DER 下额外校验最短形式）。BER 支持不定长，可嵌套，内容以匹配的 EOC（`00 00`）结束，`asnber_node_tlv` 的长度包含 EOC，`asnber_node_is_indefinite` 置位。DER 遇不定长，或在定长构造内容中出现 EOC，返回 `ASNBER_E_INDEFINITE_NOT_ALLOWED`；顶层裸 EOC（UNIVERSAL 0）在 BER/DER 下均返回 `ASNBER_E_MALFORMED_TAG`。`encoding = DER` 的其余规范化校验见 §5.3 与 §9。

### 5.2 类型种类、标注方式与字段标志

类型种类取值：

| 种类 | 含义 | 构造性 | 标签 |
| --- | --- | --- | --- |
| `ASNBER_TYPE_KIND_SIMPLE` | 单一基本类型，内容按标签解释 | 非构造 | 使用 `tag_class/tag_number/tag_mode`；`UNIVERSAL` 下 `tag_number` 必须大于 0，`CONTEXT/APPLICATION/PRIVATE` 下 `tag_number = 0` 合法 |
| `ASNBER_TYPE_KIND_SEQUENCE` | 有序字段集合 | 构造 | 使用自身标签或默认 UNIVERSAL SEQUENCE |
| `ASNBER_TYPE_KIND_SET` | 无序字段集合 | 构造 | 使用自身标签或默认 UNIVERSAL SET |
| `ASNBER_TYPE_KIND_CHOICE` | 备选分支，按分支标签选择 | 由选中分支决定 | `DEFAULT`：无自身基本标签，`tag_class = ASNBER_TAG_UNIVERSAL`、`tag_number = 0`；`EXPLICIT`：允许非 UNIVERSAL 的 `tag_class/tag_number` 作为外层显式包装；`IMPLICIT` 非法 |
| `ASNBER_TYPE_KIND_SEQUENCE_OF` | 元素有序集合 | 构造 | `element_type_id` 指向元素类型，有效值从 1 开始；元素类型可为 ANY |
| `ASNBER_TYPE_KIND_SET_OF` | 元素无序集合 | 构造 | `element_type_id` 指向元素类型，有效值从 1 开始；元素类型可为 ANY；DER 要求按元素完整 TLV 规范排序 |
| `ASNBER_TYPE_KIND_ANY` | 开放类型，保留一个完整 TLV | 由 schema 决定 | 无包装：`tag_class = ASNBER_TAG_UNIVERSAL`、`tag_number = 0`、`tag_mode = DEFAULT`；外层包装：`tag_mode = EXPLICIT` + 非 UNIVERSAL 的 `tag_class/tag_number`；`element_type_id = 0` |

规则：

- 类型编号由 `asnber_schema_add_type` 从 1 开始连续分配；`0` 表示无效引用，`type_id`/`parent_type_id` 不得为 0，最大有效编号等于已注册类型数。
- `element_type_id` 仅对 `SEQUENCE_OF`/`SET_OF` 有效，必须为 `1..type_count`；其他种类必须为 0；越界或引用未注册类型返回 `ASNBER_E_SCHEMA_TYPE`。
- `tag_mode = DEFAULT` 继承描述表头部的模块默认标注方式；`EXPLICIT`/`IMPLICIT` 只表示类型级显式覆盖。
- `CHOICE` + `IMPLICIT` 视为 `kind` 与 `tag_mode` 冲突，加载失败并返回 `ASNBER_E_SCHEMA_TYPE`。
- `CHOICE` + `DEFAULT` 必须 `tag_class = ASNBER_TAG_UNIVERSAL`、`tag_number = 0`；模块默认标注即使是 `IMPLICIT`，也不作用于 `CHOICE` 类型本身；否则冲突。
- `CHOICE` + `EXPLICIT` 允许携带非 UNIVERSAL 的 `tag_class/tag_number` 作为外层包装；缺少有效非 UNIVERSAL 标签则冲突。
- `SIMPLE` 使用 `IMPLICIT` 且 `tag_class = ASNBER_TAG_UNIVERSAL`、`tag_number = 0` 时冲突；`CONTEXT/APPLICATION/PRIVATE` 下 `tag_number = 0` 合法（例如 PKIX 的 `[0] IMPLICIT`）。`SEQUENCE` 使用 `IMPLICIT` 但没有可用标签等组合同样加载失败。
- `ANY` 允许两种形态：无包装（`tag_class = ASNBER_TAG_UNIVERSAL`、`tag_number = 0`、`tag_mode = DEFAULT`）或非 UNIVERSAL 标签的显式外层包装（`tag_mode = EXPLICIT`）。`tag_mode = IMPLICIT` 对 ANY 无意义，返回 `ASNBER_E_SCHEMA_TYPE`；`tag_mode = DEFAULT` 且标签非 `UNIVERSAL 0`、或 `EXPLICIT` 且标签为 UNIVERSAL 同样返回 `ASNBER_E_SCHEMA_TYPE`。ANY 不得挂类型级约束（`ASNBER_E_SCHEMA_TYPE`），不得挂字段（`ASNBER_E_SCHEMA_FIELD`）；`element_type_id` 必须为 0，但 ANY 可以作为 `SEQUENCE_OF`/`SET_OF` 的元素类型来源（即 OF 类型自身的 `element_type_id` 指向 ANY 类型）。
- 构造性由 `kind` 派生，不存在独立布尔字段。

`[0] EXPLICIT CHOICE` 的建模示例：

```text
ExampleChoice ::= CHOICE { intValue INTEGER, textValue UTF8String }
WrappedChoice ::= [0] EXPLICIT ExampleChoice
```

运行时注册 `WrappedChoice` 时，`kind = ASNBER_TYPE_KIND_CHOICE`、`tag_mode = ASNBER_TAG_MODE_EXPLICIT`、`tag_class = ASNBER_TAG_CONTEXT`、`tag_number = 0`、`element_type_id = 0`；解码先剥离 `[0]` 外层显式包装，再按分支标签选择。

位标志：

| 标志 | 值 | 含义 |
| --- | --- | --- |
| `ASNBER_TYPE_EXTENSIBLE` | `1u << 0` | 类型含扩展标记 `...`；未知扩展字段在非严格校验下可保留 |
| `ASNBER_FIELD_OPTIONAL` | `1u << 0` | 字段可选 |
| `ASNBER_FIELD_EXTENSION` | `1u << 1` | 字段位于扩展标记之后 |

旧的构造/OF/CHOICE/DEFAULT 标志位均已删除，不再保留兼容别名；构造性由 `kind` 派生，DEFAULT 由 `default_value_size != 0` 派生。

### 5.3 时间标志

| 标志 | 值 | 含义 |
| --- | --- | --- |
| `ASNBER_TIME_UTC` | `1u << 0` | UTCTime；两位年份窗口固定 1950–2049 |
| `ASNBER_TIME_GENERALIZED` | `1u << 1` | GeneralizedTime |
| `ASNBER_TIME_HAS_OFFSET` | `1u << 2` | 含显式 `±hhmm`（含 `+00:00`）；与 `LOCAL` 互斥 |
| `ASNBER_TIME_FRACTIONAL` | `1u << 3` | `nanosecond` 有效 |
| `ASNBER_TIME_LOCAL` | `1u << 4` | 本地时间、无偏移；与 `HAS_OFFSET` 互斥，仅 BER 接受 |

规则：时间有三态——`HAS_OFFSET` 表示显式偏移，`LOCAL` 表示本地时间且无偏移，两者都不置位表示 `Z`。`HAS_OFFSET` 与 `LOCAL` 同时置位返回 `ASNBER_E_INVALID_VALUE`；`LOCAL` 时 `utc_offset_minutes` 必须为 0。`nanosecond` 范围 0–999,999,999。**BER** 接受 `±hhmm`（含 `+0000`/`-0000`，范围 `-14:00` 至 `+14:00`）与本地时间形式，本地时间按 `LOCAL` 解析；**DER** 只接受 `Z`，拒绝任何 `±hhmm`（包括 `+0000`/`-0000`）、本地时间与闰秒（`second = 60`），GeneralizedTime 小数只接受 `.`（拒绝 `,`）且禁止冗余尾零；非规范形式返回 `ASNBER_E_NON_CANONICAL`。

### 5.4 约束与默认值

- 约束挂在**类型**上：每个带约束的子类型是独立 type 条目；字段只引用 `type_id`，并可附加少量字段级约束（`field_constraints`）。
- 同一类型允许多条约束，按 `constraint_count` 依次校验；范围、SIZE、枚举、MAX/无界、大整数边界分别由 `kind` 表达。
- 范围/SIZE 使用 `lower`/`upper`；`is_unbounded = 1` 表示 `MAX`/无界；大整数边界用 `decimal` + `decimal_size` 的十进制文本。
- 扩展标记由 `ASNBER_TYPE_EXTENSIBLE` 表示：非严格校验下允许扩展字段保留；严格校验下未知扩展字段按未知字段规则处理。
- `default_value` 必须是**可规范化的 DER TLV 字节**（含标签与长度），`asnber_schema_add_field` 时复制进 schema。`default_value` 为 `NULL` 且 `default_value_size = 0` 表示无 DEFAULT；`default_value_size != 0` 但 `default_value` 为 `NULL`、解析失败或重新编码后与原始字节不一致时返回 `ASNBER_E_SCHEMA_DEFAULT`。
- `default_value` 只用于 schema 感知编码的 DEFAULT 省略与解码比对；不改变节点内容的所有权。

### 5.5 选项初始化

`asnber_ctx_config_init`、`asnber_decode_options_init`、`asnber_encode_options_init` 均把结构体清零并写入 `struct_size = sizeof(...)`，调用方随后只覆盖需要的字段。`asnber_encode_options_init` 的默认结果为 `encoding = ASNBER_ENCODING_DER`、`schema = NULL`、`flags = 0`；`asnber_ctx_config_init` 的预算字段保持 0，表示使用第 9 节的默认值（含 `max_warnings = 1024`）。

### 5.6 ANY / 开放类型节点语义

- `ASNBER_TYPE_KIND_ANY`（描述表 `kind = 6`）表示一个不透明的开放类型。无包装形态解码时消费**恰好一个完整 TLV**，保留原始 tag/len/content 字节，不做结构化展开，也不为构造型 ANY 建立子节点。
- **外层包装形态**（`tag_mode = EXPLICIT` + 非 UNIVERSAL 标签）把 ANY 节点建模为外层包装节点：`asnber_node_tlv` 返回**外层完整 TLV**，`asnber_node_content` 返回**内层原始 TLV**（不是内层的 content），`asnber_node_child_count` 恒为 0，`asnber_node_child_at`/`asnber_node_child_by_name` 恒返回 `NULL`。解码要求外层为构造型且恰好包含一个内层 TLV，否则返回 `ASNBER_E_SCHEMA_TYPE`。
- 无包装形态下，`asnber_node_tlv` 返回**原始完整 TLV**（含 tag 与 length，BER 不定长时含结尾 EOC），长度与源字节一致；`asnber_node_content` 返回**原始内容字节**（不含 tag/len），构造型 ANY 同样返回该切片。这与普通构造节点的 `ASNBER_E_INVALID_STATE` 行为不同。空内容（例如 `NULL` 的 `05 00`）允许 `*out_size = 0`。
- `asnber_node_parent` 仍返回其父节点，`asnber_node_encoding_form`、`asnber_node_is_indefinite` 反映外层（无包装时为自身）TLV 的形态。
- ANY 节点不可改写：`asnber_doc_set_node_content` 对 ANY 返回 `ASNBER_E_INVALID_STATE`。
- 编码：无 schema 的通用编码器按节点保存的 TLV 原样写回（此时节点 TLV 已是含包装的完整形态，不重复加包装）；schema 感知编码对 EXPLICIT ANY 按 schema 重新加外层包装，对无包装 ANY 写回原始 TLV。**schema 感知 DER 编码要求这些保留 TLV 是规范 DER**：BER 不定长、非最短长度、长形式标签表示小 tag number、构造字符串、非规范基本值、未排序 `SET`/`SET OF` 等返回 `ASNBER_E_NON_CANONICAL`，不做隐式重新编码；无 schema 通用编码路径仍允许 BER 源原样往返。若节点缺少可用原始 TLV（例如既不是解码节点、也不是 ANY 节点的 runtime 构树节点），编码返回 `ASNBER_E_INVALID_STATE`。该错误码是“保留 TLV 与节点状态不一致”的唯一约定值。
- **runtime 构树 ANY**：`asnber_node_create_any` 接受的原始 TLV 复制进文档 arena 并挂在节点上，因此 `asnber_node_tlv` 对这类节点同样返回完整 TLV，`asnber_node_content` 返回内容切片。其编码行为与解码得到的 ANY 一致：无 schema 通用编码逐字节写回；schema 感知编码按同一套 `ASNBER_E_NON_CANONICAL` 规则校验保留 TLV。ANY 节点不建立子节点，`asnber_node_create` 以其为父节点返回 `ASNBER_E_INVALID_STATE`。
- **资源上限与错误分类**：schema 感知 DER 编码校验保留 TLV 时复用上下文 `max_depth`（编码器内部直接使用 `ctx->m_maxDepth`）；`asnber_doc_validate` 的 `max_depth` 只约束 schema 绑定深度，不遍历 ANY 内层。ANY 内层 TLV 嵌套超过上下文 `max_depth`（默认 64）返回 `ASNBER_E_DEPTH_LIMIT`；节点数、输入字节数、内存预算超限分别返回 `ASNBER_E_NODE_LIMIT`、`ASNBER_E_INPUT_LIMIT`、`ASNBER_E_MEMORY_LIMIT`/`ASNBER_E_STATIC_POOL_EXHAUSTED`。这些资源类失败**不是**“非规范 DER”，不会改写为 `ASNBER_E_NON_CANONICAL`。回归用例见 `tests/c_api/test_build_any.c` 第 7b 节：70 层嵌套 ANY 编码返回 `ASNBER_E_DEPTH_LIMIT`，3 层成功。

**SEQUENCE 中的消歧规则（封存期强制）**

- ANY 字段**不承诺标签**，因此不参与字段标签唯一性判定，也不作为后续 OPTIONAL/DEFAULT 字段的“后继标签”。SEQUENCE 内标签冲突检查跳过 ANY 字段。
- `tag_mode = DEFAULT` 的 ANY 字段（无自身标签）**必须是所在 SEQUENCE 的最后一个字段**；否则 `asnber_schema_seal` 返回 `ASNBER_E_SCHEMA_TYPE`。
- `tag_mode = EXPLICIT` 的 ANY 字段有外层标签，位置不受“必须末位”限制，但其外层标签仍须满足 SEQUENCE 标签唯一性（重复则 `ASNBER_E_SCHEMA_TYPE`）。
- SET 依靠标签识别字段，无标签的 ANY 无法判定归属：SET 中不得出现 `tag_mode = DEFAULT` 的 ANY 字段，`asnber_schema_seal` 返回 `ASNBER_E_SCHEMA_TYPE`。SET 中的 EXPLICIT ANY 仍可用，并以外层标签参与唯一性判定。

**SET OF ANY**

- `SET OF ANY`（例如 `AttributeSet.values ::= SET SIZE (1..MAX) OF ANY`）允许注册：OF 类型的 `element_type_id` 指向 `kind = ANY` 的类型。解码为异构元素列表，每个元素都是独立的 ANY 节点（不展开）；编码按 DER SET OF 规则对元素完整 TLV 排序后写回。

## 6. 函数清单（设计基线）

模块 API 已拆为独立页：[asnber-pkix](02a-模块API-pkix.md)、[asnber-pkcs](02b-模块API-pkcs.md)、[asnber-cms](02c-模块API-cms.md)；下文 6.8–6.18 只保留索引。

```c
/* 版本与能力 */
ASNBER_API asnber_err_t asnber_version(asnber_version_info_t *out_info);
ASNBER_API asnber_err_t asnber_version_check(uint32_t expected_major,
                                       uint32_t expected_minor);
ASNBER_API int        asnber_has_capability(uint64_t capability);

/* 上下文与错误 */
ASNBER_API void       asnber_ctx_config_init(asnber_ctx_config_t *config);
ASNBER_API asnber_err_t asnber_ctx_size_for_config(const asnber_ctx_config_t *config,
                                             size_t *out_size);
ASNBER_API asnber_err_t asnber_ctx_create(const asnber_ctx_config_t *config,
                                    asnber_ctx_t **out_ctx);
ASNBER_API void       asnber_ctx_destroy(asnber_ctx_t *ctx);
ASNBER_API asnber_err_t asnber_ctx_get_error(const asnber_ctx_t *ctx,
                                       asnber_error_info_t *out_info);
ASNBER_API void       asnber_ctx_clear_error(asnber_ctx_t *ctx);

/* 告警 */
typedef void (*asnber_warning_fn)(void *user,
                                const asnber_warning_t *warning);
ASNBER_API asnber_err_t asnber_ctx_set_warning_handler(asnber_ctx_t *ctx,
                                                 asnber_warning_fn handler,
                                                 void *user);
ASNBER_API size_t     asnber_ctx_warning_count(const asnber_ctx_t *ctx);
ASNBER_API asnber_err_t asnber_ctx_get_warning(const asnber_ctx_t *ctx,
                                         size_t index,
                                         asnber_warning_t *out_warning);
ASNBER_API void       asnber_ctx_clear_warnings(asnber_ctx_t *ctx);

/* 解码 */
ASNBER_API void       asnber_decode_options_init(asnber_decode_options_t *options);
ASNBER_API asnber_err_t asnber_decode_buffer(asnber_ctx_t *ctx,
                                       const uint8_t *data, size_t size,
                                       const asnber_decode_options_t *options,
                                       asnber_doc_t **out_doc,
                                       size_t *consumed);
ASNBER_API asnber_err_t asnber_decode_reader(asnber_ctx_t *ctx,
                                       const asnber_reader_t *reader,
                                       const asnber_decode_options_t *options,
                                       asnber_doc_t **out_doc,
                                       size_t *consumed);
ASNBER_API void       asnber_doc_destroy(asnber_doc_t *doc);

/* 增量 feed 解码器（push 模式） */
typedef struct asnber_decoder asnber_decoder_t;
ASNBER_API asnber_decoder_t *asnber_decoder_create(
    asnber_ctx_t *ctx, const asnber_decode_options_t *options);
ASNBER_API void           asnber_decoder_destroy(asnber_decoder_t *decoder);
ASNBER_API asnber_err_t     asnber_decoder_feed(asnber_ctx_t *ctx,
                                          asnber_decoder_t *decoder,
                                          const uint8_t *data, size_t size);
ASNBER_API asnber_err_t     asnber_decoder_finalize(asnber_ctx_t *ctx,
                                              asnber_decoder_t *decoder,
                                              asnber_doc_t **out_doc,
                                              size_t *consumed);

/* 模板机制：描述表加载与运行时注册共用同一类型树 */
ASNBER_API asnber_err_t asnber_schema_create(asnber_ctx_t *ctx,
                                       asnber_tag_mode_t default_tag_mode,
                                       asnber_schema_t **out_schema);
ASNBER_API asnber_err_t asnber_schema_load(asnber_ctx_t *ctx,
                                     const asnber_schema_table_t *table,
                                     asnber_schema_t **out_schema);
ASNBER_API asnber_err_t asnber_schema_load_with_root(
                                        asnber_ctx_t *ctx,
                                        const asnber_schema_table_t *table,
                                        uint32_t root_type_id,
                                        asnber_schema_t **out_schema);
ASNBER_API asnber_err_t asnber_schema_add_type(asnber_schema_t *schema,
                                         const asnber_type_desc_t *desc,
                                         uint32_t *out_type_id);
ASNBER_API asnber_err_t asnber_schema_add_field(asnber_schema_t *schema,
                                          uint32_t parent_type_id,
                                          const asnber_field_desc_t *desc);

typedef struct asnber_schema_name_info {
    uint32_t struct_size;   /* 必须为 sizeof(asnber_schema_name_info_t) */
    uint32_t type_id;
    uint32_t kind;          /* ASNBER_SCHEMA_NAME_KIND_BIT / _NUMBER */
    uint32_t flags;         /* ASNBER_SCHEMA_NAME_FLAG_EXTENSION */
    int64_t value;
    const char *name;       /* 借用，schema 存活期间有效 */
} asnber_schema_name_info_t;

#define ASNBER_SCHEMA_NAME_KIND_BIT 0u
#define ASNBER_SCHEMA_NAME_KIND_NUMBER 1u
#define ASNBER_SCHEMA_NAME_FLAG_EXTENSION 1u

ASNBER_API asnber_err_t asnber_schema_name_count(const asnber_schema_t *schema,
                                           uint32_t type_id,
                                           uint32_t *out_count);
ASNBER_API asnber_err_t asnber_schema_name_at(const asnber_schema_t *schema,
                                        uint32_t type_id, uint32_t index,
                                        asnber_schema_name_info_t *out_info);
ASNBER_API asnber_err_t asnber_schema_name_for_bit(const asnber_schema_t *schema,
                                             uint32_t type_id, uint32_t bit,
                                             const char **out_name);
ASNBER_API asnber_err_t asnber_schema_name_for_value(const asnber_schema_t *schema,
                                               uint32_t type_id, int64_t value,
                                               const char **out_name);
ASNBER_API asnber_err_t asnber_schema_value_for_name(const asnber_schema_t *schema,
                                               uint32_t type_id,
                                               const char *name,
                                               int64_t *out_value,
                                               int *out_found);

ASNBER_API asnber_err_t asnber_schema_set_root(asnber_schema_t *schema,
                                         uint32_t root_type_id);
ASNBER_API asnber_err_t asnber_schema_seal(asnber_schema_t *schema);
ASNBER_API void       asnber_schema_destroy(asnber_schema_t *schema);

ASNBER_API asnber_err_t asnber_decode_buffer_with_schema(
                                        asnber_ctx_t *ctx,
                                        const uint8_t *data, size_t size,
                                        const asnber_schema_t *schema,
                                        const asnber_decode_options_t *options,
                                        asnber_doc_t **out_doc,
                                        size_t *consumed);
ASNBER_API asnber_err_t asnber_decode_reader_with_schema(
                                        asnber_ctx_t *ctx,
                                        const asnber_reader_t *reader,
                                        const asnber_schema_t *schema,
                                        const asnber_decode_options_t *options,
                                        asnber_doc_t **out_doc,
                                        size_t *consumed);
ASNBER_API asnber_err_t asnber_doc_validate(asnber_ctx_t *ctx,
                                      const asnber_doc_t *doc,
                                      const asnber_schema_t *schema,
                                      const asnber_decode_options_t *options);

/* runtime 构树（主线能力） */
ASNBER_API asnber_err_t asnber_doc_create(asnber_ctx_t *ctx, asnber_doc_t **out_doc);
ASNBER_API asnber_err_t asnber_doc_seal(asnber_doc_t *doc);
ASNBER_API asnber_err_t asnber_node_create(asnber_doc_t *doc,
                                     asnber_node_t *parent,
                                     asnber_tag_class_t tag_class,
                                     uint32_t tag_number,
                                     int constructed,
                                     asnber_node_t **out_node);
ASNBER_API asnber_err_t asnber_node_create_any(asnber_doc_t *doc,
                                        asnber_node_t *parent,
                                        const uint8_t *tlv, size_t tlv_size,
                                        asnber_node_t **out_node);
ASNBER_API asnber_err_t asnber_node_set_content(asnber_node_t *node,
                                          const uint8_t *data, size_t size);
ASNBER_API asnber_err_t asnber_node_set_bool(asnber_node_t *node, int value);
ASNBER_API asnber_err_t asnber_node_set_int64(asnber_node_t *node, int64_t value);
ASNBER_API asnber_err_t asnber_node_set_oid(asnber_node_t *node, const char *dotted);
ASNBER_API asnber_err_t asnber_node_set_utf8(asnber_node_t *node,
                                       const char *text, size_t size);

/* 文档与节点只读访问 */
ASNBER_API const asnber_node_t   *asnber_doc_root(const asnber_doc_t *doc);
ASNBER_API asnber_encoding_t      asnber_doc_source_encoding(const asnber_doc_t *doc);
ASNBER_API asnber_tag_class_t     asnber_node_tag_class(const asnber_node_t *node);
ASNBER_API uint32_t             asnber_node_tag_number(const asnber_node_t *node);
ASNBER_API asnber_encoding_form_t asnber_node_encoding_form(const asnber_node_t *node);
ASNBER_API int                  asnber_node_is_indefinite(const asnber_node_t *node);
ASNBER_API size_t               asnber_node_child_count(const asnber_node_t *node);
ASNBER_API const asnber_node_t   *asnber_node_child_at(const asnber_node_t *node,
                                                 size_t index);
ASNBER_API const asnber_node_t   *asnber_node_child_by_name(const asnber_node_t *node,
                                                      const char *field_name);
ASNBER_API const char          *asnber_node_field_name(const asnber_node_t *node);
ASNBER_API const asnber_node_t   *asnber_node_parent(const asnber_node_t *node);
ASNBER_API asnber_err_t asnber_node_content(const asnber_node_t *node,
                                      const uint8_t **out_data,
                                      size_t *out_size);
ASNBER_API const uint8_t       *asnber_node_tlv(const asnber_node_t *node,
                                            size_t *out_size);
ASNBER_API size_t               asnber_node_offset(const asnber_node_t *node);

/* 语义读取（失败返回错误码，不写部分输出） */
ASNBER_API asnber_err_t asnber_node_get_bool(const asnber_node_t *node, int *out_value);
ASNBER_API asnber_err_t asnber_node_get_int64(const asnber_node_t *node, int64_t *out_value);
ASNBER_API asnber_err_t asnber_node_get_octets(const asnber_node_t *node,
                                         const uint8_t **out_data,
                                         size_t *out_size);
ASNBER_API asnber_err_t asnber_node_get_oid(const asnber_node_t *node,
                                      const char **out_dotted,
                                      size_t *out_size);
ASNBER_API asnber_err_t asnber_node_get_bits(const asnber_node_t *node,
                                       const uint8_t **out_data,
                                       size_t *out_size,
                                       size_t *out_bit_length,
                                       uint8_t *out_unused_bits);
ASNBER_API asnber_err_t asnber_node_get_raw_string(const asnber_node_t *node,
                                             const uint8_t **out_data,
                                             size_t *out_size);
ASNBER_API asnber_err_t asnber_node_get_utf8(const asnber_node_t *node,
                                       const char **out_text,
                                       size_t *out_size);
ASNBER_API asnber_err_t asnber_node_get_bigint_decimal(const asnber_node_t *node,
                                                 const char **out_text,
                                                 size_t *out_size);
ASNBER_API asnber_err_t asnber_node_get_time(const asnber_node_t *node,
                                       asnber_time_t *out_time);

/* 编码 */
ASNBER_API void       asnber_encode_options_init(asnber_encode_options_t *options);
ASNBER_API asnber_err_t asnber_encode_writer(asnber_ctx_t *ctx,
                                       const asnber_doc_t *doc,
                                       const asnber_encode_options_t *options,
                                       const asnber_writer_t *writer);
ASNBER_API asnber_err_t asnber_encode_buffer(asnber_ctx_t *ctx,
                                       const asnber_doc_t *doc,
                                       const asnber_encode_options_t *options,
                                       asnber_buf_t *out_buf);
ASNBER_API asnber_err_t asnber_buf_release(asnber_ctx_t *ctx, asnber_buf_t *buf);
```

说明：

- `asnber_node_get_*` 输出参数在失败时保持原值不变。
- `asnber_node_get_int64` 只处理可放入 `int64_t` 的 INTEGER/ENUMERATED；超出范围返回 `ASNBER_E_RANGE`。大整数读取使用 `asnber_node_get_bigint_decimal`，原始字节通过 `asnber_node_get_octets` 或 `asnber_node_content` 获取。
- `asnber_node_get_bigint_decimal` 返回借用文本与字节长度，由文档 arena 持有；规则见 6.6，只做十进制导出，不做算术。
- `asnber_node_get_utf8` 只对白名单字符集做转换，转换结果存放在文档 arena；白名单外统一返回 `ASNBER_E_CONVERSION`，其中 T61String/TeletexString 不提供 UTF-8 转换，原始字节一律走 `asnber_node_get_raw_string`，见 6.6。
- `asnber_node_get_time` 只接受 UTCTime/GeneralizedTime，填充 `asnber_time_t`；保留时区偏移与纳秒，不做归一或格式化。`struct_size` 错误返回 `ASNBER_E_INVALID_CONFIG`。
- `asnber_node_field_name` 在未启用 schema 时返回 `NULL`；启用 schema 后返回指向文档 arena 的字段名，生命周期与文档一致。`asnber_node_child_by_name` 只按字段名查找，不按标签猜测。
- OID 以点分十进制文本返回，借用存储由文档 arena 持有，惰性生成，最多生成一次。
- `asnber_node_content` 仅对基本节点有效：成功时返回 `ASNBER_OK` 并写出内容指针与长度（空内容允许 `*out_data = NULL`、`*out_size = 0`）。构造节点返回 `ASNBER_E_INVALID_STATE`，不写输出；**ANY 节点例外**，构造型 ANY 也返回原始内容字节（不含 tag/len），见 5.6。需要构造形式的合并内容时使用 `asnber_node_get_octets` 或 `asnber_node_get_raw_string`，需要观测编码形态时使用 `asnber_node_encoding_form`。
- `asnber_node_child_count` / `asnber_node_child_at` / `asnber_node_child_by_name` 对 ANY 节点固定返回 0 / `NULL` / `NULL`，不展开其内部结构；ANY 自身的父节点指针仍然有效。
- `asnber_node_encoding_form` 是**运行期编码形态**的只读观测接口，返回该节点在源编码中实际使用的形式（基本/构造），与 schema 的 `kind` 无关；用于 BER 构造字符串等观测场景。
- `asnber_doc_source_encoding` 返回文档创建时记录的源编码规则：解码文档返回本次解码选项中的 `encoding`，runtime 构树文档返回 `ASNBER_ENCODING_NONE`，`doc == NULL` 返回 `ASNBER_ENCODING_NONE`；不做编码推断。
- runtime 构树的节点没有原始 TLV：`asnber_node_tlv` 返回 `NULL`/0，`asnber_node_offset` 返回 `SIZE_MAX`；原始 TLV 回读只适用于解码文档。ANY 节点是例外：其原始 TLV 由节点单独保留，`asnber_node_tlv` 对 ANY 始终返回该 TLV（见 5.6）。
- `asnber_encode_options_init` 清零并写 `struct_size`，默认 `encoding = ASNBER_ENCODING_DER`、`schema = NULL`、`flags = 0`；与 `asnber_ctx_config_init`、`asnber_decode_options_init` 的初始化约定一致。
- `asnber_encode_*` 通过 `asnber_encode_options_t` 传入编码规则与 schema；`options == NULL` 等价于 `encoding = ASNBER_ENCODING_DER` 且无 schema。基线只接受 `ASNBER_ENCODING_DER`，其他值返回 `ASNBER_E_UNSUPPORTED_ENCODING`。**`flags` 不设“请求 schema 感知”位**：`schema != NULL` 本身即启用 schema 语义，非零 `flags` 返回 `ASNBER_E_INVALID_CONFIG`。`schema` 必须已封存且设置了根类型（`asnber_schema_set_root`），否则返回 `ASNBER_E_INVALID_STATE`；满足条件后按 9.1 的 schema 感知规则编码（DEFAULT 省略、字段顺序、SET/SET OF 排序、EXPLICIT ANY 重包装），不会静默退化为通用编码。
- `asnber_encode_writer` 只调用 `write` **一次**，把整个输出交给 sink；回调返回非 `ASNBER_OK` 即整体失败，返回 `ASNBER_E_IO_WRITE`，原始回调码放入 `callback_code`，错误详情 `offset` 固定记 0（不把失败回调视为已接收任何字节），不做重试或部分回滚。

### 6.1 runtime 构树语义

- `asnber_doc_create` 创建一个空文档；该文档在 `asnber_doc_seal` 前可写，封存后只读。
- `asnber_node_create` 的 `parent == NULL` 表示设置根节点；根节点只能创建一次。非空 `parent` 表示追加为最后一个子节点。
- `constructed` 参数是**运行期构造位**，只决定该节点在输出编码中是否带构造形式，不是 schema 的种类字段：构造节点通过子节点表达内容，不接受 `asnber_node_set_content`；基本节点必须设置一次内容。解码文档的实际形态通过 `asnber_node_encoding_form` 观测。
- `asnber_node_create_any(doc, parent, tlv, tlv_size, out_node)` 创建 runtime ANY 节点：`tlv` 必须恰好是一个完整、长度确定的 TLV，字节复制进文档 arena；标签类别/标签号/构造形态从 TLV 头推导。拒绝空输入（`ASNBER_E_INVALID_ARG`）、截断（`ASNBER_E_TRUNCATED`）、不定长（`ASNBER_E_INDEFINITE_NOT_ALLOWED`）、尾随字节（`ASNBER_E_TRAILING_DATA`）、畸形标签/长度（`ASNBER_E_MALFORMED_TAG` / `ASNBER_E_MALFORMED_LENGTH`），并写入上下文错误 `offset`（TLV 内字节偏移）。ANY 节点不得挂子节点：以 ANY 为 `parent` 调用 `asnber_node_create` 返回 `ASNBER_E_INVALID_STATE`；ANY 节点也不接受内容设置函数。
- `asnber_node_set_content/set_bool/set_int64/set_oid/set_utf8` 把内容复制到文档 arena；同一节点只能设置一次，重复设置返回 `ASNBER_E_INVALID_STATE`。
- 内容设置函数的标签匹配由调用方负责：例如 `set_bool` 用于 BOOLEAN，`set_int64` 用于 INTEGER/ENUMERATED。库在封存时检查结构与内容存在性，但不做模式语义校验。
- `asnber_doc_seal` 冻结树并校验结构：根节点缺失、基本节点未设置内容、构造节点设置了内容三种失败均返回 `ASNBER_E_INVALID_STATE`，文档仍可销毁；标签号/类别与 EOC（UNIVERSAL 0）在 `asnber_node_create` 阶段校验，非法返回 `ASNBER_E_INVALID_ARG`。对已封存文档再次调用返回 `ASNBER_OK`（幂等）。
- 解码得到的文档已经处于封存状态；对解码文档调用可变接口返回 `ASNBER_E_INVALID_STATE`。
- 节点指针在文档销毁前保持有效；追加子节点不会使已有节点指针失效（节点地址稳定）。

### 6.2 模板机制语义

- `asnber_schema_create(ctx, default_tag_mode, out_schema)` 创建空类型树，供运行时注册；`default_tag_mode` 记录模块级默认标注方式，只接受 `ASNBER_TAG_MODE_EXPLICIT` / `ASNBER_TAG_MODE_IMPLICIT` / `ASNBER_TAG_MODE_DEFAULT`（等价于该模块未声明默认标注方式）。运行时注册不表达 `AUTOMATIC`；源模块为 `AUTOMATIC TAGS` 时，生成器已为未标注组件分配标签，调用方按 `ASNBER_TAG_MODE_IMPLICIT` 传入。描述表加载路径保留头部原值（0=AUTOMATIC、1=EXPLICIT、2=IMPLICIT、3=未声明）用于溯源，并把 0/2 归一为 `IMPLICIT`、3 归一为 `DEFAULT`。
- `asnber_schema_load` 从 `asnber_schema_table_t` 构建类型树；模块默认标注方式取自描述表头部，加载路径不接收该入参。两条入口产出同一种 `asnber_schema_t`，封存后行为必须等价。
- `asnber_schema_load_with_root(ctx, table, root_type_id, out)` 与 `asnber_schema_load` 语义相同，只是根类型由调用方指定：`root_type_id == 0` 沿用描述表头部记录（与 `asnber_schema_load` 完全等价）；非 0 覆盖表头根，必须在 `1..type_count` 内，越界返回 `ASNBER_E_INVALID_ARG` 且 `*out_schema = NULL`。表头自身的根仍按格式校验（越界返回 `ASNBER_E_SCHEMA_FORMAT`）。覆盖不修改调用方表字节，CRC32C 仍按原表校验。用于“一份描述表对应多个顶层类型”的模块。
- `asnber_schema_add_type` 返回稳定类型编号，编号从 1 开始连续分配，`0` 保留为无效引用；`asnber_schema_add_field` 把字段追加到父类型，`parent_type_id` 必须是已注册的 `1..type_count`。描述符内容（名称、约束、默认值 TLV）在调用期间复制进 schema 对象（上下文级分配），调用返回后调用方可释放原缓冲区。
- `asnber_schema_set_root(schema, root_type_id)` 设置单一根类型，`0` 表示清除根（允许多个顶层类型并列）；非 0 必须在 `1..type_count` 内，否则返回 `ASNBER_E_SCHEMA_TYPE`；schema 已封存返回 `ASNBER_E_INVALID_STATE`。描述表加载路径从头部 `root_type_id` 取得同一语义，越界返回 `ASNBER_E_SCHEMA_FORMAT`。
- 名称表查询（`asnber_schema_name_count` / `asnber_schema_name_at` / `asnber_schema_name_for_bit` / `asnber_schema_name_for_value` / `asnber_schema_value_for_name`）：
  - 运行时注册路径（`asnber_schema_create`）不产生名称，`name_count == 0`：`*_count` 返回 0，按位/按值/按名查询均为“未命中”。
  - 前置条件：schema 必须已封存，否则返回 `ASNBER_E_INVALID_STATE`；空 schema 句柄、空出参或 `type_id` 为 0/大于 `type_count` 返回 `ASNBER_E_INVALID_ARG`；`asnber_schema_name_at` 的 `index >= 该类型名称数` 返回 `ASNBER_E_INVALID_ARG`，`out_info->struct_size != sizeof(asnber_schema_name_info_t)` 返回 `ASNBER_E_INVALID_CONFIG`。
  - `asnber_schema_name_count` / `asnber_schema_name_at` 只统计/访问指定类型的记录；`name_at` 的 `index` 是**该类型内**从 0 开始的下标，不提供全局下标。
  - `asnber_schema_name_for_bit` 只匹配 `BIT_NAME`；`asnber_schema_name_for_value` 只匹配 `NUMBER_NAME`，二者互不回退。未命中返回 `ASNBER_OK` 且 `*out_name = NULL`，不视为错误。
  - `asnber_schema_value_for_name` 在任意 `kind` 中按名称精确匹配（区分大小写）：命中返回 `ASNBER_OK`、`*out_found = 1`、`*out_value = 名称对应值`；未命中返回 `ASNBER_OK`、`*out_found = 0`、`*out_value = 0`。
  - 返回的名称字符串借用 schema 内部存储，schema 销毁后失效；调用方不得释放。
- API 描述符中的 `reserved` 字段非 0、未知 `flags` 位、未知 `tag_mode`/`tag_class`/`kind` 或结构尺寸不符均返回 `ASNBER_E_INVALID_CONFIG`；描述表头部与表记录的预留字段非 0 返回 `ASNBER_E_SCHEMA_FORMAT`。
- 约束合法性：`RANGE`/`BIGINT_RANGE` 的 `lower <= upper`；`MAX` 上界无界且下界固定为 0、不得另行给出 lower；`BIGINT` 十进制只允许可选负号 + 至少一位数字，除 `"0"` 外无前导零，禁止 `"-0"`；`ENUM` 至少一个取值且不得重复；`SIZE` 对 OCTET STRING 与字符串为字节数、对 `SEQUENCE OF`/`SET OF` 为元素数。违反返回 `ASNBER_E_SCHEMA_CONSTRAINT`；描述表路径返回 `ASNBER_E_SCHEMA_FORMAT`。多条约束按交集语义全部保留（本轮不求值）。
- 本阶段不提供按类型名/ID 或字段名查询 schema 的公共接口（名称表查询见 6.2）；需要时在解码/编码阶段按实际消费方需求定义。
- `asnber_schema_seal` 冻结类型树并校验：引用完整性、字段顺序、`element_type_id` 适用范围、`kind` 与 `tag_mode` 冲突、重复标签、`CHOICE` 分支标签唯一性、约束数据合法性、默认值 DER 规范性、`CHOICE` 分支字段标志、`SEQUENCE_OF`/`SET_OF` 字段数。未封存的 schema 不能用于解码或校验。封存幂等。
- `CHOICE` 的分支字段不得设置 `OPTIONAL`、`DEFAULT`（`default_index != 0`）或 `EXTENSION`；任一出现返回 `ASNBER_E_SCHEMA_FIELD`。`SEQUENCE_OF`/`SET_OF` 不得添加任何字段（`field_count` 必须为 0），否则返回 `ASNBER_E_SCHEMA_FIELD`。描述表加载路径执行同一组检查。
- 描述表 `format_version` 不匹配统一返回 `ASNBER_E_SCHEMA_FORMAT`；描述表内部越界、偏移错误或恶意构造返回同一错误码，不返回部分类型树。`struct_size` 错误仍返回 `ASNBER_E_INVALID_CONFIG`。
- `kind` 与 `tag_mode` 冲突（如 `CHOICE` + `IMPLICIT`、`SIMPLE` + `IMPLICIT` 且 `tag_class = UNIVERSAL`/`tag_number = 0`、`CHOICE` + `EXPLICIT` 但缺少非 UNIVERSAL 外层标签、`SEQUENCE_OF` 携带与元素不一致的显式标签）在加载或 `add_type` 阶段失败，返回 `ASNBER_E_SCHEMA_TYPE`。
- 默认值必须是可规范化的 DER TLV；解析或规范化失败返回 `ASNBER_E_SCHEMA_DEFAULT`。
- schema 感知解码只改变命名与校验，不改变 DOM 节点布局；未知字段是否保留、是否告警由解码选项控制。
- `asnber_doc_validate(ctx, doc, schema, options)` 对既有文档按 schema 与解码选项重新校验，不修改节点；`options` 只使用与校验相关的位（`STRICT_SCHEMA`、`WARN_UNKNOWN_FIELD`、`max_depth`），编码相关位被忽略；`options == NULL` 仅校验相关位取默认值（未知字段静默保留、不启用 schema 严格校验、`max_depth` 取上下文默认）。常用于 runtime 构树后的结构检查。
- 字段名在解码时复制到文档 arena；schema 可在解码完成后销毁，文档不保留 schema 指针。

### 6.3 模块边界

- 核心只提供通用能力：文档、节点、模板、编解码、错误、内存；不提供任何标准结构 API。
- 模块（如 `asnber-pkix`）拥有独立公共头、包名、版本与符号前缀；模块函数可接收核心文档/节点句柄，但不得暴露核心内部类型。
- 模块错误码使用独立前缀；模块可以定义自己的不透明句柄，但生命周期必须写明与核心文档的关系。
- 模块头文件不并入 `asnber/asnber.h`；消费者按需 `find_package(asnber-pkix CONFIG REQUIRED)`。
- 模块不得反向包含 `src/` 内部头文件，也不得要求核心链接模块符号。

### 6.4 版本查询与自检

- `asnber_version` 填充调用方提供的 `asnber_version_info_t`，返回**实际链接的库版本**；`string` 指向库内静态存储，调用方不得释放；`capabilities` 为能力位集合。`struct_size` 错误返回 `ASNBER_E_INVALID_CONFIG`，`out_info == NULL` 返回 `ASNBER_E_INVALID_ARG`；失败时不写部分输出。
- `asnber_version_check(expected_major, expected_minor)` **只对主版本不一致报错**：`expected_major != ASNBER_VERSION_MAJOR` 返回 `ASNBER_E_VERSION_MISMATCH`；次版本差异视为兼容，返回 `ASNBER_OK`。`expected_minor` 参数保留用于诊断与未来策略，不参与失败判定。该函数不接收上下文，错误信息只通过返回值表达。
- `asnber_has_capability(capability)` 查询运行库是否具备某个能力位，返回 1/0，不写错误状态。`capability` 必须是单个已知位；未定义位返回 0。调用方应通过能力位判断可选特性，而不是比较次版本号。
- **编译期宏 vs 运行时值**：`ASNBER_VERSION_MAJOR/MINOR/PATCH/STRING/ENCODED` 来自 CMake 生成的 `asnber/asnber_version.h`，代表**调用方编译时**看到的版本；`asnber_version` 返回**实际链接的库版本**。两者可能因头文件与二进制不一致而分离。
- **典型场景与检测**：旧头新库（用 0.1 头编译、链接 0.2 库）运行时值高于宏，主版本一致即视为兼容；新头旧库（用 0.2 头编译、链接 0.1 库）可能调用旧库不存在的符号，加载或调用失败。宿主应在初始化阶段调用 `asnber_version_check(ASNBER_VERSION_MAJOR, ASNBER_VERSION_MINOR)`，主版本不一致时拒绝继续并提供明确的诊断。
- 版本宏与运行时值不必逐位相等：二进制兼容允许同一主版本内的次版本差异；跨主版本必须视为不兼容。

### 6.5 能力位

| 能力位 | 值 | 含义 | 基线 |
| --- | --- | --- | --- |
| `ASNBER_CAP_SCHEMA_TABLE_LOAD` | `1ull << 0` | 支持 `asnber_schema_load` 加载描述表 | 具备 |
| `ASNBER_CAP_SCHEMA_RUNTIME_REGISTER` | `1ull << 1` | 支持运行时注册类型/字段 | 具备 |
| `ASNBER_CAP_STRICT_SCHEMA` | `1ull << 2` | 支持 `ASNBER_DECODE_STRICT_SCHEMA` | 具备 |
| `ASNBER_CAP_WARNING` | `1ull << 3` | 支持告警记录与回调 | 具备 |
| `ASNBER_CAP_BER_CONSTRUCTED_STRING` | `1ull << 4` | 支持 BER 构造字符串解码与合并 | 具备 |
| `ASNBER_CAP_TIME_NANOSECOND` | `1ull << 5` | 支持 `asnber_time_t.nanosecond` | 具备 |
| `ASNBER_CAP_BIGINT_DECIMAL` | `1ull << 6` | 支持大整数十进制导出 | 具备 |
| `ASNBER_CAP_ENCODE_SCHEMA_AWARE` | `1ull << 7` | 支持带 schema 的 DER 编码（DEFAULT 省略、排序） | 具备 |
| `ASNBER_CAP_CER` | `1ull << 8` | 支持 CER 编解码 | 不具备，保留位 |
| `ASNBER_CAP_PER` | `1ull << 9` | 支持 PER/UPER | 不具备，保留位 |
| `ASNBER_CAP_ANY_OPEN_TYPE` | `1ull << 10` | 支持 ANY/开放类型的 schema 注册、节点语义、显式包装解码与编码回写 | 具备 |
| `ASNBER_CAP_SCHEMA_NAMES` | `1ull << 11` | 支持描述表名称表加载与名称查询 API | 具备 |

- 能力位一旦发布不得改变语义；新增能力位在同一 `uint64_t` 内追加，耗尽后通过新增查询函数扩展。
- 结构体字段与函数是能力位的“编译期存在性”，能力位是“运行期可用性”；调用方在头文件可见的前提下仍应查询能力位。
- 表中“具备”是基线目标；运行期能力位只反映**已验收**能力。当前置位集合：`SCHEMA_TABLE_LOAD`、`SCHEMA_RUNTIME_REGISTER`、`STRICT_SCHEMA`、`WARNING`、`BER_CONSTRUCTED_STRING`、`TIME_NANOSECOND`、`BIGINT_DECIMAL`、`ENCODE_SCHEMA_AWARE`、`ANY_OPEN_TYPE` 与 `SCHEMA_NAMES`（掩码 `0xCFF`）。`CER`、`PER` 仍未实现，对应位不置位；`asnberc` 已实现 MVP 并通过 `test_asnberc_*` 端到端用例，多模块 `IMPORTS` 与单类型参数化展开已落地（值参数与多参数仍报 9006）；conformance/差分/模糊测试已落地。`ASNBER_CAP_SCHEMA_NAMES` 的置位依据：描述表名称表可用于表示 `BIT STRING` 命名位与 `ENUMERATED`/`INTEGER` 名值，5 个只读查询 API 与加载期一致性校验已实现。`ASNBER_CAP_ANY_OPEN_TYPE` 的置位依据：schema 感知解码（`asnber_decode_buffer_with_schema` / `asnber_decode_reader_with_schema`）可通过 `AlgorithmIdentifier.parameters ::= ANY OPTIONAL` 与 `[0]/[1] EXPLICIT ANY` 产生 ANY 节点，真实 RSA/RSA-PSS/EC 证书解码已实测（`NULL`、内层 `SEQUENCE`、缺省三种形态），并且节点语义、通用编码回写与 schema 感知编码回写均逐字节一致。

- **能力位是“特性可用”判断，不是安全认证。** `ASNBER_CAP_*` 置位仅表示对应功能路径已实现、已通过常规单元测试与 fuzz 短跑/长跑（无崩溃、无泄漏），不等于“已证明抗恶意输入”。它不构成对任意恶意/畸形输入的抗性承诺，也不能作为安全等级、合规或 fuzz-hardened 认证的依据。抗恶意输入需另行开展专项 fuzz-hardened 测试与安全审计；本仓库当前**不承诺**此类认证。

生成头 `asnber/asnber_features.h` 暴露构建期特性：
`ASNBER_FEATURE_ENCODE`、`ASNBER_FEATURE_BUILD_API`、
`ASNBER_FEATURE_SCHEMA_BUILD_API`、`ASNBER_FEATURE_PKIX_BUILDER`。值为 0 时对应
声明不参与编译；能力位随之调整：`ASNBER_CAP_ENCODE_SCHEMA_AWARE` 仅在
`ASNBER_FEATURE_ENCODE=1` 时置位，`ASNBER_CAP_SCHEMA_RUNTIME_REGISTER` 仅在
`ASNBER_FEATURE_SCHEMA_BUILD_API=1` 时置位。full 构建下四个宏均为 1，能力位
与既有基线一致。

### 6.6 值类型语义

**BIT STRING**

- `asnber_node_get_bits(node, out_data, out_size, out_bit_length, out_unused_bits)` 返回合并后的位串内容：BER 构造形式的多段内容按顺序拼接；`out_data` **不含** unused-bits 计数首字节。
- `out_size` 为 `out_data` 的字节数；`out_bit_length = out_size * 8 - out_unused_bits`；`out_unused_bits` 为最后一个字节中的未使用位数，合法范围 `0..7`。
- 零值 BIT STRING：编码内容为单个 `0x00` 的 unused-bits 计数，API 返回 `out_data = NULL`、`out_size = 0`、`out_bit_length = 0`、`out_unused_bits = 0`；不得把该计数首字节计入 `out_size`。
- DER 下零值仍要求规范编码 `03 01 00`，API 侧仍返回 `out_size = 0`；构造形式在 DER 下返回 `ASNBER_E_NON_CANONICAL`。
- 构造形式合并后若各段填充位不一致，按 BER 规则以最后一段为准；DER 下出现构造形式返回 `ASNBER_E_NON_CANONICAL`。
- 所有输出指针均为文档 arena 借用，失败时不写任何输出。

**字符串**

- `asnber_node_get_raw_string` 返回节点原始内容字节，不做字符集解释；基本形式直接借用输入，BER 构造形式返回按段顺序合并后的结果，合并结果由文档 arena 持有。`asnber_node_get_octets` 对构造 OCTET STRING 同样返回合并结果，不暴露分段边界。
- `asnber_node_get_utf8` 先按 `asnber_node_get_raw_string` 的规则处理源内容（基本形式直接取内容，BER 构造形式按段顺序合并），再按白名单字符集转换为 UTF-8；结果分配在文档 arena，NUL 结尾不保证存在（调用方以 `out_size` 为准）。合并或转换阶段失败返回 `ASNBER_E_CONVERSION`；节点预算、内存等资源类失败保留原错误码（如 `ASNBER_E_MEMORY_LIMIT`）。
- 白名单：UTF8String、PrintableString、IA5String、VisibleString、NumericString、BMPString、UniversalString。
- T61String/TeletexString 不支持转换：`asnber_node_get_utf8` 返回 `ASNBER_E_CONVERSION`，调用方应改用 `asnber_node_get_raw_string`。
- 转换失败（非法码点、非法字节序列、长度不可整除等）返回 `ASNBER_E_CONVERSION`，不写部分输出。

**时间**

- `asnber_time_t` 已含 `nanosecond`；`ASNBER_TIME_FRACTIONAL` 置位时有效，范围 `0..999,999,999`。
- 时间三态：`ASNBER_TIME_HAS_OFFSET` 表示显式偏移（含 `+00:00`），`ASNBER_TIME_LOCAL` 表示本地时间且无偏移，两者都不置位表示 `Z`；`HAS_OFFSET` 与 `LOCAL` 互斥，同时置位返回 `ASNBER_E_INVALID_VALUE`。
- UTCTime 两位年份固定映射窗口 1950–2049；GeneralizedTime 使用四位年份。
- DER 下秒必填、只接受 `Z`（拒绝任何 `±hhmm`，包括 `+0000`/`-0000`）、拒绝本地时间形式、拒绝闰秒（`second == 60`），GeneralizedTime 小数只接受 `.`；非规范形式返回 `ASNBER_E_NON_CANONICAL`。BER 下允许省略秒、`±hhmm`（限定 `-14:00..+14:00`）、本地时间形式与逗号小数：本地时间形式按 `ASNBER_TIME_LOCAL` 解析，不伪造偏移。

**大整数十进制**

- 零长度内容非法，返回 `ASNBER_E_INVALID_VALUE`。
- 正数去掉高位补零后输出，无前导零；负数按二进制补码解释，输出带前导 `-`。
- 零输出 `"0"`；不输出 `-0`。
- 只做十进制导出，不做算术、不进位、不补位。

**源编码读取**

- `asnber_doc_source_encoding` 返回值语义见第 6 节说明：解码文档返回源 `encoding`，runtime 构树返回 `ASNBER_ENCODING_NONE`，空句柄返回 `ASNBER_ENCODING_NONE`。

**空句柄访问器**

- 返回指针的元数据访问器在 `node == NULL` 时返回默认值：`tag_class = ASNBER_TAG_UNIVERSAL`、`tag_number = 0`、`encoding_form = PRIMITIVE`、`is_indefinite = 0`、`child_count = 0`、`parent/child_at/child_by_name/field_name = NULL`、`tlv = NULL`（`out_size = 0`）、`offset = SIZE_MAX`；`asnber_doc_root(NULL) == NULL`。
- 返回错误码的访问器（`asnber_node_content` 与全部 `asnber_node_get_*`）在句柄为 `NULL`（或文档/上下文已销毁）时返回 `ASNBER_E_INVALID_ARG`，失败时不写任何输出参数；标签不匹配等类型错误按本节各类型的约定返回。

### 6.7 告警接口语义

- `asnber_ctx_set_warning_handler(ctx, NULL, user)` 清除已注册的回调；`user` 参数被忽略，清除后不再调用任何回调，已记录的告警仍可通过 `asnber_ctx_get_warning` 读取。
- `asnber_ctx_get_warning(ctx, index, out_warning)` 在 `index >= asnber_ctx_warning_count(ctx)` 时返回 `ASNBER_E_INVALID_ARG`，且不修改 `out_warning`；读取按上下文记录顺序，索引从 0 开始。
- `out_warning->field_name` 由上下文持有：有效期为**下一次解码调用开始前**与**上下文销毁前**两者中的较早者；下一次解码可能复用或释放该字符串，调用方不得长期保存指针，需要长期保留时自行复制。
- `asnber_warning_t.message` 同样由上下文持有，生命周期与 `field_name` 一致。

### 6.8 asnber-pkix 模块 API

本节内容已拆到独立页：见 [asnber-pkix 模块 API](02a-模块API-pkix.md)。

### 6.9 asnber-pkcs 模块 API

本节内容已拆到独立页：见 [asnber-pkcs 模块 API](02b-模块API-pkcs.md)。

### 6.10 asnber-cms 模块 API

本节内容已拆到独立页：见 [asnber-cms 模块 API](02c-模块API-cms.md)。

### 6.11 asnber-cms EnvelopedData 只读 API（0.2.0 第一块）

本节内容已拆到独立页：见 [asnber-cms 模块 API](02c-模块API-cms.md)。

### 6.12 asnber-cms EnvelopedData 写侧 API（0.2.0 第二块）

本节内容已拆到独立页：见 [asnber-cms 模块 API](02c-模块API-cms.md)。

### 6.13 asnber-cms EncryptedData 只读 API（0.2.0 第三块）

本节内容已拆到独立页：见 [asnber-cms 模块 API](02c-模块API-cms.md)。

### 6.14 asnber-cms EncryptedData 写侧 API（0.2.0 第四块）

本节内容已拆到独立页：见 [asnber-cms 模块 API](02c-模块API-cms.md)。

### 6.15 asnber-cms CompressedData 只读 API（0.3.0 第一块）

本节内容已拆到独立页：见 [asnber-cms 模块 API](02c-模块API-cms.md)。

### 6.16 asnber-cms CompressedData 写侧 API（0.3.0 第二块）

本节内容已拆到独立页：见 [asnber-cms 模块 API](02c-模块API-cms.md)。

### 6.17 asnber-cms AuthenticatedData 只读 API（0.3.0 第三块）

本节内容已拆到独立页：见 [asnber-cms 模块 API](02c-模块API-cms.md)。

### 6.18 asnber-cms AuthenticatedData 写侧 API（0.3.0 第四块）

本节内容已拆到独立页：见 [asnber-cms 模块 API](02c-模块API-cms.md)。

## 7. 错误信息获取

```c
typedef struct asnber_error_info {
    size_t struct_size;      /* 输入：必须为 sizeof(asnber_error_info_t) */
    asnber_err_t code;         /* 最近一次失败的稳定错误码 */
    int32_t callback_code;   /* 原始 reader/writer 回调错误码；无则为 0 */
    const char *message;     /* 上下文持有，直到下一次修改错误的调用或销毁上下文 */
    size_t offset;           /* 输入字节偏移；编码时为已输出字节数；无意义时为 SIZE_MAX */
    uint32_t depth;          /* 出错时的嵌套深度；无意义时为 0 */
    uint32_t reserved;       /* 必须置零 */
    const char *path;        /* schema 字段路径（如 "issuer.rdnSequence[0].type"）；无则 NULL */
} asnber_error_info_t;
```

| 字段 | 填充规则 |
| --- | --- |
| `code` | 对外稳定错误码；回调失败已包装为 `ASNBER_E_IO_READ` / `ASNBER_E_IO_WRITE` |
| `callback_code` | 仅当 `code` 为 `ASNBER_E_IO_READ` / `ASNBER_E_IO_WRITE` 时有效，保存回调原样返回的整数；其他场景为 0 |
| `message` | 静态英文短消息；回调场景不拼接原始回调码，调用方读取 `callback_code` |
| `offset` | 解码：出错字节偏移；编码：已成功交给 sink 的字节数；无意义 `SIZE_MAX` |
| `depth` | 出错时的嵌套深度；无意义 0 |
| `path` | schema 感知解码/校验得到的字段路径；schema 编码失败时为 `类型名` 或 `类型名/字段名`（最内层）。未启用 schema 或无法定位时 `NULL`。路径字符串存放在上下文固定槽位，不经 arena 分配 |

- `asnber_ctx_get_error` 总是返回 `ASNBER_OK`（上下文为空除外），并通过 `code` 表示是否存在错误；无错误时 `message = NULL`、`callback_code = 0`、`offset = SIZE_MAX`、`depth = 0`、`path = NULL`。
- 回调失败只通过包装码暴露：解码把 reader 回调的非零返回包装为 `ASNBER_E_IO_READ`，编码把 writer 回调的非零返回包装为 `ASNBER_E_IO_WRITE`，原始值放在 `callback_code`。回调返回 `ASNBER_OK` 视为成功。
- 错误消息不是线程安全的共享资源；只能在创建该上下文的线程中读取。
- 调用成功后是否清除旧错误：**不清除**。错误状态只在 `asnber_ctx_clear_error`、下一次失败或上下文销毁时改变，便于调用方在成功后仍能排查先前问题。
- 错误详情固定大小存放，不依赖 arena 分配，保证 `ASNBER_E_NOMEM` 时仍可读取。
- 详细分类与“可恢复/致命”定义见[错误模型](05-错误模型.md)。

## 8. 内存所有权

| 对象/数据 | 所有权 | 释放方式 | 生命周期 |
| --- | --- | --- | --- |
| `asnber_ctx_t` | 调用方触发创建 | `asnber_ctx_destroy` | 最后销毁 |
| `asnber_doc_t` | 上下文持有 | `asnber_doc_destroy` | 必须先于上下文销毁 |
| `asnber_schema_t` | **上下文级分配**，调用方通过 `asnber_schema_destroy` 归还 | `asnber_schema_destroy` | 必须先于上下文销毁；解码调用期间必须有效 |
| `asnber_node_t` | 文档借用 | 不可释放 | 不超过文档 |
| 节点内容/OID/大整数/UTF-8/字段名指针 | 文档借用 | 不可释放 | 不超过文档 |
| `asnber_buf_t` 输出 | **上下文级分配** | `asnber_buf_release` → `asnber_err_t` | 不超过上下文；跨上下文返回 `ASNBER_E_INVALID_ARG`；未释放时由 `asnber_ctx_destroy` 回收 |
| reader/writer 回调数据 | 调用方 | 由调用方定义 | 调用期间必须有效 |
| 静态池 | 调用方 | 调用方 | 必须覆盖上下文整个生命周期 |

规则：

1. 库只释放自己分配的内存；绝不 `free` 调用方传入的缓冲区、reader/writer 或静态池。
2. `asnber_schema_t` 与输出缓冲均由创建它们的上下文分配，不能跨上下文释放。`asnber_schema_destroy` 不接收调用方上下文，始终通过 schema 记录的所属上下文释放；`asnber_buf_release(ctx, buf)` 校验 `buf` 是否属于 `ctx`，跨上下文返回 `ASNBER_E_INVALID_ARG` 且不修改 `buf`。
3. `asnber_ctx_destroy` **回收仍被上下文持有的 schema 与输出缓冲**，即使调用方漏调 `asnber_schema_destroy` / `asnber_buf_release`；固有规则仍是文档与 schema 必须先于上下文销毁，回收只作为兜底，不保证调用方定义的析构语义。
4. 失败时所有输出指针被置 `NULL`，不会返回部分文档。
5. `asnber_buf_release` 成功时释放并置零 `data`、`size`、`capacity`，返回 `ASNBER_OK`；`buf == NULL` 或已释放/全零缓冲为空操作并返回 `ASNBER_OK`；`ctx == NULL` 或缓冲属于其他上下文返回 `ASNBER_E_INVALID_ARG`，且不修改缓冲。
6. 输入所有权见[数据表示与内存模型](04-数据与内存模型.md)：`asnber_decode_buffer` 默认零拷贝借用，调用方必须保证输入内存在文档存续期间有效。

### 8.1 静态池

- 启用静态池时，池内存在**包含上下文对象本身**以及上下文的簿记结构；池起始地址必须按 `max_align_t` 对齐，否则 `asnber_ctx_create` 返回 `ASNBER_E_INVALID_ARG`。
- `asnber_ctx_size_for_config(config, out_size)` 返回满足该配置的静态池**最小字节数**（含上下文对象、对齐填充与固定簿记）；`config.static_pool` 可为 `NULL`（此时只计算尺寸）。返回 `ASNBER_OK` 时写 `out_size`；`config` 或 `out_size` 为空返回 `ASNBER_E_INVALID_ARG`，配置非法返回 `ASNBER_E_INVALID_CONFIG`，尺寸溢出返回 `ASNBER_E_MEMORY_LIMIT`。
- `static_pool_size` 小于该最小值时 `asnber_ctx_create` 返回 `ASNBER_E_INVALID_CONFIG`；等于或大于时创建成功，剩余空间用于上下文级对象（schema、输出缓冲）与文档 arena。
- 静态池耗尽返回 `ASNBER_E_STATIC_POOL_EXHAUSTED`，绝不回退到堆。
- 池由调用方持有，生命周期必须覆盖上下文；`asnber_ctx_destroy` 不释放池本身。

## 9. 缓冲区与流式接口

```c
typedef asnber_err_t (*asnber_read_fn)(void *user, uint8_t *dst,
                                   size_t capacity, size_t *out_size);

struct asnber_reader {
    size_t struct_size;      /* 必须为 sizeof(asnber_reader_t) */
    void *user;
    asnber_read_fn read;       /* out_size == 0 表示输入结束 */
};

typedef asnber_err_t (*asnber_write_fn)(void *user, const uint8_t *data, size_t size);

struct asnber_writer {
    size_t struct_size;      /* 必须为 sizeof(asnber_writer_t) */
    void *user;
    asnber_write_fn write;
};

struct asnber_buf {
    uint8_t *data;
    size_t   size;
    size_t   capacity;
};
```

- **缓冲区解码**：`asnber_decode_buffer` 是一次性物化整棵树的接口，适合已知完整输入。
- **流式解码**：`asnber_decode_reader` 按需拉取字节，仍然输出完整文档树；它不是事件式/SAX 接口。
- **事件式接口**：基线不提供。解码器内部保留架构扩展位，二期评估是否需要，见[能力范围](03-ASN1能力范围.md)。
- reader 的 `read` 回调返回非零值时，解码立即中止，对外返回 `ASNBER_E_IO_READ`，原始回调码放在 `asnber_error_info_t.callback_code`；不得在回调内递归调用库接口。
- **writer 契约：全写或返回错误**。`write` 返回 `ASNBER_OK` 表示 `size` 个字节已全部被 sink 接受；返回非零表示未接受或未完整接受。库把非零返回包装为 `ASNBER_E_IO_WRITE`，原始值放入 `callback_code`，并立即中止编码。库禁止“返回成功但只写了一部分”，也不对已写出的字节做回滚；部分写入后的 sink 状态由调用方负责清理。
- `consumed` 语义：调用方可传 `NULL`。成功时，`asnber_decode_buffer` 写入从 `data` 消费的字节数（顶层 TLV 完整长度）；`asnber_decode_reader` 写入本次从 reader 实际拉取的字节数，可能因预读大于顶层 TLV 长度。失败时 `consumed` 保持原值。
- 未设置 `ALLOW_TRAILING` 时，缓冲区路径若 `size > *consumed` 返回 `ASNBER_E_TRAILING_DATA`；设置后允许尾随，剩余字节为 `data + *consumed`、长度为 `size - *consumed`。reader 路径无法回退预读字节，`ALLOW_TRAILING` 只表示“不因尾随报错”，不提供剩余字节访问。
- 两种接口都不保证“调用返回后仍可复用解码器状态”；每次解码独立创建文档。
- **增量 feed 解码**：`asnber_decoder_create` / `asnber_decoder_feed` / `asnber_decoder_finalize` 提供 push 模式入口。调用方分块 `feed` 数据，`finalize` 时一次性构建 DOM；与 `asnber_decode_buffer` 解码行为一致，`COPY_INPUT` 按忽略处理（feed 数据总是内部累积）。`finalize` 只能调用一次，之后再 `feed` 或 `finalize` 返回 `ASNBER_E_INVALID_ARG`；`consumed` 为累计 feed 的总字节数。未 finalize 即 `destroy` 安全释放累积数据。

### 9.1 schema 感知 DER 编码规则

- **字段顺序**：`SEQUENCE` 按 schema 声明顺序输出；`SET` 的字段仍按 DER 规则排序，而不是声明顺序。
- **未知字段保留**：schema 感知编码时，凡未匹配到 schema 字段的子节点一律保留，**不限于** `ASNBER_TYPE_EXTENSIBLE`。`SEQUENCE` 中已知字段按 schema 声明顺序在前，未匹配字段按 DOM 中的原始相对顺序追加到已知字段之后，未匹配字段之间不重排。`SET` 不得直接追加未知字段：本轮不做“已知 + 未知合并排序”，`SET` 中出现未匹配子节点返回 `ASNBER_E_SCHEMA_FIELD`，绝不静默产出非法 DER。
- **严格检查**：`asnber_encode_*` 没有严格开关，默认保留未知字段；需要严格检查时先调用 `asnber_doc_validate(..., ASNBER_DECODE_STRICT_SCHEMA)`，该路径对未知字段返回 `ASNBER_E_SCHEMA_FIELD`。
- **ANY 与保留 TLV 的 DER 一致性**：schema 感知 DER 编码中，`ANY` 节点与保留的未知字段只保证**规范 DER 源**按其原始 TLV 逐字节回写；BER 不定长、非最短长度、长形式标签表示小 tag number、构造字符串、非规范基本值、未排序 `SET`/`SET OF` 等非规范源返回 `ASNBER_E_NON_CANONICAL`，**不做隐式重新编码**。无 schema 的通用编码路径（`schema == NULL`）对 `ANY` 仍按节点保存的 TLV 原样写回，允许 BER 源往返；其余普通节点按通用 DER 规范化重建。回归用例：`tests/c_api/test_any.c` 的“BER 不定长保留 TLV → schema 编码 `NON_CANONICAL`”用例（约 709–750 行）与 `tests/c_api/test_schema_decode.c` 的非最短长度 ANY 用例（约 523–545 行）。
- **runtime 构树 ANY 一致性**：解码得到的 ANY 与 `asnber_node_create_any` 建立的 runtime ANY 在两条编码路径上行为一致——原始 TLV 均来自节点自身保留的字节；schema 路径同样执行上述规范性校验，不因来源不同而放宽或拒绝。
- **DER 输出保证范围**：库只在两条路径承诺输出 DER——(1) **由规范 DER 输入解码得到的文档**，经通用编码重建（普通节点按内容重建，`ANY` 保留的原始 TLV 本身也是 DER）；(2) **`schema != NULL` 的 schema 感知编码**，保留 TLV 按上一条校验，非规范源直接拒绝。`schema == NULL` 且文档含 `ANY`/保留 TLV 时，通用编码器只保证“按保存字节原样写回”；若这些字节来自 BER 源或 runtime 构树时传入的非规范 TLV，输出可能不是 DER，库不做隐式规范化。需要严格 DER 输出时只能使用 schema 感知编码（以 `ASNBER_E_NON_CANONICAL` 拒绝非规范保留 TLV）；`asnber_doc_validate` 只做 schema 结构与约束绑定，不校验保留 TLV 的 DER 规范性，也不遍历 ANY 内层。
- **DEFAULT 省略**：启用 schema 时，字段编码结果与 schema 中的规范 DER 默认值逐字节相同时省略该字段；未启用 schema 时无法判定 DEFAULT，一律输出。
- **OPTIONAL**：未出现的可选字段不输出；出现但值等于默认值的 DEFAULT 字段按上一条省略。
- **SET OF 排序**：按 DER 规则，将每个元素的完整 DER 编码字节按无符号字典序升序排列。启用 schema 时按元素类型的 schema 语义先规范化再排序；未启用 schema 时按节点保存的完整 TLV 字节排序。
- **SET 排序**：按字段完整 DER 编码字节的无符号字典序升序；`SET` 字段的有效标签唯一性**只在 schema 路径校验**（`asnber_schema_seal`），无 schema 的通用编码不做该检查。
- **CHOICE**：只输出被选中的分支，不输出包装层，除非 `tag_mode = EXPLICIT` 要求外层显式标签。
- **SEQUENCE OF**：保持文档中的元素顺序，不排序。
- 无 schema 时只应用通用 DER 规范化，无法恢复 DEFAULT 省略语义。

## 10. 可重入与线程安全

- 不同上下文之间完全独立，可并发使用；库内部无可变全局状态。
- 单个上下文不是线程安全的：`asnber_ctx_get_error`、`asnber_ctx_clear_error`、解码、编码都可能写入错误状态，必须由外部加锁或每线程一个上下文。
- 解码完成后的 `asnber_doc_t` 与 `asnber_node_t` 是只读的，可被多个线程同时读取；前提是没有任何线程销毁文档或上下文。
- 封存后的 `asnber_schema_t` 只读，可被多个线程同时用于解码；创建/注册/封存不是线程安全的。
- allocator 回调可能被跨上下文共享；若共享，回调本身必须线程安全。库不额外加锁。
- 告警记录按上下文存放：`asnber_ctx_warning_count` / `asnber_ctx_get_warning` / `asnber_ctx_clear_warnings` 与解码同属一个上下文的可变状态，必须与解码串行；告警回调在**解码线程内同步调用**，回调中不得递归调用同一上下文的编解码接口，也不得销毁该上下文。
- 告警回调返回 `void`。**告警不影响解码流程，不写入主错误码，也不会中止解码**；回调无法通过返回值影响解码结果，回调内自行记录或忽略。回调抛出的宿主级异常不属于 C ABI 契约。
- 告警数量上限由 `asnber_ctx_config_t.max_warnings` 决定，默认 `1024`；达到上限后继续解码但不再追加记录，`asnber_ctx_warning_count` 返回上限值，解码结果不受影响。
- `asnber_version`、`asnber_version_check` 与 `asnber_has_capability` 不读写任何可变状态，线程安全。

## 11. ABI 稳定性与版本策略

**基线承诺向后兼容**：已发布的公共 ABI 在后续版本中保持可用，破坏性变更只能通过主版本升级并明确公告。

```c
/* 由 CMake 从 project(asnber VERSION ...) 生成到构建目录，源码树中不手写。 */
#define ASNBER_VERSION_MAJOR 0
#define ASNBER_VERSION_MINOR 1
#define ASNBER_VERSION_PATCH 1
#define ASNBER_VERSION_STRING "0.1.1"

/* 编码规则：major << 16 | minor << 8 | patch */
#define ASNBER_VERSION_ENCODED \
    ((ASNBER_VERSION_MAJOR << 16) | (ASNBER_VERSION_MINOR << 8) | ASNBER_VERSION_PATCH)
```

- 版本遵循 `MAJOR.MINOR.PATCH`；唯一真源是根 `CMakeLists.txt` 的 `project(asnber VERSION ...)`。版本宏由 `configure_file` 生成，公共版本宏、`asnber_version` 返回值、SONAME 与 CMake 包版本必须一致；源码树中不手写版本宏。
- 版本号编码为单个整数，便于调用方做编译期比较：`major << 16 | minor << 8 | patch`。
- 公共头文件**只增不改**：不删除、不改签名、不改变既有枚举值与错误码语义；新增能力通过新函数或结构体尾部字段（配合 `struct_size`）实现。
- `struct_size` 允许调用方使用旧版结构体；库只读取调用方声明的范围内存，并拒绝非零的未知预留字段。
- 共享库 SONAME 由 `project(... VERSION ...)` 的**主版本**派生：Linux `libasnber.so.<MAJOR>`、macOS `libasnber.<MAJOR>.dylib`；Windows 无 SONAME，使用 `asnber.dll` + 导入库。次版本升级不改变 SONAME。详细规则见[构建与移植](06-构建与移植.md)第 8 节。
- 模块包（`asnber-pkix`、`asnber-cms`、`asnber-pkcs`、`asnber-pkcs1`、`asnber-pkcs8`、`asnber-pkcs10`、`asnber-pkcs12`）各自声明版本，安装到独立 `lib/cmake/<pkg>`；模块配置使用 `find_dependency(asnber <最低版本> CONFIG)` 声明对核心的最低版本要求。`asnber-pkcs` 聚合包额外 `find_dependency` 四个实现包。
- **符号增量的版本门槛**：当前导出符号基线为 `asnber` 73、`asnber-pkix` 57、`asnber-pkcs1` 31、`asnber-pkcs8` 27、`asnber-pkcs10` 25、`asnber-pkcs12` 37、`asnber-cms` 148，共 **7 个包**（`asnber-pkcs` 不产库、不导符号，无基线文件；记录见 [`abi/README.md`](../abi/README.md)）。包版本字符串是 0.1.1。自 0.1.0 起，`asnber-pkix` 增加了 CertificateList 读写（含 CRL 扩展与条目扩展），`asnber-pkcs8` 增加了 EncryptedPrivateKeyInfo builder。此后任何**新增导出符号**都必须进入 minor 或 major 版本，**不得在 patch 版本中新增符号**；删除、改名或改变既有符号语义只能进入 major。`scripts/check_exports.py` 只校验基线与实际导出一致，不替代版本决策。
- 只导出 `ASNBER_API` 标记的符号；内部 C++ 符号默认隐藏（`CXX_VISIBILITY_PRESET hidden`）。
- 不导出 C++ 符号、RTTI 信息或模板实例；公共头文件不要求消费者使用 C++。
- 核心 ABI 稳定期内，模块可在自身次版本内独立升级；模块跨主版本升级同时要求兼容的核心 ABI 范围。
- **已发布符号不得改名或删除**：PKCS#12 的 `asnber_pkcs12_*`（0.1.0 基线 37 个）是前缀例外。未来若统一为 `asnber_pkcs_`，只能在**下一个 minor 版本**新增别名，并保留旧符号至少一个次版本周期，不得重命名或删除既有符号。

## 12. 典型调用示例（C）

```c
#include <asnber/asnber.h>
#include <stdio.h>

static const unsigned char kInput[] = {0x02, 0x01, 0x2A}; /* INTEGER 42 */

int main(void)
{
    asnber_ctx_config_t config;
    asnber_decode_options_t options;
    asnber_ctx_t *ctx = NULL;
    asnber_doc_t *doc = NULL;
    const asnber_node_t *root;
    int64_t value = 0;
    asnber_err_t rc;

    asnber_ctx_config_init(&config);
    rc = asnber_ctx_create(&config, &ctx);
    if (rc != ASNBER_OK) {
        printf("create failed: %d\n", (int)rc);
        return 1;
    }

    asnber_decode_options_init(&options);
    options.encoding = ASNBER_ENCODING_DER;
    rc = asnber_decode_buffer(ctx, kInput, sizeof(kInput), &options, &doc, NULL);
    if (rc != ASNBER_OK) {
        asnber_error_info_t info;
        info.struct_size = sizeof(info);
        if (asnber_ctx_get_error(ctx, &info) == ASNBER_OK) {
            printf("decode failed: %s (offset=%zu, depth=%u, path=%s)\n",
                   info.message, info.offset, (unsigned)info.depth,
                   info.path ? info.path : "-");
        }
        asnber_ctx_destroy(ctx);
        return 1;
    }

    root = asnber_doc_root(doc);
    if (asnber_node_get_int64(root, &value) == ASNBER_OK) {
        printf("value=%lld\n", (long long)value);
    }

    asnber_doc_destroy(doc);
    asnber_ctx_destroy(ctx);
    return 0;
}
```

编码侧同理：`asnber_encode_buffer(ctx, doc, &options, &buf)`，其中 `options.encoding = ASNBER_ENCODING_DER`；使用完毕后 `asnber_buf_release(ctx, &buf)`；或提供 writer 回调直接写入文件/网络。

runtime 构树示例：

```c
asnber_doc_t *built = NULL;
asnber_node_t *root = NULL;
asnber_node_t *child = NULL;
asnber_encode_options_t enc;
asnber_buf_t buf = {0};

/* 构造 SEQUENCE { INTEGER 1 }；标签号常量见 asnber/asnber_tag.h */
asnber_doc_create(ctx, &built);
asnber_node_create(built, NULL, ASNBER_TAG_UNIVERSAL,
                 ASNBER_UNIVERSAL_SEQUENCE, ASNBER_CONSTRUCTED, &root);
asnber_node_create(built, root, ASNBER_TAG_UNIVERSAL,
                 ASNBER_UNIVERSAL_INTEGER, ASNBER_PRIMITIVE, &child);
asnber_node_set_int64(child, 1);
asnber_doc_seal(built);

asnber_encode_options_init(&enc);
asnber_encode_buffer(ctx, built, &enc, &buf);
asnber_buf_release(ctx, &buf);
asnber_doc_destroy(built);
```

`ASNBER_UNIVERSAL_*` 与 `ASNBER_PRIMITIVE` / `ASNBER_CONSTRUCTED` 定义在 `asnber/asnber_tag.h`，由核心伞头 `asnber/asnber.h` 包含。`tag_number` 仍是 X.690 标签号，不是完整 identifier octet；库不会根据标签号推导 `constructed`，调用方必须为 `SEQUENCE`/`SET` 传 `ASNBER_CONSTRUCTED`，为基本类型传 `ASNBER_PRIMITIVE`。

模板加载与 schema 感知解码：

```c
asnber_schema_table_t table = {0};
asnber_schema_t *schema = NULL;
asnber_doc_t *doc = NULL;
size_t consumed = 0;

table.struct_size = sizeof(table);
table.data = kExampleTable;       /* 由 asnberc 生成，模块/宿主提供 */
table.size = sizeof(kExampleTable);
table.format_version = (1u << 16) | 0;   /* 主版本 1、次版本 0 */
if (asnber_schema_load(ctx, &table, &schema) != ASNBER_OK) { /* 处理错误 */ }
if (asnber_decode_buffer_with_schema(ctx, data, size, schema,
                                   &options, &doc, &consumed) != ASNBER_OK) {
    /* 处理错误；options 的 flags 已在 5.1 定义 */
}

const asnber_node_t *root = asnber_doc_root(doc);
const asnber_node_t *value = asnber_node_child_by_name(root, "value");
/* 模块 API 可在此基础上做字段路径封装 */
asnber_doc_destroy(doc);
asnber_schema_destroy(schema);
```

## 13. 公共头文件约束清单

- 只允许包含 `<stddef.h>`、`<stdint.h>` 等 C 标准头；不使用 `<stdbool.h>` 与 `bool`，布尔语义统一用 `int`（0/非 0）。
- 不使用 `//` 之外的花哨扩展；C99 注释风格兼容 MSVC C 编译器。
- 不用 `_Generic`、指定初始化器、匿名结构体等 C11/C23 特性。
- 不定义带副作用的宏；函数式宏只在无法用 `static inline` 时使用。
- 所有核心函数声明带 `ASNBER_API`，模块函数声明带 `ASNBER_<模块>_API`；不导出变量（版本字符串通过函数返回）。
- 公共枚举显式赋值，避免默认递增值随插入变化。
- 核心头文件不得包含模块头、不得出现领域词；模块头文件不得包含 `src/` 内部头，也不得要求包含核心未公开的符号。
