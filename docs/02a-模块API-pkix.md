# asnber-pkix 模块 API

本节原为 [C API 设计规范](02-C-API规范.md) 6.8；模块 API 单独成页，核心规范只保留索引。

`asnber-pkix` 是独立包（`find_package(asnber-pkix CONFIG)`），只依赖核心公共 C ABI。公共头为 `<asnber/pkix/pkix.h>`，导出宏 `ASNBER_PKIX_API`，静态链接时宏 `ASNBER_PKIX_STATIC`。

```c
typedef struct asnber_pkix_certificate asnber_pkix_certificate_t;

const char *asnber_pkix_version_string(void);

asnber_err_t asnber_pkix_certificate_open(asnber_ctx_t *ctx,
                                       const uint8_t *der, size_t der_size,
                                       asnber_pkix_certificate_t **out_cert);
void asnber_pkix_certificate_close(asnber_pkix_certificate_t *cert);

asnber_err_t asnber_pkix_certificate_find(const asnber_pkix_certificate_t *cert,
                                       const char *path,
                                       const asnber_node_t **out_node);

asnber_err_t asnber_pkix_certificate_signature_algorithm_oid(
    const asnber_pkix_certificate_t *cert, const char **out_dotted,
    size_t *out_size);
asnber_err_t asnber_pkix_certificate_signature_value(
    const asnber_pkix_certificate_t *cert, const uint8_t **out_data,
    size_t *out_size, size_t *out_bit_length, uint8_t *out_unused_bits);
asnber_err_t asnber_pkix_certificate_serial_number(
    const asnber_pkix_certificate_t *cert, const char **out_decimal,
    size_t *out_size);
asnber_err_t asnber_pkix_certificate_version(
    const asnber_pkix_certificate_t *cert, uint32_t *out_version);
asnber_err_t asnber_pkix_certificate_issuer_der(
    const asnber_pkix_certificate_t *cert, const uint8_t **out_data,
    size_t *out_size);
asnber_err_t asnber_pkix_certificate_subject_der(
    const asnber_pkix_certificate_t *cert, const uint8_t **out_data,
    size_t *out_size);
asnber_err_t asnber_pkix_certificate_validity(
    const asnber_pkix_certificate_t *cert, asnber_time_t *out_not_before,
    asnber_time_t *out_not_after);
```

语义：

- `open` 用模块随包发布的 PKIX 描述表加载 schema，再以 `ASNBER_ENCODING_DER` + `ASNBER_DECODE_COPY_INPUT` 解码；DER 被复制进文档，调用方可在返回后释放输入。空参 `ASNBER_E_INVALID_ARG`，分配失败 `ASNBER_E_NOMEM`，截断/尾随/语法错误/Certificate schema 不符由核心错误码直接返回。
- 句柄借用调用方的 `asnber_ctx_t`，ctx 必须比句柄存活更久；`close(NULL)` 为空操作。
- `find` 的路径以 `.` 分隔、相对 Certificate 根，空串表示根。为便于使用，接受 RFC 5280 常用名并映射到展平模块的具名字段：`tbsCertificate` → `toBeSigned`、`signatureAlgorithm` → `algorithmIdentifier`、`signatureValue` → `signature`。路径不存在（含 DEFAULT/OPTIONAL 缺省）返回 `ASNBER_OK` 且 `*out_node = NULL`；空段返回 `ASNBER_E_INVALID_ARG`。
- 便捷访问器返回借用于句柄的指针：OID 点分文本、BIT STRING 内容（`out_bit_length = out_size * 8 - out_unused_bits`）、序列号大整数十进制文本、issuer/subject 完整原始 DER。`version` 返回 0/1/2（v1/v2/v3），DEFAULT v1 缺省为 0。
- `validity` 的两个 `asnber_time_t.struct_size` 必须由调用方初始化；失败不写部分输出。
- ANY 字段（如 `algorithmIdentifier.parameters`）只返回原始完整 TLV 节点，`child_count = 0`；模块不做算法参数展开，调用方按 OID 二次解析。

线程与缓存：模块没有全局可变状态。schema 在每次 `open` 时从模块内静态表加载，随句柄存活、`close` 时销毁，因此不同 `asnber_ctx_t` 各自持有一份，互不串状态；同一 ctx 的并发调用仍需由调用方加锁（核心错误状态挂在 ctx 上）。模块不新增错误码，全部复用核心 1000–8999 错误空间。

描述表发布机制：`modules/pkix/generated/pkix_schema.{h,bin}` 检入仓库并随源码发布；默认构建直接使用检入产物，无需 `asnberc`。`-DASNBER_PKIX_REGENERATE_TABLE=ON` 时在构建期用 `asnberc` 从 `PKIX-Flattened-2009.asn1` 重新生成，并与检入产物逐字节比对，任一差异即构建失败。

## Certificate / TBSCertificate 构造

```c
typedef struct asnber_pkix_certificate_builder asnber_pkix_certificate_builder_t;

typedef struct asnber_pkix_name_attribute {
    const char *oid;            /* 点分 OID，如 "2.5.4.3" */
    const uint8_t *value;       /* 原始字符串字节 */
    size_t value_size;
    uint32_t string_tag;        /* 0 = 按 OID 选择；否则 12/19/22 */
} asnber_pkix_name_attribute_t;

typedef struct asnber_pkix_name_rdn {
    const asnber_pkix_name_attribute_t *attributes;
    size_t count;               /* 必须 >= 1 */
} asnber_pkix_name_rdn_t;

asnber_err_t asnber_pkix_certificate_builder_create(asnber_ctx_t *ctx,
                                                asnber_pkix_certificate_builder_t **out);
void asnber_pkix_certificate_builder_destroy(asnber_pkix_certificate_builder_t *builder);

asnber_err_t asnber_pkix_certificate_builder_set_version(builder, int32_t version);
asnber_err_t asnber_pkix_certificate_builder_set_serial_number(
    builder, const uint8_t *magnitude, size_t size);
asnber_err_t asnber_pkix_certificate_builder_set_signature_algorithm(
    builder, const char *oid, const uint8_t *parameters, size_t parameters_size);
asnber_err_t asnber_pkix_certificate_builder_set_issuer(
    builder, const asnber_pkix_name_rdn_t *rdns, size_t rdn_count);
asnber_err_t asnber_pkix_certificate_builder_set_validity(
    builder, const asnber_time_t *not_before, const asnber_time_t *not_after);
asnber_err_t asnber_pkix_certificate_builder_set_subject(
    builder, const asnber_pkix_name_rdn_t *rdns, size_t rdn_count);
asnber_err_t asnber_pkix_certificate_builder_set_subject_public_key_algorithm(
    builder, const char *oid, const uint8_t *parameters, size_t parameters_size);
asnber_err_t asnber_pkix_certificate_builder_set_subject_public_key(
    builder, const uint8_t *bits, size_t size, uint8_t unused_bits);
asnber_err_t asnber_pkix_certificate_builder_set_issuer_unique_id(
    builder, const uint8_t *bits, size_t size, uint8_t unused_bits);
asnber_err_t asnber_pkix_certificate_builder_set_subject_unique_id(
    builder, const uint8_t *bits, size_t size, uint8_t unused_bits);

asnber_err_t asnber_pkix_certificate_builder_add_extension(
    builder, const char *oid, int critical,
    const uint8_t *value, size_t value_size);
asnber_err_t asnber_pkix_certificate_builder_add_basic_constraints(
    builder, int critical, int is_ca, int has_path_len, uint32_t path_len);
asnber_err_t asnber_pkix_certificate_builder_add_key_usage(
    builder, int critical, const uint8_t *bits, size_t size,
    uint8_t unused_bits);
asnber_err_t asnber_pkix_certificate_builder_add_extended_key_usage(
    builder, int critical, const char *const *oids, size_t count);

asnber_err_t asnber_pkix_certificate_builder_set_signature_value(
    builder, const uint8_t *bits, size_t size, uint8_t unused_bits);
asnber_err_t asnber_pkix_certificate_builder_encode(
    builder, asnber_buf_t *out_der);
```

语义：

- 所有 `set_*`/`add_*` 深拷贝输入，调用返回后可立即释放缓冲；同一字段重复设置返回 `ASNBER_E_INVALID_STATE`。
- `set_version` 只接受 0..2。`version = 0` 视为 DEFAULT v1，构建时不写 `[0] EXPLICIT`；未调用 `set_version` 与显式设 0 等价。
- `set_serial_number` 接收无符号大端幅值：去掉冗余前导零，最高位为 1 时补前导 `00`，空输入拒绝。
- Name 以 RDN 数组表达：RDN 之间保持数组顺序，RDN 内部属性顺序不排序，最终 `SET OF` 字节序由核心 DER 编码完成。`string_tag = 0` 时按 OID 选择：`2.5.4.6`/`2.5.4.5`/`2.5.4.46` → PrintableString，`0.9.2342.19200300.100.1.25`/`1.2.840.113549.1.9.1` → IA5String，其余 → UTF8String；显式给出时必须为 12/19/22。
- 有效期只接受可精确写为 `Z` 的时间（1950..2049 用 UTCTime，其余用 GeneralizedTime）；带偏移、本地时间或小数秒返回 `ASNBER_E_INVALID_VALUE`。
- BIT STRING 的 `unused_bits` 必须小于 8；空串只能为 `0x00` 且 `unused_bits = 0`；填充位必须为零。
- 扩展采用“通用 TLV + 高频便捷函数”混合方案：`add_extension` 接受完整扩展值 DER（如 SAN 的 `SEQUENCE` 编码），`add_basic_constraints`/`add_key_usage`/`add_extended_key_usage` 生成常用值。三条 DER 约束在构建期强制：`critical = 0` 时完全省略 BOOLEAN；`pathLenConstraint` 仅在 `is_ca != 0` 时允许；同一 Extensions 内 OID 重复返回 `ASNBER_E_INVALID_VALUE`。
- `encode` 要求各必填字段齐全（version 可缺省），成功后返回新分配缓冲，由 `asnber_buf_release(ctx, &buf)` 释放；失败清空输出。
- 同一签名算法同时写入 `TBSCertificate.signature` 与 `Certificate.signatureAlgorithm`，两者不做二次比较。

## CertificateList 构造与读取

`asnber_pkix_crl_open` 打开 DER 编码的 `CertificateList`。路径别名：`tbsCertList` → `toBeSigned`、`signatureAlgorithm` → `algorithmIdentifier`、`signatureValue` → `signature`。`version` 缺省为 0。`nextUpdate` 缺省时 `*out_present = 0`。吊销项只读序列号（十进制）和 `revocationDate`。

扩展读取：`asnber_pkix_crl_extension_count` / `extension_at` 读 `crlExtensions`；`asnber_pkix_crl_entry_extension_count` / `entry_extension_at` 读某条吊销记录的 `crlEntryExtensions`。字段缺省时条数为 0。`critical` 缺省为 0。`extnValue` 返回 OCTET STRING 内容，借用句柄。

`asnber_pkix_crl_builder_*` 组装同一结构。`set_version` 只接受 0 或 1；0 省略 INTEGER。`add_revoked` 追加序列号与吊销时间。`add_extension` 与 `add_entry_extension` 写入扩展，`extn_value_der` 是一条完整 DER TLV，同一集合内 OID 不得重复。出现任一扩展时 `version` 必须为 1，否则 `encode` 返回 `ASNBER_E_INVALID_VALUE`。builder 不解释扩展，也不判断吊销。

cert-decode 裁剪表不含 `CertificateList`，对该表调用 `open` 会失败。完整表的根类型编号是 28。
