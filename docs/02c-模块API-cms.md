# asnber-cms 模块 API

本节原为 [C API 设计规范](02-C-API规范.md) 6.10–6.14；模块 API 单独成页，核心规范只保留索引。6.15–6.18 为后续结构分块续补，编号顺延。

## 6.10 asnber-cms 模块 API

`asnber-cms` 是独立包（`find_package(asnber-cms CONFIG)`），只依赖核心公共 C ABI，**不依赖 asnber-pkix**（ADR-0012；从 `ContentInfo`/`SignedData`/`EnvelopedData`/`EncryptedData`/`CompressedData`/`AuthenticatedData` 可达的 PKIX 类型已复制进本模块展平源）。公共头为伞头 `<asnber/cms/cms.h>`，按结构和 builder 拆为 `cms_types.h` 等子头；导出宏 `ASNBER_CMS_API`，静态链接时宏 `ASNBER_CMS_STATIC`。只读侧 6 个不透明句柄各由 `open` 创建、`close` 销毁（`close(NULL)` 为空操作）：`ContentInfo`、`SignedData`、`EnvelopedData`、`EncryptedData`、`CompressedData`、`AuthenticatedData`；构造侧有 5 个句柄：`asnber_cms_builder_t`（ContentInfo 内嵌 SignedData）、`asnber_cms_enveloped_builder_t`（ContentInfo 内嵌 EnvelopedData）、`asnber_cms_encrypted_builder_t`（ContentInfo 内嵌 EncryptedData）、`asnber_cms_compressed_builder_t`（ContentInfo 内嵌 CompressedData）与 `asnber_cms_authenticated_builder_t`（ContentInfo 内嵌 AuthenticatedData），各由对应 `create` 创建、`destroy` 销毁。

语义：

- `open` 用模块随包发布的描述表加载 schema，再以 `ASNBER_ENCODING_DER` + `ASNBER_DECODE_COPY_INPUT` 解码；输入被复制进文档，调用方可在返回后释放。空参 `ASNBER_E_INVALID_ARG`，分配失败 `ASNBER_E_NOMEM`，截断/尾随/语法错误/结构不符由核心错误码直接返回。
- 句柄借用调用方的 `asnber_ctx_t`，ctx 必须比句柄存活更久；访问器返回的指针（OID 文本、大整数十进制文本、字节/TLV）借用句柄，`close` 后失效；下标越界 `ASNBER_E_INVALID_ARG`。
- 只读边界：不验签、不计算摘要、不解密、不校验证书链、不查询吊销状态。`ContentInfo.content`、`AlgorithmIdentifier.parameters`、`SignerInfo.signedAttrs`/`unsignedAttrs`、属性值等一律只给完整原始 TLV/字节，`ANY` 不按 OID 展开，密码学语义由调用方二次解析。
- `ContentInfo.content` 返回 `[0] EXPLICIT` 包装内层 ANY 的完整 TLV（不含 `[0]`），可直接交给 `asnber_cms_signed_data_open`；`certificates` / `crls` 为 `[0]` / `[1] IMPLICIT` SET，逐项按实际标签判别 `ASNBER_CMS_CERT_CHOICE_*` / `ASNBER_CMS_REVOCATION_CHOICE_*`；`certificate_at` 对所有分支都返回 `kind` 与完整原始 TLV；只有 `certificate` 分支提供 `subject`/`issuer` 原始 TLV 与 `serialNumber` 十进制文本，`extendedCertificate`、`v1AttrCert`、`v2AttrCert`、`other` 分支的结构化访问器返回 `ASNBER_E_UNSUPPORTED`。
- `SignerInfo.sid` 分两支：`ASNBER_CMS_SID_ISSUER_AND_SERIAL`（`issuer` 原始 TLV + `serial` 十进制文本）与 `ASNBER_CMS_SID_SUBJECT_KEY_IDENTIFIER`（内容字节）；不符分支的访问器返回 `ASNBER_E_INVALID_ARG`。`version` 与 `CMSVersion` 均原样返回，不做范围校验。
- 缺省字段（detached 的 `eContent`、无证书/CRL、无 `signedAttrs`/`unsignedAttrs`）返回 `ASNBER_OK` 且 `NULL/0`，与字段缺失可区分于错误。
- 结构构造（写）：`asnber_cms_builder_create` / `asnber_cms_builder_destroy` 提供 ContentInfo（内嵌 SignedData）builder，只做结构组装与 DER 编码。实现只用核心公共 ABI（含 `asnber_node_create_any`）与随包描述表，不新增编码器。生命周期为 create → 设置/追加 → `asnber_cms_builder_encode` → destroy；`destroy(NULL)` 为空操作，**同一句柄只能 destroy 一次**，重复 destroy 或使用已销毁指针为未定义行为（句柄指针归调用方所有，库无法置空）；builder 无全局状态；输入字节在调用返回时已复制，调用方可立即释放原缓冲。
- builder 必填项：`CMSVersion`、至少一条 `digestAlgorithm`、`eContentType`、至少一个 signer。缺失或重复设置单值字段返回 `ASNBER_E_INVALID_STATE`；OID 非法、根标签/分支不符返回 `ASNBER_E_INVALID_VALUE`；非单一完整规范 TLV 返回 `ASNBER_E_TRUNCATED` / `ASNBER_E_MALFORMED_LENGTH` / `ASNBER_E_TRAILING_DATA` / `ASNBER_E_NON_CANONICAL` 等核心错误码。`encode` 失败时输出缓冲清零，不产出半成品；成功时缓冲由上下文分配，调用方用 `asnber_buf_release` 归还。
- `CMSVersion` 与 `SignerInfo.version` 由调用方显式给值，模块不推导、不校验范围。`sid` 为 `issuerAndSerialNumber` 时，`issuer` 必须是 `SEQUENCE`、`serialNumber` 必须是 `INTEGER`；标签不符返回 `ASNBER_E_INVALID_VALUE`。
- `signedAttrs` / `unsignedAttrs` 原样承载：输入必须是完整、规范的 `SET OF` TLV（外层 `0x31`），集合非空且每个元素为 `SEQUENCE`（`Attribute`）；模块只把外层标签改写为 `0xA0` / `0xA1`，长度字节与内容逐字节不变，不重建、不排序。签名覆盖的是 `SET OF` 编码，调用方必须对同一份字节签名。非规范输入返回 `ASNBER_E_NON_CANONICAL`；空集合或元素不是 `SEQUENCE` 返回 `ASNBER_E_INVALID_VALUE`。
- `certificates` / `crls` 在单 TLV 校验之外检查分支根标签：证书必须为 `Certificate` 的 `SEQUENCE` 或 `[0..3]` 备选，CRL 必须为 `CertificateList` 的 `SEQUENCE` 或 `other [1]`；不解析内部、不做信任判断；输出按 DER `SET OF` 规则排序。
- 构造侧不提供签名生成、摘要计算、加解密、证书链校验；`signature` 由调用方给出 OCTET STRING 内容字节，模块只负责结构编码。
- 模块不新增错误码，全部复用核心 1000–8999 错误空间；模块无全局可变状态，同一 ctx 的并发使用需调用方加锁。
- 描述表发布机制：`modules/cms/generated/` 只检入一张 `cms_schema`（`.bin` + 描述头），头部默认根 `ContentInfo`，默认构建不依赖 `asnberc`；`-DASNBER_CMS_REGENERATE_TABLE=ON` 在构建期重新生成并与检入产物逐字节比对（`asnber_cms_table_verify`），差异即失败。`SignedData` / `EnvelopedData` / `EncryptedData` / `CompressedData` / `AuthenticatedData` 通过 `asnber_schema_load_with_root` 在加载期指定根类型编号（`3/48/72/73/75`，登记在 `src/cms_tables.h`）。表含整模块类型池，新增类型会让表重新生成；类型编号是描述表内部引用、会随模块类型增长而重排，检入表的逐字节不变**不是**回归契约（见 [11-描述表格式](11-描述表格式.md) 第 5 节）。

### 6.11 asnber-cms EnvelopedData 只读 API（0.2.0 第一块）

`EnvelopedData` 使用只读句柄 `asnber_cms_enveloped_data_t`，由 `asnber_cms_enveloped_data_open` 创建、`close` 销毁（`close(NULL)` 为空操作）。新增 27 个 `asnber_cms_enveloped_data_*` 导出符号；不新增核心 ABI、不新增错误码，错误码沿用核心 `asnber_err_t` 语义。

语义：

- `open` 只接受**裸 `EnvelopedData`**（不含外层 `ContentInfo`）：调用方先用 `asnber_cms_content_info_open` + `asnber_cms_content_info_content` 取 `[0]` 内层 TLV，再传入本函数；模块不提供自动剥壳入口。`recipientInfos` 的 `SET SIZE (1..MAX)` 由描述表生效，空集合在 `open` 阶段返回 `ASNBER_E_SCHEMA_CONSTRAINT`。
- `recipientInfos` 逐项判别：`ktri` 在 RFC 5652 中**无标签**（裸 `SEQUENCE`），`kari`/`kekri`/`pwri`/`ori` 分别为 `[1]`/`[2]`/`[3]`/`[4]`（RFC 3852 的 `ktri [0]` 不适用于本模块）；判别值见 `ASNBER_CMS_RECIPIENT_*`，`recipient_tlv` 对全部分支返回完整原始 TLV。
- `ktri.rid` 分两支（`ASNBER_CMS_RID_*`）：`issuerAndSerialNumber` 给 issuer 与 serialNumber 完整原始 TLV（issuer **不解析 RDN**），serialNumber 另给严格十进制文本（缓冲不足返回 `ASNBER_E_INVALID_ARG`）；`subjectKeyIdentifier` 给内容字节。分支不符返回 `ASNBER_E_UNSUPPORTED`。
- `kekri` 给 `kekid.keyIdentifier` 内容字节；`pwri` 给 `keyDerivationAlgorithm` 的 `[0] IMPLICIT` 完整 TLV（字段缺省返回 `ASNBER_OK` 且 `NULL/0`）；`ori` 给 `oriType` OID 文本与 `oriValue` 完整原始 TLV。
- `kari.originator` 判别 `ASNBER_CMS_ORIGINATOR_*`（`issuerAndSerialNumber` / `subjectKeyIdentifier` / `publicKey`）并给 `[0] EXPLICIT` 包装的完整原始 TLV；`recipientEncryptedKeys` 只给元素个数，不展开内部。
- `encryptedContent` 是 `[0] IMPLICIT OCTET STRING`，内容按核心既有 BER 构造形式合并规则展平：给合并字节与完整 TLV（含 `[0]` 标签），**不分段**、不提供分片视图。
- `version`、`EncryptedContentInfo.contentType`、`contentEncryptionAlgorithm`（OID + parameters 原始 TLV）、`originatorInfo [0]`、`unprotectedAttrs [1] IMPLICIT` 均原样给值，不做范围校验。
- 只读边界：不解密、不做密钥协商、不做 KEK/口令派生、不校验 MAC、不解析 `encryptedKey`/`oriValue`/属性内容；密码学语义由调用方按 OID 二次解析。
- 缺省字段（`originatorInfo`、`unprotectedAttrs`、`pwri.keyDerivationAlgorithm`、无 `encryptedContent`）返回 `ASNBER_OK` 且 `NULL/0`；下标越界 `ASNBER_E_INVALID_ARG`；分支不适用统一 `ASNBER_E_UNSUPPORTED`。
- `_recipient_rid_serial_decimal` 的出参语义：成功时 `buf` 写入 NUL 结尾的十进制串，`*out_size` 为**不含 NUL 的字符数**；`buf_size` 必须至少为 `字符数 + 1`，否则返回 `ASNBER_E_INVALID_ARG`（不部分写入、不截断）。缓冲区与 `out_size` 均不得为 `NULL`。
- 句柄生命周期：句柄借用创建它的 `asnber_ctx_t`，所有访问器都在该 `ctx` 内解码/取指针；**句柄不得晚于 `ctx` 销毁**（必须先 `close` 句柄再 `asnber_ctx_destroy`）。句柄与跨 `ctx` 混用（例如用 A 的句柄传给 B 的 `ctx`，或在 `ctx` 销毁后调用任何访问器）行为未定义，模块不做检测。返回的指针借用句柄内部节点，`close` 后失效。

### 6.12 asnber-cms EnvelopedData 写侧 API（0.2.0 第二块）

`asnber_cms_enveloped_builder_t` 用于组装 `ContentInfo { contentType = id-envelopedData, content = [0] EXPLICIT EnvelopedData }`。新增 14 个 `asnber_cms_enveloped_builder_*` 导出符号；不新增核心 ABI、不新增错误码。生命周期为 `create` → 设置/追加 → `encode` → `destroy`；`destroy(NULL)` 为空操作，**同一句柄只能 destroy 一次**，重复 destroy 或使用已销毁指针为未定义行为（句柄指针归调用方所有，库无法置空）。builder 借用调用方的 `asnber_ctx_t`，**句柄不得晚于其 `ctx` 销毁**；跨 `ctx` 使用（含 `ctx` 销毁后调用任何接口）行为未定义。输入字节在调用返回时复制，builder 无全局状态。

| 函数 | 语义 |
| --- | --- |
| `_create` / `_destroy` | 创建/销毁 builder；`create` 借用调用方 `ctx` |
| `_set_version` | `EnvelopedData.version`，必填；重复设置 `ASNBER_E_INVALID_STATE` |
| `_set_originator_info` | 可选 `[0] IMPLICIT OriginatorInfo` 完整 TLV（`0xA0`）；子节点只能是可选的 `certs [0]`（`0xA0`）与 `crls [1]`（`0xA1`），顺序固定、各至多一次 |
| `_add_ktri` | 追加 `ktri`；`rid` 支持 issuerAndSerialNumber（issuer `SEQUENCE` + serial `INTEGER`）与 subjectKeyIdentifier（非空内容） |
| `_add_kari` | 追加 `kari`；`originator [0] EXPLICIT` 子节点须为 `SEQUENCE`/`0x80`/`0xA1` 三支之一；`ukm [1] EXPLICIT` 子节点须为 OCTET STRING；`recipientEncryptedKeys` 允许空序列，每个元素依次为 `rid`（SEQUENCE 或 `[0]` constructed）与 OCTET STRING |
| `_add_kekri` | 追加 `kekri`；`KEKIdentifier` 以完整 `SEQUENCE` TLV 传入，首子节点须为 OCTET STRING，其后可选 GeneralizedTime 与 SEQUENCE，顺序固定 |
| `_add_pwri` | 追加 `pwri`；可选 `[0] IMPLICIT AlgorithmIdentifier` KDF 完整 TLV，子节点须为 OID 加可选 parameters |
| `_add_ori` | 追加 `ori`；`oriType` 为合法 OID，`oriValue` 为恰好一个完整 TLV |
| `_set_content_type` | `EncryptedContentInfo.contentType`，必填 |
| `_set_content_encryption_algorithm` | OID + `parameters` 完整 TLV，必填 |
| `_set_encrypted_content` | `encryptedContent` 内容字节；不设置即 detached，允许空内容；`NULL + size≠0` 拒绝 |
| `_set_unprotected_attrs` | `[1] IMPLICIT SET OF Attribute`；输入外层 `0x31`，模块只改写为 `0xA1`，内容逐字节不变 |
| `_encode` | 校验必填项并输出 DER `ContentInfo`；失败时缓冲清零，成功时由 `ctx` 分配、调用方 `asnber_buf_release` 归还 |

语义与边界：

- 必填项为 `version`、至少一个 recipient、`contentType`、`contentEncryptionAlgorithm`；缺失或重复设置单值字段返回 `ASNBER_E_INVALID_STATE`。
- 预构造 TLV 不只看根标签：`originatorInfo`、kari 的 `originator`/`ukm`、`KEKIdentifier`、`recipientEncryptedKeys` 与 PWRI KDF 会校验直接子节点的标签、构造位、顺序与重复；这些子结构按 ANY 原样承载，schema 编码器不再复查内部，因此写侧校验以这一步为准。`SET OF` 非空、OID 合法性、TLV 截断/尾随/非规范等分别返回 `ASNBER_E_INVALID_VALUE`、`ASNBER_E_TRUNCATED`、`ASNBER_E_TRAILING_DATA`、`ASNBER_E_NON_CANONICAL` 等核心错误码；失败的追加/设置调用不改变 builder 已有状态。
- 五个 recipient 分支按调用顺序收集，编码时按 DER `SET OF` 规则排序；`originatorInfo` 与 `unprotectedAttrs` 至多设置一次。
- 写侧不推导版本、不做密钥协商/KEK/口令派生、不生成内容密钥或密文、不计算 MAC；所有密码学值由调用方提供并原样承载。

### 6.13 asnber-cms EncryptedData 只读 API（0.2.0 第三块）

`EncryptedData` 使用只读句柄 `asnber_cms_encrypted_data_t`，由 `asnber_cms_encrypted_data_open` 创建、`close` 销毁（`close(NULL)` 为空操作）。新增 8 个 `asnber_cms_encrypted_data_*` 导出符号；不新增核心 ABI、不新增错误码。

语义：

- `open` 只接受**裸 `EncryptedData`**（不含外层 `ContentInfo`）：调用方先用 `asnber_cms_content_info_open` + `asnber_cms_content_info_content` 取 `[0]` 内层 TLV，再传入本函数；模块不提供自动剥壳入口。`version` 与 `encryptedContentInfo` 为必填，缺失由描述表在 `open` 阶段拒绝。
- `version` 原样返回，**不做范围校验**，也不校验 RFC 5652 的配对约束（无 `unprotectedAttrs` 时应为 0、有时应为 2）；需要断言的调用方自行比较。构造侧在 `encode` 时执行该配对校验（见 6.14）。
- `content_type` 给 `EncryptedContentInfo.contentType` 的 OID 文本；`content_encryption_algorithm` 给 OID 文本与 `parameters` 完整原始 TLV（缺省时 `NULL/0`）。
- `encrypted_content` 是 `[0] IMPLICIT OCTET STRING`，返回内容字节（不含 `[0]` 标签），构造形式按核心既有 BER 合并规则展平，**不分段**。空内容 `80 00` 返回 `ASNBER_OK`、非 `NULL` 指针且 `*out_size == 0`；字段整体缺省（detached）返回 `ASNBER_OK` 且 `NULL/0`，两者可区分。
- `encrypted_content_tlv` 与 `unprotected_attrs_tlv` 返回含上下文标签的完整原始 TLV（分别为 `0x80` / `0xA1`）；字段缺省时返回 `ASNBER_OK` 且 `NULL/0`。
- 只读边界：不解密、不派生密钥、不校验 MAC、不展开 `contentEncryptionAlgorithm.parameters` 或属性内容；密码学语义由调用方按 OID 二次解析。
- 句柄生命周期与指针借用规则同 6.11：句柄借用创建它的 `asnber_ctx_t`，不得晚于 `ctx` 销毁；访问器返回的指针借用句柄内部节点，`close` 后失效；跨 `ctx` 混用行为未定义。

### 6.14 asnber-cms EncryptedData 写侧 API（0.2.0 第四块）

`asnber_cms_encrypted_builder_t` 用于组装 `ContentInfo { contentType = id-encryptedData, content = [0] EXPLICIT EncryptedData }`。新增 8 个 `asnber_cms_encrypted_builder_*` 导出符号；不新增核心 ABI、不新增错误码。生命周期、`ctx` 借用与销毁契约同 6.12（`destroy(NULL)` 为空操作，同一句柄只能 destroy 一次）。

| 函数 | 语义 |
| --- | --- |
| `_create` / `_destroy` | 创建/销毁 builder；`create` 借用调用方 `ctx` |
| `_set_version` | `EncryptedData.version`，必填；只接受 `0` / `2`，其他值立即返回 `ASNBER_E_INVALID_VALUE`；与 `unprotectedAttrs` 的配对在 `encode` 校验 |
| `_set_content_type` | `EncryptedContentInfo.contentType`，必填，合法 OID |
| `_set_content_encryption_algorithm` | OID + `parameters` 完整 TLV，必填 |
| `_set_encrypted_content` | `encryptedContent` 内容字节；不调用即 detached，允许空内容；`NULL + size≠0` 拒绝 |
| `_set_unprotected_attrs` | `[1] IMPLICIT SET OF Attribute`；输入外层 `0x31`、非空且元素为 `SEQUENCE`，模块只改写为 `0xA1`，内容逐字节不变 |
| `_encode` | 校验必填项与版本配对并输出 DER `ContentInfo`；失败时缓冲清零，成功时由 `ctx` 分配、调用方 `asnber_buf_release` 归还 |

语义与边界：

- 必填项为 `version`、`contentType`、`contentEncryptionAlgorithm`；缺失或重复设置单值字段返回 `ASNBER_E_INVALID_STATE`。
- `version` 只接受 `0` / `2`：`_set_version` 对其他值立即返回 `ASNBER_E_INVALID_VALUE`，不留到编码期；失败调用不改变 builder 状态，随后仍可设置合法版本。
- 版本配对在 `encode` 时强制：有 `unprotectedAttrs` 必须 `version == 2`，无 `unprotectedAttrs` 必须 `version == 0`；不一致返回 `ASNBER_E_INVALID_VALUE`。模块不推导、不改写版本。
- 与 `SignedData` 的 `CMSVersion` 故意不同：`SignedData.version` 取决于证书分支、`eContent` 等语义组合，模块交给调用方判断、不校验范围；`EncryptedData` 只有两档且与 `unprotectedAttrs` 是否出现一一绑定，是机械规则，因此 setter 与 `encode` 都硬校验。两者均使用 `ASNBER_E_INVALID_VALUE` 表示值组合不合法。
- detached 与空密文严格区分：不调用 `_set_encrypted_content` 输出中无 `[0]` 字段；调用且 `size == 0` 输出 `80 00`。
- 写侧不做加密、不派生密钥、不计算 MAC；所有密码学值由调用方提供并原样承载。

### 6.15 asnber-cms CompressedData 只读 API（0.3.0 第一块）

`CompressedData` 使用只读句柄 `asnber_cms_compressed_data_t`，由 `asnber_cms_compressed_data_open` 创建、`close` 销毁（`close(NULL)` 为空操作）。新增 7 个 `asnber_cms_compressed_data_*` 导出符号；不新增核心 ABI、不新增错误码。

语义：

- `open` 只接受**裸 `CompressedData`**（不含外层 `ContentInfo`）：调用方先用 `asnber_cms_content_info_open` + `asnber_cms_content_info_content` 取 `[0]` 内层 TLV，再传入本函数；模块不提供自动剥壳入口。`version`、`compressionAlgorithm` 与 `encapsulatedContentInfo` 为必填，缺失由描述表在 `open` 阶段拒绝。
- `version` 原样返回，**不做范围校验**，也不校验 RFC 3274 的“必须为 0”语义；需要断言的调用方自行比较。构造侧在 `encode` 时强制为 0（见 6.16）。
- `compression_algorithm` 给 `compressionAlgorithm` 的 OID 文本与 `parameters` 完整原始 TLV（缺省时 `NULL/0`）；不展开算法参数、不判断压缩算法与内容类型是否匹配。
- `econtent_type` 给 `EncapsulatedContentInfo.eContentType` 的 OID 文本。
- `econtent` 是 `[0] EXPLICIT OCTET STRING` 的内层内容字节（不含 tag/len），构造形式按核心既有 BER 合并规则展平，**不分段**。空内容与 detached 均返回 `ASNBER_OK` 且 `*out_size == 0`（空内容为非 NULL 指针、长度 0；detached 为 `NULL/0`）；区分二者应看 `econtent_tlv`：空内容返回 `04 00`，detached 返回 `NULL/0`。
- `econtent_tlv` 返回**内层 OCTET STRING 的完整 TLV**（`0x04`，不含外层 `[0]` 包装）；字段缺省时返回 `ASNBER_OK` 且 `NULL/0`。需要连 `[0]` 包装一起转发的调用方自行拼接。
- 只读边界：不解压、不展开压缩算法参数或内容；压缩语义由调用方按 OID 二次解析。
- 未知字段与错标签：与 6.17 相同，读侧**不启用** `ASNBER_DECODE_STRICT_SCHEMA`；与任何字段都不匹配的错标签 TLV 按未知字段静默忽略，根 `SEQUENCE` 之后的尾随数据返回 `ASNBER_E_TRAILING_DATA`。
- 句柄生命周期与指针借用规则同 6.11：句柄借用创建它的 `asnber_ctx_t`，不得晚于 `ctx` 销毁；访问器返回的指针借用句柄内部节点，`close` 后失效；跨 `ctx` 混用行为未定义。

### 6.16 asnber-cms CompressedData 写侧 API（0.3.0 第二块）

`asnber_cms_compressed_builder_t` 用于组装 `ContentInfo { contentType = id-ct-compressedData（1.2.840.113549.1.9.16.1.9）, content = [0] EXPLICIT CompressedData }`。新增 7 个 `asnber_cms_compressed_builder_*` 导出符号；不新增核心 ABI、不新增错误码。生命周期、`ctx` 借用与销毁契约同 6.12（`destroy(NULL)` 为空操作，同一句柄只能 destroy 一次）。

| 函数 | 语义 |
| --- | --- |
| `_create` / `_destroy` | 创建/销毁 builder；`create` 借用调用方 `ctx` |
| `_set_version` | `CompressedData.version`，必填；只接受 `0`（RFC 3274），其他值立即返回 `ASNBER_E_INVALID_VALUE`；重复设置 `ASNBER_E_INVALID_STATE` |
| `_set_compression_algorithm` | 必填；OID 必须合法，可选的 `parameters` 必须是恰好一个完整 TLV；重复设置 `ASNBER_E_INVALID_STATE` |
| `_set_econtent_type` | `EncapsulatedContentInfo.eContentType`，必填，合法 OID；重复设置 `ASNBER_E_INVALID_STATE` |
| `_set_econtent` | 已压缩内容的 OCTET STRING 内容字节；不调用即 detached，允许空内容；`NULL + size≠0` 拒绝；重复设置 `ASNBER_E_INVALID_STATE` |
| `_encode` | 校验必填项与 `version` 并输出 DER `ContentInfo`；失败时缓冲清零，成功时由 `ctx` 分配、调用方 `asnber_buf_release` 归还 |

语义与边界：

- 必填项为 `version`、`compressionAlgorithm`、`eContentType`；缺失或重复设置单值字段返回 `ASNBER_E_INVALID_STATE`。`version` 除 setter 立即拒绝外，`encode` 还会再校验一次，防止绕过。
- 模块不压缩、不解压、不生成随机数、不推导版本；`eContent` 是调用方给出的已压缩字节，模块原样承载。
- detached 与空内容严格区分：不调用 `_set_econtent` 输出中无 `[0]` 字段；调用且 `size == 0` 输出 `A0 02 04 00`。
- 输出按结构定义顺序编码：`version`、`compressionAlgorithm`、`encapsulatedContentInfo`（`eContentType` + 可选 `eContent`）。

### 6.17 asnber-cms AuthenticatedData 只读 API（0.3.0 第三块）

`AuthenticatedData` 使用只读句柄 `asnber_cms_authenticated_data_t`，由 `asnber_cms_authenticated_data_open` 创建、`close` 销毁（`close(NULL)` 为空操作）。新增 15 个 `asnber_cms_authenticated_data_*` 导出符号；不新增核心 ABI、不新增错误码。

语义：

- `open` 只接受**裸 `AuthenticatedData`**（不含外层 `ContentInfo`）：调用方先用 `asnber_cms_content_info_open` + `asnber_cms_content_info_content` 取 `[0]` 内层 TLV，再传入本函数；模块不提供自动剥壳入口。`version`、`recipientInfos`、`macAlgorithm`、`encapsulatedContentInfo` 与 `mac` 为必填；`recipientInfos` 的 `SET SIZE (1..MAX)` 由描述表生效，空集合在 `open` 阶段返回 `ASNBER_E_SCHEMA_CONSTRAINT`；`authAttrs`/`unauthAttrs` 的空 SET（`A2 00`/`A3 00`）同样被 `SET SIZE (1..MAX)` 拒绝。
- `version` 原样返回，**不做范围校验**，也不校验 RFC 5652 的 0/1/3 语义；需要断言的调用方自行比较。构造侧在 `encode` 时执行版本配对（见 6.18）。
- `originator_info_tlv` 给 `[0] IMPLICIT OriginatorInfo` 的完整原始 TLV；缺省返回 `ASNBER_OK` 且 `NULL/0`，不展开 `certs`/`crls`。
- `recipient_count` 给条目数（描述表保证至少 1 条）；`recipient_at` 按下标给分支判别值 `ASNBER_CMS_RECIPIENT_*`（ktri 为裸 `SEQUENCE`，kari..ori 为 `[1]`..`[4]`）与该分支完整原始 TLV。下标越界（含等于条目数）返回 `ASNBER_E_INVALID_ARG`，并把 out 参数复位为 `-1 / NULL / 0`，不影响句柄后续读取。**不展开分支内部字段**——与 EnvelopedData 的分支专用访问器不同，调用方按分支自行二次解析。
- `mac_algorithm` 给 OID 文本与 `parameters` 完整原始 TLV（缺省时 `NULL/0`）；`digest_algorithm` 给 `[1] IMPLICIT` 的 OID 与 parameters（字段缺省返回 `ASNBER_OK` 且 `NULL/0`）。
- `econtent_type` 给 OID 文本；`econtent` 是 `[0] EXPLICIT OCTET STRING` 的内层内容字节，按核心既有 BER 合并规则展平、**不分段**；空内容与 detached 均返回 `ASNBER_OK` 且 `*out_size == 0`，区分二者应看 `econtent_tlv`（空内容 `04 00`，detached `NULL/0`）。
- `econtent_tlv` 返回内层 OCTET STRING 的完整 TLV（`0x04`，不含外层 `[0]`）；`auth_attrs_tlv` / `unauth_attrs_tlv` 返回 `[2]` / `[3] IMPLICIT SET OF Attribute` 的完整原始 TLV，缺省均返回 `ASNBER_OK` 且 `NULL/0`，不解析属性内容。
- `mac` 给 OCTET STRING 内容字节（空 MAC 返回 `ASNBER_OK` 且 `*out_size == 0`）；`mac_tlv` 给完整原始 TLV（空 MAC 为 `04 00`）。
- 只读边界：不校验 MAC、不计算摘要、不做密钥派生/解密、不展开 `recipientInfo` 分支或属性内容；密码学语义由调用方按 OID 二次解析。**读侧不校验 `authAttrs` 与 `digestAlgorithm` 的耦合**：RFC 5652 要求二者成对出现，但本模块只做结构投影，两个方向的缺失（`authAttrs` 有而 `digestAlgorithm` 无、`digestAlgorithm` 有而 `authAttrs` 无）都照常返回 `ASNBER_OK`，配对校验只在构造侧 `encode` 执行（见 6.18）。
- 未知字段与错标签：读侧**不启用** `ASNBER_DECODE_STRICT_SCHEMA`。与任何字段都不匹配的错标签 TLV 按未知字段静默忽略（不报错、不影响其余字段投影）；根 `SEQUENCE` 之后的尾随数据返回 `ASNBER_E_TRAILING_DATA`；`version` 取任意整数（含 5）都照常投影。
- 句柄生命周期与指针借用规则同 6.11：句柄借用创建它的 `asnber_ctx_t`，不得晚于 `ctx` 销毁；访问器返回的指针借用句柄内部节点，`close` 后失效；跨 `ctx` 混用行为未定义。

### 6.18 asnber-cms AuthenticatedData 写侧 API（0.3.0 第四块）

`asnber_cms_authenticated_builder_t` 用于组装 `ContentInfo { contentType = id-ct-authData（1.2.840.113549.1.9.16.1.2）, content = [0] EXPLICIT AuthenticatedData }`。新增 13 个 `asnber_cms_authenticated_builder_*` 导出符号；不新增核心 ABI、不新增错误码。生命周期、`ctx` 借用与销毁契约同 6.12（`destroy(NULL)` 为空操作，同一句柄只能 destroy 一次）。

| 函数 | 语义 |
| --- | --- |
| `_create` / `_destroy` | 创建/销毁 builder；`create` 借用调用方 `ctx` |
| `_set_version` | `AuthenticatedData.version`，必填；只接受 `0` / `1` / `3`，其他值立即返回 `ASNBER_E_INVALID_VALUE`；重复设置 `ASNBER_E_INVALID_STATE` |
| `_set_originator_info` | 可选 `[0] IMPLICIT OriginatorInfo` 完整 TLV（`0xA0`）；子节点只能是可选的 `certs [0]`（`0xA0`）与 `crls [1]`（`0xA1`），顺序固定、各至多一次；重复设置 `ASNBER_E_INVALID_STATE` |
| `_add_recipient` | 追加一条 RecipientInfo 完整 TLV：`ktri` 为 `SEQUENCE`，`kari`/`kekri`/`pwri`/`ori` 为 `[1]`..`[4]` 构造标签；只校验分支根标签，内部字段由调用方保证 |
| `_set_mac_algorithm` | 必填；OID 必须合法，可选的 `parameters` 必须是恰好一个完整 TLV；重复设置 `ASNBER_E_INVALID_STATE` |
| `_set_digest_algorithm` | 可选 `[1] IMPLICIT AlgorithmIdentifier` 完整 TLV（`0xA1`），子节点为 OID 加可选 parameters；与 `authAttrs` 必须成对出现（`encode` 校验）；重复设置 `ASNBER_E_INVALID_STATE` |
| `_set_econtent_type` | `EncapsulatedContentInfo.eContentType`，必填，合法 OID；重复设置 `ASNBER_E_INVALID_STATE` |
| `_set_econtent` | 内容字节；不调用即 detached，允许空内容；`NULL + size≠0` 拒绝；重复设置 `ASNBER_E_INVALID_STATE` |
| `_set_auth_attrs` | 可选、非空 `SET OF Attribute`（外层 `0x31`，元素为 `SEQUENCE`）；模块把外层改写为 `0xA2`，长度与内容逐字节不变；重复设置 `ASNBER_E_INVALID_STATE` |
| `_set_mac` | `mac` OCTET STRING 内容字节，必填；允许空 MAC；重复设置 `ASNBER_E_INVALID_STATE` |
| `_set_unauth_attrs` | 可选、非空 `SET OF Attribute`（外层 `0x31`，元素为 `SEQUENCE`）；模块把外层改写为 `0xA3`，长度与内容逐字节不变；重复设置 `ASNBER_E_INVALID_STATE` |
| `_encode` | 校验必填项、版本配对与属性配对并输出 DER `ContentInfo`；失败时缓冲清零，成功时由 `ctx` 分配、调用方 `asnber_buf_release` 归还 |

语义与边界：

- 必填项为 `version`、至少一条 recipient、`macAlgorithm`、`eContentType`、`mac`；缺失或重复设置单值字段返回 `ASNBER_E_INVALID_STATE`。
- 版本规则：`_set_version` 只接受 `0` / `1` / `3`，其他值立即返回 `ASNBER_E_INVALID_VALUE`；`encode` 再校验非 0 版本必须带 `originatorInfo`。模块**不检查** `originatorInfo` 内是 v1 还是 v2 属性证书，即不推导版本，`0`/`1`/`3` 与证书类型的语义配对由调用方负责。
- `digestAlgorithm` 与 `authAttrs` 必须同时出现或同时缺省；`eContentType` 不是 `id-data`（`1.2.840.113549.1.7.1`）时 `authAttrs` 必填；两条规则都在 `encode` 时校验，不一致返回 `ASNBER_E_INVALID_VALUE`。
- 预构造 TLV 校验深度与 EnvelopedData 不同：`originatorInfo` 与 `digestAlgorithm` 校验直接子节点（标签、构造位、顺序、重复），`authAttrs`/`unauthAttrs` 校验 `SET OF` 非空且元素为 `SEQUENCE`；`add_recipient` 只校验分支根标签，`ktri`/`kari`/`kekri`/`pwri`/`ori` 的内部字段由调用方保证。TLV 截断/尾随/非规范分别返回 `ASNBER_E_TRUNCATED`、`ASNBER_E_TRAILING_DATA`、`ASNBER_E_NON_CANONICAL` 等核心错误码；失败的追加/设置调用不改变 builder 已有状态。
- 多个 recipient 按调用顺序收集，编码时按 DER `SET OF` 规则排序；`originatorInfo`、`digestAlgorithm`、`authAttrs`、`unauthAttrs` 至多设置一次。
- detached 与空内容严格区分：不调用 `_set_econtent` 输出中无 `[0]` 字段；调用且 `size == 0` 输出 `A0 02 04 00`。
- 写侧不计算或校验 MAC、不计算摘要、不做密钥派生/解密；`mac`、`digestAlgorithm` 与全部属性内容由调用方给值并原样承载。
