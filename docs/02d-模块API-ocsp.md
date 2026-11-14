# asnber-ocsp 模块 API

`asnber-ocsp` 是独立包（`find_package(asnber-ocsp CONFIG)`），只依赖核心公共 C ABI，不依赖 `asnber-pkix`，也不进入 `asnber-pkcs`。公共头为 `<asnber/ocsp/ocsp.h>`。构造接口在 `<asnber/ocsp/ocsp_builder.h>`，该头已包含 `ocsp.h`。导出宏 `ASNBER_OCSP_API`，静态链接时宏 `ASNBER_OCSP_STATIC`。

模块只做 RFC 6960 结构的读取和组装。不签名、不验签、不判断证书状态、不解释扩展。`Certificate`、`Name`、`GeneralName` 在本模块里保持完整 TLV，调用方把证书 DER 交给 `asnber-pkix`。

一张描述表、三个根。`OCSPResponse` 是表头默认根。`OCSPRequest` 与 `BasicOCSPResponse` 由 `asnber_schema_load_with_root` 在打开时指定。

```c
const char *asnber_ocsp_version_string(void);

asnber_err_t asnber_ocsp_request_open(asnber_ctx_t *ctx,
                                   const uint8_t *der, size_t der_size,
                                   asnber_ocsp_request_t **out_request);
void asnber_ocsp_request_close(asnber_ocsp_request_t *request);

asnber_err_t asnber_ocsp_response_open(asnber_ctx_t *ctx,
                                    const uint8_t *der, size_t der_size,
                                    asnber_ocsp_response_t **out_response);
void asnber_ocsp_response_close(asnber_ocsp_response_t *response);

asnber_err_t asnber_ocsp_basic_open(asnber_ctx_t *ctx,
                                 const uint8_t *der, size_t der_size,
                                 asnber_ocsp_basic_t **out_basic);
void asnber_ocsp_basic_close(asnber_ocsp_basic_t *basic);
```

语义：

- `open` 用模块随包发布的 OCSP 描述表加载 schema，再以 `ASNBER_ENCODING_DER` + `ASNBER_DECODE_COPY_INPUT` 解码。空参或 `der_size == 0` 返回 `ASNBER_E_INVALID_ARG`。失败时对应的输出句柄置 `NULL`。`close(NULL)` 为空操作。
- 句柄借用调用方的 `asnber_ctx_t`，ctx 必须比句柄存活更久。访问器返回的指针借用句柄，`close` 后失效。
- `asnber_ocsp_response_open` 不展开 `response` 的 OCTET STRING。`asnber_ocsp_response_bytes` 仅在 `responseStatus == 0`（successful）且字段存在时给出 `responseType` 点分 OID 和内容字节，`*out_present = 1`。其他状态或字段缺失时返回 `ASNBER_OK`，`*out_present = 0`。模块不判断该 OID 是否为 `id-pkix-ocsp-basic`（`1.3.6.1.5.5.7.48.1.1`）。
- `asnber_ocsp_basic_open` 的输入是上述内容字节，不是外层 `OCSPResponse`。它不核对 `responseType`。把外层响应交给它会按 `BasicOCSPResponse` 失败。
- `requestorName` 与 responder `byName` 返回内层 TLV，不含外层上下文标签。`byKey` 返回 `KeyHash` 的内容字节。`*out_choice` 为 1 表示 byName，为 2 表示 byKey。
- `certStatus` 为 0 good、1 revoked、2 unknown。不是 revoked 时 `asnber_ocsp_basic_revocation` 返回 `ASNBER_E_INVALID_ARG`。
- `CRLReason` 按 RFC 5912 勘误 3259 是 `ENUMERATED`，不是 RFC 6960 附录里的 `INTEGER`。读取结果为枚举值；没有 reason 时 `*out_reason_present = 0`。
- 扩展的 `extnValue` 是 OCTET STRING 的内容字节。`critical` 缺省时为 0。同一列表内 OID 重复在构造侧返回 `ASNBER_E_INVALID_VALUE`。
- version 缺省为 0（v1）。描述表把 `Version ::= INTEGER { v1(0) }` 当作值约束，线上出现其他整数时读取返回 `ASNBER_E_SCHEMA_CONSTRAINT`。

## 构造

三个 builder：`asnber_ocsp_request_builder_*`、`asnber_ocsp_response_builder_*`、`asnber_ocsp_basic_builder_*`。`create` 借用 ctx，`destroy(NULL)` 为空操作。输入在设置时复制。

- `set_version` 只接受 0，且只允许设置一次。0 与不设置一样，编码时省略 DEFAULT。其他值返回 `ASNBER_E_INVALID_VALUE`。
- 请求至少一条 `Request` 才能 `encode`。`serial` 是大端无符号幅值。`hash_params_size == 0` 时省略 `parameters`。
- 响应必须先 `set_status`。允许的值是 0、1、2、3、5、6。`set_bytes` 写入调用方给出的类型 OID 和不透明内容；状态不是 successful 时这些字节仍会出现在编码里，但读取侧按上面的规则隐藏。
- 基本响应必须有 responder、`producedAt` 和至少一条 `SingleResponse`。`set_responder_name` 与 `set_responder_key` 互斥，第二次返回 `ASNBER_E_INVALID_STATE`。byName 传入 Name 的完整 TLV。时间总是 `GeneralizedTime`；`struct_size` 必须为 `sizeof(asnber_time_t)`，不接受偏移、本地时间和小数。
- `add_revoked` 的吊销时间必填。reason 可选；7 以及未定义的值返回 `ASNBER_E_INVALID_VALUE`。接受 0、1、2、3、4、5、6、8、9、10。
- 签名证书必须在 `set_signature` 之后追加，否则 `ASNBER_E_INVALID_STATE`。
- `encode` 失败时 `out_buf` 被清零。成功时缓冲由 ctx 分配，调用方用 `asnber_buf_release` 释放。

线程与缓存与其他模块相同：没有全局可变状态；schema 随句柄或编码过程加载并销毁；同一 ctx 的并发仍由调用方加锁。模块不新增错误码。

描述表发布机制：`modules/ocsp/generated/ocsp_schema.{h,bin}` 检入仓库。默认构建直接使用检入产物。`-DASNBER_OCSP_REGENERATE_TABLE=ON` 时在构建期用 `asnberc` 重新生成，并与检入产物逐字节比对。`cert-decode` 与 `cert-and-csr` 裁剪配置会关闭本模块；裁剪后的 PKIX 表不含这三个根。
