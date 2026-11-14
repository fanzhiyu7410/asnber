# asnber-ocsp

OCSP 结构模块（RFC 6960）。只依赖核心公共 C ABI，不依赖 `asnber-pkix`，也不进入 `asnber-pkcs`。

只做结构读写：不签名、不验签、不判断证书状态、不解释扩展。`Certificate`、`Name`、`GeneralName` 保持完整 TLV。

## 用法

```c
asnber_ocsp_response_t *response = NULL;
asnber_ocsp_response_open(ctx, der, der_size, &response);

const char *type_oid = NULL;
size_t type_oid_size = 0;
const uint8_t *content = NULL;
size_t content_size = 0;
int present = 0;
asnber_ocsp_response_bytes(response, &type_oid, &type_oid_size,
                           &content, &content_size, &present);

asnber_ocsp_basic_t *basic = NULL;
if (present) {
    asnber_ocsp_basic_open(ctx, content, content_size, &basic);
}
asnber_ocsp_basic_close(basic);
asnber_ocsp_response_close(response);
```

- 公共头：`asnber/ocsp/ocsp.h`。构造侧 API 在 `asnber/ocsp/ocsp_builder.h`。
- `OCSPResponse` 是默认根。`basic_open` 吃的是 `response` 内容字节，不核对 `responseType`，也不接受外层 `OCSPResponse`。
- 只有 `responseStatus == 0` 且带 `responseBytes` 时，读取侧才返回内容。构造侧仍可把调用方给的字节写进其他状态。
- version 只接受 0，编码时省略。`CRLReason` 按勘误 3259 是 `ENUMERATED`，不接受 7。
- 链接目标：`asnber::ocsp::shared` 或 `asnber::ocsp::static`（`find_package(asnber-ocsp CONFIG REQUIRED)`）。

## 描述表

`modules/ocsp/generated/ocsp_schema.{h,bin}` 检入仓库。默认构建直接使用。`-DASNBER_OCSP_REGENERATE_TABLE=ON` 时用 `asnberc` 重生成并与检入产物比对。

展平源是 `DEFINITIONS IMPLICIT TAGS`，带标签的字段仍写明 `EXPLICIT` 或 `IMPLICIT`，线上结果与 RFC 6960 附录的显式模块一致。原因见 `modules/ocsp/asn1/reconciliation.md`。
