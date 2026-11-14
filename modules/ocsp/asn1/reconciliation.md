# OCSP 展平对账

来源是 RFC 6960 附录的 1988 模块，模块头为 `DEFINITIONS EXPLICIT TAGS`。不使用 RFC 5912 第 4 节。

一张描述表，默认根是 `OCSPResponse`（类型号 17）。`OCSPRequest` 是 14，`BasicOCSPResponse` 是 24。号按具名类型在本文件中的出现顺序，从 1 起。加载另两个根时用 `asnber_schema_load_with_root`，不改表字节。

## 与 RFC 正文的差别

1. `CRLReason` 使用 PKIX 的 `ENUMERATED` 和原有命名值（0、1、2、3、4、5、6、8、9、10）。不用 RFC 6960 正文把 `CRLReason` 写成 `INTEGER` 的定义。这是勘误 3259。
2. `Signature.certs` 与 `BasicOCSPResponse.certs` 的元素类型写成 `ANY`，名字仍叫 `Certificate`。`ANY` 保留一张证书的完整 TLV。不复制 PKIX 证书类型树，也不链接 `asnber-pkix`。
3. `GeneralName` 与 `Name` 写成 `ANY`。`requestorName` 交回 `GeneralName` 的原始 DER。`ResponderID.byName` 交回 `Name` 的原始 DER。`byKey` 仍是 `KeyHash`（`OCTET STRING`）。

其余字段名、顺序和标签按附录模块保留。`ResponseBytes.response` 保持 `OCTET STRING`。`id-pkix-ocsp-basic` 只是 OID 值，打开 `OCSPResponse` 时不展开里面的 `BasicOCSPResponse`。

扩展内容留在 `extnValue`。本模块不定义 `Nonce`、`CrlID`、`PreferredSignatureAlgorithm`、`ServiceLocator` 这些扩展语法。
