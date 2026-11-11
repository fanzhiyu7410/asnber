# 变更记录

本文件记录对外可见的版本变更；格式参考 Keep a Changelog，版本号遵循语义化版本。

## [Unreleased]

### 新增

- `asnber-pkix`：CertificateList 的结构读取与 builder，含 CRL 扩展和条目扩展。不判断吊销，不解释扩展。出现扩展时 version 必须为 1。这些符号属于下一个 minor。
- `asnber-pkcs8`：EncryptedPrivateKeyInfo builder。只组装算法标识和密文字节，不加密。
- `asnber_example_pool_estimate`：对一份描述表和一份 DER 二分求最小静态池。

### 变更

- CMS SignedData builder 可以输出 certificates-only / CRL-only。没有签名者时 `digestAlgorithms` 可以为空；证书、CRL、签名者三者全空仍然拒绝。
- schema 编码失败时，`asnber_error_info_t.path` 带上最内层的类型名或 `类型名/字段名`。

## [0.1.0] - 2026-11-11

首个版本。核心库、描述表工具和标准模块一起发布。

### 新增

- 核心 `asnber`：BER/DER 解码与 DER 编码、DOM、schema 感知编解码、增量 feed 解码、静态池。
- 工具 `asnberc`：解析 `.asn1` 文本并生成描述表，支持多模块 `IMPORTS` 与单类型参数化。
- 模块 `asnber-pkix`、`asnber-cms`、`asnber-pkcs1`、`asnber-pkcs8`、`asnber-pkcs10`、`asnber-pkcs12`，以及不产库的聚合包 `asnber-pkcs`。
- 库不签名、不加密、不解密，也不校验证书链。

[0.1.0]: https://github.com/fanzhiyu7410/asnber/releases/tag/v0.1.0
