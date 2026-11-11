# asnber-pkix

X.509 / PKIX 标准结构模块（基于 RFC 5912 扁平化 ASN.1），以 `.asn1` 描述表驱动，只依赖核心公共 C ABI。

## 用法

```c
/* 读：打开证书并访问字段 */
asnber_pkix_certificate_t *cert = NULL;
asnber_err_t rc = asnber_pkix_certificate_open(ctx, pem_or_der, len, &cert);
/* 字段访问…… */
asnber_pkix_certificate_close(cert);

/* 写：构造 Certificate / TBSCertificate */
asnber_pkix_certificate_builder_t *builder = NULL;
asnber_pkix_certificate_builder_create(ctx, &builder);
asnber_pkix_certificate_builder_set_version(builder, 2);
asnber_pkix_certificate_builder_set_serial_number(builder, serial, serial_size);
asnber_pkix_certificate_builder_set_signature_algorithm(
    builder, "1.2.840.113549.1.1.11", NULL, 0);
asnber_pkix_certificate_builder_set_issuer(builder, rdns, rdn_count);
asnber_pkix_certificate_builder_set_validity(builder, &not_before, &not_after);
asnber_pkix_certificate_builder_set_subject(builder, rdns, rdn_count);
asnber_pkix_certificate_builder_set_subject_public_key_algorithm(
    builder, "1.2.840.113549.1.1.1", NULL, 0);
asnber_pkix_certificate_builder_set_subject_public_key(builder, spki, spki_size, 0);
asnber_pkix_certificate_builder_add_basic_constraints(builder, 1, 1, 0, 0);
asnber_pkix_certificate_builder_set_signature_value(builder, sig, sig_size, 0);
asnber_buf_t der;
asnber_pkix_certificate_builder_encode(builder, &der);
asnber_buf_release(ctx, &der);
asnber_pkix_certificate_builder_destroy(builder);
```

- 公共头：`asnber/pkix/pkix.h`（构造侧 API 在 `pkix_builder.h`，由 `pkix.h` 一并包含）
- CRL：`asnber_pkix_crl_open` 读 CertificateList，`asnber_pkix_crl_builder_*` 组装，含 CRL 扩展和条目扩展。不判断吊销，不解释扩展。出现扩展时 version 必须为 1。cert-decode 裁剪表没有这个类型，open 会失败。
- 链接目标：`asnber::pkix::shared` 或 `asnber::pkix::static`（需 `find_package(asnber-pkix CONFIG REQUIRED)`）

## 描述表与缓存

**每次 `open` 加载一次 `.asn1` 描述表并构建上下文级 schema，生命周期到 `close` 结束；无全局缓存、无进程级单例。** 表数据随模块（检入产物 `generated/pkix_schema.bin`）编译进库，运行时只读；不同句柄互不共享可变状态。据此，多线程下只要每个句柄由单线程创建/使用（或在外部加锁），并发打开不同证书是安全的。

批量基准见仓库根 README 与 `docs/07-测试与验证.md`：MSVC Release 下 RSA 自签证书 1,000 次 open+close 约 445 ms，峰值堆 73,260 字节。

## 状态

0.1.1：CertificateList 结构读取与 builder，含 CRL 扩展和条目扩展。不判断吊销，不解释扩展。出现扩展时 version 必须为 1。cert-decode 裁剪表不含此类型。

0.1.0：证书打开与字段访问（RSA / RSA-PSS / EC）、ANY 三形态、独立安装消费；已在本机 MSVC、MinGW、WSL GCC/Clang、ASan/UBSan 与 ARM 交叉构建中验证，详见 `docs/06` 第 10 节。

P5（2026-11-10，未发版）：新增 `Certificate`/`TBSCertificate` builder，18 个公开函数；RSA 自签证书 865 字节逐字节重建，含三条 DER 约束与便捷扩展函数。
