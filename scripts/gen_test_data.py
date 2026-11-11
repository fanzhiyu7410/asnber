#!/usr/bin/env python3
# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT
"""生成 tests/data/ 下的真实 ASN.1 测试材料。

只依赖 openssl 命令行与 Python 标准库，不引入第三方依赖。

用法：
    python scripts/gen_test_data.py            # 重新生成全部材料与 C 数组头
    python scripts/gen_test_data.py --headers  # 只从已有 .der 重新生成 C 数组头
    python scripts/gen_test_data.py --derived  # 只从已有 key_rsa_pkcs8.pem 派生
                                               # PKCS#1 公私钥与加密 PKCS#8 材料
    python scripts/gen_test_data.py --cms      # 只用已有证书/私钥生成 CMS 样本
    python scripts/gen_test_data.py --cms-enveloped  # 只用已有证书生成
                                                     # CMS EnvelopedData 样本
    python scripts/gen_test_data.py --cms-encrypted  # 生成 CMS EncryptedData 样本
    python scripts/gen_test_data.py --cms-compressed # 生成 CMS CompressedData 样本
    python scripts/gen_test_data.py --pkcs12   # 只用已有证书/私钥生成 PKCS#12 样本

产物：
    tests/data/*.pem  PEM 文本材料（自签名证书、私钥、CSR）
    tests/data/*.der  DER 二进制材料（证书、PKCS#8 私钥、PKCS#1 公私钥、CSR）
    tests/data/*.h    由 .der 转换出的 C 数组头，供零第三方 C 测试直接 include
    tests/data/README.md 材料来源与重现说明

注意：密钥与签名含随机成分，重新生成得到的字节与仓库内已提交的版本不同；
测试只依赖“解码→编码逐字节一致”的自洽性，不依赖固定字节。仓库内已提交的
.der/.h 是权威快照，--headers 模式可避免重新生成密钥。
"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "tests" / "data"
OPENSSL = os.environ.get("OPENSSL", "openssl")

# 最小 openssl 配置，避免系统默认配置里的 v3_ca 扩展干扰生成。
MINIMAL_CONFIG = """[ req ]
default_md = sha256
distinguished_name = dn
[ dn ]
"""

_CONFIG_PATH = None

# 材料清单：(C 标识符词干, PEM 文件, DER 文件, 生成命令参数, 说明)
CERTS = [
    (
        "cert_rsa_selfsigned",
        "RSA-2048 自签名证书",
        ["-new", "-x509", "-sha256", "-days", "3650",
         "-subj", "/C=CN/O=ASN1 Test/CN=ASN1 RSA Self Signed",
         "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "subjectAltName=DNS:asn1-rsa.example"],
        "key_rsa_pkcs8.pem",
    ),
    (
        "cert_ec_selfsigned",
        "ECDSA P-256 自签名证书",
        ["-new", "-x509", "-sha256", "-days", "3650",
         "-subj", "/C=CN/O=ASN1 Test/CN=ASN1 EC Self Signed",
         "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "subjectAltName=DNS:asn1-ec.example"],
        "key_ec_pkcs8.pem",
    ),
    (
        "cert_rsa_pss_selfsigned",
        "RSA-PSS 自签名证书（AlgorithmIdentifier.parameters 为 SEQUENCE）",
        ["-new", "-x509", "-sha256", "-days", "3650",
         "-subj", "/C=CN/O=ASN1 Test/CN=ASN1 RSA-PSS Self Signed",
         "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "subjectAltName=DNS:asn1-rsa-pss.example"],
        "key_rsa_pss_pkcs8.pem",
    ),
]

CSRS = [
    (
        "csr_rsa",
        "RSA-2048 证书请求",
        "/C=CN/O=ASN1 Test/CN=ASN1 RSA CSR",
        "key_rsa_pkcs8.pem",
    ),
    (
        "csr_ec",
        "ECDSA P-256 证书请求",
        "/C=CN/O=ASN1 Test/CN=ASN1 EC CSR",
        "key_ec_pkcs8.pem",
    ),
]

KEYS = [
    (
        "key_rsa_pkcs8",
        "RSA-2048 私钥（PKCS#8，未加密）",
        ["genpkey", "-algorithm", "RSA",
         "-pkeyopt", "rsa_keygen_bits:2048"],
    ),
    (
        "key_ec_pkcs8",
        "ECDSA P-256 私钥（PKCS#8，未加密）",
        ["genpkey", "-algorithm", "EC",
         "-pkeyopt", "ec_paramgen_curve:P-256"],
    ),
    (
        "key_rsa_pss_pkcs8",
        "RSA-PSS 2048 私钥（PKCS#8，未加密）",
        ["genpkey", "-algorithm", "RSA-PSS",
         "-pkeyopt", "rsa_keygen_bits:2048"],
    ),
]


# 派生材料：只依赖已提交的 key_rsa_pkcs8.pem，不重新生成密钥。
# (C 标识符词干, 说明, 类型)
DERIVED = [
    (
        "key_rsa_pkcs1_private",
        "RSA-2048 私钥（PKCS#1，传统格式）",
        "rsa_private",
    ),
    (
        "key_rsa_pkcs1_public",
        "RSA-2048 公钥（PKCS#1）",
        "rsa_public",
    ),
    (
        "key_rsa_pkcs8_encrypted",
        "RSA-2048 私钥（PKCS#8，PBES2 / AES-256-CBC 加密）",
        "pkcs8_encrypted",
    ),
]

ENCRYPTED_PASSPHRASE = "asn1-test"

# CMS 样本：复用已提交的证书与私钥，不生成新密钥。
# (C 标识符词干, 说明, 签名者参数, 附加参数)
CMS_SAMPLES = [
    (
        "cms_rsa_attached",
        "RSA SignedData，attached（含 eContent、证书、signedAttrs）",
        [("cert_rsa_selfsigned.pem", "key_rsa_pkcs8.pem")],
        ["-nodetach"],
    ),
    (
        "cms_rsa_detached",
        "RSA SignedData，detached（无 eContent，含证书、signedAttrs）",
        [("cert_rsa_selfsigned.pem", "key_rsa_pkcs8.pem")],
        [],
    ),
    (
        "cms_rsa_minimal",
        "RSA SignedData 最小样本（无证书、无 signedAttrs、detached）",
        [("cert_rsa_selfsigned.pem", "key_rsa_pkcs8.pem")],
        ["-nocerts", "-noattr"],
    ),
    (
        "cms_rsa_ec_multicert",
        "RSA + ECDSA 双签名者 SignedData（多证书，attached）",
        [("cert_rsa_selfsigned.pem", "key_rsa_pkcs8.pem"),
         ("cert_ec_selfsigned.pem", "key_ec_pkcs8.pem")],
        ["-nodetach"],
    ),
    (
        "cms_rsa_keyid",
        "RSA SignedData，SignerIdentifier 使用 subjectKeyIdentifier",
        [("cert_rsa_selfsigned.pem", "key_rsa_pkcs8.pem")],
        ["-keyid"],
    ),
]

CMS_CONTENT = b"asn1-cms differential and structure test content\n"

# CMS EnvelopedData 样本：复用已提交证书；kekri / pwri 为 openssl 真实产物。
# (C 标识符词干, 说明, openssl 选项, 位置参数里的收件人证书)
CMS_ENVELOPED_SAMPLES = [
    (
        "cms_enveloped_ktri",
        "RSA 收件人，RecipientInfo 分支 [0]",
        [],
        ["cert_rsa_selfsigned.pem"],
    ),
    (
        "cms_enveloped_ktri_multi",
        "同一 RSA 证书作为两个收件人，RecipientInfo 分支 [0]×2",
        [],
        ["cert_rsa_selfsigned.pem", "cert_rsa_selfsigned.pem"],
    ),
    (
        "cms_enveloped_ktri_keyid",
        "RSA 收件人 + subjectKeyIdentifier，RecipientInfo 分支 [0]，rid 第二分支",
        ["-keyid"],
        ["cert_rsa_selfsigned.pem"],
    ),
    (
        "cms_enveloped_kari",
        "EC 收件人 + subjectKeyIdentifier，RecipientInfo 分支 [1]",
        ["-keyid"],
        ["cert_ec_selfsigned.pem"],
    ),
    (
        "cms_enveloped_kekri",
        "预共享 KEK + key identifier，RecipientInfo 分支 [2]",
        ["-secretkeyid", "0102030405060708",
         "-secretkey",
         "000102030405060708090A0B0C0D0E0F"
         "101112131415161718191A1B1C1D1E1F"],
        [],
    ),
    (
        "cms_enveloped_pwri",
        "口令收件人，RecipientInfo 分支 [3]",
        ["-pwri_password", "secret"],
        [],
    ),
]

# CMS EncryptedData 样本：openssl 用 -secretkey 直接加密内容。
# RFC 5652 §8 的 unprotectedAttrs 无对应生成选项，version 2 只用构造级用例。
CMS_ENCRYPTED_KEY = (
    "000102030405060708090A0B0C0D0E0F"
    "101112131415161718191A1B1C1D1E1F"
)
CMS_ENCRYPTED_SAMPLES = [
    (
        "cms_encrypted_data",
        "对称密钥 EncryptedData，version 0，AES-256-CBC",
        ["-aes-256-cbc", "-secretkey", CMS_ENCRYPTED_KEY],
    ),
]

# CMS CompressedData 样本：openssl cms -compress（默认 zlib）。
# 压缩结果不含随机成分，重跑得到的字节与已提交快照一致。
CMS_COMPRESSED_SAMPLES = [
    (
        "cms_compressed_data",
        "zlib 压缩的 CompressedData，version 0，内容类型 id-data",
        [],
    ),
]

# PKCS#12 样本：复用已提交的证书与私钥，不生成新密钥。
# (C 标识符词干, 说明, openssl pkcs12 -export 参数)
PKCS12_PASSPHRASE = "asn1-test"
PKCS12_SAMPLES = [
    (
        "pfx_rsa_unencrypted",
        "PFX，证书 + RSA 私钥，SafeContents 未加密、无 MAC",
        ["-inkey", "key_rsa_pkcs8.pem", "-in", "cert_rsa_selfsigned.pem",
         "-name", "asn1-test-key",
         "-keypbe", "NONE", "-certpbe", "NONE", "-nomac"],
    ),
    (
        "pfx_rsa_encrypted",
        "PFX，证书 + RSA 私钥，PBES2 / AES-256-CBC，SHA-256 MAC，iterations 2048",
        ["-inkey", "key_rsa_pkcs8.pem", "-in", "cert_rsa_selfsigned.pem",
         "-name", "asn1-test-key",
         "-keypbe", "AES-256-CBC", "-certpbe", "AES-256-CBC",
         "-macalg", "sha256", "-iter", "2048"],
    ),
    (
        "pfx_certs_only",
        "PFX，仅证书，certBag 使用 AES-256-CBC，SHA-256 MAC",
        ["-nokeys", "-in", "cert_rsa_selfsigned.pem",
         "-name", "asn1-cert-only",
         "-certpbe", "AES-256-CBC", "-macalg", "sha256", "-iter", "2048"],
    ),
]


def run_openssl(args):
    """调用 openssl，失败时给出可读错误。"""
    command = [OPENSSL] + args
    result = subprocess.run(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
    )
    if result.returncode != 0:
        sys.stderr.write("openssl 调用失败：%s\n" % " ".join(command))
        sys.stderr.write(result.stderr.decode("utf-8", "replace"))
        raise SystemExit(1)


def minimal_config():
    """返回最小 openssl 配置路径；进程内复用。"""
    global _CONFIG_PATH
    if _CONFIG_PATH is None:
        handle, path = tempfile.mkstemp(prefix="asn1-openssl-", suffix=".cnf")
        with os.fdopen(handle, "w", encoding="ascii") as stream:
            stream.write(MINIMAL_CONFIG)
        _CONFIG_PATH = path
    return _CONFIG_PATH


def generate_keys():
    for stem, description, args in KEYS:
        pem_path = DATA_DIR / (stem + ".pem")
        der_path = DATA_DIR / (stem + ".der")
        run_openssl(args + ["-out", str(pem_path)])
        # openssl pkey 默认写出 PKCS#8；DER 形式用于测试解码。
        run_openssl(["pkey", "-in", str(pem_path),
                     "-outform", "DER", "-out", str(der_path)])


def generate_csrs():
    for stem, description, subject, key_file in CSRS:
        pem_path = DATA_DIR / (stem + ".pem")
        der_path = DATA_DIR / (stem + ".der")
        run_openssl(["req", "-new", "-sha256", "-config", minimal_config(),
                     "-key", str(DATA_DIR / key_file),
                     "-subj", subject, "-out", str(pem_path)])
        run_openssl(["req", "-in", str(pem_path),
                     "-outform", "DER", "-out", str(der_path)])


def generate_certs():
    for stem, description, args, key_file in CERTS:
        pem_path = DATA_DIR / (stem + ".pem")
        der_path = DATA_DIR / (stem + ".der")
        run_openssl(["req", "-config", minimal_config()] + args +
                    ["-key", str(DATA_DIR / key_file),
                     "-out", str(pem_path)])
        run_openssl(["x509", "-in", str(pem_path),
                     "-outform", "DER", "-out", str(der_path)])


def generate_derived():
    """从既有 key_rsa_pkcs8.pem 派生 PKCS#1 公私钥与加密 PKCS#8。"""
    key_pem = DATA_DIR / "key_rsa_pkcs8.pem"
    if not key_pem.exists():
        sys.stderr.write("缺少派生材料源文件：%s\n" % key_pem)
        raise SystemExit(1)
    for stem, description, kind in DERIVED:
        pem_path = DATA_DIR / (stem + ".pem")
        der_path = DATA_DIR / (stem + ".der")
        if kind == "rsa_private":
            run_openssl(["rsa", "-in", str(key_pem), "-traditional",
                         "-out", str(pem_path)])
            run_openssl(["rsa", "-in", str(pem_path), "-traditional",
                         "-outform", "DER", "-out", str(der_path)])
        elif kind == "rsa_public":
            run_openssl(["rsa", "-in", str(key_pem), "-RSAPublicKey_out",
                         "-out", str(pem_path)])
            run_openssl(["rsa", "-pubin", "-in", str(pem_path),
                         "-RSAPublicKey_out", "-outform", "DER",
                         "-out", str(der_path)])
        elif kind == "pkcs8_encrypted":
            run_openssl(["pkcs8", "-topk8", "-in", str(key_pem),
                         "-v2", "aes-256-cbc",
                         "-passout", "pass:%s" % ENCRYPTED_PASSPHRASE,
                         "-out", str(pem_path)])
            run_openssl(["pkcs8", "-topk8", "-in", str(key_pem),
                         "-v2", "aes-256-cbc",
                         "-passout", "pass:%s" % ENCRYPTED_PASSPHRASE,
                         "-outform", "DER", "-out", str(der_path)])
        else:
            sys.stderr.write("未知派生类型：%s\n" % kind)
            raise SystemExit(1)


def generate_cms():
    """用已提交的证书/私钥生成 CMS SignedData 样本。

    签名与 signingTime 含随机/时间成分，重新生成得到的签名字节与仓库内
    已提交版本不同；测试只依赖结构字段，不依赖固定字节。
    """
    for stem in ("cert_rsa_selfsigned.pem", "key_rsa_pkcs8.pem",
                 "cert_ec_selfsigned.pem", "key_ec_pkcs8.pem"):
        if not (DATA_DIR / stem).exists():
            sys.stderr.write("缺少 CMS 材料源文件：%s\n" % (DATA_DIR / stem))
            raise SystemExit(1)

    handle, content_path = tempfile.mkstemp(prefix="asn1-cms-", suffix=".bin")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(CMS_CONTENT)
        for stem, description, signers, extra in CMS_SAMPLES:
            der_path = DATA_DIR / (stem + ".der")
            command = ["cms", "-sign", "-binary", "-md", "sha256",
                       "-in", content_path]
            for cert_file, key_file in signers:
                command += ["-signer", str(DATA_DIR / cert_file),
                            "-inkey", str(DATA_DIR / key_file)]
            command += extra + ["-outform", "DER", "-out", str(der_path)]
            run_openssl(command)
    finally:
        if os.path.exists(content_path):
            os.unlink(content_path)


def generate_cms_enveloped():
    """用已提交的证书生成 CMS EnvelopedData 样本。

    encryptedContent、随机内容加密密钥以及 KEK/口令派生盐含随机成分，
    重新生成得到的字节与仓库内已提交版本不同；测试只依赖结构字段
    （版本、OID、分支、原始 TLV、计数），不对密文做断言。
    """
    required = ("cert_rsa_selfsigned.pem", "cert_rsa_pss_selfsigned.pem",
                "cert_ec_selfsigned.pem")
    for stem in required:
        if not (DATA_DIR / stem).exists():
            sys.stderr.write("缺少 CMS EnvelopedData 材料源文件：%s\n"
                             % (DATA_DIR / stem))
            raise SystemExit(1)

    handle, content_path = tempfile.mkstemp(prefix="asn1-cms-env-",
                                            suffix=".bin")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(CMS_CONTENT)
        for stem, description, options, recipients in CMS_ENVELOPED_SAMPLES:
            der_path = DATA_DIR / (stem + ".der")
            command = ["cms", "-encrypt", "-binary", "-aes-256-cbc"]
            command += options
            command += ["-in", str(content_path), "-outform", "DER",
                        "-out", str(der_path)]
            command += [str(DATA_DIR / name) for name in recipients]
            run_openssl(command)
    finally:
        if os.path.exists(content_path):
            os.unlink(content_path)


def generate_cms_encrypted():
    """用 openssl 生成 CMS EncryptedData 真实样本（version 0）。

    encryptedContent 含随机内容加密密钥与 IV，重跑得到的字节与已提交快照
    不同；测试只读取结构字段，不对密文做断言。
    """
    handle, content_path = tempfile.mkstemp(prefix="asn1-cms-enc-",
                                            suffix=".bin")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(CMS_CONTENT)
        for stem, description, options in CMS_ENCRYPTED_SAMPLES:
            der_path = DATA_DIR / (stem + ".der")
            command = ["cms", "-EncryptedData_encrypt", "-binary"]
            command += options
            command += ["-in", str(content_path), "-outform", "DER",
                        "-out", str(der_path)]
            run_openssl(command)
    finally:
        if os.path.exists(content_path):
            os.unlink(content_path)


def generate_cms_compressed():
    """用 openssl 生成 CMS CompressedData 真实样本（默认 zlib 压缩）。

    zlib 压缩结果确定，重跑得到的字节与已提交快照一致；测试仍只读取结构
    字段，不对压缩数据做解压或内容断言。
    """
    handle, content_path = tempfile.mkstemp(prefix="asn1-cms-comp-",
                                            suffix=".bin")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(CMS_CONTENT)
        for stem, description, options in CMS_COMPRESSED_SAMPLES:
            der_path = DATA_DIR / (stem + ".der")
            command = ["cms", "-compress", "-binary"]
            command += options
            command += ["-in", content_path, "-outform", "DER",
                        "-out", str(der_path)]
            run_openssl(command)
    finally:
        if os.path.exists(content_path):
            os.unlink(content_path)


# 合成样本：AuthenticatedData（RFC 5652 第 9 节）version 0 完整形态。
# 无外部生成器（OpenSSL 的 cms 子命令没有 authData 入口），字节由本脚本
# 固定写出，不是外部实现产物。version 0 不带 originatorInfo（RFC 5652 要求
# 非 0 版本必须出现该字段，因此不把空 `A0 00` 当作完整形态）；version 3
# 的用例由测试在运行时用 tests/data/cert_rsa_selfsigned.der 拼装
# `certs [0]`，那份证书是 openssl 生成的自签证书，仅用于测试，不是生产证书。
CMS_AUTHENTICATED_DATA_DER = bytes([
    0x30, 0x81, 0xB2, 0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01,
    0x09, 0x10, 0x01, 0x02, 0xA0, 0x81, 0xA2, 0x30, 0x81, 0x9F, 0x02, 0x01,
    0x00, 0x31, 0x52, 0x30, 0x2C, 0x02, 0x01, 0x00, 0x30, 0x14, 0x30, 0x0F,
    0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x04, 0x74,
    0x65, 0x73, 0x74, 0x02, 0x01, 0x01, 0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86,
    0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x04, 0x04, 0x01, 0x02, 0x03,
    0x04, 0xA2, 0x22, 0x02, 0x01, 0x00, 0x30, 0x0A, 0x04, 0x08, 0x01, 0x02,
    0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x30, 0x0B, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2D, 0x04, 0x04, 0xAA, 0xBB, 0xCC,
    0xDD, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02,
    0x09, 0xA1, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
    0x02, 0x01, 0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
    0x01, 0x07, 0x01, 0xA2, 0x0C, 0x30, 0x0A, 0x06, 0x03, 0x2A, 0x03, 0x04,
    0x31, 0x03, 0x02, 0x01, 0x01, 0x04, 0x04, 0x11, 0x22, 0x33, 0x44, 0xA3,
    0x0C, 0x30, 0x0A, 0x06, 0x03, 0x2A, 0x03, 0x04, 0x31, 0x03, 0x02, 0x01,
    0x01,
])


# 最小合法 CertificateList（SHA-256 with RSA、空 issuer Name、单个 UTCTime
# thisUpdate、空签名）。用作 `crls [1]` 的结构正例，不含任何真实吊销信息。
CMS_CRL_CERTIFICATE_LIST = bytes.fromhex(
    "3034"
    "3020"
    "300d06092a864886f70d01010b0500"
    "3000"
    "170d3236303130313030303030305a"
    "300d06092a864886f70d01010b0500"
    "030100"
)


def der_len_bytes(value):
    if value < 0x80:
        return 1
    if value < 0x100:
        return 2
    return 3


def der_put_len(value):
    if value < 0x80:
        return bytes([value])
    if value < 0x100:
        return bytes([0x81, value])
    return bytes([0x82, (value >> 8) & 0xFF, value & 0xFF])


def authenticated_originator(certs, crls):
    """拼 `originatorInfo [0] IMPLICIT`：外层 A0 + 可选 certs [0] + 可选 crls [1]。"""
    body = b""
    if certs:
        cert_set = b"".join(certs)
        body += b"\xA0" + der_put_len(len(cert_set)) + cert_set
    if crls:
        crl_set = b"".join(crls)
        body += b"\xA1" + der_put_len(len(crl_set)) + crl_set
    return b"\xA0" + der_put_len(len(body)) + body


# AuthenticatedData 的完整尾段（version/originatorInfo 之后）：ktri + kekri、
# hmacWithSHA256、digestAlgorithm [1]、id-data、authAttrs [2]、mac、
# unauthAttrs [3]。与 tests/cms/test_cms_authenticated.c 的 kFullTail 相同。
CMS_AUTHENTICATED_FULL_TAIL = bytes.fromhex(
    "3152"
    "302c0201003014300f310d300b06035504030c0474657374020101"
    "300b06092a864886f70d010101040401020304"
    "a222020100300a0408010203040506070830"
    "0b060960864801650304012d0404aabbccdd"
    "300a06082a864886f70d0209"
    "a10b0609608648016503040201"
    "300b06092a864886f70d010701"
    "a20c300a06032a03043103020101040411223344"
    "a30c300a06032a03043103020101"
)

# version 1 尾段：单 ktri + hmacWithSHA256 + id-data + mac（无 digest/authAttrs）。
CMS_AUTHENTICATED_V1_TAIL = bytes.fromhex(
    "312e302c0201003014300f310d300b06035504030c0474657374020101"
    "300b06092a864886f70d010101040401020304"
    "300a06082a864886f70d0209"
    "300b06092a864886f70d010701"
    "040411223344"
)


def authenticated_inner(version, originator, tail):
    body = b"\x02\x01" + bytes([version]) + originator + tail
    return b"\x30" + der_put_len(len(body)) + body


def generate_cms_authenticated():
    """写出固定的 AuthenticatedData 合成样本（version 0 / 1 / 3）。

    OpenSSL 的 `cms` 子命令没有 authData 生成入口（该结构在生产工具中
    少见），因此这些样本由脚本直接写出固定的 DER 字节，**不是外部实现
    产物**。主样本是 version 0 的干净形态（不含 originatorInfo）；
    version 1 / 3 样本的 `certs [0]` 取自 `cert_rsa_selfsigned.der`
    （合成自签证书，非生产证书），version 3 样本另带一个最小合法
    `crls [1]`（CertificateList）。三次写出全部由本脚本确定性拼装，
    不调用外部生成器；重跑得到的字节与已提交快照一致。样本只给只读
    访问与差分脚本提供稳定锚点，不声称被 OpenSSL 或其他生产方接受。
    """
    (DATA_DIR / "cms_authenticated_data.der").write_bytes(
        CMS_AUTHENTICATED_DATA_DER)

    cert = (DATA_DIR / "cert_rsa_selfsigned.der").read_bytes()
    originator_with_certs = authenticated_originator([cert], [])
    originator_with_certs_and_crls = authenticated_originator(
        [cert], [CMS_CRL_CERTIFICATE_LIST])

    def wrap(inner):
        oid = bytes.fromhex("060b2a864886f70d0109100102")
        return b"\x30" + der_put_len(len(oid) + 1 + der_len_bytes(
            len(inner)) + len(inner)) + oid + b"\xA0" + der_put_len(
                len(inner)) + inner

    v1_inner = authenticated_inner(1, originator_with_certs,
                                   CMS_AUTHENTICATED_V1_TAIL)
    v3_inner = authenticated_inner(3, originator_with_certs_and_crls,
                                   CMS_AUTHENTICATED_FULL_TAIL)
    (DATA_DIR / "cms_authenticated_data_v1.der").write_bytes(wrap(v1_inner))
    (DATA_DIR / "cms_authenticated_data_v3.der").write_bytes(wrap(v3_inner))


def generate_pkcs12():
    """用已提交的证书/私钥生成 PKCS#12 PFX 样本。

    PFX 中的 MAC、盐与加密填充含随机成分，重新生成得到的字节与仓库内已
    提交版本不同；测试只依赖结构字段（版本、OID、计数、原始 TLV），不对
    MAC 值或密文做断言。
    """
    required = ("key_rsa_pkcs8.pem", "cert_rsa_selfsigned.pem")
    for stem in required:
        if not (DATA_DIR / stem).exists():
            sys.stderr.write("缺少 PKCS#12 材料源文件：%s\n" % (DATA_DIR / stem))
            raise SystemExit(1)

    for stem, description, args in PKCS12_SAMPLES:
        der_path = DATA_DIR / (stem + ".der")
        command = [str(DATA_DIR / arg) if arg.endswith(".pem") else arg
                   for arg in args]
        run_openssl(["pkcs12", "-export"] + command +
                    ["-passout", "pass:%s" % PKCS12_PASSPHRASE,
                     "-out", str(der_path)])


def c_identifier(stem):
    """cert_rsa_selfsigned -> CertRsaSelfsigned。"""
    return "".join(part.capitalize() for part in stem.split("_"))


def write_header(der_path):
    """把 .der 转成 C 数组头；结果写入同名 .h。"""
    data = der_path.read_bytes()
    ident = c_identifier(der_path.stem)
    guard = "ASNBER_TEST_DATA_%s_H_INCLUDED" % der_path.stem.upper()
    lines = []
    lines.append("/*")
    lines.append(" * Copyright (c) 2026 asnber project contributors")
    lines.append(" * SPDX-License-Identifier: MIT")
    lines.append(" *")
    lines.append(" * 由 scripts/gen_test_data.py 自动生成，请勿手工修改。")
    lines.append(" * 源文件：tests/data/%s" % der_path.name)
    lines.append(" */")
    lines.append("#ifndef %s" % guard)
    lines.append("#define %s" % guard)
    lines.append("")
    lines.append("#include <stddef.h>")
    lines.append("")
    lines.append("#define k%sSize ((size_t)%du)" % (ident, len(data)))
    lines.append("static const unsigned char k%s[] = {" % ident)
    for offset in range(0, len(data), 12):
        chunk = data[offset:offset + 12]
        text = ", ".join("0x%02X" % byte for byte in chunk)
        lines.append("    %s," % text)
    lines.append("};")
    lines.append("")
    lines.append("#endif /* %s */" % guard)
    lines.append("")
    (der_path.with_suffix(".h")).write_text("\n".join(lines), encoding="utf-8")


def write_readme():
    readme = """# tests/data 测试材料

本目录存放零第三方 C 测试使用的真实 ASN.1 材料。所有 `.pem` / `.der` 由
`scripts/gen_test_data.py` 调用本机 `openssl` 生成；`*.h` 是同名 `.der` 的
C 数组表示，测试运行期不读文件。

## 来源与生成方式

- 生成脚本：`scripts/gen_test_data.py`（仅依赖 `openssl` 与 Python 标准库）。
- 生成命令：`python scripts/gen_test_data.py`。
- 本仓库快照使用 OpenSSL 3.5.9 生成。
- 只从已有 `.der` 重新生成头文件：`python scripts/gen_test_data.py --headers`。
- 只派生 PKCS#1 公私钥与加密 PKCS#8（不重新生成既有密钥）：
  `python scripts/gen_test_data.py --derived`。
- 只用已提交的证书/私钥生成 CMS SignedData 样本：
  `python scripts/gen_test_data.py --cms`。
- 只用已提交的证书生成 CMS EnvelopedData 样本：
  `python scripts/gen_test_data.py --cms-enveloped`。
- 生成 CMS EncryptedData 样本：
  `python scripts/gen_test_data.py --cms-encrypted`。
- 生成 CMS CompressedData 样本：
  `python scripts/gen_test_data.py --cms-compressed`。
- 写出 CMS AuthenticatedData **合成**样本（固定 DER，非外部生成器产物；
  主样本 version 0，version 3 用例在测试里用合成自签证书拼 `certs [0]`）：
  `python scripts/gen_test_data.py --cms-authenticated`。
- 只用已提交的证书/私钥生成 PKCS#12 PFX 样本：
  `python scripts/gen_test_data.py --pkcs12`。

| 文件 | 内容 |
| --- | --- |
| `key_rsa_pkcs8.pem/.der` | RSA-2048 私钥，PKCS#8，未加密 |
| `key_ec_pkcs8.pem/.der` | ECDSA P-256 私钥，PKCS#8，未加密 |
| `key_rsa_pss_pkcs8.pem/.der` | RSA-PSS 2048 私钥，PKCS#8，未加密 |
| `key_rsa_pkcs1_private.pem/.der` | RSA-2048 私钥，PKCS#1（传统格式） |
| `key_rsa_pkcs1_public.pem/.der` | RSA-2048 公钥，PKCS#1 `RSAPublicKey` |
| `key_rsa_pkcs8_encrypted.pem/.der` | RSA-2048 私钥，PKCS#8 `EncryptedPrivateKeyInfo`，PBES2 / AES-256-CBC，口令 `asn1-test` |
| `csr_rsa.pem/.der` | RSA-2048 证书请求（PKCS#10），SHA-256 |
| `csr_ec.pem/.der` | ECDSA P-256 证书请求（PKCS#10），SHA-256 |
| `cert_rsa_selfsigned.pem/.der` | RSA 自签名证书，SHA-256，含 basicConstraints/ SAN |
| `cert_ec_selfsigned.pem/.der` | ECDSA 自签名证书，SHA-256，含 basicConstraints/ SAN |
| `cert_rsa_pss_selfsigned.pem/.der` | RSA-PSS 自签名证书，SHA-256，AlgorithmIdentifier.parameters 为 SEQUENCE |
| `cms_rsa_attached.der` | CMS ContentInfo(SignedData)，attached，含 eContent、证书、signedAttrs |
| `cms_rsa_detached.der` | CMS ContentInfo(SignedData)，detached，无 eContent，含证书、signedAttrs |
| `cms_rsa_minimal.der` | CMS ContentInfo(SignedData) 最小样本，detached、无证书、无 signedAttrs |
| `cms_rsa_ec_multicert.der` | CMS ContentInfo(SignedData)，RSA + ECDSA 双签名者、多证书、attached |
| `cms_rsa_keyid.der` | CMS ContentInfo(SignedData)，SignerIdentifier 为 subjectKeyIdentifier |
| `cms_enveloped_ktri.der` | CMS ContentInfo(EnvelopedData)，单个 RSA 收件人，RecipientInfo 分支 [0] |
| `cms_enveloped_ktri_multi.der` | CMS ContentInfo(EnvelopedData)，同一 RSA 证书作为两个收件人，分支 [0]×2 |
| `cms_enveloped_ktri_keyid.der` | CMS ContentInfo(EnvelopedData)，RSA 收件人，rid 为 subjectKeyIdentifier（`-keyid`，ktri version 2） |
| `cms_enveloped_kari.der` | CMS ContentInfo(EnvelopedData)，EC 收件人 + subjectKeyIdentifier，分支 [1] |
| `cms_enveloped_kekri.der` | CMS ContentInfo(EnvelopedData)，预共享 KEK，分支 [2]（`-secretkeyid` + `-secretkey`） |
| `cms_enveloped_pwri.der` | CMS ContentInfo(EnvelopedData)，口令收件人，分支 [3]（`-pwri_password`） |
| `cms_encrypted_data.der` | CMS ContentInfo(EncryptedData)，version 0，AES-256-CBC（`-EncryptedData_encrypt -secretkey`） |
| `cms_compressed_data.der` | CMS ContentInfo(CompressedData)，version 0，zlib 压缩，内容类型 id-data（`cms -compress`） |
| `cms_authenticated_data.der` | CMS ContentInfo(AuthenticatedData)，version 0，**合成样本**（无外部生成器，脚本写入固定 DER），含 ktri/kekri、digestAlgorithm/authAttrs、mac、unauthAttrs；不带 originatorInfo |
| `cms_authenticated_data_v1.der` | CMS ContentInfo(AuthenticatedData)，version 1，**合成样本**，originatorInfo 只含 `certs [0]`（单张合成自签证书），不带 digestAlgorithm/authAttrs |
| `cms_authenticated_data_v3.der` | CMS ContentInfo(AuthenticatedData)，version 3，**合成样本**，originatorInfo 含 `certs [0]` 与最小合法 `crls [1]`（单条 CertificateList），完整 authAttrs/unauthAttrs |
| `pfx_rsa_unencrypted.der` | PKCS#12 PFX，证书 + RSA 私钥，SafeContents 未加密、无 MAC，含 friendlyName/localKeyId |
| `pfx_rsa_encrypted.der` | PKCS#12 PFX，证书 + RSA 私钥，PBES2 / AES-256-CBC，SHA-256 MAC，iterations 2048 |
| `pfx_certs_only.der` | PKCS#12 PFX，仅证书，certBag 使用 AES-256-CBC，SHA-256 MAC |

## 重现性说明

- 密钥与签名含随机成分，重新生成得到的字节与仓库内已提交的版本**不同**；
  已提交的 `.der` / `.h` 是权威快照。
- 测试只校验“解码→编码逐字节一致”的自洽性，以及结构解析，不依赖固定字节，
  因此重新生成后重新运行测试仍然成立。
- 证书有效期从生成当天起 3650 天；测试不对具体时间做断言。
- CMS 样本的签名值（ECDSA 随机）与 signingTime 含随机/时间成分，重跑得到的
  字节与已提交快照不同；测试只读取结构字段（版本、OID、原始 TLV、计数），
  不对签名值或时间做断言。
- CMS EnvelopedData 样本的内容加密密钥、`encryptedContent` 以及 KEK/口令
  派生盐含随机成分，重跑得到的字节与已提交快照不同；测试只读取结构字段，
  不对密文做断言。
- CMS EncryptedData 样本的内容加密密钥与 IV 含随机成分，重跑得到的字节与
  已提交快照不同；测试只读取结构字段，不对密文做断言。
- CMS CompressedData 样本的 zlib 压缩结果确定，重跑得到的字节与已提交快照
  一致；测试只读取结构字段，不解压内容。
- CMS AuthenticatedData 样本为**合成固定字节**（OpenSSL 的 `cms` 子命令
  没有 authData 生成入口）：主样本为 version 0 干净形态（不含
  `originatorInfo`），另有 version 1（`certs [0]`）与 version 3
  （`certs [0]` + `crls [1]`）两份静态样本。它们的证书取自
  `cert_rsa_selfsigned.der`（合成自签证书，非生产证书），由脚本确定性
  拼装，不调用外部生成器。重跑得到的字节与已提交快照一致；它们只作为
  结构读取与差分的稳定锚点，不声称被外部实现接受。
- PKCS#12 样本的 MAC、盐与加密填充含随机成分，重跑得到的字节与已提交快照
  不同；测试只读取结构字段，不对 MAC 值或密文做断言。

## 变异样本

DER 严格校验的“反例”字节（非最短长度、BOOLEAN 0x01、INTEGER 前导零、
SET 乱序、时间缺秒、OID 非最短等）直接写在测试源码的字面量数组里，不进
本目录，便于就近阅读与定位。
"""
    (DATA_DIR / "README.md").write_text(readme, encoding="utf-8")


def main(argv):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    headers_only = "--headers" in argv[1:]
    derived_only = "--derived" in argv[1:]
    cms_only = "--cms" in argv[1:]
    cms_enveloped_only = "--cms-enveloped" in argv[1:]
    cms_encrypted_only = "--cms-encrypted" in argv[1:]
    cms_compressed_only = "--cms-compressed" in argv[1:]
    cms_authenticated_only = "--cms-authenticated" in argv[1:]
    pkcs12_only = "--pkcs12" in argv[1:]

    try:
        if not headers_only and (derived_only or cms_only or cms_enveloped_only
                                 or cms_encrypted_only or cms_compressed_only
                                 or cms_authenticated_only or pkcs12_only):
            if derived_only:
                generate_derived()
            if cms_only:
                generate_cms()
            if cms_enveloped_only:
                generate_cms_enveloped()
            if cms_encrypted_only:
                generate_cms_encrypted()
            if cms_compressed_only:
                generate_cms_compressed()
            if cms_authenticated_only:
                generate_cms_authenticated()
            if pkcs12_only:
                generate_pkcs12()
        elif not headers_only:
            generate_keys()
            generate_csrs()
            generate_certs()
            generate_derived()
            generate_cms()
            generate_cms_enveloped()
            generate_cms_encrypted()
            generate_cms_compressed()
            generate_cms_authenticated()
            generate_pkcs12()
    finally:
        if _CONFIG_PATH is not None and os.path.exists(_CONFIG_PATH):
            os.unlink(_CONFIG_PATH)

    der_files = sorted(DATA_DIR.glob("*.der"))
    if not der_files:
        sys.stderr.write("tests/data 下没有 .der 文件可转换\n")
        return 1
    for der_path in der_files:
        write_header(der_path)

    write_readme()
    print("已处理 %d 个 .der 文件" % len(der_files))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
