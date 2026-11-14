# tests/data 测试材料

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
- 只用已提交的证书/私钥生成 OCSP 请求：
  `python scripts/gen_test_data.py --ocsp`。

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
| `ocsp_request.der` | OCSPRequest，自签证书的 CertID，无 nonce、无签名（`openssl ocsp -no_nonce -reqout`） |
| `ocsp_request_signed.der` | OCSPRequest，同一 CertID，带 requestorName、nonce 扩展和 optionalSignature（`openssl ocsp -signer -signkey -reqout`） |

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
- OCSP 无签名请求由证书哈希决定，重跑得到的字节与已提交快照一致。带签名
  请求的 nonce 和签名含随机成分，重跑得到的字节不同；测试只读取结构字段，
  不对 nonce 或签名值做断言。

## 变异样本

DER 严格校验的“反例”字节（非最短长度、BOOLEAN 0x01、INTEGER 前导零、
SET 乱序、时间缺秒、OID 非最短等）直接写在测试源码的字面量数组里，不进
本目录，便于就近阅读与定位。
