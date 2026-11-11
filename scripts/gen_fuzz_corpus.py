#!/usr/bin/env python3
# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT
"""确定性生成 libFuzzer 种子语料到 tests/fuzz/corpus/<harness>/。

只依赖标准库；纯确定性。产物体积小，检入仓库供 CI 复用。
扩展方式见 tests/fuzz/README.md。
"""
import os
import shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "tests", "data")
CORPUS = os.path.join(ROOT, "tests", "fuzz", "corpus")
PKIX_BIN = os.path.join(ROOT, "modules", "pkix", "generated", "pkix_schema.bin")

# 模块描述表（schema_load 语料）：直接喂入模块实际解码使用的表字节。
PKCS_BINS = [
    os.path.join(ROOT, "modules", module, "generated", name + ".bin")
    for module, name in [
        ("pkcs1", "pkcs1_schema"),
        ("pkcs8", "pkcs8_schema"),
        ("pkcs10", "pkcs10_schema"),
        ("pkcs12", "pkcs12_schema"),
    ]
]

CMS_BINS = [
    os.path.join(ROOT, "modules", "cms", "generated", "cms_schema.bin")
]

# 需要二进制种子（DER/BER）的 harness。
BIN_HARNESSES = [
    "decode_ber",
    "decode_der",
    "reader",
    "schema_decode",
    "roundtrip",
]

# 真实 DER 样本（tests/data 下的 .der）。
REAL_DERS = [
    "cert_rsa_selfsigned.der",
    "cert_rsa_pss_selfsigned.der",
    "cert_ec_selfsigned.der",
    "csr_rsa.der",
    "csr_ec.der",
    "key_rsa_pkcs8.der",
    "key_rsa_pss_pkcs8.der",
    "key_ec_pkcs8.der",
    "key_rsa_pkcs8_encrypted.der",
    "key_rsa_pkcs1_private.der",
    "key_rsa_pkcs1_public.der",
    "cms_rsa_attached.der",
    "cms_rsa_detached.der",
    "cms_rsa_minimal.der",
    "cms_rsa_ec_multicert.der",
    "cms_rsa_keyid.der",
    "cms_enveloped_ktri.der",
    "cms_enveloped_ktri_multi.der",
    "cms_enveloped_ktri_keyid.der",
    "cms_enveloped_kari.der",
    "cms_enveloped_kekri.der",
    "cms_enveloped_pwri.der",
    "cms_encrypted_data.der",
]

# 合成二进制种子：覆盖未知扩展/ANY 三形态/EXPLICIT ANY/不定长（单层+嵌套）/
# 截断/超长长度/多字节 tag/SET 乱序/非最短长度/时间变体/空输入 等。
SYNTH_BINARY = {
    "empty": b"",
    "null_any": b"\x05\x00",
    "seq_int": b"\x30\x03\x02\x01\x05",
    "seq_two_int": b"\x30\x06\x02\x01\x05\x02\x01\x00",
    "indefinite_seq": b"\x30\x80\x02\x01\x05\x00\x00",
    "indefinite_nested": b"\x30\x80\x30\x80\x02\x01\x05\x00\x00\x00\x00",
    "indefinite_missing_eoc": b"\x30\x80\x02\x01\x05",
    "trunc_struct": b"\x30\x06\x02\x01\x05",
    "trunc_header": b"\x30",
    "long_len_4byte_zero": b"\x30\x84\x00\x00\x00\x00",
    "long_len_claim_huge": b"\x30\x84\x7f\xff\xff\xff",
    "long_len_1byte": b"\x30\x81\x80",
    "multi_tag_128": b"\x1f\x81\x00\x00",
    "multi_tag_16383": b"\x1f\xff\x7f\x00",
    "multi_tag_trunc": b"\x1f\x81",
    "set_unordered": b"\x31\x06\x02\x01\x05\x02\x01\x00",
    "non_minimal_len_int": b"\x02\x81\x01\x05",
    "non_minimal_len_seq": b"\x30\x81\x03\x02\x01\x05",
    "explicit_any": b"\xa0\x03\x02\x01\x05",
    "explicit_any_nested": b"\xa0\x07\x30\x03\x02\x01\x05",
    "context_constructed": b"\xa1\x03\x02\x01\x05",
    "context_primitive": b"\x83\x01\x05",
    "unknown_ext": b"\xa3\x05\x30\x03\x02\x01\x01",
    "boolean_true": b"\x01\x01\xff",
    "boolean_bad": b"\x01\x01\x01",
    "oid_ec_p256": b"\x06\x07\x2a\x86\x48\xce\x3d\x04\x01",
    "utctime_z": b"\x17\x0d" + b"250101000000Z",
    "gentime_z": b"\x18\x0f" + b"20250101000000Z",
    "gentime_frac": b"\x18\x11" + b"20250101000000.5Z",
    "time_bad_char": b"\x17\x0d" + b"2501010000XXZ",
    "eoc_only": b"\x00\x00",
    "eoc_misplaced": b"\x00\x00\x05\x00",
    "octet_constructed": b"\x24\x80\x04\x02ab\x00\x00",
    "high_tag_private": b"\xdf\x81\x00\x00",
}

def _der_tlv(tag, content):
    if len(content) < 0x80:
        header = bytes([tag, len(content)])
    else:
        n = len(content)
        octets = []
        while n:
            octets.insert(0, n & 0xFF)
            n >>= 8
        header = bytes([tag, 0x80 | len(octets)] + octets)
    return header + content


def _der_int(value):
    if value == 0:
        return b"\x00"
    size = 1
    while True:
        try:
            return value.to_bytes(size, "big", signed=True)
        except OverflowError:
            size += 1


def _der_seq(*items):
    return _der_tlv(0x30, b"".join(items))


def _der_set(*items):
    return _der_tlv(0x31, b"".join(items))


def _der_null():
    return b"\x05\x00"


OID_P256 = _der_tlv(0x06, b"\x2a\x86\x48\xce\x3d\x04\x01")
BOOL_TRUE = b"\x01\x01\xff"

# schema_decode 专用种子：与 harness 内富表（RichRoot）、未知字段表（SEQ{INT}）、
# SET 表（SET{INT,OCT OPT}）、根 SIMPLE/CHOICE/必需 ANY 表逐项对应。
SCHEMA_DECODE_SYNTH = {
    # RichRoot：基础与全量。
    "rich_min": _der_seq(_der_tlv(0x02, _der_int(0))),
    "rich_range_high": _der_seq(_der_tlv(0x02, _der_int(8))),
    "rich_range_low": _der_seq(_der_tlv(0x02, _der_int(-6))),
    "rich_full": _der_seq(
        _der_tlv(0x02, _der_int(0)),
        _der_tlv(0x86, _der_int(10 ** 19)),
        _der_tlv(0x8B, _der_int(3)),
        _der_tlv(0x0A, _der_int(3)),
        _der_tlv(0x04, b"ab"),
        _der_tlv(0x87, b"ab"),
        _der_tlv(0xA0, _der_tlv(0x02, _der_int(5))),
        _der_tlv(0x85, _der_int(5)),
        OID_P256,
        _der_tlv(0xA9, _der_seq(OID_P256, _der_tlv(0x06, b"\x2a"))),
        _der_tlv(0xAA, _der_set(_der_tlv(0x02, _der_int(1)),
                               _der_tlv(0x02, _der_int(2)))),
        _der_tlv(0xA8, _der_set(BOOL_TRUE, _der_tlv(0x02, _der_int(5)))),
        _der_tlv(0xA2, _der_seq(_der_tlv(0x02, _der_int(5)) )),
        _der_tlv(0x02, _der_int(3)),
        _der_tlv(0xA3, _der_null()),
        _der_null(),
    ),
    # BIGINT 约束两侧：10^19 通过，10^21 越界。
    "rich_big_ok": _der_seq(_der_tlv(0x02, _der_int(0)),
                           _der_tlv(0x86, _der_int(10 ** 19))),
    "rich_big_fail": _der_seq(_der_tlv(0x02, _der_int(0)),
                              _der_tlv(0x86, _der_int(10 ** 21))),
    # ENUM（IMPLICIT）与 ENUMERATED 两侧。
    "rich_enum_ok": _der_seq(_der_tlv(0x02, _der_int(0)),
                             _der_tlv(0x8B, _der_int(3))),
    "rich_enum_bad": _der_seq(_der_tlv(0x02, _der_int(0)),
                              _der_tlv(0x8B, _der_int(2))),
    "rich_enum_big": _der_seq(_der_tlv(0x02, _der_int(0)),
                              _der_tlv(0x8B, _der_int(-2 ** 63))),
    "rich_enumtag_ok": _der_seq(_der_tlv(0x02, _der_int(0)),
                                _der_tlv(0x0A, _der_int(3))),
    "rich_enumtag_bad": _der_seq(_der_tlv(0x02, _der_int(0)),
                                 _der_tlv(0x0A, _der_int(2))),
    # IMPLICIT INTEGER 约束两侧。
    "rich_impl_ok": _der_seq(_der_tlv(0x02, _der_int(0)),
                             _der_tlv(0x85, _der_int(5))),
    "rich_impl_bad": _der_seq(_der_tlv(0x02, _der_int(0)),
                              _der_tlv(0x85, _der_int(11))),
    # OCTET STRING SIZE 与 MAX 两侧。
    "rich_oct_short": _der_seq(_der_tlv(0x02, _der_int(0)),
                               _der_tlv(0x04, b"a")),
    "rich_oct_long": _der_seq(_der_tlv(0x02, _der_int(0)),
                              _der_tlv(0x04, b"abcde")),
    "rich_maxoct_ok": _der_seq(_der_tlv(0x02, _der_int(0)),
                               _der_tlv(0x87, b"ab")),
    "rich_maxoct_bad": _der_seq(_der_tlv(0x02, _der_int(0)),
                                _der_tlv(0x87, b"a")),
    # EXPLICIT INTEGER：通过、越界、内层非 INTEGER、包装标签错误、多子节点。
    "rich_expl_ok": _der_seq(_der_tlv(0x02, _der_int(0)),
                             _der_tlv(0xA0, _der_tlv(0x02, _der_int(5))),
                             ),
    "rich_expl_bad": _der_seq(_der_tlv(0x02, _der_int(0)),
                              _der_tlv(0xA0, _der_tlv(0x02, _der_int(11))),
                              ),
    "rich_expl_nonint": _der_seq(_der_tlv(0x02, _der_int(0)),
                                 _der_tlv(0xA0, _der_tlv(0x04, b"a"))),
    "rich_expl_wrongtag": _der_seq(_der_tlv(0x02, _der_int(0)),
                                   _der_tlv(0xA1, _der_tlv(0x02, _der_int(5)))),
    "rich_expl_two": _der_seq(_der_tlv(0x02, _der_int(0)),
                              _der_tlv(0xA0, _der_tlv(0x02, _der_int(5)) +
                                       _der_tlv(0x02, _der_int(6))),
                              _der_tlv(0x05, b"")),
    # CHOICE 两个分支与无分支。
    "rich_choice_oid": _der_seq(_der_tlv(0x02, _der_int(0)), OID_P256),
    "rich_choice_bool": _der_seq(_der_tlv(0x02, _der_int(0)),
                                 BOOL_TRUE),
    # SEQUENCE OF / SET OF 数量两侧与元素类型错误。
    "rich_seqof_ok": _der_seq(_der_tlv(0x02, _der_int(0)),
                              _der_tlv(0xA9, _der_seq(OID_P256,
                                                      _der_tlv(0x06, b"\x2a"))),
                              ),
    "rich_seqof_empty": _der_seq(_der_tlv(0x02, _der_int(0)),
                                 _der_tlv(0xA9, _der_seq())),
    "rich_seqof_four": _der_seq(
        _der_tlv(0x02, _der_int(0)),
        _der_tlv(0xA9, _der_seq(OID_P256, _der_tlv(0x06, b"\x2a"),
                                _der_tlv(0x06, b"\x2a"),
                                _der_tlv(0x06, b"\x2a"))),
    ),
    "rich_seqof_badelem": _der_seq(_der_tlv(0x02, _der_int(0)),
                                  _der_tlv(0xA9, _der_seq(
                                      _der_tlv(0x02, _der_int(5)))),
                                  ),
    "rich_setof_ok": _der_seq(
        _der_tlv(0x02, _der_int(0)),
        _der_tlv(0xAA, _der_set(_der_tlv(0x02, _der_int(1)),
                                _der_tlv(0x02, _der_int(2)))),
    ),
    "rich_setof_empty": _der_seq(_der_tlv(0x02, _der_int(0)),
                                 _der_tlv(0xAA, _der_set())),
    "rich_setof_badelem": _der_seq(_der_tlv(0x02, _der_int(0)),
                                   _der_tlv(0xAA, _der_set(
                                       _der_tlv(0x04, b"a"))),
                                   ),
    # SET（EXPLICIT 包装）通过、必需字段缺失、未知字段、乱序。
    "rich_innerset_ok": _der_seq(_der_tlv(0x02, _der_int(0)),
                                 _der_tlv(0xA8, _der_set(
                                     BOOL_TRUE,
                                     _der_tlv(0x02, _der_int(5)))),
                                 ),
    "rich_innerset_missing": _der_seq(
        _der_tlv(0x02, _der_int(0)),
        _der_tlv(0xA8, _der_set(_der_tlv(0x02, _der_int(5)))),
    ),
    "rich_innerset_unknown": _der_seq(
        _der_tlv(0x02, _der_int(0)),
        _der_tlv(0xA8, _der_set(BOOL_TRUE, _der_tlv(0x02, _der_int(5)),
                                _der_tlv(0x04, b"a"))),
    ),
    # EXPLICIT SEQUENCE 与 EXPLICIT ANY（单子、双子、空包装）。
    "rich_explseq_ok": _der_seq(_der_tlv(0x02, _der_int(0)),
                                _der_tlv(0xA2, _der_seq(
                                    _der_tlv(0x02, _der_int(5)))),
                                ),
    "rich_anyexp_two": _der_seq(_der_tlv(0x02, _der_int(0)),
                                _der_tlv(0xA3, _der_null() + _der_null())),
    "rich_anyexp_empty": _der_seq(_der_tlv(0x02, _der_int(0)),
                                  _der_tlv(0xA3, b"")),
    # 未知字段表 SEQ { INT a }：未知保留 / 缺失必需。
    "unknown_seq_ok": _der_seq(_der_tlv(0x02, _der_int(5))),
    "unknown_seq_unknown": _der_seq(_der_tlv(0x02, _der_int(5)), BOOL_TRUE),
    "unknown_seq_missing": _der_seq(),
    # SET 表：通过、未知、缺失。
    "set_root_ok": _der_set(_der_tlv(0x02, _der_int(5)),
                            _der_tlv(0x04, b"a")),
    "set_root_unknown": _der_set(_der_tlv(0x02, _der_int(5)), BOOL_TRUE),
    "set_root_missing": _der_set(_der_tlv(0x04, b"a")),
    # 根 SIMPLE / 根 CHOICE / 必需 ANY。
    "simple_root_ok": _der_tlv(0x02, _der_int(5)),
    "simple_root_wrongtag": _der_tlv(0x04, b"a"),
    "choice_root_ok": OID_P256,
    "choice_root_nomatch": _der_tlv(0x03, b"\x00"),
    "any_required_ok": _der_seq(_der_tlv(0x02, _der_int(5)), _der_null()),
    "any_required_missing": _der_seq(_der_tlv(0x02, _der_int(5))),
    # EXPLICIT CHOICE / IMPLICIT SEQUENCE / IMPLICIT SET OF。
    "rich_expl_choice": _der_seq(_der_tlv(0x02, _der_int(0)),
                                 _der_tlv(0xAC, OID_P256)),
    "rich_expl_choice_bad": _der_seq(_der_tlv(0x02, _der_int(0)),
                                    _der_tlv(0xAC,
                                             _der_tlv(0x02, _der_int(5)))),
    "rich_implseq": _der_seq(_der_tlv(0x02, _der_int(0)),
                             _der_tlv(0xAD, _der_tlv(0x02, _der_int(5)))),
    "rich_implseq_missing": _der_seq(_der_tlv(0x02, _der_int(0)),
                                     _der_tlv(0xAD, b"")),
    "rich_implsetof": _der_seq(_der_tlv(0x02, _der_int(0)),
                               _der_tlv(0xAE, _der_tlv(0x02, _der_int(1)) +
                                        _der_tlv(0x02, _der_int(2)))),
    "rich_implsetof_empty": _der_seq(_der_tlv(0x02, _der_int(0)),
                                     _der_tlv(0xAE, b"")),
    "rich_implsetof_three": _der_seq(_der_tlv(0x02, _der_int(0)),
                                     _der_tlv(0xAE, _der_tlv(0x02, _der_int(1)) +
                                              _der_tlv(0x02, _der_int(2)) +
                                              _der_tlv(0x02, _der_int(3)))),
    "rich_impl_empty": _der_seq(_der_tlv(0x02, _der_int(0)),
                                _der_tlv(0x85, b"")),
    "rich_range_huge": _der_seq(_der_tlv(0x02, b"\x01" + b"\x00" * 512)),
    "rich_enum_huge": _der_seq(_der_tlv(0x02, _der_int(0)),
                               _der_tlv(0x8B, _der_int(10 ** 20))),
    "rich_any_bare": _der_seq(_der_tlv(0x02, _der_int(0)), _der_null()),
    "rich_any_indef": _der_seq(_der_tlv(0x02, _der_int(0)),
                               b"\x05\x80\x00\x00"),
    "rich_any_long": _der_seq(_der_tlv(0x02, _der_int(0)),
                              _der_tlv(0x04, b"a" * 200)),
    "rich_missing_ranged": _der_seq(_der_tlv(0x04, b"ab")),
    "rich_implset": _der_seq(_der_tlv(0x02, _der_int(0)),
                             _der_tlv(0xAF, _der_tlv(0x02, _der_int(5)))),
    # SET 内字段约束失败（count 超出 RANGE）。
    "rich_innerset_bad": _der_seq(_der_tlv(0x02, _der_int(0)),
                                  _der_tlv(0xA8, _der_set(
                                      BOOL_TRUE, _der_tlv(0x02, _der_int(8)))),
                                  ),
    # SET 根表：缺省 DEFAULT 字段。
    "set_root_default": _der_set(_der_tlv(0x02, _der_int(5))),
    # SEQUENCE OF 带元素值域约束：进入非 SIZE 约束分支后必然失败。
    "of_range": _der_seq(_der_tlv(0x02, _der_int(1))),
    "of_range_empty": _der_seq(),
    # 三层嵌套 / 根 EXPLICIT 包装。
    "nested3": _der_seq(_der_tlv(0x02, _der_int(0)),
                        _der_seq(_der_tlv(0x02, _der_int(0)),
                                 _der_seq(_der_tlv(0x02, _der_int(0))))) ,
    "expl_root_ok": _der_tlv(0xA0, _der_tlv(0x02, _der_int(5))),
    "expl_root_badtag": _der_tlv(0xA1, _der_tlv(0x02, _der_int(5))),
    "any_expl_root_ok": _der_tlv(0xA3, _der_null()),
    "any_expl_root_badtag": _der_tlv(0xA4, _der_null()),
    # 尾随与截断。
    "rich_trailing": _der_seq(_der_tlv(0x02, _der_int(0))) + _der_null(),
    "rich_truncated": b"\x30\x03\x02",
}


# 模块级 open harness：每个结构只放对应的真实样本，再派生截断/标签翻转/
# 长度 +1 三类确定性变体。同一输入会被 harness 依次按多种结构尝试。
MODULE_CORPORA = {
    "pkix_open": [
        "cert_rsa_selfsigned.der",
        "cert_rsa_pss_selfsigned.der",
        "cert_ec_selfsigned.der",
    ],
    "pkcs_open": [
        "key_rsa_pkcs8.der",
        "key_rsa_pss_pkcs8.der",
        "key_ec_pkcs8.der",
        "key_rsa_pkcs8_encrypted.der",
        "key_rsa_pkcs1_private.der",
        "key_rsa_pkcs1_public.der",
        "csr_rsa.der",
        "csr_ec.der",
        "pfx_rsa_unencrypted.der",
        "pfx_rsa_encrypted.der",
        "pfx_certs_only.der",
    ],
    "cms_open": [
        "cms_rsa_attached.der",
        "cms_rsa_detached.der",
        "cms_rsa_minimal.der",
        "cms_rsa_ec_multicert.der",
        "cms_rsa_keyid.der",
        "cms_enveloped_ktri.der",
        "cms_enveloped_ktri_multi.der",
        "cms_enveloped_ktri_keyid.der",
        "cms_enveloped_kari.der",
        "cms_enveloped_kekri.der",
        "cms_enveloped_pwri.der",
        "cms_encrypted_data.der",
        "cms_compressed_data.der",
        "cms_authenticated_data.der",
        "cms_authenticated_data_v1.der",
        "cms_authenticated_data_v3.der",
    ],
}

# 无外部生成器样本的结构：手写最小 DER 作为语料，仅用于覆盖只读入口与
# 访问器；不代表真实生产方输出。
MODULE_SYNTH = {
    "cms_open": {
        # 裸 AuthenticatedData：version 0 + ktri + hmacWithSHA256 +
        # id-data（detached）+ 4 字节 MAC。
        "auth_data_minimal.der": bytes.fromhex(
            "3052"
            "020100"
            "312E"
            "302C0201003014300F310D300B06035504030C0474657374020101"
            "300B06092A864886F70D010101"
            "040401020304"
            "300A06082A864886F70D0209"
            "300B06092A864886F70D010701"
            "040411223344"
        ),
    },
}


def _module_variants(name, data):
    """真实样本 + 截断 + 首字节标签翻转 + 长度字段 +1。"""
    stem = name[:-4] if name.endswith(".der") else name
    yield stem, data

    if len(data) > 1:
        yield stem + "_trunc_half", data[: len(data) // 2]

    if data:
        flipped = bytearray(data)
        flipped[0] ^= 0x20
        yield stem + "_tagflip", bytes(flipped)

    if len(data) >= 2:
        bumped = bytearray(data)
        if bumped[1] < 0x80:
            bumped[1] += 1
        elif bumped[1] != 0x80 and len(bumped) >= 3:
            bumped[2] += 1
        yield stem + "_lenplus1", bytes(bumped)


ASNBERC_DIR = os.path.join(DATA, "asnberc")
ASNBERC_SEEDS = ["equiv_sample.asn1"] + [
    os.path.join("negative", f)
    for f in sorted(os.listdir(os.path.join(ASNBERC_DIR, "negative")))
]

SYNTH_ASNBERC = {
    "empty": "",
    "minimal_module": "M DEFINITIONS ::= BEGIN END\n",
    "junk": "@@@ ### $$$",
    "truncated_module": "M DEFINITIONS ::= BEGIN\nT ::= SEQUENCE {\n",
    "seq_module": ("M DEFINITIONS EXPLICIT TAGS ::= BEGIN\n"
                   "T ::= SEQUENCE { a INTEGER OPTIONAL, b OCTET STRING }\n"
                   "END\n"),
}


def write_bytes(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def write_text(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def main():
    # 1) 二进制 harness：真实 DER + 合成二进制种子。
    for h in BIN_HARNESSES:
        hdir = os.path.join(CORPUS, h)
        for name in REAL_DERS:
            src = os.path.join(DATA, name)
            write_bytes(os.path.join(hdir, name), open(src, "rb").read())
        for name, data in SYNTH_BINARY.items():
            write_bytes(os.path.join(hdir, name), data)

    # 1.1) schema_decode 专用定向种子（对应 harness 内富表与各根表）。
    hdir = os.path.join(CORPUS, "schema_decode")
    for name, data in SCHEMA_DECODE_SYNTH.items():
        write_bytes(os.path.join(hdir, name), data)

    # 1.2) 模块级 open harness：对应真实样本 + 确定性变体 + 空输入。
    for harness, names in MODULE_CORPORA.items():
        hdir = os.path.join(CORPUS, harness)
        for name in names:
            src = os.path.join(DATA, name)
            data = open(src, "rb").read()
            for seed_name, payload in _module_variants(name, data):
                write_bytes(os.path.join(hdir, seed_name), payload)
        for seed_name, payload in MODULE_SYNTH.get(harness, {}).items():
            write_bytes(os.path.join(hdir, seed_name), payload)
        write_bytes(os.path.join(hdir, "empty"), b"")
        write_bytes(os.path.join(hdir, "tag_only"), b"\x30")

    # 2) schema_load：真实 PKIX/PKCS/CMS 表字节（最大攻击面）+ 空/垃圾。
    hdir = os.path.join(CORPUS, "schema_load")
    write_bytes(os.path.join(hdir, "pkix_schema.bin"),
                open(PKIX_BIN, "rb").read())
    for path in PKCS_BINS + CMS_BINS:
        write_bytes(os.path.join(hdir, os.path.basename(path)),
                    open(path, "rb").read())
    write_bytes(os.path.join(hdir, "empty"), b"")
    write_bytes(os.path.join(hdir, "magic_only"), b"ASN1SCH")
    write_bytes(os.path.join(hdir, "garbage"), b"\xde\xad\xbe\xef" * 16)

    # 3) asnberc 文本 harness。
    hdir = os.path.join(CORPUS, "asnberc")
    for name in ASNBERC_SEEDS:
        src = os.path.join(ASNBERC_DIR, name)
        write_text(os.path.join(hdir, name.replace("/", "_")),
                   open(src, encoding="utf-8").read())
    for name, text in SYNTH_ASNBERC.items():
        write_text(os.path.join(hdir, name), text)

    print("corpus generated under", CORPUS)


if __name__ == "__main__":
    main()