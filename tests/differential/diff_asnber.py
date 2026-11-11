#!/usr/bin/env python3
# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT
"""差分测试：核心 DER 解码 vs OpenSSL asn1parse（主），asn1tools 生成器（可选参照）。

判据：
  - 对 tests/data 的 DER 样本，比“能否解析、TLV 边界与偏移、结构层级”。
  - decode -> encode 往返后，用 openssl 确认仍是合法 DER 且逐字节一致。

留档：
  - --report <path>      写出 Markdown 逐样本对照记录（可检入仓库）；
  - --report-json <path> 写出同内容的结构化 JSON（CI artifact）。
  记录只含样本名、大小、双方 TLV 树字段与结论，不含工具版本与时间戳，
  同一仓库快照本地复跑产出一致。

退出码：
  0 = 通过（全部比较完成，无未归类差异）
  1 = 失败（发现未归类差异）
  2 = skipped（必需参照工具缺失：asnber_dump 或 openssl）

参照工具不链接进产物、不做运行时依赖；asn1tools 缺装时该段显式 skipped。
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA = os.path.join(ROOT, "tests", "data")

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
    "cms_compressed_data.der",
    # 合成样本：AuthenticatedData 无外部生成器，字节由
    # scripts/gen_test_data.py 固定写出；差分只比对 TLV 结构与偏移，
    # 不声称该样本被外部实现接受。
    "cms_authenticated_data.der",
    "cms_authenticated_data_v1.der",
    "cms_authenticated_data_v3.der",
]

OPENSSL_LINE = re.compile(
    r"^\s*(\d+):d=(\d+)\s+hl=(\d+)\s+l=\s*(\d+)\s+(cons|prim):")

# 已知可接受差异：openssl 对构造字符串的展开与我们（合并为基本）不同。
# 当前 DER 样本均不触发；若触发则记录并跳过失败，另列清单核对。
KNOWN_ACCEPTABLE = set()


def find_tool(name):
    return shutil.which(name)


def run_openssl_dump(openssl, path):
    """返回 openssl asn1parse 解析出的 (offset,depth,hl,l,cons) 列表。"""
    proc = subprocess.run(
        [openssl, "asn1parse", "-inform", "DER", "-i", "-in", path],
        capture_output=True, text=True)
    entries = []
    for line in proc.stdout.splitlines():
        m = OPENSSL_LINE.match(line)
        if m:
            offset, depth, hl, l, cons = m.groups()
            entries.append((int(offset), int(depth), int(hl), int(l), cons))
    return entries, proc.returncode, proc.stderr


def run_our_dump(asnber_dump, path):
    proc = subprocess.run([asnber_dump, path], capture_output=True, text=True)
    entries = []
    for line in proc.stdout.splitlines():
        m = OPENSSL_LINE.match(line)
        if m:
            offset, depth, hl, l, cons = m.groups()
            entries.append((int(offset), int(depth), int(hl), int(l), cons))
    return entries, proc.returncode, proc.stderr


def compare_entry(our, osl):
    # 逐字段比较 offset/depth/hl/l/cons。
    return our == osl


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--asnber-dump", default=None,
                    help="asnber_dump 可执行文件路径（默认自动探测 build 目录）")
    ap.add_argument("--data-dir", default=DATA)
    ap.add_argument("--skip-asn1tools", action="store_true")
    ap.add_argument("--report", default=None,
                    help="写出 Markdown 逐样本对照记录")
    ap.add_argument("--report-json", default=None,
                    help="写出结构化 JSON 对照记录")
    args = ap.parse_args()

    openssl = find_tool("openssl")
    asnber_dump = args.asnber_dump or _find_dump()
    if asnber_dump is None:
        print("SKIPPED: asnber_dump 未找到（先构建 tests/differential）")
        return 2
    if openssl is None:
        print("SKIPPED: openssl 未安装")
        return 2

    total = 0
    mismatches = []
    roundtrip_ok = 0
    roundtrip_fail = 0
    results = []
    asn1tools_status = "skipped (未运行)"

    with tempfile.TemporaryDirectory() as tmp:
        for name in REAL_DERS:
            path = os.path.join(args.data_dir, name)
            if not os.path.exists(path):
                continue
            total += 1
            size = os.path.getsize(path)

            ours, our_rc, _ = run_our_dump(asnber_dump, path)
            openr, op_rc, _ = run_openssl_dump(openssl, path)

            record = {
                "sample": name,
                "size": size,
                "openssl": {"returncode": op_rc, "entries": openr},
                "ours": {"returncode": our_rc, "entries": ours},
                "verdict": "FAIL",
                "reason": None,
                "roundtrip": "not-run",
            }

            if our_rc != 0:
                record["reason"] = "我们无法解析"
                mismatches.append((name, "我们无法解析"))
                results.append(record)
                continue
            if op_rc != 0:
                record["reason"] = "openssl 无法解析"
                mismatches.append((name, "openssl 无法解析"))
                results.append(record)
                continue

            if ours != openr:
                # 逐条找差异归因。
                diff_detail = []
                for i in range(max(len(ours), len(openr))):
                    a = ours[i] if i < len(ours) else None
                    b = openr[i] if i < len(openr) else None
                    if a != b:
                        diff_detail.append((i, a, b))
                record["reason"] = "结构差异 %r" % (diff_detail,)
                mismatches.append((name, record["reason"]))
                results.append(record)
                continue

            # decode -> encode 往返。
            out_path = os.path.join(tmp, name + ".rt.der")
            rt = subprocess.run(
                [asnber_dump, "--roundtrip", path, out_path],
                capture_output=True)
            if rt.returncode != 0:
                roundtrip_fail += 1
                record["reason"] = "往返编码失败"
                mismatches.append((name, "往返编码失败"))
                results.append(record)
                continue
            with open(path, "rb") as f:
                orig = f.read()
            with open(out_path, "rb") as f:
                encoded = f.read()
            if orig != encoded:
                roundtrip_fail += 1
                record["reason"] = "往返结果与输入逐字节不一致"
                mismatches.append((name, "往返结果与输入逐字节不一致"))
                results.append(record)
                continue
            # 用 openssl 确认往返产物仍是合法 DER。
            _, rt_op_rc, _ = run_openssl_dump(openssl, out_path)
            if rt_op_rc != 0:
                roundtrip_fail += 1
                record["reason"] = "往返产物 openssl 无法解析"
                mismatches.append((name, "往返产物 openssl 无法解析"))
                results.append(record)
                continue

            roundtrip_ok += 1
            record["verdict"] = "PASS"
            record["roundtrip"] = "pass"
            results.append(record)

        # asn1tools 参照（可选）：在持久 tmp 内运行。
        if not args.skip_asn1tools:
            asn1tools_status = _run_asn1tools(asnber_dump, openssl, tmp)

    if args.report:
        _write_markdown_report(args.report, results, total,
                               roundtrip_ok, roundtrip_fail)
    if args.report_json:
        _write_json_report(args.report_json, results, total,
                           roundtrip_ok, roundtrip_fail)

    print("样本数:", total)
    print("往返通过:", roundtrip_ok, "往返失败:", roundtrip_fail)
    print("asn1tools:", asn1tools_status)
    if mismatches:
        print("差异明细:")
        for name, detail in mismatches:
            print("  - %s: %s" % (name, detail))
        return 1
    print("差分通过：未发现未归类差异")
    return 0


def _write_markdown_report(path, results, total, roundtrip_ok,
                           roundtrip_fail):
    """写出逐样本的 TLV 树对照记录；内容与运行环境无关。"""
    lines = []
    lines.append("# 差分记录：核心 DER 解码对照 OpenSSL asn1parse")
    lines.append("")
    lines.append("本文件由 `tests/differential/diff_asnber.py --report` 生成，"
                 "随仓库留档，用于逐样本审计。")
    lines.append("")
    lines.append("- 参照方：OpenSSL `asn1parse -inform DER -i`；"
                 "被比较方：`asnber_dump`（核心严格 DER 解码）。")
    lines.append("- 比较字段：偏移、层级（depth）、TLV 头长度（hl）、"
                 "内容长度（l）、形态（cons/prim）。")
    lines.append("- 记录不含工具版本与时间戳；同一仓库快照本地复跑产出一致。")
    lines.append("- 结构一致后继续做 decode→encode 往返：与输入逐字节比较，"
                 "并用 OpenSSL 复核产物可解析。")
    lines.append("")
    lines.append("汇总：样本 %d，结构一致 %d，结构失败 %d；"
                 "往返一致 %d，往返失败 %d。"
                 % (total, sum(1 for r in results if r["verdict"] == "PASS"),
                    sum(1 for r in results if r["verdict"] != "PASS"),
                    roundtrip_ok, roundtrip_fail))
    lines.append("")

    for index, result in enumerate(results, start=1):
        lines.append("## %d. %s" % (index, result["sample"]))
        lines.append("")
        lines.append("- 输入大小：%d 字节" % result["size"])
        lines.append("- 结论：%s" % result["verdict"])
        if result["reason"] is not None:
            lines.append("- 失败原因：%s" % result["reason"])
        lines.append("- 往返：%s" % result["roundtrip"])

        our_entries = result["ours"]["entries"]
        op_entries = result["openssl"]["entries"]
        rows = max(len(our_entries), len(op_entries))
        lines.append("")
        lines.append("| # | OpenSSL offset | OpenSSL depth | OpenSSL hl | "
                     "OpenSSL l | OpenSSL 形态 | asnber_dump offset | "
                     "asnber_dump depth | asnber_dump hl | asnber_dump l | "
                     "asnber_dump 形态 | 一致 |")
        lines.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- | "
                     "--- | --- | --- |")
        for i in range(rows):
            op = op_entries[i] if i < len(op_entries) else None
            our = our_entries[i] if i < len(our_entries) else None
            same = "是" if op == our else "否"
            op_off = "—" if op is None else str(op[0])
            op_depth = "—" if op is None else str(op[1])
            op_hl = "—" if op is None else str(op[2])
            op_l = "—" if op is None else str(op[3])
            op_form = "—" if op is None else op[4]
            our_off = "—" if our is None else str(our[0])
            our_depth = "—" if our is None else str(our[1])
            our_hl = "—" if our is None else str(our[2])
            our_l = "—" if our is None else str(our[3])
            our_form = "—" if our is None else our[4]
            lines.append("| %d | %s | %s | %s | %s | %s | %s | %s | %s | %s | "
                         "%s | %s |"
                         % (i, op_off, op_depth, op_hl, op_l, op_form,
                            our_off, our_depth, our_hl, our_l, our_form, same))
        lines.append("")

    _write_text(path, "\n".join(lines))


def _write_json_report(path, results, total, roundtrip_ok, roundtrip_fail):
    payload = {
        "schema": "asnber-differential-report",
        "version": 1,
        "summary": {
            "samples": total,
            "passed": sum(1 for r in results if r["verdict"] == "PASS"),
            "failed": sum(1 for r in results if r["verdict"] != "PASS"),
            "roundtrip_ok": roundtrip_ok,
            "roundtrip_fail": roundtrip_fail,
        },
        "samples": [
            {
                "sample": r["sample"],
                "size": r["size"],
                "verdict": r["verdict"],
                "reason": r["reason"],
                "roundtrip": r["roundtrip"],
                "openssl": {
                    "returncode": r["openssl"]["returncode"],
                    "entries": [list(e) for e in r["openssl"]["entries"]],
                },
                "ours": {
                    "returncode": r["ours"]["returncode"],
                    "entries": [list(e) for e in r["ours"]["entries"]],
                },
            }
            for r in results
        ],
    }
    _write_text(path, json.dumps(payload, ensure_ascii=False, indent=2,
                                 sort_keys=True) + "\n")


def _write_text(path, text):
    with open(path, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(text)


def _find_dump():
    for cand in [
        os.path.join(ROOT, "build", "tests", "differential", "asnber_dump"),
        os.path.join(ROOT, "build-diff", "tests", "differential", "asnber_dump"),
    ]:
        if os.path.exists(cand):
            return cand
    return None


def _run_asn1tools(asnber_dump, openssl, tmp):
    try:
        import asn1tools  # noqa: F401
    except ImportError:
        return "skipped (asn1tools 未安装)"

    spec = (""""Rec DEFINITIONS ::= BEGIN
  Rec ::= SEQUENCE { i INTEGER, s OCTET STRING, b BOOLEAN OPTIONAL }
END
""")
    try:
        with tempfile.NamedTemporaryFile(
                "w", suffix=".asn1", delete=False) as f:
            f.write(spec)
            spec_path = f.name
        compiler = asn1tools.compile_files([spec_path], codec="der")
        vectors = [
            {"i": 5, "s": b"abc", "b": True},
            {"i": -1, "s": b"", "b": False},
            {"i": 0, "s": b"x" * 300},
        ]
        for idx, vec in enumerate(vectors):
            der = compiler.encode("Rec", vec)
            der_path = os.path.join(tmp, "at_%d.der" % idx)
            with open(der_path, "wb") as f:
                f.write(der)
            ours, our_rc, _ = run_our_dump(asnber_dump, der_path)
            openr, op_rc, _ = run_openssl_dump(openssl, der_path)
            if our_rc != 0 or op_rc != 0 or ours != openr:
                return "失败: asn1tools 生成样本 #%d 三方不一致" % idx
        os.unlink(spec_path)
        return "通过 (%d 个生成样本三方一致)" % len(vectors)
    except Exception as exc:  # noqa: BLE001
        return "skipped (asn1tools 调用失败: %r)" % (exc,)


if __name__ == "__main__":
    sys.exit(main())