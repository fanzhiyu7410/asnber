#!/usr/bin/env python3
# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT
"""裁剪静态库符号守卫。

只匹配已定义的全局 C 符号（以 asnber_ 开头，剥离平台前导下划线与版本后缀）。
工具顺序：nm -> objdump -> dumpbin。

退出码：0 通过，1 出现禁止符号或缺少必须符号，2 无法读取归档。
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

FORBIDDEN_EXACT = {
    "asnber_doc_create",
    "asnber_doc_seal",
    "asnber_schema_create",
    "asnber_schema_set_root",
    "asnber_schema_seal",
}
FORBIDDEN_PREFIXES = (
    "asnber_encode_",
    "asnber_node_create",
    "asnber_node_set_",
    "asnber_schema_add_",
    "asnber_pkix_certificate_builder_",
)
REQUIRED = {
    "asnber_pkix_certificate_open",
    "asnber_pkix_certificate_close",
    "asnber_pkix_certificate_find",
    "asnber_pkix_certificate_signature_algorithm_oid",
    "asnber_pkix_certificate_signature_value",
    "asnber_pkix_certificate_serial_number",
    "asnber_pkix_certificate_version",
    "asnber_pkix_certificate_issuer_der",
    "asnber_pkix_certificate_subject_der",
    "asnber_pkix_certificate_validity",
    "asnber_doc_destroy",
    "asnber_schema_destroy",
    "asnber_schema_load",
}

CERT_CSR_FORBIDDEN_EXACT = {
    "asnber_schema_create",
    "asnber_schema_set_root",
    "asnber_schema_seal",
}
CERT_CSR_FORBIDDEN_PREFIXES = ("asnber_schema_add_",)
CERT_CSR_REQUIRED = {
    "asnber_pkix_certificate_open",
    "asnber_pkix_certificate_close",
    "asnber_pkix_certificate_find",
    "asnber_pkix_certificate_issuer_der",
    "asnber_pkix_certificate_serial_number",
    "asnber_pkix_certificate_signature_algorithm_oid",
    "asnber_pkix_certificate_signature_value",
    "asnber_pkix_certificate_subject_der",
    "asnber_pkix_certificate_validity",
    "asnber_pkix_certificate_version",
    "asnber_pkix_certificate_builder_create",
    "asnber_pkix_certificate_builder_encode",
    "asnber_pkcs_certification_request_open",
    "asnber_pkcs_certification_request_close",
    "asnber_pkcs_certification_request_builder_create",
    "asnber_pkcs_certification_request_builder_encode",
    "asnber_encode_buffer",
    "asnber_doc_create",
    "asnber_doc_seal",
    "asnber_doc_destroy",
    "asnber_schema_load",
    "asnber_schema_destroy",
}


def run(command: list[str]) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError:
        return None


def clean_name(raw: str) -> str | None:
    name = raw.split("@", 1)[0]
    if name.startswith("_"):
        name = name[1:]
    return name if name.startswith("asnber_") else None


def symbols_from_nm(path: Path) -> set[str] | None:
    result = run(["nm", "-g", "--defined-only", str(path)])
    if result is None or result.returncode != 0:
        return None
    symbols: set[str] = set()
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if not stripped or stripped.endswith(":"):
            continue
        parts = stripped.split()
        if len(parts) < 3:
            continue
        kind = parts[-2]
        if kind.upper() in {"U", "N"}:
            continue
        name = clean_name(parts[-1])
        if name is not None:
            symbols.add(name)
    return symbols


def symbols_from_objdump(path: Path) -> set[str] | None:
    executable = shutil.which("objdump")
    if executable is None:
        return None
    result = run([executable, "-t", str(path)])
    if result is None or result.returncode != 0:
        return None
    symbols: set[str] = set()
    for line in result.stdout.splitlines():
        if "*UND*" in line:
            continue
        parts = line.split()
        if len(parts) < 6:
            continue
        name = clean_name(parts[-1])
        if name is not None:
            symbols.add(name)
    return symbols


def find_dumpbin() -> str | None:
    executable = shutil.which("dumpbin")
    if executable is not None:
        return executable
    vswhere = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / (
        "Microsoft Visual Studio/Installer/vswhere.exe"
    )
    if not vswhere.is_file():
        return None
    result = run(
        [
            str(vswhere),
            "-latest",
            "-products",
            "*",
            "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-property",
            "installationPath",
        ]
    )
    if result is None or result.returncode != 0 or not result.stdout.strip():
        return None
    root = Path(result.stdout.strip().splitlines()[0])
    matches = sorted(root.glob("VC/Tools/MSVC/*/bin/Hostx64/x64/dumpbin.exe"))
    return str(matches[-1]) if matches else None


def symbols_from_dumpbin(path: Path) -> set[str] | None:
    executable = find_dumpbin()
    if executable is None:
        return None
    result = run([executable, "/nologo", "/symbols", str(path)])
    if result is None or result.returncode != 0:
        return None
    symbols: set[str] = set()
    for line in result.stdout.splitlines():
        if "External" not in line or "|" not in line:
            continue
        name = clean_name(line.rsplit("|", 1)[1].strip())
        if name is not None:
            symbols.add(name)
    return symbols


def archive_symbols(path: Path) -> set[str]:
    for reader in (symbols_from_nm, symbols_from_objdump, symbols_from_dumpbin):
        symbols = reader(path)
        if symbols is not None:
            return symbols
    print(f"无法读取归档符号：{path}", file=sys.stderr)
    raise SystemExit(2)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="裁剪静态库符号守卫")
    parser.add_argument("--archive", action="append", required=True, type=Path,
                        help="静态库路径，可重复")
    parser.add_argument("--profile", choices=("cert-decode", "cert-and-csr"),
                        default="cert-decode")
    args = parser.parse_args(argv)

    if args.profile == "cert-and-csr":
        forbidden_exact = CERT_CSR_FORBIDDEN_EXACT
        forbidden_prefixes = CERT_CSR_FORBIDDEN_PREFIXES
        required = CERT_CSR_REQUIRED
    else:
        forbidden_exact = FORBIDDEN_EXACT
        forbidden_prefixes = FORBIDDEN_PREFIXES
        required = REQUIRED

    symbols: set[str] = set()
    for archive in args.archive:
        symbols |= archive_symbols(archive)

    forbidden = sorted(
        name
        for name in symbols
        if name in forbidden_exact
        or any(name.startswith(prefix) for prefix in forbidden_prefixes)
    )
    missing = sorted(required - symbols)
    if forbidden:
        print("禁止符号仍存在：" + ", ".join(forbidden), file=sys.stderr)
    if missing:
        print("必须符号缺失：" + ", ".join(missing), file=sys.stderr)
    if forbidden or missing:
        return 1
    print(f"TRIM SYMBOLS OK（{len(symbols)} 个 asnber_ 符号）")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
