#!/usr/bin/env python3
# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT
"""裁剪配置校验：12 条负向规则 + 2 条正例。

每个用例在独立临时目录执行 CMake configure，只配置不构建。
负向用例必须失败且 stderr 含规定片段；正例必须成功。
退出码：0 全部符合预期，1 有用例不符，2 缺少 cmake。
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent.parent

CERT_MODULES_OFF = [
    "-DASNBER_BUILD_MODULES=ON",
    "-DASNBER_BUILD_MODULE_PKIX=ON",
    "-DASNBER_BUILD_MODULE_PKCS=OFF",
    "-DASNBER_BUILD_MODULE_PKCS1=OFF",
    "-DASNBER_BUILD_MODULE_PKCS8=OFF",
    "-DASNBER_BUILD_MODULE_PKCS10=OFF",
    "-DASNBER_BUILD_MODULE_PKCS12=OFF",
    "-DASNBER_BUILD_MODULE_CMS=OFF",
]

CSR_MODULES = [
    "-DASNBER_BUILD_MODULES=ON",
    "-DASNBER_BUILD_MODULE_PKIX=ON",
    "-DASNBER_BUILD_MODULE_PKCS=OFF",
    "-DASNBER_BUILD_MODULE_PKCS1=OFF",
    "-DASNBER_BUILD_MODULE_PKCS8=OFF",
    "-DASNBER_BUILD_MODULE_PKCS10=ON",
    "-DASNBER_BUILD_MODULE_PKCS12=OFF",
    "-DASNBER_BUILD_MODULE_CMS=OFF",
]

NEGATIVE_CASES = [
    (
        "shared_with_encode_off",
        ["-DASNBER_ENABLE_ENCODE=OFF"],
        "共享库要求三个核心特性全部开启",
    ),
    (
        "shared_with_pkix_builder_off",
        ["-DASNBER_PKIX_ENABLE_BUILDER=OFF"],
        "共享库要求 asnber-pkix 构造接口完整",
    ),
    (
        "cert_decode_modules_off",
        [
            "-DASNBER_TRIM_PROFILE=cert-decode",
            "-DASNBER_BUILD_SHARED=OFF",
            "-DASNBER_BUILD_MODULES=OFF",
        ],
        "需要 ASNBER_BUILD_MODULES=ON",
    ),
    (
        "cert_decode_pkix_off",
        [
            "-DASNBER_TRIM_PROFILE=cert-decode",
            "-DASNBER_BUILD_SHARED=OFF",
            "-DASNBER_BUILD_MODULES=ON",
            "-DASNBER_BUILD_MODULE_PKIX=OFF",
        ]
        + CERT_MODULES_OFF[2:],
        "需要 ASNBER_BUILD_MODULE_PKIX=ON",
    ),
    (
        "cert_decode_extra_module",
        # 末尾必须是 CMS=ON：CERT_MODULES_OFF[7:] 仍带 CMS=OFF，追加在后会覆盖。
        ["-DASNBER_TRIM_PROFILE=cert-decode", "-DASNBER_BUILD_SHARED=OFF"]
        + CERT_MODULES_OFF[:2]
        + ["-DASNBER_BUILD_MODULE_CMS=ON"]
        + CERT_MODULES_OFF[2:7],
        "只允许 PKIX 模块",
    ),
    (
        "cert_decode_tests_on",
        [
            "-DASNBER_TRIM_PROFILE=cert-decode",
            "-DASNBER_BUILD_SHARED=OFF",
            "-DASNBER_BUILD_TESTS=ON",
        ]
        + CERT_MODULES_OFF,
        "不允许 ASNBER_BUILD_TESTS=ON",
    ),
    (
        "builder_with_encode_off",
        [
            "-DASNBER_BUILD_SHARED=OFF",
            "-DASNBER_ENABLE_ENCODE=OFF",
            "-DASNBER_PKIX_ENABLE_BUILDER=ON",
        ],
        "需要 ASNBER_ENABLE_ENCODE=ON",
    ),
    (
        "builder_with_build_api_off",
        [
            "-DASNBER_BUILD_SHARED=OFF",
            "-DASNBER_ENABLE_BUILD_API=OFF",
            "-DASNBER_PKIX_ENABLE_BUILDER=ON",
        ],
        "需要 ASNBER_ENABLE_BUILD_API=ON",
    ),
    (
        "cert_and_csr_pkcs10_off",
        [
            "-DASNBER_TRIM_PROFILE=cert-and-csr",
            "-DASNBER_BUILD_SHARED=OFF",
            "-DASNBER_BUILD_TESTS=OFF",
        ]
        + CSR_MODULES[:5]
        + ["-DASNBER_BUILD_MODULE_PKCS10=OFF"]
        + CSR_MODULES[6:],
        "需要 ASNBER_BUILD_MODULE_PKCS10=ON",
    ),
    (
        "cert_and_csr_extra_module",
        [
            "-DASNBER_TRIM_PROFILE=cert-and-csr",
            "-DASNBER_BUILD_SHARED=OFF",
            "-DASNBER_BUILD_TESTS=OFF",
        ]
        + CSR_MODULES[:-1]
        + ["-DASNBER_BUILD_MODULE_CMS=ON"],
        "只允许 PKIX 与 PKCS#10",
    ),
    (
        "cert_and_csr_tests_on",
        [
            "-DASNBER_TRIM_PROFILE=cert-and-csr",
            "-DASNBER_BUILD_SHARED=OFF",
            "-DASNBER_BUILD_TESTS=ON",
        ]
        + CSR_MODULES,
        "不允许 ASNBER_BUILD_TESTS=ON",
    ),
    (
        "cert_and_csr_shared_on",
        [
            "-DASNBER_TRIM_PROFILE=cert-and-csr",
            "-DASNBER_BUILD_SHARED=ON",
        ]
        + CSR_MODULES,
        "三个核心特性全部开启",
    ),
]

POSITIVE_CASES = [
    (
        "cert_decode_ok",
        [
            "-DASNBER_TRIM_PROFILE=cert-decode",
            "-DASNBER_BUILD_SHARED=OFF",
            "-DASNBER_BUILD_STATIC=ON",
            "-DASNBER_BUILD_TOOLS=OFF",
            "-DASNBER_BUILD_TESTS=OFF",
            "-DASNBER_BUILD_EMBEDDED_TEST=ON",
        ]
        + CERT_MODULES_OFF,
    ),
    (
        "cert_and_csr_ok",
        [
            "-DASNBER_TRIM_PROFILE=cert-and-csr",
            "-DASNBER_BUILD_SHARED=OFF",
            "-DASNBER_BUILD_STATIC=ON",
            "-DASNBER_BUILD_TOOLS=OFF",
            "-DASNBER_BUILD_TESTS=OFF",
            "-DASNBER_BUILD_EMBEDDED_TEST=ON",
        ]
        + CSR_MODULES,
    ),
]


def normalized(text: str) -> str:
    """折叠空白。CMake 会按列宽把 FATAL_ERROR 拆行，诊断片段不能依赖换行位置。"""
    return " ".join(text.split())


def configure(cmake: str, build_dir: Path, definitions: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [cmake, "-S", str(ROOT), "-B", str(build_dir), *definitions],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="验证裁剪配置的 12 条负向规则")
    parser.add_argument("--cmake", default=shutil.which("cmake"))
    args = parser.parse_args(argv)
    if not args.cmake:
        print("找不到 cmake", file=sys.stderr)
        return 2

    failed = 0
    for name, definitions, expected in NEGATIVE_CASES:
        with tempfile.TemporaryDirectory(prefix=f"asnber-trim-{name}-") as tmp:
            result = configure(args.cmake, Path(tmp), definitions)
        combined = (result.stdout or "") + (result.stderr or "")
        if result.returncode == 0:
            print(f"FAIL {name}: configure 成功，预期失败")
            failed += 1
        elif expected not in normalized(combined):
            print(f"FAIL {name}: 缺少诊断片段 '{expected}'")
            print(combined)
            failed += 1
        else:
            print(f"PASS {name}")

    for name, definitions in POSITIVE_CASES:
        with tempfile.TemporaryDirectory(prefix=f"asnber-trim-{name}-") as tmp:
            result = configure(args.cmake, Path(tmp), definitions)
        if result.returncode != 0:
            print(f"FAIL {name}: 合法配置失败")
            print((result.stdout or "") + (result.stderr or ""))
            failed += 1
        else:
            print(f"PASS {name}")

    if failed:
        print(f"{failed} 个用例不符合预期", file=sys.stderr)
        return 1
    print("TRIM CONFIG OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
