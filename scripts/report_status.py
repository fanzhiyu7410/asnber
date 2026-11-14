#!/usr/bin/env python3
# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT

"""从构建产物派生文档所需的状态数字，避免在 README 中手写。

输出项：

  - 核心与各模块版本：读构建目录生成的 `<模块>_version.h`；
  - 注册用例数：调用 `ctest -N` 解析 `Total Tests`；
  - 能力位定义：读生成的 `asnber_version.h` 中 `ASNBER_CAP_*` 位；
  - ABI 基线符号数：统计 `abi/*.symbols.txt` 的符号行。

用法：
  python scripts/report_status.py --build-dir build-mingw-Release-shared
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

# Windows 控制台默认代码页会让中文诊断输出乱码；统一按 UTF-8 输出。
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

REPO_ROOT = Path(__file__).resolve().parent.parent

VERSION_HEADERS = [
    ("asnber", "generated/include/asnber/asnber_version.h"),
    ("asnber-pkix", "modules/pkix/generated/include/asnber/pkix/pkix_version.h"),
    ("asnber-pkcs", "modules/pkcs/generated/include/asnber/pkcs/pkcs_version.h"),
    ("asnber-cms", "modules/cms/generated/include/asnber/cms/cms_version.h"),
    ("asnber-ocsp", "modules/ocsp/generated/include/asnber/ocsp/ocsp_version.h"),
]


def version_string(path: Path) -> str | None:
    text = path.read_text(encoding="utf-8", errors="replace")
    match = re.search(r'#define\s+ASNBER_[A-Z0-9_]*VERSION_STRING\s+"([^"]+)"', text)
    return match.group(1) if match else None


def capability_bits(path: Path) -> list[tuple[str, int]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    bits: list[tuple[str, int]] = []
    for name, shift in re.findall(
        r"#define\s+(ASNBER_CAP_[A-Z0-9_]+)\s+\(UINT64_C\(1\)\s*<<\s*(\d+)\)", text
    ):
        bits.append((name, int(shift)))
    return bits


def registered_tests(build_dir: Path) -> int | None:
    try:
        output = subprocess.run(
            ["ctest", "--test-dir", str(build_dir), "-N"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        ).stdout
    except OSError:
        return None
    match = re.search(r"Total Tests:\s*(\d+)", output)
    return int(match.group(1)) if match else None


def abi_symbol_counts(abi_dir: Path) -> list[tuple[str, int]]:
    counts: list[tuple[str, int]] = []
    for path in sorted(abi_dir.glob("*.symbols.txt")):
        symbols = [
            line.strip()
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        counts.append((path.name, len(symbols)))
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", required=True, type=Path,
                        help="已配置并构建的目录（含生成的版本头）")
    parser.add_argument("--abi-dir", type=Path, default=REPO_ROOT / "abi",
                        help="ABI 基线目录，默认 abi/")
    args = parser.parse_args()

    build_dir = args.build_dir.resolve()
    if not build_dir.is_dir():
        print(f"构建目录不存在：{build_dir}", file=sys.stderr)
        return 2

    missing = False
    print(f"构建目录：{build_dir}")
    for package, relative in VERSION_HEADERS:
        path = build_dir / relative
        if not path.is_file():
            print(f"  版本 {package}: 缺（未生成 {relative}）")
            missing = True
            continue
        print(f"  版本 {package}: {version_string(path) or '缺'}")

    count = registered_tests(build_dir)
    print(f"注册用例数（ctest -N）：{'缺' if count is None else count}")

    core_header = build_dir / VERSION_HEADERS[0][1]
    if core_header.is_file():
        bits = capability_bits(core_header)
        print(f"能力位定义（生成头，{len(bits)} 个）：")
        for name, shift in bits:
            print(f"  {name} = bit {shift}")
    else:
        print("能力位定义：缺（未生成 asnber_version.h）")
        missing = True

    counts = abi_symbol_counts(args.abi_dir)
    if counts:
        print("ABI 基线符号数：" + "、".join(f"{n}={c}" for n, c in counts))
    else:
        print(f"ABI 基线符号数：缺（{args.abi_dir} 无 *.symbols.txt）")
        missing = True

    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
