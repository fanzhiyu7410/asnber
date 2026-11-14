#!/usr/bin/env python3
# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT

"""第三方依赖与许可证检查（骨架）。

比对 docs/第三方依赖与许可证清单.md 与实际引用：
  - 清单登记的依赖名称集合；
  - 源码与构建文件中的第三方引用（include、CMake 依赖声明、vendored 目录、fuzzer 链接）。

发现未登记引用、禁止许可或清单格式错误时以非零码退出。

退出码：
  0  通过
  1  发现未登记依赖或禁止许可
  2  清单缺失或格式错误

用法：
  python scripts/check_third_party.py
  python scripts/check_third_party.py --list
  python scripts/check_third_party.py --manifest docs/第三方依赖与许可证清单.md
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = REPO_ROOT / "docs" / "第三方依赖与许可证清单.md"

# 仅允许的宽松许可（前缀匹配，忽略大小写）。SPDX 表达式含 AND/OR 时逐个判断。
ALLOWED_LICENSES = (
    "mit",
    "bsd-2-clause",
    "bsd-3-clause",
    "apache-2.0",
    "apache-2.0-with-llvm-exception",
    "llvm",
)

FORBIDDEN_LICENSES = ("gpl", "lgpl", "agpl")

# 扫描范围：源码与构建目录，不含文档与脚本自身。
SCAN_SUFFIXES = (".c", ".h", ".cpp", ".hpp", ".cc", ".cmake", ".txt")
SCAN_DIRS = ("src", "include", "modules", "tools", "tests", "examples", "cmake")
SCAN_ROOT_FILES = ("CMakeLists.txt",)

# vendored 目录：出现即视为第三方源码，必须登记。
VENDOR_DIR_NAMES = ("third_party", "third-party", "vendor", "external", "extern")

# 系统头豁免：无目录前缀且属于常见标准头，不作为第三方依赖。
KNOWN_SINGLE_HEADERS = {
    "doctest.h", "doctest_fwd.h", "catch.hpp",  # 常见测试单头
}

# 项目自身 include 前缀与 CMake 包名。
PROJECT_INCLUDE_PREFIXES = ("asnber/", "asnber_")
IGNORED_CMAKE_PACKAGES = {
    "threads", "c", "cxx", "asnber", "asnber-pkix", "asnber-cms", "asnber-pkcs",
    "asnber-ocsp",
}

# 构建文件中视为第三方引入信号的 CMake 命令。
CMAKE_DEP_PATTERNS = (
    re.compile(r"FetchContent_Declare\s*\(\s*([A-Za-z0-9_.\-]+)"),
    re.compile(r"find_package\s*\(\s*([A-Za-z0-9_.\-]+)"),
    re.compile(r"\bpkg_check_modules\s*\([^)]*?\b([A-Za-z0-9_.\-]+)", re.S),
)

# 从 include 语句中提取头文件名。
INCLUDE_PATTERN = re.compile(r'^\s*#\s*include\s*[<"]([^">]+)[">]', re.M)


class ManifestError(Exception):
    """清单缺失或格式错误。"""


def parse_manifest(path: Path) -> list[dict[str, str]]:
    """解析清单中的登记表，返回依赖条目列表。"""
    if not path.is_file():
        raise ManifestError(f"清单文件不存在：{path}")

    text = path.read_text(encoding="utf-8-sig")
    lines = text.splitlines()

    header_cols: list[str] | None = None
    entries: list[dict[str, str]] = []

    for line in lines:
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [c.strip() for c in stripped.strip("|").split("|")]
        if not cells:
            continue
        # 登记表表头（同时含名称、许可证、随产物分发三列）；重复表头跳过
        if "名称" in cells and "许可证" in cells and "随产物分发" in cells:
            if header_cols is None:
                header_cols = cells
            continue
        # 分隔行
        if all(set(c) <= set("-: ") and c for c in cells):
            continue
        if header_cols is None:
            continue
        # 模板占位行
        if any(c.startswith("<!--") for c in cells):
            continue
        if len(cells) != len(header_cols):
            raise ManifestError(
                f"清单表格列数不一致（期望 {len(header_cols)}，实际 {len(cells)}）：{stripped}"
            )
        entries.append(dict(zip(header_cols, cells)))

    if header_cols is None:
        raise ManifestError("清单中未找到登记表（缺少表头行）")
    if not entries:
        # 空清单是合法状态（当前尚无第三方依赖），但必须有表头。
        return []
    return entries


def license_allowed(license_text: str) -> bool:
    """判断许可证是否在允许范围内。"""
    lowered = license_text.lower()
    if any(bad in lowered for bad in FORBIDDEN_LICENSES):
        return False
    if not lowered or "不明" in license_text or lowered in ("unknown", "n/a", "-"):
        return False
    return any(ok in lowered for ok in ALLOWED_LICENSES)


def iter_scan_files() -> list[Path]:
    """收集待扫描的源码与构建文件。"""
    files: list[Path] = []
    for name in SCAN_ROOT_FILES:
        candidate = REPO_ROOT / name
        if candidate.is_file():
            files.append(candidate)
    for dirname in SCAN_DIRS:
        base = REPO_ROOT / dirname
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            if path.is_file() and path.suffix in SCAN_SUFFIXES:
                files.append(path)
    return files


def normalize(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def collect_include_usages(files: list[Path]) -> set[str]:
    """收集可能的第三方 include 名称。"""
    found: set[str] = set()
    for path in files:
        try:
            text = path.read_text(encoding="utf-8-sig", errors="ignore")
        except OSError:
            continue
        for match in INCLUDE_PATTERN.finditer(text):
            header = match.group(1).strip()
            lowered = header.lower()
            if lowered.startswith(PROJECT_INCLUDE_PREFIXES):
                continue
            if "/" in header:
                # 只把带目录前缀的头视为第三方候选，避免误报标准库。
                found.add(normalize(header.split("/")[0]))
            elif lowered in KNOWN_SINGLE_HEADERS:
                found.add(normalize(header.rsplit(".", 1)[0]))
    return found


def collect_cmake_usages(files: list[Path]) -> set[str]:
    """收集构建文件中显式引入的第三方名称。"""
    found: set[str] = set()
    for path in files:
        if path.suffix not in (".txt", ".cmake"):
            continue
        try:
            text = path.read_text(encoding="utf-8-sig", errors="ignore")
        except OSError:
            continue
        for pattern in CMAKE_DEP_PATTERNS:
            for match in pattern.finditer(text):
                name = normalize(match.group(1))
                if name in IGNORED_CMAKE_PACKAGES:
                    continue
                found.add(name)
    return found


def collect_vendor_dirs() -> set[str]:
    """收集 vendored 目录下的实际依赖目录名。"""
    found: set[str] = set()
    for path in REPO_ROOT.rglob("*"):
        if not path.is_dir() or path.name.lower() not in VENDOR_DIR_NAMES:
            continue
        if ".git" in path.parts:
            continue
        for child in path.iterdir():
            if child.is_dir() and child.name != ".git":
                found.add(normalize(child.name))
    return found


def check(manifest_path: Path, list_only: bool) -> int:
    try:
        entries = parse_manifest(manifest_path)
    except ManifestError as exc:
        print(f"[错误] {exc}")
        return 2

    print(f"清单：{manifest_path}")
    if list_only:
        if not entries:
            print("已登记依赖：无")
        else:
            print(f"已登记依赖（{len(entries)} 项）：")
            for item in entries:
                print(
                    f"  - {item.get('名称', '?')} {item.get('版本', '')}"
                    f" / {item.get('许可证', '?')}"
                    f" / 随产物分发={item.get('随产物分发', '?')}"
                )
        return 0

    registered = {normalize(item.get("名称", "")) for item in entries if item.get("名称")}

    problems: list[str] = []

    for item in entries:
        name = item.get("名称", "?")
        lic = item.get("许可证", "")
        if not license_allowed(lic):
            problems.append(f"许可证不合规或缺失：{name} -> {lic!r}")
        if item.get("随产物分发", "").strip().lower() in ("是", "yes", "true", "1"):
            problems.append(f"运行库不得分发第三方组件：{name}")

    usages = collect_include_usages(iter_scan_files())
    usages |= collect_cmake_usages(iter_scan_files())
    usages |= collect_vendor_dirs()

    # 允许清单里出现的名称转写形式（如 doctest -> doctest）。
    unregistered = sorted(
        u for u in usages
        if u and u not in registered and not any(u in r or r in u for r in registered if r)
    )

    if unregistered:
        problems.append(
            "疑似未登记依赖：" + ", ".join(unregistered)
            + "（确认后登记到清单；系统头请加入脚本豁免）"
        )

    if problems:
        print("[失败] 发现以下问题：")
        for p in problems:
            print(f"  - {p}")
        return 1

    print(f"[通过] 已登记 {len(registered)} 项依赖，未发现未登记引用。")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="第三方依赖与许可证检查（骨架）")
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST,
        help="清单路径，默认 docs/第三方依赖与许可证清单.md",
    )
    parser.add_argument("--list", action="store_true", help="只列出已登记依赖")
    args = parser.parse_args(argv)
    return check(args.manifest, args.list)


if __name__ == "__main__":
    sys.exit(main())
