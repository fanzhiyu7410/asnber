#!/usr/bin/env python3
# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT

"""C ABI 导出符号守卫。

把构建目录中共享库的实际导出符号与 `abi/<module>.symbols.txt` 基线逐项比较：

  - 基线中存在、共享库未导出 -> 可能破坏 ABI（函数被删除或不再导出）；
  - 共享库导出、基线中不存在 -> 需要显式更新基线并评审。

只统计以 `asnber_` 开头的符号；隐藏的 C++ 实现符号与运行时内部符号不参与比较。

退出码：
  0  全部模块匹配
  1  存在缺失或额外导出
  2  参数、工具或基线文件错误

用法：
  python scripts/check_exports.py --build-dir build
  python scripts/check_exports.py --build-dir build --module asnber
  python scripts/check_exports.py --build-dir build --baseline-dir abi
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# Windows 控制台默认代码页会让中文诊断输出乱码；统一按 UTF-8 输出。
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BASELINE_DIR = REPO_ROOT / "abi"
DEFAULT_MODULES = (
    "asnber",
    "asnber-pkix",
    "asnber-pkcs1",
    "asnber-pkcs8",
    "asnber-pkcs10",
    "asnber-pkcs12",
    "asnber-cms",
    "asnber-ocsp",
)

# 共享库文件名：libasnber.so / libasnber.so.0 / libasnber.dylib / libasnber.dll。
# macOS 的版本化产物写作 libasnber.0.0.0.dylib，版本号在 .dylib 之前。
LIBRARY_PATTERNS = {
    "asnber": re.compile(
        r"^(?:lib)?asnber(?:\.\d+)*\.(?:so(?:\.\d+)*|dylib|dll)$",
        re.IGNORECASE,
    ),
    "asnber-pkix": re.compile(
        r"^(?:lib)?asnber-pkix(?:\.\d+)*\.(?:so(?:\.\d+)*|dylib|dll)$",
        re.IGNORECASE,
    ),
    "asnber-pkcs1": re.compile(
        r"^(?:lib)?asnber-pkcs1(?:\.\d+)*\.(?:so(?:\.\d+)*|dylib|dll)$",
        re.IGNORECASE,
    ),
    "asnber-pkcs8": re.compile(
        r"^(?:lib)?asnber-pkcs8(?:\.\d+)*\.(?:so(?:\.\d+)*|dylib|dll)$",
        re.IGNORECASE,
    ),
    "asnber-pkcs10": re.compile(
        r"^(?:lib)?asnber-pkcs10(?:\.\d+)*\.(?:so(?:\.\d+)*|dylib|dll)$",
        re.IGNORECASE,
    ),
    "asnber-pkcs12": re.compile(
        r"^(?:lib)?asnber-pkcs12(?:\.\d+)*\.(?:so(?:\.\d+)*|dylib|dll)$",
        re.IGNORECASE,
    ),
    "asnber-cms": re.compile(
        r"^(?:lib)?asnber-cms(?:\.\d+)*\.(?:so(?:\.\d+)*|dylib|dll)$",
        re.IGNORECASE,
    ),
    "asnber-ocsp": re.compile(
        r"^(?:lib)?asnber-ocsp(?:\.\d+)*\.(?:so(?:\.\d+)*|dylib|dll)$",
        re.IGNORECASE,
    ),
}


class ExportError(Exception):
    """无法读取符号或基线。"""


def run_tool(command: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError as exc:
        raise ExportError(f"无法执行 {command[0]}：{exc}") from exc


def find_library(build_dir: Path, module: str) -> Path | None:
    """在构建目录中寻找模块对应的共享库。

    测试目录会复制 DLL，安装目录也可能保留副本；优先选择 src/ 与
    modules/<name>/ 下的原始产物。
    """
    pattern = LIBRARY_PATTERNS[module]
    candidates = [
        path
        for path in build_dir.rglob("*")
        if path.is_file() and pattern.match(path.name)
    ]
    if not candidates:
        return None

    module_part = module.split("-", 1)[1] if "-" in module else ""

    def score(path: Path) -> tuple[int, int, str]:
        parts = [part.lower() for part in path.parts]
        penalty = 0
        if "tests" in parts:
            penalty += 100
        if "install" in parts:
            penalty += 20
        if module == "asnber":
            if "src" not in parts:
                penalty += 30
        elif "modules" not in parts or module_part not in parts:
            penalty += 30
        return (penalty, len(path.parts), str(path))

    return min(candidates, key=score)


def find_dumpbin() -> str | None:
    executable = shutil.which("dumpbin")
    if executable is not None:
        return executable

    vswhere_candidates = [
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
        / "Microsoft Visual Studio"
        / "Installer"
        / "vswhere.exe",
        Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
        / "Microsoft Visual Studio"
        / "Installer"
        / "vswhere.exe",
    ]
    for vswhere in vswhere_candidates:
        if not vswhere.is_file():
            continue
        result = run_tool(
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
        root_text = result.stdout.strip().splitlines()
        if result.returncode != 0 or not root_text:
            continue
        root = Path(root_text[0])
        matches = sorted(root.glob("VC/Tools/MSVC/*/bin/Hostx64/x64/dumpbin.exe"))
        if matches:
            return str(matches[-1])
    return None


def symbols_from_nm(path: Path) -> set[str]:
    commands = []
    if path.suffix == ".dylib":
        commands.append(["nm", "-gU", str(path)])
    else:
        commands.append(["nm", "-D", "--defined-only", str(path)])
        commands.append(["nm", "-g", "--defined-only", str(path)])

    last_output = ""
    for command in commands:
        result = run_tool(command)
        if result.returncode != 0:
            last_output = result.stderr.strip()
            continue
        symbols: set[str] = set()
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            name = parts[-1]
            if name.startswith("_asnber_"):
                name = name[1:]
            if name.startswith("asnber_"):
                symbols.add(name.split("@", 1)[0])
        return symbols
    raise ExportError(f"nm 无法读取 {path}：{last_output}")


def symbols_from_objdump(path: Path) -> set[str] | None:
    executable = shutil.which("objdump")
    if executable is None:
        return None
    result = run_tool([executable, "-p", str(path)])
    if result.returncode != 0:
        return None

    symbols: set[str] = set()
    in_table = False
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if stripped == "[Ordinal/Name Pointer] Table":
            in_table = True
            continue
        if not in_table:
            continue
        if not stripped:
            break
        match = re.match(r"^\[\s*\d+\]\s+(\S+)$", stripped)
        if match is None:
            break
        name = match.group(1)
        if name.startswith("asnber_"):
            symbols.add(name)
    return symbols if symbols else None


def symbols_from_dumpbin(path: Path) -> set[str]:
    executable = find_dumpbin()
    if executable is None:
        raise ExportError(f"找不到 nm/objdump/dumpbin，无法读取 {path}")
    result = run_tool([executable, "/nologo", "/exports", str(path)])
    if result.returncode != 0:
        raise ExportError(
            f"dumpbin 无法读取 {path}：{result.stderr.strip() or result.stdout.strip()}"
        )

    symbols: set[str] = set()
    in_table = False
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if "ordinal" in stripped.lower() and "name" in stripped.lower():
            in_table = True
            continue
        if not in_table:
            continue
        # Debug DLL 常把导出指向 ILT thunk，行形如
        #   1 0 000010DC asnber_buf_release = @ILT+215(asnber_buf_release)
        # 名称是第 4 列；行尾的 = @ILT... 不是符号名。
        match = re.match(r"^\s*\d+\s+\S+\s+[0-9A-Fa-f]+\s+(\S+)", stripped)
        if match is None:
            continue
        name = match.group(1)
        if name.startswith("_asnber_"):
            name = name[1:]
        if name.startswith("asnber_"):
            symbols.add(name)
    return symbols


def export_symbols(path: Path) -> set[str]:
    if path.suffix.lower() == ".dll":
        # MinGW objdump 能直接读取 PE 导出表；MSVC 环境回退到 dumpbin。
        symbols = symbols_from_objdump(path)
        if symbols is not None:
            return symbols
        return symbols_from_dumpbin(path)
    return symbols_from_nm(path)


def load_baseline(path: Path) -> set[str]:
    if not path.is_file():
        raise ExportError(f"基线文件不存在：{path}")
    symbols: set[str] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line in symbols:
            raise ExportError(f"基线 {path} 含重复符号：{line}")
        if not line.startswith("asnber_"):
            raise ExportError(f"基线 {path} 含非 asnber_ 符号：{line}")
        symbols.add(line)
    if not symbols:
        raise ExportError(f"基线为空：{path}")
    return symbols


def check_module(
    build_dir: Path, baseline_dir: Path, module: str
) -> tuple[bool, str]:
    baseline_path = baseline_dir / f"{module}.symbols.txt"
    expected = load_baseline(baseline_path)
    library = find_library(build_dir, module)
    if library is None:
        raise ExportError(f"在 {build_dir} 中找不到 {module} 的共享库")

    actual = export_symbols(library)
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    if missing or unexpected:
        lines = [
            f"{module}: 不一致（基线 {len(expected)}，实际 {len(actual)}）",
            f"  库文件：{library}",
        ]
        if missing:
            lines.append("  缺失（基线有、库未导出）：" + ", ".join(missing))
        if unexpected:
            lines.append("  额外（库导出、基线没有）：" + ", ".join(unexpected))
        return False, "\n".join(lines)
    return True, f"{module}: {len(actual)} 个导出符号与 {baseline_path.name} 一致"


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="比较共享库导出符号与 abi/*.symbols.txt 基线"
    )
    parser.add_argument(
        "--build-dir",
        required=True,
        type=Path,
        help="包含共享库的 CMake 构建目录",
    )
    parser.add_argument(
        "--baseline-dir",
        type=Path,
        default=DEFAULT_BASELINE_DIR,
        help=f"符号基线目录（默认 {DEFAULT_BASELINE_DIR}）",
    )
    parser.add_argument(
        "--module",
        action="append",
        choices=DEFAULT_MODULES,
        help="只检查指定模块，可重复；默认检查全部",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    build_dir = args.build_dir.resolve()
    baseline_dir = args.baseline_dir.resolve()
    if not build_dir.is_dir():
        print(f"构建目录不存在：{build_dir}", file=sys.stderr)
        return 2

    modules = args.module if args.module else list(DEFAULT_MODULES)
    failed = False
    try:
        for module in modules:
            ok, message = check_module(build_dir, baseline_dir, module)
            print(message)
            failed = failed or not ok
    except ExportError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 2

    if failed:
        print(
            "ABI 导出检查失败。若变更是有意为之，请评审后更新 abi/*.symbols.txt。",
            file=sys.stderr,
        )
        return 1
    print(f"ABI 导出检查通过（{len(modules)} 个模块）")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
