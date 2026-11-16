#!/usr/bin/env python3
# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT
"""本地多平台构建与测试：build / test 子命令分开调用。

产物按档位落在仓库根 out/<档位>/：
  build/    CMake 构建树（含测试可执行文件）
  install/  cmake --install 安装前缀（头文件、库、CMake 包）

用法：
  python scripts/build_and_test.py build
  python scripts/build_and_test.py test
  python scripts/build_and_test.py build --only msvc-debug
  python scripts/build_and_test.py test --only msvc-debug
  python scripts/build_and_test.py --list
"""

from __future__ import annotations

import argparse
import os
import shlex
import shutil
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(SCRIPT_DIR)
OUT_ROOT = os.path.join(ROOT, "out")

COMMON_OPTIONS = [
    "-DASNBER_BUILD_TESTS=ON",
    "-DASNBER_BUILD_EXAMPLES=ON",
    "-DASNBER_WARNINGS_AS_ERRORS=ON",
    "-DASNBER_BUILD_MODULE_PKCS=ON",
    "-DASNBER_BUILD_MODULE_CMS=ON",
    "-DASNBER_BUILD_MODULE_OCSP=ON",
    "-DASNBER_BUILD_SHARED=ON",
    "-DASNBER_BUILD_STATIC=ON",
]

PROFILES = [
    {
        "name": "msvc-debug",
        "toolchain": "msvc",
        "build_type": "Debug",
    },
    {
        "name": "msvc-release",
        "toolchain": "msvc",
        "build_type": "Release",
    },
    {
        "name": "mingw-release",
        "toolchain": "mingw",
        "build_type": "Release",
    },
    {
        "name": "wsl-debug",
        "toolchain": "wsl",
        "build_type": "Debug",
    },
    {
        "name": "wsl-release",
        "toolchain": "wsl",
        "build_type": "Release",
    },
]


def to_wsl_path(path: str) -> str:
    drive, rest = os.path.splitdrive(path)
    if not drive:
        return path.replace("\\", "/")
    return "/mnt/" + drive[0].lower() + rest.replace("\\", "/")


def profile_dirs(name: str) -> tuple[str, str, str]:
    base = os.path.join(OUT_ROOT, name)
    return base, os.path.join(base, "build"), os.path.join(base, "install")


def stream_command(argv: list[str], cwd: str, log_path: str) -> int:
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    with open(log_path, "a", encoding="utf-8", errors="replace") as log:
        proc = subprocess.Popen(
            argv,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            log.write(line)
            sys.stdout.write(line)
        return proc.wait()


def toolchain_available(profile: dict, wsl_distro: str) -> tuple[bool, str]:
    toolchain = profile["toolchain"]
    if toolchain == "msvc":
        if shutil.which("cmake") is None:
            return False, "本机 PATH 没有 cmake"
        return True, "可用"
    if toolchain == "mingw":
        if shutil.which("gcc") is None or shutil.which("g++") is None:
            return False, "本机 PATH 没有 gcc/g++"
        if shutil.which("ninja") is None:
            return False, "本机 PATH 没有 ninja"
        return True, "可用"
    if toolchain == "wsl":
        if shutil.which("wsl") is None:
            return False, "本机没有 wsl"
        probe = subprocess.run(
            [
                "wsl",
                "-d",
                wsl_distro,
                "--",
                "bash",
                "-lc",
                "command -v cmake && command -v ninja && command -v gcc && command -v g++",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if probe.returncode != 0:
            return False, "WSL 发行版 %s 缺少 cmake/ninja/gcc/g++" % wsl_distro
        return True, "可用"
    return False, "未知工具链"


def build_commands(
    profile: dict, build_dir: str, install_dir: str, jobs: int | None
) -> tuple[list[str], list[str], list[str]]:
    build_type = profile["build_type"]
    common = list(COMMON_OPTIONS)

    if profile["toolchain"] == "msvc":
        configure = [
            "cmake",
            "-S",
            ".",
            "-B",
            build_dir,
            "-A",
            "x64",
            "-DCMAKE_BUILD_TYPE=" + build_type,
        ] + common
        build = [
            "cmake",
            "--build",
            build_dir,
            "--config",
            build_type,
            "--parallel",
        ]
        if jobs is not None:
            build.append(str(jobs))
        install = [
            "cmake",
            "--install",
            build_dir,
            "--config",
            build_type,
            "--prefix",
            install_dir,
        ]
        return configure, build, install

    configure = [
        "cmake",
        "-S",
        ".",
        "-B",
        build_dir,
        "-G",
        "Ninja",
        "-DCMAKE_BUILD_TYPE=" + build_type,
        "-DCMAKE_C_COMPILER=gcc",
        "-DCMAKE_CXX_COMPILER=g++",
    ] + common
    build = ["cmake", "--build", build_dir, "--parallel"]
    if jobs is not None:
        build.append(str(jobs))
    install = [
        "cmake",
        "--install",
        build_dir,
        "--prefix",
        install_dir,
    ]
    return configure, build, install


def test_command(profile: dict, build_dir: str) -> list[str]:
    cmd = ["ctest", "--test-dir", build_dir, "--output-on-failure"]
    if profile["toolchain"] == "msvc":
        cmd += ["-C", profile["build_type"]]
    return cmd


def wrap_wsl(
    cmd: list[str],
    build_dir: str,
    install_dir: str,
    relative_build: str,
    relative_install: str,
    wsl_distro: str,
) -> list[str]:
    replaced = []
    for part in cmd:
        if part == build_dir:
            replaced.append(relative_build)
        elif part == install_dir:
            replaced.append(relative_install)
        else:
            replaced.append(part)
    joined = " ".join(shlex.quote(part) for part in replaced)
    wsl_root = to_wsl_path(ROOT)
    return [
        "wsl",
        "-d",
        wsl_distro,
        "--",
        "bash",
        "-lc",
        "cd %s && %s" % (shlex.quote(wsl_root), joined),
    ]


def run_build(profile: dict, args: argparse.Namespace) -> tuple[str, str]:
    available, reason = toolchain_available(profile, args.wsl_distro)
    if not available:
        return "skip", reason

    _base, build_dir, install_dir = profile_dirs(profile["name"])
    relative_build = os.path.join("out", profile["name"], "build").replace("\\", "/")
    relative_install = os.path.join("out", profile["name"], "install").replace(
        "\\", "/"
    )
    log_path = os.path.join(build_dir, "build_and_test.log")

    if args.clean and os.path.isdir(build_dir):
        shutil.rmtree(build_dir)
    os.makedirs(build_dir, exist_ok=True)
    if os.path.exists(log_path):
        os.remove(log_path)

    configure, build, install = build_commands(
        profile, build_dir, install_dir, args.jobs
    )
    steps = [("配置", configure), ("构建", build)]
    if not args.skip_install:
        steps.append(("安装", install))

    if profile["toolchain"] == "wsl":
        steps = [
            (
                label,
                wrap_wsl(
                    cmd,
                    build_dir,
                    install_dir,
                    relative_build,
                    relative_install,
                    args.wsl_distro,
                ),
            )
            for label, cmd in steps
        ]

    print("\n==> build %s（%s）" % (profile["name"], profile["build_type"]))
    for label, cmd in steps:
        print("--- %s" % label)
        code = stream_command(cmd, ROOT, log_path)
        if code != 0:
            return "fail", "%s失败（退出码 %d）" % (label, code)
    if args.skip_install:
        return "ok", "配置与构建通过（未安装）"
    return "ok", "配置、构建与安装通过"


def run_test(profile: dict, args: argparse.Namespace) -> tuple[str, str]:
    available, reason = toolchain_available(profile, args.wsl_distro)
    if not available:
        return "skip", reason

    _base, build_dir, install_dir = profile_dirs(profile["name"])
    relative_build = os.path.join("out", profile["name"], "build").replace("\\", "/")
    relative_install = os.path.join("out", profile["name"], "install").replace(
        "\\", "/"
    )
    cache = os.path.join(build_dir, "CMakeCache.txt")
    if not os.path.isfile(cache):
        # 全量 test：未 build 的档跳过。显式 --only 点名时仍失败，避免误以为跑过。
        if args.only:
            return "fail", "未找到构建目录，请先执行：build --only %s" % profile["name"]
        return "skip", "尚未 build，跳过"

    log_path = os.path.join(build_dir, "build_and_test.log")
    cmd = test_command(profile, build_dir)
    if profile["toolchain"] == "wsl":
        cmd = wrap_wsl(
            cmd,
            build_dir,
            install_dir,
            relative_build,
            relative_install,
            args.wsl_distro,
        )

    print("\n==> test %s（%s）" % (profile["name"], profile["build_type"]))
    print("--- 测试")
    code = stream_command(cmd, ROOT, log_path)
    if code != 0:
        return "fail", "测试失败（退出码 %d）" % code
    return "ok", "测试通过"


def select_profiles(only: list[str] | None) -> list[dict]:
    if not only:
        return list(PROFILES)
    wanted = set(only)
    selected = [p for p in PROFILES if p["name"] in wanted]
    missing = wanted - {p["name"] for p in selected}
    if missing:
        raise SystemExit("未知档位：%s" % "、".join(sorted(missing)))
    return selected


def print_summary(action: str, results: list[tuple[str, str, str]]) -> int:
    labels = {"ok": "通过", "fail": "失败", "skip": "跳过"}
    print("\n== %s 汇总 ==" % action)
    for name, status, detail in results:
        print("%-16s %-6s %s" % (name, labels[status], detail))
    failed = [r for r in results if r[1] == "fail"]
    skipped = [r for r in results if r[1] == "skip"]
    if failed:
        print("\n总判定：失败（%d 档失败）" % len(failed))
        return 1
    if skipped and not any(r[1] == "ok" for r in results):
        print("\n总判定：无可用档位（全部跳过）")
        return 2
    if skipped:
        print("\n总判定：完成（%d 档跳过）" % len(skipped))
        return 0
    print("\n总判定：全部通过")
    return 0


def add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--only",
        action="append",
        metavar="档位",
        help="只处理指定档位（可重复）",
    )
    parser.add_argument(
        "--wsl-distro",
        default="Ubuntu",
        help="WSL 发行版名称，默认 Ubuntu",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="本地多平台构建与测试（build / test 分开）"
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="列出档位与工具链是否可用后退出",
    )
    sub = parser.add_subparsers(dest="command")

    build_parser = sub.add_parser(
        "build", help="配置、编译，并安装到 out/<档位>/install"
    )
    add_common_args(build_parser)
    build_parser.add_argument(
        "--clean",
        action="store_true",
        help="删除该档 out/<档位>/build 后重新配置",
    )
    build_parser.add_argument(
        "--skip-install",
        action="store_true",
        help="只编译，不执行 cmake --install",
    )
    build_parser.add_argument(
        "--jobs",
        type=int,
        default=None,
        help="构建并行度，传给 cmake --build --parallel",
    )

    test_parser = sub.add_parser("test", help="对已有 out/<档位>/build 跑 ctest")
    add_common_args(test_parser)

    args = parser.parse_args(argv)

    if args.list:
        for profile in PROFILES:
            ok, detail = toolchain_available(profile, "Ubuntu")
            print(
                "%-16s %-6s %s"
                % (profile["name"], profile["toolchain"], detail if not ok else "可用")
            )
        return 0

    if args.command is None:
        parser.print_help()
        print(
            "\n请使用子命令：build（编译安装）或 test（单独跑测试）。",
            file=sys.stderr,
        )
        return 2

    selected = select_profiles(args.only)
    results: list[tuple[str, str, str]] = []
    runner = run_build if args.command == "build" else run_test
    for profile in selected:
        status, detail = runner(profile, args)
        results.append((profile["name"], status, detail))
    return print_summary(args.command, results)


if __name__ == "__main__":
    sys.exit(main())
