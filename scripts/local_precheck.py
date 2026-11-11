#!/usr/bin/env python3
# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT
"""发版前本地预检：按工具链矩阵逐档构建、跑测试，并检查链接警告。

一条命令给出逐档结论与总判定：任何一档构建或测试失败、或构建输出里出现
链接警告，退出码即非零，视为不可打 tag。CI 是背书，不是第一次发现错误的
地方——打 tag 之前本机必须已经过一遍。

档位定义见 PROFILES，每档都标注了它在覆盖哪类风险：语言标准、平台宏、
链接器差异。--only 可只跑指定档位用于迭代，发版必须全跑。
"""

import argparse
import os
import re
import shlex
import shutil
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(SCRIPT_DIR)

COMMON_OPTIONS = [
    "-DASNBER_BUILD_TESTS=ON",
    "-DASNBER_BUILD_EXAMPLES=ON",
    # 与 CI 一致：警告即错误，避免本地放过 CI 才报的告警。
    "-DASNBER_WARNINGS_AS_ERRORS=ON",
    "-DASNBER_BUILD_MODULE_PKCS=ON",
    "-DASNBER_BUILD_MODULE_CMS=ON",
]

# 链接警告一律视为失败：重复库会掩盖真实的链接依赖问题，长期挂着就成噪声。
LINK_WARNING_PATTERNS = [
    re.compile(r"ld: warning:"),
    re.compile(r"ignoring duplicate libraries"),
    re.compile(r"^.*\bLNK\d{4}\b.*$", re.MULTILINE),
]

PROFILES = [
    {
        "name": "msvc-debug-static",
        "toolchain": "msvc",
        "build_type": "Debug",
        "shared": False,
        "why": "MSVC 默认语言标准（C++14）与 /W4 /WX；_MSC_VER 分支；"
               "静态核心的链接重复只在这一档暴露",
    },
    {
        "name": "msvc-release-shared",
        "toolchain": "msvc",
        "build_type": "Release",
        "shared": True,
        "why": "优化 + NDEBUG；DLL 导出/导入宏与 __declspec 路径",
    },
    {
        "name": "wsl-debug-shared",
        "toolchain": "wsl",
        "build_type": "Debug",
        "shared": True,
        "why": "Linux ELF/ld、__linux__ 与共享库符号可见性",
    },
    {
        "name": "wsl-release-static",
        "toolchain": "wsl",
        "build_type": "Release",
        "shared": False,
        "why": "Linux 优化 + 静态归档的链接顺序",
    },
    {
        "name": "mingw-release-static",
        "toolchain": "mingw",
        "build_type": "Release",
        "shared": False,
        "why": "Windows 平台宏不带 _MSC_VER；GNU 链接器与 MSVC 的差异",
    },
]


def to_wsl_path(path):
    """把 Windows 绝对路径映射为 WSL 的 /mnt/<disk>/... 形式。"""
    drive, rest = os.path.splitdrive(path)
    if not drive:
        return path.replace("\\", "/")
    return "/mnt/" + drive[0].lower() + rest.replace("\\", "/")


def stream_command(argv, cwd, log_path):
    """执行命令，输出同时追加到日志并打到控制台；返回进程退出码。"""
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
        for line in proc.stdout:
            log.write(line)
            sys.stdout.write(line)
        proc.wait()
        return proc.returncode


def find_link_warnings(log_path):
    """返回日志里的链接警告行（去重后保序）。"""
    if not os.path.exists(log_path):
        return []
    with open(log_path, encoding="utf-8", errors="replace") as handle:
        text = handle.read()
    hits = []
    for pattern in LINK_WARNING_PATTERNS:
        for match in pattern.finditer(text):
            line = match.group(0).strip()
            if line and line not in hits:
                hits.append(line)
    return hits


def build_plan(profile, build_dir):
    """按档位拼出配置、构建、测试三条命令。"""
    shared = "ON" if profile["shared"] else "OFF"
    static = "OFF" if profile["shared"] else "ON"
    common = COMMON_OPTIONS + [
        "-DASNBER_BUILD_SHARED=" + shared,
        "-DASNBER_BUILD_STATIC=" + static,
    ]
    build_type = profile["build_type"]

    if profile["toolchain"] == "msvc":
        configure = ["cmake", "-S", ".", "-B", build_dir, "-A", "x64",
                     "-DCMAKE_BUILD_TYPE=" + build_type] + common
        build = ["cmake", "--build", build_dir, "--config", build_type,
                 "--parallel"]
        test = ["ctest", "--test-dir", build_dir, "-C", build_type,
                "--output-on-failure"]
    else:
        compiler = "gcc" if profile["toolchain"] == "mingw" else "cc"
        cxx = "g++" if profile["toolchain"] == "mingw" else "c++"
        configure = ["cmake", "-S", ".", "-B", build_dir, "-G", "Ninja",
                     "-DCMAKE_BUILD_TYPE=" + build_type,
                     "-DCMAKE_C_COMPILER=" + compiler,
                     "-DCMAKE_CXX_COMPILER=" + cxx] + common
        build = ["cmake", "--build", build_dir, "--parallel"]
        test = ["ctest", "--test-dir", build_dir, "--output-on-failure"]

    return configure, build, test


def run_profile(profile, args):
    """跑一档，返回 (状态, 说明)。状态取 ok / fail / skip。"""
    build_dir_name = "build-precheck-" + profile["name"]
    build_dir = os.path.join(ROOT, build_dir_name)
    configure, build, test = build_plan(profile, build_dir)
    # 三个阶段共用一个日志：链接警告只出现在构建阶段，若被后续阶段覆盖就
    # 等于没检查。
    log_path = os.path.join(build_dir, "precheck.log")
    if not os.path.isdir(build_dir):
        os.makedirs(build_dir, exist_ok=True)
    if os.path.exists(log_path):
        os.remove(log_path)

    if profile["toolchain"] == "wsl":
        wsl_root = to_wsl_path(ROOT)
        # cmake 在 WSL 里执行，构建目录要用仓库内相对路径，否则 Windows
        # 绝对路径会被当成一个带反斜杠的怪名字目录。
        relative_dir = build_dir_name
        configure = [part.replace(build_dir, relative_dir)
                     for part in configure]
        build = [part.replace(build_dir, relative_dir) for part in build]
        test = [part.replace(build_dir, relative_dir) for part in test]

        def wrap(cmd):
            joined = " ".join(shlex.quote(part) for part in cmd)
            return ["wsl", "-d", args.wsl_distro, "--", "bash", "-lc",
                    "cd %s && %s" % (shlex.quote(wsl_root), joined)]

        configure, build, test = wrap(configure), wrap(build), wrap(test)
    elif profile["toolchain"] == "mingw":
        if not shutil.which("gcc"):
            return "skip", "本机 PATH 没有 gcc，无法覆盖 MinGW 档"

    print("\n==> %s（%s，%s）" % (
        profile["name"], profile["build_type"],
        "共享" if profile["shared"] else "静态"))
    print("    覆盖风险：%s" % profile["why"])

    for label, cmd in (("配置", configure), ("构建", build), ("测试", test)):
        print("--- %s" % label)
        code = stream_command(cmd, ROOT, log_path)
        if code != 0:
            return "fail", "%s失败（退出码 %d）" % (label, code)

    warnings = find_link_warnings(log_path)
    if warnings:
        print("\n链接警告（必须为零）：")
        for line in warnings:
            print("    " + line)
        return "fail", "构建输出含 %d 条链接警告" % len(warnings)
    return "ok", "构建与测试通过，无链接警告"


def main():
    parser = argparse.ArgumentParser(
        description="发版前本地预检：逐档构建 + ctest + 链接警告检查")
    parser.add_argument("--only", action="append", metavar="档位",
                        help="只跑指定档位（可重复），用于迭代")
    parser.add_argument("--wsl-distro", default="Ubuntu",
                        help="WSL 发行版名称，默认 Ubuntu")
    parser.add_argument("--list", action="store_true", help="列出档位后退出")
    args = parser.parse_args()

    if args.list:
        for profile in PROFILES:
            print("%-22s %-6s %s" % (profile["name"], profile["toolchain"],
                                     profile["why"]))
        return 0

    selected = PROFILES
    if args.only:
        wanted = set(args.only)
        selected = [p for p in PROFILES if p["name"] in wanted]
        missing = wanted - {p["name"] for p in selected}
        if missing:
            print("未知档位：%s" % "、".join(sorted(missing)))
            return 2

    results = []
    for profile in selected:
        status, detail = run_profile(profile, args)
        results.append((profile["name"], status, detail))

    print("\n== 预检汇总 ==")
    for name, status, detail in results:
        print("%-22s %-6s %s" % (name, {"ok": "通过", "fail": "失败",
                                        "skip": "跳过"}[status], detail))

    failed = [r for r in results if r[1] == "fail"]
    skipped = [r for r in results if r[1] == "skip"]
    if failed:
        print("\n总判定：不可发版（%d 档失败）" % len(failed))
        return 1
    if skipped:
        print("\n总判定：预检不完整（%d 档因缺工具链跳过），不得据此打 tag"
              % len(skipped))
        return 2
    print("\n总判定：通过，可以打 tag")
    return 0


if __name__ == "__main__":
    sys.exit(main())
