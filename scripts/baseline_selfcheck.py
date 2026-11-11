#!/usr/bin/env python3
# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT
"""证明 refactor_baseline.py 不是空转：在临时克隆里做三次变异。

每次变异都必须让基线脚本以非零退出：

1. 篡改一张检入的 `.bin` 描述表的一个字节（描述表逐字节比对必须失败）；
2. 改写 `abi/asnber.symbols.txt` 中的一个导出符号名（ABI 集合比对必须失败）；
3. 改动 `tests/support/test_support.c` 的测试期望并重建（ctest 必须失败）。

清理前会先跑一次未变异基线，确认它通过（否则本脚本自身失败）。
用法:  python scripts/baseline_selfcheck.py [--keep] [--jobs N]
"""

import argparse
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASELINE = os.path.join("scripts", "refactor_baseline.py")
TABLE = os.path.join("modules", "cms", "generated", "cms_schema.bin")
ABI = os.path.join("abi", "asnber.symbols.txt")
TEST = os.path.join("tests", "support", "test_support.c")


def run(args, cwd):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True)


def sync_worktree(root, clone):
    """把当前工作区改动覆盖到克隆上，保证自检针对即将提交的状态。"""
    proc = run(["git", "-c", "core.quotepath=false", "-C", root,
                "status", "--porcelain"], root)
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        status = line[:2]
        path = line[3:].strip()
        if path.startswith('"') and path.endswith('"'):
            path = path[1:-1]
        if " -> " in path:
            path = path.split(" -> ", 1)[1]
        src = os.path.join(root, path)
        dst = os.path.join(clone, path)
        if os.path.isdir(src):
            if os.path.isdir(dst):
                shutil.rmtree(dst)
            shutil.copytree(src, dst)
            continue
        if os.path.exists(src):
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
        elif os.path.exists(dst):
            os.remove(dst)


def configure(clone, build):
    base = ["cmake", "-S", clone, "-B", build,
            "-DCMAKE_BUILD_TYPE=Debug",
            "-DASNBER_BUILD_TESTS=ON",
            "-DASNBER_BUILD_TOOLS=ON",
            "-DASNBER_BUILD_MODULES=ON",
            "-DASNBER_BUILD_MODULE_PKCS=ON",
            "-DASNBER_BUILD_MODULE_CMS=ON",
            "-DASNBER_BUILD_SHARED=ON",
            "-DASNBER_BUILD_STATIC=ON",
            "-DASNBER_BUILD_DIFFERENTIAL=ON"]
    if shutil.which("ninja") and shutil.which("gcc") and shutil.which("g++"):
        proc = run(base[:5] + ["-G", "Ninja",
                               "-DCMAKE_C_COMPILER=gcc",
                               "-DCMAKE_CXX_COMPILER=g++"] + base[5:], clone)
        if proc.returncode == 0:
            return True
    proc = run(base, clone)
    return proc.returncode == 0


def build_args(build):
    args = ["cmake", "--build", build, "--parallel"]
    cache = os.path.join(build, "CMakeCache.txt")
    if os.path.exists(cache):
        with open(cache, "r", encoding="utf-8", errors="ignore") as handle:
            if "CMAKE_CONFIGURATION_TYPES" in handle.read():
                args += ["--config", "Debug"]
    return args


def baseline(clone, build, log_path):
    proc = run([sys.executable, BASELINE, "--strict", "--build-dir", build], clone)
    output = (proc.stdout or "") + (proc.stderr or "")
    with io.open(log_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(output)
    return proc.returncode, output


def failure_evidence(text):
    keys = ("CTEST FAILED", "TABLE ", "ABI ", "DIFF FAIL", "RT FAIL",
            "ASSERT FAIL", "DOC MISMATCH", "BASELINE FAIL")
    lines = [line for line in text.splitlines() if line.startswith(keys)]
    if not lines:
        lines = text.strip().splitlines()[-6:]
    return "\n".join(lines[-16:])


def flip_byte(path):
    with open(path, "rb") as handle:
        data = bytearray(handle.read())
    data[0] ^= 0x01
    with open(path, "wb") as handle:
        handle.write(data)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true", help="保留临时目录")
    ap.add_argument("--jobs", default=None)
    args = ap.parse_args()

    tmp = tempfile.mkdtemp(prefix="asnber-baseline-selfcheck-")
    clone = os.path.join(tmp, "repo")
    build = os.path.join(clone, "build-check")
    try:
        proc = run(["git", "clone", "--quiet", ROOT, clone], ROOT)
        if proc.returncode != 0:
            print("FAIL 克隆失败:", proc.stderr.strip())
            return 1
        sync_worktree(ROOT, clone)
        if not configure(clone, build):
            print("FAIL 克隆配置失败")
            return 1
        build_cmd = build_args(build)
        proc = run(build_cmd, clone)
        if proc.returncode != 0:
            print("FAIL 克隆构建失败:", proc.stdout.strip().splitlines()[-5:])
            return 1

        print("SELFCHECK 未变异基线")
        rc, text = baseline(clone, build, os.path.join(tmp, "clean.txt"))
        print("SELFCHECK clean exit=%d %s" % (rc, "PASS" if rc == 0 else "FAIL"))
        if rc != 0:
            print(failure_evidence(text))
            return 1

        table_path = os.path.join(clone, TABLE)
        with open(table_path, "rb") as handle:
            table_orig = handle.read()
        abi_path = os.path.join(clone, ABI)
        with open(abi_path, "r", encoding="utf-8") as handle:
            abi_orig = handle.read()
        test_path = os.path.join(clone, TEST)
        with open(test_path, "r", encoding="utf-8") as handle:
            test_orig = handle.read()

        checks = []

        # 变异 1：篡改描述表一个字节。
        flip_byte(table_path)
        rc, text = baseline(clone, build, os.path.join(tmp, "mutate_table.txt"))
        print("SELFCHECK 变异1 描述表改字节 exit=%d %s"
              % (rc, "EXPECTED-FAIL" if rc != 0 else "UNEXPECTED-PASS"))
        print(failure_evidence(text))
        checks.append(rc != 0)
        with open(table_path, "wb") as handle:
            handle.write(table_orig)

        # 变异 2：改一个导出符号名。
        match = re.search(r"^(asnber_\w+)", abi_orig, re.M)
        if match is None:
            print("FAIL 导出符号清单中没有可改名的 asnber_ 符号")
            return 1
        abi_orig_new = (abi_orig[:match.start()]
                        + "asnber_baseline_selfcheck_probe"
                        + abi_orig[match.end():])
        with open(abi_path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(abi_orig_new)
        rc, text = baseline(clone, build, os.path.join(tmp, "mutate_abi.txt"))
        print("SELFCHECK 变异2 导出符号改名 exit=%d %s"
              % (rc, "EXPECTED-FAIL" if rc != 0 else "UNEXPECTED-PASS"))
        print(failure_evidence(text))
        checks.append(rc != 0)
        with open(abi_path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(abi_orig)

        # 变异 3：改测试期望并重建。
        mutated = test_orig.replace("ASNBER_VERSION_ENCODED ==\n", "ASNBER_VERSION_ENCODED !=\n", 1)
        if mutated == test_orig:
            mutated = test_orig.replace("!=", "==", 1)
        with open(test_path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(mutated)
        proc = run(build_args(build) + ["--target", "test_support"], clone)
        rc, text = baseline(clone, build, os.path.join(tmp, "mutate_test.txt"))
        print("SELFCHECK 变异3 测试期望反转 exit=%d %s"
              % (rc, "EXPECTED-FAIL" if rc != 0 else "UNEXPECTED-PASS"))
        print(failure_evidence(text))
        checks.append(rc != 0)
        with open(test_path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(test_orig)
        run(build_args(build) + ["--target", "test_support"], clone)

        if all(checks):
            print("SELFCHECK OK 三次变异均按预期失败")
            return 0
        print("SELFCHECK FAIL 有变异未被基线脚本捕获")
        return 1
    finally:
        if args.keep:
            print("SELFCHECK 临时目录:", tmp)
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
