#!/usr/bin/env python3
# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT
"""覆盖率门禁：合并 profraw、对核心库对象聚合 llvm-cov 报告并校验阈值。

只统计 src/CMakeFiles/asnber_static.dir 下的对象，避免共享库与静态库
两份对象重复计数；因此本地与 CI 都应使用 -DASNBER_BUILD_SHARED=OFF
的插桩构建。测试进程需按 build-dir/covdata/%p-%m.profraw 写 profile：

    LLVM_PROFILE_FILE=$PWD/build-cov/covdata/%p-%m.profraw \\
      ctest --test-dir build-cov --output-on-failure
    python3 scripts/check_coverage.py --build-dir build-cov

退出码：0 达标，1 低于阈值，2 缺少工具/对象/采样数据。
"""

import argparse
import glob
import os
import re
import shutil
import subprocess
import sys

LINE_THRESHOLD = 80.0
BRANCH_THRESHOLD = 70.0
OBJECT_DIR = os.path.join("src", "CMakeFiles", "asnber_static.dir")


def find_tool(name):
    exe = shutil.which(name)
    if exe:
        return exe
    versioned = glob.glob("/usr/lib/llvm-*/bin/" + name)
    if versioned:
        def version_key(path):
            match = re.search(r"llvm-(\d+)", path)
            return int(match.group(1)) if match else 0
        return sorted(versioned, key=version_key)[-1]
    program_files = os.environ.get("ProgramFiles")
    if program_files:
        candidate = os.path.join(program_files, "LLVM", "bin", name + ".exe")
        if os.path.isfile(candidate):
            return candidate
    raise SystemExit("找不到 %s：请安装 LLVM 或把它加入 PATH" % name)


def find_objects(build_dir):
    base = os.path.join(build_dir, OBJECT_DIR)
    objects = []
    for suffix in ("*.o", "*.obj"):
        objects.extend(glob.glob(os.path.join(base, "**", suffix),
                                 recursive=True))
    return sorted(objects)


def merge_profiles(profdata_tool, profraw_dir, profdata_path):
    profraws = sorted(glob.glob(os.path.join(profraw_dir, "*.profraw")))
    if not profraws:
        raise SystemExit("%s 下没有 .profraw：测试进程未按 LLVM_PROFILE_FILE 运行"
                         % profraw_dir)
    subprocess.run([profdata_tool, "merge", "-sparse"] + profraws +
                   ["-o", profdata_path], check=True)
    return len(profraws)


def run_report(cov_tool, objects, profdata_path):
    command = [cov_tool, "report", objects[0]]
    command.extend("-object=" + path for path in objects[1:])
    command.append("-instr-profile=" + profdata_path)
    return subprocess.run(command, check=True, capture_output=True,
                          text=True).stdout


def parse_total(report_text):
    for line in report_text.splitlines():
        if not line.startswith("TOTAL"):
            continue
        fields = line.split()
        if len(fields) < 13:
            break
        try:
            line_pct = float(fields[9].rstrip("%"))
            branch_pct = float(fields[12].rstrip("%"))
        except ValueError:
            break
        return {
            "line_pct": line_pct,
            "line_covered": int(fields[7]) - int(fields[8]),
            "line_total": int(fields[7]),
            "branch_pct": branch_pct,
            "branch_covered": int(fields[10]) - int(fields[11]),
            "branch_total": int(fields[10]),
        }
    raise SystemExit("llvm-cov 报告缺少可解析的 TOTAL 行")


def main():
    parser = argparse.ArgumentParser(description="核心库覆盖率门禁")
    parser.add_argument("--build-dir", default="build-cov",
                        help="插桩构建目录（含 covdata/ 与静态库对象）")
    parser.add_argument("--profdata",
                        help="已有的 .profdata；省略则合并 covdata/*.profraw")
    parser.add_argument("--line", type=float, default=LINE_THRESHOLD,
                        help="行覆盖率下限（默认值 {}，单位为百分数）".format(
                            LINE_THRESHOLD))
    parser.add_argument("--branch", type=float, default=BRANCH_THRESHOLD,
                        help="分支覆盖率下限（默认值 {}，单位为百分数）".format(
                            BRANCH_THRESHOLD))
    args = parser.parse_args()

    build_dir = os.path.abspath(args.build_dir)
    objects = find_objects(build_dir)
    if not objects:
        raise SystemExit("%s 下没有静态库对象：请用 -DASNBER_BUILD_STATIC=ON "
                         "且 -DASNBER_BUILD_SHARED=OFF 配置" % os.path.join(
                             build_dir, OBJECT_DIR))

    profdata_path = args.profdata
    merged = 0
    if profdata_path is None:
        profdata_path = os.path.join(build_dir, "coverage.profdata")
        merged = merge_profiles(find_tool("llvm-profdata"),
                                os.path.join(build_dir, "covdata"),
                                profdata_path)
    elif not os.path.isfile(profdata_path):
        raise SystemExit("找不到 %s" % profdata_path)

    report_text = run_report(find_tool("llvm-cov"), objects, profdata_path)
    report_path = os.path.join(build_dir, "coverage-report.txt")
    with open(report_path, "w", encoding="utf-8") as handle:
        handle.write(report_text)

    total = parse_total(report_text)
    failures = []
    print("对象 %d 个，profraw %s，报告 %s"
          % (len(objects),
             ("%d 份" % merged) if merged else "复用",
             report_path))
    for label, pct, covered, count, threshold in (
            ("行", total["line_pct"], total["line_covered"],
             total["line_total"], args.line),
            ("分支", total["branch_pct"], total["branch_covered"],
             total["branch_total"], args.branch)):
        verdict = "PASS" if pct >= threshold else "FAIL"
        print("%s覆盖 %.2f%% (%d/%d) 阈值 %.1f%%: %s"
              % (label, pct, covered, count, threshold, verdict))
        if pct < threshold:
            failures.append(label)

    if failures:
        print("覆盖率低于阈值：%s" % "、".join(failures))
        return 1
    print("COVERAGE OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
