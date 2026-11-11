#!/usr/bin/env python3
# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT
"""单文件行数守卫：任何 .cpp 超过 800 行即失败。

允许清单 scripts/file_size_allowlist.txt 只应随拆分逐步变短：
每行格式为 "<相对路径> <冻结行数>"，脚本要求该文件仍然存在、
仍然超过 800 行，且行数不超过登记值；低于 800 行时视为清单过期，
必须删除该条目（防止把合规文件补进清单）。
"""

import argparse
import os
import sys

HARD_LIMIT = 800
ALLOWLIST = "file_size_allowlist.txt"
SKIP_DIRS = {".git", "build", "out", "docs", "abi", "sdks"}
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(SCRIPT_DIR)


def iter_sources(root):
    for base, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith("build"))
        for name in sorted(files):
            if name.endswith(".cpp"):
                path = os.path.join(base, name)
                yield os.path.relpath(path, root).replace(os.sep, "/")


def read_allowlist(path):
    entries = {}
    if not os.path.exists(path):
        return entries
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) != 2 or not parts[1].isdigit():
                raise ValueError("允许清单格式应为 '<路径> <行数>'：%s" % line)
            entries[parts[0]] = int(parts[1])
    return entries


def line_count(path):
    with open(path, "rb") as handle:
        return sum(1 for _ in handle)


def main():
    parser = argparse.ArgumentParser(description="单文件行数守卫")
    parser.add_argument("--root", default=ROOT, help="仓库根目录")
    parser.add_argument("--allowlist", default=os.path.join(SCRIPT_DIR, ALLOWLIST))
    args = parser.parse_args()

    allowed = read_allowlist(args.allowlist)
    problems = []
    checked = 0

    for rel in iter_sources(args.root):
        count = line_count(os.path.join(args.root, rel))
        checked += 1
        if rel in allowed:
            budget = allowed[rel]
            if count <= HARD_LIMIT:
                problems.append(
                    "%s 已降至 %d 行（硬上限 %d），请从允许清单删除该条目"
                    % (rel, count, HARD_LIMIT))
            elif count > budget:
                problems.append(
                    "%s 增至 %d 行，超过登记的 %d 行；不能放宽清单"
                    % (rel, count, budget))
        elif count > HARD_LIMIT:
            problems.append(
                "%s 为 %d 行，超过硬上限 %d 行" % (rel, count, HARD_LIMIT))

    for rel in allowed:
        if not os.path.exists(os.path.join(args.root, rel)):
            problems.append("%s 在允许清单中但文件不存在，请删除该条目" % rel)

    for item in problems:
        print("FAIL %s" % item)
    print("检查 %d 个 .cpp，允许清单 %d 条，硬上限 %d 行"
          % (checked, len(allowed), HARD_LIMIT))
    if problems:
        return 1
    print("FILE SIZE OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
