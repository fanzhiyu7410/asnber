#!/usr/bin/env python3
# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT
"""派生测试断言点静态计数，并保持 README / docs 与之同步。

计数口径：`tests/` 下所有 `.c` / `.cpp` / `.h` 文件中 `ASNBER_TEST_CHECK(` 的出现次数
（与 `grep ASNBER_TEST_CHECK` 一致，含 `tests/support/check.h` 里的宏定义一行；
循环体内的实际执行次数不计入）。README 与 docs/07 中的数字必须由本脚本写入，
不允许手写：

  python scripts/count_assertions.py           # 打印计数与 Top 文件
  python scripts/count_assertions.py --check   # 校验文档数字（不一致时退出 1）
  python scripts/count_assertions.py --write   # 用派生值改写文档
"""

import argparse
import io
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS = os.path.join(ROOT, "tests")
DOCS = (os.path.join(ROOT, "README.md"),
        os.path.join(ROOT, "docs", "07-测试与验证.md"))
PATTERN = re.compile(r"断言点静态计数 \*\*([0-9,]+) 处\*\*")
SOURCE_SUFFIX = (".c", ".cpp", ".cc", ".h")


def count_assertions():
    total = 0
    files = []
    for base, dirs, names in os.walk(TESTS):
        dirs[:] = sorted(d for d in dirs if d != "data")
        for name in sorted(names):
            if not name.endswith(SOURCE_SUFFIX):
                continue
            path = os.path.join(base, name)
            with io.open(path, encoding="utf-8", errors="ignore") as handle:
                count = handle.read().count("ASNBER_TEST_CHECK(")
            if count:
                files.append((os.path.relpath(path, ROOT).replace("\\", "/"), count))
                total += count
    return total, files


def documented_values():
    values = []
    for path in DOCS:
        with io.open(path, encoding="utf-8") as handle:
            for lineno, line in enumerate(handle, 1):
                for match in PATTERN.finditer(line):
                    values.append((path, lineno, int(match.group(1).replace(",", ""))))
    return values


def main():
    parser = argparse.ArgumentParser(description="断言点静态计数派生")
    parser.add_argument("--check", action="store_true", help="校验文档数字")
    parser.add_argument("--write", action="store_true", help="改写文档数字")
    args = parser.parse_args()

    total, files = count_assertions()
    print("ASSERTIONS total=%d files=%d" % (total, len(files)))
    for relpath, count in sorted(files, key=lambda item: (-item[1], item[0]))[:10]:
        print("ASSERTIONS %-48s %d" % (relpath, count))

    values = documented_values()
    if not values:
        print("FAIL 文档中未找到“断言点静态计数 **N 处**”锚点")
        return 1
    for path, lineno, value in values:
        print("DOC %s:%d documented=%d derived=%d %s"
              % (os.path.relpath(path, ROOT).replace("\\", "/"), lineno,
                 value, total, "OK" if value == total else "MISMATCH"))

    if args.write:
        for path in DOCS:
            with io.open(path, encoding="utf-8") as handle:
                text = handle.read()
            text = PATTERN.sub("断言点静态计数 **%s 处**" % format(total, ","), text)
            with io.open(path, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
        print("ASSERTIONS written=%d" % total)
        return 0

    bad = [item for item in values if item[2] != total]
    if args.check and bad:
        print("FAIL 文档断言计数与派生值不一致（共 %d 处）" % len(bad))
        return 1
    if args.check:
        print("ASSERTIONS OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
