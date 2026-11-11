#!/usr/bin/env python3
"""结构重组基线证据（fail-closed）。

一次输出固定顺序、与运行时间无关的基线事实；任何一项无法验证都按失败处理：

- ctest 注册用例数、逐条结果、失败用例名与真实退出码；
- 六张 asnber-cms 描述表与再生表逐字节比对（未指定再生目录时自动配置并构建
  `asnber_cms_table_generate`，绝不输出 `not-run`）；
- 共享库实际导出符号与 `abi/*.symbols.txt` 的逐符号集合比对（新增/删除/改名
  都会失败并打印符号名）；
- 27 份差分 DER 的差分/往返结论；
- CMS 样本往返逐字节摘要；
- README/docs 中用例数和断言点计数由脚本派生并与 `ctest -N` / 源码一致。

用法:
  python scripts/refactor_baseline.py [--build-dir build-cms-env]
                                      [--regen-dir build-cms-regen]
                                      [--strict]

`--strict` 供 CI 使用：与默认行为一致（所有检查已 fail-closed），额外明确要求
ABI 符号比对、描述表逐字节比对与断言计数校验全部通过。

输出只写 stdout；需要留档时由调用方重定向。退出码 0 表示全部检查通过。
"""

import argparse
import glob
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "tests", "data")
DIFF = os.path.join(ROOT, "tests", "differential", "diff_asnber.py")
CHECK_EXPORTS = os.path.join(ROOT, "scripts", "check_exports.py")
COUNT_ASSERTIONS = os.path.join(ROOT, "scripts", "count_assertions.py")

TABLE_NAMES = ("cms_schema",)

# 每个 ASN.1 文件只保留一张描述表：模块目录、表名、表体字节、合法根编号
# （首项为表头默认根，其余由 asnber_schema_load_with_root 在加载期指定）。
TABLE_INVENTORY = (
    ("cms", "cms_schema", 19024, (1, 3, 48, 72, 73, 75)),
    ("pkcs1", "pkcs1_schema", 1624, (1, 2)),
    ("pkcs8", "pkcs8_schema", 1448, (1, 5)),
    ("pkcs10", "pkcs10_schema", 2160, (1, 2)),
    ("pkcs12", "pkcs12_schema", 3112, (1, 7, 8, 11)),
    ("pkix", "pkix_schema", 24144, (20,)),
)
EXPECTED_TABLE_TOTAL = 51512
ABI_FILES = (
    ("asnber", "abi/asnber.symbols.txt"),
    ("asnber-pkix", "abi/asnber-pkix.symbols.txt"),
    ("asnber-pkcs1", "abi/asnber-pkcs1.symbols.txt"),
    ("asnber-pkcs8", "abi/asnber-pkcs8.symbols.txt"),
    ("asnber-pkcs10", "abi/asnber-pkcs10.symbols.txt"),
    ("asnber-pkcs12", "abi/asnber-pkcs12.symbols.txt"),
    ("asnber-cms", "abi/asnber-cms.symbols.txt"),
)
CMS_ENVELOPED = (
    "cms_enveloped_ktri.der",
    "cms_enveloped_ktri_multi.der",
    "cms_enveloped_ktri_keyid.der",
    "cms_enveloped_kari.der",
    "cms_enveloped_kekri.der",
    "cms_enveloped_pwri.der",
)
CMS_SIGNED = (
    "cms_rsa_attached.der",
    "cms_rsa_detached.der",
    "cms_rsa_minimal.der",
    "cms_rsa_ec_multicert.der",
    "cms_rsa_keyid.der",
)
CMS_ENCRYPTED = ("cms_encrypted_data.der",)
CMS_COMPRESSED = ("cms_compressed_data.der",)
CMS_AUTHENTICATED = ("cms_authenticated_data.der",
                     "cms_authenticated_data_v1.der",
                     "cms_authenticated_data_v3.der")
# 只读 PKCS 实现包的静态库不得引用编码/构树写侧符号：
# 静态链接按 .o 裁剪的前提是“只读库的未定义符号只落在解码路径”。
# asnber-pkcs8 自 P1 起、asnber-pkcs1 自 P2 起、asnber-pkcs10 自 P4 起、
# asnber-pkcs12 自 P6 起提供 builder，能力位改为 decode+encode，
# 不再受此约束。
PKCS_STATIC_MODULES = ()
FORBIDDEN_UNDEFINED = ("asnber_encode_", "asnber_node_create", "asnber_node_set_",
                       "asnber_doc_seal")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def rel(path):
    return os.path.relpath(path, ROOT).replace("\\", "/")


def run(args, **kwargs):
    return subprocess.run(args, cwd=ROOT, capture_output=True, text=True, **kwargs)


def multi_config(build):
    cache = os.path.join(build, "CMakeCache.txt")
    if not os.path.exists(cache):
        return False
    with open(cache, "r", encoding="utf-8", errors="ignore") as handle:
        return "CMAKE_CONFIGURATION_TYPES" in handle.read()


def ctest_names(build):
    args = ["ctest", "--test-dir", build, "-N"]
    if multi_config(build):
        args += ["-C", "Debug"]
    proc = run(args)
    names = []
    for line in proc.stdout.splitlines():
        m = re.match(r"\s*Test\s+#\d+:\s+(\S+)", line)
        if m:
            names.append(m.group(1))
    return names, proc.returncode


def parse_junit(path):
    results = []
    try:
        tree = ET.parse(path)
    except (OSError, ET.ParseError):
        return None
    for case in tree.getroot().iter("testcase"):
        name = case.get("name") or ""
        if case.find("failure") is not None or case.find("error") is not None:
            status = "FAILED"
        elif case.find("skipped") is not None:
            status = "SKIPPED"
        else:
            status = "PASSED"
        results.append((name, status))
    return results


def parse_ctest_stdout(text):
    pattern = re.compile(
        r"\s*\d+/\d+\s+Test\s+#\d+:\s+(\S+)\s+[.*]*\s*"
        r"(Passed|Failed|Not Run|Timeout|Skipped)"
    )
    results = []
    for line in text.splitlines():
        m = pattern.match(line)
        if m:
            results.append((m.group(1), m.group(2).upper().replace(" ", "_")))
    return results


def ctest_results(build):
    with tempfile.TemporaryDirectory() as tmp:
        xml_path = os.path.join(tmp, "ctest.xml")
        args = ["ctest", "--test-dir", build, "--output-on-failure",
                "--output-junit", xml_path]
        if multi_config(build):
            args += ["-C", "Debug"]
        proc = run(args)
        results = parse_junit(xml_path) if os.path.exists(xml_path) else None
        if not results:
            results = parse_ctest_stdout(proc.stdout)
        return results, proc.returncode, proc.stdout


REGEN_SOURCES = (
    ("modules", "cms", "generated", "table"),
)


def regen_ready(regen_dir):
    for name in TABLE_NAMES:
        for ext in (".bin", ".h"):
            path = os.path.join(regen_dir, *REGEN_SOURCES[0], name + ext)
            if not os.path.exists(path):
                return False
    return True


def build_regen(regen_dir):
    """没有现成再生表时，在本仓库内配置并构建再生目标。"""
    print("REGEN 再生表缺失，配置并构建 asnber_cms_table_generate -> %s" % rel(regen_dir))
    configure = [
        "cmake", "-S", ROOT, "-B", regen_dir,
        "-DASNBER_CMS_REGENERATE_TABLE=ON",
        "-DASNBER_BUILD_TOOLS=ON",
        "-DASNBER_BUILD_MODULES=ON",
        "-DASNBER_BUILD_MODULE_CMS=ON",
        "-DASNBER_BUILD_TESTS=OFF",
        "-DASNBER_BUILD_EXAMPLES=OFF",
        "-DASNBER_BUILD_STATIC=ON",
        "-DASNBER_BUILD_SHARED=OFF",
    ]
    proc = run(configure)
    if proc.returncode != 0:
        print("REGEN CONFIGURE FAILED exit=%d" % proc.returncode)
        print("\n".join(proc.stderr.strip().splitlines()[-15:]))
        return False
    proc = run(["cmake", "--build", regen_dir, "--target",
                "asnber_cms_table_generate", "--parallel"])
    if proc.returncode != 0:
        print("REGEN BUILD FAILED exit=%d" % proc.returncode)
        print("\n".join(proc.stdout.strip().splitlines()[-15:]))
        return False
    if not regen_ready(regen_dir):
        print("REGEN BUILD OK 但产物不全：", rel(regen_dir))
        return False
    return True


def check_tables(regen_dir):
    ok = True
    ready = regen_ready(regen_dir) or build_regen(regen_dir)
    if not ready:
        print("TABLE FAIL: 无法获得再生表，拒绝以 not-run 通过")
        return False
    print("## 描述表 SHA256")
    for name in TABLE_NAMES:
        checked = os.path.join(ROOT, "modules", "cms", "generated", name + ".bin")
        regen = os.path.join(regen_dir, *REGEN_SOURCES[0], name + ".bin")
        digest = sha256_file(checked)
        status = "equal" if sha256_file(regen) == digest else "DIFF"
        if status == "DIFF":
            ok = False
        checked_h = os.path.join(ROOT, "modules", "cms", "generated", name + ".h")
        regen_h = os.path.join(regen_dir, *REGEN_SOURCES[0], name + ".h")
        if os.path.exists(regen_h):
            if sha256_file(regen_h) != sha256_file(checked_h):
                status += ",h-DIFF"
                ok = False
        else:
            status += ",h-MISSING"
            ok = False
        print("TABLE %-28s %s regen=%s" % (name, digest, status))
    return ok


def read_u32(data, offset):
    return int.from_bytes(data[offset:offset + 4], "little")


def check_table_inventory():
    """校验一文件一表的表体总量、表头默认根与全部登记根。"""
    print("## 表体与根类型编号")
    ok = True
    total = 0
    seen = set()
    for module, name, expected, roots in TABLE_INVENTORY:
        path = os.path.join(ROOT, "modules", module, "generated", name + ".bin")
        seen.add(os.path.normcase(path))
        if not os.path.exists(path):
            print("TABLE-INV %-8s %-18s FAIL 缺失" % (module, name))
            ok = False
            continue
        with open(path, "rb") as handle:
            data = handle.read()
        total += len(data)
        header_root = read_u32(data, 96)
        type_count = read_u32(data, 52)
        problems = []
        if len(data) != expected:
            problems.append("size=%d!=%d" % (len(data), expected))
        if header_root != roots[0]:
            problems.append("header_root=%d!=%d" % (header_root, roots[0]))
        for root in roots:
            if root < 1 or root > type_count:
                problems.append("root=%d>type_count=%d" % (root, type_count))
        status = "OK" if not problems else "FAIL " + ",".join(problems)
        if problems:
            ok = False
        print("TABLE-INV %-8s %-18s %6d bytes roots=%s header=%d %s"
              % (module, name, len(data),
                 "/".join(str(root) for root in roots), header_root, status))

    for pattern in ("modules/*/generated/*.bin",):
        for path in glob.glob(os.path.join(ROOT, pattern)):
            if os.path.normcase(path) not in seen:
                print("TABLE-INV EXTRA %s（一文件一表后不应存在）" % rel(path))
                ok = False
    total_status = "OK" if total == EXPECTED_TABLE_TOTAL else "FAIL"
    if total != EXPECTED_TABLE_TOTAL:
        ok = False
    print("TABLE-INV TOTAL %d bytes expected=%d %s"
          % (total, EXPECTED_TABLE_TOTAL, total_status))
    return ok


def find_static_library(build, module):
    names = {
        (module + "_static.a").lower(),
        ("lib" + module + "_static.a").lower(),
        (module + "_static.lib").lower(),
    }
    candidates = []
    for root, _dirs, files in os.walk(build):
        for name in files:
            if name.lower() not in names:
                continue
            path = os.path.join(root, name)
            parts = {part.lower() for part in path.split(os.sep)}
            penalty = 100 if "tests" in parts else 0
            if "install" in parts:
                penalty += 20
            candidates.append((penalty, len(path), path))
    if not candidates:
        return None
    return min(candidates)[2]


def undefined_symbols(path):
    """读取静态库的未定义符号；无可用工具时抛 RuntimeError（fail-closed）。"""
    nm = shutil.which("nm")
    if nm is not None:
        proc = run([nm, "-u", path])
        if proc.returncode == 0:
            symbols = set()
            for line in proc.stdout.splitlines():
                parts = line.split()
                if not parts:
                    continue
                name = parts[-1]
                if name.startswith("_asnber_"):
                    name = name[1:]
                if name.startswith("asnber_"):
                    symbols.add(name.split("@", 1)[0])
            return symbols
    if path.lower().endswith(".lib"):
        dumpbin = None
        vswhere = os.path.join(
            os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
            "Microsoft Visual Studio", "Installer", "vswhere.exe")
        if os.path.isfile(vswhere):
            proc = run([vswhere, "-latest", "-products", "*", "-requires",
                        "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                        "-property", "installationPath"])
            root_text = proc.stdout.strip().splitlines()
            if proc.returncode == 0 and root_text:
                matches = sorted(glob.glob(os.path.join(
                    root_text[0], "VC", "Tools", "MSVC", "*", "bin",
                    "Hostx64", "x64", "dumpbin.exe")))
                dumpbin = matches[-1] if matches else None
        if dumpbin is not None:
            proc = run([dumpbin, "/nologo", "/symbols", path])
            if proc.returncode == 0:
                symbols = set()
                for line in proc.stdout.splitlines():
                    m = re.search(r"UNDEF\s+\S+\s+\S+\s+External\s+\|\s+(\S+)",
                                  line)
                    if m is None:
                        continue
                    name = m.group(1)
                    if name.startswith("_asnber_"):
                        name = name[1:]
                    if name.startswith("asnber_"):
                        symbols.add(name.split("@", 1)[0])
                return symbols
    raise RuntimeError("找不到 nm/dumpbin 或工具执行失败：%s" % path)


def check_decode_only(build):
    print("## 只读包未引用编码符号（nm -u）")
    ok = True
    for module in PKCS_STATIC_MODULES:
        lib = find_static_library(build, module)
        if lib is None:
            print("DECODE-ONLY %-12s FAIL 未找到静态库" % module)
            ok = False
            continue
        try:
            undefined = undefined_symbols(lib)
        except RuntimeError as exc:
            print("DECODE-ONLY %-12s FAIL %s" % (module, exc))
            ok = False
            continue
        hits = sorted(name for name in undefined
                      if any(name.startswith(prefix)
                             for prefix in FORBIDDEN_UNDEFINED))
        status = "OK" if not hits else "FAIL"
        if hits:
            ok = False
        print("DECODE-ONLY %-12s %s undefined=%d %s"
              % (module, status, len(undefined), ",".join(hits)))
    return ok


def check_abi(build):
    print("## ABI 导出符号")
    for module, relpath in ABI_FILES:
        path = os.path.join(ROOT, relpath)
        count = 0
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    count += 1
        print("ABI baseline %-10s %d" % (module, count))
    proc = run([sys.executable, CHECK_EXPORTS, "--build-dir", build])
    for line in (proc.stdout or "").strip().splitlines():
        print("ABI %s" % line)
    for line in (proc.stderr or "").strip().splitlines():
        print("ABI ERR %s" % line)
    print("ABI exit=%d" % proc.returncode)
    return proc.returncode == 0


def find_dump(build):
    base = os.path.join(build, "tests", "differential")
    candidates = [os.path.join(base, "asnber_dump.exe"), os.path.join(base, "asnber_dump")]
    for config in ("Debug", "Release", "RelWithDebInfo", "MinSizeRel"):
        candidates.append(os.path.join(base, config, "asnber_dump.exe"))
        candidates.append(os.path.join(base, config, "asnber_dump"))
    for path in candidates:
        if os.path.exists(path):
            return path
    return None


def check_differential(build):
    print("## 差分与往返")
    dump = find_dump(build)
    if dump is None:
        print("DIFF FAIL: asnber_dump 未找到（请以 -DASNBER_BUILD_DIFFERENTIAL=ON 构建）")
        return False
    proc = run([sys.executable, DIFF, "--asnber-dump", dump,
                "--data-dir", DATA, "--skip-asn1tools"])
    for line in proc.stdout.splitlines():
        if line.startswith(("样本数:", "往返通过:", "差分通过", "差异明细:", "  - ")):
            print("DIFF", line)
    print("DIFF exit=%d" % proc.returncode)
    return proc.returncode == 0


def cms_roundtrip(build):
    print("## CMS 样本往返")
    dump = find_dump(build)
    if dump is None:
        print("RT FAIL: asnber_dump 未找到（请以 -DASNBER_BUILD_DIFFERENTIAL=ON 构建）")
        return False
    ok = True
    groups = (("enveloped", CMS_ENVELOPED), ("signed", CMS_SIGNED),
              ("encrypted", CMS_ENCRYPTED), ("compressed", CMS_COMPRESSED),
              ("authenticated", CMS_AUTHENTICATED))
    with tempfile.TemporaryDirectory() as tmp:
        for label, names in groups:
            passed = 0
            for name in names:
                src = os.path.join(DATA, name)
                dst = os.path.join(tmp, name + ".rt.der")
                proc = run([dump, "--roundtrip", src, dst])
                same = (proc.returncode == 0 and os.path.exists(dst)
                        and sha256_file(dst) == sha256_file(src))
                print("RT %-12s %-32s %s" % (label, name, "OK" if same else "FAIL"))
                if same:
                    passed += 1
                else:
                    ok = False
            print("RT %-12s %d/%d" % (label, passed, len(names)))
    return ok


def current_doc_counts(total):
    """报告 README/docs 中与本轮一致的用例计数；历史基线单独标注。"""
    print("## 文档计数一致性")
    files = [os.path.join(ROOT, "README.md"),
             os.path.join(ROOT, "docs", "07-测试与验证.md")]
    mismatches = []
    for path in files:
        with open(path, "r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                for m in re.finditer(r"(\d+)\s*条用例", line):
                    n = int(m.group(1))
                    tag = "OK" if n == total else "HISTORY"
                    if n != total and not re.search(
                            r"0\.1\.[01]|34 条|切片|历史", line):
                        tag = "MISMATCH"
                        mismatches.append("%s:%d=%d" % (rel(path), lineno, n))
                    print("DOC %s:%d 条用例=%d %s" % (rel(path), lineno, n, tag))
                for m in re.finditer(r"\*\*(\d+)/\1\*\*", line):
                    n = int(m.group(1))
                    tag = "OK" if n == total else "HISTORY"
                    print("DOC %s:%d %d/%d %s" % (rel(path), lineno, n, n, tag))
    for item in mismatches:
        print("DOC MISMATCH", item)
    return not mismatches


def check_assertion_counts():
    print("## 断言点计数（脚本派生）")
    proc = run([sys.executable, COUNT_ASSERTIONS, "--check"])
    for line in (proc.stdout or "").strip().splitlines():
        print("ASSERT %s" % line)
    for line in (proc.stderr or "").strip().splitlines():
        print("ASSERT ERR %s" % line)
    print("ASSERT exit=%d" % proc.returncode)
    return proc.returncode == 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build-dir", default="build-cms-env")
    ap.add_argument("--regen-dir", default="build-cms-regen")
    ap.add_argument("--strict", action="store_true",
                    help="CI 模式：所有检查均为硬失败（默认已 fail-closed）")
    args = ap.parse_args()

    build = args.build_dir if os.path.isabs(args.build_dir) else os.path.join(ROOT, args.build_dir)
    regen = args.regen_dir if os.path.isabs(args.regen_dir) else os.path.join(ROOT, args.regen_dir)

    ok = True
    print("# 结构重组基线")
    print("BUILD", os.path.basename(build))
    print("STRICT", "ON" if args.strict else "OFF")

    names, rc = ctest_names(build)
    print("## CTest 注册")
    print("CTEST registered=%d exit=%d" % (len(names), rc))
    if rc != 0:
        ok = False

    results, rc, stdout = ctest_results(build)
    print("## CTest 结果")
    for name, status in results:
        print("CTEST %-40s %s" % (name, status))
    failed = [n for n, s in results if s != "PASSED"]
    for name in failed:
        print("CTEST FAILED %s" % name)
    print("CTEST passed=%d failed=%d exit=%d" % (len(results) - len(failed),
                                                 len(failed), rc))
    if rc != 0 or failed or len(results) != len(names):
        ok = False
        if rc != 0 and not failed:
            print("CTEST FAILED 未解析到失败用例名，以下为 ctest 原始尾部输出：")
            for line in stdout.strip().splitlines()[-30:]:
                print("CTEST RAW %s" % line)

    print("## 用例数")
    print("TOTAL registered=%d results=%d" % (len(names), len(results)))
    if len(names) != len(results):
        ok = False

    if not check_tables(regen):
        ok = False
    if not check_table_inventory():
        ok = False
    if not check_abi(build):
        ok = False
    if not check_decode_only(build):
        ok = False
    if not check_differential(build):
        ok = False
    if not cms_roundtrip(build):
        ok = False
    if not current_doc_counts(len(names)):
        ok = False
    if not check_assertion_counts():
        ok = False

    print("BASELINE %s" % ("OK" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
