# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT
#
# asnberc CLI 行为测试（CTest 脚本模式）。
# 需要 -DASNBERC_EXE=、-DSOURCE_DIR=、-DWORK_DIR=。

cmake_minimum_required(VERSION 3.20)

if(NOT DEFINED ASNBERC_EXE OR NOT DEFINED SOURCE_DIR OR NOT DEFINED WORK_DIR)
  message(FATAL_ERROR "ASNBERC_EXE / SOURCE_DIR / WORK_DIR must be provided")
endif()
if(NOT EXISTS "${ASNBERC_EXE}")
  message(FATAL_ERROR "asnberc executable not found: ${ASNBERC_EXE}")
endif()

set(PKIX_SOURCE
    "${SOURCE_DIR}/modules/pkix/asn1/PKIX-Flattened-2009.asn1")
set(NEGATIVE_DIR "${SOURCE_DIR}/tests/data/asnberc/negative")

file(MAKE_DIRECTORY "${WORK_DIR}")

# ---- 1. 两次运行的输出必须逐字节一致 -------------------------------------
execute_process(
  COMMAND "${ASNBERC_EXE}" -o "${WORK_DIR}/det_a.bin" -c "${WORK_DIR}/det_a.h"
          --root Certificate "${PKIX_SOURCE}"
  RESULT_VARIABLE rc_a
  OUTPUT_VARIABLE out_a
  ERROR_VARIABLE err_a
)
if(NOT rc_a EQUAL 0)
  message(FATAL_ERROR "first run failed (${rc_a}): ${out_a}${err_a}")
endif()

execute_process(
  COMMAND "${ASNBERC_EXE}" -o "${WORK_DIR}/det_b.bin" -c "${WORK_DIR}/det_b.h"
          --root Certificate "${PKIX_SOURCE}"
  RESULT_VARIABLE rc_b
  OUTPUT_VARIABLE out_b
  ERROR_VARIABLE err_b
)
if(NOT rc_b EQUAL 0)
  message(FATAL_ERROR "second run failed (${rc_b}): ${out_b}${err_b}")
endif()

file(SHA256 "${WORK_DIR}/det_a.bin" hash_a)
file(SHA256 "${WORK_DIR}/det_b.bin" hash_b)
if(NOT hash_a STREQUAL hash_b)
  message(FATAL_ERROR "asnberc output is not deterministic: ${hash_a} != ${hash_b}")
endif()

# ---- 2. C 头中的字节序列必须与 .bin 完全一致 -----------------------------
file(READ "${WORK_DIR}/det_a.h" header_text)
string(REGEX MATCHALL "0x[0-9A-Fa-f][0-9A-Fa-f]" header_tokens
       "${header_text}")
string(REPLACE "0x" "" header_hex "${header_tokens}")
string(REPLACE ";" "" header_hex "${header_hex}")
string(TOLOWER "${header_hex}" header_hex)

file(READ "${WORK_DIR}/det_a.bin" bin_hex HEX)
string(TOLOWER "${bin_hex}" bin_hex)

if(header_hex STREQUAL "")
  message(FATAL_ERROR "generated C header contains no byte sequence")
endif()
string(LENGTH "${header_hex}" header_len)
string(LENGTH "${bin_hex}" bin_len)
if(NOT header_len EQUAL bin_len)
  message(FATAL_ERROR
          "header byte count (${header_len}) != binary size (${bin_len})")
endif()
if(NOT header_hex STREQUAL bin_hex)
  message(FATAL_ERROR "generated C header bytes differ from .bin content")
endif()

# ---- 3. 负例：退出码 1 + 诊断格式 ----------------------------------------
# 每项：样本文件名|符号错误码|文档中的数字错误码
set(NEGATIVE_CASES
    "unsupported_class.asn1|ASNBERC_E_UNSUPPORTED_CONSTRUCT|9006"
    "any_defined_by.asn1|ASNBERC_E_UNSUPPORTED_CONSTRUCT|9006"
    "missing_end.asn1|ASNBERC_E_SYNTAX|9001"
    "undefined_type.asn1|ASNBERC_E_UNDEFINED_TYPE|9002"
    "duplicate_type.asn1|ASNBERC_E_DUPLICATE_TYPE|9003"
    "invalid_default.asn1|ASNBERC_E_CONSTRAINT_INVALID|9009"
    "duplicate_named_value.asn1|ASNBERC_E_DUPLICATE_FIELD|9004"
    "duplicate_named_bit.asn1|ASNBERC_E_DUPLICATE_FIELD|9004"
    "bit_out_of_range.asn1|ASNBERC_E_CONSTRAINT_INVALID|9009"
    "default_undefined_ref.asn1|ASNBERC_E_CONSTRAINT_INVALID|9009"
)

foreach(case IN LISTS NEGATIVE_CASES)
  string(REPLACE "|" ";" parts "${case}")
  list(GET parts 0 sample)
  list(GET parts 1 code_name)
  list(GET parts 2 code_number)
  set(sample_path "${NEGATIVE_DIR}/${sample}")

  execute_process(
    COMMAND "${ASNBERC_EXE}" -o "${WORK_DIR}/neg_${sample}.bin"
            "${sample_path}"
    RESULT_VARIABLE rc
    OUTPUT_VARIABLE out
    ERROR_VARIABLE err
  )
  if(NOT rc EQUAL 1)
    message(FATAL_ERROR
            "${sample}: expected exit code 1, got ${rc}\n${out}${err}")
  endif()

  set(combined "${out}${err}")
  string(FIND "${combined}" "${code_name}" found_pos)
  if(found_pos EQUAL -1)
    message(FATAL_ERROR
            "${sample}: missing ${code_name} (${code_number}) in diagnostics:\n${combined}")
  endif()

  # 诊断行必须形如 <file>:<line>:<col>: error: <code>: <msg>
  string(REGEX MATCH "[^ :]+:([0-9]+):([0-9]+): error: ${code_name}: "
         location "${combined}")
  if(location STREQUAL "")
    message(FATAL_ERROR
            "${sample}: diagnostic line is not in '<file>:<line>:<col>: error: <code>: <msg>' form:\n${combined}")
  endif()
  # 位置必须指向源码（行号 >= 1），不能退化成未知位置 0:0
  set(diag_line "${CMAKE_MATCH_1}")
  set(diag_column "${CMAKE_MATCH_2}")
  if(diag_line LESS 1 OR diag_column LESS 1)
    message(FATAL_ERROR
            "${sample}: diagnostic position must be >= 1:1, got ${diag_line}:${diag_column}")
  endif()
endforeach()

# ---- 4. 多模块 IMPORTS：合并表 / 人工展平 / 发现顺序 ---------------------
set(MM_DIR "${SOURCE_DIR}/tests/data/asnberc/multimodule")
set(MM_INPUTS
    "${MM_DIR}/Base-2026.asn1"
    "${MM_DIR}/Mid-2026.asn1"
    "${MM_DIR}/Leaf-2026.asn1")

execute_process(
  COMMAND "${ASNBERC_EXE}" -o "${WORK_DIR}/mm_all.bin"
          -c "${WORK_DIR}/mm_all.h" --root LeafDocument ${MM_INPUTS}
  RESULT_VARIABLE mm_rc
  OUTPUT_VARIABLE mm_out
  ERROR_VARIABLE mm_err
)
if(NOT mm_rc EQUAL 0)
  message(FATAL_ERROR "multi-module run failed (${mm_rc}): ${mm_out}${mm_err}")
endif()

execute_process(
  COMMAND "${ASNBERC_EXE}" -o "${WORK_DIR}/mm_flat.bin"
          --root LeafDocument "${MM_DIR}/flattened.asn1"
  RESULT_VARIABLE flat_rc
  OUTPUT_VARIABLE flat_out
  ERROR_VARIABLE flat_err
)
if(NOT flat_rc EQUAL 0)
  message(FATAL_ERROR "flattened run failed (${flat_rc}): ${flat_out}${flat_err}")
endif()

file(SHA256 "${WORK_DIR}/mm_all.bin" mm_hash)
file(SHA256 "${WORK_DIR}/mm_flat.bin" flat_hash)
if(NOT mm_hash STREQUAL flat_hash)
  message(FATAL_ERROR
          "merged table differs from hand-flattened equivalent: ${mm_hash} != ${flat_hash}")
endif()

# 检入的 golden 必须能由 asnberc 每次复现：差异说明合并规则或输出发生漂移。
file(SHA256 "${MM_DIR}/golden.bin" golden_hash)
if(NOT mm_hash STREQUAL golden_hash)
  message(FATAL_ERROR
          "merged table differs from checked-in golden: ${mm_hash} != ${golden_hash}")
endif()

# `-I` 按需发现：只给 Leaf 时，发现顺序必须等价于显式给出 Base、Mid。
execute_process(
  COMMAND "${ASNBERC_EXE}" -o "${WORK_DIR}/mm_disc.bin" --root LeafDocument
          -I "${MM_DIR}" "${MM_DIR}/Leaf-2026.asn1"
  RESULT_VARIABLE disc_rc
  OUTPUT_VARIABLE disc_out
  ERROR_VARIABLE disc_err
)
if(NOT disc_rc EQUAL 0)
  message(FATAL_ERROR "module discovery run failed (${disc_rc}): ${disc_out}${disc_err}")
endif()

execute_process(
  COMMAND "${ASNBERC_EXE}" -o "${WORK_DIR}/mm_expl.bin" --root LeafDocument
          "${MM_DIR}/Leaf-2026.asn1" "${MM_DIR}/Base-2026.asn1"
          "${MM_DIR}/Mid-2026.asn1"
  RESULT_VARIABLE expl_rc
  OUTPUT_VARIABLE expl_out
  ERROR_VARIABLE expl_err
)
if(NOT expl_rc EQUAL 0)
  message(FATAL_ERROR "explicit-order run failed (${expl_rc}): ${expl_out}${expl_err}")
endif()

file(SHA256 "${WORK_DIR}/mm_disc.bin" disc_hash)
file(SHA256 "${WORK_DIR}/mm_expl.bin" expl_hash)
if(NOT disc_hash STREQUAL expl_hash)
  message(FATAL_ERROR
          "discovery order is not deterministic: ${disc_hash} != ${expl_hash}")
endif()

# 限定根形式可用。
execute_process(
  COMMAND "${ASNBERC_EXE}" -o "${WORK_DIR}/mm_qualified.bin"
          --root "Base-2026.BaseRecord" ${MM_INPUTS}
  RESULT_VARIABLE qual_rc
  OUTPUT_VARIABLE qual_out
  ERROR_VARIABLE qual_err
)
if(NOT qual_rc EQUAL 0)
  message(FATAL_ERROR
          "qualified --root failed (${qual_rc}): ${qual_out}${qual_err}")
endif()

# 未限定但跨模块同名的根必须报歧义，不能静默挑一个。
execute_process(
  COMMAND "${ASNBERC_EXE}" -o "${WORK_DIR}/mm_ambiguous.bin" --root BaseRecord
          ${MM_INPUTS}
  RESULT_VARIABLE amb_rc
  OUTPUT_VARIABLE amb_out
  ERROR_VARIABLE amb_err
)
if(NOT amb_rc EQUAL 1)
  message(FATAL_ERROR
          "ambiguous --root: expected exit code 1, got ${amb_rc}\n${amb_out}${amb_err}")
endif()
string(FIND "${amb_out}${amb_err}" "ambiguous" amb_pos)
if(amb_pos EQUAL -1)
  message(FATAL_ERROR
          "ambiguous --root: message does not explain the ambiguity:\n${amb_out}${amb_err}")
endif()

# ---- 5. 多模块 IMPORTS 负例 ----------------------------------------------
# 每项：样本|符号错误码|数字错误码|附加输入（相对 negative 目录，可空）
set(MULTIMODULE_NEGATIVE_CASES
    "missing_module.asn1|ASNBERC_E_UNDEFINED_TYPE|9002|"
    "missing_symbol.asn1|ASNBERC_E_UNDEFINED_TYPE|9002|"
    "not_exported.asn1|ASNBERC_E_UNDEFINED_TYPE|9002|"
    "import_conflict.asn1|ASNBERC_E_DUPLICATE_TYPE|9003|"
    "import_duplicate.asn1|ASNBERC_E_DUPLICATE_TYPE|9003|"
    "cycle_a.asn1|ASNBERC_E_UNDEFINED_TYPE|9002|"
    "imports_syntax.asn1|ASNBERC_E_SYNTAX|9001|"
    "duplicate_module.asn1|ASNBERC_E_DUPLICATE_TYPE|9003|NegBase-2026.asn1"
)

foreach(case IN LISTS MULTIMODULE_NEGATIVE_CASES)
  string(REPLACE "|" ";" parts "${case}")
  list(GET parts 0 sample)
  list(GET parts 1 code_name)
  list(GET parts 2 code_number)
  list(GET parts 3 extra)
  set(extra_args "")
  if(NOT extra STREQUAL "")
    list(APPEND extra_args "${NEGATIVE_DIR}/${extra}")
  endif()

  execute_process(
    COMMAND "${ASNBERC_EXE}" -o "${WORK_DIR}/mmneg_${sample}.bin"
            "${NEGATIVE_DIR}/${sample}" ${extra_args}
    RESULT_VARIABLE rc
    OUTPUT_VARIABLE out
    ERROR_VARIABLE err
  )
  if(NOT rc EQUAL 1)
    message(FATAL_ERROR
            "${sample}: expected exit code 1, got ${rc}\n${out}${err}")
  endif()

  set(combined "${out}${err}")
  string(FIND "${combined}" "${code_name}" found_pos)
  if(found_pos EQUAL -1)
    message(FATAL_ERROR
            "${sample}: missing ${code_name} (${code_number}) in diagnostics:\n${combined}")
  endif()
  # 9007 已从契约中移除，任何路径都不应再出现。
  string(FIND "${combined}" "9007" legacy_pos)
  if(NOT legacy_pos EQUAL -1)
    message(FATAL_ERROR
            "${sample}: removed diagnostic 9007 must not appear:\n${combined}")
  endif()

  string(REGEX MATCH "[^ :]+:([0-9]+):([0-9]+): error: ${code_name}: "
         location "${combined}")
  if(location STREQUAL "")
    message(FATAL_ERROR
            "${sample}: diagnostic line is not in '<file>:<line>:<col>: error: <code>: <msg>' form:\n${combined}")
  endif()
  set(diag_line "${CMAKE_MATCH_1}")
  set(diag_column "${CMAKE_MATCH_2}")
  if(diag_line LESS 1 OR diag_column LESS 1)
    message(FATAL_ERROR
            "${sample}: diagnostic position must be >= 1:1, got ${diag_line}:${diag_column}")
  endif()
endforeach()

# ---- 6. 版本、参数与缺失输入的退出码 -------------------------------------
execute_process(
  COMMAND "${ASNBERC_EXE}" --version
  RESULT_VARIABLE version_rc
  OUTPUT_VARIABLE version_out
  ERROR_VARIABLE version_err
)
if(NOT version_rc EQUAL 0)
  message(FATAL_ERROR "--version failed (${version_rc}): ${version_err}")
endif()
string(REGEX MATCH "^asnberc " version_prefix "${version_out}")
if(version_prefix STREQUAL "")
  message(FATAL_ERROR "--version output must start with 'asnberc ': ${version_out}")
endif()

execute_process(
  COMMAND "${ASNBERC_EXE}"
  RESULT_VARIABLE noarg_rc
  OUTPUT_VARIABLE noarg_out
  ERROR_VARIABLE noarg_err
)
if(NOT noarg_rc EQUAL 2)
  message(FATAL_ERROR
          "no-argument invocation: expected exit code 2, got ${noarg_rc}\n${noarg_out}${noarg_err}")
endif()

execute_process(
  COMMAND "${ASNBERC_EXE}" -o "${WORK_DIR}/missing.bin"
          "${WORK_DIR}/does_not_exist.asn1"
  RESULT_VARIABLE missing_rc
  OUTPUT_VARIABLE missing_out
  ERROR_VARIABLE missing_err
)
if(NOT missing_rc EQUAL 3)
  message(FATAL_ERROR
          "missing input: expected exit code 3, got ${missing_rc}\n${missing_out}${missing_err}")
endif()

# ---- 6. 参数化展开：实例化输出与人工展平逐字节一致 ------------------------
set(PARAM_DIR "${SOURCE_DIR}/tests/data/asnberc/parameterized")

execute_process(
  COMMAND "${ASNBERC_EXE}" -o "${WORK_DIR}/param.bin"
          --root MyKey "${PARAM_DIR}/parameterized.asn1"
  RESULT_VARIABLE param_rc
  OUTPUT_VARIABLE param_out
  ERROR_VARIABLE param_err
)
if(NOT param_rc EQUAL 0)
  message(FATAL_ERROR "parameterized run failed (${param_rc}): ${param_out}${param_err}")
endif()

file(SHA256 "${WORK_DIR}/param.bin" param_hash)
file(SHA256 "${PARAM_DIR}/golden.bin" param_golden_hash)
if(NOT param_hash STREQUAL param_golden_hash)
  message(FATAL_ERROR
          "parameterized output differs from golden: ${param_hash} != ${param_golden_hash}")
endif()

# 同一实例化多次出现只生成一个合成类型；确定性。
execute_process(
  COMMAND "${ASNBERC_EXE}" -o "${WORK_DIR}/param2.bin"
          --root MyKey "${PARAM_DIR}/parameterized.asn1"
  RESULT_VARIABLE param2_rc
  OUTPUT_VARIABLE param2_out
  ERROR_VARIABLE param2_err
)
if(NOT param2_rc EQUAL 0)
  message(FATAL_ERROR "parameterized second run failed (${param2_rc}): ${param2_out}${param2_err}")
endif()
file(SHA256 "${WORK_DIR}/param2.bin" param2_hash)
if(NOT param_hash STREQUAL param2_hash)
  message(FATAL_ERROR "parameterized output is not deterministic")
endif()

# ---- 7. 参数化负例 -------------------------------------------------------
set(PARAM_NEGATIVE_CASES
    "param_arg_count.asn1|ASNBERC_E_PARAM_INSTANTIATION|9008"
    "param_not_template.asn1|ASNBERC_E_PARAM_INSTANTIATION|9008"
    "param_no_instance.asn1|ASNBERC_E_PARAM_INSTANTIATION|9008"
    "constraint_undefined_value.asn1|ASNBERC_E_UNDEFINED_TYPE|9002"
)

foreach(case IN LISTS PARAM_NEGATIVE_CASES)
  string(REPLACE "|" ";" parts "${case}")
  list(GET parts 0 sample)
  list(GET parts 1 code_name)
  list(GET parts 2 code_number)

  execute_process(
    COMMAND "${ASNBERC_EXE}" -o "${WORK_DIR}/pneg_${sample}.bin"
            "${NEGATIVE_DIR}/${sample}"
    RESULT_VARIABLE rc
    OUTPUT_VARIABLE out
    ERROR_VARIABLE err
  )
  if(NOT rc EQUAL 1)
    message(FATAL_ERROR
            "${sample}: expected exit code 1, got ${rc}\n${out}${err}")
  endif()

  set(combined "${out}${err}")
  string(FIND "${combined}" "${code_name}" found_pos)
  if(found_pos EQUAL -1)
    message(FATAL_ERROR
            "${sample}: missing ${code_name} (${code_number}) in diagnostics:\n${combined}")
  endif()
endforeach()

# ---- 8. 约束值引用正例 ---------------------------------------------------
execute_process(
  COMMAND "${ASNBERC_EXE}" -o "${WORK_DIR}/vr.bin" --root LimitedString
          "${SOURCE_DIR}/tests/data/asnberc/constraint_value_ref.asn1"
  RESULT_VARIABLE vr_rc
  OUTPUT_VARIABLE vr_out
  ERROR_VARIABLE vr_err
)
if(NOT vr_rc EQUAL 0)
  message(FATAL_ERROR
          "constraint value ref positive failed (${vr_rc}): ${vr_out}${vr_err}")
endif()

# ---- 9. DEFAULT 编码：OBJECT IDENTIFIER 按 base-128 写入 TLV --------------
set(DEFAULT_OID_SOURCE "${SOURCE_DIR}/tests/data/asnberc/default_oid.asn1")

execute_process(
  COMMAND "${ASNBERC_EXE}" -o "${WORK_DIR}/default_oid.bin"
          --root Algorithm "${DEFAULT_OID_SOURCE}"
  RESULT_VARIABLE oid_rc
  OUTPUT_VARIABLE oid_out
  ERROR_VARIABLE oid_err
)
if(NOT oid_rc EQUAL 0)
  message(FATAL_ERROR
          "default OID run failed (${oid_rc}): ${oid_out}${oid_err}")
endif()

file(READ "${WORK_DIR}/default_oid.bin" oid_hex HEX)
string(TOUPPER "${oid_hex}" oid_hex)
string(FIND "${oid_hex}" "06092A864886F70D010101" oid_pos)
if(oid_pos EQUAL -1)
  message(FATAL_ERROR
          "default OID TLV 06 09 2A 86 48 86 F7 0D 01 01 01 not found in table")
endif()

# ---- 10. CLI 参数形式与错误分支 ------------------------------------------
# 帮助：-h 与 --help 均以退出码 0 打印用法。
foreach(help_flag "-h" "--help")
  execute_process(
    COMMAND "${ASNBERC_EXE}" "${help_flag}"
    RESULT_VARIABLE help_rc
    OUTPUT_VARIABLE help_out
    ERROR_VARIABLE help_err
  )
  if(NOT help_rc EQUAL 0)
    message(FATAL_ERROR
            "${help_flag}: expected exit code 0, got ${help_rc}\n${help_out}${help_err}")
  endif()
  string(FIND "${help_out}" "Usage: asnberc" help_pos)
  if(help_pos EQUAL -1)
    message(FATAL_ERROR "${help_flag}: usage text missing from stdout:\n${help_out}")
  endif()
endforeach()

# `=` 形式的长选项必须等价于分离写法。
execute_process(
  COMMAND "${ASNBERC_EXE}"
          "--output-bin=${WORK_DIR}/eq.bin"
          "--output-c=${WORK_DIR}/eq.h"
          "--root=Algorithm"
          "--diagnostics=minimal"
          "--include=${SOURCE_DIR}/tests/data/asnberc"
          "${DEFAULT_OID_SOURCE}"
  RESULT_VARIABLE eq_rc
  OUTPUT_VARIABLE eq_out
  ERROR_VARIABLE eq_err
)
if(NOT eq_rc EQUAL 0)
  message(FATAL_ERROR
          "'='-form options failed (${eq_rc}): ${eq_out}${eq_err}")
endif()
if(NOT EXISTS "${WORK_DIR}/eq.bin" OR NOT EXISTS "${WORK_DIR}/eq.h")
  message(FATAL_ERROR "'='-form options did not produce both outputs")
endif()

# 只给 -c 也必须成功（不依赖 -o）。
execute_process(
  COMMAND "${ASNBERC_EXE}" -c "${WORK_DIR}/only_c.h"
          --root Algorithm "${DEFAULT_OID_SOURCE}"
  RESULT_VARIABLE onlyc_rc
  OUTPUT_VARIABLE onlyc_out
  ERROR_VARIABLE onlyc_err
)
if(NOT onlyc_rc EQUAL 0)
  message(FATAL_ERROR
          "-c only run failed (${onlyc_rc}): ${onlyc_out}${onlyc_err}")
endif()

# 用法错误统一退出码 2。
set(USAGE_CASES
    "-o"
    "-c"
    "--root"
    "--diagnostics"
    "-I"
    "--bogus"
    "--diagnostics=bogus"
    "--diagnostics"
)
foreach(case IN LISTS USAGE_CASES)
  execute_process(
    COMMAND "${ASNBERC_EXE}" "${case}"
    RESULT_VARIABLE usage_rc
    OUTPUT_VARIABLE usage_out
    ERROR_VARIABLE usage_err
  )
  if(NOT usage_rc EQUAL 2)
    message(FATAL_ERROR
            "'${case}': expected exit code 2, got ${usage_rc}\n${usage_out}${usage_err}")
  endif()
endforeach()

execute_process(
  COMMAND "${ASNBERC_EXE}" -o "${WORK_DIR}/conflict.bin"
          --diagnostics minimal --diagnostics normal "${DEFAULT_OID_SOURCE}"
  RESULT_VARIABLE conflict_rc
  OUTPUT_VARIABLE conflict_out
  ERROR_VARIABLE conflict_err
)
if(NOT conflict_rc EQUAL 2)
  message(FATAL_ERROR
          "conflicting --diagnostics: expected exit code 2, got ${conflict_rc}\n${conflict_out}${conflict_err}")
endif()

# 有输入但没有输出选项同样属于用法错误。
execute_process(
  COMMAND "${ASNBERC_EXE}" "${DEFAULT_OID_SOURCE}"
  RESULT_VARIABLE noout_rc
  OUTPUT_VARIABLE noout_out
  ERROR_VARIABLE noout_err
)
if(NOT noout_rc EQUAL 2)
  message(FATAL_ERROR
          "missing output option: expected exit code 2, got ${noout_rc}\n${noout_out}${noout_err}")
endif()

# verbose 成功路径打印类型统计。
execute_process(
  COMMAND "${ASNBERC_EXE}" -o "${WORK_DIR}/verbose.bin"
          --diagnostics verbose --root Algorithm "${DEFAULT_OID_SOURCE}"
  RESULT_VARIABLE verbose_rc
  OUTPUT_VARIABLE verbose_out
  ERROR_VARIABLE verbose_err
)
if(NOT verbose_rc EQUAL 0)
  message(FATAL_ERROR
          "verbose run failed (${verbose_rc}): ${verbose_out}${verbose_err}")
endif()
string(FIND "${verbose_err}" "types (" verbose_pos)
if(verbose_pos EQUAL -1)
  message(FATAL_ERROR "verbose run did not report type counts:\n${verbose_err}")
endif()

# 输出写入失败（目录不存在）以退出码 3 报出。
execute_process(
  COMMAND "${ASNBERC_EXE}" -o "${WORK_DIR}/no_such_dir/out.bin"
          --root Algorithm "${DEFAULT_OID_SOURCE}"
  RESULT_VARIABLE io_rc
  OUTPUT_VARIABLE io_out
  ERROR_VARIABLE io_err
)
if(NOT io_rc EQUAL 3)
  message(FATAL_ERROR
          "output write failure: expected exit code 3, got ${io_rc}\n${io_out}${io_err}")
endif()

# ---- 11. --trim-schema：闭包裁剪、确定性、退出码 -------------------------
set(TRIM_SOURCE "${SOURCE_DIR}/tests/data/asnberc/trim/trim_sample.asn1")

execute_process(
  COMMAND "${ASNBERC_EXE}" --trim-schema --root RootDocument
          -o "${WORK_DIR}/trim_a.bin" -c "${WORK_DIR}/trim_a.h"
          "${TRIM_SOURCE}"
  RESULT_VARIABLE trim_rc
  OUTPUT_VARIABLE trim_out
  ERROR_VARIABLE trim_err
)
if(NOT trim_rc EQUAL 0)
  message(FATAL_ERROR "trim run failed (${trim_rc}): ${trim_out}${trim_err}")
endif()

execute_process(
  COMMAND "${ASNBERC_EXE}" --trim-schema --root RootDocument
          -o "${WORK_DIR}/trim_b.bin" "${TRIM_SOURCE}"
  RESULT_VARIABLE trim_b_rc
  OUTPUT_VARIABLE trim_b_out
  ERROR_VARIABLE trim_b_err
)
if(NOT trim_b_rc EQUAL 0)
  message(FATAL_ERROR
          "trim repeat run failed (${trim_b_rc}): ${trim_b_out}${trim_b_err}")
endif()
file(SHA256 "${WORK_DIR}/trim_a.bin" trim_a_hash)
file(SHA256 "${WORK_DIR}/trim_b.bin" trim_b_hash)
if(NOT trim_a_hash STREQUAL trim_b_hash)
  message(FATAL_ERROR "trim output is not deterministic")
endif()

execute_process(
  COMMAND "${ASNBERC_EXE}" --root RootDocument
          -o "${WORK_DIR}/full.bin" "${TRIM_SOURCE}"
  RESULT_VARIABLE full_rc
  OUTPUT_VARIABLE full_out
  ERROR_VARIABLE full_err
)
if(NOT full_rc EQUAL 0)
  message(FATAL_ERROR "full run failed (${full_rc}): ${full_out}${full_err}")
endif()

file(READ "${WORK_DIR}/trim_a.bin" trim_hex HEX)
file(READ "${WORK_DIR}/full.bin" full_hex HEX)
string(TOUPPER "${trim_hex}" trim_hex)
string(TOUPPER "${full_hex}" full_hex)
# "UnusedRecord"
string(FIND "${trim_hex}" "556E757365645265636F7264" trim_unused_pos)
string(FIND "${full_hex}" "556E757365645265636F7264" full_unused_pos)
if(NOT trim_unused_pos EQUAL -1)
  message(FATAL_ERROR "trimmed table still contains UnusedRecord")
endif()
if(full_unused_pos EQUAL -1)
  message(FATAL_ERROR "full table does not contain UnusedRecord")
endif()

# --trim-schema 缺少 --root：用法错误 2。
execute_process(
  COMMAND "${ASNBERC_EXE}" --trim-schema -o "${WORK_DIR}/trim_noroot.bin"
          "${TRIM_SOURCE}"
  RESULT_VARIABLE trim_noroot_rc
  OUTPUT_VARIABLE trim_noroot_out
  ERROR_VARIABLE trim_noroot_err
)
if(NOT trim_noroot_rc EQUAL 2)
  message(FATAL_ERROR
          "--trim-schema without --root: expected 2, got ${trim_noroot_rc}")
endif()

# 根不存在：9002 + 退出码 1。
execute_process(
  COMMAND "${ASNBERC_EXE}" --trim-schema --root Missing
          -o "${WORK_DIR}/trim_missing.bin" "${TRIM_SOURCE}"
  RESULT_VARIABLE trim_missing_rc
  OUTPUT_VARIABLE trim_missing_out
  ERROR_VARIABLE trim_missing_err
)
if(NOT trim_missing_rc EQUAL 1)
  message(FATAL_ERROR
          "trim missing root: expected 1, got ${trim_missing_rc}")
endif()
string(FIND "${trim_missing_out}${trim_missing_err}"
       "ASNBERC_E_UNDEFINED_TYPE" trim_missing_code)
if(trim_missing_code EQUAL -1)
  message(FATAL_ERROR
          "trim missing root: ASNBERC_E_UNDEFINED_TYPE (9002) missing")
endif()

# 跨模块同名根：歧义 9003 + 退出码 1。
execute_process(
  COMMAND "${ASNBERC_EXE}" --trim-schema --root BaseRecord
          -o "${WORK_DIR}/trim_ambiguous.bin" ${MM_INPUTS}
  RESULT_VARIABLE trim_amb_rc
  OUTPUT_VARIABLE trim_amb_out
  ERROR_VARIABLE trim_amb_err
)
if(NOT trim_amb_rc EQUAL 1)
  message(FATAL_ERROR
          "trim ambiguous root: expected 1, got ${trim_amb_rc}")
endif()
string(FIND "${trim_amb_out}${trim_amb_err}" "ambiguous" trim_amb_text)
if(trim_amb_text EQUAL -1)
  message(FATAL_ERROR "trim ambiguous root: message does not explain ambiguity")
endif()

message(STATUS "asnberc CLI behaviour verified")
