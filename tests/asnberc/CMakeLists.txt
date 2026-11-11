# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT
# asnberc 端到端测试：构建期用 asnberc 生成描述表，再在 C 用例中加载并校验。

set(ASNBERC_PKIX_SOURCE
    ${asnber_SOURCE_DIR}/modules/pkix/asn1/PKIX-Flattened-2009.asn1)
set(ASNBERC_EQUIV_SOURCE
    ${asnber_SOURCE_DIR}/tests/data/asnberc/equiv_sample.asn1)
set(ASNBERC_GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)

file(MAKE_DIRECTORY ${ASNBERC_GENERATED_DIR})

add_custom_command(
  OUTPUT
    ${ASNBERC_GENERATED_DIR}/pkix_schema.bin
    ${ASNBERC_GENERATED_DIR}/pkix_schema.h
  COMMAND $<TARGET_FILE:asnberc>
    -o ${ASNBERC_GENERATED_DIR}/pkix_schema.bin
    -c ${ASNBERC_GENERATED_DIR}/pkix_schema.h
    --root Certificate
    ${ASNBERC_PKIX_SOURCE}
  DEPENDS asnberc ${ASNBERC_PKIX_SOURCE}
  COMMENT "Generating PKIX descriptor table with asnberc"
  VERBATIM
)
add_custom_target(asnberc_generated_pkix
  DEPENDS
    ${ASNBERC_GENERATED_DIR}/pkix_schema.bin
    ${ASNBERC_GENERATED_DIR}/pkix_schema.h
)

add_custom_command(
  OUTPUT
    ${ASNBERC_GENERATED_DIR}/equiv.bin
    ${ASNBERC_GENERATED_DIR}/equiv.h
  COMMAND $<TARGET_FILE:asnberc>
    -o ${ASNBERC_GENERATED_DIR}/equiv.bin
    -c ${ASNBERC_GENERATED_DIR}/equiv.h
    --root Container
    ${ASNBERC_EQUIV_SOURCE}
  DEPENDS asnberc ${ASNBERC_EQUIV_SOURCE}
  COMMENT "Generating equivalence-sample descriptor table with asnberc"
  VERBATIM
)
add_custom_target(asnberc_generated_equiv
  DEPENDS
    ${ASNBERC_GENERATED_DIR}/equiv.bin
    ${ASNBERC_GENERATED_DIR}/equiv.h
)

asnber_add_test(test_asnberc_pkix test_asnberc_pkix.c)
# asnber_test_schema_compare 以 PUBLIC 依赖带入 asnber_test_schema_probe，
# 再直接链一次会让 probe 在链接行出现两次（ld64 报 duplicate libraries）。
target_link_libraries(
  test_asnberc_pkix
  PRIVATE
    asnber_test_support
    asnber_test_schema_compare
)
target_include_directories(
  test_asnberc_pkix
  PRIVATE
    ${asnber_SOURCE_DIR}/tests/data
)
target_compile_definitions(
  test_asnberc_pkix
  PRIVATE
    ASNBERC_PKIX_BIN="${ASNBERC_GENERATED_DIR}/pkix_schema.bin"
    ASNBERC_EQUIV_BIN="${ASNBERC_GENERATED_DIR}/equiv.bin"
)
add_dependencies(test_asnberc_pkix asnberc_generated_pkix asnberc_generated_equiv)

add_test(
  NAME test_asnberc_cli
  COMMAND ${CMAKE_COMMAND}
    -DASNBERC_EXE=$<TARGET_FILE:asnberc>
    -DSOURCE_DIR=${asnber_SOURCE_DIR}
    -DWORK_DIR=${CMAKE_CURRENT_BINARY_DIR}/cli
    -P ${CMAKE_CURRENT_SOURCE_DIR}/test_asnberc_cli.cmake
)
asnber_apply_sanitizer_test_environment(test_asnberc_cli)

add_custom_command(
  OUTPUT
    ${ASNBERC_GENERATED_DIR}/pkix_trim_schema.bin
    ${ASNBERC_GENERATED_DIR}/pkix_trim_schema.h
  COMMAND $<TARGET_FILE:asnberc>
    -o ${ASNBERC_GENERATED_DIR}/pkix_trim_schema.bin
    -c ${ASNBERC_GENERATED_DIR}/pkix_trim_schema.h
    --trim-schema
    --root Certificate
    ${ASNBERC_PKIX_SOURCE}
  DEPENDS asnberc ${ASNBERC_PKIX_SOURCE}
  COMMENT "Generating trimmed PKIX descriptor table with asnberc"
  VERBATIM
)
add_custom_target(asnberc_generated_pkix_trim
  DEPENDS
    ${ASNBERC_GENERATED_DIR}/pkix_trim_schema.bin
    ${ASNBERC_GENERATED_DIR}/pkix_trim_schema.h
)

asnber_add_test(test_asnberc_trim test_asnberc_trim.c)
target_include_directories(
  test_asnberc_trim
  PRIVATE
    ${ASNBERC_GENERATED_DIR}
    ${asnber_SOURCE_DIR}/tests/data
)
add_dependencies(test_asnberc_trim asnberc_generated_pkix_trim)
