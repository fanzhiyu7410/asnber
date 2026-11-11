# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT

# asnber-pkix：X.509/PKIX 标准结构模块。
# 独立包与版本；只依赖核心公共 ABI，核心不反向引用本模块。
cmake_minimum_required(VERSION 3.20)

project(
  asnber-pkix
  VERSION 0.1.0
  DESCRIPTION "X.509/PKIX 标准结构模块（RFC 5912）"
  LANGUAGES C CXX
)

# capability: decode+encode（builder 可裁切）
set(ASNBER_PKIX_SOURCES
  src/asnber_pkix_certificate.cpp
  src/asnber_pkix_crl.cpp
  src/asnber_pkix_version.cpp
)
if(ASNBER_PKIX_ENABLE_BUILDER)
  list(APPEND ASNBER_PKIX_SOURCES
    src/pkix_builder.cpp
    src/pkix_builder_extensions.cpp
    src/pkix_crl_builder.cpp
  )
endif()
set(ASNBER_PKIX_TARGETS "")

# 描述表产物：检入 modules/pkix/generated/，未安装、不进入公共头。
set(ASNBER_PKIX_FULL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/generated")
set(ASNBER_PKIX_FULL_BIN "${ASNBER_PKIX_FULL_DIR}/pkix_schema.bin")
set(ASNBER_PKIX_FULL_HEADER "${ASNBER_PKIX_FULL_DIR}/pkix_schema.h")
set(ASNBER_PKIX_CERT_DIR "${ASNBER_PKIX_FULL_DIR}/certificate")
set(ASNBER_PKIX_CERT_BIN "${ASNBER_PKIX_CERT_DIR}/pkix_schema.bin")
set(ASNBER_PKIX_CERT_HEADER "${ASNBER_PKIX_CERT_DIR}/pkix_schema.h")
set(ASNBER_PKIX_ASN1 "${CMAKE_CURRENT_SOURCE_DIR}/asn1/PKIX-Flattened-2009.asn1")

if(ASNBER_PKIX_SCHEMA_VARIANT STREQUAL "certificate")
  set(ASNBER_PKIX_CHECKED_IN_DIR "${ASNBER_PKIX_CERT_DIR}")
  set(ASNBER_PKIX_CHECKED_IN_BIN "${ASNBER_PKIX_CERT_BIN}")
  set(ASNBER_PKIX_CHECKED_IN_HEADER "${ASNBER_PKIX_CERT_HEADER}")
else()
  set(ASNBER_PKIX_CHECKED_IN_DIR "${ASNBER_PKIX_FULL_DIR}")
  set(ASNBER_PKIX_CHECKED_IN_BIN "${ASNBER_PKIX_FULL_BIN}")
  set(ASNBER_PKIX_CHECKED_IN_HEADER "${ASNBER_PKIX_FULL_HEADER}")
endif()

if(ASNBER_PKIX_REGENERATE_TABLE)
  if(NOT TARGET asnberc)
    message(
      FATAL_ERROR
      "ASNBER_PKIX_REGENERATE_TABLE=ON 需要同时启用 ASNBER_BUILD_TOOLS=ON 以提供 asnberc"
    )
  endif()
  set(regenerated_full_dir "${CMAKE_CURRENT_BINARY_DIR}/generated/table/full")
  set(regenerated_cert_dir
      "${CMAKE_CURRENT_BINARY_DIR}/generated/table/certificate")
  file(MAKE_DIRECTORY "${regenerated_full_dir}" "${regenerated_cert_dir}")
  set(regenerated_full_bin "${regenerated_full_dir}/pkix_schema.bin")
  set(regenerated_full_header "${regenerated_full_dir}/pkix_schema.h")
  set(regenerated_cert_bin "${regenerated_cert_dir}/pkix_schema.bin")
  set(regenerated_cert_header "${regenerated_cert_dir}/pkix_schema.h")

  add_custom_command(
    OUTPUT "${regenerated_full_bin}" "${regenerated_full_header}"
    COMMAND
      $<TARGET_FILE:asnberc> -o "${regenerated_full_bin}"
      -c "${regenerated_full_header}" --root Certificate "${ASNBER_PKIX_ASN1}"
    DEPENDS asnberc "${ASNBER_PKIX_ASN1}"
    COMMENT "用 asnberc 重新生成 asnber-pkix 全量描述表"
    VERBATIM
  )
  add_custom_target(asnber_pkix_table_generate_full
    DEPENDS "${regenerated_full_bin}" "${regenerated_full_header}"
  )

  add_custom_command(
    OUTPUT "${regenerated_cert_bin}" "${regenerated_cert_header}"
    COMMAND
      $<TARGET_FILE:asnberc> -o "${regenerated_cert_bin}"
      -c "${regenerated_cert_header}" --trim-schema --root Certificate
      "${ASNBER_PKIX_ASN1}"
    DEPENDS asnberc "${ASNBER_PKIX_ASN1}"
    COMMENT "用 asnberc --trim-schema 重新生成 asnber-pkix 证书描述表"
    VERBATIM
  )
  add_custom_target(asnber_pkix_table_generate_certificate
    DEPENDS "${regenerated_cert_bin}" "${regenerated_cert_header}"
  )

  add_custom_target(asnber_pkix_table_verify
    COMMAND
      ${CMAKE_COMMAND} -E compare_files "${regenerated_full_bin}"
      "${ASNBER_PKIX_FULL_BIN}"
    COMMAND
      ${CMAKE_COMMAND} -E compare_files "${regenerated_full_header}"
      "${ASNBER_PKIX_FULL_HEADER}"
    DEPENDS asnber_pkix_table_generate_full "${ASNBER_PKIX_FULL_BIN}"
            "${ASNBER_PKIX_FULL_HEADER}"
    COMMENT "校验全量描述表与检入产物逐字节一致"
    VERBATIM
  )
  add_custom_target(asnber_pkix_table_verify_certificate
    COMMAND
      ${CMAKE_COMMAND} -E compare_files "${regenerated_cert_bin}"
      "${ASNBER_PKIX_CERT_BIN}"
    COMMAND
      ${CMAKE_COMMAND} -E compare_files "${regenerated_cert_header}"
      "${ASNBER_PKIX_CERT_HEADER}"
    DEPENDS asnber_pkix_table_generate_certificate "${ASNBER_PKIX_CERT_BIN}"
            "${ASNBER_PKIX_CERT_HEADER}"
    COMMENT "校验证书描述表与检入产物逐字节一致"
    VERBATIM
  )

  if(ASNBER_PKIX_SCHEMA_VARIANT STREQUAL "certificate")
    set(pkix_table_include_dir "${regenerated_cert_dir}")
    set(pkix_table_header "${regenerated_cert_header}")
  else()
    set(pkix_table_include_dir "${regenerated_full_dir}")
    set(pkix_table_header "${regenerated_full_header}")
  endif()
else()
  if(NOT EXISTS "${ASNBER_PKIX_CHECKED_IN_BIN}" OR
     NOT EXISTS "${ASNBER_PKIX_CHECKED_IN_HEADER}")
    message(FATAL_ERROR
      "缺少检入的 asnber-pkix 描述表产物：${ASNBER_PKIX_CHECKED_IN_DIR}")
  endif()
  set(pkix_table_include_dir "${ASNBER_PKIX_CHECKED_IN_DIR}")
  set(pkix_table_header "${ASNBER_PKIX_CHECKED_IN_HEADER}")
endif()

asnber_generate_module_version_header(pkix)

if(ASNBER_BUILD_SHARED)
  add_library(asnber_pkix_shared SHARED ${ASNBER_PKIX_SOURCES})
  set_target_properties(
    asnber_pkix_shared
    PROPERTIES
      OUTPUT_NAME asnber-pkix
      EXPORT_NAME shared
      VERSION ${PROJECT_VERSION}
      SOVERSION ${PROJECT_VERSION_MAJOR}
  )
  asnber_apply_module_settings(
    asnber_pkix_shared
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${ASNBER_MODULE_GENERATED_INCLUDE_DIR}"
    ASNBER_PKIX_BUILDING_LIBRARY
  )
  target_include_directories(asnber_pkix_shared PRIVATE "${pkix_table_include_dir}")
  target_sources(asnber_pkix_shared PRIVATE "${pkix_table_header}")
  target_link_libraries(asnber_pkix_shared PUBLIC asnber::shared)
  add_library(asnber::pkix::shared ALIAS asnber_pkix_shared)
  list(APPEND ASNBER_PKIX_TARGETS asnber_pkix_shared)
endif()

if(ASNBER_BUILD_STATIC)
  add_library(asnber_pkix_static STATIC ${ASNBER_PKIX_SOURCES})
  set_target_properties(
    asnber_pkix_static
    PROPERTIES
      OUTPUT_NAME asnber-pkix_static
      EXPORT_NAME static
  )
  asnber_apply_module_settings(
    asnber_pkix_static
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${ASNBER_MODULE_GENERATED_INCLUDE_DIR}"
    ASNBER_PKIX_BUILDING_LIBRARY
  )
  target_include_directories(asnber_pkix_static PRIVATE "${pkix_table_include_dir}")
  target_sources(asnber_pkix_static PRIVATE "${pkix_table_header}")
  target_compile_definitions(asnber_pkix_static PRIVATE ASNBER_PKIX_STATIC INTERFACE ASNBER_PKIX_STATIC)
  target_link_libraries(asnber_pkix_static PUBLIC asnber::static)
  add_library(asnber::pkix::static ALIAS asnber_pkix_static)
  list(APPEND ASNBER_PKIX_TARGETS asnber_pkix_static)
endif()

if(ASNBER_PKIX_REGENERATE_TABLE)
  foreach(_target IN LISTS ASNBER_PKIX_TARGETS)
    add_dependencies(${_target}
      asnber_pkix_table_verify
      asnber_pkix_table_verify_certificate
    )
  endforeach()
endif()

asnber_install_module(
  asnber-pkix pkix
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${ASNBER_MODULE_GENERATED_INCLUDE_DIR}"
  ${ASNBER_PKIX_TARGETS}
)
