# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT

# asnberc：`.asn1` 文本解析、语义校验与描述表生成工具。
# 工具内部静态库只在本目录使用，不链接核心库或模块。
cmake_minimum_required(VERSION 3.20)

project(
  asnberc
  VERSION 0.1.1
  DESCRIPTION "ASN.1 模块文本解析与描述表生成工具"
  LANGUAGES CXX
)

# 独立版本头：只由本目录的 project VERSION 派生，不安装到消费者。
set(asnberc_generated_dir "${CMAKE_CURRENT_BINARY_DIR}/generated/include")
file(MAKE_DIRECTORY "${asnberc_generated_dir}")

configure_file(
  "${asnber_SOURCE_DIR}/cmake/asnbercVersion.h.in"
  "${asnberc_generated_dir}/asnberc_version.h"
  @ONLY
)

asnber_assert_generated_version_header(
  "${asnberc_generated_dir}/asnberc_version.h"
  "${PROJECT_VERSION_MAJOR}" "${PROJECT_VERSION_MINOR}"
  "${PROJECT_VERSION_PATCH}" "${PROJECT_VERSION}" "ASNBERC")

add_library(asnberc_lib STATIC
  src/crc32c.cpp
  src/diag.cpp
  src/lexer.cpp
  src/module_set.cpp
  src/parser.cpp
  src/parser_types.cpp
  src/parser_constraints.cpp
  src/parser_values.cpp
  src/semantic.cpp
  src/semantic_values.cpp
  src/semantic_types.cpp
  src/semantic_constraints.cpp
  src/semantic_defaults.cpp
  src/semantic_checks.cpp
  src/trim.cpp
  src/table.cpp
)
target_include_directories(asnberc_lib PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
asnber_apply_common_settings(asnberc_lib)

add_executable(asnberc src/main.cpp)
target_link_libraries(asnberc PRIVATE asnberc_lib)
target_include_directories(asnberc PRIVATE
  "${asnberc_generated_dir}"
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
)
asnber_apply_common_settings(asnberc)

install(TARGETS asnberc RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
