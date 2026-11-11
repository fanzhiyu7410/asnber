# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.20)

project(
  asnber
  VERSION 0.1.0
  DESCRIPTION "跨平台 ASN.1 解析与编解码库（C ABI 对外，C++ 内部实现）"
  LANGUAGES C CXX
)

# MSVC：禁用 CMake 默认注入的 /EHsc，完全由 AsnberCompilerChecks 的
# /EHs-c-（禁用 SEH、仅保留 C++ 异常）负责。否则命令行同一项被写两次，
# 产生 D9025 "overriding '/EHc' with '/EHc-'" 噪音。
cmake_policy(SET CMP0092 NEW)

# 让 cl 命令行里只有一条异常处理选项：/EHs-c-（SEH 开 + C++ 异常关）。
# CMP0092 NEW 先关掉 CMake 默认注入的 /EHsc，再通过 CMAKE_CXX_FLAGS_INIT
# 写入我们的选项，这样 CMake 就不会在 ItemDefinitionGroup 里重复写 Sync。
if(MSVC)
  set(CMAKE_CXX_FLAGS_INIT "/EHs-c- /GR-")
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include(GNUInstallDirs)
include(AsnberOptions)
include(AsnberCompilerChecks)
include(AsnberModule)
include(AsnberVersion)

asnber_generate_core_version_header()
asnber_generate_core_features_header()

add_subdirectory(src)

# 工具先于模块配置：模块可选地在构建期调用 asnberc 重新生成描述表。
if(ASNBER_BUILD_TOOLS)
  add_subdirectory(tools)
endif()

if(ASNBER_BUILD_MODULES)
  add_subdirectory(modules)
endif()

if(ASNBER_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()

if(ASNBER_BUILD_BENCHMARKS)
  add_subdirectory(benchmarks)
  add_subdirectory(tests/bench)
endif()

if(ASNBER_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

# 嵌入式最小用例可以独立于 CTest 构建（交叉编译时只链接，不运行）。
if(ASNBER_BUILD_EMBEDDED_TEST AND NOT ASNBER_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests/embedded)
endif()

# libFuzzer harness 可独立于单元测试构建（fuzz 专属构建不触碰 CTest 用例）。
if(ASNBER_BUILD_FUZZ AND NOT ASNBER_BUILD_TESTS)
  add_subdirectory(tests/fuzz)
endif()

# 差分测试辅助工具（asnber_dump），供 tests/differential/diff_asnber.py 使用。
if(ASNBER_BUILD_DIFFERENTIAL)
  add_subdirectory(tests/differential)
endif()

include(AsnberInstall)
asnber_install_library("${ASNBER_LIBRARY_TARGETS}")
