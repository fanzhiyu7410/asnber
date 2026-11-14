# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT

# 构建选项定义。
# 所有选项均以缓存变量暴露，便于上层项目或交叉编译工具链覆盖。
include_guard(GLOBAL)

option(ASNBER_BUILD_SHARED "构建共享库目标 asnber::shared" ON)
option(ASNBER_BUILD_STATIC "构建静态库目标 asnber::static" ON)
option(ASNBER_BUILD_MODULES "构建 modules/ 下的独立标准模块" ON)
option(ASNBER_BUILD_MODULE_PKIX "构建 asnber-pkix 模块（仅 ASNBER_BUILD_MODULES=ON 时生效）" ON)
option(ASNBER_BUILD_MODULE_CMS "构建 asnber-cms 模块（仅 ASNBER_BUILD_MODULES=ON 时生效）" ON)
option(ASNBER_BUILD_MODULE_OCSP "构建 asnber-ocsp 模块（仅 ASNBER_BUILD_MODULES=ON 时生效）" ON)
option(ASNBER_BUILD_MODULE_PKCS "构建 asnber-pkcs 门面包（需要同时启用 pkcs1/8/10/12，仅 ASNBER_BUILD_MODULES=ON 时生效）" ON)
option(ASNBER_BUILD_MODULE_PKCS1 "构建 asnber-pkcs1 模块（仅 ASNBER_BUILD_MODULES=ON 时生效）" ON)
option(ASNBER_BUILD_MODULE_PKCS8 "构建 asnber-pkcs8 模块（仅 ASNBER_BUILD_MODULES=ON 时生效）" ON)
option(ASNBER_BUILD_MODULE_PKCS10 "构建 asnber-pkcs10 模块（仅 ASNBER_BUILD_MODULES=ON 时生效）" ON)
option(ASNBER_BUILD_MODULE_PKCS12 "构建 asnber-pkcs12 模块（仅 ASNBER_BUILD_MODULES=ON 时生效）" ON)
option(ASNBER_BUILD_TOOLS "构建 tools/asnberc" ON)
option(
  ASNBER_PKIX_REGENERATE_TABLE
  "构建期用 asnberc 重新生成 asnber-pkix 描述表，并与检入产物逐字节比对（默认使用检入产物）"
  OFF
)
option(
  ASNBER_PKCS1_REGENERATE_TABLE
  "构建期用 asnberc 重新生成 asnber-pkcs1 描述表，并与检入产物逐字节比对（默认使用检入产物）"
  OFF
)
option(
  ASNBER_PKCS8_REGENERATE_TABLE
  "构建期用 asnberc 重新生成 asnber-pkcs8 描述表，并与检入产物逐字节比对（默认使用检入产物）"
  OFF
)
option(
  ASNBER_PKCS10_REGENERATE_TABLE
  "构建期用 asnberc 重新生成 asnber-pkcs10 描述表，并与检入产物逐字节比对（默认使用检入产物）"
  OFF
)
option(
  ASNBER_PKCS12_REGENERATE_TABLE
  "构建期用 asnberc 重新生成 asnber-pkcs12 描述表，并与检入产物逐字节比对（默认使用检入产物）"
  OFF
)
option(
  ASNBER_CMS_REGENERATE_TABLE
  "构建期用 asnberc 重新生成 asnber-cms 描述表，并与检入产物逐字节比对（默认使用检入产物）"
  OFF
)
option(
  ASNBER_OCSP_REGENERATE_TABLE
  "构建期用 asnberc 重新生成 asnber-ocsp 描述表，并与检入产物逐字节比对（默认使用检入产物）"
  OFF
)
option(ASNBER_BUILD_EXAMPLES "构建 C 与 C++ 消费示例" OFF)
option(ASNBER_BUILD_BENCHMARKS "构建可选基准（不进 CTest 主流程）" OFF)
option(ASNBER_BUILD_TESTS "构建单元测试并注册到 CTest" OFF)
option(
  ASNBER_BUILD_FUZZ
  "构建 libFuzzer harness（tests/fuzz，需 Clang；覆盖率/ASan/UBSan 由全局 flags 注入）"
  OFF
)
option(
  ASNBER_BUILD_DIFFERENTIAL
  "构建差分测试辅助工具 asnber_dump（tests/differential）"
  OFF
)
option(
  ASNBER_BUILD_EMBEDDED_TEST
  "构建嵌入式最小用例 tests/embedded（静态池、无堆、无标准 IO），可独立于 CTest 交叉编译"
  OFF
)
option(ASNBER_FREESTANDING "按 freestanding 子集构建（无异常、无 RTTI、无标准 IO）" OFF)
option(ASNBER_WARNINGS_AS_ERRORS "将编译警告视为错误" OFF)
option(ASNBER_ENABLE_SANITIZERS "启用 AddressSanitizer 与 UBSan（仅宿主平台调试构建）" OFF)

# ---------------------------------------------------------------------------
# 嵌入式裁切：profile 只设置默认值，细粒度选项可单独覆盖。
# ---------------------------------------------------------------------------
set(ASNBER_TRIM_PROFILE "full" CACHE STRING
    "裁切配置：full、cert-decode 或 cert-and-csr")
set_property(CACHE ASNBER_TRIM_PROFILE PROPERTY STRINGS
             full cert-decode cert-and-csr)
if(NOT ASNBER_TRIM_PROFILE MATCHES "^(full|cert-decode|cert-and-csr)$")
  message(FATAL_ERROR
    "ASNBER_TRIM_PROFILE 只接受 full、cert-decode 或 cert-and-csr：${ASNBER_TRIM_PROFILE}")
endif()

if(ASNBER_TRIM_PROFILE STREQUAL "cert-decode")
  set(_asnber_trim_encode_default OFF)
  set(_asnber_trim_build_api_default OFF)
  set(_asnber_trim_schema_build_default OFF)
  set(_asnber_trim_pkix_builder_default OFF)
  set(_asnber_trim_pkix_variant_default "certificate")
elseif(ASNBER_TRIM_PROFILE STREQUAL "cert-and-csr")
  set(_asnber_trim_encode_default ON)
  set(_asnber_trim_build_api_default ON)
  set(_asnber_trim_schema_build_default OFF)
  set(_asnber_trim_pkix_builder_default ON)
  set(_asnber_trim_pkix_variant_default "certificate")
else()
  set(_asnber_trim_encode_default ON)
  set(_asnber_trim_build_api_default ON)
  set(_asnber_trim_schema_build_default ON)
  set(_asnber_trim_pkix_builder_default ON)
  set(_asnber_trim_pkix_variant_default "full")
endif()

if(NOT DEFINED ASNBER_ENABLE_ENCODE)
  set(ASNBER_ENABLE_ENCODE ${_asnber_trim_encode_default} CACHE BOOL
      "编译 DER 编码实现（关闭后编码符号不进入库）")
endif()
if(NOT DEFINED ASNBER_ENABLE_BUILD_API)
  set(ASNBER_ENABLE_BUILD_API ${_asnber_trim_build_api_default} CACHE BOOL
      "编译运行时构树 API（asnber_doc_create / asnber_node_create 等）")
endif()
if(NOT DEFINED ASNBER_ENABLE_SCHEMA_BUILD_API)
  set(ASNBER_ENABLE_SCHEMA_BUILD_API ${_asnber_trim_schema_build_default} CACHE BOOL
      "编译 schema 运行时注册 API（asnber_schema_create / add_* / seal）")
endif()
if(NOT DEFINED ASNBER_PKIX_ENABLE_BUILDER)
  set(ASNBER_PKIX_ENABLE_BUILDER ${_asnber_trim_pkix_builder_default} CACHE BOOL
      "编译 asnber-pkix 证书构造实现")
endif()
if(NOT DEFINED ASNBER_PKIX_SCHEMA_VARIANT)
  set(ASNBER_PKIX_SCHEMA_VARIANT "${_asnber_trim_pkix_variant_default}" CACHE STRING
      "asnber-pkix 描述表变体：full 或 certificate")
endif()
set_property(CACHE ASNBER_PKIX_SCHEMA_VARIANT PROPERTY STRINGS full certificate)
if(NOT ASNBER_PKIX_SCHEMA_VARIANT MATCHES "^(full|certificate)$")
  message(FATAL_ERROR
    "ASNBER_PKIX_SCHEMA_VARIANT 只接受 full 或 certificate：${ASNBER_PKIX_SCHEMA_VARIANT}")
endif()

set(ASNBER_CXX_STANDARD "17" CACHE STRING "内部 C++ 实现使用的语言标准（基线为 17）")
set_property(CACHE ASNBER_CXX_STANDARD PROPERTY STRINGS 17 20)

if(NOT ASNBER_BUILD_SHARED AND NOT ASNBER_BUILD_STATIC)
  message(FATAL_ERROR "至少需要启用一个库目标：ASNBER_BUILD_SHARED 或 ASNBER_BUILD_STATIC")
endif()

if(ASNBER_CXX_STANDARD STREQUAL "14")
  message(FATAL_ERROR "基线要求 C++17 或更高；14 仅作为历史记录保留在文档中，不受支持")
endif()

if(ASNBER_BUILD_SHARED)
  set(ASNBER_HAS_SHARED_TARGET ON)
endif()

# ---------------------------------------------------------------------------
# 裁切配置校验。规则绑定“特性关闭”这一事实，不绑定 profile 名称。
# ---------------------------------------------------------------------------
if(ASNBER_BUILD_SHARED)
  if(NOT ASNBER_ENABLE_ENCODE OR NOT ASNBER_ENABLE_BUILD_API OR
     NOT ASNBER_ENABLE_SCHEMA_BUILD_API)
    message(FATAL_ERROR
      "共享库要求三个核心特性全部开启：ASNBER_ENABLE_ENCODE、"
      "ASNBER_ENABLE_BUILD_API、ASNBER_ENABLE_SCHEMA_BUILD_API；"
      "裁切构建请使用 -DASNBER_BUILD_SHARED=OFF")
  endif()
  if(ASNBER_BUILD_MODULES AND ASNBER_BUILD_MODULE_PKIX AND
     NOT ASNBER_PKIX_ENABLE_BUILDER)
    message(FATAL_ERROR
      "共享库要求 asnber-pkix 构造接口完整：ASNBER_PKIX_ENABLE_BUILDER=OFF 时"
      "请使用 -DASNBER_BUILD_SHARED=OFF")
  endif()
endif()

if(ASNBER_PKIX_ENABLE_BUILDER)
  if(NOT ASNBER_ENABLE_ENCODE)
    message(FATAL_ERROR
      "ASNBER_PKIX_ENABLE_BUILDER=ON 需要 ASNBER_ENABLE_ENCODE=ON")
  endif()
  if(NOT ASNBER_ENABLE_BUILD_API)
    message(FATAL_ERROR
      "ASNBER_PKIX_ENABLE_BUILDER=ON 需要 ASNBER_ENABLE_BUILD_API=ON")
  endif()
endif()

if(ASNBER_TRIM_PROFILE STREQUAL "cert-decode")
  if(NOT ASNBER_BUILD_MODULES)
    message(FATAL_ERROR
      "ASNBER_TRIM_PROFILE=cert-decode 需要 ASNBER_BUILD_MODULES=ON")
  endif()
  if(NOT ASNBER_BUILD_MODULE_PKIX)
    message(FATAL_ERROR
      "ASNBER_TRIM_PROFILE=cert-decode 需要 ASNBER_BUILD_MODULE_PKIX=ON")
  endif()
  if(ASNBER_BUILD_MODULE_PKCS OR ASNBER_BUILD_MODULE_PKCS1 OR
     ASNBER_BUILD_MODULE_PKCS8 OR ASNBER_BUILD_MODULE_PKCS10 OR
     ASNBER_BUILD_MODULE_PKCS12 OR ASNBER_BUILD_MODULE_CMS OR
     ASNBER_BUILD_MODULE_OCSP)
    message(FATAL_ERROR
      "ASNBER_TRIM_PROFILE=cert-decode 只允许 PKIX 模块；"
      "请显式关闭 PKCS/PKCS1/PKCS8/PKCS10/PKCS12/CMS/OCSP")
  endif()
  if(ASNBER_BUILD_TESTS)
    message(FATAL_ERROR
      "ASNBER_TRIM_PROFILE=cert-decode 不允许 ASNBER_BUILD_TESTS=ON；"
      "请使用 -DASNBER_BUILD_TESTS=OFF -DASNBER_BUILD_EMBEDDED_TEST=ON")
  endif()
endif()

if(ASNBER_TRIM_PROFILE STREQUAL "cert-and-csr")
  if(NOT ASNBER_BUILD_MODULES)
    message(FATAL_ERROR
      "ASNBER_TRIM_PROFILE=cert-and-csr 需要 ASNBER_BUILD_MODULES=ON")
  endif()
  if(NOT ASNBER_BUILD_MODULE_PKIX)
    message(FATAL_ERROR
      "ASNBER_TRIM_PROFILE=cert-and-csr 需要 ASNBER_BUILD_MODULE_PKIX=ON")
  endif()
  if(NOT ASNBER_BUILD_MODULE_PKCS10)
    message(FATAL_ERROR
      "ASNBER_TRIM_PROFILE=cert-and-csr 需要 ASNBER_BUILD_MODULE_PKCS10=ON")
  endif()
  if(ASNBER_BUILD_MODULE_PKCS OR ASNBER_BUILD_MODULE_PKCS1 OR
     ASNBER_BUILD_MODULE_PKCS8 OR ASNBER_BUILD_MODULE_PKCS12 OR
     ASNBER_BUILD_MODULE_CMS OR ASNBER_BUILD_MODULE_OCSP)
    message(FATAL_ERROR
      "ASNBER_TRIM_PROFILE=cert-and-csr 只允许 PKIX 与 PKCS#10；"
      "请显式关闭 PKCS/PKCS1/PKCS8/PKCS12/CMS/OCSP")
  endif()
  if(ASNBER_BUILD_TESTS)
    message(FATAL_ERROR
      "ASNBER_TRIM_PROFILE=cert-and-csr 不允许 ASNBER_BUILD_TESTS=ON；"
      "请使用 -DASNBER_BUILD_TESTS=OFF -DASNBER_BUILD_EMBEDDED_TEST=ON")
  endif()
endif()
