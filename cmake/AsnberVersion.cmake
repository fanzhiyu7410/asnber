# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT

# 版本头生成。
# 唯一真源是各包自己的 project(... VERSION ...)；源码树中不手写版本宏。
include_guard(GLOBAL)

# 配置期断言：生成头的 MAJOR/MINOR/PATCH/STRING 逐项与 project VERSION 比对。
# prefix 为宏前缀，核心传 ASNBER，模块传 ASNBER_<模块大写>，工具传 ASNBERC。
function(asnber_assert_generated_version_header header expected_major expected_minor
         expected_patch expected_string prefix)
  if(NOT EXISTS "${header}")
    message(FATAL_ERROR "版本头未生成：${header}")
  endif()

  file(READ "${header}" _asnber_version_header_content)

  foreach(_asnber_part MAJOR MINOR PATCH)
    string(REGEX MATCH "#define ${prefix}_VERSION_${_asnber_part} ([0-9]+)"
           _asnber_version_match "${_asnber_version_header_content}")
    if(NOT _asnber_version_match)
      message(FATAL_ERROR
        "版本头 ${header} 缺少宏 ${prefix}_VERSION_${_asnber_part}")
    endif()
    string(TOLOWER "${_asnber_part}" _asnber_part_lower)
    set(_asnber_expected_value "${expected_${_asnber_part_lower}}")
    if(NOT "${CMAKE_MATCH_1}" STREQUAL "${_asnber_expected_value}")
      message(FATAL_ERROR
        "版本头 ${header} 的 ${prefix}_VERSION_${_asnber_part}=${CMAKE_MATCH_1} "
        "与 project VERSION 的 ${_asnber_part}=${_asnber_expected_value} 不一致")
    endif()
  endforeach()

  string(REGEX MATCH "#define ${prefix}_VERSION_STRING \"([^\"]*)\""
         _asnber_version_string_match "${_asnber_version_header_content}")
  if(NOT _asnber_version_string_match)
    message(FATAL_ERROR
      "版本头 ${header} 缺少宏 ${prefix}_VERSION_STRING")
  endif()
  if(NOT "${CMAKE_MATCH_1}" STREQUAL "${expected_string}")
    message(FATAL_ERROR
      "版本头 ${header} 的 ${prefix}_VERSION_STRING=${CMAKE_MATCH_1} "
      "与 project VERSION ${expected_string} 不一致")
  endif()
endfunction()

# 核心版本头：构建目录 generated/include/asnber/asnber_version.h。
# 结果通过 ASNBER_GENERATED_INCLUDE_DIR 暴露给上层，并在安装阶段复制到 include/asnber/。
function(asnber_generate_core_version_header)
  set(generated_dir "${CMAKE_BINARY_DIR}/generated/include")
  file(MAKE_DIRECTORY "${generated_dir}/asnber")

  configure_file(
    "${asnber_SOURCE_DIR}/cmake/asnber_version.h.in"
    "${generated_dir}/asnber/asnber_version.h"
    @ONLY
  )

  asnber_assert_generated_version_header(
    "${generated_dir}/asnber/asnber_version.h"
    "${PROJECT_VERSION_MAJOR}" "${PROJECT_VERSION_MINOR}"
    "${PROJECT_VERSION_PATCH}" "${PROJECT_VERSION}" "ASNBER")

  set(ASNBER_GENERATED_INCLUDE_DIR "${generated_dir}" PARENT_SCOPE)
endfunction()

# 模块版本头：<module_binary_dir>/generated/include/asnber/<name>/<name>_version.h。
# 结果通过 ASNBER_MODULE_GENERATED_INCLUDE_DIR 暴露给调用方的目录作用域。
function(asnber_generate_module_version_header name)
  string(TOUPPER "${name}" module_upper)
  set(ASNBER_MODULE_MACRO "ASNBER_${module_upper}")

  set(generated_dir "${CMAKE_CURRENT_BINARY_DIR}/generated/include")
  file(MAKE_DIRECTORY "${generated_dir}/asnber/${name}")

  configure_file(
    "${asnber_SOURCE_DIR}/cmake/asnberModuleVersion.h.in"
    "${generated_dir}/asnber/${name}/${name}_version.h"
    @ONLY
  )

  asnber_assert_generated_version_header(
    "${generated_dir}/asnber/${name}/${name}_version.h"
    "${PROJECT_VERSION_MAJOR}" "${PROJECT_VERSION_MINOR}"
    "${PROJECT_VERSION_PATCH}" "${PROJECT_VERSION}" "${ASNBER_MODULE_MACRO}")

  set(ASNBER_MODULE_GENERATED_INCLUDE_DIR "${generated_dir}" PARENT_SCOPE)
endfunction()

# 核心特性头：与版本头同目录，安装为 include/asnber/asnber_features.h。
function(asnber_generate_core_features_header)
  set(generated_dir "${CMAKE_BINARY_DIR}/generated/include/asnber")
  file(MAKE_DIRECTORY "${generated_dir}")

  if(ASNBER_ENABLE_ENCODE)
    set(ASNBER_FEATURE_ENCODE 1)
  else()
    set(ASNBER_FEATURE_ENCODE 0)
  endif()
  if(ASNBER_ENABLE_BUILD_API)
    set(ASNBER_FEATURE_BUILD_API 1)
  else()
    set(ASNBER_FEATURE_BUILD_API 0)
  endif()
  if(ASNBER_ENABLE_SCHEMA_BUILD_API)
    set(ASNBER_FEATURE_SCHEMA_BUILD_API 1)
  else()
    set(ASNBER_FEATURE_SCHEMA_BUILD_API 0)
  endif()
  if(ASNBER_PKIX_ENABLE_BUILDER)
    set(ASNBER_FEATURE_PKIX_BUILDER 1)
  else()
    set(ASNBER_FEATURE_PKIX_BUILDER 0)
  endif()

  configure_file(
    "${asnber_SOURCE_DIR}/cmake/asnber_features.h.in"
    "${generated_dir}/asnber_features.h"
    @ONLY
  )
endfunction()
