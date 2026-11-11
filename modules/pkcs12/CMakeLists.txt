# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT

# asnber-pkcs12：PKCS#12（RFC 7292）结构访问与 PFX 构造。
# 独立包与版本；只依赖核心公共 ABI，核心不反向引用本模块。
cmake_minimum_required(VERSION 3.20)

project(
  asnber-pkcs12
  VERSION 0.1.0
  DESCRIPTION "PKCS#12 结构模块（RFC 7292）"
  LANGUAGES C CXX
)

# capability: decode+encode
set(ASNBER_PKCS12_SOURCES
  src/asnber_pkcs12_structures.cpp
  src/pkcs_handle.cpp
  src/pkcs12_schema_table.cpp
  src/pkcs12_builder.cpp
)
set(ASNBER_PKCS12_TARGETS "")

# 描述表产物：检入 modules/pkcs12/generated/，未安装、不进入公共头。
# 一个 ASN.1 文件只生成一张表，头部写默认根 PFX；AuthenticatedSafe /
# SafeContents / CertBag 由模块在 asnber_schema_load_with_root 加载时指定根。
set(ASNBER_PKCS12_CHECKED_IN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/generated")
set(ASNBER_PKCS12_ASN1_7292
    "${CMAKE_CURRENT_SOURCE_DIR}/asn1/PKCS12-Flattened-7292.asn1")

set(ASNBER_PKCS12_TABLE_NAMES
  pkcs12_schema
)
set(ASNBER_PKCS12_TABLE_ROOTS
  PFX
)
set(ASNBER_PKCS12_TABLE_INPUTS
  "${ASNBER_PKCS12_ASN1_7292}"
)

set(ASNBER_PKCS12_CHECKED_IN_BINARIES "")
set(ASNBER_PKCS12_CHECKED_IN_HEADERS "")
foreach(name IN LISTS ASNBER_PKCS12_TABLE_NAMES)
  list(APPEND ASNBER_PKCS12_CHECKED_IN_BINARIES
       "${ASNBER_PKCS12_CHECKED_IN_DIR}/${name}.bin")
  list(APPEND ASNBER_PKCS12_CHECKED_IN_HEADERS
       "${ASNBER_PKCS12_CHECKED_IN_DIR}/${name}.h")
endforeach()

if(ASNBER_PKCS12_REGENERATE_TABLE)
  if(NOT TARGET asnberc)
    message(
      FATAL_ERROR
      "ASNBER_PKCS12_REGENERATE_TABLE=ON 需要同时启用 ASNBER_BUILD_TOOLS=ON 以提供 asnberc"
    )
  endif()
  set(pkcs12_regenerated_dir "${CMAKE_CURRENT_BINARY_DIR}/generated/table")
  file(MAKE_DIRECTORY "${pkcs12_regenerated_dir}")
  set(pkcs12_regenerated_outputs "")

  foreach(name root input IN ZIP_LISTS ASNBER_PKCS12_TABLE_NAMES
          ASNBER_PKCS12_TABLE_ROOTS ASNBER_PKCS12_TABLE_INPUTS)
    set(regenerated_bin "${pkcs12_regenerated_dir}/${name}.bin")
    set(regenerated_header "${pkcs12_regenerated_dir}/${name}.h")
    add_custom_command(
      OUTPUT "${regenerated_bin}" "${regenerated_header}"
      COMMAND
        $<TARGET_FILE:asnberc> -o "${regenerated_bin}" -c "${regenerated_header}"
        --root "${root}" "${input}"
      DEPENDS asnberc "${input}"
      COMMENT "用 asnberc 重新生成 asnber-pkcs12 描述表 ${name}（根 ${root}）"
      VERBATIM
    )
    list(APPEND pkcs12_regenerated_outputs "${regenerated_bin}"
         "${regenerated_header}")
  endforeach()

  add_custom_target(asnber_pkcs12_table_generate
                    DEPENDS ${pkcs12_regenerated_outputs})

  # 与检入产物逐字节比对；任一差异或缺失即构建失败，避免长期漂移。
  set(pkcs12_verify_commands "")
  foreach(name IN LISTS ASNBER_PKCS12_TABLE_NAMES)
    list(APPEND pkcs12_verify_commands
      COMMAND
        ${CMAKE_COMMAND} -E compare_files
        "${pkcs12_regenerated_dir}/${name}.bin"
        "${ASNBER_PKCS12_CHECKED_IN_DIR}/${name}.bin"
      COMMAND
        ${CMAKE_COMMAND} -E compare_files
        "${pkcs12_regenerated_dir}/${name}.h"
        "${ASNBER_PKCS12_CHECKED_IN_DIR}/${name}.h"
    )
  endforeach()
  add_custom_target(asnber_pkcs12_table_verify
    ${pkcs12_verify_commands}
    DEPENDS asnber_pkcs12_table_generate ${ASNBER_PKCS12_CHECKED_IN_BINARIES}
            ${ASNBER_PKCS12_CHECKED_IN_HEADERS}
    COMMENT "校验重新生成的 asnber-pkcs12 描述表与检入产物逐字节一致"
    VERBATIM
  )
  set(pkcs12_table_include_dir "${pkcs12_regenerated_dir}")
else()
  foreach(path IN LISTS ASNBER_PKCS12_CHECKED_IN_BINARIES
          ASNBER_PKCS12_CHECKED_IN_HEADERS)
    if(NOT EXISTS "${path}")
      message(FATAL_ERROR "缺少检入的 asnber-pkcs12 描述表产物：${path}")
    endif()
  endforeach()
  set(pkcs12_table_include_dir "${ASNBER_PKCS12_CHECKED_IN_DIR}")
endif()

asnber_generate_module_version_header(pkcs12)

if(ASNBER_BUILD_SHARED)
  add_library(asnber_pkcs12_shared SHARED ${ASNBER_PKCS12_SOURCES})
  set_target_properties(
    asnber_pkcs12_shared
    PROPERTIES
      OUTPUT_NAME asnber-pkcs12
      EXPORT_NAME shared
      VERSION ${PROJECT_VERSION}
      SOVERSION ${PROJECT_VERSION_MAJOR}
  )
  asnber_apply_module_settings(
    asnber_pkcs12_shared
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${ASNBER_MODULE_GENERATED_INCLUDE_DIR}"
    ASNBER_PKCS12_BUILDING_LIBRARY
  )
  target_include_directories(asnber_pkcs12_shared PRIVATE
                             "${pkcs12_table_include_dir}")
  target_link_libraries(asnber_pkcs12_shared PUBLIC asnber::shared)
  add_library(asnber::pkcs12::shared ALIAS asnber_pkcs12_shared)
  list(APPEND ASNBER_PKCS12_TARGETS asnber_pkcs12_shared)
endif()

if(ASNBER_BUILD_STATIC)
  add_library(asnber_pkcs12_static STATIC ${ASNBER_PKCS12_SOURCES})
  set_target_properties(
    asnber_pkcs12_static
    PROPERTIES
      OUTPUT_NAME asnber-pkcs12_static
      EXPORT_NAME static
  )
  asnber_apply_module_settings(
    asnber_pkcs12_static
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${ASNBER_MODULE_GENERATED_INCLUDE_DIR}"
    ASNBER_PKCS12_BUILDING_LIBRARY
  )
  target_include_directories(asnber_pkcs12_static PRIVATE
                             "${pkcs12_table_include_dir}")
  target_compile_definitions(asnber_pkcs12_static PRIVATE ASNBER_PKCS12_STATIC
                             INTERFACE ASNBER_PKCS12_STATIC)
  target_link_libraries(asnber_pkcs12_static PUBLIC asnber::static)
  add_library(asnber::pkcs12::static ALIAS asnber_pkcs12_static)
  list(APPEND ASNBER_PKCS12_TARGETS asnber_pkcs12_static)
endif()

if(ASNBER_PKCS12_REGENERATE_TABLE)
  if(TARGET asnber_pkcs12_shared)
    add_dependencies(asnber_pkcs12_shared asnber_pkcs12_table_verify)
  endif()
  if(TARGET asnber_pkcs12_static)
    add_dependencies(asnber_pkcs12_static asnber_pkcs12_table_verify)
  endif()
endif()

asnber_install_module(
  asnber-pkcs12 pkcs12
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${ASNBER_MODULE_GENERATED_INCLUDE_DIR}"
  ${ASNBER_PKCS12_TARGETS}
)
