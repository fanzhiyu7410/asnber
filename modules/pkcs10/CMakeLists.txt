# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT

# asnber-pkcs10：PKCS#10（RFC 2986）只读结构访问。
# 独立包与版本；只依赖核心公共 ABI，核心不反向引用本模块。
cmake_minimum_required(VERSION 3.20)

project(
  asnber-pkcs10
  VERSION 0.1.1
  DESCRIPTION "PKCS#10 结构模块（RFC 2986，读写）"
  LANGUAGES C CXX
)

# capability: decode+encode
set(ASNBER_PKCS10_SOURCES
  src/pkcs10_builder.cpp
  src/pkcs10_structures.cpp
  src/pkcs_handle.cpp
  src/pkcs10_schema_table.cpp
)
set(ASNBER_PKCS10_TARGETS "")

# 描述表产物：检入 modules/pkcs10/generated/，未安装、不进入公共头。
# 一个 ASN.1 文件只生成一张表，头部写默认根 CertificationRequest；
# CertificationRequestInfo 由模块在 asnber_schema_load_with_root 加载时指定根。
set(ASNBER_PKCS10_CHECKED_IN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/generated")
set(ASNBER_PKCS10_ASN1_2986
    "${CMAKE_CURRENT_SOURCE_DIR}/asn1/PKCS10-Flattened-2986.asn1")

set(ASNBER_PKCS10_TABLE_NAMES
  pkcs10_schema
)
set(ASNBER_PKCS10_TABLE_ROOTS
  CertificationRequest
)
set(ASNBER_PKCS10_TABLE_INPUTS
  "${ASNBER_PKCS10_ASN1_2986}"
)

set(ASNBER_PKCS10_CHECKED_IN_BINARIES "")
set(ASNBER_PKCS10_CHECKED_IN_HEADERS "")
foreach(name IN LISTS ASNBER_PKCS10_TABLE_NAMES)
  list(APPEND ASNBER_PKCS10_CHECKED_IN_BINARIES
       "${ASNBER_PKCS10_CHECKED_IN_DIR}/${name}.bin")
  list(APPEND ASNBER_PKCS10_CHECKED_IN_HEADERS
       "${ASNBER_PKCS10_CHECKED_IN_DIR}/${name}.h")
endforeach()

if(ASNBER_PKCS10_REGENERATE_TABLE)
  if(NOT TARGET asnberc)
    message(
      FATAL_ERROR
      "ASNBER_PKCS10_REGENERATE_TABLE=ON 需要同时启用 ASNBER_BUILD_TOOLS=ON 以提供 asnberc"
    )
  endif()
  set(pkcs10_regenerated_dir "${CMAKE_CURRENT_BINARY_DIR}/generated/table")
  file(MAKE_DIRECTORY "${pkcs10_regenerated_dir}")
  set(pkcs10_regenerated_outputs "")

  foreach(name root input IN ZIP_LISTS ASNBER_PKCS10_TABLE_NAMES
          ASNBER_PKCS10_TABLE_ROOTS ASNBER_PKCS10_TABLE_INPUTS)
    set(regenerated_bin "${pkcs10_regenerated_dir}/${name}.bin")
    set(regenerated_header "${pkcs10_regenerated_dir}/${name}.h")
    add_custom_command(
      OUTPUT "${regenerated_bin}" "${regenerated_header}"
      COMMAND
        $<TARGET_FILE:asnberc> -o "${regenerated_bin}" -c "${regenerated_header}"
        --root "${root}" "${input}"
      DEPENDS asnberc "${input}"
      COMMENT "用 asnberc 重新生成 asnber-pkcs10 描述表 ${name}（根 ${root}）"
      VERBATIM
    )
    list(APPEND pkcs10_regenerated_outputs "${regenerated_bin}"
         "${regenerated_header}")
  endforeach()

  add_custom_target(asnber_pkcs10_table_generate
                    DEPENDS ${pkcs10_regenerated_outputs})

  # 与检入产物逐字节比对；任一差异或缺失即构建失败，避免长期漂移。
  set(pkcs10_verify_commands "")
  foreach(name IN LISTS ASNBER_PKCS10_TABLE_NAMES)
    list(APPEND pkcs10_verify_commands
      COMMAND
        ${CMAKE_COMMAND} -E compare_files
        "${pkcs10_regenerated_dir}/${name}.bin"
        "${ASNBER_PKCS10_CHECKED_IN_DIR}/${name}.bin"
      COMMAND
        ${CMAKE_COMMAND} -E compare_files
        "${pkcs10_regenerated_dir}/${name}.h"
        "${ASNBER_PKCS10_CHECKED_IN_DIR}/${name}.h"
    )
  endforeach()
  add_custom_target(asnber_pkcs10_table_verify
    ${pkcs10_verify_commands}
    DEPENDS asnber_pkcs10_table_generate ${ASNBER_PKCS10_CHECKED_IN_BINARIES}
            ${ASNBER_PKCS10_CHECKED_IN_HEADERS}
    COMMENT "校验重新生成的 asnber-pkcs10 描述表与检入产物逐字节一致"
    VERBATIM
  )
  set(pkcs10_table_include_dir "${pkcs10_regenerated_dir}")
else()
  foreach(path IN LISTS ASNBER_PKCS10_CHECKED_IN_BINARIES
          ASNBER_PKCS10_CHECKED_IN_HEADERS)
    if(NOT EXISTS "${path}")
      message(FATAL_ERROR "缺少检入的 asnber-pkcs10 描述表产物：${path}")
    endif()
  endforeach()
  set(pkcs10_table_include_dir "${ASNBER_PKCS10_CHECKED_IN_DIR}")
endif()

asnber_generate_module_version_header(pkcs10)

if(ASNBER_BUILD_SHARED)
  add_library(asnber_pkcs10_shared SHARED ${ASNBER_PKCS10_SOURCES})
  set_target_properties(
    asnber_pkcs10_shared
    PROPERTIES
      OUTPUT_NAME asnber-pkcs10
      EXPORT_NAME shared
      VERSION ${PROJECT_VERSION}
      SOVERSION ${PROJECT_VERSION_MAJOR}
  )
  asnber_apply_module_settings(
    asnber_pkcs10_shared
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${ASNBER_MODULE_GENERATED_INCLUDE_DIR}"
    ASNBER_PKCS10_BUILDING_LIBRARY
  )
  target_include_directories(asnber_pkcs10_shared PRIVATE
                             "${pkcs10_table_include_dir}")
  target_link_libraries(asnber_pkcs10_shared PUBLIC asnber::shared)
  add_library(asnber::pkcs10::shared ALIAS asnber_pkcs10_shared)
  list(APPEND ASNBER_PKCS10_TARGETS asnber_pkcs10_shared)
endif()

if(ASNBER_BUILD_STATIC)
  add_library(asnber_pkcs10_static STATIC ${ASNBER_PKCS10_SOURCES})
  set_target_properties(
    asnber_pkcs10_static
    PROPERTIES
      OUTPUT_NAME asnber-pkcs10_static
      EXPORT_NAME static
  )
  asnber_apply_module_settings(
    asnber_pkcs10_static
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${ASNBER_MODULE_GENERATED_INCLUDE_DIR}"
    ASNBER_PKCS10_BUILDING_LIBRARY
  )
  target_include_directories(asnber_pkcs10_static PRIVATE
                             "${pkcs10_table_include_dir}")
  target_compile_definitions(asnber_pkcs10_static PRIVATE ASNBER_PKCS10_STATIC
                             INTERFACE ASNBER_PKCS10_STATIC)
  target_link_libraries(asnber_pkcs10_static PUBLIC asnber::static)
  add_library(asnber::pkcs10::static ALIAS asnber_pkcs10_static)
  list(APPEND ASNBER_PKCS10_TARGETS asnber_pkcs10_static)
endif()

if(ASNBER_PKCS10_REGENERATE_TABLE)
  if(TARGET asnber_pkcs10_shared)
    add_dependencies(asnber_pkcs10_shared asnber_pkcs10_table_verify)
  endif()
  if(TARGET asnber_pkcs10_static)
    add_dependencies(asnber_pkcs10_static asnber_pkcs10_table_verify)
  endif()
endif()

asnber_install_module(
  asnber-pkcs10 pkcs10
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${ASNBER_MODULE_GENERATED_INCLUDE_DIR}"
  ${ASNBER_PKCS10_TARGETS}
)
