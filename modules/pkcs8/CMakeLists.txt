# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT

# asnber-pkcs8：PKCS#8（RFC 5208）结构访问与 PrivateKeyInfo 构造。
# 独立包与版本；只依赖核心公共 ABI，核心不反向引用本模块。
cmake_minimum_required(VERSION 3.20)

project(
  asnber-pkcs8
  VERSION 0.2.0
  DESCRIPTION "PKCS#8 结构模块（RFC 5208，读写）"
  LANGUAGES C CXX
)

# capability: decode+encode
set(ASNBER_PKCS8_SOURCES
  src/pkcs8_builder.cpp
  src/pkcs8_structures.cpp
  src/pkcs_handle.cpp
  src/pkcs8_schema_table.cpp
)
set(ASNBER_PKCS8_TARGETS "")

# 描述表产物：检入 modules/pkcs8/generated/，未安装、不进入公共头。
# 一个 ASN.1 文件只生成一张表，头部写默认根 PrivateKeyInfo；
# EncryptedPrivateKeyInfo 由模块在 asnber_schema_load_with_root 加载时指定根。
set(ASNBER_PKCS8_CHECKED_IN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/generated")
set(ASNBER_PKCS8_ASN1_5208
    "${CMAKE_CURRENT_SOURCE_DIR}/asn1/PKCS8-Flattened-5208.asn1")

set(ASNBER_PKCS8_TABLE_NAMES
  pkcs8_schema
)
set(ASNBER_PKCS8_TABLE_ROOTS
  PrivateKeyInfo
)
set(ASNBER_PKCS8_TABLE_INPUTS
  "${ASNBER_PKCS8_ASN1_5208}"
)

set(ASNBER_PKCS8_CHECKED_IN_BINARIES "")
set(ASNBER_PKCS8_CHECKED_IN_HEADERS "")
foreach(name IN LISTS ASNBER_PKCS8_TABLE_NAMES)
  list(APPEND ASNBER_PKCS8_CHECKED_IN_BINARIES
       "${ASNBER_PKCS8_CHECKED_IN_DIR}/${name}.bin")
  list(APPEND ASNBER_PKCS8_CHECKED_IN_HEADERS
       "${ASNBER_PKCS8_CHECKED_IN_DIR}/${name}.h")
endforeach()

if(ASNBER_PKCS8_REGENERATE_TABLE)
  if(NOT TARGET asnberc)
    message(
      FATAL_ERROR
      "ASNBER_PKCS8_REGENERATE_TABLE=ON 需要同时启用 ASNBER_BUILD_TOOLS=ON 以提供 asnberc"
    )
  endif()
  set(pkcs8_regenerated_dir "${CMAKE_CURRENT_BINARY_DIR}/generated/table")
  file(MAKE_DIRECTORY "${pkcs8_regenerated_dir}")
  set(pkcs8_regenerated_outputs "")

  foreach(name root input IN ZIP_LISTS ASNBER_PKCS8_TABLE_NAMES
          ASNBER_PKCS8_TABLE_ROOTS ASNBER_PKCS8_TABLE_INPUTS)
    set(regenerated_bin "${pkcs8_regenerated_dir}/${name}.bin")
    set(regenerated_header "${pkcs8_regenerated_dir}/${name}.h")
    add_custom_command(
      OUTPUT "${regenerated_bin}" "${regenerated_header}"
      COMMAND
        $<TARGET_FILE:asnberc> -o "${regenerated_bin}" -c "${regenerated_header}"
        --root "${root}" "${input}"
      DEPENDS asnberc "${input}"
      COMMENT "用 asnberc 重新生成 asnber-pkcs8 描述表 ${name}（根 ${root}）"
      VERBATIM
    )
    list(APPEND pkcs8_regenerated_outputs "${regenerated_bin}"
         "${regenerated_header}")
  endforeach()

  add_custom_target(asnber_pkcs8_table_generate
                    DEPENDS ${pkcs8_regenerated_outputs})

  # 与检入产物逐字节比对；任一差异或缺失即构建失败，避免长期漂移。
  set(pkcs8_verify_commands "")
  foreach(name IN LISTS ASNBER_PKCS8_TABLE_NAMES)
    list(APPEND pkcs8_verify_commands
      COMMAND
        ${CMAKE_COMMAND} -E compare_files
        "${pkcs8_regenerated_dir}/${name}.bin"
        "${ASNBER_PKCS8_CHECKED_IN_DIR}/${name}.bin"
      COMMAND
        ${CMAKE_COMMAND} -E compare_files
        "${pkcs8_regenerated_dir}/${name}.h"
        "${ASNBER_PKCS8_CHECKED_IN_DIR}/${name}.h"
    )
  endforeach()
  add_custom_target(asnber_pkcs8_table_verify
    ${pkcs8_verify_commands}
    DEPENDS asnber_pkcs8_table_generate ${ASNBER_PKCS8_CHECKED_IN_BINARIES}
            ${ASNBER_PKCS8_CHECKED_IN_HEADERS}
    COMMENT "校验重新生成的 asnber-pkcs8 描述表与检入产物逐字节一致"
    VERBATIM
  )
  set(pkcs8_table_include_dir "${pkcs8_regenerated_dir}")
else()
  foreach(path IN LISTS ASNBER_PKCS8_CHECKED_IN_BINARIES
          ASNBER_PKCS8_CHECKED_IN_HEADERS)
    if(NOT EXISTS "${path}")
      message(FATAL_ERROR "缺少检入的 asnber-pkcs8 描述表产物：${path}")
    endif()
  endforeach()
  set(pkcs8_table_include_dir "${ASNBER_PKCS8_CHECKED_IN_DIR}")
endif()

asnber_generate_module_version_header(pkcs8)

if(ASNBER_BUILD_SHARED)
  add_library(asnber_pkcs8_shared SHARED ${ASNBER_PKCS8_SOURCES})
  set_target_properties(
    asnber_pkcs8_shared
    PROPERTIES
      OUTPUT_NAME asnber-pkcs8
      EXPORT_NAME shared
      VERSION ${PROJECT_VERSION}
      SOVERSION ${PROJECT_VERSION_MAJOR}
  )
  asnber_apply_module_settings(
    asnber_pkcs8_shared
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${ASNBER_MODULE_GENERATED_INCLUDE_DIR}"
    ASNBER_PKCS8_BUILDING_LIBRARY
  )
  target_include_directories(asnber_pkcs8_shared PRIVATE
                             "${pkcs8_table_include_dir}")
  target_link_libraries(asnber_pkcs8_shared PUBLIC asnber::shared)
  add_library(asnber::pkcs8::shared ALIAS asnber_pkcs8_shared)
  list(APPEND ASNBER_PKCS8_TARGETS asnber_pkcs8_shared)
endif()

if(ASNBER_BUILD_STATIC)
  add_library(asnber_pkcs8_static STATIC ${ASNBER_PKCS8_SOURCES})
  set_target_properties(
    asnber_pkcs8_static
    PROPERTIES
      OUTPUT_NAME asnber-pkcs8_static
      EXPORT_NAME static
  )
  asnber_apply_module_settings(
    asnber_pkcs8_static
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${ASNBER_MODULE_GENERATED_INCLUDE_DIR}"
    ASNBER_PKCS8_BUILDING_LIBRARY
  )
  target_include_directories(asnber_pkcs8_static PRIVATE
                             "${pkcs8_table_include_dir}")
  target_compile_definitions(asnber_pkcs8_static PRIVATE ASNBER_PKCS8_STATIC
                             INTERFACE ASNBER_PKCS8_STATIC)
  target_link_libraries(asnber_pkcs8_static PUBLIC asnber::static)
  add_library(asnber::pkcs8::static ALIAS asnber_pkcs8_static)
  list(APPEND ASNBER_PKCS8_TARGETS asnber_pkcs8_static)
endif()

if(ASNBER_PKCS8_REGENERATE_TABLE)
  if(TARGET asnber_pkcs8_shared)
    add_dependencies(asnber_pkcs8_shared asnber_pkcs8_table_verify)
  endif()
  if(TARGET asnber_pkcs8_static)
    add_dependencies(asnber_pkcs8_static asnber_pkcs8_table_verify)
  endif()
endif()

asnber_install_module(
  asnber-pkcs8 pkcs8
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${ASNBER_MODULE_GENERATED_INCLUDE_DIR}"
  ${ASNBER_PKCS8_TARGETS}
)
