# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT

# asnber-ocsp：OCSP（RFC 6960）结构读写。
# 独立包与版本；只依赖核心公共 ABI，核心不反向引用本模块。
cmake_minimum_required(VERSION 3.20)

project(
  asnber-ocsp
  VERSION 0.2.0
  DESCRIPTION "OCSP 结构模块（RFC 6960）"
  LANGUAGES C CXX
)

# capability: decode+encode
set(ASNBER_OCSP_SOURCES
  src/ocsp_access.cpp
  src/ocsp_schema_table.cpp
  src/asnber_ocsp_request.cpp
  src/asnber_ocsp_response.cpp
  src/asnber_ocsp_basic.cpp
  src/ocsp_builder.cpp
  src/asnber_ocsp_version.cpp
)
set(ASNBER_OCSP_TARGETS "")

# 描述表产物：检入 modules/ocsp/generated/，未安装、不进入公共头。
# 一个 ASN.1 文件只生成一张表，头部写默认根 OCSPResponse；OCSPRequest
# 与 BasicOCSPResponse 由模块在 asnber_schema_load_with_root 时指定根类型编号。
set(ASNBER_OCSP_CHECKED_IN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/generated")
set(ASNBER_OCSP_ASN1_6960
    "${CMAKE_CURRENT_SOURCE_DIR}/asn1/OCSP-Flattened-6960.asn1")

set(ASNBER_OCSP_TABLE_NAMES ocsp_schema)
set(ASNBER_OCSP_TABLE_ROOTS OCSPResponse)
set(ASNBER_OCSP_TABLE_INPUTS "${ASNBER_OCSP_ASN1_6960}")

set(ASNBER_OCSP_CHECKED_IN_BINARIES "")
set(ASNBER_OCSP_CHECKED_IN_HEADERS "")
foreach(name IN LISTS ASNBER_OCSP_TABLE_NAMES)
  list(APPEND ASNBER_OCSP_CHECKED_IN_BINARIES
       "${ASNBER_OCSP_CHECKED_IN_DIR}/${name}.bin")
  list(APPEND ASNBER_OCSP_CHECKED_IN_HEADERS
       "${ASNBER_OCSP_CHECKED_IN_DIR}/${name}.h")
endforeach()

if(ASNBER_OCSP_REGENERATE_TABLE)
  if(NOT TARGET asnberc)
    message(
      FATAL_ERROR
      "ASNBER_OCSP_REGENERATE_TABLE=ON 需要同时启用 ASNBER_BUILD_TOOLS=ON 以提供 asnberc"
    )
  endif()
  set(ocsp_regenerated_dir "${CMAKE_CURRENT_BINARY_DIR}/generated/table")
  file(MAKE_DIRECTORY "${ocsp_regenerated_dir}")
  set(ocsp_regenerated_outputs "")

  foreach(name root input IN ZIP_LISTS ASNBER_OCSP_TABLE_NAMES
          ASNBER_OCSP_TABLE_ROOTS ASNBER_OCSP_TABLE_INPUTS)
    set(regenerated_bin "${ocsp_regenerated_dir}/${name}.bin")
    set(regenerated_header "${ocsp_regenerated_dir}/${name}.h")
    add_custom_command(
      OUTPUT "${regenerated_bin}" "${regenerated_header}"
      COMMAND
        $<TARGET_FILE:asnberc> -o "${regenerated_bin}" -c "${regenerated_header}"
        --root "${root}" "${input}"
      DEPENDS asnberc "${input}"
      COMMENT "用 asnberc 重新生成 asnber-ocsp 描述表 ${name}（根 ${root}）"
      VERBATIM
    )
    list(APPEND ocsp_regenerated_outputs "${regenerated_bin}"
         "${regenerated_header}")
  endforeach()

  add_custom_target(asnber_ocsp_table_generate
                    DEPENDS ${ocsp_regenerated_outputs})

  set(ocsp_verify_commands "")
  foreach(name IN LISTS ASNBER_OCSP_TABLE_NAMES)
    list(APPEND ocsp_verify_commands
      COMMAND
        ${CMAKE_COMMAND} -E compare_files
        "${ocsp_regenerated_dir}/${name}.bin"
        "${ASNBER_OCSP_CHECKED_IN_DIR}/${name}.bin"
      COMMAND
        ${CMAKE_COMMAND} -E compare_files
        "${ocsp_regenerated_dir}/${name}.h"
        "${ASNBER_OCSP_CHECKED_IN_DIR}/${name}.h"
    )
  endforeach()
  add_custom_target(asnber_ocsp_table_verify
    ${ocsp_verify_commands}
    DEPENDS asnber_ocsp_table_generate ${ASNBER_OCSP_CHECKED_IN_BINARIES}
            ${ASNBER_OCSP_CHECKED_IN_HEADERS}
    COMMENT "校验重新生成的 asnber-ocsp 描述表与检入产物逐字节一致"
    VERBATIM
  )
  set(ocsp_table_include_dir "${ocsp_regenerated_dir}")
else()
  foreach(path IN LISTS ASNBER_OCSP_CHECKED_IN_BINARIES
          ASNBER_OCSP_CHECKED_IN_HEADERS)
    if(NOT EXISTS "${path}")
      message(FATAL_ERROR "缺少检入的 asnber-ocsp 描述表产物：${path}")
    endif()
  endforeach()
  set(ocsp_table_include_dir "${ASNBER_OCSP_CHECKED_IN_DIR}")
endif()

asnber_generate_module_version_header(ocsp)

if(ASNBER_BUILD_SHARED)
  add_library(asnber_ocsp_shared SHARED ${ASNBER_OCSP_SOURCES})
  set_target_properties(
    asnber_ocsp_shared
    PROPERTIES
      OUTPUT_NAME asnber-ocsp
      EXPORT_NAME shared
      VERSION ${PROJECT_VERSION}
      SOVERSION ${PROJECT_VERSION_MAJOR}
  )
  asnber_apply_module_settings(
    asnber_ocsp_shared
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${ASNBER_MODULE_GENERATED_INCLUDE_DIR}"
    ASNBER_OCSP_BUILDING_LIBRARY
  )
  target_include_directories(asnber_ocsp_shared PRIVATE
                             "${ocsp_table_include_dir}")
  target_link_libraries(asnber_ocsp_shared PUBLIC asnber::shared)
  add_library(asnber::ocsp::shared ALIAS asnber_ocsp_shared)
  list(APPEND ASNBER_OCSP_TARGETS asnber_ocsp_shared)
endif()

if(ASNBER_BUILD_STATIC)
  add_library(asnber_ocsp_static STATIC ${ASNBER_OCSP_SOURCES})
  set_target_properties(
    asnber_ocsp_static
    PROPERTIES
      OUTPUT_NAME asnber-ocsp_static
      EXPORT_NAME static
  )
  asnber_apply_module_settings(
    asnber_ocsp_static
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${ASNBER_MODULE_GENERATED_INCLUDE_DIR}"
    ASNBER_OCSP_BUILDING_LIBRARY
  )
  target_include_directories(asnber_ocsp_static PRIVATE
                             "${ocsp_table_include_dir}")
  target_compile_definitions(asnber_ocsp_static PRIVATE ASNBER_OCSP_STATIC
                             INTERFACE ASNBER_OCSP_STATIC)
  target_link_libraries(asnber_ocsp_static PUBLIC asnber::static)
  add_library(asnber::ocsp::static ALIAS asnber_ocsp_static)
  list(APPEND ASNBER_OCSP_TARGETS asnber_ocsp_static)
endif()

if(ASNBER_OCSP_REGENERATE_TABLE)
  if(TARGET asnber_ocsp_shared)
    add_dependencies(asnber_ocsp_shared asnber_ocsp_table_verify)
  endif()
  if(TARGET asnber_ocsp_static)
    add_dependencies(asnber_ocsp_static asnber_ocsp_table_verify)
  endif()
endif()

asnber_install_module(
  asnber-ocsp ocsp
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${ASNBER_MODULE_GENERATED_INCLUDE_DIR}"
  ${ASNBER_OCSP_TARGETS}
)
