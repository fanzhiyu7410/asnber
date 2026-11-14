# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT

# asnber-cms：CMS/PKCS#7 标准结构模块（RFC 5652 只读结构访问）。
# 独立包与版本；只依赖核心公共 ABI，核心不反向引用本模块。
cmake_minimum_required(VERSION 3.20)

project(
  asnber-cms
  VERSION 0.2.0
  DESCRIPTION "CMS/PKCS#7 标准结构模块（RFC 5652，只读与结构构造）"
  LANGUAGES C CXX
)

set(ASNBER_CMS_SOURCES
  src/cms_builder_common.cpp
  src/cms_content_info_builder.cpp
  src/cms_signed_builder.cpp
  src/cms_enveloped_builder.cpp
  src/cms_encrypted_builder.cpp
  src/cms_compressed_builder.cpp
  src/cms_authenticated_builder.cpp
  src/asnber_cms_encrypted.cpp
  src/asnber_cms_enveloped.cpp
  src/asnber_cms_compressed.cpp
  src/asnber_cms_authenticated.cpp
  src/asnber_cms_structures.cpp
  src/asnber_cms_version.cpp
  src/cms_schema_table.cpp
)
set(ASNBER_CMS_TARGETS "")

# 描述表产物：检入 modules/cms/generated/，未安装、不进入公共头。
# 一个 ASN.1 文件只生成一张表，头部写默认根 ContentInfo；其余顶层结构
# （SignedData/EnvelopedData/EncryptedData/CompressedData/AuthenticatedData）
# 由模块在 asnber_schema_load_with_root 加载时指定根类型编号。
set(ASNBER_CMS_CHECKED_IN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/generated")
set(ASNBER_CMS_ASN1_5652 "${CMAKE_CURRENT_SOURCE_DIR}/asn1/CMS-Flattened-5652.asn1")

set(ASNBER_CMS_TABLE_NAMES
  cms_schema
)
set(ASNBER_CMS_TABLE_ROOTS
  ContentInfo
)
set(ASNBER_CMS_TABLE_INPUTS
  "${ASNBER_CMS_ASN1_5652}"
)

set(ASNBER_CMS_CHECKED_IN_BINARIES "")
set(ASNBER_CMS_CHECKED_IN_HEADERS "")
foreach(name IN LISTS ASNBER_CMS_TABLE_NAMES)
  list(APPEND ASNBER_CMS_CHECKED_IN_BINARIES "${ASNBER_CMS_CHECKED_IN_DIR}/${name}.bin")
  list(APPEND ASNBER_CMS_CHECKED_IN_HEADERS "${ASNBER_CMS_CHECKED_IN_DIR}/${name}.h")
endforeach()

if(ASNBER_CMS_REGENERATE_TABLE)
  if(NOT TARGET asnberc)
    message(
      FATAL_ERROR
      "ASNBER_CMS_REGENERATE_TABLE=ON 需要同时启用 ASNBER_BUILD_TOOLS=ON 以提供 asnberc"
    )
  endif()
  set(cms_regenerated_dir "${CMAKE_CURRENT_BINARY_DIR}/generated/table")
  file(MAKE_DIRECTORY "${cms_regenerated_dir}")
  set(cms_regenerated_outputs "")

  foreach(name root input IN ZIP_LISTS ASNBER_CMS_TABLE_NAMES ASNBER_CMS_TABLE_ROOTS ASNBER_CMS_TABLE_INPUTS)
    set(regenerated_bin "${cms_regenerated_dir}/${name}.bin")
    set(regenerated_header "${cms_regenerated_dir}/${name}.h")
    add_custom_command(
      OUTPUT "${regenerated_bin}" "${regenerated_header}"
      COMMAND
        $<TARGET_FILE:asnberc> -o "${regenerated_bin}" -c "${regenerated_header}"
        --root "${root}" "${input}"
      DEPENDS asnberc "${input}"
      COMMENT "用 asnberc 重新生成 asnber-cms 描述表 ${name}（根 ${root}）"
      VERBATIM
    )
    list(APPEND cms_regenerated_outputs "${regenerated_bin}" "${regenerated_header}")
  endforeach()

  add_custom_target(asnber_cms_table_generate DEPENDS ${cms_regenerated_outputs})

  # 与检入产物逐字节比对；任一差异或缺失即构建失败，避免长期漂移。
  set(cms_verify_commands "")
  foreach(name IN LISTS ASNBER_CMS_TABLE_NAMES)
    list(APPEND cms_verify_commands
      COMMAND
        ${CMAKE_COMMAND} -E compare_files
        "${cms_regenerated_dir}/${name}.bin"
        "${ASNBER_CMS_CHECKED_IN_DIR}/${name}.bin"
      COMMAND
        ${CMAKE_COMMAND} -E compare_files
        "${cms_regenerated_dir}/${name}.h"
        "${ASNBER_CMS_CHECKED_IN_DIR}/${name}.h"
    )
  endforeach()
  add_custom_target(asnber_cms_table_verify
    ${cms_verify_commands}
    DEPENDS asnber_cms_table_generate ${ASNBER_CMS_CHECKED_IN_BINARIES}
            ${ASNBER_CMS_CHECKED_IN_HEADERS}
    COMMENT "校验重新生成的 asnber-cms 描述表与检入产物逐字节一致"
    VERBATIM
  )
  set(cms_table_include_dir "${cms_regenerated_dir}")
else()
  foreach(path IN LISTS ASNBER_CMS_CHECKED_IN_BINARIES ASNBER_CMS_CHECKED_IN_HEADERS)
    if(NOT EXISTS "${path}")
      message(FATAL_ERROR "缺少检入的 asnber-cms 描述表产物：${path}")
    endif()
  endforeach()
  set(cms_table_include_dir "${ASNBER_CMS_CHECKED_IN_DIR}")
endif()

asnber_generate_module_version_header(cms)

if(ASNBER_BUILD_SHARED)
  add_library(asnber_cms_shared SHARED ${ASNBER_CMS_SOURCES})
  set_target_properties(
    asnber_cms_shared
    PROPERTIES
      OUTPUT_NAME asnber-cms
      EXPORT_NAME shared
      VERSION ${PROJECT_VERSION}
      SOVERSION ${PROJECT_VERSION_MAJOR}
  )
  asnber_apply_module_settings(
    asnber_cms_shared
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${ASNBER_MODULE_GENERATED_INCLUDE_DIR}"
    ASNBER_CMS_BUILDING_LIBRARY
  )
  target_include_directories(asnber_cms_shared PRIVATE "${cms_table_include_dir}")
  target_link_libraries(asnber_cms_shared PUBLIC asnber::shared)
  add_library(asnber::cms::shared ALIAS asnber_cms_shared)
  list(APPEND ASNBER_CMS_TARGETS asnber_cms_shared)
endif()

if(ASNBER_BUILD_STATIC)
  add_library(asnber_cms_static STATIC ${ASNBER_CMS_SOURCES})
  set_target_properties(
    asnber_cms_static
    PROPERTIES
      OUTPUT_NAME asnber-cms_static
      EXPORT_NAME static
  )
  asnber_apply_module_settings(
    asnber_cms_static
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${ASNBER_MODULE_GENERATED_INCLUDE_DIR}"
    ASNBER_CMS_BUILDING_LIBRARY
  )
  target_include_directories(asnber_cms_static PRIVATE "${cms_table_include_dir}")
  target_compile_definitions(asnber_cms_static PRIVATE ASNBER_CMS_STATIC INTERFACE ASNBER_CMS_STATIC)
  target_link_libraries(asnber_cms_static PUBLIC asnber::static)
  add_library(asnber::cms::static ALIAS asnber_cms_static)
  list(APPEND ASNBER_CMS_TARGETS asnber_cms_static)
endif()

if(ASNBER_CMS_REGENERATE_TABLE)
  if(TARGET asnber_cms_shared)
    add_dependencies(asnber_cms_shared asnber_cms_table_verify)
  endif()
  if(TARGET asnber_cms_static)
    add_dependencies(asnber_cms_static asnber_cms_table_verify)
  endif()
endif()

asnber_install_module(
  asnber-cms cms
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${ASNBER_MODULE_GENERATED_INCLUDE_DIR}"
  ${ASNBER_CMS_TARGETS}
)
