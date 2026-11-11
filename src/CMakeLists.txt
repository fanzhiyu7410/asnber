# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT

# 库目标定义。当前仅包含版本/能力查询实现，其余源文件按模块逐步加入。
# 模块目录约定：
#   core/   编解码编排、资源上限、流式适配
#   types/  ASN.1 标签与节点模型
#   ber/    BER TLV 读写与长度解析
#   der/    DER 规范化与严格校验
#   memory/ 分配器、arena 与静态池
#   error/  错误码与错误上下文
#   io/     缓冲区与 reader/writer 适配
#   schema/ 模板类型树、描述表加载与约束校验
#   c_api/  C ABI 适配层

set(ASNBER_CORE_BASE_SOURCES
  core/asnber_version.cpp
  core/asnber_context.cpp
  types/asnber_dom.cpp
  types/asnber_value.cpp
)

set(ASNBER_CORE_DECODE_SOURCES
  ber/asnber_ber_decoder.cpp
  schema/asnber_schema.cpp
  schema/asnber_schema_types.cpp
  schema/asnber_schema_constraints.cpp
  schema/asnber_schema_tlv.cpp
  schema/asnber_schema_table.cpp
  schema/asnber_schema_table_header.cpp
  schema/asnber_schema_table_records.cpp
  schema/asnber_schema_table_constraints.cpp
  schema/asnber_schema_decode.cpp
  schema/asnber_schema_decode_tags.cpp
  schema/asnber_schema_decode_constraints.cpp
  schema/asnber_schema_decode_bind.cpp
  c_api/asnber_ctx_api.cpp
  c_api/asnber_decode_api.cpp
  c_api/asnber_node_api.cpp
  c_api/asnber_value_basic_api.cpp
  c_api/asnber_value_text_api.cpp
  c_api/asnber_schema_load_api.cpp
)

set(ASNBER_CORE_ENCODE_SOURCES
  der/asnber_tag_codec.cpp
  der/asnber_encoder.cpp
  schema/asnber_schema_encode.cpp
  schema/asnber_schema_encode_tags.cpp
  schema/asnber_schema_encode_size.cpp
  schema/asnber_schema_encode_any.cpp
  schema/asnber_schema_encode_write.cpp
  c_api/asnber_encode_api.cpp
)

set(ASNBER_CORE_BUILD_API_SOURCES
  types/asnber_dom_build.cpp
  c_api/asnber_doc_api.cpp
)

set(ASNBER_CORE_SCHEMA_BUILD_SOURCES
  c_api/asnber_schema_build_api.cpp
)

set(ASNBER_LIBRARY_SOURCES
  ${ASNBER_CORE_BASE_SOURCES}
  ${ASNBER_CORE_DECODE_SOURCES}
)

if(ASNBER_ENABLE_ENCODE)
  list(APPEND ASNBER_LIBRARY_SOURCES ${ASNBER_CORE_ENCODE_SOURCES})
endif()
if(ASNBER_ENABLE_BUILD_API)
  list(APPEND ASNBER_LIBRARY_SOURCES ${ASNBER_CORE_BUILD_API_SOURCES})
endif()
if(ASNBER_ENABLE_SCHEMA_BUILD_API)
  list(APPEND ASNBER_LIBRARY_SOURCES ${ASNBER_CORE_SCHEMA_BUILD_SOURCES})
endif()

set(ASNBER_LIBRARY_TARGETS "")

if(ASNBER_BUILD_SHARED)
  add_library(asnber_shared SHARED ${ASNBER_LIBRARY_SOURCES})
  set_target_properties(
    asnber_shared
    PROPERTIES
      OUTPUT_NAME asnber
      EXPORT_NAME shared
      VERSION ${PROJECT_VERSION}
      SOVERSION ${PROJECT_VERSION_MAJOR}
  )
  asnber_apply_library_settings(asnber_shared)
  add_library(asnber::shared ALIAS asnber_shared)
  list(APPEND ASNBER_LIBRARY_TARGETS asnber_shared)
endif()

if(ASNBER_BUILD_STATIC)
  add_library(asnber_static STATIC ${ASNBER_LIBRARY_SOURCES})
  set_target_properties(
    asnber_static
    PROPERTIES
      OUTPUT_NAME asnber_static
      EXPORT_NAME static
  )
  asnber_apply_library_settings(asnber_static)
  target_compile_definitions(asnber_static PRIVATE ASNBER_STATIC INTERFACE ASNBER_STATIC)
  add_library(asnber::static ALIAS asnber_static)
  list(APPEND ASNBER_LIBRARY_TARGETS asnber_static)
endif()

set(ASNBER_LIBRARY_TARGETS "${ASNBER_LIBRARY_TARGETS}" PARENT_SCOPE)
