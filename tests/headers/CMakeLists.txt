# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT

# 公共头自包含编译测试：每个公共头生成一个独立翻译单元，只包含该头自身。
# 任一公共头缺少依赖包含或需要调用方先包含其他头时，构建期直接失败。

set(_asnber_header_roots "${PROJECT_SOURCE_DIR}/include")
if(TARGET asnber::pkix::static OR TARGET asnber::pkix::shared)
  list(APPEND _asnber_header_roots "${PROJECT_SOURCE_DIR}/modules/pkix/include")
endif()
if(TARGET asnber::pkcs1::static OR TARGET asnber::pkcs1::shared)
  list(APPEND _asnber_header_roots "${PROJECT_SOURCE_DIR}/modules/pkcs1/include")
endif()
if(TARGET asnber::pkcs8::static OR TARGET asnber::pkcs8::shared)
  list(APPEND _asnber_header_roots "${PROJECT_SOURCE_DIR}/modules/pkcs8/include")
endif()
if(TARGET asnber::pkcs10::static OR TARGET asnber::pkcs10::shared)
  list(APPEND _asnber_header_roots "${PROJECT_SOURCE_DIR}/modules/pkcs10/include")
endif()
if(TARGET asnber::pkcs12::static OR TARGET asnber::pkcs12::shared)
  list(APPEND _asnber_header_roots "${PROJECT_SOURCE_DIR}/modules/pkcs12/include")
endif()
if(TARGET asnber::pkcs)
  list(APPEND _asnber_header_roots "${PROJECT_SOURCE_DIR}/modules/pkcs/include")
endif()
if(TARGET asnber::cms::static OR TARGET asnber::cms::shared)
  list(APPEND _asnber_header_roots "${PROJECT_SOURCE_DIR}/modules/cms/include")
endif()
if(TARGET asnber::ocsp::static OR TARGET asnber::ocsp::shared)
  list(APPEND _asnber_header_roots "${PROJECT_SOURCE_DIR}/modules/ocsp/include")
endif()

set(_asnber_header_sources)
foreach(_root IN LISTS _asnber_header_roots)
  file(GLOB_RECURSE _headers CONFIGURE_DEPENDS "${_root}/asnber/*.h")
  foreach(_hdr IN LISTS _headers)
    file(RELATIVE_PATH _rel "${_root}" "${_hdr}")
    string(REPLACE "/" "_" _uid "${_rel}")
    set(ASNBER_HEADER_REL "${_rel}")
    configure_file(
      "${CMAKE_CURRENT_SOURCE_DIR}/selfcontained.c.in"
      "${CMAKE_CURRENT_BINARY_DIR}/${_uid}.c"
      @ONLY
    )
    list(APPEND _asnber_header_sources "${CMAKE_CURRENT_BINARY_DIR}/${_uid}.c")
  endforeach()
endforeach()

# 裁剪场景：只包含解码子头与四个 PKCS 公共头，不包含 <asnber/asnber.h>。
set(_asnber_pkcs_decode_only ON)
foreach(_module IN ITEMS pkcs1 pkcs8 pkcs10 pkcs12)
  if(NOT TARGET asnber::${_module}::static AND NOT TARGET asnber::${_module}::shared)
    set(_asnber_pkcs_decode_only OFF)
  endif()
endforeach()
if(_asnber_pkcs_decode_only)
  list(APPEND _asnber_header_sources
       "${CMAKE_CURRENT_SOURCE_DIR}/decode_only.c")
endif()

add_library(asnber_public_headers_selfcontained OBJECT ${_asnber_header_sources})
set_target_properties(
  asnber_public_headers_selfcontained
  PROPERTIES
    C_STANDARD 99
    C_STANDARD_REQUIRED ON
)
if(MSVC)
  target_compile_options(asnber_public_headers_selfcontained PRIVATE /utf-8)
endif()

# 通过目标 usage requirements 获得源码树、生成头与模块头的包含路径。
if(TARGET asnber::static)
  target_link_libraries(asnber_public_headers_selfcontained PRIVATE asnber::static)
else()
  target_link_libraries(asnber_public_headers_selfcontained PRIVATE asnber::shared)
endif()
foreach(_module IN ITEMS pkix pkcs1 pkcs8 pkcs10 pkcs12 cms ocsp)
  if(TARGET asnber::${_module}::static)
    target_link_libraries(asnber_public_headers_selfcontained PRIVATE
                          asnber::${_module}::static)
  elseif(TARGET asnber::${_module}::shared)
    target_link_libraries(asnber_public_headers_selfcontained PRIVATE
                          asnber::${_module}::shared)
  endif()
endforeach()
if(TARGET asnber::pkcs)
  target_link_libraries(asnber_public_headers_selfcontained PRIVATE asnber::pkcs)
endif()
