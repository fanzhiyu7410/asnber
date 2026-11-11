# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT

# 模块 open/close 成本基线（ASNBER_BUILD_BENCHMARKS=ON 时构建，不进 CTest）。

if(NOT (TARGET asnber::pkix::static OR TARGET asnber::pkix::shared))
  message(STATUS "asnber-pkix 未构建，跳过模块基准")
  return()
endif()
if(NOT TARGET asnber::pkcs)
  message(STATUS "asnber-pkcs 未构建，跳过模块基准")
  return()
endif()
if(NOT (TARGET asnber::cms::static OR TARGET asnber::cms::shared))
  message(STATUS "asnber-cms 未构建，跳过模块基准")
  return()
endif()

set(ASNBER_BENCH_USE_STATIC ON)
foreach(module core pkix pkcs cms)
  if(module STREQUAL "core")
    if(NOT TARGET asnber::static)
      set(ASNBER_BENCH_USE_STATIC OFF)
    endif()
  elseif(module STREQUAL "pkcs")
    # 聚合包无自身产物，静态可用性由四个实现包决定。
    if(NOT TARGET asnber::pkcs1::static)
      set(ASNBER_BENCH_USE_STATIC OFF)
    endif()
  elseif(NOT TARGET asnber::${module}::static)
    set(ASNBER_BENCH_USE_STATIC OFF)
  endif()
endforeach()

add_executable(bench_module_open bench_module_open.c)
asnber_apply_sanitizer_options(bench_module_open)
set_target_properties(
  bench_module_open
  PROPERTIES
    C_STANDARD 99
    C_STANDARD_REQUIRED ON
    LINKER_LANGUAGE CXX
)
target_compile_definitions(
  bench_module_open PRIVATE
  ASNBER_BENCH_DATA_DIR="${CMAKE_SOURCE_DIR}/tests/data"
)
if(MSVC)
  target_compile_options(bench_module_open PRIVATE /utf-8)
endif()

# 核心库由模块与聚合包的 PUBLIC 依赖带入，不再直接链接：重复出现会让
# 链接行两次带上同一个核心库（ld64 报 duplicate libraries）。
if(ASNBER_BENCH_USE_STATIC)
  target_link_libraries(
    bench_module_open PRIVATE
    asnber::pkix::static
    asnber::pkcs
    asnber::cms::static
  )
else()
  target_link_libraries(
    bench_module_open PRIVATE
    asnber::pkix::shared
    asnber::pkcs
    asnber::cms::shared
  )
  if(WIN32)
    foreach(target asnber::shared asnber::pkix::shared
            asnber::pkcs1::shared asnber::pkcs8::shared
            asnber::pkcs10::shared asnber::pkcs12::shared asnber::cms::shared)
      add_custom_command(
        TARGET bench_module_open POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
          $<TARGET_FILE:${target}> $<TARGET_FILE_DIR:bench_module_open>
      )
    endforeach()
  endif()
endif()
