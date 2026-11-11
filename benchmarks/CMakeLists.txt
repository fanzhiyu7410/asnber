# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT

# 可选基准（ASNBER_BUILD_BENCHMARKS=ON 时构建），不注册到 CTest 主流程。

if(NOT TARGET asnber::pkix::static AND NOT TARGET asnber::pkix::shared)
  message(STATUS "asnber-pkix 未构建，跳过基准")
  return()
endif()

add_executable(asnber_pkix_bench pkix_bench.c)
set_target_properties(asnber_pkix_bench PROPERTIES C_STANDARD 99
                                                 C_STANDARD_REQUIRED ON)
if(MSVC)
  target_compile_options(asnber_pkix_bench PRIVATE /utf-8)
endif()

if(TARGET asnber::pkix::static)
  target_link_libraries(asnber_pkix_bench PRIVATE asnber::pkix::static)
else()
  target_link_libraries(asnber_pkix_bench PRIVATE asnber::pkix::shared)
  if(WIN32)
    add_custom_command(
      TARGET asnber_pkix_bench POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:asnber::pkix::shared> $<TARGET_FILE_DIR:asnber_pkix_bench>
    )
    add_custom_command(
      TARGET asnber_pkix_bench POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:asnber::shared> $<TARGET_FILE_DIR:asnber_pkix_bench>
    )
  endif()
endif()
