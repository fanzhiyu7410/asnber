# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT
# 测试骨架。当前用无第三方依赖的最小 C 用例覆盖已落地的版本查询契约；
# doctest 与 libFuzzer 在登记后接入，规划见 docs/07-测试与验证.md。

if(NOT ASNBER_BUILD_TESTS)
  return()
endif()

# 统一注册 C 测试：优先静态库（避免 Windows 运行期 DLL 路径问题），
# 仅共享库构建时把 DLL 复制到测试可执行文件目录。
# NO_CORE：调用方随后会链接模块目标，核心库已由其 PUBLIC 依赖带入；
# 再直接链核心会让同一条链接行出现两次 asnber_static，ld64 报
# “ignoring duplicate libraries”。模块用例因此只链模块目标。
function(asnber_add_test name source)
  cmake_parse_arguments(ARG "NO_CORE" "" "" ${ARGN})
  add_executable(${name} ${source})
  if(NOT ARG_NO_CORE)
    if(TARGET asnber::static)
      target_link_libraries(${name} PRIVATE asnber::static)
    else()
      target_link_libraries(${name} PRIVATE asnber::shared)
      if(WIN32)
        add_custom_command(
          TARGET ${name} POST_BUILD
          COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:asnber::shared> $<TARGET_FILE_DIR:${name}>
        )
      endif()
    endif()
  endif()
  set_target_properties(
    ${name}
    PROPERTIES
      LINKER_LANGUAGE CXX
      C_STANDARD 99
      C_STANDARD_REQUIRED ON
  )
  if(MSVC)
    target_compile_options(${name} PRIVATE /utf-8)
  endif()
  asnber_apply_sanitizer_options(${name})
  asnber_copy_sanitizer_runtime(${name})
  add_test(NAME ${name} COMMAND ${name})
  asnber_apply_sanitizer_test_environment(${name})
endfunction()

add_subdirectory(support)
add_subdirectory(embedded)
add_subdirectory(unit)
add_subdirectory(c_api)
add_subdirectory(headers)
add_subdirectory(consumer)

# 模块用例依赖模块目标；模块未构建时跳过。
if(TARGET asnber::pkix::static OR TARGET asnber::pkix::shared)
  add_subdirectory(pkix)
endif()
if(TARGET asnber::pkcs1::static OR TARGET asnber::pkcs1::shared)
  add_subdirectory(pkcs1)
endif()
if(TARGET asnber::pkcs8::static OR TARGET asnber::pkcs8::shared)
  add_subdirectory(pkcs8)
endif()
if(TARGET asnber::pkcs10::static OR TARGET asnber::pkcs10::shared)
  add_subdirectory(pkcs10)
endif()
if(TARGET asnber::pkcs)
  add_subdirectory(pkcs)
endif()
if(TARGET asnber::pkcs12::static OR TARGET asnber::pkcs12::shared)
  add_subdirectory(pkcs12)
endif()
if(TARGET asnber::cms::static OR TARGET asnber::cms::shared)
  add_subdirectory(cms)
endif()
if(TARGET asnber::ocsp::static OR TARGET asnber::ocsp::shared)
  add_subdirectory(ocsp)
endif()

add_subdirectory(conformance)
add_subdirectory(fuzz)

# asnberc 端到端测试依赖工具目标，仅在构建 asnberc 时接入。
if(TARGET asnberc)
  add_subdirectory(asnberc)
endif()
