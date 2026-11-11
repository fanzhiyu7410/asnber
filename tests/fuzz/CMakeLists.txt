# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT
#
# fuzz 目录：
#  - tests 模式：注册确定性冒烟用例（随 ASNBER_BUILD_TESTS）。
#  - fuzz 模式：构建 libFuzzer harness（随 ASNBER_BUILD_FUZZ，需 Clang + 静态核心）。
#
# 构建方式（全套以覆盖率 + ASan/UBSan 插桩）：
#   cmake -S . -B build-fuzz -G Ninja \
#     -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
#     -DCMAKE_C_FLAGS="-fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer" \
#     -DCMAKE_CXX_FLAGS="-fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer" \
#     -DASNBER_BUILD_STATIC=ON -DASNBER_BUILD_SHARED=OFF \
#     -DASNBER_BUILD_TESTS=OFF -DASNBER_BUILD_TOOLS=ON -DASNBER_BUILD_FUZZ=ON
#   cmake --build build-fuzz

if(ASNBER_BUILD_TESTS)
  asnber_add_test(test_fuzz_smoke test_fuzz_smoke.c)
  target_link_libraries(test_fuzz_smoke PRIVATE asnber_test_support)
endif()

if(NOT ASNBER_BUILD_FUZZ)
  return()
endif()

if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  message(WARNING "ASNBER_BUILD_FUZZ 需要 Clang（libFuzzer）；跳过 fuzz harness 构建")
  return()
endif()

if(NOT TARGET asnber::static)
  message(WARNING "ASNBER_BUILD_FUZZ 需要静态核心库 asnber::static；跳过 fuzz harness 构建")
  return()
endif()

function(asnber_add_fuzz_harness name source)
  add_executable(${name} ${source} fuzz_common.c)
  target_link_libraries(${name} PRIVATE asnber::static)
  asnber_apply_sanitizer_options(${name})
  set_target_properties(
    ${name}
    PROPERTIES
      C_STANDARD 99
      C_STANDARD_REQUIRED ON
  )
  # 覆盖率插桩由全局 -fsanitize=fuzzer-no-link,... 提供；此处补一份无副作用。
  target_compile_options(${name} PRIVATE -fsanitize=fuzzer-no-link -fno-omit-frame-pointer)
  # 只在此处链接 libFuzzer 运行时（提供 main 与 fuzzing 循环）。
  target_link_options(${name} PRIVATE -fsanitize=fuzzer)
  # harness 不进 CTest：由 CI 或手动按固定时间预算运行并记录迭代数。
endfunction()

asnber_add_fuzz_harness(fuzz_decode_ber fuzz_decode_ber.c)
asnber_add_fuzz_harness(fuzz_decode_der fuzz_decode_der.c)
asnber_add_fuzz_harness(fuzz_reader fuzz_reader.c)
asnber_add_fuzz_harness(fuzz_roundtrip fuzz_roundtrip.c)
asnber_add_fuzz_harness(fuzz_schema_load fuzz_schema_load.c)

# schema-aware 解码使用真实 PKIX 生成表头。
asnber_add_fuzz_harness(fuzz_schema_decode fuzz_schema_decode.c)
target_include_directories(fuzz_schema_decode PRIVATE
  ${PROJECT_SOURCE_DIR}/modules/pkix/generated)

# 模块级 open/accessor harness：链接对应模块静态库，覆盖只读访问面。
if(TARGET asnber::pkix::static)
  asnber_add_fuzz_harness(fuzz_pkix_open fuzz_pkix_open.c)
  target_link_libraries(fuzz_pkix_open PRIVATE asnber::pkix::static)
else()
  message(WARNING "fuzz_pkix_open 需要 asnber::pkix::static；跳过")
endif()

if(TARGET asnber::pkcs1::static)
  asnber_add_fuzz_harness(fuzz_pkcs_open fuzz_pkcs_open.c)
  target_link_libraries(fuzz_pkcs_open PRIVATE asnber::pkcs)
else()
  message(WARNING "fuzz_pkcs_open 需要静态实现包 asnber::pkcs1::static；跳过")
endif()

if(TARGET asnber::cms::static)
  asnber_add_fuzz_harness(fuzz_cms_open fuzz_cms_open.c)
  target_link_libraries(fuzz_cms_open PRIVATE asnber::cms::static)
else()
  message(WARNING "fuzz_cms_open 需要 asnber::cms::static；跳过")
endif()

# asnberc 工具入口 harness（C++，链接 asnberc_lib 静态库）。
if(TARGET asnberc_lib)
  add_executable(fuzz_asnberc fuzz_asnberc.cpp)
  target_link_libraries(fuzz_asnberc PRIVATE asnberc_lib)
  asnber_apply_sanitizer_options(fuzz_asnberc)
  target_include_directories(fuzz_asnberc PRIVATE
    ${PROJECT_SOURCE_DIR}/tools/asnberc/src)
  set_target_properties(
    fuzz_asnberc
    PROPERTIES
      CXX_STANDARD 17
      CXX_STANDARD_REQUIRED ON
      CXX_EXTENSIONS OFF
  )
  target_compile_options(fuzz_asnberc PRIVATE
    -fsanitize=fuzzer-no-link -fno-exceptions -fno-rtti -fno-omit-frame-pointer)
  target_link_options(fuzz_asnberc PRIVATE -fsanitize=fuzzer)
endif()