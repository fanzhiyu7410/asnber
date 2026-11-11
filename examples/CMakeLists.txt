# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT

# 消费示例：分别以 C 与 C++ 编译，验证公共头文件只依赖 C ABI。
if(TARGET asnber::shared)
  set(ASNBER_EXAMPLE_LIBRARY asnber::shared)
else()
  set(ASNBER_EXAMPLE_LIBRARY asnber::static)
endif()

add_executable(asnber_example_c c/example_decode.c)
target_link_libraries(asnber_example_c PRIVATE ${ASNBER_EXAMPLE_LIBRARY})
set_target_properties(asnber_example_c PROPERTIES LINKER_LANGUAGE CXX)

add_executable(asnber_example_cpp cpp/example_usage.cpp)
target_compile_features(asnber_example_cpp PRIVATE cxx_std_17)
target_link_libraries(asnber_example_cpp PRIVATE ${ASNBER_EXAMPLE_LIBRARY})

if(MSVC)
  target_compile_options(asnber_example_c PRIVATE /utf-8)
  target_compile_options(asnber_example_cpp PRIVATE /utf-8)
endif()

# 裁切集成参考。静态库优先，和嵌入式只链静态库的用法一致。
if(TARGET asnber::pkix::static)
  set(ASNBER_EXAMPLE_PKIX asnber::pkix::static)
elseif(TARGET asnber::pkix::shared)
  set(ASNBER_EXAMPLE_PKIX asnber::pkix::shared)
endif()
if(TARGET asnber::pkcs10::static)
  set(ASNBER_EXAMPLE_PKCS10 asnber::pkcs10::static)
elseif(TARGET asnber::pkcs10::shared)
  set(ASNBER_EXAMPLE_PKCS10 asnber::pkcs10::shared)
endif()

if(ASNBER_EXAMPLE_PKIX)
  add_executable(asnber_example_cert_decode c/example_cert_decode.c)
  set_target_properties(asnber_example_cert_decode PROPERTIES
                        C_STANDARD 99
                        C_STANDARD_REQUIRED ON
                        LINKER_LANGUAGE CXX)
  target_include_directories(asnber_example_cert_decode PRIVATE
                             ${PROJECT_SOURCE_DIR}/tests/data)
  target_link_libraries(asnber_example_cert_decode PRIVATE ${ASNBER_EXAMPLE_PKIX})
  if(MSVC)
    target_compile_options(asnber_example_cert_decode PRIVATE /utf-8)
  endif()
endif()

if(ASNBER_EXAMPLE_PKIX AND ASNBER_EXAMPLE_PKCS10
   AND ASNBER_ENABLE_ENCODE AND ASNBER_ENABLE_BUILD_API
   AND ASNBER_PKIX_ENABLE_BUILDER)
  add_executable(asnber_example_cert_csr c/example_cert_csr.c)
  set_target_properties(asnber_example_cert_csr PROPERTIES
                        C_STANDARD 99
                        C_STANDARD_REQUIRED ON
                        LINKER_LANGUAGE CXX)
  target_include_directories(asnber_example_cert_csr PRIVATE
                             ${PROJECT_SOURCE_DIR}/tests/data)
  target_link_libraries(asnber_example_cert_csr PRIVATE
                        ${ASNBER_EXAMPLE_PKIX}
                        ${ASNBER_EXAMPLE_PKCS10})
  if(MSVC)
    target_compile_options(asnber_example_cert_csr PRIVATE /utf-8)
  endif()
endif()

# PKCS#1 / PKCS#8 / PKCS#12 / CMS。静态库优先。编码关闭时不编这些示例。
function(asnber_example_prefer_static out_var static_target shared_target)
  if(TARGET ${static_target})
    set(${out_var} ${static_target} PARENT_SCOPE)
  elseif(TARGET ${shared_target})
    set(${out_var} ${shared_target} PARENT_SCOPE)
  else()
    set(${out_var} "" PARENT_SCOPE)
  endif()
endfunction()

asnber_example_prefer_static(ASNBER_EXAMPLE_PKCS1 asnber::pkcs1::static
                           asnber::pkcs1::shared)
asnber_example_prefer_static(ASNBER_EXAMPLE_PKCS8 asnber::pkcs8::static
                           asnber::pkcs8::shared)
asnber_example_prefer_static(ASNBER_EXAMPLE_PKCS12 asnber::pkcs12::static
                           asnber::pkcs12::shared)
asnber_example_prefer_static(ASNBER_EXAMPLE_CMS asnber::cms::static
                           asnber::cms::shared)

function(asnber_add_module_example target source library)
  if(NOT library OR NOT ASNBER_ENABLE_ENCODE OR NOT ASNBER_ENABLE_BUILD_API)
    return()
  endif()
  add_executable(${target} ${source})
  set_target_properties(${target} PROPERTIES
                        C_STANDARD 99
                        C_STANDARD_REQUIRED ON
                        LINKER_LANGUAGE CXX)
  target_include_directories(${target} PRIVATE
                             ${PROJECT_SOURCE_DIR}/tests/data)
  target_link_libraries(${target} PRIVATE ${library})
  if(MSVC)
    target_compile_options(${target} PRIVATE /utf-8)
  endif()
endfunction()

asnber_add_module_example(asnber_example_pkcs1 c/example_pkcs1.c
                        "${ASNBER_EXAMPLE_PKCS1}")
asnber_add_module_example(asnber_example_pkcs8 c/example_pkcs8.c
                        "${ASNBER_EXAMPLE_PKCS8}")
asnber_add_module_example(asnber_example_pkcs12 c/example_pkcs12.c
                        "${ASNBER_EXAMPLE_PKCS12}")
asnber_add_module_example(asnber_example_cms c/example_cms.c
                        "${ASNBER_EXAMPLE_CMS}")
