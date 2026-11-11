# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT

# 六个独立消费工程：核心、PKIX、PKCS 门面、PKCS#1、PKCS#12、CMS。每个只
# find_package 对应包（PKCS#1 / PKCS#12 不引入 CMS 依赖），安装到临时前缀后以
# 共享/静态两种形态构建并运行，再整体移动前缀验证可重定位。

function(asnber_add_consumer_test name namespace package main sample)
  if(namespace STREQUAL "asnber")
    set(shared_target asnber::shared)
    set(static_target asnber::static)
    set(has_shared FALSE)
    set(has_static FALSE)
    if(TARGET asnber::shared)
      set(has_shared TRUE)
    endif()
    if(TARGET asnber::static)
      set(has_static TRUE)
    endif()
  elseif(namespace STREQUAL "pkcs")
    # 聚合包无自身产物，只有一个 INTERFACE 目标；两种链接模式都链接它，
    # 具体形态由包配置转发到四个实现包。
    set(shared_target asnber::pkcs)
    set(static_target asnber::pkcs)
    set(has_shared FALSE)
    set(has_static FALSE)
    if(TARGET asnber::pkcs)
      set(has_shared TRUE)
      set(has_static TRUE)
    endif()
  else()
    set(shared_target asnber::${namespace}::shared)
    set(static_target asnber::${namespace}::static)
    set(has_shared FALSE)
    set(has_static FALSE)
    if(TARGET asnber::${namespace}::shared)
      set(has_shared TRUE)
    endif()
    if(TARGET asnber::${namespace}::static)
      set(has_static TRUE)
    endif()
  endif()

  set(link_modes "")
  if(has_shared)
    list(APPEND link_modes shared)
  endif()
  if(has_static)
    list(APPEND link_modes static)
  endif()
  if(NOT link_modes)
    return()
  endif()
  string(REPLACE ";" "," link_modes_arg "${link_modes}")

  # 父工程启用 sanitizer 开关时 CMAKE_*_FLAGS 本身为空，插桩标志必须显式
  # 拼进来，否则独立消费工程链接已插桩静态库会缺运行时符号。
  string(STRIP "${CMAKE_C_FLAGS} ${ASNBER_SANITIZER_COMPILE_FLAGS}"
         _consumer_c_flags)
  string(STRIP "${CMAKE_CXX_FLAGS} ${ASNBER_SANITIZER_COMPILE_FLAGS}"
         _consumer_cxx_flags)
  string(STRIP "${CMAKE_EXE_LINKER_FLAGS} ${ASNBER_SANITIZER_LINK_FLAGS}"
         _consumer_linker_flags)

  add_test(
    NAME ${name}
    COMMAND
      ${CMAKE_COMMAND}
      -DASNBER_CONSUMER_BUILD_DIR=${CMAKE_BINARY_DIR}
      -DASNBER_CONSUMER_WORK_DIR=${CMAKE_CURRENT_BINARY_DIR}/${name}-work
      -DASNBER_CONSUMER_PACKAGE=${package}
      -DASNBER_CONSUMER_TARGET_SHARED=${shared_target}
      -DASNBER_CONSUMER_TARGET_STATIC=${static_target}
      -DASNBER_CONSUMER_MAIN=${CMAKE_CURRENT_SOURCE_DIR}/${main}
      -DASNBER_CONSUMER_SAMPLE=${CMAKE_SOURCE_DIR}/tests/data/${sample}
      -DASNBER_CONSUMER_CONFIG=$<CONFIG>
      -DASNBER_CONSUMER_GENERATOR=${CMAKE_GENERATOR}
      -DASNBER_CONSUMER_GENERATOR_PLATFORM=${CMAKE_GENERATOR_PLATFORM}
      -DASNBER_CONSUMER_C_COMPILER=${CMAKE_C_COMPILER}
      -DASNBER_CONSUMER_RC_COMPILER=${CMAKE_RC_COMPILER}
      -DASNBER_CONSUMER_BUILD_TYPE=${CMAKE_BUILD_TYPE}
      -DASNBER_CONSUMER_LINK_MODES=${link_modes_arg}
      -DASNBER_CONSUMER_C_FLAGS=${_consumer_c_flags}
      -DASNBER_CONSUMER_CXX_FLAGS=${_consumer_cxx_flags}
      -DASNBER_CONSUMER_EXE_LINKER_FLAGS=${_consumer_linker_flags}
      -P ${CMAKE_CURRENT_SOURCE_DIR}/test_consumer.cmake
  )
  asnber_apply_sanitizer_test_environment(${name})
  set_tests_properties(${name} PROPERTIES TIMEOUT 420)
endfunction()

asnber_add_consumer_test(
  test_consumer_core asnber asnber consumer_core.c cert_rsa_selfsigned.der)
asnber_add_consumer_test(
  test_consumer_pkix pkix asnber-pkix consumer_pkix.c cert_rsa_selfsigned.der)
asnber_add_consumer_test(
  test_consumer_pkcs pkcs asnber-pkcs consumer_pkcs.c key_rsa_pkcs8.der)
asnber_add_consumer_test(
  test_consumer_pkcs1 pkcs1 asnber-pkcs1 consumer_pkcs1.c
  key_rsa_pkcs1_public.der)
asnber_add_consumer_test(
  test_consumer_pkcs12 pkcs12 asnber-pkcs12 consumer_pkcs12.c
  pfx_rsa_unencrypted.der)
asnber_add_consumer_test(
  test_consumer_cms cms asnber-cms consumer_cms.c cms_rsa_attached.der)
