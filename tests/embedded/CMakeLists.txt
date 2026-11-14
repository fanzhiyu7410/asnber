# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT

# 嵌入式最小用例：静态池 / 无堆 / 无标准 IO。
# 宿主构建时注册为 CTest；交叉编译时只构建与链接，不做运行验证。

add_executable(test_embedded_pool embedded_pool.c)
asnber_apply_sanitizer_options(test_embedded_pool)
asnber_copy_sanitizer_runtime(test_embedded_pool)
set_target_properties(test_embedded_pool PROPERTIES C_STANDARD 99
                                                     C_STANDARD_REQUIRED ON)

if(TARGET asnber::static)
  target_link_libraries(test_embedded_pool PRIVATE asnber::static)
else()
  target_link_libraries(test_embedded_pool PRIVATE asnber::shared)
  if(WIN32)
    add_custom_command(
      TARGET test_embedded_pool POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:asnber::shared> $<TARGET_FILE_DIR:test_embedded_pool>
    )
    add_dependencies(test_embedded_pool asnber_shared)
  endif()
endif()

if(NOT CMAKE_CROSSCOMPILING)
  add_test(NAME test_embedded_pool COMMAND test_embedded_pool)
  asnber_apply_sanitizer_test_environment(test_embedded_pool)

  # 宿主测量：静态池 + PKIX 描述表 + 真实证书解码 的最小池尺寸。
  add_executable(test_pkix_pool test_pkix_pool.c)
  asnber_apply_sanitizer_options(test_pkix_pool)
  asnber_copy_sanitizer_runtime(test_pkix_pool)
  set_target_properties(test_pkix_pool PROPERTIES C_STANDARD 99
                                                   C_STANDARD_REQUIRED ON)
  target_include_directories(
    test_pkix_pool PRIVATE
      ${PROJECT_SOURCE_DIR}/modules/pkix/generated
      ${PROJECT_SOURCE_DIR}/tests/data
  )
  if(TARGET asnber::static)
    target_link_libraries(test_pkix_pool PRIVATE asnber::static)
  else()
    target_link_libraries(test_pkix_pool PRIVATE asnber::shared)
  endif()
  add_test(NAME test_pkix_pool COMMAND test_pkix_pool)
  asnber_apply_sanitizer_test_environment(test_pkix_pool)

  # 宿主测量：静态池 + 模块真实 open 的最小池，并验证池耗尽错误码。
  foreach(_module IN ITEMS pkcs12 cms)
    if(TARGET asnber::${_module}::static OR TARGET asnber::${_module}::shared)
      add_executable(test_${_module}_pool test_${_module}_pool.c)
      asnber_apply_sanitizer_options(test_${_module}_pool)
      asnber_copy_sanitizer_runtime(test_${_module}_pool)
      set_target_properties(test_${_module}_pool PROPERTIES C_STANDARD 99
                                                            C_STANDARD_REQUIRED ON)
      target_include_directories(
        test_${_module}_pool PRIVATE
          ${PROJECT_SOURCE_DIR}/tests/data
      )
      if(TARGET asnber::${_module}::static)
        target_link_libraries(test_${_module}_pool PRIVATE
                              asnber::${_module}::static)
      else()
        target_link_libraries(test_${_module}_pool PRIVATE
                              asnber::${_module}::shared)
        if(WIN32)
          add_custom_command(
            TARGET test_${_module}_pool POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
              $<TARGET_FILE:asnber::${_module}::shared>
              $<TARGET_FILE:asnber::shared>
              $<TARGET_FILE_DIR:test_${_module}_pool>
          )
          add_dependencies(test_${_module}_pool asnber_${_module}_shared asnber_shared)
        endif()
      endif()
      add_test(NAME test_${_module}_pool COMMAND test_${_module}_pool)
      asnber_apply_sanitizer_test_environment(test_${_module}_pool)
    endif()
  endforeach()
endif()

# cert-decode：宿主运行行为断言与池测量；交叉只构建、链接。
if(ASNBER_TRIM_PROFILE STREQUAL "cert-decode"
   AND (TARGET asnber::pkix::static OR TARGET asnber::pkix::shared))
  add_executable(test_pkix_cert_trim test_pkix_cert_trim.c)
  asnber_apply_sanitizer_options(test_pkix_cert_trim)
  asnber_copy_sanitizer_runtime(test_pkix_cert_trim)
  set_target_properties(test_pkix_cert_trim PROPERTIES C_STANDARD 99
                                                       C_STANDARD_REQUIRED ON)
  target_include_directories(
    test_pkix_cert_trim PRIVATE
      ${PROJECT_SOURCE_DIR}/modules/pkix/generated/certificate
      ${PROJECT_SOURCE_DIR}/tests/data
  )
  if(TARGET asnber::pkix::static)
    target_link_libraries(test_pkix_cert_trim PRIVATE asnber::pkix::static)
  else()
    target_link_libraries(test_pkix_cert_trim PRIVATE asnber::pkix::shared)
    if(WIN32)
      add_custom_command(
        TARGET test_pkix_cert_trim POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
          $<TARGET_FILE:asnber::pkix::shared>
          $<TARGET_FILE:asnber::shared>
          $<TARGET_FILE_DIR:test_pkix_cert_trim>
      )
      add_dependencies(test_pkix_cert_trim asnber_pkix_shared asnber_shared)
    endif()
  endif()

  if(NOT CMAKE_CROSSCOMPILING)
    add_test(NAME test_pkix_cert_trim COMMAND test_pkix_cert_trim)
    asnber_apply_sanitizer_test_environment(test_pkix_cert_trim)

    find_package(Python3 COMPONENTS Interpreter)
    if(Python3_Interpreter_FOUND AND TARGET asnber::static
       AND TARGET asnber::pkix::static)
      add_test(
        NAME test_trim_symbols
        COMMAND ${Python3_EXECUTABLE}
          ${PROJECT_SOURCE_DIR}/scripts/check_trim_symbols.py
          --archive $<TARGET_FILE:asnber::static>
          --archive $<TARGET_FILE:asnber::pkix::static>
      )
    endif()
  endif()
endif()

# cert-and-csr：宿主运行证书打开、最小证书/CSR 编解码与池测量；交叉只构建、链接。
if(ASNBER_TRIM_PROFILE STREQUAL "cert-and-csr"
   AND TARGET asnber::pkix::static
   AND TARGET asnber::pkcs10::static)
  add_executable(test_cert_csr test_cert_csr.c)
  asnber_apply_sanitizer_options(test_cert_csr)
  asnber_copy_sanitizer_runtime(test_cert_csr)
  set_target_properties(test_cert_csr PROPERTIES C_STANDARD 99
                                                 C_STANDARD_REQUIRED ON)
  target_include_directories(
    test_cert_csr PRIVATE
      ${PROJECT_SOURCE_DIR}/tests/data
  )
  target_link_libraries(test_cert_csr PRIVATE
                        asnber::pkix::static
                        asnber::pkcs10::static)

  if(NOT CMAKE_CROSSCOMPILING)
    add_test(NAME test_cert_csr COMMAND test_cert_csr)
    asnber_apply_sanitizer_test_environment(test_cert_csr)

    find_package(Python3 COMPONENTS Interpreter)
    if(Python3_Interpreter_FOUND)
      add_test(
        NAME test_cert_csr_symbols
        COMMAND ${Python3_EXECUTABLE}
          ${PROJECT_SOURCE_DIR}/scripts/check_trim_symbols.py
          --profile cert-and-csr
          --archive $<TARGET_FILE:asnber::static>
          --archive $<TARGET_FILE:asnber::pkix::static>
          --archive $<TARGET_FILE:asnber::pkcs10::static>
      )
    endif()
  endif()
endif()
