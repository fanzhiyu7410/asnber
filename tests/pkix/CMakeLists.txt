# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT

# 模块用例只链模块目标：核心库由模块的 PUBLIC 依赖带入，直接再链一次会
# 让链接行重复出现 asnber_static（ld64 报 duplicate libraries）。
asnber_add_test(test_pkix_certificate test_pkix_certificate.c NO_CORE)
target_link_libraries(test_pkix_certificate PRIVATE asnber_test_support)

asnber_add_test(test_pkix_certificate_builder test_pkix_certificate_builder.c
              NO_CORE)
target_link_libraries(test_pkix_certificate_builder PRIVATE asnber_test_support)

asnber_add_test(test_pkix_crl test_pkix_crl.c NO_CORE)
target_link_libraries(test_pkix_crl PRIVATE asnber_test_support)

# 独立消费由 tests/consumer 的通用用例覆盖（含安装前缀重定位）。

if(TARGET asnber::pkix::static)
  target_link_libraries(test_pkix_certificate PRIVATE asnber::pkix::static)
  target_link_libraries(test_pkix_certificate_builder PRIVATE asnber::pkix::static)
  target_link_libraries(test_pkix_crl PRIVATE asnber::pkix::static)
else()
  target_link_libraries(test_pkix_certificate PRIVATE asnber::pkix::shared)
  target_link_libraries(test_pkix_certificate_builder PRIVATE asnber::pkix::shared)
  target_link_libraries(test_pkix_crl PRIVATE asnber::pkix::shared)
  if(WIN32)
    foreach(test_name test_pkix_certificate test_pkix_certificate_builder
                      test_pkix_crl)
      add_custom_command(
        TARGET ${test_name} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
          $<TARGET_FILE:asnber::pkix::shared>
          $<TARGET_FILE:asnber::shared>
          $<TARGET_FILE_DIR:${test_name}>
      )
    endforeach()
  endif()
endif()
