# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT

# 模块用例只链模块目标：核心库由模块的 PUBLIC 依赖带入。
asnber_add_test(test_ocsp_request test_ocsp_request.c NO_CORE)
target_link_libraries(test_ocsp_request PRIVATE asnber_test_support)

if(TARGET asnber::ocsp::static)
  target_link_libraries(test_ocsp_request PRIVATE asnber::ocsp::static)
else()
  target_link_libraries(test_ocsp_request PRIVATE asnber::ocsp::shared)
  if(WIN32)
    add_custom_command(
      TARGET test_ocsp_request POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:asnber::ocsp::shared>
        $<TARGET_FILE:asnber::shared>
        $<TARGET_FILE_DIR:test_ocsp_request>
    )
  endif()
endif()
