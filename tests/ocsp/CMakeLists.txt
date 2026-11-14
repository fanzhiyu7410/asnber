# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT

# 模块用例只链模块目标：核心库由模块的 PUBLIC 依赖带入。
set(ASNBER_OCSP_TESTS test_ocsp_request test_ocsp_basic test_ocsp_builder)

foreach(test_name ${ASNBER_OCSP_TESTS})
  asnber_add_test(${test_name} ${test_name}.c NO_CORE)
  target_link_libraries(${test_name} PRIVATE asnber_test_support)
endforeach()

if(TARGET asnber::ocsp::static)
  foreach(test_name ${ASNBER_OCSP_TESTS})
    target_link_libraries(${test_name} PRIVATE asnber::ocsp::static)
  endforeach()
else()
  foreach(test_name ${ASNBER_OCSP_TESTS})
    target_link_libraries(${test_name} PRIVATE asnber::ocsp::shared)
  endforeach()
  if(WIN32)
    foreach(test_name ${ASNBER_OCSP_TESTS})
      add_custom_command(
        TARGET ${test_name} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
          $<TARGET_FILE:asnber::ocsp::shared>
          $<TARGET_FILE:asnber::shared>
          $<TARGET_FILE_DIR:${test_name}>
      )
      add_dependencies(${test_name} asnber_ocsp_shared asnber_shared)
    endforeach()
  endif()
endif()
