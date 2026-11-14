# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT

# 模块用例只链模块目标：核心库由模块的 PUBLIC 依赖带入，直接再链一次会
# 让链接行重复出现 asnber_static（ld64 报 duplicate libraries）。
set(ASNBER_PKCS8_TESTS
  test_pkcs8_builder
  test_pkcs8_structures
)

foreach(test_name IN LISTS ASNBER_PKCS8_TESTS)
  asnber_add_test(${test_name} ${test_name}.c NO_CORE)
  target_link_libraries(${test_name} PRIVATE asnber_test_support)

  if(TARGET asnber::pkcs8::static)
    target_link_libraries(${test_name} PRIVATE asnber::pkcs8::static)
  else()
    target_link_libraries(${test_name} PRIVATE asnber::pkcs8::shared)
    if(WIN32)
      add_custom_command(
        TARGET ${test_name} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
          $<TARGET_FILE:asnber::pkcs8::shared>
          $<TARGET_FILE:asnber::shared>
          $<TARGET_FILE_DIR:${test_name}>
      )
      add_dependencies(${test_name} asnber_pkcs8_shared asnber_shared)
    endif()
  endif()
endforeach()
