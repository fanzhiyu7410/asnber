# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT

add_library(asnber_test_support INTERFACE)
target_include_directories(asnber_test_support INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

# 共用比较辅助：字节/文本相等与 TLV 外层标签改写，供各用例共享一份实现。
add_library(asnber_test_compare STATIC test_compare.c)
target_include_directories(
  asnber_test_compare
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
  PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${ASNBER_GENERATED_INCLUDE_DIR}
)
target_link_libraries(asnber_test_support INTERFACE asnber_test_compare)

# 测试专用 schema 探针：读取内部类型树并投影为 C 可见结构。
# 只服务测试，不进入公共头或核心库。
add_library(asnber_test_schema_probe STATIC schema_probe.cpp)
target_link_libraries(asnber_test_schema_probe PUBLIC asnber_test_support)
target_include_directories(
  asnber_test_schema_probe
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
  PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/src
    ${ASNBER_GENERATED_INCLUDE_DIR}
)
set_target_properties(
  asnber_test_schema_probe
  PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)
if(MSVC)
  target_compile_options(asnber_test_schema_probe PRIVATE /utf-8)
endif()

asnber_add_test(test_support test_support.c)
target_link_libraries(test_support PRIVATE asnber_test_support)

# 测试专用 schema 等价比较：逐类型/字段/约束比较两条已封存类型树。
add_library(asnber_test_schema_compare STATIC schema_compare.c)
target_link_libraries(asnber_test_schema_compare PUBLIC asnber_test_schema_probe)
target_include_directories(
  asnber_test_schema_compare
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
  PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${ASNBER_GENERATED_INCLUDE_DIR}
)
