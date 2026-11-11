# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT

asnber_add_test(test_version test_version.c)
target_link_libraries(test_version PRIVATE asnber_test_support)

asnber_add_test(test_context_memory test_context_memory.c)
target_link_libraries(test_context_memory PRIVATE asnber_test_support)

asnber_add_test(test_dom test_dom.c)
target_link_libraries(test_dom PRIVATE asnber_test_support)

asnber_add_test(test_schema_runtime test_schema_runtime.c)
target_link_libraries(test_schema_runtime PRIVATE asnber_test_support
                      asnber_test_schema_probe)

asnber_add_test(test_schema_table test_schema_table.c)
# asnber_test_schema_compare 以 PUBLIC 依赖带入 asnber_test_schema_probe，
# 再直接链一次会让 probe 在链接行出现两次（ld64 报 duplicate libraries）。
target_link_libraries(test_schema_table PRIVATE asnber_test_support
                      asnber_test_schema_compare)

asnber_add_test(test_schema_names test_schema_names.c)
target_link_libraries(test_schema_names PRIVATE asnber_test_support)

# 共享构造层 X.509 原语（源码级，不属于公共 ABI）：直接包含
# modules/common/src/detail，只验证编码规则本身。
if(TARGET asnber::module_support)
  asnber_add_test(test_x509_primitives test_x509_primitives.cpp)
  target_link_libraries(test_x509_primitives PRIVATE asnber_test_support
                        asnber::module_support)
endif()
