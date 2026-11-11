# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT

asnber_add_test(test_version_abi test_version_abi.c)
target_link_libraries(test_version_abi PRIVATE asnber_test_support)

asnber_add_test(test_ber_decode test_ber_decode.c)
target_link_libraries(test_ber_decode PRIVATE asnber_test_support)

asnber_add_test(test_struct_size test_struct_size.c)
target_link_libraries(test_struct_size PRIVATE asnber_test_support)

asnber_add_test(test_value_read test_value_read.c)
target_link_libraries(test_value_read PRIVATE asnber_test_support)

asnber_add_test(test_encode test_encode.c)
target_link_libraries(test_encode PRIVATE asnber_test_support)

asnber_add_test(test_der_strict test_der_strict.c)
target_link_libraries(test_der_strict PRIVATE asnber_test_support)

# test_any 只依赖公共 API + schema 探针（schema_probe 读取内部类型树，不依赖
# 隐藏 C++ 符号），共享/静态配置均可构建。
asnber_add_test(test_any test_any.c)
target_link_libraries(test_any PRIVATE asnber_test_support asnber_test_schema_probe)

asnber_add_test(test_build_any test_build_any.c)
target_link_libraries(test_build_any PRIVATE asnber_test_support)

asnber_add_test(test_schema_decode test_schema_decode.c)
target_link_libraries(test_schema_decode PRIVATE asnber_test_support)

asnber_add_test(test_reader test_reader.c)
target_link_libraries(test_reader PRIVATE asnber_test_support)

asnber_add_test(test_decode_feed test_decode_feed.c)
target_link_libraries(test_decode_feed PRIVATE asnber_test_support)
