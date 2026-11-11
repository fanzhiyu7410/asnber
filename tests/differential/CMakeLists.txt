# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT
#
# 差分测试辅助工具 asnber_dump（读 DER 文件，输出规范 TLV 树）。
# 选择 ASNBER_BUILD_DIFFERENTIAL=ON 时构建；供 tests/differential/diff_asnber.py 使用，
# 不注册 CTest、不链接第三方参照工具。

if(NOT TARGET asnber::static AND NOT TARGET asnber::shared)
  return()
endif()

add_executable(asnber_dump asnber_dump.c)
asnber_apply_sanitizer_options(asnber_dump)
if(TARGET asnber::static)
  target_link_libraries(asnber_dump PRIVATE asnber::static)
else()
  target_link_libraries(asnber_dump PRIVATE asnber::shared)
endif()
set_target_properties(asnber_dump PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED ON)