# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT

# 模块共享构造支撑：源码级、header-only。
# 该目标只把 modules/common/src 暴露给模块构建单元，不产生编译产物、
# 不安装、不导出，也不新增任何 ABI 符号。消费者通过
# asnber_apply_module_settings 以 $<BUILD_INTERFACE:...> 方式接入。
add_library(asnber_module_support INTERFACE)
add_library(asnber::module_support ALIAS asnber_module_support)

target_include_directories(
  asnber_module_support
  INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
)

# 头文件使用 C++17 特性（inline 变量、if constexpr 等），由该目标声明语言
# 标准要求，消费者自动继承。MSVC 默认按 C++14 编译，缺少这条会以
# error C7525 拒绝 inline 变量。
target_compile_features(asnber_module_support
                        INTERFACE cxx_std_${ASNBER_CXX_STANDARD})
