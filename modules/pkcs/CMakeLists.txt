# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT

# asnber-pkcs：PKCS 系列聚合包。自身不产库、不导符号，只提供伞头 pkcs.h、
# 版本头与 find_package 入口；结构 API 全部来自 asnber-pkcs1 / asnber-pkcs8 /
# asnber-pkcs10 / asnber-pkcs12 四个实现包，由 INTERFACE 目标 asnber::pkcs 转发。
cmake_minimum_required(VERSION 3.20)

project(
  asnber-pkcs
  VERSION 0.1.1
  DESCRIPTION "PKCS 系列聚合包（结构 API 由 asnber-pkcs1/8/10/12 提供）"
  LANGUAGES C CXX
)

# 聚合包依赖的四个实现包；缺一不可（modules/CMakeLists.txt 在配置期校验）。
set(ASNBER_PKCS_SUBMODULES pkcs1 pkcs8 pkcs10 pkcs12)
set(ASNBER_MODULE_PACKAGE_DEPENDS "")
foreach(dep IN LISTS ASNBER_PKCS_SUBMODULES)
  list(APPEND ASNBER_MODULE_PACKAGE_DEPENDS "asnber-${dep}")
endforeach()

asnber_generate_module_version_header(pkcs)

# 聚合目标没有自己的产物，只能转发到实现包。两种形态同时构建时取静态
# （静态链接无需分发 DLL）；只构建共享时转发共享。
if(ASNBER_BUILD_STATIC)
  set(ASNBER_PKCS_LINK_FLAVOR static)
else()
  set(ASNBER_PKCS_LINK_FLAVOR shared)
endif()

add_library(asnber_pkcs INTERFACE)
add_library(asnber::pkcs ALIAS asnber_pkcs)
set_target_properties(asnber_pkcs PROPERTIES EXPORT_NAME pkcs)
target_include_directories(
  asnber_pkcs
  INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${ASNBER_MODULE_GENERATED_INCLUDE_DIR}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
foreach(dep IN LISTS ASNBER_PKCS_SUBMODULES)
  target_link_libraries(asnber_pkcs INTERFACE
                        "asnber::${dep}::${ASNBER_PKCS_LINK_FLAVOR}")
endforeach()

asnber_install_interface_module(
  asnber-pkcs pkcs
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${ASNBER_MODULE_GENERATED_INCLUDE_DIR}"
  asnber_pkcs
)
