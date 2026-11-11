# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT

# 标准模块的构建与安装辅助。
# 模块只依赖核心公共 ABI；每个模块拥有独立包名、版本、导出集与头文件目录。
include_guard(GLOBAL)

include(CMakePackageConfigHelpers)

function(asnber_apply_module_settings target module_dir generated_dir define_name)
  set(generated_include_dirs)
  if(generated_dir)
    list(APPEND generated_include_dirs
      $<BUILD_INTERFACE:${generated_dir}>)
  endif()

  target_include_directories(
    ${target}
    PUBLIC
      $<BUILD_INTERFACE:${module_dir}/include>
      ${generated_include_dirs}
      $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
      ${module_dir}/src
  )

  target_compile_definitions(${target} PRIVATE ${define_name})

  # 模块共享构造支撑：header-only，仅构建期可见。必须包 BUILD_INTERFACE，
  # 否则静态库的 PRIVATE 依赖会以 LINK_ONLY 进入导出集引用未导出目标。
  if(TARGET asnber::module_support)
    target_link_libraries(${target}
      PRIVATE $<BUILD_INTERFACE:asnber::module_support>)
  endif()

  asnber_apply_common_settings(${target})
endfunction()

# package：包名，如 asnber-pkix
# name：命名空间片段，如 pkix
# module_dir：模块根目录
# generated_dir：模块版本头生成目录
# 其余参数：需要安装的模块目标
function(asnber_install_module package name module_dir generated_dir)
  set(module_targets ${ARGN})
  if(NOT module_targets)
    return()
  endif()

  install(
    TARGETS ${module_targets}
    EXPORT ${package}Targets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  )

  install(
    DIRECTORY "${module_dir}/include/"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
    FILES_MATCHING PATTERN "*.h"
  )

  install(
    FILES "${generated_dir}/asnber/${name}/${name}_version.h"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/asnber/${name}"
  )

  set(module_cmake_dir "${CMAKE_INSTALL_LIBDIR}/cmake/${package}")

  install(
    EXPORT ${package}Targets
    FILE ${package}Targets.cmake
    NAMESPACE asnber::${name}::
    DESTINATION "${module_cmake_dir}"
  )

  asnber_write_module_config(${package} "${module_cmake_dir}")
endfunction()

# 聚合包安装：目标是无产物的 INTERFACE 库，导出名直接是 asnber::<name>。
# package：包名，如 asnber-pkcs
# name：命名空间片段，同时也是导出名，如 pkcs
function(asnber_install_interface_module package name module_dir generated_dir target)
  install(TARGETS ${target} EXPORT ${package}Targets)

  install(
    DIRECTORY "${module_dir}/include/"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
    FILES_MATCHING PATTERN "*.h"
  )

  install(
    FILES "${generated_dir}/asnber/${name}/${name}_version.h"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/asnber/${name}"
  )

  set(module_cmake_dir "${CMAKE_INSTALL_LIBDIR}/cmake/${package}")

  install(
    EXPORT ${package}Targets
    FILE ${package}Targets.cmake
    NAMESPACE asnber::
    DESTINATION "${module_cmake_dir}"
  )

  asnber_write_module_config(${package} "${module_cmake_dir}")
endfunction()

# 写出模块包的 Config / ConfigVersion：依赖核心，并按需 find_dependency
# 其他由 ASNBER_MODULE_PACKAGE_DEPENDS 声明的包。
function(asnber_write_module_config package module_cmake_dir)
  set(ASNBER_MODULE_PACKAGE "${package}")
  set(ASNBER_CORE_VERSION "${asnber_VERSION}")

  # 门面包（如 asnber-pkcs）PUBLIC 链接其他包导出的 target，安装后的
  # Config 必须先 find_dependency 这些包，导入目标才能解析依赖名。
  set(ASNBER_MODULE_FIND_DEPENDENCIES "")
  if(DEFINED ASNBER_MODULE_PACKAGE_DEPENDS)
    foreach(dep IN LISTS ASNBER_MODULE_PACKAGE_DEPENDS)
      string(APPEND ASNBER_MODULE_FIND_DEPENDENCIES
             "find_dependency(${dep} CONFIG)\n")
    endforeach()
  endif()

  configure_package_config_file(
    "${asnber_SOURCE_DIR}/cmake/asnberModuleConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/${package}Config.cmake"
    INSTALL_DESTINATION "${module_cmake_dir}"
  )

  write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/${package}ConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
  )

  install(
    FILES
      "${CMAKE_CURRENT_BINARY_DIR}/${package}Config.cmake"
      "${CMAKE_CURRENT_BINARY_DIR}/${package}ConfigVersion.cmake"
    DESTINATION "${module_cmake_dir}"
  )
endfunction()
