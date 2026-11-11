# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT

# 安装与 export：生成 asnberConfig.cmake / asnberTargets.cmake，供 find_package(asnber CONFIG) 消费。
include_guard(GLOBAL)

include(CMakePackageConfigHelpers)

function(asnber_install_library targets)
  install(
    TARGETS ${targets}
    EXPORT asnberTargets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  )

  install(
    DIRECTORY "${PROJECT_SOURCE_DIR}/include/"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
    FILES_MATCHING PATTERN "*.h"
  )

  install(
    FILES
      "${ASNBER_GENERATED_INCLUDE_DIR}/asnber/asnber_version.h"
      "${ASNBER_GENERATED_INCLUDE_DIR}/asnber/asnber_features.h"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/asnber"
  )

  set(asnber_cmake_dir "${CMAKE_INSTALL_LIBDIR}/cmake/asnber")

  install(
    EXPORT asnberTargets
    FILE asnberTargets.cmake
    NAMESPACE asnber::
    DESTINATION "${asnber_cmake_dir}"
  )

  configure_package_config_file(
    "${PROJECT_SOURCE_DIR}/cmake/asnberConfig.cmake.in"
    "${PROJECT_BINARY_DIR}/asnberConfig.cmake"
    INSTALL_DESTINATION "${asnber_cmake_dir}"
  )

  write_basic_package_version_file(
    "${PROJECT_BINARY_DIR}/asnberConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
  )

  install(
    FILES
      "${PROJECT_BINARY_DIR}/asnberConfig.cmake"
      "${PROJECT_BINARY_DIR}/asnberConfigVersion.cmake"
    DESTINATION "${asnber_cmake_dir}"
  )
endfunction()
