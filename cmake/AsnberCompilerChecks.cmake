# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT

# 编译选项与告警分层。
# 公共头文件只暴露 C ABI，因此 C++ 标准要求对消费者保持 PRIVATE。
include_guard(GLOBAL)

# sanitizer 插桩选项的唯一来源：库、工具与测试可执行文件共用同一组
# 编译/链接标志。只有两者都覆盖，仅打开开关的构建才不会被
# `undefined reference to __asan_init` 卡住。
set(ASNBER_SANITIZER_COMPILE_OPTIONS "")
set(ASNBER_SANITIZER_LINK_OPTIONS "")
set(ASNBER_SANITIZER_COMPILE_FLAGS "")
set(ASNBER_SANITIZER_LINK_FLAGS "")
if(ASNBER_ENABLE_SANITIZERS AND NOT MSVC)
  set(ASNBER_SANITIZER_COMPILE_OPTIONS
      -fsanitize=address,undefined
      -fno-omit-frame-pointer)
  set(ASNBER_SANITIZER_LINK_OPTIONS -fsanitize=address,undefined)
  # 独立消费工程只接受字符串形式的 C_FLAGS/链接标志，这里给同一组选项的
  # 空格拼接版本，避免两处定义漂移。
  string(JOIN " " ASNBER_SANITIZER_COMPILE_FLAGS ${ASNBER_SANITIZER_COMPILE_OPTIONS})
  string(JOIN " " ASNBER_SANITIZER_LINK_FLAGS ${ASNBER_SANITIZER_LINK_OPTIONS})
endif()

# Windows + Clang 的 ASan 运行时是动态 DLL（Windows 目标不支持 -static-libsan）。
# 若 DLL 不在 PATH、也没有复制到可执行文件旁，构建期工具与所有测试会以
# 0xc0000135 退出并弹出“找不到 DLL”。这里集中定位运行时，供构建目标复制
# 与 CTest 环境使用；不依赖 ASNBER_ENABLE_SANITIZERS，因为插桩标志也可能由
# 调用方通过 CMAKE_C_FLAGS/CMAKE_CXX_FLAGS 直接传入。
set(ASNBER_SANITIZER_RUNTIME_DLL "")
set(ASNBER_SANITIZER_RUNTIME_DIR "")
set(ASNBER_SANITIZER_TEST_ENVIRONMENT "")

if(WIN32 AND NOT MSVC AND CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  string(CONCAT _asnber_sanitize_flags
         "${CMAKE_C_FLAGS} ${CMAKE_CXX_FLAGS} ${CMAKE_EXE_LINKER_FLAGS}")
  if(ASNBER_ENABLE_SANITIZERS OR _asnber_sanitize_flags MATCHES "-fsanitize=[^ ]*address")
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
      if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|ARM64)$")
        set(_asnber_sanitizer_arch aarch64)
      else()
        set(_asnber_sanitizer_arch x86_64)
      endif()
    else()
      set(_asnber_sanitizer_arch i386)
    endif()

    # 优先用编译器自己的 resource dir，确保运行时版本与编译器一致；
    # 取不到时再按安装目录回退匹配。
    execute_process(
      COMMAND "${CMAKE_CXX_COMPILER}" -print-resource-dir
      OUTPUT_VARIABLE _asnber_resource_dir
      OUTPUT_STRIP_TRAILING_WHITESPACE
      RESULT_VARIABLE _asnber_resource_result
      ERROR_QUIET)
    if(_asnber_resource_result EQUAL 0 AND EXISTS
       "${_asnber_resource_dir}/lib/windows/clang_rt.asan_dynamic-${_asnber_sanitizer_arch}.dll")
      set(ASNBER_SANITIZER_RUNTIME_DLL
          "${_asnber_resource_dir}/lib/windows/clang_rt.asan_dynamic-${_asnber_sanitizer_arch}.dll")
    else()
      get_filename_component(_asnber_compiler_dir "${CMAKE_CXX_COMPILER}" DIRECTORY)
      file(GLOB _asnber_asan_runtime_candidates
           "${_asnber_compiler_dir}/../lib/clang/*/lib/windows/clang_rt.asan_dynamic-${_asnber_sanitizer_arch}.dll")
      if(_asnber_asan_runtime_candidates)
        list(SORT _asnber_asan_runtime_candidates COMPARE NATURAL ORDER DESCENDING)
        list(GET _asnber_asan_runtime_candidates 0 ASNBER_SANITIZER_RUNTIME_DLL)
      endif()
    endif()
    if(ASNBER_SANITIZER_RUNTIME_DLL)
      get_filename_component(ASNBER_SANITIZER_RUNTIME_DIR
                             "${ASNBER_SANITIZER_RUNTIME_DLL}" DIRECTORY)
      # CTest 的 ENVIRONMENT 是“VAR=value”列表；Windows PATH 自带 ';'，
      # 必须转义，否则会被拆成多个环境变量项。
      set(_asnber_test_path "${ASNBER_SANITIZER_RUNTIME_DIR};$ENV{PATH}")
      string(REPLACE ";" "\\;" _asnber_test_path "${_asnber_test_path}")
      set(ASNBER_SANITIZER_TEST_ENVIRONMENT "PATH=${_asnber_test_path}")
    else()
      message(WARNING
        "未找到 clang_rt.asan_dynamic-${_asnber_sanitizer_arch}.dll；"
        "ASan 构建的测试可能因缺少运行时 DLL 而失败。")
    endif()
  endif()
endif()

# 把 ASan 运行时复制到目标输出目录；对静态库目标为空操作意义，但无害。
function(asnber_copy_sanitizer_runtime target)
  if(NOT ASNBER_SANITIZER_RUNTIME_DLL OR NOT TARGET ${target})
    return()
  endif()
  get_target_property(_asnber_target_type ${target} TYPE)
  if(_asnber_target_type STREQUAL "STATIC_LIBRARY"
     OR _asnber_target_type STREQUAL "OBJECT_LIBRARY")
    return()
  endif()
  add_custom_command(
    TARGET ${target} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      "${ASNBER_SANITIZER_RUNTIME_DLL}" "$<TARGET_FILE_DIR:${target}>"
    VERBATIM
  )
endfunction()

# 给已注册的 CTest 用例补上 sanitizer 运行时目录；对未启用 ASan 的构建为空操作。
function(asnber_apply_sanitizer_test_environment test_name)
  if(NOT ASNBER_SANITIZER_TEST_ENVIRONMENT)
    return()
  endif()
  set_tests_properties(${test_name}
                       PROPERTIES ENVIRONMENT "${ASNBER_SANITIZER_TEST_ENVIRONMENT}")
endfunction()

# 把 sanitizer 编译与链接标志应用到目标；开关关闭时为空操作。
# 所有链接插桩库的可执行文件都必须调用，否则链接期会缺运行时符号。
function(asnber_apply_sanitizer_options target)
  if(NOT ASNBER_SANITIZER_COMPILE_OPTIONS OR NOT TARGET ${target})
    return()
  endif()
  target_compile_options(${target} PRIVATE ${ASNBER_SANITIZER_COMPILE_OPTIONS})
  target_link_options(${target} PRIVATE ${ASNBER_SANITIZER_LINK_OPTIONS})
endfunction()

# 核心与模块共享的方言、告警、可见性与 sanitizer 设置。
# 调用方负责补充各自的 include 目录与构建期定义。
function(asnber_apply_common_settings target)
  target_compile_features(${target} PRIVATE cxx_std_${ASNBER_CXX_STANDARD})

  set_target_properties(
    ${target}
    PROPERTIES
      CXX_EXTENSIONS OFF
      CXX_VISIBILITY_PRESET hidden
      VISIBILITY_INLINES_HIDDEN ON
  )

  if(ASNBER_FREESTANDING)
    target_compile_definitions(${target} PRIVATE ASNBER_FREESTANDING=1)
  endif()

  if(MSVC)
    # /EHs-c- 和 /GR- 已由根 CMakeLists.txt 通过 CMAKE_CXX_FLAGS_INIT
    # 统一注入，避免与 CMake 在 ItemDefinitionGroup 里写的 Sync 冲突。
    target_compile_definitions(${target} PRIVATE _HAS_EXCEPTIONS=0)
  else()
    target_compile_options(${target} PRIVATE -fno-exceptions -fno-rtti)
  endif()

  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8)
  else()
    target_compile_options(
      ${target}
      PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wshadow
        -Wconversion
        -Wsign-conversion
    )
  endif()

  if(ASNBER_WARNINGS_AS_ERRORS)
    if(MSVC)
      target_compile_options(${target} PRIVATE /WX)
    else()
      target_compile_options(${target} PRIVATE -Werror)
    endif()
  endif()

  if(ASNBER_ENABLE_SANITIZERS)
    if(MSVC)
      message(WARNING "ASNBER_ENABLE_SANITIZERS 在 MSVC 下未接入，请改用 clang-cl 或宿主平台工具链")
    else()
      asnber_apply_sanitizer_options(${target})
    endif()
  endif()

  asnber_copy_sanitizer_runtime(${target})
endfunction()

# 核心库目标设置：核心 include 目录、生成版本头目录、内部 src 目录与核心构建期定义。
function(asnber_apply_library_settings target)
  set(generated_include_dirs)
  if(ASNBER_GENERATED_INCLUDE_DIR)
    list(APPEND generated_include_dirs
      $<BUILD_INTERFACE:${ASNBER_GENERATED_INCLUDE_DIR}>)
  endif()

  target_include_directories(
    ${target}
    PUBLIC
      $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
      ${generated_include_dirs}
      $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
      ${PROJECT_SOURCE_DIR}/src
  )

  target_compile_definitions(${target} PRIVATE ASNBER_BUILDING_LIBRARY)

  asnber_apply_common_settings(${target})
endfunction()
