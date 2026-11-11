# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT
#
# 通用独立消费验证：
#   1) 安装到临时前缀 prefix，独立工程只 find_package(指定包) 并链接、
#      打开样本读一个字段；
#   2) 把整个安装前缀移动到 prefix-moved 后，用全新构建目录重新配置、
#      构建、运行，验证安装树可重定位。
#

foreach(required IN ITEMS ASNBER_CONSUMER_BUILD_DIR ASNBER_CONSUMER_WORK_DIR
                           ASNBER_CONSUMER_PACKAGE ASNBER_CONSUMER_MAIN
                           ASNBER_CONSUMER_SAMPLE)
  if(NOT DEFINED ${required})
    message(FATAL_ERROR "缺少参数 ${required}")
  endif()
endforeach()

if(NOT DEFINED ASNBER_CONSUMER_LINK_MODES OR ASNBER_CONSUMER_LINK_MODES STREQUAL "")
  set(ASNBER_CONSUMER_LINK_MODES "shared,static")
endif()
string(REPLACE "," ";" link_modes "${ASNBER_CONSUMER_LINK_MODES}")

set(prefix "${ASNBER_CONSUMER_WORK_DIR}/prefix")
file(REMOVE_RECURSE "${ASNBER_CONSUMER_WORK_DIR}")
file(MAKE_DIRECTORY "${ASNBER_CONSUMER_WORK_DIR}")

set(install_command
    ${CMAKE_COMMAND} --install "${ASNBER_CONSUMER_BUILD_DIR}" --prefix "${prefix}"
)
if(ASNBER_CONSUMER_CONFIG)
  list(APPEND install_command --config "${ASNBER_CONSUMER_CONFIG}")
endif()
execute_process(COMMAND ${install_command} RESULT_VARIABLE install_result)
if(NOT install_result EQUAL 0)
  message(FATAL_ERROR "安装失败：${install_result}")
endif()

# 模块描述表可能以 .bin 资源或内嵌数组形式随安装落地；二者都在本用例中
# 由消费方真实 open 样本证伪：若资源缺失，open 会失败。
file(GLOB_RECURSE installed_tables "${prefix}/*.bin")
if(installed_tables)
  message(STATUS "${ASNBER_CONSUMER_PACKAGE} 安装包含描述表资源：${installed_tables}")
else()
  message(STATUS "${ASNBER_CONSUMER_PACKAGE} 描述表以内嵌数组随库安装（无 .bin 文件）")
endif()

set(consumer_cmake "${ASNBER_CONSUMER_WORK_DIR}/CMakeLists.txt")
file(TO_CMAKE_PATH "${ASNBER_CONSUMER_MAIN}" consumer_main_path)
file(WRITE "${consumer_cmake}" "
cmake_minimum_required(VERSION 3.20)
project(consumer_${ASNBER_CONSUMER_PACKAGE} C)

find_package(${ASNBER_CONSUMER_PACKAGE} CONFIG REQUIRED)

add_executable(consumer \"${consumer_main_path}\")
if(LINK_MODE STREQUAL \"static\")
  target_link_libraries(consumer PRIVATE ${ASNBER_CONSUMER_TARGET_STATIC})
else()
  target_link_libraries(consumer PRIVATE ${ASNBER_CONSUMER_TARGET_SHARED})
endif()
")

function(run_consumer_phase phase prefix_dir)
  foreach(link_mode IN LISTS link_modes)
    set(mode_dir "${ASNBER_CONSUMER_WORK_DIR}/${phase}/${link_mode}")
    file(MAKE_DIRECTORY "${mode_dir}")

    set(configure_command
        ${CMAKE_COMMAND} -S "${ASNBER_CONSUMER_WORK_DIR}" -B "${mode_dir}"
        -DLINK_MODE=${link_mode} -DCMAKE_PREFIX_PATH=${prefix_dir}
    )
    if(ASNBER_CONSUMER_GENERATOR)
      list(APPEND configure_command -G "${ASNBER_CONSUMER_GENERATOR}")
    endif()
    if(ASNBER_CONSUMER_GENERATOR_PLATFORM)
      list(APPEND configure_command -A "${ASNBER_CONSUMER_GENERATOR_PLATFORM}")
    endif()
    if(ASNBER_CONSUMER_C_COMPILER)
      list(APPEND configure_command -DCMAKE_C_COMPILER=${ASNBER_CONSUMER_C_COMPILER})
    endif()
    # Windows + clang 下 CMake 需要显式资源编译器；父工程已探测到就透传，
    # 否则独立工程会因找不到 RC 编译器而配置失败。
    if(ASNBER_CONSUMER_RC_COMPILER)
      list(APPEND configure_command -DCMAKE_RC_COMPILER=${ASNBER_CONSUMER_RC_COMPILER})
    endif()
    if(ASNBER_CONSUMER_BUILD_TYPE)
      list(APPEND configure_command -DCMAKE_BUILD_TYPE=${ASNBER_CONSUMER_BUILD_TYPE})
    endif()
    # 父工程带插桩标志（如 ASan/UBSan）时，独立消费工程必须同步，
    # 否则链接已插桩静态库会缺运行时符号。
    if(ASNBER_CONSUMER_C_FLAGS)
      list(APPEND configure_command "-DCMAKE_C_FLAGS=${ASNBER_CONSUMER_C_FLAGS}")
    endif()
    if(ASNBER_CONSUMER_CXX_FLAGS)
      list(APPEND configure_command "-DCMAKE_CXX_FLAGS=${ASNBER_CONSUMER_CXX_FLAGS}")
    endif()
    if(ASNBER_CONSUMER_EXE_LINKER_FLAGS)
      list(APPEND configure_command
           "-DCMAKE_EXE_LINKER_FLAGS=${ASNBER_CONSUMER_EXE_LINKER_FLAGS}")
    endif()

    execute_process(COMMAND ${configure_command} RESULT_VARIABLE configure_result)
    if(NOT configure_result EQUAL 0)
      message(FATAL_ERROR "${phase}/${link_mode} 配置失败：${configure_result}")
    endif()

    set(build_command ${CMAKE_COMMAND} --build "${mode_dir}")
    if(ASNBER_CONSUMER_CONFIG)
      list(APPEND build_command --config "${ASNBER_CONSUMER_CONFIG}")
    endif()
    execute_process(COMMAND ${build_command} RESULT_VARIABLE build_result)
    if(NOT build_result EQUAL 0)
      message(FATAL_ERROR "${phase}/${link_mode} 构建失败：${build_result}")
    endif()

    set(consumer_exe "${mode_dir}/consumer")
    if(WIN32)
      set(consumer_exe "${mode_dir}/${ASNBER_CONSUMER_CONFIG}/consumer.exe")
      if(NOT EXISTS "${consumer_exe}")
        set(consumer_exe "${mode_dir}/consumer.exe")
      endif()
    endif()

    # 运行时库搜索路径按平台取分隔符：Windows 用 PATH（DLL 在 bin/），
    # Unix 用 LD_LIBRARY_PATH/DYLD_LIBRARY_PATH（共享库在 lib/lib64）。
    # 变量必须加引号展开：Windows 的 PATH 以 ';' 分隔，未加引号会被 CMake
    # 当成列表拆分，导致 `cmake -E env` 收到多个参数。
    if(WIN32)
      set(consumer_env "PATH=${prefix_dir}/bin;$ENV{PATH}")
    elseif(APPLE)
      set(consumer_env
          "DYLD_LIBRARY_PATH=${prefix_dir}/lib:${prefix_dir}/lib64:$ENV{DYLD_LIBRARY_PATH}")
    else()
      set(consumer_env
          "LD_LIBRARY_PATH=${prefix_dir}/lib:${prefix_dir}/lib64:$ENV{LD_LIBRARY_PATH}")
    endif()

    execute_process(
      COMMAND ${CMAKE_COMMAND} -E env "${consumer_env}"
              "${consumer_exe}" "${ASNBER_CONSUMER_SAMPLE}"
      RESULT_VARIABLE run_result
    )
    if(NOT run_result EQUAL 0)
      message(FATAL_ERROR "${phase}/${link_mode} 运行失败：${run_result}")
    endif()
  endforeach()
endfunction()

run_consumer_phase(origin "${prefix}")

# 把安装树整体换一个前缀，验证包配置不写入绝对路径。
set(moved_prefix "${ASNBER_CONSUMER_WORK_DIR}/prefix-moved")
file(RENAME "${prefix}" "${moved_prefix}")
run_consumer_phase(moved "${moved_prefix}")

message(STATUS "${ASNBER_CONSUMER_PACKAGE} 独立消费与重定位通过：${link_modes}")
