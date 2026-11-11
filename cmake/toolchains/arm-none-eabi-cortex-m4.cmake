# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT

# arm-none-eabi 交叉编译工具链（Cortex-M4F，裸机/嵌入式）。
#
# 用法：
#   cmake -S . -B build-arm \
#     -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/arm-none-eabi-cortex-m4.cmake \
#     -DASNBER_BUILD_SHARED=OFF -DASNBER_BUILD_STATIC=ON \
#     -DASNBER_FREESTANDING=ON -DASNBER_BUILD_MODULES=OFF -DASNBER_BUILD_TOOLS=OFF \
#     -DASNBER_BUILD_EMBEDDED_TEST=ON -DCMAKE_BUILD_TYPE=Release
#
# 目标参数按 Cortex-M4F 实际能力取值：
#   -mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard

set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR arm)

set(ASNBER_ARM_CPU_FLAGS "-mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard")

set(CMAKE_C_COMPILER arm-none-eabi-gcc)
set(CMAKE_CXX_COMPILER arm-none-eabi-g++)
set(CMAKE_ASM_COMPILER arm-none-eabi-gcc)
set(CMAKE_AR arm-none-eabi-ar)
set(CMAKE_RANLIB arm-none-eabi-ranlib)
set(CMAKE_OBJCOPY arm-none-eabi-objcopy)
set(CMAKE_SIZE arm-none-eabi-size)

# 链接阶段不能运行目标程序，用静态库探测即可。
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

set(CMAKE_C_FLAGS_INIT "${ASNBER_ARM_CPU_FLAGS} -ffunction-sections -fdata-sections")
set(CMAKE_CXX_FLAGS_INIT "${ASNBER_ARM_CPU_FLAGS} -ffunction-sections -fdata-sections")
set(CMAKE_EXE_LINKER_FLAGS_INIT "-specs=nosys.specs -Wl,--gc-sections -Wl,-Map=output.map")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
