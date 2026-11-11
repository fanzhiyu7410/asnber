# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT

# 标准模块集合。每个子目录是一个独立 CMake 包，只依赖核心公共 ABI。
# 全局开关关闭时本目录不会被加入，包级开关随之失效。

# asnber-pkcs 是门面包：公共头聚合四个实现包的公共头，make/install 时以
# PUBLIC 依赖传递。四个实现包缺一不可，否则门包头无法自洽，故配置期拒绝。
if(ASNBER_BUILD_MODULE_PKCS)
  foreach(_pkcs_dep IN ITEMS PKCS1 PKCS8 PKCS10 PKCS12)
    if(NOT ASNBER_BUILD_MODULE_${_pkcs_dep})
      message(
        FATAL_ERROR
        "ASNBER_BUILD_MODULE_PKCS=ON 需要同时启用 ASNBER_BUILD_MODULE_${_pkcs_dep}；"
        "如需只构建部分标准，请关闭 ASNBER_BUILD_MODULE_PKCS 并直接使用对应实现包"
      )
    endif()
  endforeach()
endif()

# 模块共享构造支撑（header-only、不安装、不导出），必须先于消费者配置。
add_subdirectory(common)

if(ASNBER_BUILD_MODULE_PKIX)
  add_subdirectory(pkix)
endif()
if(ASNBER_BUILD_MODULE_CMS)
  add_subdirectory(cms)
endif()
# 实现包先于门面包，门面包才能引用它们的 target。
if(ASNBER_BUILD_MODULE_PKCS1)
  add_subdirectory(pkcs1)
endif()
if(ASNBER_BUILD_MODULE_PKCS8)
  add_subdirectory(pkcs8)
endif()
if(ASNBER_BUILD_MODULE_PKCS10)
  add_subdirectory(pkcs10)
endif()
if(ASNBER_BUILD_MODULE_PKCS12)
  add_subdirectory(pkcs12)
endif()
if(ASNBER_BUILD_MODULE_PKCS)
  add_subdirectory(pkcs)
endif()
