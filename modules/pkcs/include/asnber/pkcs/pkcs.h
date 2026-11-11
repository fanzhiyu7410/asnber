/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-pkcs 公共头文件（PKCS 系列聚合包）。
 *
 * 结构 API 已按标准拆分为独立包，本头文件只做聚合，保持既有 include 用法：
 *   - PKCS#1  → <asnber/pkcs1/pkcs1.h>   （asnber-pkcs1）
 *   - PKCS#8  → <asnber/pkcs8/pkcs8.h>   （asnber-pkcs8）
 *   - PKCS#10 → <asnber/pkcs10/pkcs10.h> （asnber-pkcs10）
 *   - PKCS#12 → <asnber/pkcs12/pkcs12.h> （asnber-pkcs12）
 *
 * 聚合包不产库、不导符号；链接 asnber::pkcs 会以 INTERFACE 依赖把四个实现包
 * 一并带给使用者。只读语义与生命周期约定见各实现包头文件。
 */

#ifndef ASNBER_PKCS_PKCS_H_INCLUDED
#define ASNBER_PKCS_PKCS_H_INCLUDED

/* 由 CMake 从 project(asnber-pkcs VERSION ...) 生成，源码树中不手写版本宏。 */
#include <asnber/pkcs/pkcs_version.h>

#include <asnber/pkcs1/pkcs1.h>
#include <asnber/pkcs10/pkcs10.h>
#include <asnber/pkcs12/pkcs12.h>
#include <asnber/pkcs8/pkcs8.h>

#endif /* ASNBER_PKCS_PKCS_H_INCLUDED */
