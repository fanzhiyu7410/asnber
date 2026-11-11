/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-cms 公共头文件（伞头）：RFC 5652 / RFC 3274 结构访问与构造。
 *
 * 具体声明按结构拆分到同目录子头文件；本文件只做聚合，保持既有
 * `#include <asnber/cms/cms.h>` 用法不变。
 *
 * 本模块承载 RFC 5652 第 12.1 节展平模块生成的描述表，并自包含复制
 * SignedData 可达的 PKIX 类型（见 asnber/reconciliation.md）。只读语义：
 * 不验签、不计算摘要、不解密、不校验证书链；ANY 与属性集合只返回原始
 * TLV，密码学语义由调用方按 OID 二次解析。
 *
 * 生命周期：句柄由 open 创建、close 销毁；内部文档与 schema 随句柄创建
 * 和销毁。句柄借用调用方的 asnber_ctx_t，ctx 必须比句柄存活更久。所有由
 * 访问器返回的指针均借用句柄，close 后立即失效。
 */

#ifndef ASNBER_CMS_CMS_H_INCLUDED
#define ASNBER_CMS_CMS_H_INCLUDED

#include <asnber/cms/cms_types.h>

#include <asnber/cms/cms_content_info.h>
#include <asnber/cms/cms_signed_data.h>
#include <asnber/cms/cms_enveloped_data.h>
#include <asnber/cms/cms_encrypted_data.h>
#include <asnber/cms/cms_compressed_data.h>
#include <asnber/cms/cms_authenticated_data.h>

#include <asnber/cms/cms_content_info_builder.h>
#include <asnber/cms/cms_signed_builder.h>
#include <asnber/cms/cms_enveloped_builder.h>
#include <asnber/cms/cms_encrypted_builder.h>
#include <asnber/cms/cms_compressed_builder.h>
#include <asnber/cms/cms_authenticated_builder.h>

#endif /* ASNBER_CMS_CMS_H_INCLUDED */
