/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-cms 公共子头文件：共享类型、导出宏与版本入口。
 */

#ifndef ASNBER_CMS_TYPES_H_INCLUDED
#define ASNBER_CMS_TYPES_H_INCLUDED

/* 由 CMake 从 project(asnber-cms VERSION ...) 生成，源码树中不手写版本宏。 */
#include <asnber/cms/cms_version.h>

#include <stddef.h>
#include <stdint.h>

#include <asnber/asnber_build.h>
#include <asnber/asnber_encode.h>
#include <asnber/asnber_node.h>

#if defined(ASNBER_CMS_STATIC)
#define ASNBER_CMS_API
#elif defined(_WIN32) || defined(__CYGWIN__)
#if defined(ASNBER_CMS_BUILDING_LIBRARY)
#define ASNBER_CMS_API __declspec(dllexport)
#else
#define ASNBER_CMS_API __declspec(dllimport)
#endif
#elif defined(__GNUC__) && __GNUC__ >= 4
#define ASNBER_CMS_API __attribute__((visibility("default")))
#else
#define ASNBER_CMS_API
#endif

/* CertificateChoices 分支判别值（与 RFC 5652 备选顺序一致）。 */
#define ASNBER_CMS_CERT_CHOICE_CERTIFICATE 0
#define ASNBER_CMS_CERT_CHOICE_EXTENDED 1
#define ASNBER_CMS_CERT_CHOICE_V1_ATTR_CERT 2
#define ASNBER_CMS_CERT_CHOICE_V2_ATTR_CERT 3
#define ASNBER_CMS_CERT_CHOICE_OTHER 4

/* SignerIdentifier 分支判别值。 */
#define ASNBER_CMS_SID_ISSUER_AND_SERIAL 0
#define ASNBER_CMS_SID_SUBJECT_KEY_IDENTIFIER 1

/* RevocationInfoChoice 分支判别值。 */
#define ASNBER_CMS_REVOCATION_CHOICE_CRL 0
#define ASNBER_CMS_REVOCATION_CHOICE_OTHER 1

#ifdef __cplusplus
extern "C" {
#endif

/* 不透明句柄；具体布局属于模块私有实现。 */
typedef struct asnber_cms_content_info asnber_cms_content_info_t;
typedef struct asnber_cms_signed_data asnber_cms_signed_data_t;
typedef struct asnber_cms_enveloped_data asnber_cms_enveloped_data_t;
typedef struct asnber_cms_encrypted_data asnber_cms_encrypted_data_t;
typedef struct asnber_cms_compressed_data asnber_cms_compressed_data_t;
typedef struct asnber_cms_authenticated_data asnber_cms_authenticated_data_t;

/* 返回模块版本字符串；静态存储，调用方不得释放。 */
ASNBER_CMS_API const char *asnber_cms_version_string(void);

#ifdef __cplusplus
}
#endif

#endif /* ASNBER_CMS_TYPES_H_INCLUDED */
