/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 裁剪场景的编译用例：只包含解码子头与四个 PKCS 公共头，不包含
 * <asnber/asnber.h> 伞头。作为 tests/headers 的 OBJECT 成员只编译不链接，
 * 用于证明“按子头包含”的头文件集合自足。
 *
 * 注意：本文件只验证声明可用，不做运行时调用。
 */

#include <stddef.h>
#include <stdint.h>

#include <asnber/asnber_allocator.h>
#include <asnber/asnber_decode.h>
#include <asnber/asnber_error.h>
#include <asnber/asnber_export.h>
#include <asnber/asnber_node.h>
#include <asnber/asnber_schema.h>
#include <asnber/asnber_tag.h>
#include <asnber/asnber_warning.h>

#include <asnber/pkcs1/pkcs1.h>
#include <asnber/pkcs8/pkcs8.h>
#include <asnber/pkcs10/pkcs10.h>
#include <asnber/pkcs12/pkcs12.h>

int asnber_decode_only_headers_compile(void);

int asnber_decode_only_headers_compile(void)
{
    asnber_ctx_t *ctx = NULL;
    asnber_doc_t *doc = NULL;
    size_t consumed = 0;
    asnber_decode_options_t options;
    const uint8_t der[1] = {0};

    asnber_pkcs_rsa_public_key_t *rsa_public = NULL;
    asnber_pkcs_private_key_info_t *private_key_info = NULL;
    asnber_pkcs_certification_request_t *request = NULL;
    asnber_pkcs12_pfx_t *pfx = NULL;

    asnber_decode_options_init(&options);
    (void)doc;
    (void)consumed;

    if (ctx == NULL) {
        return 0;
    }

    (void)asnber_decode_buffer(ctx, der, sizeof(der), &options, &doc, &consumed);
    (void)asnber_pkcs_rsa_public_key_open(ctx, der, sizeof(der), &rsa_public);
    (void)asnber_pkcs_private_key_info_open(ctx, der, sizeof(der),
                                          &private_key_info);
    (void)asnber_pkcs_certification_request_open(ctx, der, sizeof(der), &request);
    (void)asnber_pkcs12_pfx_open(ctx, der, sizeof(der), &pfx);
    return 0;
}
