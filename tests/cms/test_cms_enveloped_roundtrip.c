/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * asnber-cms EnvelopedData 往返：用公共 C API 解码再编码，逐字节比较。
 * 公共核心 ABI 没有“按描述表重编码”入口，因此往返分两段：
 *   1) ContentInfo 整段：通用 DER 解码 → 通用编码 → 与输入逐字节比较；
 *   2) `[0]` 内层裸 EnvelopedData：同样解码/编码/比较，并用模块 API 校验
 *      描述表能接受同一段字节。
 * 表数组随库编译，节点 0/1 的检入产物即测试使用的表。
 */

#include <asnber/asnber.h>
#include <asnber/cms/cms.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "../data/cms_enveloped_kari.h"
#include "../data/cms_enveloped_kekri.h"
#include "../data/cms_enveloped_ktri.h"
#include "../data/cms_enveloped_ktri_keyid.h"
#include "../data/cms_enveloped_ktri_multi.h"
#include "../data/cms_enveloped_pwri.h"
#include "check.h"

static asnber_ctx_t *make_ctx(void)
{
    asnber_ctx_config_t config;
    asnber_ctx_config_init(&config);
    asnber_ctx_t *ctx = NULL;
    if (asnber_ctx_create(&config, &ctx) != ASNBER_OK) {
        return NULL;
    }
    return ctx;
}

/* 通用 DER 解码 → 编码，要求输出与输入逐字节相同。 */
static int roundtrip_bytes(asnber_ctx_t *ctx, const uint8_t *der, size_t der_size)
{
    asnber_decode_options_t options;
    asnber_doc_t *doc = NULL;
    size_t consumed = 0;
    asnber_buf_t out;
    int equal = 0;

    asnber_decode_options_init(&options);
    options.struct_size = sizeof(options);
    options.encoding = ASNBER_ENCODING_DER;

    ASNBER_TEST_CHECK(asnber_decode_buffer(ctx, der, der_size, &options, &doc,
                                       &consumed) == ASNBER_OK);
    ASNBER_TEST_CHECK(consumed == der_size);

    memset(&out, 0, sizeof(out));
    ASNBER_TEST_CHECK(asnber_encode_buffer(ctx, doc, NULL, &out) == ASNBER_OK);
    equal = out.size == der_size && memcmp(out.data, der, der_size) == 0;
    (void)asnber_buf_release(ctx, &out);
    asnber_doc_destroy(doc);
    ASNBER_TEST_CHECK(equal);
    return 0;
}

static int roundtrip_sample(asnber_ctx_t *ctx, const uint8_t *der, size_t der_size)
{
    asnber_cms_content_info_t *info = NULL;
    asnber_cms_enveloped_data_t *env = NULL;
    const uint8_t *inner = NULL;
    size_t inner_size = 0;
    size_t count = 0;

    /* ContentInfo 整段往返。 */
    ASNBER_TEST_CHECK(roundtrip_bytes(ctx, der, der_size) == 0);

    /* 内层裸 EnvelopedData 往返 + 描述表接受同一段字节。 */
    ASNBER_TEST_CHECK(asnber_cms_content_info_open(ctx, der, der_size, &info) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_content_info_content(info, &inner, &inner_size) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(roundtrip_bytes(ctx, inner, inner_size) == 0);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_open(ctx, inner, inner_size, &env) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_cms_enveloped_data_recipient_count(env, &count) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(count >= 1);
    asnber_cms_enveloped_data_close(env);
    asnber_cms_content_info_close(info);
    return 0;
}

int main(void)
{
    asnber_ctx_t *ctx = make_ctx();
    ASNBER_TEST_CHECK(ctx != NULL);

    ASNBER_TEST_CHECK(roundtrip_sample(ctx, kCmsEnvelopedKtri,
                                     kCmsEnvelopedKtriSize) == 0);
    ASNBER_TEST_CHECK(roundtrip_sample(ctx, kCmsEnvelopedKtriMulti,
                                     kCmsEnvelopedKtriMultiSize) == 0);
    ASNBER_TEST_CHECK(roundtrip_sample(ctx, kCmsEnvelopedKtriKeyid,
                                     kCmsEnvelopedKtriKeyidSize) == 0);
    ASNBER_TEST_CHECK(roundtrip_sample(ctx, kCmsEnvelopedKari,
                                     kCmsEnvelopedKariSize) == 0);
    ASNBER_TEST_CHECK(roundtrip_sample(ctx, kCmsEnvelopedKekri,
                                     kCmsEnvelopedKekriSize) == 0);
    ASNBER_TEST_CHECK(roundtrip_sample(ctx, kCmsEnvelopedPwri,
                                     kCmsEnvelopedPwriSize) == 0);

    asnber_ctx_destroy(ctx);
    return 0;
}
