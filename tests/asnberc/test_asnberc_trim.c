/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * 裁剪后的 PKIX 描述表必须可加载、可解码真实证书，并保留根字段名。
 */
#include <asnber/asnber.h>

#include <stdio.h>
#include <string.h>

#include "pkix_trim_schema.h"
#include "cert_rsa_selfsigned.h"

/*
 * 名称表是 NUL 结尾字符串的拼接；按字节搜索足以判断某个类型名是否还在表里。
 * 只用于正向/负向断言，不依赖字符串边界。
 */
static int table_contains(const char *needle)
{
    const size_t needle_size = strlen(needle);
    size_t i = 0;

    if (needle_size == 0 || needle_size > kPKIXFlattened2009Schema_size) {
        return 0;
    }
    for (i = 0; i + needle_size <= kPKIXFlattened2009Schema_size; ++i) {
        if (memcmp(kPKIXFlattened2009Schema + i, needle, needle_size) == 0) {
            return 1;
        }
    }
    return 0;
}

int main(void)
{
    asnber_ctx_config_t config;
    asnber_ctx_t *ctx = NULL;
    asnber_schema_t *schema = NULL;
    asnber_schema_table_t table;
    asnber_decode_options_t options;
    asnber_doc_t *doc = NULL;
    size_t consumed = 0;
    int status = 1;

    asnber_ctx_config_init(&config);
    if (asnber_ctx_create(&config, &ctx) != ASNBER_OK) {
        return 1;
    }

    table.struct_size = sizeof(table);
    table.data = kPKIXFlattened2009Schema;
    table.size = kPKIXFlattened2009Schema_size;
    table.format_version = 1u << 16;
    table.reserved = 0;
    if (asnber_schema_load(ctx, &table, &schema) != ASNBER_OK ||
        schema == NULL) {
        goto done;
    }

    asnber_decode_options_init(&options);
    options.encoding = ASNBER_ENCODING_DER;
    if (asnber_decode_buffer_with_schema(
            ctx, kCertRsaSelfsigned, kCertRsaSelfsignedSize, schema, &options,
            &doc, &consumed) != ASNBER_OK ||
        doc == NULL) {
        goto done;
    }

    {
        const asnber_node_t *root = asnber_doc_root(doc);
        if (root == NULL ||
            asnber_node_child_by_name(root, "toBeSigned") == NULL ||
            asnber_node_child_by_name(root, "algorithmIdentifier") == NULL ||
            asnber_node_child_by_name(root, "signature") == NULL) {
            goto done;
        }
    }

    /* 闭包事实：TBSCertificate 可达；BasicConstraints/CertificateList 不可达。 */
    if (!table_contains("TBSCertificate") ||
        table_contains("BasicConstraints") ||
        table_contains("CertificateList")) {
        goto done;
    }

    status = 0;

done:
    if (doc != NULL) {
        asnber_doc_destroy(doc);
    }
    if (schema != NULL) {
        asnber_schema_destroy(schema);
    }
    asnber_ctx_destroy(ctx);
    if (status != 0) {
        fprintf(stderr, "FAIL: trimmed PKIX table cannot decode certificate\n");
    } else {
        printf("OK\n");
    }
    return status;
}
