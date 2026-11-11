/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * 独立消费工程（PKCS）：只依赖 find_package(asnber-pkcs)，打开 PKCS#8
 * PrivateKeyInfo 并读取 version 与算法 OID。
 */
#include <asnber/asnber.h>
#include <asnber/pkcs/pkcs.h>

#include <stdio.h>
#include <string.h>

#include <stdlib.h>

int main(int argc, char **argv)
{
    FILE *file = NULL;
    unsigned char *der = NULL;
    long length = 0;
    asnber_ctx_config_t config;
    asnber_ctx_t *ctx = NULL;
    asnber_pkcs_private_key_info_t *info = NULL;
    int64_t version = -1;
    const char *oid = NULL;
    size_t oid_size = 0;
    int result = 1;

    if (argc != 2) {
        return 1;
    }
    file = fopen(argv[1], "rb");
    if (file == NULL) {
        return 1;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return 1;
    }
    length = ftell(file);
    if (length <= 0 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return 1;
    }
    der = (unsigned char *)malloc((size_t)length);
    if (der == NULL || fread(der, 1, (size_t)length, file) != (size_t)length) {
        free(der);
        fclose(file);
        return 1;
    }
    fclose(file);

    asnber_ctx_config_init(&config);
    if (asnber_ctx_create(&config, &ctx) != ASNBER_OK) {
        free(der);
        return 1;
    }
    if (asnber_pkcs_private_key_info_open(ctx, der, (size_t)length, &info) ==
            ASNBER_OK &&
        asnber_pkcs_private_key_info_version(info, &version) == ASNBER_OK &&
        version == 0 &&
        asnber_pkcs_private_key_info_algorithm_oid(info, &oid, &oid_size) ==
            ASNBER_OK &&
        oid_size == strlen("1.2.840.113549.1.1.1") &&
        memcmp(oid, "1.2.840.113549.1.1.1", oid_size) == 0) {
        result = 0;
    }
    asnber_pkcs_private_key_info_close(info);
    asnber_ctx_destroy(ctx);
    free(der);
    return result;
}
