/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * 独立消费工程（PKCS#12）：只依赖 find_package(asnber-pkcs12)，打开 PFX 并
 * 读取 version。
 */
#include <asnber/asnber.h>
#include <asnber/pkcs12/pkcs12.h>

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    FILE *file = NULL;
    unsigned char *der = NULL;
    long length = 0;
    asnber_ctx_config_t config;
    asnber_ctx_t *ctx = NULL;
    asnber_pkcs12_pfx_t *pfx = NULL;
    int64_t version = -1;
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
    if (asnber_pkcs12_pfx_open(ctx, der, (size_t)length, &pfx) == ASNBER_OK &&
        asnber_pkcs12_pfx_version(pfx, &version) == ASNBER_OK && version == 3) {
        result = 0;
    }
    asnber_pkcs12_pfx_close(pfx);
    asnber_ctx_destroy(ctx);
    free(der);
    return result;
}
