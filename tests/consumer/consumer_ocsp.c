/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * 独立消费工程（OCSP）：只依赖 find_package(asnber-ocsp)，打开 OCSPRequest
 * 并读取 version 与 request 条数。
 */
#include <asnber/asnber.h>
#include <asnber/ocsp/ocsp.h>

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    FILE *file = NULL;
    unsigned char *der = NULL;
    long length = 0;
    asnber_ctx_config_t config;
    asnber_ctx_t *ctx = NULL;
    asnber_ocsp_request_t *request = NULL;
    uint32_t version = 99;
    size_t count = 0;
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
    if (asnber_ocsp_request_open(ctx, der, (size_t)length, &request) == ASNBER_OK &&
        asnber_ocsp_request_version(request, &version) == ASNBER_OK &&
        asnber_ocsp_request_count(request, &count) == ASNBER_OK && version == 0 &&
        count == 1) {
        result = 0;
    }
    asnber_ocsp_request_close(request);
    asnber_ctx_destroy(ctx);
    free(der);
    return result;
}
