/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * 独立消费工程（PKIX）：只依赖 find_package(asnber-pkix)，打开证书并读取 version
 * 与 subject 节点。
 */
#include <asnber/asnber.h>
#include <asnber/pkix/pkix.h>

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    FILE *file = NULL;
    unsigned char *der = NULL;
    long length = 0;
    asnber_ctx_config_t config;
    asnber_ctx_t *ctx = NULL;
    asnber_pkix_certificate_t *cert = NULL;
    const asnber_node_t *subject = NULL;
    uint32_t version = 0;
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
    if (asnber_pkix_certificate_open(ctx, der, (size_t)length, &cert) == ASNBER_OK &&
        asnber_pkix_certificate_version(cert, &version) == ASNBER_OK && version == 2 &&
        asnber_pkix_certificate_find(cert, "tbsCertificate.subject", &subject) ==
            ASNBER_OK &&
        subject != NULL) {
        result = 0;
    }
    asnber_pkix_certificate_close(cert);
    asnber_ctx_destroy(ctx);
    free(der);
    return result;
}
