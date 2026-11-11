/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * 独立消费工程（PKCS#1）：只依赖 find_package(asnber-pkcs1)，打开
 * RSAPublicKey 并读取模数长度与公开指数。
 */
#include <asnber/asnber.h>
#include <asnber/pkcs1/pkcs1.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    FILE *file = NULL;
    unsigned char *der = NULL;
    long length = 0;
    asnber_ctx_config_t config;
    asnber_ctx_t *ctx = NULL;
    asnber_pkcs_rsa_public_key_t *key = NULL;
    const char *modulus = NULL;
    const char *exponent = NULL;
    size_t modulus_size = 0;
    size_t exponent_size = 0;
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
    if (asnber_pkcs_rsa_public_key_open(ctx, der, (size_t)length, &key) ==
            ASNBER_OK &&
        asnber_pkcs_rsa_public_key_modulus(key, &modulus, &modulus_size) ==
            ASNBER_OK &&
        modulus != NULL && modulus_size > 0 &&
        asnber_pkcs_rsa_public_key_public_exponent(key, &exponent,
                                                 &exponent_size) == ASNBER_OK &&
        exponent_size == strlen("65537") &&
        memcmp(exponent, "65537", exponent_size) == 0) {
        result = 0;
    }
    asnber_pkcs_rsa_public_key_close(key);
    asnber_ctx_destroy(ctx);
    free(der);
    return result;
}
