/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * libFuzzer harness：DER 严格解码（asnber_decode_buffer，encoding=DER）。
 * 覆盖 NON_CANONICAL 分支：非最短长度 / 违规编码等返回错误码属正常行为。
 */
#include <asnber/asnber.h>

#include <stddef.h>
#include <stdint.h>

#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    asnber_ctx_t *ctx = fuzz_ctx_create();
    if (ctx == NULL) {
        return 0;
    }

    asnber_decode_options_t options;
    asnber_decode_options_init(&options);
    options.struct_size = sizeof(options);
    options.encoding = ASNBER_ENCODING_DER;

    asnber_doc_t *doc = NULL;
    size_t consumed = 0;
    (void)asnber_decode_buffer(ctx, data, size, &options, &doc, &consumed);
    if (doc != NULL) {
        fuzz_walk(asnber_doc_root(doc));
        asnber_doc_destroy(doc);
    }

    asnber_ctx_destroy(ctx);
    return 0;
}