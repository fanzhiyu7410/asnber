/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * libFuzzer harness：DER 解码 → DER 编码 → 再解码 往返。
 * 断言：对 DER 严格解码成功的输入，编码产物必须能再次 DER 解码成功，
 * 且与输入逐字节一致（规范 DER 唯一）。违反即内部不变式破坏，掉 trap。
 */
#include <asnber/asnber.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

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
    asnber_err_t rc = asnber_decode_buffer(ctx, data, size, &options, &doc,
                                       &consumed);
    /* DER 严格解码：输入非法/非最短等返回错误码（含 NON_CANONICAL），正常。 */
    if (rc == ASNBER_OK && doc != NULL && consumed == size) {
        asnber_buf_t buf;
        memset(&buf, 0, sizeof(buf));
        if (asnber_encode_buffer(ctx, doc, NULL, &buf) == ASNBER_OK) {
            asnber_doc_t *doc2 = NULL;
            size_t consumed2 = 0;
            asnber_err_t rc2 = asnber_decode_buffer(ctx, buf.data, buf.size,
                                                &options, &doc2, &consumed2);
            int identical = (buf.size == size) &&
                            (memcmp(buf.data, data, size) == 0);
            if (rc2 != ASNBER_OK || consumed2 != buf.size || !identical) {
                __builtin_trap();
            }
            if (doc2 != NULL) {
                fuzz_walk(asnber_doc_root(doc2));
                asnber_doc_destroy(doc2);
            }
            (void)asnber_buf_release(ctx, &buf);
        }
        asnber_doc_destroy(doc);
    }

    asnber_ctx_destroy(ctx);
    return 0;
}