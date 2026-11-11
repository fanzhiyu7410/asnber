/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-pkix Certificate builder 的模块内部状态（不安装、不导出）。
 *
 * 拆分原因：builder 实现跨两个翻译单元（主流程与扩展便捷函数），
 * 需要共享状态布局；该头只含类型定义，不含任何编码逻辑。
 */

#ifndef ASNBER_PKIX_BUILDER_INTERNAL_H_INCLUDED
#define ASNBER_PKIX_BUILDER_INTERNAL_H_INCLUDED

#include <cstddef>
#include <cstdint>

#include <asnber/pkix/pkix.h>

#include "detail/module_builder_support.h"

struct name_attribute_store {
    char *oid;
    uint8_t *value;
    size_t value_size;
    uint32_t string_tag;
};

struct name_store {
    name_attribute_store *attributes;
    size_t attribute_count;
    asnber::module_detail::name_rdn *rdns;
    size_t rdn_count;
    asnber::module_detail::name_attribute *views;
};

struct asnber_pkix_certificate_builder {
    asnber_ctx_t *ctx;

    bool version_set;
    int64_t version;

    bool serial_set;
    asnber::module_detail::byte_span serial;

    bool signature_algorithm_set;
    char *signature_algorithm_oid;
    asnber::module_detail::byte_span signature_algorithm_params;

    bool issuer_set;
    name_store issuer;

    bool validity_set;
    asnber_time_t not_before;
    asnber_time_t not_after;

    bool subject_set;
    name_store subject;

    bool subject_public_key_algorithm_set;
    char *subject_public_key_algorithm_oid;
    asnber::module_detail::byte_span subject_public_key_algorithm_params;

    bool subject_public_key_set;
    asnber::module_detail::byte_span subject_public_key;
    uint8_t subject_public_key_unused_bits;

    bool issuer_unique_id_set;
    asnber::module_detail::byte_span issuer_unique_id;
    uint8_t issuer_unique_id_unused_bits;

    bool subject_unique_id_set;
    asnber::module_detail::byte_span subject_unique_id;
    uint8_t subject_unique_id_unused_bits;

    asnber::module_detail::extension_entry *extensions;
    size_t extension_count;
    size_t extension_capacity;

    bool signature_value_set;
    asnber::module_detail::byte_span signature_value;
    uint8_t signature_value_unused_bits;
};

#endif /* ASNBER_PKIX_BUILDER_INTERNAL_H_INCLUDED */
