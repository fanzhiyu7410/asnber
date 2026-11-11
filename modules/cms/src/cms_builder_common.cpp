/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-cms 构造侧共享实现：CMS 条目释放与 ContentInfo 编码。
 * 领域无关的单 TLV 校验、子节点形状规则与构树辅助已下沉到
 * detail/module_builder_support.h。
 */

#include "detail/cms_builder_internal.h"

#include <cstring>

namespace asnber_cms_detail {

void freeSigner(signer_entry *signer)
{
    std::free(signer->sid1.data);
    std::free(signer->sid2.data);
    std::free(signer->digest_oid);
    std::free(signer->digest_params.data);
    std::free(signer->signed_attrs.data);
    std::free(signer->signature_oid);
    std::free(signer->signature_params.data);
    std::free(signer->signature.data);
    std::free(signer->unsigned_attrs.data);
    std::memset(signer, 0, sizeof(*signer));
}

void freeRecipient(recipient_entry *recipient)
{
    std::free(recipient->rid1.data);
    std::free(recipient->rid2.data);
    std::free(recipient->originator.data);
    std::free(recipient->ukm.data);
    std::free(recipient->recipient_encrypted_keys.data);
    std::free(recipient->kekid.data);
    std::free(recipient->key_derivation_algorithm.data);
    std::free(recipient->key_encryption_oid);
    std::free(recipient->key_encryption_params.data);
    std::free(recipient->encrypted_key.data);
    std::free(recipient->ori_type);
    std::free(recipient->ori_value.data);
    std::memset(recipient, 0, sizeof(*recipient));
}

asnber_err_t encodeExplicitWrapper(asnber_ctx_t *ctx, const uint8_t *inner,
                                size_t inner_size, asnber_buf_t *out_buf)
{
    asnber_doc_t *doc = nullptr;
    asnber_err_t rc = asnber_doc_create(ctx, &doc);
    if (rc != ASNBER_OK) {
        return rc;
    }
    asnber_node_t *wrapper = nullptr;
    asnber_node_t *any_node = nullptr;
    rc = createNode(doc, nullptr, ASNBER_TAG_CONTEXT, kTagContext0, 1, &wrapper);
    if (rc == ASNBER_OK) {
        rc = asnber_node_create_any(doc, wrapper, inner, inner_size, &any_node);
    }
    if (rc == ASNBER_OK) {
        rc = asnber_doc_seal(doc);
    }
    if (rc != ASNBER_OK) {
        asnber_doc_destroy(doc);
        return rc;
    }

    rc = asnber_encode_buffer(ctx, doc, nullptr, out_buf);
    asnber_doc_destroy(doc);
    return rc;
}

/* 组装并编码 ContentInfo。 */
asnber_err_t encodeContentInfo(asnber_ctx_t *ctx, const char *content_type_oid,
                            const uint8_t *content, size_t content_size,
                            asnber_buf_t *out_buf)
{
    asnber_buf_t wrapper;
    std::memset(&wrapper, 0, sizeof(wrapper));
    asnber_err_t rc =
        encodeExplicitWrapper(ctx, content, content_size, &wrapper);
    if (rc != ASNBER_OK) {
        return rc;
    }

    asnber_doc_t *doc = nullptr;
    rc = asnber_doc_create(ctx, &doc);
    if (rc != ASNBER_OK) {
        asnber_buf_release(ctx, &wrapper);
        return rc;
    }
    asnber_node_t *root = nullptr;
    asnber_node_t *ignored = nullptr;
    rc = createNode(doc, nullptr, ASNBER_TAG_UNIVERSAL, kTagSequence, 1, &root);
    if (rc == ASNBER_OK) {
        rc = createOidNode(doc, root, content_type_oid, &ignored);
    }
    if (rc == ASNBER_OK) {
        rc = asnber_node_create_any(doc, root, wrapper.data, wrapper.size,
                                  &ignored);
    }
    if (rc == ASNBER_OK) {
        rc = asnber_doc_seal(doc);
    }
    asnber_buf_release(ctx, &wrapper);
    if (rc != ASNBER_OK) {
        asnber_doc_destroy(doc);
        return rc;
    }

    asnber_schema_t *schema = nullptr;
    rc = loadTable(ctx, cmsSchemaTable(), kCmsRootContentInfo, &schema);
    if (rc != ASNBER_OK) {
        asnber_doc_destroy(doc);
        return rc;
    }
    asnber_encode_options_t options;
    asnber_encode_options_init(&options);
    options.schema = schema;
    rc = asnber_encode_buffer(ctx, doc, &options, out_buf);
    asnber_schema_destroy(schema);
    asnber_doc_destroy(doc);
    return rc;
}

} /* namespace asnber_cms_detail */
