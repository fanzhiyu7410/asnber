/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asnber-cms SignedData builder：构树、编码与公共接口。
 */

#include "detail/cms_builder_internal.h"

#include <cstdlib>
#include <cstring>

namespace asnber_cms_detail {

asnber_err_t addSid(asnber_doc_t *doc, asnber_node_t *parent,
                 const signer_entry &signer, asnber_node_t **out_node)
{
    asnber_node_t *node = nullptr;
    if (signer.sid_kind == ASNBER_CMS_SID_ISSUER_AND_SERIAL) {
        asnber_err_t rc = createNode(doc, parent, ASNBER_TAG_UNIVERSAL,
                                   kTagSequence, 1, &node);
        if (rc != ASNBER_OK) {
            return rc;
        }
        asnber_node_t *ignored = nullptr;
        rc = asnber_node_create_any(doc, node, signer.sid1.data,
                                  signer.sid1.size, &ignored);
        if (rc != ASNBER_OK) {
            return rc;
        }
        rc = asnber_node_create_any(doc, node, signer.sid2.data,
                                  signer.sid2.size, &ignored);
        if (rc != ASNBER_OK) {
            return rc;
        }
    } else {
        asnber_err_t rc = createNode(doc, parent, ASNBER_TAG_CONTEXT,
                                   kTagContext0, 0, &node);
        if (rc != ASNBER_OK) {
            return rc;
        }
        rc = asnber_node_set_content(node, signer.sid1.data, signer.sid1.size);
        if (rc != ASNBER_OK) {
            return rc;
        }
    }
    *out_node = node;
    return ASNBER_OK;
}

asnber_err_t addSignerInfo(asnber_doc_t *doc, asnber_node_t *parent,
                        const signer_entry &signer)
{
    asnber_node_t *sequence = nullptr;
    asnber_err_t rc = createNode(doc, parent, ASNBER_TAG_UNIVERSAL, kTagSequence, 1,
                               &sequence);
    if (rc != ASNBER_OK) {
        return rc;
    }
    asnber_node_t *ignored = nullptr;
    rc = createIntegerNode(doc, sequence, signer.version, &ignored);
    if (rc != ASNBER_OK) {
        return rc;
    }
    rc = addSid(doc, sequence, signer, &ignored);
    if (rc != ASNBER_OK) {
        return rc;
    }
    rc = addAlgorithmIdentifier(doc, sequence, signer.digest_oid,
                                signer.digest_params);
    if (rc != ASNBER_OK) {
        return rc;
    }
    if (signer.signed_attrs.size != 0) {
        rc = asnber_node_create_any(doc, sequence, signer.signed_attrs.data,
                                  signer.signed_attrs.size, &ignored);
        if (rc != ASNBER_OK) {
            return rc;
        }
    }
    rc = addAlgorithmIdentifier(doc, sequence, signer.signature_oid,
                                signer.signature_params);
    if (rc != ASNBER_OK) {
        return rc;
    }
    rc = createOctetStringNode(doc, sequence, signer.signature.data,
                               signer.signature.size, &ignored);
    if (rc != ASNBER_OK) {
        return rc;
    }
    if (signer.unsigned_attrs.size != 0) {
        rc = asnber_node_create_any(doc, sequence, signer.unsigned_attrs.data,
                                  signer.unsigned_attrs.size, &ignored);
    }
    return rc;
}

/* 组装 SignedData 文档（不含 ContentInfo 包装）。 */
asnber_err_t buildSignedData(const asnber_cms_builder &builder, asnber_doc_t **out_doc)
{
    asnber_doc_t *doc = nullptr;
    asnber_err_t rc = asnber_doc_create(builder.ctx, &doc);
    if (rc != ASNBER_OK) {
        return rc;
    }

    asnber_node_t *root = nullptr;
    asnber_node_t *ignored = nullptr;
    rc = createNode(doc, nullptr, ASNBER_TAG_UNIVERSAL, kTagSequence, 1, &root);
    if (rc != ASNBER_OK) {
        asnber_doc_destroy(doc);
        return rc;
    }
    rc = createIntegerNode(doc, root, builder.version, &ignored);
    if (rc != ASNBER_OK) {
        asnber_doc_destroy(doc);
        return rc;
    }

    asnber_node_t *digests = nullptr;
    rc = createNode(doc, root, ASNBER_TAG_UNIVERSAL, kTagSet, 1, &digests);
    if (rc != ASNBER_OK) {
        asnber_doc_destroy(doc);
        return rc;
    }
    for (size_t i = 0; i < builder.digest_count; ++i) {
        rc = addAlgorithmIdentifier(doc, digests, builder.digests[i].oid,
                                    builder.digests[i].params);
        if (rc != ASNBER_OK) {
            asnber_doc_destroy(doc);
            return rc;
        }
    }

    asnber_node_t *encap = nullptr;
    rc = createNode(doc, root, ASNBER_TAG_UNIVERSAL, kTagSequence, 1, &encap);
    if (rc != ASNBER_OK) {
        asnber_doc_destroy(doc);
        return rc;
    }
    rc = createOidNode(doc, encap, builder.econtent_type, &ignored);
    if (rc != ASNBER_OK) {
        asnber_doc_destroy(doc);
        return rc;
    }
    if (builder.econtent_set) {
        asnber_node_t *wrapper = nullptr;
        rc = createNode(doc, encap, ASNBER_TAG_CONTEXT, kTagContext0, 1,
                        &wrapper);
        if (rc == ASNBER_OK) {
            rc = createOctetStringNode(doc, wrapper, builder.econtent.data,
                                       builder.econtent.size, &ignored);
        }
        if (rc != ASNBER_OK) {
            asnber_doc_destroy(doc);
            return rc;
        }
    }

    if (builder.cert_count != 0) {
        asnber_node_t *certificates = nullptr;
        rc = createNode(doc, root, ASNBER_TAG_CONTEXT, kTagContext0, 1,
                        &certificates);
        if (rc != ASNBER_OK) {
            asnber_doc_destroy(doc);
            return rc;
        }
        for (size_t i = 0; i < builder.cert_count; ++i) {
            rc = asnber_node_create_any(doc, certificates, builder.certs[i].data,
                                      builder.certs[i].size, &ignored);
            if (rc != ASNBER_OK) {
                asnber_doc_destroy(doc);
                return rc;
            }
        }
    }

    if (builder.crl_count != 0) {
        asnber_node_t *crls = nullptr;
        rc = createNode(doc, root, ASNBER_TAG_CONTEXT, kTagContext1, 1, &crls);
        if (rc != ASNBER_OK) {
            asnber_doc_destroy(doc);
            return rc;
        }
        for (size_t i = 0; i < builder.crl_count; ++i) {
            rc = asnber_node_create_any(doc, crls, builder.crls[i].data,
                                      builder.crls[i].size, &ignored);
            if (rc != ASNBER_OK) {
                asnber_doc_destroy(doc);
                return rc;
            }
        }
    }

    asnber_node_t *signer_infos = nullptr;
    rc = createNode(doc, root, ASNBER_TAG_UNIVERSAL, kTagSet, 1, &signer_infos);
    if (rc != ASNBER_OK) {
        asnber_doc_destroy(doc);
        return rc;
    }
    for (size_t i = 0; i < builder.signer_count; ++i) {
        rc = addSignerInfo(doc, signer_infos, builder.signers[i]);
        if (rc != ASNBER_OK) {
            asnber_doc_destroy(doc);
            return rc;
        }
    }

    rc = asnber_doc_seal(doc);
    if (rc != ASNBER_OK) {
        asnber_doc_destroy(doc);
        return rc;
    }
    *out_doc = doc;
    return ASNBER_OK;
}

/* 编码 SignedData 文档（schema 感知）。 */
asnber_err_t encodeSignedData(const asnber_cms_builder &builder,
                           const asnber_doc_t *doc, asnber_buf_t *out_buf)
{
    asnber_schema_t *schema = nullptr;
    asnber_err_t rc = loadTable(builder.ctx, cmsSchemaTable(), kCmsRootSignedData,
                              &schema);
    if (rc != ASNBER_OK) {
        return rc;
    }
    asnber_encode_options_t options;
    asnber_encode_options_init(&options);
    options.schema = schema;
    rc = asnber_encode_buffer(builder.ctx, doc, &options, out_buf);
    asnber_schema_destroy(schema);
    return rc;
}

/*
 * 用通用编码器把 SignedData TLV 包进 `[0]` 显式包装，得到 ContentInfo.content
 * 的完整原始 TLV。避免在模块内手写长度编码。
 */

} /* namespace asnber_cms_detail */

using namespace asnber_cms_detail;

/* ========================================================================= */
/* 公共接口                                                                  */
/* ========================================================================= */

extern "C" asnber_err_t asnber_cms_builder_create(asnber_ctx_t *ctx,
                                             asnber_cms_builder_t **out_builder)
{
    if (ctx == nullptr || out_builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    *out_builder = nullptr;
    asnber_cms_builder_t *builder =
        static_cast<asnber_cms_builder_t *>(std::malloc(sizeof(asnber_cms_builder_t)));
    if (builder == nullptr) {
        return ASNBER_E_NOMEM;
    }
    std::memset(builder, 0, sizeof(*builder));
    builder->ctx = ctx;
    *out_builder = builder;
    return ASNBER_OK;
}

extern "C" void asnber_cms_builder_destroy(asnber_cms_builder_t *builder)
{
    if (builder == nullptr) {
        return;
    }
    for (size_t i = 0; i < builder->digest_count; ++i) {
        std::free(builder->digests[i].oid);
        std::free(builder->digests[i].params.data);
    }
    std::free(builder->digests);
    std::free(builder->econtent_type);
    std::free(builder->econtent.data);
    freeSpans(builder->certs, builder->cert_count);
    freeSpans(builder->crls, builder->crl_count);
    for (size_t i = 0; i < builder->signer_count; ++i) {
        freeSigner(&builder->signers[i]);
    }
    std::free(builder->signers);
    std::memset(builder, 0, sizeof(*builder));
    std::free(builder);
}

extern "C" asnber_err_t asnber_cms_builder_set_version(
    asnber_cms_builder_t *builder, int64_t version)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->version_set) {
        return ASNBER_E_INVALID_STATE;
    }
    builder->version = version;
    builder->version_set = true;
    return ASNBER_OK;
}

extern "C" asnber_err_t asnber_cms_builder_add_digest_algorithm(
    asnber_cms_builder_t *builder, const char *oid, const uint8_t *params,
    size_t params_size)
{
    if (builder == nullptr || oid == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (params == nullptr && params_size != 0) {
        return ASNBER_E_INVALID_ARG;
    }
    asnber_err_t rc = validateOid(builder->ctx, oid);
    if (rc != ASNBER_OK) {
        return rc;
    }
    if (params_size != 0) {
        rc = validateSingleDer(builder->ctx, params, params_size, nullptr);
        if (rc != ASNBER_OK) {
            return rc;
        }
    }

    if (!ensureCapacity(&builder->digests, builder->digest_count,
                        &builder->digest_capacity)) {
        return ASNBER_E_NOMEM;
    }

    alg_entry entry;
    std::memset(&entry, 0, sizeof(entry));
    entry.oid = copyText(oid);
    if (entry.oid == nullptr) {
        return ASNBER_E_NOMEM;
    }
    if (params_size != 0) {
        entry.params.data = copyBytes(params, params_size);
        if (entry.params.data == nullptr) {
            std::free(entry.oid);
            return ASNBER_E_NOMEM;
        }
        entry.params.size = params_size;
    }
    builder->digests[builder->digest_count] = entry;
    ++builder->digest_count;
    return ASNBER_OK;
}

extern "C" asnber_err_t asnber_cms_builder_set_econtent_type(
    asnber_cms_builder_t *builder, const char *oid)
{
    if (builder == nullptr || oid == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->econtent_type_set) {
        return ASNBER_E_INVALID_STATE;
    }
    asnber_err_t rc = validateOid(builder->ctx, oid);
    if (rc != ASNBER_OK) {
        return rc;
    }
    char *copy = copyText(oid);
    if (copy == nullptr) {
        return ASNBER_E_NOMEM;
    }
    builder->econtent_type = copy;
    builder->econtent_type_set = true;
    return ASNBER_OK;
}

extern "C" asnber_err_t asnber_cms_builder_set_econtent(
    asnber_cms_builder_t *builder, const uint8_t *econtent, size_t econtent_size)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    if (builder->econtent_set) {
        return ASNBER_E_INVALID_STATE;
    }
    if (econtent == nullptr || econtent_size == 0) {
        return ASNBER_E_INVALID_ARG;
    }

    der_root root;
    root.tag_class = ASNBER_TAG_UNIVERSAL;
    root.tag_number = 0;
    root.constructed = 0;
    asnber_err_t rc =
        validateSingleDer(builder->ctx, econtent, econtent_size, &root);
    if (rc != ASNBER_OK) {
        return rc;
    }
    if (root.tag_class != ASNBER_TAG_UNIVERSAL ||
        root.tag_number != kTagOctetString || root.constructed != 0) {
        return ASNBER_E_INVALID_VALUE;
    }

    /* 重新解码一次以取得内容字节；文档释放后指针失效，因此复制。 */
    asnber_decode_options_t options;
    asnber_decode_options_init(&options);
    options.encoding = ASNBER_ENCODING_DER;
    options.flags = ASNBER_DECODE_COPY_INPUT;
    asnber_doc_t *doc = nullptr;
    size_t consumed = 0;
    rc = asnber_decode_buffer(builder->ctx, econtent, econtent_size, &options,
                            &doc, &consumed);
    if (rc != ASNBER_OK) {
        return rc;
    }
    const uint8_t *content = nullptr;
    size_t content_size = 0;
    rc = asnber_node_content(asnber_doc_root(doc), &content, &content_size);
    if (rc == ASNBER_OK) {
        if (content_size == 0) {
            builder->econtent.data = nullptr;
            builder->econtent.size = 0;
            builder->econtent_set = true;
        } else {
            uint8_t *copy = copyBytes(content, content_size);
            if (copy == nullptr) {
                rc = ASNBER_E_NOMEM;
            } else {
                builder->econtent.data = copy;
                builder->econtent.size = content_size;
                builder->econtent_set = true;
            }
        }
    }
    asnber_doc_destroy(doc);
    return rc;
}

extern "C" asnber_err_t asnber_cms_builder_add_certificate(
    asnber_cms_builder_t *builder, const uint8_t *tlv, size_t tlv_size)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    der_root root;
    asnber_err_t rc = validateSingleDer(builder->ctx, tlv, tlv_size, &root);
    if (rc != ASNBER_OK) {
        return rc;
    }
    /* CertificateChoices：certificate SEQUENCE，或 [0..3] IMPLICIT 备选。 */
    const bool certificate =
        rootMatches(root, ASNBER_TAG_UNIVERSAL, kTagSequence, 1);
    const bool alternate = root.tag_class == ASNBER_TAG_CONTEXT &&
                           root.constructed == 1 && root.tag_number <= 3;
    if (!certificate && !alternate) {
        return ASNBER_E_INVALID_VALUE;
    }
    return appendSpan(&builder->certs, &builder->cert_count,
                      &builder->cert_capacity, tlv, tlv_size)
               ? ASNBER_OK
               : ASNBER_E_NOMEM;
}

extern "C" asnber_err_t asnber_cms_builder_add_crl(asnber_cms_builder_t *builder,
                                               const uint8_t *tlv,
                                               size_t tlv_size)
{
    if (builder == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    der_root root;
    asnber_err_t rc = validateSingleDer(builder->ctx, tlv, tlv_size, &root);
    if (rc != ASNBER_OK) {
        return rc;
    }
    /* RevocationInfoChoice：crl CertificateList SEQUENCE，或 other [1]。 */
    const bool crl = rootMatches(root, ASNBER_TAG_UNIVERSAL, kTagSequence, 1);
    const bool other = rootMatches(root, ASNBER_TAG_CONTEXT, kTagContext1, 1);
    if (!crl && !other) {
        return ASNBER_E_INVALID_VALUE;
    }
    return appendSpan(&builder->crls, &builder->crl_count,
                      &builder->crl_capacity, tlv, tlv_size)
               ? ASNBER_OK
               : ASNBER_E_NOMEM;
}

extern "C" asnber_err_t asnber_cms_builder_add_signer(
    asnber_cms_builder_t *builder, int64_t version, int32_t sid_kind,
    const uint8_t *sid1, size_t sid1_size, const uint8_t *sid2,
    size_t sid2_size, const char *digest_oid, const uint8_t *digest_params,
    size_t digest_params_size, const uint8_t *signed_attrs_tlv,
    size_t signed_attrs_size, const char *signature_oid,
    const uint8_t *signature_params, size_t signature_params_size,
    const uint8_t *signature, size_t signature_size,
    const uint8_t *unsigned_attrs_tlv, size_t unsigned_attrs_size)
{
    if (builder == nullptr || digest_oid == nullptr || signature_oid == nullptr ||
        signature == nullptr || signature_size == 0) {
        return ASNBER_E_INVALID_ARG;
    }
    if (sid_kind != ASNBER_CMS_SID_ISSUER_AND_SERIAL &&
        sid_kind != ASNBER_CMS_SID_SUBJECT_KEY_IDENTIFIER) {
        return ASNBER_E_INVALID_VALUE;
    }

    asnber_err_t rc = ASNBER_OK;
    byte_span signed_attrs;
    byte_span unsigned_attrs;
    std::memset(&signed_attrs, 0, sizeof(signed_attrs));
    std::memset(&unsigned_attrs, 0, sizeof(unsigned_attrs));

    /* 先完成全部校验与派生，再一次性复制提交，避免半成品追加。 */
    if (sid_kind == ASNBER_CMS_SID_ISSUER_AND_SERIAL) {
        /* issuer Name = RDNSequence SEQUENCE；serialNumber = INTEGER。 */
        rc = validateSingleDerRoot(builder->ctx, sid1, sid1_size,
                                   ASNBER_TAG_UNIVERSAL, kTagSequence, 1);
        if (rc == ASNBER_OK) {
            rc = validateSingleDerRoot(builder->ctx, sid2, sid2_size,
                                       ASNBER_TAG_UNIVERSAL, kTagInteger, 0);
        }
    } else {
        if (sid1 == nullptr || sid1_size == 0 || sid2 != nullptr ||
            sid2_size != 0) {
            return ASNBER_E_INVALID_ARG;
        }
    }
    if (rc != ASNBER_OK) {
        return rc;
    }
    rc = validateOid(builder->ctx, digest_oid);
    if (rc == ASNBER_OK) {
        rc = validateOid(builder->ctx, signature_oid);
    }
    if (rc != ASNBER_OK) {
        return rc;
    }
    if (digest_params_size != 0) {
        rc = validateSingleDer(builder->ctx, digest_params, digest_params_size,
                               nullptr);
        if (rc != ASNBER_OK) {
            return rc;
        }
    }
    if (signature_params_size != 0) {
        rc = validateSingleDer(builder->ctx, signature_params,
                               signature_params_size, nullptr);
        if (rc != ASNBER_OK) {
            return rc;
        }
    }
    if (signed_attrs_size != 0) {
        rc = validateAndRewriteSet(builder->ctx, signed_attrs_tlv,
                                   signed_attrs_size, 0xA0, &signed_attrs);
        if (rc != ASNBER_OK) {
            return rc;
        }
    }
    if (unsigned_attrs_size != 0) {
        rc = validateAndRewriteSet(builder->ctx, unsigned_attrs_tlv,
                                   unsigned_attrs_size, 0xA1, &unsigned_attrs);
        if (rc != ASNBER_OK) {
            std::free(signed_attrs.data);
            return rc;
        }
    }

    if (!ensureCapacity(&builder->signers, builder->signer_count,
                        &builder->signer_capacity)) {
        std::free(signed_attrs.data);
        std::free(unsigned_attrs.data);
        return ASNBER_E_NOMEM;
    }

    signer_entry entry;
    std::memset(&entry, 0, sizeof(entry));
    entry.version = version;
    entry.sid_kind = sid_kind;
    entry.sid1.data = copyBytes(sid1, sid1_size);
    entry.sid1.size = sid1_size;
    if (entry.sid1.data == nullptr) {
        std::free(signed_attrs.data);
        std::free(unsigned_attrs.data);
        return ASNBER_E_NOMEM;
    }
    if (sid2_size != 0) {
        entry.sid2.data = copyBytes(sid2, sid2_size);
        if (entry.sid2.data == nullptr) {
            freeSigner(&entry);
            std::free(signed_attrs.data);
            std::free(unsigned_attrs.data);
            return ASNBER_E_NOMEM;
        }
        entry.sid2.size = sid2_size;
    }
    entry.digest_oid = copyText(digest_oid);
    entry.signature_oid = copyText(signature_oid);
    if (entry.digest_oid == nullptr || entry.signature_oid == nullptr) {
        freeSigner(&entry);
        std::free(signed_attrs.data);
        std::free(unsigned_attrs.data);
        return ASNBER_E_NOMEM;
    }
    if (digest_params_size != 0) {
        entry.digest_params.data =
            copyBytes(digest_params, digest_params_size);
        entry.digest_params.size = digest_params_size;
    }
    if (signature_params_size != 0) {
        entry.signature_params.data =
            copyBytes(signature_params, signature_params_size);
        entry.signature_params.size = signature_params_size;
    }
    entry.signature.data = copyBytes(signature, signature_size);
    entry.signature.size = signature_size;
    entry.signed_attrs = signed_attrs;
    entry.unsigned_attrs = unsigned_attrs;

    if ((digest_params_size != 0 && entry.digest_params.data == nullptr) ||
        (signature_params_size != 0 && entry.signature_params.data == nullptr) ||
        entry.signature.data == nullptr) {
        freeSigner(&entry);
        return ASNBER_E_NOMEM;
    }

    builder->signers[builder->signer_count] = entry;
    ++builder->signer_count;
    return ASNBER_OK;
}

extern "C" asnber_err_t asnber_cms_builder_encode(
    const asnber_cms_builder_t *builder, asnber_buf_t *out_buf)
{
    if (builder == nullptr || out_buf == nullptr) {
        return ASNBER_E_INVALID_ARG;
    }
    out_buf->data = nullptr;
    out_buf->size = 0;
    out_buf->capacity = 0;

    /* version 与 eContentType 必填。RFC 5652 允许 certificates-only：
     * signerInfos 与 digestAlgorithms 都可以为空，但证书、CRL、签名者
     * 三者至少要有一项，否则没有可输出的内容。有签名者时仍要求至少一条
     * digestAlgorithm。 */
    if (!builder->version_set || !builder->econtent_type_set) {
        return ASNBER_E_INVALID_STATE;
    }
    if (builder->signer_count == 0) {
        if (builder->cert_count == 0 && builder->crl_count == 0) {
            return ASNBER_E_INVALID_STATE;
        }
    } else if (builder->digest_count == 0) {
        return ASNBER_E_INVALID_STATE;
    }

    asnber_doc_t *signed_data = nullptr;
    asnber_err_t rc = buildSignedData(*builder, &signed_data);
    if (rc != ASNBER_OK) {
        return rc;
    }
    asnber_buf_t signed_data_buf;
    std::memset(&signed_data_buf, 0, sizeof(signed_data_buf));
    rc = encodeSignedData(*builder, signed_data, &signed_data_buf);
    asnber_doc_destroy(signed_data);
    if (rc != ASNBER_OK) {
        return rc;
    }

    rc = encodeContentInfo(builder->ctx, kSignedDataOid, signed_data_buf.data,
                           signed_data_buf.size, out_buf);
    asnber_buf_release(builder->ctx, &signed_data_buf);
    return rc;
}
