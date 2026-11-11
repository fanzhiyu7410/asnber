/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * schema 感知编码内部共享定义。
 *
 * 只允许 src/schema 同一子系统的 cpp 包含。编码状态与跨翻译单元复用的
 * 标签/尺寸/写出辅助集中在此，EncState 全仓库只在此处定义一次。
 */

#ifndef ASNBER_SCHEMA_ENCODE_INTERNAL_H_INCLUDED
#define ASNBER_SCHEMA_ENCODE_INTERNAL_H_INCLUDED

#include <cstddef>
#include <cstdint>

#include "ber/asnber_ber_decoder.h"
#include "schema/asnber_schema_encode.h"
#include "der/asnber_tag_codec.h"
#include "types/asnber_dom.h"

namespace asnber {
namespace schema_encode_detail {

struct EncState {
    Context *ctx;
    const Document *doc;
    const Schema *schema;
    const uint8_t *defaultTlv;
    size_t defaultSize;
    /* schema 编码失败时记下“类型名/字段名”。sizeOf/writeOf 以 const 引用
     * 传递状态，所以槽位是 mutable。空串表示这次失败没有字段可定位。 */
    static constexpr size_t kEncodePathBytes = 160;
    mutable char errorPath[kEncodePathBytes];
};

/* 记下当前失败的类型与字段。field 为空时只写类型名。后写覆盖先写，
 * 因此嵌套失败留下的是最内层。 */
void noteEncodePath(const EncState &st, const char *typeName,
                    const char *fieldName) noexcept;

const SchemaType *typeAt(const Schema *schema, uint32_t typeId);
uint32_t effectiveTagMode(const Schema *schema, const SchemaType *type);
uint32_t universalTagOf(const SchemaType *type);
void typeTag(const Schema *schema, const SchemaType *type, bool unwrapped,
             uint32_t *outClass, uint32_t *outNumber, bool *outConstructed);
using der_detail::tagFieldBytes;
using der_detail::lengthFieldBytes;
using der_detail::writeTag;
using der_detail::writeLength;

bool rawTlvOf(const Document *doc, const Node *node, const uint8_t **outData,
              size_t *outSize);
bool rawTlvOfNode(const Document *doc, const Node *node,
                  const uint8_t **outData, size_t *outSize);
const Node *namedChild(const Node *parent, const char *name);
bool tagMatches(const Schema *schema, const SchemaType *type, const Node *node,
                bool unwrapped);
int32_t branchIndex(const Schema *schema, const SchemaType *type,
                    const Node *node);
bool isDefaultEqual(const Document *doc, const Node *child,
                    const SchemaField &field);

bool sizeAny(const EncState &st, const SchemaType *type, const Node *node,
             size_t *outSize, asnber_err_t *outError);
bool hasNamedChildren(const Node *node);
bool validateRetainedDer(Context *ctx, const uint8_t *tlv, size_t size,
                         asnber_err_t *outError);
bool allocateFieldSlots(const EncState &st, uint32_t count,
                        const Node ***outSlots, asnber_err_t *outError);
void releaseFieldSlots(const EncState &st, const Node **slots);
void matchFields(const EncState &st, const SchemaType *type, const Node *node,
                 const Node **slots);
bool isKnownFieldChild(const Node *child, const Node **slots, uint32_t count);
bool sumKnownFields(const EncState &st, const SchemaType *type,
                    const Node **slots, size_t *outTotal,
                    asnber_err_t *outError);
bool addRetainedChild(const EncState &st, const Node *child, size_t *total,
                      asnber_err_t *outError);
bool sizeSequenceFields(const EncState &st, const SchemaType *type,
                        const Node *node, size_t *outContent,
                        asnber_err_t *outError);
bool sizeSetFields(const EncState &st, const SchemaType *type,
                   const Node *node, size_t *outContent,
                   asnber_err_t *outError);
bool sizeOf(const EncState &st, uint32_t typeId, const Node *node,
            bool unwrapped, size_t *outSize, asnber_err_t *outError);

bool writeTaggedContent(const EncState &st, uint32_t tagClass,
                        uint32_t tagNumber, bool constructed,
                        const uint8_t *content, size_t contentSize,
                        uint8_t *dst, size_t capacity, size_t *outUsed,
                        asnber_err_t *outError);
void writeSorted(const uint8_t *buffer, size_t *offsets, size_t *sizes,
                 size_t count);
bool writeSetOf(const EncState &st, uint32_t typeId, const Node *node,
                uint32_t tagClass, uint32_t tagNumber, uint8_t *dst,
                size_t capacity, size_t *outUsed, asnber_err_t *outError);
bool writeSequenceFields(const EncState &st, const SchemaType *type,
                         const Node *node, uint8_t *dst, size_t capacity,
                         size_t *outUsed, asnber_err_t *outError);
bool writeSet(const EncState &st, const SchemaType *type, const Node *node,
              uint32_t cls, uint32_t num, uint8_t *dst, size_t capacity,
              size_t *outUsed, asnber_err_t *outError);
bool writeAny(const EncState &st, const SchemaType *type, const Node *node,
              uint8_t *dst, size_t capacity, size_t *outUsed,
              asnber_err_t *outError);
bool writeOf(const EncState &st, uint32_t typeId, const Node *node,
             bool unwrapped, uint8_t *dst, size_t capacity, size_t *outUsed,
             asnber_err_t *outError);

} /* namespace schema_encode_detail */
} /* namespace asnber */

#endif /* ASNBER_SCHEMA_ENCODE_INTERNAL_H_INCLUDED */
