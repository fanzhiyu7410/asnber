/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * schema 运行时注册路径：描述符校验、类型/字段追加与封存检查。
 */

#include <asnber/asnber.h>

#include <string.h>

#include "check.h"
#include "schema_probe.h"

static asnber_type_desc_t makeType(const char *name, asnber_type_kind_t kind,
                                 asnber_tag_class_t tagClass, uint32_t tagNumber,
                                 asnber_tag_mode_t tagMode,
                                 uint32_t elementTypeId)
{
    asnber_type_desc_t desc;
    memset(&desc, 0, sizeof(desc));
    desc.struct_size = sizeof(desc);
    desc.name = name;
    desc.kind = kind;
    desc.tag_class = tagClass;
    desc.tag_number = tagNumber;
    desc.tag_mode = tagMode;
    desc.element_type_id = elementTypeId;
    return desc;
}

static asnber_field_desc_t makeField(const char *name, uint32_t typeId)
{
    asnber_field_desc_t desc;
    memset(&desc, 0, sizeof(desc));
    desc.struct_size = sizeof(desc);
    desc.name = name;
    desc.type_id = typeId;
    return desc;
}

static asnber_bound_t makeBound(int64_t value, int32_t unbounded)
{
    asnber_bound_t bound;
    memset(&bound, 0, sizeof(bound));
    bound.struct_size = sizeof(bound);
    bound.is_unbounded = unbounded;
    bound.value = value;
    return bound;
}

static asnber_constraint_t makeRange(int64_t lower, int64_t upper)
{
    asnber_constraint_t constraint;
    memset(&constraint, 0, sizeof(constraint));
    constraint.struct_size = sizeof(constraint);
    constraint.kind = ASNBER_CONSTRAINT_RANGE;
    constraint.lower = makeBound(lower, 0);
    constraint.upper = makeBound(upper, 0);
    return constraint;
}

static asnber_constraint_t makeSize(int64_t lower, int64_t upper)
{
    asnber_constraint_t constraint;
    memset(&constraint, 0, sizeof(constraint));
    constraint.struct_size = sizeof(constraint);
    constraint.kind = ASNBER_CONSTRAINT_SIZE;
    constraint.lower = makeBound(lower, 0);
    constraint.upper = makeBound(upper, 0);
    return constraint;
}

static asnber_constraint_t makeMaxConstraint(void)
{
    asnber_constraint_t constraint;
    memset(&constraint, 0, sizeof(constraint));
    constraint.struct_size = sizeof(constraint);
    constraint.kind = ASNBER_CONSTRAINT_MAX;
    constraint.lower = makeBound(0, 0);
    constraint.upper = makeBound(0, 1);
    return constraint;
}

static asnber_constraint_t makeEnumConstraint(const int64_t *values,
                                            uint32_t count)
{
    asnber_constraint_t constraint;
    memset(&constraint, 0, sizeof(constraint));
    constraint.struct_size = sizeof(constraint);
    constraint.kind = ASNBER_CONSTRAINT_ENUM;
    constraint.enum_values = values;
    constraint.enum_count = count;
    return constraint;
}

static asnber_constraint_t makeBigintConstraint(const char *lower,
                                              size_t lowerSize,
                                              const char *upper,
                                              size_t upperSize)
{
    asnber_constraint_t constraint;
    memset(&constraint, 0, sizeof(constraint));
    constraint.struct_size = sizeof(constraint);
    constraint.kind = ASNBER_CONSTRAINT_BIGINT_RANGE;
    constraint.lower = makeBound(0, 0);
    constraint.lower.decimal = lower;
    constraint.lower.decimal_size = lowerSize;
    constraint.upper = makeBound(0, 0);
    constraint.upper.decimal = upper;
    constraint.upper.decimal_size = upperSize;
    return constraint;
}

static int addTypeOk(asnber_schema_t *schema, const asnber_type_desc_t *desc,
                     uint32_t *outId)
{
    return asnber_schema_add_type(schema, desc, outId) == ASNBER_OK;
}

/* 默认值 DER TLV 校验：accept != 0 期望 ASNBER_OK，否则期望 SCHEMA_DEFAULT。 */
static int expectDefaultVerdict(asnber_ctx_t *ctx, const char *fieldName,
                                const uint8_t *tlv, size_t size, int accept)
{
    asnber_type_desc_t type = makeType("IntType", ASNBER_TYPE_KIND_SIMPLE,
                                     ASNBER_TAG_UNIVERSAL, 2,
                                     ASNBER_TAG_MODE_DEFAULT, 0);
    asnber_schema_t *schema = NULL;
    uint32_t typeId = 0;
    ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_EXPLICIT,
                                       &schema) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &type, &typeId) == ASNBER_OK);
    asnber_field_desc_t field = makeField(fieldName, typeId);
    field.default_value = tlv;
    field.default_value_size = size;
    const asnber_err_t rc = asnber_schema_add_field(schema, typeId, &field);
    ASNBER_TEST_CHECK(rc == (accept != 0 ? ASNBER_OK : ASNBER_E_SCHEMA_DEFAULT));
    asnber_schema_destroy(schema);
    return 0;
}

int main(void)
{
    asnber_ctx_config_t config;
    asnber_ctx_config_init(&config);
    asnber_ctx_t *ctx = NULL;
    ASNBER_TEST_CHECK(asnber_ctx_create(&config, &ctx) == ASNBER_OK);

    /* 入口参数与默认标注方式。 */
    asnber_schema_t *schema = NULL;
    ASNBER_TEST_CHECK(asnber_schema_create(NULL, ASNBER_TAG_MODE_EXPLICIT,
                                       &schema) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_EXPLICIT,
                                       NULL) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_schema_create(ctx, (asnber_tag_mode_t)3,
                                       &schema) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(schema == NULL);

    /* 正常注册：INTEGER、UTF8String、SEQUENCE。 */
    ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_EXPLICIT,
                                       &schema) == ASNBER_OK);
    ASNBER_TEST_CHECK(schema != NULL);

    uint32_t idInt = 0;
    uint32_t idText = 0;
    uint32_t idSeq = 0;
    asnber_type_desc_t intDesc = makeType("IntType", ASNBER_TYPE_KIND_SIMPLE,
                                        ASNBER_TAG_UNIVERSAL, 2,
                                        ASNBER_TAG_MODE_DEFAULT, 0);
    asnber_type_desc_t textDesc = makeType("TextType", ASNBER_TYPE_KIND_SIMPLE,
                                         ASNBER_TAG_UNIVERSAL, 12,
                                         ASNBER_TAG_MODE_DEFAULT, 0);
    asnber_type_desc_t seqDesc = makeType("SeqType", ASNBER_TYPE_KIND_SEQUENCE,
                                        ASNBER_TAG_UNIVERSAL, 0,
                                        ASNBER_TAG_MODE_DEFAULT, 0);
    seqDesc.flags = ASNBER_TYPE_EXTENSIBLE;
    ASNBER_TEST_CHECK(addTypeOk(schema, &intDesc, &idInt));
    ASNBER_TEST_CHECK(idInt == 1);
    ASNBER_TEST_CHECK(addTypeOk(schema, &textDesc, &idText));
    ASNBER_TEST_CHECK(idText == 2);
    ASNBER_TEST_CHECK(addTypeOk(schema, &seqDesc, &idSeq));
    ASNBER_TEST_CHECK(idSeq == 3);
    ASNBER_TEST_CHECK(asnber_test_schema_type_count(schema) == 3);

    /* 类型名重复。 */
    ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &intDesc, &idInt) ==
                    ASNBER_E_SCHEMA_TYPE);

    /* 字段表：可选字段 + 默认值 DER TLV。 */
    const uint8_t defaultText[] = {0x0C, 0x03, 'a', 'b', 'c'};
    asnber_field_desc_t fieldInt = makeField("value", 1);
    asnber_field_desc_t fieldText = makeField("label", 2);
    fieldText.flags = ASNBER_FIELD_OPTIONAL;
    fieldText.default_value = defaultText;
    fieldText.default_value_size = sizeof(defaultText);
    ASNBER_TEST_CHECK(asnber_schema_add_field(schema, 3, &fieldInt) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_schema_add_field(schema, 3, &fieldText) == ASNBER_OK);

    asnber_test_field_info textInfo;
    ASNBER_TEST_CHECK(asnber_test_schema_field_info(schema, 3, 1, &textInfo) == 1);
    ASNBER_TEST_CHECK(strcmp(textInfo.name, "label") == 0);
    ASNBER_TEST_CHECK(textInfo.type_id == 2);
    ASNBER_TEST_CHECK(textInfo.flags == ASNBER_FIELD_OPTIONAL);
    ASNBER_TEST_CHECK(textInfo.default_size == sizeof(defaultText));
    size_t defaultSize = 0;
    const uint8_t *defaultBytes =
        asnber_test_schema_field_default(schema, 3, 1, &defaultSize);
    ASNBER_TEST_CHECK(defaultBytes != NULL);
    ASNBER_TEST_CHECK(defaultSize == sizeof(defaultText));
    ASNBER_TEST_CHECK(memcmp(defaultBytes, defaultText, sizeof(defaultText)) == 0);

    /* 根类型：越界/清除/设置。 */
    ASNBER_TEST_CHECK(asnber_schema_set_root(NULL, 1) == ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_schema_set_root(schema, 4) == ASNBER_E_SCHEMA_TYPE);
    ASNBER_TEST_CHECK(asnber_test_schema_root_type_id(schema) == 0);
    ASNBER_TEST_CHECK(asnber_schema_set_root(schema, 2) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_test_schema_root_type_id(schema) == 2);
    ASNBER_TEST_CHECK(asnber_schema_set_root(schema, 0) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_test_schema_root_type_id(schema) == 0);
    ASNBER_TEST_CHECK(asnber_schema_set_root(schema, 3) == ASNBER_OK);

    /* 封存成功且幂等。 */
    ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_test_schema_sealed(schema) == 1);
    ASNBER_TEST_CHECK(asnber_test_schema_root_type_id(schema) == 3);
    ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);

    /* 封存后不得追加或改根。 */
    ASNBER_TEST_CHECK(asnber_schema_set_root(schema, 1) == ASNBER_E_INVALID_STATE);
    ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &intDesc, &idInt) ==
                    ASNBER_E_INVALID_STATE);
    ASNBER_TEST_CHECK(asnber_schema_add_field(schema, 3, &fieldInt) ==
                    ASNBER_E_INVALID_STATE);
    asnber_schema_destroy(schema);

    /* 类型组合冲突。 */
    ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_EXPLICIT,
                                       &schema) == ASNBER_OK);
    asnber_type_desc_t choiceImplicit =
        makeType("BadChoice1", ASNBER_TYPE_KIND_CHOICE, ASNBER_TAG_UNIVERSAL, 0,
                 ASNBER_TAG_MODE_IMPLICIT, 0);
    ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &choiceImplicit, &idInt) ==
                    ASNBER_E_SCHEMA_TYPE);
    asnber_type_desc_t choiceTagged =
        makeType("BadChoice2", ASNBER_TYPE_KIND_CHOICE, ASNBER_TAG_CONTEXT, 0,
                 ASNBER_TAG_MODE_DEFAULT, 0);
    ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &choiceTagged, &idInt) ==
                    ASNBER_E_SCHEMA_TYPE);
    asnber_type_desc_t choiceExplicitUniversal =
        makeType("BadChoice3", ASNBER_TYPE_KIND_CHOICE, ASNBER_TAG_UNIVERSAL, 0,
                 ASNBER_TAG_MODE_EXPLICIT, 0);
    ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &choiceExplicitUniversal,
                                         &idInt) == ASNBER_E_SCHEMA_TYPE);
    asnber_type_desc_t simpleZero =
        makeType("BadSimple", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 0,
                 ASNBER_TAG_MODE_DEFAULT, 0);
    ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &simpleZero, &idInt) ==
                    ASNBER_E_SCHEMA_TYPE);
    asnber_type_desc_t universalExplicit =
        makeType("BadUniversalExplicit", ASNBER_TYPE_KIND_SIMPLE,
                 ASNBER_TAG_UNIVERSAL, 2, ASNBER_TAG_MODE_EXPLICIT, 0);
    ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &universalExplicit, &idInt) ==
                    ASNBER_E_SCHEMA_TYPE);

    /* OF 元素引用。 */
    asnber_type_desc_t ofType = makeType("OfType", ASNBER_TYPE_KIND_SEQUENCE_OF,
                                       ASNBER_TAG_UNIVERSAL, 0,
                                       ASNBER_TAG_MODE_DEFAULT, 0);
    ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &ofType, &idInt) ==
                    ASNBER_E_SCHEMA_TYPE);
    ofType.element_type_id = 99;
    ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &ofType, &idInt) ==
                    ASNBER_E_SCHEMA_TYPE);
    asnber_type_desc_t simpleWithElement =
        makeType("BadElement", ASNBER_TYPE_KIND_SIMPLE, ASNBER_TAG_UNIVERSAL, 2,
                 ASNBER_TAG_MODE_DEFAULT, 1);
    ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &simpleWithElement,
                                         &idInt) == ASNBER_E_SCHEMA_TYPE);

    /* 描述符结构错误。 */
    asnber_type_desc_t badSize = intDesc;
    badSize.struct_size = sizeof(badSize) - 1;
    ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &badSize, &idInt) ==
                    ASNBER_E_INVALID_CONFIG);
    asnber_type_desc_t badFlags = intDesc;
    badFlags.flags = 0x80u;
    ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &badFlags, &idInt) ==
                    ASNBER_E_INVALID_CONFIG);
    ASNBER_TEST_CHECK(asnber_schema_add_type(schema, NULL, &idInt) ==
                    ASNBER_E_INVALID_ARG);
    ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &intDesc, NULL) ==
                    ASNBER_E_INVALID_ARG);

    /* 约束合法性规则（本轮不按类型求值）。 */
    asnber_constraint_t badRange = makeRange(10, 1);
    asnber_type_desc_t rangeDesc = intDesc;
    rangeDesc.constraints = &badRange;
    rangeDesc.constraint_count = 1;
    ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &rangeDesc, &idInt) ==
                    ASNBER_E_SCHEMA_CONSTRAINT);

    asnber_constraint_t maxWithLower = makeMaxConstraint();
    maxWithLower.lower = makeBound(5, 0);
    rangeDesc.constraints = &maxWithLower;
    ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &rangeDesc, &idInt) ==
                    ASNBER_E_SCHEMA_CONSTRAINT);

    asnber_constraint_t maxWithLowerText = makeMaxConstraint();
    maxWithLowerText.lower.decimal = "0";
    maxWithLowerText.lower.decimal_size = 1;
    rangeDesc.constraints = &maxWithLowerText;
    ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &rangeDesc, &idInt) ==
                    ASNBER_E_SCHEMA_CONSTRAINT);

    asnber_constraint_t emptyEnum = makeEnumConstraint(NULL, 0);
    rangeDesc.constraints = &emptyEnum;
    ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &rangeDesc, &idInt) ==
                    ASNBER_E_SCHEMA_CONSTRAINT);

    const int64_t duplicateEnumValues[] = {1, 2, 1};
    asnber_constraint_t duplicateEnum =
        makeEnumConstraint(duplicateEnumValues, 3);
    rangeDesc.constraints = &duplicateEnum;
    ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &rangeDesc, &idInt) ==
                    ASNBER_E_SCHEMA_CONSTRAINT);

    asnber_constraint_t leadingZero =
        makeBigintConstraint("01", 2, "99", 2);
    rangeDesc.constraints = &leadingZero;
    ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &rangeDesc, &idInt) ==
                    ASNBER_E_SCHEMA_CONSTRAINT);

    asnber_constraint_t negativeZero =
        makeBigintConstraint("-0", 2, "9", 1);
    rangeDesc.constraints = &negativeZero;
    ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &rangeDesc, &idInt) ==
                    ASNBER_E_SCHEMA_CONSTRAINT);

    asnber_constraint_t reversedBigint =
        makeBigintConstraint("10", 2, "9", 1);
    rangeDesc.constraints = &reversedBigint;
    ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &rangeDesc, &idInt) ==
                    ASNBER_E_SCHEMA_CONSTRAINT);

    asnber_constraint_t noDecimalBigint = makeMaxConstraint();
    noDecimalBigint.kind = ASNBER_CONSTRAINT_BIGINT_RANGE;
    rangeDesc.constraints = &noDecimalBigint;
    ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &rangeDesc, &idInt) ==
                    ASNBER_E_SCHEMA_CONSTRAINT);

    asnber_constraint_t negativeSize = makeSize(-1, 5);
    rangeDesc.constraints = &negativeSize;
    ASNBER_TEST_CHECK(asnber_schema_add_type(schema, &rangeDesc, &idInt) ==
                    ASNBER_E_SCHEMA_CONSTRAINT);

    asnber_schema_destroy(schema);

    /* 合法约束：MAX、ENUM、BIGINT 数值比较、SIZE 单位中立存储。 */
    ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_EXPLICIT,
                                       &schema) == ASNBER_OK);
    const int64_t enumValues[] = {10, 20, 30};
    asnber_constraint_t constraints[4];
    constraints[0] = makeMaxConstraint();
    constraints[1] = makeEnumConstraint(enumValues, 3);
    constraints[2] = makeBigintConstraint("-100", 4, "100", 3);
    constraints[3] = makeSize(0, 10);
    asnber_type_desc_t constrainedInt = intDesc;
    constrainedInt.name = "ConstrainedInt";
    constrainedInt.constraints = constraints;
    constrainedInt.constraint_count = 4;
    ASNBER_TEST_CHECK(addTypeOk(schema, &constrainedInt, &idInt));

    /* SIZE 对字符串按字节数、对 OF 按元素数；本轮只存储单位无关的区间。 */
    asnber_type_desc_t sizedText = textDesc;
    sizedText.name = "SizedText";
    sizedText.constraints = &constraints[3];
    sizedText.constraint_count = 1;
    uint32_t idSizedText = 0;
    ASNBER_TEST_CHECK(addTypeOk(schema, &sizedText, &idSizedText));
    asnber_type_desc_t sizedOf = makeType("SizedSeqOf", ASNBER_TYPE_KIND_SEQUENCE_OF,
                                        ASNBER_TAG_UNIVERSAL, 0,
                                        ASNBER_TAG_MODE_DEFAULT, 2);
    sizedOf.constraints = &constraints[3];
    sizedOf.constraint_count = 1;
    uint32_t idSizedOf = 0;
    ASNBER_TEST_CHECK(addTypeOk(schema, &sizedOf, &idSizedOf));
    ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);

    asnber_test_constraint_info info;
    ASNBER_TEST_CHECK(asnber_test_schema_type_constraint(schema, 1, 1,
                                                     &info) == 1);
    ASNBER_TEST_CHECK(info.kind == ASNBER_CONSTRAINT_ENUM);
    ASNBER_TEST_CHECK(info.enum_count == 3);
    ASNBER_TEST_CHECK(info.enum_values[0] == 10);
    ASNBER_TEST_CHECK(asnber_test_schema_type_constraint(schema, 1, 2,
                                                     &info) == 1);
    ASNBER_TEST_CHECK(info.kind == ASNBER_CONSTRAINT_BIGINT_RANGE);
    ASNBER_TEST_CHECK(info.lower.decimal_size == 4);
    ASNBER_TEST_CHECK(strcmp(info.lower.decimal, "-100") == 0);
    ASNBER_TEST_CHECK(info.upper.decimal_size == 3);
    ASNBER_TEST_CHECK(strcmp(info.upper.decimal, "100") == 0);
    ASNBER_TEST_CHECK(asnber_test_schema_type_constraint(schema, 3, 0,
                                                     &info) == 1);
    ASNBER_TEST_CHECK(info.lower.value == 0);
    ASNBER_TEST_CHECK(info.upper.value == 10);
    asnber_schema_destroy(schema);

    /* 字段错误。 */
    ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_EXPLICIT,
                                       &schema) == ASNBER_OK);
    ASNBER_TEST_CHECK(addTypeOk(schema, &intDesc, &idInt));
    ASNBER_TEST_CHECK(asnber_schema_add_field(schema, 0, &fieldInt) ==
                    ASNBER_E_SCHEMA_TYPE);
    ASNBER_TEST_CHECK(asnber_schema_add_field(schema, 1, NULL) ==
                    ASNBER_E_INVALID_ARG);
    asnber_field_desc_t badTypeId = makeField("badType", 0);
    ASNBER_TEST_CHECK(asnber_schema_add_field(schema, 1, &badTypeId) ==
                    ASNBER_E_SCHEMA_TYPE);
    asnber_field_desc_t badFieldFlags = makeField("badFlags", 1);
    badFieldFlags.flags = 0x80u;
    ASNBER_TEST_CHECK(asnber_schema_add_field(schema, 1, &badFieldFlags) ==
                    ASNBER_E_INVALID_CONFIG);
    asnber_field_desc_t nullDefault = makeField("nullDefault", 1);
    nullDefault.default_value_size = 3;
    ASNBER_TEST_CHECK(asnber_schema_add_field(schema, 1, &nullDefault) ==
                    ASNBER_E_SCHEMA_DEFAULT);
    asnber_field_desc_t shortDefault = makeField("shortDefault", 1);
    const uint8_t truncated[] = {0x0C, 0x05, 'a'};
    shortDefault.default_value = truncated;
    shortDefault.default_value_size = sizeof(truncated);
    ASNBER_TEST_CHECK(asnber_schema_add_field(schema, 1, &shortDefault) ==
                    ASNBER_E_SCHEMA_DEFAULT);
    asnber_field_desc_t nonCanonical = makeField("nonCanonical", 1);
    const uint8_t longLength[] = {0x0C, 0x81, 0x03, 'a', 'b', 'c'};
    nonCanonical.default_value = longLength;
    nonCanonical.default_value_size = sizeof(longLength);
    ASNBER_TEST_CHECK(asnber_schema_add_field(schema, 1, &nonCanonical) ==
                    ASNBER_E_SCHEMA_DEFAULT);
    asnber_field_desc_t badFieldSize = makeField("badSize", 1);
    badFieldSize.struct_size = sizeof(badFieldSize) - 1;
    ASNBER_TEST_CHECK(asnber_schema_add_field(schema, 1, &badFieldSize) ==
                    ASNBER_E_INVALID_CONFIG);
    asnber_schema_destroy(schema);

    /* 默认值 DER 规范性：通用类型逐个覆盖接受/拒绝判定。 */
    static const uint8_t defEoc[] = {0x00, 0x00};
    static const uint8_t defBoolBad[] = {0x01, 0x01, 0x01};
    static const uint8_t defBoolConstructed[] = {0x21, 0x00};
    static const uint8_t defIntLeadingZero[] = {0x02, 0x02, 0x00, 0x01};
    static const uint8_t defIntLeadingOnes[] = {0x02, 0x02, 0xFF, 0x80};
    static const uint8_t defIntEmpty[] = {0x02, 0x00};
    static const uint8_t defIntConstructed[] = {0x22, 0x00};
    static const uint8_t defBitsEmpty[] = {0x03, 0x00};
    static const uint8_t defBitsUnusedTooLarge[] = {0x03, 0x01, 0x08};
    static const uint8_t defBitsPadding[] = {0x03, 0x02, 0x01, 0x01};
    static const uint8_t defNullNonEmpty[] = {0x05, 0x01, 0x00};
    static const uint8_t defSequencePrimitive[] = {0x10, 0x00};
    static const uint8_t defIndefinite[] = {0x30, 0x80};
    static const uint8_t defLongTagShort[] = {0x1F, 0x1E, 0x00};
    static const uint8_t defLongTagLeadingContinuation[] = {
        0x1F, 0x80, 0x20, 0x00};
    static const uint8_t defLongTagOverflow[] = {
        0x1F, 0x81, 0x80, 0x80, 0x80, 0x00};
    static const uint8_t defLengthLeadingZero[] = {0x0C, 0x81, 0x00};
    static const uint8_t defLengthTooManyBytes[] = {0x0C, 0x89};
    static const uint8_t defLengthOverrun[] = {0x0C, 0x02, 0x41};
    static const uint8_t defTrailingBytes[] = {0x05, 0x00, 0x00};
    static const uint8_t defTagTruncated[] = {0x1F};
    static const uint8_t defLengthTruncated[] = {0x0C};
    static const struct {
        const char *name;
        const uint8_t *tlv;
        size_t size;
    } rejectedDefaults[] = {
        {"defEoc", defEoc, sizeof(defEoc)},
        {"defBoolBad", defBoolBad, sizeof(defBoolBad)},
        {"defBoolConstructed", defBoolConstructed,
         sizeof(defBoolConstructed)},
        {"defIntLeadingZero", defIntLeadingZero, sizeof(defIntLeadingZero)},
        {"defIntLeadingOnes", defIntLeadingOnes, sizeof(defIntLeadingOnes)},
        {"defIntEmpty", defIntEmpty, sizeof(defIntEmpty)},
        {"defIntConstructed", defIntConstructed, sizeof(defIntConstructed)},
        {"defBitsEmpty", defBitsEmpty, sizeof(defBitsEmpty)},
        {"defBitsUnusedTooLarge", defBitsUnusedTooLarge,
         sizeof(defBitsUnusedTooLarge)},
        {"defBitsPadding", defBitsPadding, sizeof(defBitsPadding)},
        {"defNullNonEmpty", defNullNonEmpty, sizeof(defNullNonEmpty)},
        {"defSequencePrimitive", defSequencePrimitive,
         sizeof(defSequencePrimitive)},
        {"defIndefinite", defIndefinite, sizeof(defIndefinite)},
        {"defLongTagShort", defLongTagShort, sizeof(defLongTagShort)},
        {"defLongTagLeadingContinuation", defLongTagLeadingContinuation,
         sizeof(defLongTagLeadingContinuation)},
        {"defLongTagOverflow", defLongTagOverflow, sizeof(defLongTagOverflow)},
        {"defLengthLeadingZero", defLengthLeadingZero,
         sizeof(defLengthLeadingZero)},
        {"defLengthTooManyBytes", defLengthTooManyBytes,
         sizeof(defLengthTooManyBytes)},
        {"defLengthOverrun", defLengthOverrun, sizeof(defLengthOverrun)},
        {"defTrailingBytes", defTrailingBytes, sizeof(defTrailingBytes)},
        {"defTagTruncated", defTagTruncated, sizeof(defTagTruncated)},
        {"defLengthTruncated", defLengthTruncated, sizeof(defLengthTruncated)},
    };
    for (size_t i = 0;
         i < sizeof(rejectedDefaults) / sizeof(rejectedDefaults[0]); ++i) {
        ASNBER_TEST_CHECK(expectDefaultVerdict(ctx, rejectedDefaults[i].name,
                                             rejectedDefaults[i].tlv,
                                             rejectedDefaults[i].size, 0) == 0);
    }

    static const uint8_t defNull[] = {0x05, 0x00};
    static const uint8_t defBoolTrue[] = {0x01, 0x01, 0xFF};
    static const uint8_t defIntMinimalNegative[] = {0x02, 0x01, 0x80};
    static const uint8_t defIntMinimalPositive[] = {0x02, 0x02, 0x00, 0xFF};
    static const uint8_t defBitsValid[] = {0x03, 0x02, 0x04, 0xA0};
    static const uint8_t defSequence[] = {0x30, 0x00};
    static const uint8_t defSet[] = {0x31, 0x00};
    static const uint8_t defContextPrimitive[] = {0x80, 0x00};
    static const uint8_t defUnknownUniversal[] = {0x0F, 0x00};
    static const struct {
        const char *name;
        const uint8_t *tlv;
        size_t size;
    } acceptedDefaults[] = {
        {"defNull", defNull, sizeof(defNull)},
        {"defBoolTrue", defBoolTrue, sizeof(defBoolTrue)},
        {"defIntMinimalNegative", defIntMinimalNegative,
         sizeof(defIntMinimalNegative)},
        {"defIntMinimalPositive", defIntMinimalPositive,
         sizeof(defIntMinimalPositive)},
        {"defBitsValid", defBitsValid, sizeof(defBitsValid)},
        {"defSequence", defSequence, sizeof(defSequence)},
        {"defSet", defSet, sizeof(defSet)},
        {"defContextPrimitive", defContextPrimitive,
         sizeof(defContextPrimitive)},
        {"defUnknownUniversal", defUnknownUniversal,
         sizeof(defUnknownUniversal)},
    };
    for (size_t i = 0;
         i < sizeof(acceptedDefaults) / sizeof(acceptedDefaults[0]); ++i) {
        ASNBER_TEST_CHECK(expectDefaultVerdict(ctx, acceptedDefaults[i].name,
                                             acceptedDefaults[i].tlv,
                                             acceptedDefaults[i].size, 1) == 0);
    }

    /* 嵌套深度超过上限（32 层）即拒绝。 */
    uint8_t deepDefault[80];
    size_t deepSize = 2;
    deepDefault[0] = 0x30;
    deepDefault[1] = 0x00;
    for (int level = 0; level < 34; ++level) {
        memmove(deepDefault + 2, deepDefault, deepSize);
        deepDefault[0] = 0x30;
        deepDefault[1] = (uint8_t)deepSize;
        deepSize += 2;
    }
    ASNBER_TEST_CHECK(expectDefaultVerdict(ctx, "defDeep", deepDefault,
                                         deepSize, 0) == 0);

    /* CHOICE 分支不得可选/带默认/扩展；OF 不得有字段。 */
    ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_EXPLICIT,
                                       &schema) == ASNBER_OK);
    ASNBER_TEST_CHECK(addTypeOk(schema, &intDesc, &idInt));
    asnber_type_desc_t choiceDefault = makeType(
        "ChoiceDefault", ASNBER_TYPE_KIND_CHOICE, ASNBER_TAG_UNIVERSAL, 0,
        ASNBER_TAG_MODE_DEFAULT, 0);
    uint32_t idChoice = 0;
    ASNBER_TEST_CHECK(addTypeOk(schema, &choiceDefault, &idChoice));
    asnber_field_desc_t optionalBranch = makeField("branch", 1);
    optionalBranch.flags = ASNBER_FIELD_OPTIONAL;
    ASNBER_TEST_CHECK(asnber_schema_add_field(schema, idChoice,
                                          &optionalBranch) ==
                    ASNBER_E_SCHEMA_FIELD);
    ASNBER_TEST_CHECK(asnber_schema_add_field(schema, idChoice, &fieldInt) ==
                    ASNBER_OK);
    ofType.element_type_id = 1;
    ofType.name = "SeqOf";
    uint32_t idOf = 0;
    ASNBER_TEST_CHECK(addTypeOk(schema, &ofType, &idOf));
    ASNBER_TEST_CHECK(asnber_schema_add_field(schema, idOf, &fieldInt) ==
                    ASNBER_E_SCHEMA_FIELD);
    asnber_field_desc_t duplicate = makeField("branch", 1);
    ASNBER_TEST_CHECK(asnber_schema_add_field(schema, idChoice, &duplicate) ==
                    ASNBER_OK);
    asnber_field_desc_t duplicateAgain = makeField("branch", 1);
    ASNBER_TEST_CHECK(asnber_schema_add_field(schema, idChoice,
                                          &duplicateAgain) ==
                    ASNBER_E_SCHEMA_FIELD);
    asnber_schema_destroy(schema);

    /* 封存期冲突检查：SET 重复标签、SEQUENCE 可选后继冲突、CHOICE 分支冲突。 */
    ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_EXPLICIT,
                                       &schema) == ASNBER_OK);
    ASNBER_TEST_CHECK(addTypeOk(schema, &intDesc, &idInt));
    asnber_type_desc_t setDesc = makeType("SetDup", ASNBER_TYPE_KIND_SET,
                                        ASNBER_TAG_UNIVERSAL, 0,
                                        ASNBER_TAG_MODE_DEFAULT, 0);
    uint32_t idSet = 0;
    ASNBER_TEST_CHECK(addTypeOk(schema, &setDesc, &idSet));
    asnber_field_desc_t setA = makeField("a", 1);
    asnber_field_desc_t setB = makeField("b", 1);
    ASNBER_TEST_CHECK(asnber_schema_add_field(schema, idSet, &setA) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_schema_add_field(schema, idSet, &setB) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_E_SCHEMA_TYPE);
    asnber_schema_destroy(schema);

    ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_EXPLICIT,
                                       &schema) == ASNBER_OK);
    ASNBER_TEST_CHECK(addTypeOk(schema, &intDesc, &idInt));
    seqDesc.name = "SeqOptionalDup";
    uint32_t idSeq2 = 0;
    ASNBER_TEST_CHECK(addTypeOk(schema, &seqDesc, &idSeq2));
    asnber_field_desc_t seqA = makeField("a", 1);
    seqA.flags = ASNBER_FIELD_OPTIONAL;
    asnber_field_desc_t seqB = makeField("b", 1);
    ASNBER_TEST_CHECK(asnber_schema_add_field(schema, idSeq2, &seqA) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_schema_add_field(schema, idSeq2, &seqB) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_E_SCHEMA_TYPE);
    asnber_schema_destroy(schema);

    ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_EXPLICIT,
                                       &schema) == ASNBER_OK);
    ASNBER_TEST_CHECK(addTypeOk(schema, &intDesc, &idInt));
    choiceDefault.name = "ChoiceDup";
    ASNBER_TEST_CHECK(addTypeOk(schema, &choiceDefault, &idChoice));
    asnber_field_desc_t branchA = makeField("a", 1);
    asnber_field_desc_t branchB = makeField("b", 1);
    ASNBER_TEST_CHECK(asnber_schema_add_field(schema, idChoice, &branchA) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_schema_add_field(schema, idChoice, &branchB) ==
                    ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_E_SCHEMA_TYPE);
    asnber_schema_destroy(schema);

    /* 合法的 SET 与约束存储。 */
    ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_EXPLICIT,
                                       &schema) == ASNBER_OK);
    asnber_constraint_t range = makeRange(-128, 127);
    asnber_type_desc_t intRange = intDesc;
    intRange.constraints = &range;
    intRange.constraint_count = 1;
    ASNBER_TEST_CHECK(addTypeOk(schema, &intRange, &idInt));
    asnber_type_desc_t boolDesc = makeType("BoolType", ASNBER_TYPE_KIND_SIMPLE,
                                         ASNBER_TAG_UNIVERSAL, 1,
                                         ASNBER_TAG_MODE_DEFAULT, 0);
    uint32_t idBool = 0;
    ASNBER_TEST_CHECK(addTypeOk(schema, &boolDesc, &idBool));
    setDesc.name = "SetOk";
    ASNBER_TEST_CHECK(addTypeOk(schema, &setDesc, &idSet));
    ASNBER_TEST_CHECK(asnber_schema_add_field(schema, idSet, &setA) == ASNBER_OK);
    asnber_field_desc_t setB2 = makeField("b", idBool);
    ASNBER_TEST_CHECK(asnber_schema_add_field(schema, idSet, &setB2) == ASNBER_OK);
    ASNBER_TEST_CHECK(asnber_schema_seal(schema) == ASNBER_OK);

    asnber_test_constraint_info rangeInfo;
    ASNBER_TEST_CHECK(asnber_test_schema_type_constraint(schema, 1, 0,
                                                     &rangeInfo) == 1);
    ASNBER_TEST_CHECK(rangeInfo.kind == ASNBER_CONSTRAINT_RANGE);
    ASNBER_TEST_CHECK(rangeInfo.lower.value == -128);
    ASNBER_TEST_CHECK(rangeInfo.upper.value == 127);
    ASNBER_TEST_CHECK(rangeInfo.enum_count == 0);
    asnber_schema_destroy(schema);

    /* destroy(NULL) 空操作；销毁上下文时兜底回收未销毁 schema。 */
    asnber_schema_destroy(NULL);
    ASNBER_TEST_CHECK(asnber_schema_create(ctx, ASNBER_TAG_MODE_DEFAULT,
                                       &schema) == ASNBER_OK);
    asnber_ctx_destroy(ctx);
    return 0;
}
