/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * 测试专用 schema 探针：把内部类型树投影为 C 可见的扁平结构。
 * 仅位于 tests/ 下，不是公共 ABI。
 */
#ifndef ASNBER_TESTS_SUPPORT_SCHEMA_PROBE_H_INCLUDED
#define ASNBER_TESTS_SUPPORT_SCHEMA_PROBE_H_INCLUDED

#include <asnber/asnber.h>

#include <stddef.h>
#include <stdint.h>

#define ASNBER_TEST_MAX_NAME 64
#define ASNBER_TEST_MAX_CONSTRAINTS 8
#define ASNBER_TEST_MAX_ENUM 16
#define ASNBER_TEST_MAX_DECIMAL 64

#ifdef __cplusplus
extern "C" {
#endif

typedef struct asnber_test_bound_info {
    int32_t is_unbounded;
    int64_t value;
    char decimal[ASNBER_TEST_MAX_DECIMAL];
    size_t decimal_size;
} asnber_test_bound_info;

typedef struct asnber_test_constraint_info {
    uint32_t kind;
    int32_t lower_unbounded;
    int32_t upper_unbounded;
    asnber_test_bound_info lower;
    asnber_test_bound_info upper;
    uint32_t enum_count;
    int64_t enum_values[ASNBER_TEST_MAX_ENUM];
} asnber_test_constraint_info;

typedef struct asnber_test_field_info {
    char name[ASNBER_TEST_MAX_NAME];
    uint32_t type_id;
    uint32_t flags;
    size_t default_size;
    uint32_t constraint_count;
} asnber_test_field_info;

typedef struct asnber_test_type_info {
    char name[ASNBER_TEST_MAX_NAME];
    uint32_t kind;
    uint32_t tag_class;
    uint32_t tag_number;
    uint32_t tag_mode;
    uint32_t element_type_id;
    uint32_t flags;
    uint32_t field_count;
    uint32_t constraint_count;
} asnber_test_type_info;

uint32_t asnber_test_schema_type_count(const asnber_schema_t *schema);
uint32_t asnber_test_schema_module_tag_mode(const asnber_schema_t *schema);
uint32_t asnber_test_schema_root_type_id(const asnber_schema_t *schema);
int asnber_test_schema_sealed(const asnber_schema_t *schema);

int asnber_test_schema_type_info(const asnber_schema_t *schema, uint32_t type_id,
                               asnber_test_type_info *out);
int asnber_test_schema_field_info(const asnber_schema_t *schema, uint32_t type_id,
                                uint32_t index, asnber_test_field_info *out);
int asnber_test_schema_type_constraint(const asnber_schema_t *schema,
                                     uint32_t type_id, uint32_t index,
                                     asnber_test_constraint_info *out);
int asnber_test_schema_field_constraint(const asnber_schema_t *schema,
                                      uint32_t type_id, uint32_t field_index,
                                      uint32_t index,
                                      asnber_test_constraint_info *out);
const uint8_t *asnber_test_schema_field_default(const asnber_schema_t *schema,
                                              uint32_t type_id,
                                              uint32_t field_index,
                                              size_t *out_size);

#ifdef __cplusplus
}
#endif

#endif /* ASNBER_TESTS_SUPPORT_SCHEMA_PROBE_H_INCLUDED */
