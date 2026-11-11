/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 *
 * 测试专用 schema 等价比较实现，见 schema_compare.h。
 */

#include "schema_compare.h"

#include <string.h>

#include "schema_probe.h"

static int same_bound(const asnber_test_bound_info *a,
                      const asnber_test_bound_info *b)
{
    if (a->is_unbounded != b->is_unbounded) {
        return 0;
    }
    if (!a->is_unbounded && a->value != b->value) {
        return 0;
    }
    if (a->decimal_size != b->decimal_size) {
        return 0;
    }
    if (a->decimal_size != 0 &&
        memcmp(a->decimal, b->decimal, a->decimal_size) != 0) {
        return 0;
    }
    return 1;
}

static int same_constraint(const asnber_test_constraint_info *a,
                           const asnber_test_constraint_info *b)
{
    uint32_t i;
    if (a->kind != b->kind || a->lower_unbounded != b->lower_unbounded ||
        a->upper_unbounded != b->upper_unbounded) {
        return 0;
    }
    if (!same_bound(&a->lower, &b->lower) ||
        !same_bound(&a->upper, &b->upper)) {
        return 0;
    }
    if (a->enum_count != b->enum_count) {
        return 0;
    }
    for (i = 0; i < a->enum_count; ++i) {
        if (a->enum_values[i] != b->enum_values[i]) {
            return 0;
        }
    }
    return 1;
}

int asnber_test_compare_schemas(const asnber_schema_t *left,
                              const asnber_schema_t *right)
{
    uint32_t type_count;
    uint32_t module_mode;
    int sealed_left;
    int sealed_right;
    uint32_t t;

    type_count = asnber_test_schema_type_count(left);
    if (type_count != asnber_test_schema_type_count(right)) {
        return 1;
    }
    module_mode = asnber_test_schema_module_tag_mode(left);
    if (module_mode != asnber_test_schema_module_tag_mode(right)) {
        return 2;
    }
    if (asnber_test_schema_root_type_id(left) !=
        asnber_test_schema_root_type_id(right)) {
        return 5;
    }
    sealed_left = asnber_test_schema_sealed(left);
    sealed_right = asnber_test_schema_sealed(right);
    if (sealed_left != sealed_right) {
        return 3;
    }

    for (t = 1; t <= type_count; ++t) {
        asnber_test_type_info ta;
        asnber_test_type_info tb;
        uint32_t f;
        if (!asnber_test_schema_type_info(left, t, &ta) ||
            !asnber_test_schema_type_info(right, t, &tb)) {
            return 4;
        }
        if (strcmp(ta.name, tb.name) != 0 || ta.kind != tb.kind ||
            ta.tag_class != tb.tag_class ||
            ta.tag_number != tb.tag_number || ta.tag_mode != tb.tag_mode ||
            ta.element_type_id != tb.element_type_id ||
            ta.flags != tb.flags || ta.field_count != tb.field_count ||
            ta.constraint_count != tb.constraint_count) {
            return 10u + t;
        }

        for (f = 0; f < ta.field_count; ++f) {
            asnber_test_field_info fa;
            asnber_test_field_info fb;
            size_t size_a = 0;
            size_t size_b = 0;
            const uint8_t *bytes_a;
            const uint8_t *bytes_b;
            if (!asnber_test_schema_field_info(left, t, f, &fa) ||
                !asnber_test_schema_field_info(right, t, f, &fb)) {
                return 20u + t;
            }
            if (strcmp(fa.name, fb.name) != 0 || fa.type_id != fb.type_id ||
                fa.flags != fb.flags ||
                fa.default_size != fb.default_size ||
                fa.constraint_count != fb.constraint_count) {
                return 30u + t;
            }
            bytes_a = asnber_test_schema_field_default(left, t, f, &size_a);
            bytes_b = asnber_test_schema_field_default(right, t, f, &size_b);
            if (size_a != size_b) {
                return 40u + t;
            }
            if (size_a != 0 && (bytes_a == NULL || bytes_b == NULL ||
                                memcmp(bytes_a, bytes_b, size_a) != 0)) {
                return 50u + t;
            }
        }

        for (f = 0; f < ta.constraint_count; ++f) {
            asnber_test_constraint_info ca;
            asnber_test_constraint_info cb;
            if (!asnber_test_schema_type_constraint(left, t, f, &ca) ||
                !asnber_test_schema_type_constraint(right, t, f, &cb)) {
                return 60u + t;
            }
            if (!same_constraint(&ca, &cb)) {
                return 70u + t;
            }
        }

        for (f = 0; f < ta.field_count; ++f) {
            uint32_t c;
            asnber_test_field_info fi;
            if (!asnber_test_schema_field_info(left, t, f, &fi)) {
                return 80u + t;
            }
            for (c = 0; c < fi.constraint_count; ++c) {
                asnber_test_constraint_info ca;
                asnber_test_constraint_info cb;
                if (!asnber_test_schema_field_constraint(left, t, f, c, &ca) ||
                    !asnber_test_schema_field_constraint(right, t, f, c, &cb)) {
                    return 90u + t;
                }
                if (!same_constraint(&ca, &cb)) {
                    return 100u + t;
                }
            }
        }
    }
    return 0;
}
