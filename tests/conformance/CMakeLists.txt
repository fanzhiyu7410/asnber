# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT

asnber_add_test(test_version_conformance test_version_conformance.c)
target_link_libraries(test_version_conformance PRIVATE asnber_test_support)
