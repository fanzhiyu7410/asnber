/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

#ifndef ASNBERC_TRIM_H_INCLUDED
#define ASNBERC_TRIM_H_INCLUDED

#include "semantic.h"

namespace asnberc {

/*
 * 从 model.rootTypeId 出发保留可达类型，并按原 id 顺序连续重编号 1..N。
 * 边只有 TypeNode::element 与 Field::type；模板节点不保留。
 * 调用前 rootTypeId 必须非 0 且存在于 model 中。
 */
void trimToRootType(SchemaModel &model);

} /* namespace asnberc */

#endif /* ASNBERC_TRIM_H_INCLUDED */
