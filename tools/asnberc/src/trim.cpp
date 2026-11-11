/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

#include "trim.h"

#include <algorithm>
#include <map>
#include <memory>
#include <set>
#include <vector>

namespace asnberc {
namespace {

void collectReachable(const TypeNode *node, std::set<uint32_t> &reachable)
{
    if (node == nullptr || node->isTemplate) {
        return;
    }
    if (!reachable.insert(node->id).second) {
        return;
    }
    collectReachable(node->element, reachable);
    for (const Field &field : node->fields) {
        collectReachable(field.type, reachable);
    }
}

} /* namespace */

void trimToRootType(SchemaModel &model)
{
    const uint32_t oldRootId = model.rootTypeId;

    std::map<uint32_t, TypeNode *> byId;
    for (const std::unique_ptr<TypeNode> &node : model.nodes) {
        if (!node->isTemplate) {
            byId[node->id] = node.get();
        }
    }
    const std::map<uint32_t, TypeNode *>::const_iterator root =
        byId.find(oldRootId);
    if (root == byId.end()) {
        return;
    }

    std::set<uint32_t> reachable;
    collectReachable(root->second, reachable);

    TypeNode *anyNode = model.anyNode;
    const bool keepAny =
        anyNode != nullptr && !anyNode->isTemplate &&
        reachable.count(anyNode->id) != 0;

    std::vector<std::unique_ptr<TypeNode>> retained;
    retained.reserve(model.nodes.size());
    for (std::unique_ptr<TypeNode> &node : model.nodes) {
        if (!node->isTemplate && reachable.count(node->id) != 0) {
            retained.push_back(std::move(node));
        }
    }
    model.nodes = std::move(retained);

    std::vector<TypeNode *> ordered;
    ordered.reserve(model.nodes.size());
    for (const std::unique_ptr<TypeNode> &node : model.nodes) {
        ordered.push_back(node.get());
    }
    std::sort(ordered.begin(), ordered.end(),
              [](const TypeNode *a, const TypeNode *b) {
                  return a->id < b->id;
              });

    std::map<uint32_t, uint32_t> newIds;
    for (size_t i = 0; i < ordered.size(); ++i) {
        newIds[ordered[i]->id] = static_cast<uint32_t>(i + 1);
    }
    for (TypeNode *node : ordered) {
        node->id = newIds[node->id];
    }

    model.rootTypeId = newIds[oldRootId];
    model.anyNode = keepAny ? anyNode : nullptr;

    model.named.clear();
    model.synthetic.clear();
    for (const std::unique_ptr<TypeNode> &node : model.nodes) {
        if (node->synthetic) {
            model.synthetic.push_back(node.get());
        } else {
            model.named.push_back(node.get());
        }
    }
    const auto byIdOrder = [](const TypeNode *a, const TypeNode *b) {
        return a->id < b->id;
    };
    std::sort(model.named.begin(), model.named.end(), byIdOrder);
    std::sort(model.synthetic.begin(), model.synthetic.end(), byIdOrder);
}

} /* namespace asnberc */
