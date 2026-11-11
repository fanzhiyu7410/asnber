/*
 * Copyright (c) 2026 asnber project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 描述表 1.0 生成：字符串池、类型/字段/约束/默认值四张表、文件头、
 * CRC32C 与小端写入，以及确定性的 C 数组输出。
 */
#ifndef ASNBERC_TABLE_H_INCLUDED
#define ASNBERC_TABLE_H_INCLUDED

#include <cstdint>
#include <string>
#include <vector>

#include "semantic.h"

namespace asnberc {

struct TableOutput {
    std::vector<uint8_t> bytes;
    std::uint32_t typeCount = 0;
    std::uint32_t namedTypeCount = 0;
    std::string symbol;
    std::string sizeSymbol;
};

TableOutput buildTable(const SchemaModel &model, const std::string &moduleName);

std::string renderCArray(const TableOutput &output);

} /* namespace asnberc */

#endif /* ASNBERC_TABLE_H_INCLUDED */
