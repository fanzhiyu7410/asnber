#!/usr/bin/env python3
# Copyright (c) 2026 asnber project contributors
# SPDX-License-Identifier: MIT
"""确定性生成 schema_load 恶意表语料。

随机字节几乎不可能命中 asnber_schema_table.cpp 的结构校验分支（需要合法
magic + CRC32C + 正确的表区间后才进入逐记录校验）。本脚本基于
tests/unit/test_schema_table.c 的最小合法表夹具做逐字段变异，产出能精确
触达这些校验分支的种子，写入 tests/fuzz/corpus/schema_load/。

仅依赖标准库；纯确定性；不加宽断言、不缩表、不删既有语料。
"""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.path.join(ROOT, "tests", "fuzz", "corpus", "schema_load")

UINT64_MAX = 0xFFFFFFFFFFFFFFFF
UINT32_MAX = 0xFFFFFFFF

# ===== 小端读写（独立实现，与库/test 一致） =====

def put_u16(buf, off, value):
    buf[off] = value & 0xFF
    buf[off + 1] = (value >> 8) & 0xFF


def get_u32(buf, off):
    return (buf[off] | (buf[off + 1] << 8) | (buf[off + 2] << 16) |
            (buf[off + 3] << 24))


def put_u32(buf, off, value):
    buf[off] = value & 0xFF
    buf[off + 1] = (value >> 8) & 0xFF
    buf[off + 2] = (value >> 16) & 0xFF
    buf[off + 3] = (value >> 24) & 0xFF


def put_u64(buf, off, value):
    put_u32(buf, off, value & UINT32_MAX)
    put_u32(buf, off + 4, (value >> 32) & UINT32_MAX)


def put_i64(buf, off, value):
    if value >= 0:
        raw = value
    else:
        raw = UINT64_MAX - (-(value + 1))
    put_u64(buf, off, raw)


# ===== CRC32C（Castagnoli，反射实现，与 test_schema_table.c 一致） =====

def crc32c_zeroed(buf, zero_off, zero_len):
    crc = UINT32_MAX
    for i, byte in enumerate(buf):
        if zero_off <= i < zero_off + zero_len:
            byte = 0
        crc ^= byte
        for _ in range(8):
            mask = 0 - (crc & 1)
            crc = (crc >> 1) ^ (0x82F63B78 & mask)
    return (crc ^ UINT32_MAX) & UINT32_MAX


MAGIC = bytes([0x41, 0x53, 0x4E, 0x31, 0x53, 0x43, 0x48, 0x1A])


def refresh_checksum(buf):
    put_u32(buf, 80, 0)
    put_u32(buf, 80, crc32c_zeroed(buf, 80, 4))


# ===== 基础表（无名称表，与 test_schema_table.c 同布局，976 字节） =====

TABLE_SIZE = 976
OFF_STRING_POOL = 104
SIZE_STRING_POOL = 104
OFF_TYPE_TABLE = 216
COUNT_TYPE = 7
OFF_FIELD_TABLE = 552
COUNT_FIELD = 6
OFF_CONSTRAINT_TABLE = 744
COUNT_CONSTRAINT = 4
OFF_DEFAULT_TABLE = 936
COUNT_DEFAULT = 1
OFF_ENUM_ARRAY = 944
OFF_DEFAULT_BYTES = 968

STR_INT_TYPE = 105
STR_TEXT_TYPE = 113
STR_BOOL_TYPE = 122
STR_SEQ_TYPE = 131
STR_SET_TYPE = 139
STR_SEQ_OF_TYPE = 147
STR_CHOICE_TYPE = 157
STR_FIELD_VALUE = 168
STR_FIELD_LABEL = 174
STR_FIELD_A = 180
STR_FIELD_B = 182
STR_FIELD_INT = 184
STR_FIELD_TEXT = 194
STR_DEC_LEADING_ZERO = 205

DEFAULT_BYTES = bytes([0x0C, 0x03, 0x61, 0x62, 0x63])


def put_type(buf, index, name_off, kind, tag_mode, flags, tag_class,
             tag_number, element_type_id, field_start, field_count,
             constraint_start, constraint_count):
    off = OFF_TYPE_TABLE + index * 48
    buf[off:off + 48] = bytes(48)
    put_u32(buf, off, name_off)
    put_u16(buf, off + 4, kind)
    buf[off + 6] = tag_mode
    buf[off + 7] = flags
    buf[off + 8] = tag_class
    put_u32(buf, off + 12, tag_number)
    put_u32(buf, off + 16, element_type_id)
    put_u32(buf, off + 20, field_start)
    put_u32(buf, off + 24, field_count)
    put_u32(buf, off + 28, constraint_start)
    put_u32(buf, off + 32, constraint_count)


def put_field(buf, index, name_off, type_id, flags, default_index,
              constraint_start, constraint_count):
    off = OFF_FIELD_TABLE + index * 32
    buf[off:off + 32] = bytes(32)
    put_u32(buf, off, name_off)
    put_u32(buf, off + 4, type_id)
    put_u16(buf, off + 8, flags)
    put_u32(buf, off + 12, default_index)
    put_u32(buf, off + 16, constraint_start)
    put_u32(buf, off + 20, constraint_count)


def put_constraint(buf, index, kind, flags, enum_off, enum_count, lower_off,
                   lower_size, upper_off, upper_size, lower_value, upper_value):
    off = OFF_CONSTRAINT_TABLE + index * 48
    buf[off:off + 48] = bytes(48)
    put_u16(buf, off, kind)
    put_u16(buf, off + 2, flags)
    put_u32(buf, off + 4, enum_off)
    put_u32(buf, off + 8, enum_count)
    put_u32(buf, off + 12, lower_off)
    put_u32(buf, off + 16, lower_size)
    put_u32(buf, off + 20, upper_off)
    put_u32(buf, off + 24, upper_size)
    put_i64(buf, off + 28, lower_value)
    put_i64(buf, off + 36, upper_value)


def build_base_table():
    buf = bytearray(TABLE_SIZE)
    buf[0:8] = MAGIC
    put_u32(buf, 8, 0x00010000)      # format_version 1.0
    put_u32(buf, 12, 100)            # header_size
    put_u32(buf, 16, 0x01020304)     # endianness
    put_u32(buf, 20, 2)              # module_tag_mode = IMPLICIT
    put_u32(buf, 24, 1)              # flags 位0 = 1
    put_u32(buf, 28, 1)              # checksum_alg = CRC32C
    put_u64(buf, 32, TABLE_SIZE)     # total_size
    put_u32(buf, 40, OFF_STRING_POOL)
    put_u32(buf, 44, SIZE_STRING_POOL)
    put_u32(buf, 48, OFF_TYPE_TABLE)
    put_u32(buf, 52, COUNT_TYPE)
    put_u32(buf, 56, OFF_FIELD_TABLE)
    put_u32(buf, 60, COUNT_FIELD)
    put_u32(buf, 64, OFF_CONSTRAINT_TABLE)
    put_u32(buf, 68, COUNT_CONSTRAINT)
    put_u32(buf, 72, OFF_DEFAULT_TABLE)
    put_u32(buf, 76, COUNT_DEFAULT)
    put_u32(buf, 96, 4)              # root_type_id = SeqType

    buf[OFF_STRING_POOL] = 0
    buf[STR_INT_TYPE:STR_INT_TYPE + 8] = b"IntType\x00"
    buf[STR_TEXT_TYPE:STR_TEXT_TYPE + 9] = b"TextType\x00"
    buf[STR_BOOL_TYPE:STR_BOOL_TYPE + 9] = b"BoolType\x00"
    buf[STR_SEQ_TYPE:STR_SEQ_TYPE + 8] = b"SeqType\x00"
    buf[STR_SET_TYPE:STR_SET_TYPE + 8] = b"SetType\x00"
    buf[STR_SEQ_OF_TYPE:STR_SEQ_OF_TYPE + 10] = b"SeqOfType\x00"
    buf[STR_CHOICE_TYPE:STR_CHOICE_TYPE + 11] = b"ChoiceType\x00"
    buf[STR_FIELD_VALUE:STR_FIELD_VALUE + 6] = b"value\x00"
    buf[STR_FIELD_LABEL:STR_FIELD_LABEL + 6] = b"label\x00"
    buf[STR_FIELD_A:STR_FIELD_A + 2] = b"a\x00"
    buf[STR_FIELD_B:STR_FIELD_B + 2] = b"b\x00"
    buf[STR_FIELD_INT:STR_FIELD_INT + 10] = b"intBranch\x00"
    buf[STR_FIELD_TEXT:STR_FIELD_TEXT + 11] = b"textBranch\x00"
    buf[STR_DEC_LEADING_ZERO:STR_DEC_LEADING_ZERO + 3] = b"01\x00"

    put_type(buf, 0, STR_INT_TYPE, 0, 0, 0, 0, 2, 0, 0, 0, 0, 1)
    put_type(buf, 1, STR_TEXT_TYPE, 0, 0, 0, 0, 12, 0, 0, 0, 1, 1)
    put_type(buf, 2, STR_BOOL_TYPE, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0)
    put_type(buf, 3, STR_SEQ_TYPE, 1, 0, 1, 0, 0, 0, 0, 2, 0, 0)
    put_type(buf, 4, STR_SET_TYPE, 2, 0, 0, 0, 0, 0, 2, 2, 0, 0)
    put_type(buf, 5, STR_SEQ_OF_TYPE, 4, 0, 0, 0, 0, 1, 0, 0, 0, 0)
    put_type(buf, 6, STR_CHOICE_TYPE, 3, 0, 0, 0, 0, 0, 4, 2, 0, 0)

    put_field(buf, 0, STR_FIELD_VALUE, 1, 0, 0, 2, 1)
    put_field(buf, 1, STR_FIELD_LABEL, 2, 1, COUNT_DEFAULT, 0, 0)
    put_field(buf, 2, STR_FIELD_A, 1, 0, 0, 3, 1)
    put_field(buf, 3, STR_FIELD_B, 3, 0, 0, 0, 0)
    put_field(buf, 4, STR_FIELD_INT, 1, 0, 0, 0, 0)
    put_field(buf, 5, STR_FIELD_TEXT, 2, 0, 0, 0, 0)

    put_constraint(buf, 0, 0, 0, 0, 0, 0, 0, 0, 0, -128, 127)
    put_constraint(buf, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 64)
    put_constraint(buf, 2, 2, 0, OFF_ENUM_ARRAY, 3, 0, 0, 0, 0, 0, 0)
    put_constraint(buf, 3, 3, 0x0002, 0, 0, 0, 0, 0, 0, 0, 0)

    put_u32(buf, OFF_DEFAULT_TABLE, OFF_DEFAULT_BYTES)
    put_u32(buf, OFF_DEFAULT_TABLE + 4, len(DEFAULT_BYTES))
    put_i64(buf, OFF_ENUM_ARRAY, 1)
    put_i64(buf, OFF_ENUM_ARRAY + 8, 2)
    put_i64(buf, OFF_ENUM_ARRAY + 16, 3)
    buf[OFF_DEFAULT_BYTES:OFF_DEFAULT_BYTES + 5] = DEFAULT_BYTES

    refresh_checksum(buf)
    return buf


# ===== 名称表基础表（header_size=108，含 2 类型 + 2 名称） =====

# 布局（绝对偏移）：
NAMES_HEADER_SIZE = 108
NAMES_STRING_POOL = 108
NAMES_STR_INT = 109      # "IntType"
NAMES_STR_BITSTR = 117   # "BitStr"
NAMES_STR_NUM_A = 124    # "numA"
NAMES_STR_NUM_B = 129    # "numB"
NAMES_STR_BIT_A = 134    # "bitA"
NAMES_STR_BIT_B = 139    # "bitB"
NAMES_STRING_SIZE = 36   # 144 - 108
NAMES_TYPE_TABLE = 144
NAMES_TYPE_COUNT = 2     # IntType(INTEGER) + BitStr(BIT STRING)
NAMES_NAME_TABLE = 144 + 2 * 48  # 240
NAMES_NAME_COUNT = 2
NAMES_TOTAL = NAMES_NAME_TABLE + NAMES_NAME_COUNT * 24  # 288


def names_put_type(buf, index, name_off, kind, tag_class, tag_number):
    off = NAMES_TYPE_TABLE + index * 48
    buf[off:off + 48] = bytes(48)
    put_u32(buf, off, name_off)
    put_u16(buf, off + 4, kind)
    buf[off + 6] = 0   # tag_mode
    buf[off + 7] = 0   # flags
    buf[off + 8] = tag_class
    put_u32(buf, off + 12, tag_number)


def names_put_name(buf, index, type_id, name_off, kind, flags, value):
    off = NAMES_NAME_TABLE + index * 24
    buf[off:off + 24] = bytes(24)
    put_u32(buf, off, type_id)
    put_u32(buf, off + 4, name_off)
    put_u16(buf, off + 8, kind)
    put_u16(buf, off + 10, flags)
    put_u32(buf, off + 12, 0)   # reserved
    put_i64(buf, off + 16, value)


def build_named_table():
    buf = bytearray(NAMES_TOTAL)
    buf[0:8] = MAGIC
    put_u32(buf, 8, 0x00010000)
    put_u32(buf, 12, NAMES_HEADER_SIZE)
    put_u32(buf, 16, 0x01020304)
    put_u32(buf, 20, 2)          # IMPLICIT
    put_u32(buf, 24, 1)
    put_u32(buf, 28, 1)
    put_u64(buf, 32, NAMES_TOTAL)
    put_u32(buf, 40, NAMES_STRING_POOL)
    put_u32(buf, 44, NAMES_STRING_SIZE)
    put_u32(buf, 48, NAMES_TYPE_TABLE)
    put_u32(buf, 52, NAMES_TYPE_COUNT)
    put_u32(buf, 56, 0)          # field offset/count = 0
    put_u32(buf, 60, 0)
    put_u32(buf, 64, 0)          # constraint offset/count = 0
    put_u32(buf, 68, 0)
    put_u32(buf, 72, 0)          # default offset/count = 0
    put_u32(buf, 76, 0)
    put_u32(buf, 96, 1)          # root_type_id = IntType
    put_u32(buf, 100, NAMES_NAME_TABLE)
    put_u32(buf, 104, NAMES_NAME_COUNT)

    buf[NAMES_STRING_POOL] = 0
    buf[NAMES_STR_INT:NAMES_STR_INT + 8] = b"IntType\x00"
    buf[NAMES_STR_BITSTR:NAMES_STR_BITSTR + 7] = b"BitStr\x00"
    buf[NAMES_STR_NUM_A:NAMES_STR_NUM_A + 5] = b"numA\x00"
    buf[NAMES_STR_NUM_B:NAMES_STR_NUM_B + 5] = b"numB\x00"
    buf[NAMES_STR_BIT_A:NAMES_STR_BIT_A + 5] = b"bitA\x00"
    buf[NAMES_STR_BIT_B:NAMES_STR_BIT_B + 5] = b"bitB\x00"

    names_put_type(buf, 0, NAMES_STR_INT, 0, 0, 2)     # IntType INTEGER
    names_put_type(buf, 1, NAMES_STR_BITSTR, 0, 0, 3)  # BitStr BIT STRING

    names_put_name(buf, 0, 1, NAMES_STR_NUM_A, 1, 0, 0)  # NUMBER_NAME
    names_put_name(buf, 1, 2, NAMES_STR_BIT_A, 0, 0, 0)  # BIT_NAME

    refresh_checksum(buf)
    return buf


# ===== decimal 基础表（header_size=100，1 类型 + 2 约束，含十进制字符串池） =====
# 触达 validateConstraintRecords 的 decimalRefValid / decimalCharsValid /
# compareDecimalText 以及 RANGE(kind 0) / BIGINT_RANGE(kind 4) 的十进制分支。

DEC_HEADER_SIZE = 100
DEC_POOL = 104
DEC_INT = 105     # "IntType"
DEC_5 = 113       # "5"
DEC_999 = 115     # "999"
DEC_NEG5 = 119    # "-5"
DEC_3 = 122       # "3"
DEC_NEG0 = 124    # "-0"
DEC_001 = 127     # "001"
DEC_9X9 = 131     # "9x9"
DEC_DASH = 135    # "-"
DEC_BIG = 137     # "123456789012345678901234567890"
DEC_POOL_SIZE = 64          # 池 [104, 168)
DEC_TYPE = 168
DEC_TYPE_COUNT = 1
DEC_CONSTRAINT = 216
DEC_CONSTRAINT_COUNT = 2
DEC_TOTAL = DEC_CONSTRAINT + DEC_CONSTRAINT_COUNT * 48  # 312


def put_type_g(buf, table_off, index, name_off, kind, tag_mode, flags,
               tag_class, tag_number, field_start, field_count,
               constraint_start, constraint_count):
    off = table_off + index * 48
    buf[off:off + 48] = bytes(48)
    put_u32(buf, off, name_off)
    put_u16(buf, off + 4, kind)
    buf[off + 6] = tag_mode
    buf[off + 7] = flags
    buf[off + 8] = tag_class
    put_u32(buf, off + 12, tag_number)
    put_u32(buf, off + 16, 0)   # element_type_id
    put_u32(buf, off + 20, field_start)
    put_u32(buf, off + 24, field_count)
    put_u32(buf, off + 28, constraint_start)
    put_u32(buf, off + 32, constraint_count)


def put_constraint_g(buf, table_off, index, kind, flags, lower_off, lower_size,
                     upper_off, upper_size, lower_value, upper_value):
    off = table_off + index * 48
    buf[off:off + 48] = bytes(48)
    put_u16(buf, off, kind)
    put_u16(buf, off + 2, flags)
    put_u32(buf, off + 4, 0)    # enum_off
    put_u32(buf, off + 8, 0)    # enum_count
    put_u32(buf, off + 12, lower_off)
    put_u32(buf, off + 16, lower_size)
    put_u32(buf, off + 20, upper_off)
    put_u32(buf, off + 24, upper_size)
    put_i64(buf, off + 28, lower_value)
    put_i64(buf, off + 36, upper_value)


def build_decimal_table():
    buf = bytearray(DEC_TOTAL)
    buf[0:8] = MAGIC
    put_u32(buf, 8, 0x00010000)
    put_u32(buf, 12, DEC_HEADER_SIZE)
    put_u32(buf, 16, 0x01020304)
    put_u32(buf, 20, 2)          # IMPLICIT
    put_u32(buf, 24, 1)
    put_u32(buf, 28, 1)
    put_u64(buf, 32, DEC_TOTAL)
    put_u32(buf, 40, DEC_POOL)
    put_u32(buf, 44, DEC_POOL_SIZE)
    put_u32(buf, 48, DEC_TYPE)
    put_u32(buf, 52, DEC_TYPE_COUNT)
    put_u32(buf, 56, 0)          # field 0
    put_u32(buf, 60, 0)
    put_u32(buf, 64, DEC_CONSTRAINT)
    put_u32(buf, 68, DEC_CONSTRAINT_COUNT)
    put_u32(buf, 72, 0)          # default 0
    put_u32(buf, 76, 0)
    put_u32(buf, 96, 1)          # root_type_id = IntType

    buf[DEC_POOL] = 0
    buf[DEC_INT:DEC_INT + 8] = b"IntType\x00"
    buf[DEC_5:DEC_5 + 2] = b"5\x00"
    buf[DEC_999:DEC_999 + 4] = b"999\x00"
    buf[DEC_NEG5:DEC_NEG5 + 3] = b"-5\x00"
    buf[DEC_3:DEC_3 + 2] = b"3\x00"
    buf[DEC_NEG0:DEC_NEG0 + 3] = b"-0\x00"
    buf[DEC_001:DEC_001 + 4] = b"001\x00"
    buf[DEC_9X9:DEC_9X9 + 4] = b"9x9\x00"
    buf[DEC_DASH:DEC_DASH + 2] = b"-\x00"
    buf[DEC_BIG:DEC_BIG + 31] = b"123456789012345678901234567890\x00"

    put_type_g(buf, DEC_TYPE, 0, DEC_INT, 0, 0, 0, 0, 2, 0, 0, 0,
               DEC_CONSTRAINT_COUNT)

    put_constraint_g(buf, DEC_CONSTRAINT, 0, 0, 0, DEC_5, 1, DEC_999, 3, 0, 0)
    put_constraint_g(buf, DEC_CONSTRAINT, 1, 4, 0, DEC_5, 1, DEC_999, 3, 0, 0)

    refresh_checksum(buf)
    return buf


# ===== 带 SIZE 约束的名称表（BitStr 的 BIT_NAME value>=upper 边界） =====
# 在 named 表基础上追加一条 SIZE 约束表，使 finiteSizeUpperBound 对
# BitStr 返回有限上界；BIT_NAME 的 value 恰好等于上界，触达 818 行分支。
NAMES_CONSTRAINT_TOTAL = NAMES_TOTAL + 48      # 336
NAMES_CONSTRAINT_TABLE = NAMES_TOTAL           # 288


def build_named_constraint_table():
    t = bytearray(NAMES_CONSTRAINT_TOTAL)
    t[0:NAMES_TOTAL] = build_named_table()
    # header：约束表 offset/count 与 total_size
    put_u64(t, 32, NAMES_CONSTRAINT_TOTAL)
    put_u32(t, 64, NAMES_CONSTRAINT_TABLE)
    put_u32(t, 68, 1)
    # type[1]=BitStr 挂一条 SIZE 约束（constraint_start=0, count=1）
    put_u32(t, NAMES_TYPE_TABLE + 1 * 48 + 28, 0)
    put_u32(t, NAMES_TYPE_TABLE + 1 * 48 + 32, 1)
    # constraint[0]: SIZE(0..8)
    put_u16(t, NAMES_CONSTRAINT_TABLE, 1)       # kind = SIZE
    put_u16(t, NAMES_CONSTRAINT_TABLE + 2, 0)   # flags
    put_i64(t, NAMES_CONSTRAINT_TABLE + 28, 0)  # lower = 0
    put_i64(t, NAMES_CONSTRAINT_TABLE + 36, 8)  # upper = 8
    # name[1]=BIT_NAME value=8（>= upper）
    put_i64(t, NAMES_NAME_TABLE + 1 * 24 + 16, 8)
    refresh_checksum(t)
    return t


# ===== 变异与写盘 =====

def clone(table):
    return bytearray(table)


def emit(name, table):
    path = os.path.join(CORPUS, name)
    with open(path, "wb") as f:
        f.write(bytes(table))


def mutate_base(name, fn):
    t = clone(base)
    fn(t)
    refresh_checksum(t)
    emit(name, t)


def mutate_named(name, fn):
    t = clone(named)
    fn(t)
    refresh_checksum(t)
    emit(name, t)


def mutate_decimal(name, fn):
    t = clone(decimal)
    fn(t)
    refresh_checksum(t)
    emit(name, t)


# 修改 decimal 表第 cidx 条约束的下界 / 上界十进制引用（offset/size 指向字符串池）。
def dec_lower(cidx, off, size):
    def fn(t):
        put_u32(t, DEC_CONSTRAINT + cidx * 48 + 12, off)
        put_u32(t, DEC_CONSTRAINT + cidx * 48 + 16, size)
    return fn


def dec_upper(cidx, off, size):
    def fn(t):
        put_u32(t, DEC_CONSTRAINT + cidx * 48 + 20, off)
        put_u32(t, DEC_CONSTRAINT + cidx * 48 + 24, size)
    return fn


base = None
named = None
decimal = None


def generate():
    global base, named, decimal
    base = build_base_table()
    named = build_named_table()
    decimal = build_decimal_table()

    # 自检：CRC 与 test_schema_table.c 的向量一致。
    assert crc32c_zeroed(b"123456789", 0, 0) == 0xE3069283
    assert get_u32(base, 80) == crc32c_zeroed(base, 80, 4)

    # 正向种子：合法最小表（无名称表）与合法带名称表（覆盖 buildTree/名称解析正路径）。
    emit("valid_base.bin", base)
    emit("valid_named.bin", named)

    # ---- 头部字段 ----
    # magic 不匹配（>= 96 字节才能进入 validateHeader 的 magic 循环；CRC 已按
    # 破坏后的字节重算，但 magic 检查先于 CRC，故返回 formatError(0)）。
    mutate_base("bad_magic.bin",
                lambda t: t.__setitem__(0, 0x42))
    mutate_base("bad_format_version.bin",
                lambda t: put_u32(t, 8, 0x00020000))
    mutate_base("bad_header_size.bin",
                lambda t: put_u32(t, 12, 95))
    mutate_base("bad_endianness.bin",
                lambda t: put_u32(t, 16, 0x04030201))
    mutate_base("bad_tag_mode.bin",
                lambda t: put_u32(t, 20, 4))
    mutate_base("bad_flags.bin",
                lambda t: put_u32(t, 24, 3))
    mutate_base("bad_checksum_alg.bin",
                lambda t: put_u32(t, 28, 2))
    mutate_base("bad_total_size.bin",
                lambda t: put_u64(t, 32, TABLE_SIZE + 1))
    mutate_base("bad_reserved0.bin",
                lambda t: put_u32(t, 84, 1))
    # bad_crc 必须保留损坏的校验和，不能走 mutate_base（它会重算 CRC）。
    _bad_crc = clone(base)
    put_u32(_bad_crc, 80, (get_u32(base, 80) ^ 1) & UINT32_MAX)
    emit("bad_crc.bin", _bad_crc)

    # ---- 区域越界 / 重叠 ----
    mutate_base("region_string_zero.bin",
                lambda t: put_u32(t, 44, 0))
    mutate_base("region_string_oob.bin",
                lambda t: put_u32(t, 40, 0xFFFF))
    mutate_base("region_type_oob.bin",
                lambda t: put_u32(t, 48, 0xFFFF))
    mutate_base("region_field_oob.bin",
                lambda t: put_u32(t, 56, 0xFFFF))
    mutate_base("region_constraint_oob.bin",
                lambda t: put_u32(t, 64, 0xFFFF))
    mutate_base("region_default_oob.bin",
                lambda t: put_u32(t, 72, 0xFFFF))
    mutate_base("region_string_first_byte.bin",
                lambda t: t.__setitem__(OFF_STRING_POOL, 0x58))
    mutate_base("region_overlap.bin",
                lambda t: put_u32(t, 48, OFF_STRING_POOL))

    # ---- 类型记录 ----
    mutate_base("type_name_badref.bin",
                lambda t: put_u32(t, OFF_TYPE_TABLE, 0))
    mutate_base("type_kind_gt6.bin",
                lambda t: put_u16(t, OFF_TYPE_TABLE + 4, 7))
    mutate_base("type_tag_mode_gt2.bin",
                lambda t: t.__setitem__(OFF_TYPE_TABLE + 6, 3))
    mutate_base("type_reserved.bin",
                lambda t: put_u32(t, OFF_TYPE_TABLE + 36, 1))
    mutate_base("type_tag_class_gt3.bin",
                lambda t: t.__setitem__(OFF_TYPE_TABLE + 8, 4))
    mutate_base("type_field_start_oob.bin",
                lambda t: put_u32(t, OFF_TYPE_TABLE + 20, 100))
    mutate_base("type_constraint_start_oob.bin",
                lambda t: put_u32(t, OFF_TYPE_TABLE + 28, 100))
    mutate_base("type_kind_with_fields.bin",
                lambda t: (put_u16(t, OFF_TYPE_TABLE + 6 * 48 + 4, 5),
                           put_u32(t, OFF_TYPE_TABLE + 6 * 48 + 20, 1),
                           put_u32(t, OFF_TYPE_TABLE + 6 * 48 + 24, 1)))
    mutate_base("root_type_id_oob.bin",
                lambda t: put_u32(t, 96, 8))

    # ---- 字段记录 ----
    mutate_base("field_name_badref.bin",
                lambda t: put_u32(t, OFF_FIELD_TABLE, 0))
    mutate_base("field_type_id_zero.bin",
                lambda t: put_u32(t, OFF_FIELD_TABLE + 4, 0))
    mutate_base("field_type_id_oob.bin",
                lambda t: put_u32(t, OFF_FIELD_TABLE + 4, 99))
    mutate_base("field_flags.bin",
                lambda t: put_u16(t, OFF_FIELD_TABLE + 8, 0x0004))
    mutate_base("field_default_index_oob.bin",
                lambda t: put_u32(t, OFF_FIELD_TABLE + 12, 2))
    mutate_base("field_constraint_start_oob.bin",
                lambda t: put_u32(t, OFF_FIELD_TABLE + 16, 100))

    # ---- 约束记录 ----
    mutate_base("constraint_kind_gt4.bin",
                lambda t: put_u16(t, OFF_CONSTRAINT_TABLE, 5))
    mutate_base("constraint_flags.bin",
                lambda t: put_u16(t, OFF_CONSTRAINT_TABLE + 2, 0x0004))
    mutate_base("constraint_reserved.bin",
                lambda t: put_u32(t, OFF_CONSTRAINT_TABLE + 44, 1))
    mutate_base("constraint_enum_empty.bin",
                lambda t: put_u32(t, OFF_CONSTRAINT_TABLE + 2 * 48 + 8, 0))
    mutate_base("constraint_enum_oob.bin",
                lambda t: put_u32(t, OFF_CONSTRAINT_TABLE + 2 * 48 + 4, 0xFFFF))
    mutate_base("constraint_enum_dup.bin",
                lambda t: put_i64(t, OFF_ENUM_ARRAY + 16, 1))
    mutate_base("constraint_nonenum_enum.bin",
                lambda t: put_u32(t, OFF_CONSTRAINT_TABLE + 4, 1))
    mutate_base("constraint_range_reverse.bin",
                lambda t: (put_i64(t, OFF_CONSTRAINT_TABLE + 28, 127),
                           put_i64(t, OFF_CONSTRAINT_TABLE + 36, -128)))
    mutate_base("constraint_size_negative.bin",
                lambda t: put_i64(t, OFF_CONSTRAINT_TABLE + 1 * 48 + 28, -1))
    mutate_base("constraint_size_reverse.bin",
                lambda t: (put_i64(t, OFF_CONSTRAINT_TABLE + 1 * 48 + 28, 64),
                           put_i64(t, OFF_CONSTRAINT_TABLE + 1 * 48 + 36, 0)))
    mutate_base("constraint_max_with_lower.bin",
                lambda t: put_i64(t, OFF_CONSTRAINT_TABLE + 3 * 48 + 28, 5))

    # ---- 默认值记录 ----
    mutate_base("default_size_zero.bin",
                lambda t: put_u32(t, OFF_DEFAULT_TABLE + 4, 0))
    mutate_base("default_offset_oob.bin",
                lambda t: put_u32(t, OFF_DEFAULT_TABLE, 0xFFFF))
    mutate_base("default_overlap.bin",
                lambda t: put_u32(t, OFF_DEFAULT_TABLE, OFF_TYPE_TABLE))
    mutate_base("default_bad_tlv.bin",
                lambda t: t.__setitem__(OFF_DEFAULT_BYTES + 1, 0x05))

    # ---- 名称记录 ----
    mutate_named("name_type_id_oob.bin",
                 lambda t: put_u32(t, NAMES_NAME_TABLE, 99))
    mutate_named("name_off_bad.bin",
                 lambda t: put_u32(t, NAMES_NAME_TABLE + 4, 0xFFFF))
    mutate_named("name_kind_gt1.bin",
                 lambda t: put_u16(t, NAMES_NAME_TABLE + 8, 2))
    mutate_named("name_flags_bad.bin",
                 lambda t: put_u16(t, NAMES_NAME_TABLE + 10, 0x0002))
    mutate_named("name_reserved.bin",
                 lambda t: put_u32(t, NAMES_NAME_TABLE + 12, 1))
    mutate_named("name_bit_flags.bin",
                 lambda t: put_u16(t, NAMES_NAME_TABLE + 24 + 10, 0x0001))
    mutate_named("name_bit_type_mismatch.bin",
                 lambda t: put_u16(t, NAMES_NAME_TABLE + 8, 0))  # BIT_NAME 指向 INTEGER
    mutate_named("name_bit_value_oob.bin",
                 lambda t: put_i64(t, NAMES_NAME_TABLE + 24 + 16, -1))
    mutate_named("name_num_type_mismatch.bin",
                 lambda t: put_u32(t, NAMES_NAME_TABLE, 2))  # NUMBER_NAME 指向 BitStr
    mutate_named("name_num_flag_not_ext.bin",
                 lambda t: put_u16(t, NAMES_NAME_TABLE + 10, 0x0001))
    mutate_named("name_dup_name.bin",
                 lambda t: names_put_name(t, 1, 1, NAMES_STR_NUM_A, 1, 0, 1))
    mutate_named("name_dup_value.bin",
                 lambda t: names_put_name(t, 1, 1, NAMES_STR_NUM_B, 1, 0, 0))

    # ---- 十进制约束（RANGE/BIGINT_RANGE 的 decimalRefValid / decimalCharsValid /
    #      compareDecimalText 分支） ----
    emit("valid_decimal.bin", decimal)

    # RANGE(kind 0) 与 BIGINT_RANGE(kind 4) 的上下界反向（compareDecimalText > 0）。
    mutate_decimal("decimal_range_reverse.bin",
                   lambda t: (dec_lower(0, DEC_999, 3)(t),
                              dec_upper(0, DEC_5, 1)(t)))
    mutate_decimal("decimal_bigint_reverse.bin",
                   lambda t: (dec_lower(1, DEC_999, 3)(t),
                              dec_upper(1, DEC_5, 1)(t)))
    # BIGINT_RANGE 上下界十进制引用均为 0（kind 4 至少需要一个引用）。
    mutate_decimal("decimal_bigint_nobounds.bin",
                   lambda t: (dec_lower(1, 0, 0)(t),
                              dec_upper(1, 0, 0)(t)))
    # compareDecimalText 等长逐位比较（"5" vs "3"，lc != rc）与异号比较（"-5" vs "5"）。
    mutate_decimal("decimal_eqlen_reverse.bin",
                   lambda t: (dec_lower(0, DEC_5, 1)(t),
                              dec_upper(0, DEC_3, 1)(t)))
    mutate_decimal("decimal_mixed_sign.bin",
                   lambda t: (dec_lower(0, DEC_NEG5, 2)(t),
                              dec_upper(0, DEC_5, 1)(t)))
    # decimalCharsValid 各类非法十进制文本。
    mutate_decimal("decimal_leading_zero.bin",
                   lambda t: dec_lower(0, DEC_001, 3)(t))
    mutate_decimal("decimal_bad_char.bin",
                   lambda t: dec_lower(0, DEC_9X9, 3)(t))
    mutate_decimal("decimal_neg_zero.bin",
                   lambda t: dec_lower(0, DEC_NEG0, 2)(t))
    mutate_decimal("decimal_dash_only.bin",
                   lambda t: dec_lower(0, DEC_DASH, 1)(t))
    # decimalRefValid 引用非法。
    mutate_decimal("decimal_ref_zero_size.bin",
                   lambda t: dec_lower(0, DEC_5, 0)(t))
    mutate_decimal("decimal_ref_oob_size.bin",
                   lambda t: dec_lower(0, DEC_BIG, 31)(t))
    mutate_decimal("decimal_ref_bad_offset.bin",
                   lambda t: dec_lower(0, DEC_POOL, 1)(t))
    mutate_decimal("decimal_ref_no_nul.bin",
                   lambda t: dec_lower(0, DEC_999, 4)(t))
    # 上界（upper）十进制引用的非法分支（dec_lower 只覆盖下界）。
    mutate_decimal("decimal_upper_oob.bin",
                   lambda t: dec_upper(0, DEC_BIG, 31)(t))
    mutate_decimal("decimal_upper_badchar.bin",
                   lambda t: dec_upper(0, DEC_9X9, 3)(t))

    # ---- 剩余可达校验分支 ----

    # stringRefValid 池内到末尾无 NUL：type[0] 名引用指向池尾非零字节。
    mutate_base("type_name_nonul.bin",
                lambda t: (put_u32(t, OFF_TYPE_TABLE, 205),
                           t.__setitem__(207, 0x41)))

    # 名称表 offset（header offset 100）越界。
    mutate_named("name_table_offset_oob.bin",
                 lambda t: put_u32(t, 100, 0xFFFF))

    # 两个构造类型的 field 区间重叠（type[4] 与 type[3] 均覆盖 [0,2)）。
    mutate_base("type_field_overlap.bin",
                lambda t: put_u32(t, OFF_TYPE_TABLE + 4 * 48 + 20, 0))

    # module_tag_mode 归一分支：0=AUTOMATIC、1=EXPLICIT、3=DEFAULT。
    mutate_base("tagmode_auto.bin", lambda t: put_u32(t, 20, 0))
    mutate_base("tagmode_explicit.bin", lambda t: put_u32(t, 20, 1))
    mutate_base("tagmode_default.bin", lambda t: put_u32(t, 20, 3))

    # BIT_NAME value 恰好等于 SIZE 上界（覆盖 finiteSizeUpperBound 与 818 行）。
    emit("name_bit_value_ge_upper.bin", build_named_constraint_table())


def main():
    os.makedirs(CORPUS, exist_ok=True)
    generate()
    print("malformed schema_load corpus generated under", CORPUS)


if __name__ == "__main__":
    main()