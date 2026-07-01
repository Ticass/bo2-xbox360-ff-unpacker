#!/usr/bin/env python3
"""Parser/disassembler/repacker for BO2 Xbox 360 Treyarch Lua UI bytecode.

This is not a full source decompiler yet. It provides the foundation we need:

- parse the observed Treyarch Lua header/type table
- parse function prototypes, instructions, constants, and nested prototypes
- emit a readable disassembly/pseudo listing
- emit editable bytecode workspace JSON
- rebuild bytecode from workspace JSON while preserving unknown bytes
- recompile raw bytecode chunks losslessly, with optional manifest checks

The bytecode is HavokScript/Treyarch T6 Lua data with Xbox-specific byte order
and wrapper fields. Until the opcode semantics and control-flow rules are fully
proven, "decompile" here means structural disassembly plus an editable bytecode
workspace, not readable Lua source.
"""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import json
import math
import re
import shlex
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


TYPE_NAMES = {
    0: "nil",
    1: "boolean",
    3: "number",
    4: "string",
}

# HavokScript/Treyarch T6 opcode table. This table is cross-checked against
# JariKCoding/CoDLuaDecompiler's HavokDefaultHavokLuaOpCodeTable; the Xbox 360
# file wrapper differs, but instruction packing matches this T6 layout.
HKS_OPCODES = [
    "GETFIELD",
    "TEST",
    "CALL_I",
    "CALL_C",
    "EQ",
    "EQ_BK",
    "GETGLOBAL",
    "MOVE",
    "SELF",
    "RETURN",
    "GETTABLE_S",
    "GETTABLE_N",
    "GETTABLE",
    "LOADBOOL",
    "TFORLOOP",
    "SETFIELD",
    "SETTABLE_S",
    "SETTABLE_S_BK",
    "SETTABLE_N",
    "SETTABLE_N_BK",
    "SETTABLE",
    "SETTABLE_BK",
    "TAILCALL_I",
    "TAILCALL_C",
    "TAILCALL_M",
    "LOADK",
    "LOADNIL",
    "SETGLOBAL",
    "JMP",
    "CALL_M",
    "CALL",
    "INTRINSIC_INDEX",
    "INTRINSIC_NEWINDEX",
    "INTRINSIC_SELF",
    "INTRINSIC_INDEX_LITERAL",
    "INTRINSIC_NEWINDEX_LITERAL",
    "INTRINSIC_SELF_LITERAL",
    "TAILCALL",
    "GETUPVAL",
    "SETUPVAL",
    "ADD",
    "ADD_BK",
    "SUB",
    "SUB_BK",
    "MUL",
    "MUL_BK",
    "DIV",
    "DIV_BK",
    "MOD",
    "MOD_BK",
    "POW",
    "POW_BK",
    "NEWTABLE",
    "UNM",
    "NOT",
    "LEN",
    "LT",
    "LT_BK",
    "LE",
    "LE_BK",
    "CONCAT",
    "TESTSET",
    "FORPREP",
    "FORLOOP",
    "SETLIST",
    "CLOSE",
    "CLOSURE",
    "VARARG",
    "TAILCALL_I_R1",
    "CALL_I_R1",
    "SETUPVAL_R1",
    "TEST_R1",
    "NOT_R1",
    "GETFIELD_R1",
    "SETFIELD_R1",
    "NEWSTRUCT",
    "DATA",
    "SETSLOTN",
    "SETSLOTI",
    "SETSLOT",
    "SETSLOTS",
    "SETSLOTMT",
    "CHECKTYPE",
    "CHECKTYPES",
    "GETSLOT",
    "GETSLOTMT",
    "SELFSLOT",
    "SELFSLOTMT",
    "GETFIELD_MM",
    "CHECKTYPE_D",
    "GETSLOT_D",
    "GETGLOBAL_MEM",
    "MAX",
]
HKS_OPCODE_BY_NAME = {name: index for index, name in enumerate(HKS_OPCODES)}


class ParseError(ValueError):
    pass


@dataclass
class Constant:
    index: int
    type_tag: int
    type_name: str
    value: Any
    offset: int
    end_offset: int


@dataclass
class Instruction:
    index: int
    offset: int
    raw: bytes
    opcode: int
    opname: str
    a: int
    b: int
    c: int
    extra_c_bit: bool
    bx: int
    sbx: int


@dataclass
class Proto:
    index: int
    offset: int
    end_offset: int
    source: str | None
    line_defined: int
    last_line_defined: int
    upvalue_count: int
    param_count: int
    proto_flags: int
    instruction_count: int
    max_stack: int
    instructions: list[Instruction] = field(default_factory=list)
    constants: list[Constant] = field(default_factory=list)
    children: list["Proto"] = field(default_factory=list)
    debug: dict[str, Any] = field(default_factory=dict)


def align4(offset: int) -> int:
    return (offset + 3) & ~3


def u32(data: bytes, offset: int) -> int:
    if offset + 4 > len(data):
        raise ParseError(f"u32 at 0x{offset:X} extends past EOF")
    return int.from_bytes(data[offset : offset + 4], "big")


def u16(data: bytes, offset: int) -> int:
    if offset + 2 > len(data):
        raise ParseError(f"u16 at 0x{offset:X} extends past EOF")
    return int.from_bytes(data[offset : offset + 2], "big")


def u32le(data: bytes, offset: int) -> int:
    if offset + 4 > len(data):
        raise ParseError(f"u32le at 0x{offset:X} extends past EOF")
    return int.from_bytes(data[offset : offset + 4], "little")


def read_lua_string(data: bytes, offset: int) -> tuple[str | None, int]:
    length = u32(data, offset)
    offset += 4
    if length == 0:
        return None, offset
    if offset + length > len(data):
        raise ParseError(f"string length {length} at 0x{offset - 4:X} extends past EOF")
    raw = data[offset : offset + length]
    offset += length
    if raw.endswith(b"\x00"):
        raw = raw[:-1]
    return raw.decode("utf-8", "replace"), offset


def parse_instruction(raw: bytes, index: int, offset: int) -> Instruction:
    if len(raw) != 4:
        raise ParseError(f"instruction at 0x{offset:X} is not 4 bytes")

    # Havok/T6 instruction packing. Xbox 360 stores each 32-bit instruction
    # word big-endian; the known Havok/T6 decoder consumes the same word as
    # little-endian bytes. Reverse the four bytes for field extraction while
    # preserving raw file bytes for display and re-emission.
    packed = raw[::-1]
    # Field layout after byte-order normalization:
    #   A      = byte 0
    #   C      = byte 1 plus bit 0 of byte 2 as C's high bit
    #   B      = byte 2 >> 1 plus bit 0 of byte 3 as B's high bit
    #   opcode = byte 3 >> 1
    # Bx/SBx follow the same derived B/C fields used by CoDLuaDecompiler.
    a = packed[0]
    c = packed[1]
    b_value = packed[2]
    flags_b = packed[3]
    extra_c_bit = bool(b_value & 1)
    b = b_value >> 1
    if flags_b & 1:
        b += 128
    opcode = flags_b >> 1
    c_full = c + (256 if extra_c_bit else 0)
    bx = b * 512 + c_full
    sbx = bx - 65536 + 1
    opname = HKS_OPCODES[opcode] if opcode < len(HKS_OPCODES) else f"OP_{opcode:02d}"
    return Instruction(index, offset, raw, opcode, opname, a, b, c_full, extra_c_bit, bx, sbx)


def parse_int_field(value: Any, field: str, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ParseError(f"instruction field {field} must be an integer") from exc
    if parsed < minimum or parsed > maximum:
        raise ParseError(f"instruction field {field} out of range ({parsed}; expected {minimum}..{maximum})")
    return parsed


def opcode_from_edit(edited: dict[str, Any], original: Instruction) -> int:
    if "opcode" in edited:
        return parse_int_field(edited["opcode"], "opcode", 0, 127)
    opname = edited.get("opname", original.opname)
    if opname == original.opname:
        return original.opcode
    if isinstance(opname, str) and opname.startswith("OP_"):
        return parse_int_field(opname[3:], "opname", 0, 127)
    try:
        return HKS_OPCODE_BY_NAME[str(opname)]
    except KeyError as exc:
        raise ParseError(f"unknown Havok opcode name {opname!r}") from exc


def encode_instruction_fields(original: Instruction, edited: dict[str, Any]) -> bytes:
    """Encode one Havok/T6 instruction from editable JSON fields."""

    opcode = opcode_from_edit(edited, original)
    a = parse_int_field(edited.get("a", original.a), "a", 0, 255)

    edited_b = parse_int_field(edited["b"], "b", 0, 255) if "b" in edited else original.b
    edited_c = parse_int_field(edited["c"], "c", 0, 511) if "c" in edited else original.c
    edited_bx = parse_int_field(edited["bx"], "bx", 0, 131071) if "bx" in edited else original.bx
    edited_sbx = parse_int_field(edited["sbx"], "sbx", -65535, 65536) if "sbx" in edited else original.sbx
    b_changed = "b" in edited and edited_b != original.b
    c_changed = "c" in edited and edited_c != original.c
    bx_changed = "bx" in edited and edited_bx != original.bx
    sbx_changed = "sbx" in edited and edited_sbx != original.sbx

    if bx_changed or sbx_changed:
        if bx_changed and sbx_changed:
            bx_from_bx = edited_bx
            bx_from_sbx = edited_sbx + 65536 - 1
            if bx_from_bx != bx_from_sbx:
                raise ParseError("instruction bx and sbx edits disagree")
            bx = bx_from_bx
        elif bx_changed:
            bx = edited_bx
        else:
            bx = edited_sbx + 65536 - 1
        b = bx // 512
        c = bx % 512
        if b_changed and edited_b != b:
            raise ParseError("instruction b edit disagrees with bx/sbx")
        if c_changed and edited_c != c:
            raise ParseError("instruction c edit disagrees with bx/sbx")
    else:
        b = edited_b
        c = edited_c

    extra_c_bit = c >= 256
    c_low = c & 0xFF
    b_value = (b & 0x7F) << 1
    if extra_c_bit:
        b_value |= 1
    flags_b = opcode << 1
    if b >= 128:
        flags_b |= 1
    if flags_b > 0xFF:
        raise ParseError(f"instruction opcode {opcode} cannot fit in encoded flags byte")

    # parse_instruction reverses the file word before field extraction, so write
    # the normalized packed bytes in reverse to preserve Xbox big-endian words.
    packed = bytes([a, c_low, b_value, flags_b])
    return packed[::-1]


def encode_instruction_for_patch(original: Instruction, edited: dict[str, Any]) -> bytes:
    raw_hex = str(edited.get("raw_hex", original.raw.hex())).replace(" ", "")
    try:
        raw_from_hex = bytes.fromhex(raw_hex)
    except ValueError as exc:
        raise ParseError(f"instruction {original.index} raw_hex is invalid") from exc
    if len(raw_from_hex) != 4:
        raise ParseError(f"instruction {original.index} raw_hex must encode exactly 4 bytes")

    field_names = {"opcode", "opname", "a", "b", "c", "bx", "sbx"}
    field_edit_requested = any(
        name in edited and edited.get(name) != getattr(original, name, None) for name in field_names
    )
    raw_edit_requested = raw_from_hex != original.raw
    if raw_edit_requested and field_edit_requested:
        assembled = encode_instruction_fields(original, edited)
        if assembled != raw_from_hex:
            raise ParseError(
                f"instruction {original.index} has conflicting raw_hex and decoded field edits"
            )
        return raw_from_hex
    if raw_edit_requested:
        return raw_from_hex
    if field_edit_requested:
        return encode_instruction_fields(original, edited)
    return original.raw


def parse_constant(data: bytes, offset: int, index: int) -> tuple[Constant, int]:
    start = offset
    if offset >= len(data):
        raise ParseError("constant tag extends past EOF")
    tag = data[offset]
    offset += 1
    if tag == 0:
        value = None
    elif tag == 1:
        if offset >= len(data):
            raise ParseError("boolean constant extends past EOF")
        value = bool(data[offset])
        offset += 1
    elif tag == 3:
        if offset + 4 > len(data):
            raise ParseError("number constant extends past EOF")
        value = struct.unpack(">f", data[offset : offset + 4])[0]
        offset += 4
    elif tag == 4:
        value, offset = read_lua_string(data, offset)
        value = "" if value is None else value
    else:
        raise ParseError(f"unsupported constant tag {tag} at 0x{start:X}")
    return Constant(index, tag, TYPE_NAMES.get(tag, f"type_{tag}"), value, start, offset), offset


def encode_constant_for_patch(constant: Constant, edited: dict[str, Any]) -> bytes:
    """Encode a constant without changing its serialized size.

    This is the first safe recompilation step: users can edit values that fit in
    the existing slot, and the tool refuses anything that would shift later
    unknown Havok data.
    """

    type_name = edited.get("type", constant.type_name)
    if type_name != constant.type_name:
        raise ParseError(
            f"K[{constant.index}] type changes are not supported yet "
            f"({constant.type_name!r} -> {type_name!r})"
        )

    if constant.type_tag == 0:
        if edited.get("value") is not None:
            raise ParseError(f"K[{constant.index}] nil constant cannot hold a non-nil value")
        return b"\x00"

    if constant.type_tag == 1:
        value = edited.get("value")
        if not isinstance(value, bool):
            raise ParseError(f"K[{constant.index}] boolean value must be true or false")
        return b"\x01" + (b"\x01" if value else b"\x00")

    if constant.type_tag == 3:
        try:
            number = float(edited.get("value"))
        except (TypeError, ValueError) as exc:
            raise ParseError(f"K[{constant.index}] number value is invalid") from exc
        return b"\x03" + struct.pack(">f", number)

    if constant.type_tag == 4:
        original_size = constant.end_offset - constant.offset
        original_payload_len = original_size - 1 - 4
        value = str(edited.get("value", ""))
        raw = value.encode("utf-8")
        if len(raw) + 1 != original_payload_len:
            raise ParseError(
                f"K[{constant.index}] string edit changes serialized length "
                f"({len(raw) + 1} != {original_payload_len}); same-length edits only for now"
            )
        return b"\x04" + original_payload_len.to_bytes(4, "big") + raw + b"\x00"

    raise ParseError(f"K[{constant.index}] unsupported constant tag {constant.type_tag}")


def parse_type_table(data: bytes) -> tuple[dict[str, Any], int]:
    if data[:4] != b"\x1bLua":
        raise ParseError("not a Lua bytecode chunk")
    if len(data) < 0x12:
        raise ParseError("file too small for Treyarch Lua header")
    type_count = u16(data, 0x10)
    offset = 0x12
    types = []
    for _ in range(type_count):
        type_id = u32(data, offset)
        offset += 4
        name, offset = read_lua_string(data, offset)
        types.append({"id": type_id, "name": name})
    return {
        "signature": data[:4].hex(),
        "version": data[4],
        "format_or_flags": data[5:0x0E].hex(),
        "type_count": type_count,
        "types": types,
    }, offset


def parse_proto(data: bytes, offset: int, index: int = 0) -> tuple[Proto, int]:
    start = offset
    source, offset = read_lua_string(data, offset)
    line_defined = u32le(data, offset)
    last_line_defined = u32le(data, offset + 4)
    offset += 8
    if offset + 6 > len(data):
        raise ParseError("proto header extends past EOF")
    upvalue_count = data[offset]
    param_count = data[offset + 1]
    proto_flags = data[offset + 2]
    instruction_count = u16(data, offset + 3)
    max_stack = data[offset + 5]
    offset += 6

    instructions = []
    for i in range(instruction_count):
        inst_offset = offset
        if offset + 4 > len(data):
            raise ParseError(f"instruction {i} at 0x{offset:X} extends past EOF")
        raw = data[offset : offset + 4]
        offset += 4
        instructions.append(parse_instruction(raw, i, inst_offset))

    constant_count = u32(data, offset)
    offset += 4
    constants = []
    for i in range(constant_count):
        constant, offset = parse_constant(data, offset, i)
        constants.append(constant)

    footer_unknown = u32(data, offset)
    offset += 4

    closure_indexes = [
        inst.bx for inst in instructions if inst.opname == "CLOSURE" and inst.bx >= 0
    ]
    child_count = (max(closure_indexes) + 1) if closure_indexes else 0
    children = []
    child_parse_errors = []
    for i in range(child_count):
        child_offset = offset
        try:
            child, offset = parse_child_proto(data, offset, i)
            children.append(child)
        except ParseError as exc:
            child_parse_errors.append({"index": i, "offset": child_offset, "error": str(exc)})
            break

    debug: dict[str, Any] = {
        "footer_unknown_be32": footer_unknown,
        "child_count_inferred_from_closures": child_count,
    }
    # Lua 5.1 debug tables are often present even when source text is stripped:
    # lineinfo[count], locals[count], upvalue names[count]. Keep parsing
    # conservative; if a table is malformed we leave the remaining tail raw.
    try:
        lineinfo_count = u32(data, offset)
        offset += 4
        lineinfo = []
        if lineinfo_count <= 1_000_000 and offset + lineinfo_count * 4 <= len(data):
            for _ in range(lineinfo_count):
                lineinfo.append(u32(data, offset))
                offset += 4
        else:
            raise ParseError("lineinfo table is implausible")

        local_count = u32(data, offset)
        offset += 4
        locals_ = []
        if local_count > 100_000:
            raise ParseError("local table is implausible")
        for _ in range(local_count):
            name, offset = read_lua_string(data, offset)
            startpc = u32(data, offset)
            endpc = u32(data, offset + 4)
            offset += 8
            locals_.append({"name": name, "startpc": startpc, "endpc": endpc})

        upvalue_name_count = u32(data, offset)
        offset += 4
        upvalue_names = []
        if upvalue_name_count > 100_000:
            raise ParseError("upvalue name table is implausible")
        for _ in range(upvalue_name_count):
            name, offset = read_lua_string(data, offset)
            upvalue_names.append(name)

        debug = {
            "lineinfo_count": lineinfo_count,
            "lineinfo_sample": lineinfo[:100],
            "local_count": local_count,
            "locals": locals_,
            "upvalue_name_count": upvalue_name_count,
            "upvalue_names": upvalue_names,
        }
    except ParseError as exc:
        debug = {"status": "unparsed_or_custom", "error": str(exc), "tail_offset": offset}
    if child_parse_errors:
        debug["child_parse_errors"] = child_parse_errors
        debug["child_count_declared"] = child_count
        debug["children_parsed"] = len(children)

    return (
        Proto(
            index=index,
            offset=start,
            end_offset=offset,
            source=source,
            line_defined=line_defined,
            last_line_defined=last_line_defined,
            upvalue_count=upvalue_count,
            param_count=param_count,
            proto_flags=proto_flags,
            instruction_count=instruction_count,
            max_stack=max_stack,
            instructions=instructions,
            constants=constants,
            children=children,
            debug=debug,
        ),
        offset,
    )


def parse_child_proto(data: bytes, offset: int, index: int = 0) -> tuple[Proto, int]:
    """Parse an observed nested T6/Havok function body.

    Nested functions in the Xbox fastfiles do not start with the same stripped
    Lua source/line header used by the root function. The currently observed
    form is:

      u32  function id/hash (unknown algorithm)
      0x10 bytes of descriptor data (unknown fields; preserved in JSON)
      u8   register/max-stack count at descriptor + 0x14
      3    unknown bytes
      u8   instruction count at descriptor + 0x18
      pad  to 4-byte boundary
      code instructions
      constants
      u32  footer/unknown
      child functions inferred from nested CLOSURE operands

    The descriptor field names are intentionally cautious until we compare more
    files or identify the exact HavokScript serializer.
    """

    start = offset
    if offset + 0x19 > len(data):
        raise ParseError(f"child function descriptor at 0x{offset:X} extends past EOF")

    function_id = data[offset : offset + 4]
    descriptor = data[offset : offset + 0x19]
    # Observed nested descriptor fields (big-endian u32):
    #   +0x08 = upvalue count, +0x0C = parameter count.
    # Verified against every child in textfieldbutton.lua (self/text=2,
    # ConvertToStar=1, event handlers=2, new=3 params / 2 upvalues). Values
    # outside a sane range fall back to 0 so unknown descriptor variants stay
    # lossless rather than emitting bogus signatures.
    upvalue_count = u32(data, offset + 0x08)
    param_count = u32(data, offset + 0x0C)
    if upvalue_count > 250:
        upvalue_count = 0
    if param_count > 250:
        param_count = 0
    max_stack = data[offset + 0x14]
    # Instruction count is a big-endian uint16 at descriptor +0x17. Earlier code
    # read only the low byte at +0x18, which truncated any function with >=256
    # instructions (e.g. cacclassloadout.new has 342) and then misparsed the
    # remaining code as constants ("unsupported constant tag ..."). Verified
    # against textfieldbutton (7/27/231, high byte 0) and cacclassloadout (342).
    instruction_count = u16(data, offset + 0x17)
    code_offset = align4(offset + 0x19)
    if code_offset + instruction_count * 4 > len(data):
        raise ParseError(
            f"child function {index} at 0x{start:X} declares {instruction_count} instructions past EOF"
        )

    offset = code_offset
    instructions = []
    for i in range(instruction_count):
        inst_offset = offset
        raw = data[offset : offset + 4]
        offset += 4
        instructions.append(parse_instruction(raw, i, inst_offset))

    constant_count = u32(data, offset)
    offset += 4
    constants = []
    for i in range(constant_count):
        constant, offset = parse_constant(data, offset, i)
        constants.append(constant)

    footer_unknown = u32(data, offset) if offset + 4 <= len(data) else None
    if footer_unknown is not None:
        offset += 4

    closure_indexes = [
        inst.bx for inst in instructions if inst.opname == "CLOSURE" and inst.bx >= 0
    ]
    child_count = (max(closure_indexes) + 1) if closure_indexes else 0
    children = []
    child_parse_errors = []
    for i in range(child_count):
        child_offset = offset
        try:
            child, offset = parse_child_proto(data, offset, i)
            children.append(child)
        except ParseError as exc:
            child_parse_errors.append({"index": i, "offset": child_offset, "error": str(exc)})
            break

    debug: dict[str, Any] = {
        "layout": "nested_havok_t6_observed",
        "function_id_hex": function_id.hex(),
        "descriptor_hex": descriptor.hex(),
        "code_offset": code_offset,
        "footer_unknown_be32": footer_unknown,
        "child_count_inferred_from_closures": child_count,
    }
    if child_parse_errors:
        debug["child_parse_errors"] = child_parse_errors
        debug["children_parsed"] = len(children)

    return (
        Proto(
            index=index,
            offset=start,
            end_offset=offset,
            source=None,
            line_defined=0,
            last_line_defined=0,
            upvalue_count=upvalue_count,
            param_count=param_count,
            proto_flags=0,
            instruction_count=instruction_count,
            max_stack=max_stack,
            instructions=instructions,
            constants=constants,
            children=children,
            debug=debug,
        ),
        offset,
    )


def proto_to_dict(proto: Proto) -> dict[str, Any]:
    return {
        "index": proto.index,
        "offset": proto.offset,
        "end_offset": proto.end_offset,
        "source": proto.source,
        "line_defined": proto.line_defined,
        "last_line_defined": proto.last_line_defined,
        "upvalue_count": proto.upvalue_count,
        "param_count": proto.param_count,
        "proto_flags": proto.proto_flags,
        "instruction_count": proto.instruction_count,
        "max_stack": proto.max_stack,
        "constants": [
            {
                "index": c.index,
                "type": c.type_name,
                "value": c.value,
                "offset": c.offset,
            }
            for c in proto.constants
        ],
        "instructions": [
            {
                "index": inst.index,
                "offset": inst.offset,
                "raw_hex": inst.raw.hex(),
                "opcode": inst.opcode,
                "opname": inst.opname,
                "a": inst.a,
                "b": inst.b,
                "c": inst.c,
                "extra_c_bit": inst.extra_c_bit,
                "bx": inst.bx,
                "sbx": inst.sbx,
            }
            for inst in proto.instructions
        ],
        "children": [proto_to_dict(child) for child in proto.children],
        "debug": proto.debug,
    }


def proto_to_editable(proto: Proto) -> dict[str, Any]:
    return {
        "index": proto.index,
        "offset": proto.offset,
        "end_offset": proto.end_offset,
        "header": {
            "source": proto.source,
            "line_defined": proto.line_defined,
            "last_line_defined": proto.last_line_defined,
            "upvalue_count": proto.upvalue_count,
            "param_count": proto.param_count,
            "proto_flags": proto.proto_flags,
            "instruction_count": proto.instruction_count,
            "max_stack": proto.max_stack,
        },
        "constants": [
            {
                "index": c.index,
                "offset": c.offset,
                "end_offset": c.end_offset,
                "type": c.type_name,
                "value": c.value,
                "note": "same serialized length required for string edits",
            }
            for c in proto.constants
        ],
        "instructions": [
            {
                "index": inst.index,
                "offset": inst.offset,
                "raw_hex": inst.raw.hex(),
                "opname": inst.opname,
                "a": inst.a,
                "b": inst.b,
                "c": inst.c,
                "bx": inst.bx,
                "sbx": inst.sbx,
                "note": "edit opcode/opname and a/b/c or bx/sbx; raw_hex is also accepted",
            }
            for inst in proto.instructions
        ],
        "children": [proto_to_editable(child) for child in proto.children],
        "debug": proto.debug,
    }


def parse_chunk(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    header, offset = parse_type_table(data)
    proto, end = parse_proto(data, offset)
    return {
        "path": str(path),
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "header": header,
        "proto_start": offset,
        "proto": proto,
        "end_offset": end,
        "trailing_bytes": len(data) - end,
    }


def make_editable_workspace(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    parsed = parse_chunk(path)
    return {
        "format": "bo2-xbox-lua-edit-v1",
        "source_path": str(path),
        "original_sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "mode": (
            "editable bytecode workspace; supports same-length constant edits and raw "
            "instruction-byte edits while preserving all unknown bytes"
        ),
        "original_bytes_b64": base64.b64encode(data).decode("ascii"),
        "header": parsed["header"],
        "proto_start": parsed["proto_start"],
        "proto": proto_to_editable(parsed["proto"]),
    }


def apply_editable_proto(data: bytearray, current: Proto, edited: dict[str, Any]) -> None:
    if int(edited.get("offset", -1)) != current.offset:
        raise ParseError(
            f"proto offset mismatch: parsed 0x{current.offset:X}, JSON has 0x{int(edited.get('offset', -1)):X}"
        )

    edited_instructions = edited.get("instructions", [])
    if len(edited_instructions) != len(current.instructions):
        raise ParseError(
            f"proto 0x{current.offset:X} instruction count changed "
            f"({len(edited_instructions)} != {len(current.instructions)})"
        )
    for inst, edited_inst in zip(current.instructions, edited_instructions):
        if int(edited_inst.get("offset", -1)) != inst.offset:
            raise ParseError(f"instruction offset mismatch at proto 0x{current.offset:X}, index {inst.index}")
        raw = encode_instruction_for_patch(inst, edited_inst)
        data[inst.offset : inst.offset + 4] = raw

    edited_constants = edited.get("constants", [])
    if len(edited_constants) != len(current.constants):
        raise ParseError(
            f"proto 0x{current.offset:X} constant count changed "
            f"({len(edited_constants)} != {len(current.constants)})"
        )
    for constant, edited_constant in zip(current.constants, edited_constants):
        if int(edited_constant.get("offset", -1)) != constant.offset:
            raise ParseError(f"constant offset mismatch at proto 0x{current.offset:X}, index {constant.index}")
        encoded = encode_constant_for_patch(constant, edited_constant)
        expected_len = constant.end_offset - constant.offset
        if len(encoded) != expected_len:
            raise ParseError(
                f"K[{constant.index}] encoded length mismatch ({len(encoded)} != {expected_len})"
            )
        data[constant.offset : constant.end_offset] = encoded

    edited_children = edited.get("children", [])
    if len(edited_children) != len(current.children):
        raise ParseError(
            f"proto 0x{current.offset:X} child count changed "
            f"({len(edited_children)} != {len(current.children)})"
        )
    for child, edited_child in zip(current.children, edited_children):
        apply_editable_proto(data, child, edited_child)


def rebuild_from_workspace(workspace_path: Path) -> bytes:
    workspace = json.loads(workspace_path.read_text(encoding="utf-8"))
    if workspace.get("format") != "bo2-xbox-lua-edit-v1":
        raise ParseError("unsupported workspace format; expected bo2-xbox-lua-edit-v1")
    try:
        data = bytearray(base64.b64decode(workspace["original_bytes_b64"], validate=True))
    except Exception as exc:
        raise ParseError("workspace original_bytes_b64 is invalid") from exc

    expected_size = int(workspace.get("size", -1))
    if len(data) != expected_size:
        raise ParseError(f"workspace byte size mismatch ({len(data)} != {expected_size})")

    expected_hash = str(workspace.get("original_sha256", "")).lower()
    actual_hash = hashlib.sha256(data).hexdigest()
    if expected_hash and expected_hash != actual_hash:
        raise ParseError(f"workspace original byte hash mismatch ({actual_hash} != {expected_hash})")

    # Parse the embedded original bytes, not a sidecar file path, so the JSON is
    # self-contained and safe to share.
    header, offset = parse_type_table(bytes(data))
    current_proto, _end = parse_proto(bytes(data), offset)
    apply_editable_proto(data, current_proto, workspace["proto"])

    # Reparse after patching to make sure edits did not create malformed bytecode.
    header2, offset2 = parse_type_table(bytes(data))
    reparsed_proto, _end2 = parse_proto(bytes(data), offset2)
    if header2.get("type_count") != header.get("type_count") or reparsed_proto.offset != current_proto.offset:
        raise ParseError("rebuilt bytecode failed structural validation")
    return bytes(data)


def editable_json_rel_to_lua(rel: Path) -> Path:
    text = rel.as_posix()
    if text.endswith(".edit.json"):
        return Path(text[: -len(".edit.json")] + ".lua")
    return rel.with_suffix(".lua")


def iter_workspace_protos(proto: dict[str, Any], path: str = "0"):
    yield path, proto
    for child_index, child in enumerate(proto.get("children", [])):
        yield from iter_workspace_protos(child, f"{path}.{child_index}")


def workspace_proto_by_path(workspace: dict[str, Any], path: str) -> dict[str, Any]:
    proto = workspace["proto"]
    if path == "0":
        return proto
    parts = path.split(".")
    if not parts or parts[0] != "0":
        raise ParseError(f"invalid proto path {path!r}")
    for part in parts[1:]:
        try:
            index = int(part)
            proto = proto["children"][index]
        except (ValueError, IndexError, KeyError) as exc:
            raise ParseError(f"invalid proto path {path!r}") from exc
    return proto


def asm_quote(value: Any) -> str:
    return shlex.quote(str(value))


def hksasm_from_workspace(workspace: dict[str, Any]) -> str:
    packed_workspace = base64.b64encode(
        gzip.compress(json.dumps(workspace, separators=(",", ":")).encode("utf-8"))
    ).decode("ascii")
    lines = [
        "; BO2HKSASM v1",
        "; Human-editable Havok/T6 bytecode assembly.",
        "; Edit .const value_json/type or .inst opcode/operands/raw fields, then run recompile-asm.",
        "; A compressed workspace blob at EOF preserves unknown bytes and original payload layout.",
        "",
    ]
    for proto_path, proto in iter_workspace_protos(workspace["proto"]):
        header = proto.get("header", {})
        lines.append(
            f".func path={proto_path} offset=0x{int(proto['offset']):X} "
            f"maxstack={header.get('max_stack', 0)} instructions={len(proto.get('instructions', []))} "
            f"constants={len(proto.get('constants', []))}"
        )
        for constant in proto.get("constants", []):
            lines.append(
                f".const path={proto_path} index={int(constant['index'])} "
                f"type={constant['type']} value_json={asm_quote(json.dumps(constant.get('value')))}"
            )
        for inst in proto.get("instructions", []):
            lines.append(
                f".inst path={proto_path} index={int(inst['index'])} op={inst['opname']} "
                f"a={int(inst['a'])} b={int(inst['b'])} c={int(inst['c'])} "
                f"bx={int(inst['bx'])} sbx={int(inst['sbx'])} raw={inst['raw_hex']}"
            )
        lines.append(".endfunc")
        lines.append("")
    lines.extend(
        [
            "; Embedded workspace metadata. Keep this line intact for recompilation.",
            f"; workspace_gzip_b64={packed_workspace}",
            "",
        ]
    )
    return "\n".join(lines)


def parse_key_values(parts: list[str], line_no: int) -> dict[str, str]:
    values: dict[str, str] = {}
    for part in parts:
        if "=" not in part:
            raise ParseError(f"line {line_no}: expected key=value token, got {part!r}")
        key, value = part.split("=", 1)
        values[key] = value
    return values


def workspace_from_hksasm(path: Path) -> dict[str, Any]:
    workspace: dict[str, Any] | None = None
    lines = path.read_text(encoding="utf-8").splitlines()
    marker = "; workspace_gzip_b64="
    for line_no, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if line.startswith(marker):
            payload = line[len(marker) :].strip()
            try:
                workspace = json.loads(gzip.decompress(base64.b64decode(payload)).decode("utf-8"))
            except Exception as exc:
                raise ParseError(f"line {line_no}: embedded workspace is invalid") from exc
            break
    if workspace is None:
        raise ParseError("assembly file is missing ; workspace_gzip_b64 metadata")

    for line_no, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith(";"):
            continue

        parts = shlex.split(line)
        if not parts:
            continue
        directive = parts[0]
        fields = parse_key_values(parts[1:], line_no)
        if directive == ".const":
            proto = workspace_proto_by_path(workspace, fields.get("path", ""))
            try:
                index = int(fields["index"])
                constant = proto["constants"][index]
            except (KeyError, ValueError, IndexError) as exc:
                raise ParseError(f"line {line_no}: invalid constant index") from exc
            if "type" in fields:
                constant["type"] = fields["type"]
            if "value_json" in fields:
                try:
                    constant["value"] = json.loads(fields["value_json"])
                except json.JSONDecodeError as exc:
                    raise ParseError(f"line {line_no}: invalid value_json") from exc
        elif directive == ".inst":
            proto = workspace_proto_by_path(workspace, fields.get("path", ""))
            try:
                index = int(fields["index"])
                inst = proto["instructions"][index]
            except (KeyError, ValueError, IndexError) as exc:
                raise ParseError(f"line {line_no}: invalid instruction index") from exc
            if "op" in fields:
                inst["opname"] = fields["op"]
            for src, dst in (("opcode", "opcode"), ("a", "a"), ("b", "b"), ("c", "c"), ("bx", "bx"), ("sbx", "sbx")):
                if src in fields:
                    inst[dst] = int(fields[src], 0)
            if "raw" in fields:
                inst["raw_hex"] = fields["raw"]
        elif directive in {".func", ".endfunc"}:
            continue
        else:
            raise ParseError(f"line {line_no}: unknown directive {directive!r}")
    return workspace


def rebuild_from_hksasm(path: Path) -> bytes:
    workspace = workspace_from_hksasm(path)
    temp_path = path.with_suffix(path.suffix + ".workspace.tmp.json")
    try:
        temp_path.write_text(json.dumps(workspace, indent=2) + "\n", encoding="utf-8")
        return rebuild_from_workspace(temp_path)
    finally:
        temp_path.unlink(missing_ok=True)


def format_constant(value: Any) -> str:
    if value is None:
        return "nil"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return repr(value)
    if isinstance(value, float):
        if math.isfinite(value):
            return f"{value:.9g}"
        return repr(value)
    return repr(value)


def lua_literal(value: Any) -> str:
    if value is None:
        return "nil"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return format_constant(value)
    return json.dumps(str(value))


def constant_value(proto: Proto, index: int) -> Any:
    if 0 <= index < len(proto.constants):
        return proto.constants[index].value
    return f"K_{index}"


def constant_name(proto: Proto, index: int) -> str:
    value = constant_value(proto, index)
    if isinstance(value, str) and value:
        if all(is_lua_identifier(part) for part in value.split(".")):
            return value
    return f"K_{index}"


def is_lua_identifier(value: str) -> bool:
    return value.isidentifier() and value not in {
        "and",
        "break",
        "do",
        "else",
        "elseif",
        "end",
        "false",
        "for",
        "function",
        "if",
        "in",
        "local",
        "nil",
        "not",
        "or",
        "repeat",
        "return",
        "then",
        "true",
        "until",
        "while",
    }


def field_expr(base: str, field: Any) -> str:
    if isinstance(field, str) and is_lua_identifier(field):
        return f"{base}.{field}"
    return f"{base}[{lua_literal(field)}]"


def self_field_value(proto: Proto, index: int) -> Any:
    if index >= 256:
        index -= 256
    return constant_value(proto, index)


def rk_constant_index(index: int) -> int | None:
    return index - 256 if index >= 256 else None


def call_args(inst: Instruction, start_register: int | None = None) -> str:
    if start_register is None:
        start_register = inst.a + 1
    if inst.b <= 1:
        return "..."
    return ", ".join(f"R[{reg}]" for reg in range(start_register, start_register + inst.b - 1))


def approx_statement(proto: Proto, inst: Instruction, path: tuple[int, ...] = ()) -> str:
    """Return a valid Lua-ish statement for common HKS instructions.

    This is deliberately conservative: it improves readability for menu script
    triage without claiming source equivalence. Anything with uncertain operand
    semantics falls back to a comment with decoded fields.
    """

    op = inst.opname
    if op == "GETGLOBAL":
        return f"R[{inst.a}] = {constant_name(proto, inst.bx)}"
    if op == "SETGLOBAL":
        return f"{constant_name(proto, inst.bx)} = R[{inst.a}]"
    if op == "MOVE":
        return f"R[{inst.a}] = R[{inst.b}]"
    if op == "LOADK":
        return f"R[{inst.a}] = {lua_literal(constant_value(proto, inst.bx))}"
    if op == "LOADBOOL":
        return f"R[{inst.a}] = {'true' if inst.b else 'false'}"
    if op == "LOADNIL":
        return f"R[{inst.a}] = nil"
    if op in {"GETFIELD", "GETFIELD_R1", "GETFIELD_MM"}:
        return f"R[{inst.a}] = {field_expr(f'R[{inst.b}]', constant_value(proto, inst.c))}"
    if op in {"SETFIELD", "SETFIELD_R1"}:
        return f"{field_expr(f'R[{inst.a}]', constant_value(proto, inst.b))} = R[{inst.c}]"
    if op == "GETTABLE":
        return f"R[{inst.a}] = R[{inst.b}][R[{inst.c}]]"
    if op == "GETTABLE_S":
        return f"R[{inst.a}] = R[{inst.b}][{lua_literal(constant_value(proto, inst.c))}]"
    if op == "GETTABLE_N":
        return f"R[{inst.a}] = R[{inst.b}][{inst.c}]"
    if op.startswith("SETTABLE"):
        return f"-- approx: table write {op} A={inst.a} B={inst.b} C={inst.c}"
    if op == "NEWTABLE":
        return f"R[{inst.a}] = {{}}"
    if op == "CLOSURE":
        return f"R[{inst.a}] = {proto_path_name((*path, inst.bx))}"
    if op in {"CALL", "CALL_I", "CALL_C", "CALL_M", "CALL_I_R1"}:
        return f"R[{inst.a}] = R[{inst.a}]({call_args(inst)})"
    if op == "SELF":
        return f"R[{inst.a}] = R[{inst.b}]; R[{inst.a + 1}] = R[{inst.b}][R[{inst.c}]]"
    if op in {"TAILCALL", "TAILCALL_I", "TAILCALL_C", "TAILCALL_M", "TAILCALL_I_R1"}:
        return f"-- return R[{inst.a}]({call_args(inst)})"
    if op == "RETURN":
        if inst.b <= 1:
            return "-- return"
        return "-- return " + ", ".join(f"R[{reg}]" for reg in range(inst.a, inst.a + inst.b - 1))
    if op in {"ADD", "SUB", "MUL", "DIV", "MOD", "POW"}:
        symbol = {"ADD": "+", "SUB": "-", "MUL": "*", "DIV": "/", "MOD": "%", "POW": "^"}[op]
        return f"R[{inst.a}] = R[{inst.b}] {symbol} R[{inst.c}]"
    if op in {"UNM", "NOT", "NOT_R1", "LEN"}:
        prefix = {"UNM": "-", "NOT": "not ", "NOT_R1": "not ", "LEN": "#"}[op]
        return f"R[{inst.a}] = {prefix}R[{inst.b}]"
    if op == "CONCAT":
        return f"-- approx: R[{inst.a}] = concat R[{inst.b}]..R[{inst.c}]"
    if op in {"JMP", "FORPREP", "FORLOOP", "TFORLOOP", "TEST", "TEST_R1", "TESTSET", "EQ", "LT", "LE"}:
        return f"-- control flow: {op} A={inst.a} B={inst.b} C={inst.c} sBx={inst.sbx}"
    return f"-- unresolved: {op} A={inst.a} B={inst.b} C={inst.c} Bx={inst.bx} sBx={inst.sbx}"


def register_name(index: int) -> str:
    return f"local_{index}"


def fallback_local_name(index: int) -> str:
    return "value"


def read_registers(inst: Instruction) -> list[int]:
    op = inst.opname
    if op in {"MOVE", "UNM", "NOT", "NOT_R1", "LEN"}:
        return [inst.b]
    if op in {"GETFIELD", "GETFIELD_R1", "GETFIELD_MM", "GETTABLE", "GETTABLE_S", "GETTABLE_N", "SELF"}:
        return [inst.b]
    if op in {"SETFIELD", "SETFIELD_R1"}:
        return [inst.a, inst.c]
    if op in {"SETTABLE", "SETTABLE_S", "SETTABLE_S_BK", "SETTABLE_N"}:
        return [inst.a, inst.c]
    if op == "SETLIST":
        return [inst.a, *range(inst.a + 1, inst.a + inst.b + 1)]
    if op in {"CALL", "CALL_I", "CALL_C", "CALL_M", "CALL_I_R1", "TAILCALL", "TAILCALL_I", "TAILCALL_C", "TAILCALL_M", "TAILCALL_I_R1"}:
        return list(range(inst.a, inst.a + max(inst.b, 1)))
    if op == "TFORLOOP":
        return [inst.a, inst.a + 1, inst.a + 2]
    if op == "RETURN":
        return list(range(inst.a, inst.a + max(inst.b - 1, 0)))
    if op in {"ADD", "SUB", "MUL", "DIV", "MOD", "POW", "EQ", "LT", "LE", "EQ_BK", "LT_BK", "LE_BK"}:
        return [inst.b, inst.c]
    if op in {"ADD_BK", "SUB_BK", "MUL_BK", "DIV_BK", "MOD_BK", "POW_BK"}:
        return [inst.c]
    return []


def written_register(inst: Instruction) -> int | None:
    if inst.opname in {
        "GETGLOBAL",
        "MOVE",
        "LOADK",
        "LOADBOOL",
        "LOADNIL",
        "GETFIELD",
        "GETFIELD_R1",
        "GETFIELD_MM",
        "GETTABLE",
        "GETTABLE_S",
        "GETTABLE_N",
        "NEWTABLE",
        "CLOSURE",
        "SELF",
        "CALL",
        "CALL_I",
        "CALL_C",
        "CALL_M",
        "CALL_I_R1",
        "ADD",
        "ADD_BK",
        "SUB",
        "SUB_BK",
        "MUL",
        "MUL_BK",
        "DIV",
        "DIV_BK",
        "MOD",
        "MOD_BK",
        "POW",
        "POW_BK",
        "UNM",
        "NOT",
        "NOT_R1",
        "LEN",
        "CONCAT",
    }:
        return inst.a
    if inst.opname == "TFORLOOP":
        return inst.a + 3
    return None


def infer_input_registers(proto: Proto) -> list[int]:
    written: set[int] = set()
    inputs: set[int] = set()
    instructions = [inst for inst in proto.instructions if inst.opname != "DATA"]
    by_index = {inst.index: inst for inst in instructions}
    generic_loop_vars_by_jump: dict[int, list[int]] = {}
    for pos, inst in enumerate(instructions):
        if inst.opname == "JMP" and inst.sbx > 0:
            target = by_index.get(inst.index + inst.sbx + 1)
            following = instructions[pos + 1] if pos + 1 < len(instructions) else None
            if target and target.opname == "TFORLOOP":
                generic_loop_vars_by_jump[inst.index] = list(range(target.a + 3, target.a + 3 + max(target.c, 1)))
    for inst in instructions:
        if inst.index in generic_loop_vars_by_jump:
            written.update(generic_loop_vars_by_jump[inst.index])
        for reg in read_registers(inst):
            if reg < 64 and reg not in written:
                inputs.add(reg)
        target = written_register(inst)
        if target is not None:
            written.add(target)
            if inst.opname == "SELF":
                written.add(target + 1)
            if inst.opname in {"CALL", "CALL_I", "CALL_C", "CALL_M", "CALL_I_R1"} and inst.c > 1:
                written.update(range(inst.a, inst.a + inst.c - 1))
    if not inputs:
        return []
    highest = max(inputs)
    return list(range(highest + 1))


def _lower_first(value: str) -> str:
    return value[:1].lower() + value[1:] if value else value


def _setter_param_name(method: str, arg_pos: int) -> str | None:
    """Infer a parameter name from a `setX(param)` style method call."""
    overrides = {
        "setActionEventName": ["eventName"],
        "setText": ["text"],
        "setTitle": ["title"],
        "setSubtitle": ["text"],
        "setModel": ["model"],
        "setShader": ["shaderName"],
        "setImage": ["image"],
        "setIcon": ["icon"],
        "setState": ["state"],
        "setActionEvent": ["eventName"],
        "addElement": ["element"],
        "registerEventHandler": ["eventName", "callback"],
    }
    if method in overrides and arg_pos < len(overrides[method]):
        return overrides[method][arg_pos]
    if arg_pos == 0 and method.startswith("set") and len(method) > 3:
        candidate = _lower_first(method[3:])
        return candidate if is_lua_identifier(candidate) else None
    return None


def infer_param_names(
    proto: Proto,
    func_name: str | None = None,
    is_local: bool = False,
) -> list[str] | None:
    """Recover meaningful parameter names from bytecode usage.

    No debug symbol table survives in these payloads, so names are inferred
    from how each parameter register is consumed:
      * a member function whose first register is used as a table receiver
        gets `self`; a receiver in a local/handler function gets `element`;
      * the second parameter of a two-arg receiver function is the `event`
        table (BO2 LUI event-handler convention);
      * a register passed to `obj:setX(param)` is named after the setter;
      * a register stored into a table field is named after that field.
    Anything still unresolved falls back to a descriptive `value` name so no
    generic `arg0`/`var0` placeholders ever reach the output.
    """
    count = proto.param_count
    if count <= 0:
        return None

    insts = [inst for inst in proto.instructions if inst.opname != "DATA"]

    def is_receiver(reg: int) -> bool:
        for inst in insts:
            if (
                inst.opname
                in {
                    "SELF",
                    "GETFIELD",
                    "GETFIELD_R1",
                    "GETFIELD_MM",
                    "GETTABLE",
                    "GETTABLE_S",
                    "GETTABLE_N",
                }
                and inst.b == reg
            ):
                return True
            if (
                inst.opname
                in {"SETFIELD", "SETFIELD_R1", "SETTABLE", "SETTABLE_S", "SETTABLE_S_BK", "SETTABLE_N"}
                and inst.a == reg
            ):
                return True
        return False

    names: list[str | None] = [None] * count

    dotted_member = bool(func_name and "." in func_name and ":" not in func_name)
    if is_receiver(0):
        names[0] = "self" if (dotted_member and not is_local) else "element"
        if count == 2 and names[0] == "element":
            names[1] = "event"

    # Setter-argument names: track the method selected by the most recent SELF
    # into a register, then read it off the following CALL. Parameters are often
    # MOVEd into a scratch register before the call, so follow those copies.
    self_method: dict[int, str | None] = {}
    alias: dict[int, int] = {}
    for inst in insts:
        if inst.opname == "MOVE" and inst.b < count:
            alias[inst.a] = inst.b
        elif inst.opname == "SELF":
            const_index = rk_constant_index(inst.c)
            method = constant_value(proto, const_index) if const_index is not None else None
            self_method[inst.a] = method if isinstance(method, str) else None
        elif inst.opname in {"CALL", "CALL_I", "CALL_C", "CALL_M", "CALL_I_R1"}:
            method = self_method.get(inst.a)
            if method:
                for arg_pos, reg in enumerate(range(inst.a + 2, inst.a + max(inst.b, 1))):
                    param = reg if reg < count else alias.get(reg)
                    if param is not None and param < count and names[param] is None:
                        candidate = _setter_param_name(method, arg_pos)
                        if candidate:
                            names[param] = candidate
            self_method.pop(inst.a, None)
        else:
            target = written_register(inst)
            if target is not None:
                self_method.pop(target, None)
                alias.pop(target, None)

    # Plain-call argument names: resolve the callee of `f(...)` style calls
    # (GETGLOBAL/GETFIELD chains) and name well-known arguments.
    reg_expr: dict[int, str] = {}
    alias2: dict[int, int] = {}
    for inst in insts:
        if inst.opname == "GETGLOBAL":
            reg_expr[inst.a] = constant_name(proto, inst.bx)
        elif inst.opname in {"GETFIELD", "GETFIELD_R1", "GETFIELD_MM"}:
            base = reg_expr.get(inst.b)
            field = constant_value(proto, inst.c)
            reg_expr[inst.a] = f"{base}.{field}" if base and isinstance(field, str) else ""
        elif inst.opname == "MOVE" and inst.b < count:
            alias2[inst.a] = inst.b
        elif inst.opname in {"CALL", "CALL_I", "CALL_C", "CALL_M", "CALL_I_R1"}:
            callee = reg_expr.get(inst.a) or ""
            last = callee.rsplit(".", 1)[-1] if callee else ""
            for arg_pos, reg in enumerate(range(inst.a + 1, inst.a + max(inst.b, 1))):
                param = reg if reg < count else alias2.get(reg)
                if param is None or param >= count or names[param] is not None:
                    continue
                if last in {"len", "Localize", "ToUpper", "lower", "upper"} and arg_pos == 0:
                    names[param] = "text"
                elif last.endswith("SetText") and arg_pos == 1:
                    names[param] = "text"
            reg_expr.pop(inst.a, None)
        else:
            target = written_register(inst)
            if target is not None:
                reg_expr.pop(target, None)
                alias2.pop(target, None)

    # Table-field names: a parameter stored as `t.field = param`.
    for inst in insts:
        if inst.opname in {"SETFIELD", "SETFIELD_R1"} and inst.c < count and names[inst.c] is None:
            field = constant_value(proto, inst.b)
            if isinstance(field, str) and is_lua_identifier(field):
                names[inst.c] = _lower_first(field)

    used: set[str] = set()
    result: list[str] = []
    for index, name in enumerate(names):
        base = name or "value"
        candidate = base
        suffix = 2
        while candidate in used:
            candidate = f"{base}{suffix}"
            suffix += 1
        used.add(candidate)
        result.append(candidate)
    return result


def source_params(
    proto: Proto,
    infer: bool = False,
    func_name: str | None = None,
    is_local: bool = False,
) -> list[str]:
    def append_unique(names: list[str], base: str) -> None:
        candidate = base
        suffix = 2
        used = set(names)
        while candidate in used:
            candidate = f"{base}{suffix}"
            suffix += 1
        names.append(candidate)

    inferred = infer_param_names(proto, func_name=func_name, is_local=is_local)
    if inferred is not None and len(inferred) >= proto.param_count > 0:
        # Extend with inferred extra input registers if the caller wants them.
        if infer:
            extra = len(infer_input_registers(proto)) - len(inferred)
            for _offset in range(max(extra, 0)):
                append_unique(inferred, f"value{len(inferred)}")
        return inferred
    count = proto.param_count
    if infer:
        count = max(count, len(infer_input_registers(proto)))
    if count <= 0:
        return ["..."]
    # Last-resort naming still avoids raw arg/var placeholders.
    return [("self" if index == 0 else f"value{index}") for index in range(count)]


def strip_trailing_control_comments(lines: list[str]) -> list[str]:
    while lines and lines[-1].strip() in {"-- return", "return"}:
        lines.pop()
    return lines


def strip_empty_else_blocks(lines: list[str]) -> list[str]:
    """Remove decompiler-only empty else clauses.

    This only drops `else` when the next emitted source line at the same
    indentation is another `else` or `end`, meaning no statement would be lost.
    """
    changed = True
    result = list(lines)
    while changed:
        changed = False
        filtered: list[str] = []
        for index, line in enumerate(result):
            if line.strip() != "else":
                filtered.append(line)
                continue
            indent_len = len(line) - len(line.lstrip(" "))
            next_line = None
            for candidate in result[index + 1:]:
                if candidate.strip():
                    next_line = candidate
                    break
            if next_line is not None:
                next_indent = len(next_line) - len(next_line.lstrip(" "))
                if next_indent == indent_len and next_line.strip() in {"else", "end"}:
                    changed = True
                    continue
            filtered.append(line)
        result = filtered
    return result


def strip_redundant_branch_comments(lines: list[str]) -> list[str]:
    """Drop jump comments when the emitted `else` already represents the jump."""
    filtered: list[str] = []
    for index, line in enumerate(lines):
        if "-- control flow:" not in line:
            filtered.append(line)
            continue
        indent_len = len(line) - len(line.lstrip(" "))
        next_line = None
        for candidate in lines[index + 1:]:
            if candidate.strip():
                next_line = candidate
                break
        if next_line is not None:
            next_indent = len(next_line) - len(next_line.lstrip(" "))
            if next_indent < indent_len and next_line.strip() == "else":
                continue
            if next_indent < indent_len and next_line.strip() == "end" and "sBx=-" not in line:
                continue
        filtered.append(line)
    return filtered


def sanitize_local_name(value: str, fallback: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in value)
    if cleaned and cleaned[0].isdigit():
        cleaned = "_" + cleaned
    return cleaned if is_lua_identifier(cleaned) else fallback


def camel_from_parts(parts: list[str], fallback: str) -> str:
    cleaned = [sanitize_local_name(part, "") for part in parts if part]
    cleaned = [part for part in cleaned if part]
    if not cleaned:
        return fallback
    name = cleaned[0][0].lower() + cleaned[0][1:]
    for part in cleaned[1:]:
        name += part[:1].upper() + part[1:]
    return name if is_lua_identifier(name) else fallback


def camel_from_label(value: str, fallback: str, prefix: str = "") -> str:
    """Turn bytecode string hints like `button_prompt_back` into Lua names."""
    parts = [part for part in re.split(r"[^A-Za-z0-9]+", value) if part]
    if prefix:
        parts.insert(0, prefix)
    return camel_from_parts(parts, fallback)


def semantic_name_from_expr(value: str, fallback: str) -> str:
    call = value.split("(", 1)[0].strip()
    bare_calls = {
        "GetTextDimensions": "textDimensions",
        "RegisterMaterial": "material",
        "tonumber": "number",
        "tostring": "text",
    }
    if call in bare_calls:
        return bare_calls[call]
    if call.endswith(".new") or call.endswith(":new"):
        owner = call.rsplit(".", 1)[0].rsplit(":", 1)[0].split(".")[-1]
        known = {
            "UIButton": "button",
            "UIText": "text",
            "UIImage": "image",
            "UIElement": "element",
            "UIVerticalList": "verticalList",
            "Border": "border",
            "ButtonList": "buttonList",
            "CoD9Button": "button",
            "GrowingGridButton": "button",
            "NavButton": "button",
            "VerticalList": "verticalList",
        }
        return known.get(owner, camel_from_parts([owner], fallback))
    if ":" in call:
        method = call.rsplit(":", 1)[1]
        method_names = {
            "addButton": "button",
            "addCardCarousel": "cardCarousel",
            "addNewCard": "card",
            "getParent": "parent",
            "getFirstChild": "child",
            "getNextSibling": "sibling",
            "isInFocus": "isInFocus",
            "isPanelOnscreen": "isPanelOnscreen",
            "openMenu": "menu",
            "openPopup": "popup",
            "restoreState": "restoredState",
        }
        if method in method_names:
            return method_names[method]
        if method == "get":
            return "dvarValue"
        if method.startswith("get") and len(method) > 3:
            return camel_from_parts([method[3:]], fallback)
        if method.startswith("is") and len(method) > 2:
            return "is" + method[2:3].upper() + method[3:]
    if call.startswith("fn_"):
        return "result"
    if "." in call:
        owner, method = call.rsplit(".", 1)
        known_calls = {
            "AcceptingInvite": "isAcceptingInvite",
            "AloneInPartyIgnoreSplitscreen": "isAloneInParty",
            "AreAnyAttachmentsNew": "hasNewAttachments",
            "CheckLeagueDivisionChange": "leaguePromotionStatus",
            "DvarString": "dvarValue",
            "FormatNumberWithCommas": "formattedNumber",
            "GetCustomClass": "customClass",
            "GetAttachmentRef": "attachmentRef",
            "GetItemAttachment": "itemAttachment",
            "GetItemName": "itemName",
            "GetPlaylistID": "playlistId",
            "GetLeagueSeasonDate": "seasonDate",
            "GetXUID": "xuid",
            "HasDLCContent": "hasDLCContent",
            "HasMPPrivileges": "hasMPPrivileges",
            "PartyShowTruePlayerInfoByXuid": "showTruePlayerInfo",
            "PartyHostIsReadyToStart": "isPartyHostReady",
            "PartyIsReadyToStart": "isPartyReady",
            "PrivatePartyHost": "isPrivatePartyHost",
            "ProfileValueAsString": "profileValue",
            "ProfileInt": "profileValue",
            "SessionMode_IsSystemlinkGame": "isSystemlinkGame",
            "SessionModeIsMode": "isSessionMode",
            "GameModeIsMode": "isGameMode",
            "TableLookup": "tableValue",
            "DvarInt": "dvarValue",
            "Localize": "localizedText",
            "ToUpper": "upperText",
            "WebM_camera_IsAvailable": "isCameraAvailable",
        }
        if method in known_calls:
            return known_calls[method]
        if method == "New" and owner.endswith(".Menu"):
            return "menu"
        if method in {"NewSmallPopup", "SetupPopup", "SetupPopupBusy", "SetupPopupChoice"}:
            return "popup"
        if owner == "string" and method == "len":
            return "length"
        if owner == "string" and method in {"find", "match"}:
            return "match"
        if owner == "string" and method == "lower":
            return "lowerText"
        if owner == "math" and method in {"min", "max", "floor", "ceil"}:
            return "value"
        if owner == "math" and method == "sqrt":
            return "distance"
        if method == "NewRegistrationButton":
            return "button"
        if method.startswith("New") and method.endswith("Button"):
            return "button"
        if method == "New" and owner.startswith("CoD."):
            return camel_from_parts([owner.rsplit(".", 1)[-1]], fallback)
        if method.startswith("Is") and len(method) > 2:
            return "is" + method[2:]
        if method.startswith("Has") and len(method) > 3:
            return "has" + method[3:]
        if method.startswith("Should") and len(method) > 6:
            return "should" + method[6:]
        if method.startswith("Does") and len(method) > 4:
            return "does" + method[4:]
        if method.startswith("Can") and len(method) > 3:
            return "can" + method[3:]
        if method.startswith("Are") and len(method) > 3:
            return "are" + method[3:]
        if method.startswith("Get") and len(method) > 3:
            return camel_from_parts([method[3:]], fallback)
        if method.startswith("Create") and len(method) > 6:
            return camel_from_parts([method[6:]], fallback)
    if value.startswith("{"):
        return "data"
    return fallback


def source_lines_for_proto(
    proto: Proto,
    path: tuple[int, ...] = (),
    indent: str = "  ",
    infer_params: bool = False,
    skip_assigned_values: set[str] | None = None,
    upvalue_names: dict[int, str] | None = None,
    func_name: str | None = None,
    is_local: bool = False,
    names_by_path: dict[tuple[int, ...], str] | None = None,
) -> list[str]:
    names_by_path = names_by_path or {}
    regs: dict[int, str] = {}
    methods: dict[int, tuple[str, Any]] = {}
    table_fields: dict[int, list[tuple[Any, str]]] = {}
    declared: set[int] = set()
    local_names: dict[int, str] = {}
    used_local_names: set[str] = set()
    lines: list[str] = []
    params = source_params(proto, infer=infer_params, func_name=func_name, is_local=is_local)
    param_registers = {index for index, name in enumerate(params) if name != "..."}
    skip_assigned_values = skip_assigned_values or set()
    upvalue_names = upvalue_names or {}
    for index, name in enumerate(params):
        if name != "...":
            regs[index] = name

    def unique_local_name(base: str, reg: int) -> str:
        fallback = register_name(reg)
        base = sanitize_local_name(base, fallback)
        if base in {"arg0", "arg1", "arg2", "arg3", "arg4", "arg5"}:
            base = fallback
        candidate = base
        suffix = 2
        while candidate in used_local_names or candidate in params:
            candidate = f"{base}{suffix}"
            suffix += 1
        used_local_names.add(candidate)
        return candidate

    def local_reg_name(reg: int, hint: str | None = None) -> str:
        fallback = register_name(reg)
        if reg not in local_names:
            local_names[reg] = unique_local_name(hint or fallback_local_name(reg), reg)
        elif reg not in declared and hint:
            current = local_names[reg]
            wanted = sanitize_local_name(hint, fallback)
            if current in {fallback, fallback_local_name(reg)} and wanted != fallback:
                used_local_names.discard(current)
                local_names[reg] = unique_local_name(wanted, reg)
        return local_names[reg]

    def expr(reg: int) -> str:
        return regs.get(reg, local_reg_name(reg))

    def rk_expr(index: int) -> str:
        const_index = rk_constant_index(index)
        if const_index is not None:
            return lua_literal(constant_value(proto, const_index))
        return expr(index)

    def table_literal(fields: list[tuple[Any, str]]) -> str:
        if not fields:
            return "{}"
        positional: dict[int, str] = {}
        keyed: list[tuple[Any, str]] = []
        for key, value in fields:
            if isinstance(key, int) and key > 0:
                positional[key] = value
            else:
                keyed.append((key, value))
        parts = []
        index = 1
        while index in positional:
            parts.append(positional.pop(index))
            index += 1
        for key in sorted(positional):
            parts.append(f"[{key}] = {positional[key]}")
        for key, value in keyed:
            if isinstance(key, str) and is_lua_identifier(key):
                parts.append(f"{key} = {value}")
            else:
                parts.append(f"[{lua_literal(key)}] = {value}")
        return "{ " + ", ".join(parts) + " }"

    def refresh_table_expr(reg: int) -> None:
        if reg in table_fields:
            regs[reg] = table_literal(table_fields[reg])

    block_depth = 0

    def emit(text: str) -> None:
        lines.append(f"{indent}{'  ' * block_depth}{text}")

    def assign(reg: int, value: str, force_local: bool = False, hint: str | None = None) -> None:
        semantic_hint = hint or semantic_name_from_expr(value, register_name(reg))
        if semantic_hint == register_name(reg):
            semantic_hint = fallback_local_name(reg)
        name = local_reg_name(reg, semantic_hint)
        redeclare = False
        if reg not in declared and semantic_hint and semantic_hint != name:
            used_local_names.discard(name)
            name = unique_local_name(semantic_hint, reg)
            local_names[reg] = name
        if reg in declared and semantic_hint and semantic_hint != name:
            current_is_boolean = name.startswith("is") and len(name) > 2 and name[2].isupper()
            hint_is_boolean = semantic_hint.startswith("is") and len(semantic_hint) > 2 and semantic_hint[2].isupper()
            object_hint = semantic_hint in {
                "button",
                "buttonList",
                "element",
                "text",
                "image",
                "border",
                "verticalList",
                "slotListGridButton",
            }
            redeclare = current_is_boolean != hint_is_boolean or object_hint or name.startswith("local_")
            if redeclare:
                name = unique_local_name(semantic_hint, reg)
                local_names[reg] = name
        if force_local or reg not in declared or redeclare:
            emit(f"local {name} = {value}")
            if block_depth == 0:
                declared.add(reg)
        else:
            emit(f"{name} = {value}")
        regs[reg] = name

    def emit_param_update(reg: int) -> None:
        if block_depth > 0 and reg in param_registers:
            emit(f"{params[reg]} = {expr(reg)}")
            regs[reg] = params[reg]

    meaningful = [inst for inst in proto.instructions if inst.opname != "DATA"]
    last_meaningful_index = meaningful[-1].index if meaningful else -1
    returned_registers: set[int] = set()
    for inst in meaningful:
        if inst.opname == "RETURN" and inst.b > 1:
            returned_registers.update(range(inst.a, inst.a + inst.b - 1))
    next_meaningful: dict[int, Instruction | None] = {}
    for pos, inst in enumerate(meaningful):
        next_meaningful[inst.index] = meaningful[pos + 1] if pos + 1 < len(meaningful) else None
    skip_indices: set[int] = set()
    structured_ifs: dict[int, tuple[Instruction, int, str]] = {}
    close_after: dict[int, int] = {}
    else_after: dict[int, int] = {}
    by_index = {inst.index: inst for inst in meaningful}
    meaningful_positions = {inst.index: pos for pos, inst in enumerate(meaningful)}
    generic_loop_starts: dict[int, Instruction] = {}
    generic_loop_ends: dict[int, Instruction] = {}
    generic_iterator_calls: set[int] = set()
    goto_labels_before: dict[int, str] = {}
    goto_jumps: dict[int, str] = {}
    # Boolean-valued comparisons: cmp -> R_A = (a op b). Keyed by cmp index.
    bool_value: dict[int, int] = {}
    # Short-circuit and/or: TESTSET index -> (dst, operand_expr, "and"/"or", target).
    andor_start: dict[int, tuple[int, str, str, int]] = {}
    andor_finalize: dict[int, list[tuple[int, str, str]]] = {}

    _COMPARE_OPS = {"EQ", "EQ_BK", "LT", "LT_BK", "LE", "LE_BK", "TEST", "TEST_R1"}

    def compare_value_text(inst: Instruction) -> str:
        """The value produced by a comparison used as `x = a op b`."""
        if inst.opname in {"TEST", "TEST_R1"}:
            value = expr(inst.a if inst.opname == "TEST" else inst.b)
            return value if inst.c else f"not {value}"
        true_ops = {"EQ": "==", "EQ_BK": "==", "LT": "<", "LT_BK": "<", "LE": "<=", "LE_BK": "<="}
        false_ops = {"EQ": "~=", "EQ_BK": "~=", "LT": ">=", "LT_BK": ">=", "LE": ">", "LE_BK": ">"}
        op = true_ops[inst.opname] if inst.a else false_ops[inst.opname]
        return f"{rk_expr(inst.b)} {op} {rk_expr(inst.c)}"

    def condition_text(inst: Instruction) -> str:
        if inst.opname in {"TEST", "TEST_R1"}:
            value = expr(inst.a)
            return value if inst.c == 0 else f"not {value}"
        op_symbol = {"EQ": "==", "EQ_BK": "==", "LT": "<", "LT_BK": "<", "LE": "<=", "LE_BK": "<="}.get(inst.opname, "==")
        left = rk_expr(inst.b)
        right = rk_expr(inst.c)
        condition = f"{left} {op_symbol} {right}"
        if inst.a != 0:
            condition = f"not ({condition})"
        return condition

    def last_inner_before(boundary: int) -> Instruction | None:
        """Last meaningful instruction with index < boundary."""
        result: Instruction | None = None
        for candidate in meaningful:
            if candidate.index < boundary:
                result = candidate
            else:
                break
        return result

    # Pass 1: generic `for ... in` loops. Layout:
    #     JMP L2 ; L1: <body> ; L2: TFORLOOP ; JMP L1 (backward)
    # Identify the loop from the TFORLOOP + its backward JMP, then find the entry
    # JMP at (L1 - 1). Other forward JMPs inside the body can also target the
    # TFORLOOP (continue-style), so the entry must be located via the back edge,
    # not by picking any JMP that lands on the TFORLOOP.
    for inst in meaningful:
        if inst.opname == "TFORLOOP":
            back = next_meaningful.get(inst.index)
            if back and back.opname == "JMP" and back.sbx < 0:
                body_start = back.index + back.sbx + 1
                start = by_index.get(body_start - 1)
                if (
                    start is not None
                    and start.opname == "JMP"
                    and start.sbx > 0
                    and start.index + start.sbx + 1 == inst.index
                ):
                    generic_loop_starts[start.index] = inst
                    generic_loop_ends[inst.index] = back
                    previous_pos = meaningful_positions.get(start.index, 0) - 1
                    if previous_pos >= 0:
                        previous = meaningful[previous_pos]
                        if previous.opname in {"CALL", "CALL_I", "CALL_C", "CALL_M", "CALL_I_R1"} and previous.a == inst.a:
                            generic_iterator_calls.add(previous.index)

    generic_back_jumps = {back.index for back in generic_loop_ends.values()}
    for inst in meaningful:
        if inst.opname == "JMP" and inst.sbx < 0 and inst.index not in generic_back_jumps:
            target = inst.index + inst.sbx + 1
            label = goto_labels_before.setdefault(target, f"loop_{target}")
            goto_jumps[inst.index] = label


    # Pass 1b: boolean-valued comparisons `R_A = a op b`, encoded as
    #   <cmp> ; JMP +1 ; LOADBOOL A 0 1 ; LOADBOOL A 1 0
    # and short-circuit `and`/`or`, encoded as
    #   TESTSET A B C ; JMP +n ; <n instrs computing R_A>
    # These consume a comparison/test that would otherwise look like an `if`.
    for pos, inst in enumerate(meaningful):
        if inst.opname in _COMPARE_OPS and pos + 3 < len(meaningful):
            jmp, lb1, lb2 = meaningful[pos + 1], meaningful[pos + 2], meaningful[pos + 3]
            if (
                jmp.opname == "JMP"
                and lb1.opname == "LOADBOOL"
                and lb2.opname == "LOADBOOL"
                and lb1.a == lb2.a
                and lb1.b == 0
                and lb1.c == 1
                and lb2.b == 1
                and lb2.c == 0
            ):
                bool_value[inst.index] = lb1.a
                skip_indices.update({jmp.index, lb1.index, lb2.index})
                continue
        if inst.opname in {"CALL", "CALL_I", "CALL_C", "CALL_M", "CALL_I_R1", "NOT", "NOT_R1", "MOVE"} and pos + 3 < len(meaningful):
            jmp, lb1, lb2 = meaningful[pos + 1], meaningful[pos + 2], meaningful[pos + 3]
            if (
                jmp.opname == "JMP"
                and jmp.sbx in {2, 6}
                and lb1.opname == "LOADBOOL"
                and lb2.opname == "LOADBOOL"
                and lb1.a == inst.a
                and lb2.a == inst.a
                and lb1.b == 0
                and lb1.c == 1
                and lb2.b == 1
                and lb2.c == 0
            ):
                # Havok/T6 uses this after boolean-returning calls to normalize
                # truthiness. The call expression itself is the readable value.
                skip_indices.update({jmp.index, lb1.index, lb2.index})
                continue
        if inst.opname == "TESTSET" and pos + 1 < len(meaningful):
            jmp = meaningful[pos + 1]
            if jmp.opname == "JMP" and jmp.sbx > 0:
                target = jmp.index + jmp.sbx + 1
                operand = [m for m in meaningful if inst.index < m.index < target and m.index != jmp.index]
                # The operand block must compute a single value into R_A. Allow
                # calls/field access, but reject structural ops that would break
                # the single-expression assumption.
                safe = operand and all(
                    m.opname
                    not in {
                        "SETGLOBAL", "SETUPVAL", "SETUPVAL_R1", "RETURN", "JMP",
                        "CLOSURE", "TESTSET", "FORPREP", "FORLOOP", "TFORLOOP",
                    }
                    for m in operand
                )
                if safe:
                    op = "or" if inst.c else "and"
                    andor_start[inst.index] = (inst.a, "", op, target)
                    andor_finalize.setdefault(target, [])
                    skip_indices.add(jmp.index)

        # A JMP that lands on the very next instruction is a no-op;
        # if a bare comparison feeds only that jump, both are dead. Drop them so
        # they do not surface as `-- control flow` comments.
        if inst.opname == "JMP" and inst.sbx in {0, 1} and inst.index not in skip_indices:
            skip_indices.add(inst.index)
            if pos > 0 and meaningful[pos - 1].opname in _COMPARE_OPS and meaningful[pos - 1].index not in bool_value:
                skip_indices.add(meaningful[pos - 1].index)

    # Pass 2: if / if-else / while from a comparison or test followed by a
    # forward JMP that skips the block when the condition is false. Block
    # boundaries are emitted on arrival at the landing index (top of the main
    # loop), so all jump targets use the real `pc += sbx + 1` landing address.
    for inst in meaningful:
        if inst.index in bool_value:
            continue
        following = next_meaningful.get(inst.index)
        if inst.opname in {"EQ", "EQ_BK", "LT", "LT_BK", "LE", "LE_BK", "TEST", "TEST_R1"} and following and following.opname == "JMP" and following.sbx > 0:
            land = following.index + following.sbx + 1
            boundary = by_index.get(land - 1)
            if (
                boundary is not None
                and boundary.opname == "JMP"
                and boundary.index != following.index
                and boundary.index not in generic_loop_ends
                and boundary.index not in generic_loop_starts
            ):
                target = boundary.index + boundary.sbx + 1
                if boundary.sbx > 0 and target > land:
                    # then-block ends with a forward jump over an else-block.
                    structured_ifs[inst.index] = (following, land, "if")
                    else_after[land] = else_after.get(land, 0) + 1
                    close_after[target] = close_after.get(target, 0) + 1
                    skip_indices.add(boundary.index)
                    continue
                if boundary.sbx < 0 and target <= inst.index:
                    # body ends with a backward jump to the test: a while loop.
                    structured_ifs[inst.index] = (following, land, "while")
                    close_after[land] = close_after.get(land, 0) + 1
                    skip_indices.add(boundary.index)
                    continue
            structured_ifs[inst.index] = (following, land, "if")
            close_after[land] = close_after.get(land, 0) + 1

    goto_jumps = {index: label for index, label in goto_jumps.items() if index not in skip_indices}
    active_goto_labels = set(goto_jumps.values())
    goto_labels_before = {
        index: label for index, label in goto_labels_before.items() if label in active_goto_labels
    }

    def emit_block_boundaries(index: int) -> None:
        nonlocal block_depth
        for _ in range(close_after.get(index, 0)):
            block_depth = max(0, block_depth - 1)
            emit("end")
        for _ in range(else_after.get(index, 0)):
            block_depth = max(0, block_depth - 1)
            emit("else")
            block_depth += 1

    pending_andor: dict[int, list[tuple[int, str, str]]] = {}
    open_call_top: int | None = None

    for inst in proto.instructions:
        # Close/continue any structured blocks that end at this instruction
        # before emitting the instruction itself (the block's `end`/`else`
        # belongs above the first statement that follows the block).
        emit_block_boundaries(inst.index)
        if inst.index in goto_labels_before:
            emit(f"::{goto_labels_before[inst.index]}::")
        # Finalize any short-circuit and/or expression that lands here: the
        # operand block has run and left its value in the destination register.
        if inst.index in pending_andor:
            for dst, b_expr, op_word in pending_andor.pop(inst.index):
                current = regs.get(dst)
                rewritten = False
                # If the operand emitted an assignment (e.g. a call), splice the
                # `a and/or` prefix into that already-emitted line.
                if isinstance(current, str) and is_lua_identifier(current):
                    pattern = re.compile(r"^(\s*)(local )?" + re.escape(current) + r" = (.*)$")
                    for line_index in range(len(lines) - 1, -1, -1):
                        match = pattern.match(lines[line_index])
                        if match:
                            lines[line_index] = (
                                f"{match.group(1)}{match.group(2) or ''}{current} = "
                                f"{b_expr} {op_word} {match.group(3)}"
                            )
                            rewritten = True
                            break
                if not rewritten:
                    regs[dst] = f"({b_expr} {op_word} {expr(dst)})"
        if inst.index in skip_indices:
            continue
        op = inst.opname
        if op == "DATA":
            continue
        if inst.index in bool_value:
            regs[bool_value[inst.index]] = f"({compare_value_text(inst)})"
            continue
        if op == "TESTSET" and inst.index in andor_start:
            dst, _unused, op_word, target = andor_start[inst.index]
            pending_andor.setdefault(target, []).append((dst, expr(inst.b), op_word))
            continue
        if inst.index in structured_ifs:
            jump_inst, _, kind = structured_ifs[inst.index]
            condition = condition_text(inst)
            if kind == "while":
                emit(f"while {condition} do")
            else:
                emit(f"if {condition} then")
            block_depth += 1
            skip_indices.add(jump_inst.index)
            continue
        if inst.index in goto_jumps:
            emit(f"goto {goto_jumps[inst.index]}")
            continue
        if inst.index in generic_loop_starts:
            tfor_inst = generic_loop_starts[inst.index]
            iterator = expr(tfor_inst.a)
            loop_regs = list(range(tfor_inst.a + 3, tfor_inst.a + 3 + max(tfor_inst.c, 1)))
            if "ipairs" in iterator:
                hints = ["index", "value"]
            elif "pairs" in iterator:
                hints = ["key", "value"]
            else:
                hints = ["key", "value"]
            loop_vars = [local_reg_name(reg, hints[pos] if pos < len(hints) else None) for pos, reg in enumerate(loop_regs)]
            for reg in loop_regs:
                declared.add(reg)
                regs[reg] = local_reg_name(reg)
            emit(f"for {', '.join(loop_vars)} in {iterator} do")
            block_depth += 1
            continue
        if op == "GETGLOBAL":
            regs[inst.a] = constant_name(proto, inst.bx)
            emit_param_update(inst.a)
        elif op == "SETGLOBAL":
            value = expr(inst.a)
            if value not in skip_assigned_values:
                emit(f"{constant_name(proto, inst.bx)} = {value}")
        elif op == "GETUPVAL":
            regs[inst.a] = upvalue_names.get(inst.b, f"upvalue_{inst.b}")
        elif op in {"SETUPVAL", "SETUPVAL_R1"}:
            emit(f"{upvalue_names.get(inst.b, f'upvalue_{inst.b}')} = {expr(inst.a)}")
        elif op == "MOVE":
            moved = expr(inst.b)
            if inst.a in declared and regs.get(inst.a) != moved:
                assign(inst.a, moved)
            else:
                regs[inst.a] = moved
            emit_param_update(inst.a)
        elif op == "LOADK":
            regs[inst.a] = lua_literal(constant_value(proto, inst.bx))
            if block_depth == 0 and inst.a in returned_registers and inst.a not in declared:
                assign(inst.a, regs[inst.a])
            else:
                emit_param_update(inst.a)
        elif op == "LOADBOOL":
            regs[inst.a] = "true" if inst.b else "false"
            emit_param_update(inst.a)
        elif op == "LOADNIL":
            regs[inst.a] = "nil"
            emit_param_update(inst.a)
        elif op == "NEWTABLE":
            regs[inst.a] = "{}"
            table_fields[inst.a] = []
        elif op in {"GETFIELD", "GETFIELD_R1", "GETFIELD_MM"}:
            regs[inst.a] = field_expr(expr(inst.b), constant_value(proto, inst.c))
            emit_param_update(inst.a)
        elif op in {"SETFIELD", "SETFIELD_R1"}:
            value = rk_expr(inst.c)
            if inst.a in table_fields:
                table_fields[inst.a].append((constant_value(proto, inst.b), value))
                refresh_table_expr(inst.a)
            elif value in skip_assigned_values:
                pass
            else:
                emit(f"{field_expr(expr(inst.a), constant_value(proto, inst.b))} = {value}")
        elif op == "GETTABLE":
            regs[inst.a] = f"{expr(inst.b)}[{expr(inst.c)}]"
        elif op == "GETTABLE_S":
            regs[inst.a] = f"{expr(inst.b)}[{lua_literal(constant_value(proto, inst.c))}]"
        elif op == "GETTABLE_N":
            regs[inst.a] = f"{expr(inst.b)}[{inst.c}]"
        elif op == "SETTABLE":
            emit(f"{expr(inst.a)}[{rk_expr(inst.b)}] = {rk_expr(inst.c)}")
        elif op == "SETTABLE_S":
            emit(f"{expr(inst.a)}[{lua_literal(constant_value(proto, inst.b))}] = {rk_expr(inst.c)}")
        elif op == "SETTABLE_S_BK":
            key = constant_value(proto, inst.b)
            value = rk_expr(inst.c)
            if inst.a in table_fields:
                table_fields[inst.a].append((key, value))
                refresh_table_expr(inst.a)
            else:
                emit(f"{expr(inst.a)}[{lua_literal(key)}] = {value}")
        elif op == "SETTABLE_N":
            emit(f"{expr(inst.a)}[{inst.b}] = {rk_expr(inst.c)}")
        elif op == "SETLIST":
            start_index = ((inst.c or 1) - 1) * 50
            for offset in range(1, inst.b + 1):
                table_fields.setdefault(inst.a, []).append((start_index + offset, expr(inst.a + offset)))
            refresh_table_expr(inst.a)
        elif op == "CLOSURE":
            regs[inst.a] = names_by_path.get((*path, inst.bx)) or proto_path_name((*path, inst.bx))
        elif op == "SELF":
            base = expr(inst.b)
            method = self_field_value(proto, inst.c)
            regs[inst.a] = field_expr(base, method)
            regs[inst.a + 1] = base
            methods[inst.a] = (base, method)
        elif op in {"CALL", "CALL_I", "CALL_C", "CALL_M", "CALL_I_R1"}:
            fn = expr(inst.a)
            if inst.b == 0 and open_call_top is not None and open_call_top >= inst.a + 1:
                arg_end = open_call_top + 1
            else:
                arg_end = inst.a + max(inst.b, 1)
            arg_regs = [expr(reg) for reg in range(inst.a + 1, arg_end)]
            call_expr = f"{fn}({', '.join(arg_regs)})"
            if inst.a in methods:
                base, method = methods.pop(inst.a)
                method_text = method if isinstance(method, str) and is_lua_identifier(method) else lua_literal(method)
                if isinstance(method_text, str) and is_lua_identifier(method_text):
                    call_expr = f"{base}:{method_text}({', '.join(arg_regs[1:])})"
                else:
                    call_expr = f"{field_expr(base, method)}({', '.join(arg_regs)})"
            if inst.index in generic_iterator_calls:
                regs[inst.a] = call_expr
                continue
            if inst.c == 1:
                emit(call_expr)
                regs[inst.a] = call_expr
            else:
                assign(inst.a, call_expr)
            open_call_top = inst.a if inst.c == 0 else None
        elif op in {"TAILCALL", "TAILCALL_I", "TAILCALL_C", "TAILCALL_M", "TAILCALL_I_R1"}:
            if inst.b == 0 and open_call_top is not None and open_call_top >= inst.a + 1:
                arg_end = open_call_top + 1
            else:
                arg_end = inst.a + max(inst.b, 1)
            arg_regs = [expr(reg) for reg in range(inst.a + 1, arg_end)]
            emit(f"return {expr(inst.a)}({', '.join(arg_regs)})")
            open_call_top = None
        elif op == "RETURN":
            following = next_meaningful.get(inst.index)
            if inst.b > 1 and following and following.opname == "RETURN" and following.b <= 1:
                returned = ", ".join(expr(reg) for reg in range(inst.a, inst.a + inst.b - 1))
                emit(f"return {returned}")
                skip_indices.add(following.index)
            elif inst.index == last_meaningful_index:
                if inst.b <= 1:
                    if not (lines and lines[-1].strip().startswith("return ")):
                        emit("return")
                else:
                    returned = ", ".join(expr(reg) for reg in range(inst.a, inst.a + inst.b - 1))
                    emit(f"return {returned}")
            else:
                returned = "" if inst.b <= 1 else " " + ", ".join(expr(reg) for reg in range(inst.a, inst.a + inst.b - 1))
                if block_depth > 0:
                    if returned or not (lines and lines[-1].strip().startswith("return ")):
                        emit(f"return{returned}")
                else:
                    emit(f"-- return{returned}")
        elif op in {"ADD", "ADD_BK", "SUB", "SUB_BK", "MUL", "MUL_BK", "DIV", "DIV_BK", "MOD", "MOD_BK", "POW", "POW_BK"}:
            base_op = op.removesuffix("_BK")
            symbol = {"ADD": "+", "SUB": "-", "MUL": "*", "DIV": "/", "MOD": "%", "POW": "^"}[base_op]
            left = lua_literal(constant_value(proto, inst.b)) if op.endswith("_BK") else rk_expr(inst.b)
            regs[inst.a] = f"({left} {symbol} {rk_expr(inst.c)})"
        elif op in {"UNM", "NOT", "NOT_R1", "LEN"}:
            prefix = {"UNM": "-", "NOT": "not ", "NOT_R1": "not ", "LEN": "#"}[op]
            regs[inst.a] = f"{prefix}{expr(inst.b)}"
        elif op == "CONCAT":
            regs[inst.a] = " .. ".join(expr(reg) for reg in range(inst.b, inst.c + 1))
            if inst.a in declared:
                assign(inst.a, regs[inst.a])
        elif op == "FORPREP":
            loop_name = local_reg_name(inst.a + 3, "index")
            declared.add(inst.a + 3)
            regs[inst.a + 3] = loop_name
            emit(f"for {loop_name} = {expr(inst.a)}, {expr(inst.a + 1)}, {expr(inst.a + 2)} do")
            block_depth += 1
        elif op == "FORLOOP":
            block_depth = max(0, block_depth - 1)
            emit("end")
        elif op == "TFORLOOP" and inst.index in generic_loop_ends:
            block_depth = max(0, block_depth - 1)
            emit("end")
            skip_indices.add(generic_loop_ends[inst.index].index)
        elif op in {"JMP", "TFORLOOP", "TEST", "TEST_R1", "TESTSET", "EQ", "LT", "LE", "EQ_BK", "LT_BK", "LE_BK"}:
            emit(f"-- control flow: {readable_instruction_comment(proto, inst)[3:]}")
        else:
            emit(f"-- unresolved: {readable_instruction_comment(proto, inst)[3:]}")

    lines = strip_redundant_branch_comments(strip_empty_else_blocks(strip_trailing_control_comments(lines)))
    return lines or [f"{indent}-- empty function"]


def proto_path_name(path: tuple[int, ...]) -> str:
    if not path:
        return "chunk"
    return "fn_" + "_".join(str(part) for part in path)


def iter_protos(proto: Proto, path: tuple[int, ...] = ()):
    yield path, proto
    for child_index, child in enumerate(proto.children):
        yield from iter_protos(child, (*path, child_index))


def readable_instruction_comment(proto: Proto, inst: Instruction) -> str:
    detail = ""
    if inst.opname in {"GETGLOBAL", "SETGLOBAL", "LOADK"}:
        detail = f" -- K[{inst.bx}]={lua_literal(constant_value(proto, inst.bx))}"
    elif inst.opname in {"GETFIELD", "GETFIELD_R1", "GETFIELD_MM"}:
        detail = f" -- K[{inst.c}]={lua_literal(constant_value(proto, inst.c))}"
    elif inst.opname in {"SETFIELD", "SETFIELD_R1"}:
        detail = f" -- K[{inst.b}]={lua_literal(constant_value(proto, inst.b))}"
    elif inst.opname == "CLOSURE":
        detail = f" -- child[{inst.bx}]"
    return (
        f"-- [{inst.index:04d}] {inst.opname:<22} "
        f"A={inst.a} B={inst.b} C={inst.c} Bx={inst.bx} sBx={inst.sbx}{detail}"
    )


def recover_root_child_exports(proto: Proto) -> dict[int, str]:
    regs: dict[int, str] = {}
    closure_regs: dict[int, int] = {}
    exports: dict[int, str] = {}
    for inst in proto.instructions:
        if inst.opname == "GETGLOBAL":
            regs[inst.a] = constant_name(proto, inst.bx)
            closure_regs.pop(inst.a, None)
        elif inst.opname in {"GETFIELD", "GETFIELD_R1", "GETFIELD_MM"}:
            base = regs.get(inst.b, register_name(inst.b))
            regs[inst.a] = field_expr(base, constant_value(proto, inst.c))
            closure_regs.pop(inst.a, None)
        elif inst.opname == "NEWTABLE":
            regs[inst.a] = "{}"
            closure_regs.pop(inst.a, None)
        elif inst.opname == "CLOSURE":
            regs[inst.a] = proto_path_name((inst.bx,))
            closure_regs[inst.a] = inst.bx
        elif inst.opname in {"SETFIELD", "SETFIELD_R1"}:
            child_index = closure_regs.get(inst.c)
            if child_index is not None:
                base = regs.get(inst.a, register_name(inst.a))
                exports[child_index] = field_expr(base, constant_value(proto, inst.b))
        elif inst.opname == "SETGLOBAL":
            child_index = closure_regs.get(inst.a)
            if child_index is not None:
                exports[child_index] = constant_name(proto, inst.bx)
    return exports


def recover_root_child_upvalues(proto: Proto) -> dict[int, dict[int, str]]:
    regs: dict[int, str] = {}
    bindings: dict[int, dict[int, str]] = {}
    instructions = proto.instructions
    index = 0
    while index < len(instructions):
        inst = instructions[index]
        if inst.opname == "GETGLOBAL":
            regs[inst.a] = constant_name(proto, inst.bx)
        elif inst.opname in {"GETFIELD", "GETFIELD_R1", "GETFIELD_MM"}:
            regs[inst.a] = field_expr(regs.get(inst.b, register_name(inst.b)), constant_value(proto, inst.c))
        elif inst.opname == "NEWTABLE":
            regs[inst.a] = "{}"
        elif inst.opname == "CLOSURE":
            child_bindings: dict[int, str] = {}
            lookahead = index + 1
            upvalue_index = 0
            while lookahead < len(instructions) and instructions[lookahead].opname == "DATA":
                data_inst = instructions[lookahead]
                if data_inst.a == 1:
                    child_bindings[upvalue_index] = regs.get(data_inst.c, register_name(data_inst.c))
                    upvalue_index += 1
                lookahead += 1
            if child_bindings:
                bindings[inst.bx] = child_bindings
            regs[inst.a] = proto_path_name((inst.bx,))
        index += 1
    return bindings


def infer_event_upvalue_names(proto: Proto) -> dict[int, str]:
    regs: dict[int, Any] = {}
    methods: dict[int, tuple[str, Any]] = {}
    names: dict[int, str] = {}
    # Registers currently holding a real string constant (from LOADK). Only
    # these are trusted as event-name literals; a plain register fallback name
    # like "local_1" must never be mistaken for an event string.
    const_str_regs: set[int] = set()

    def value(reg: int) -> Any:
        return regs.get(reg, register_name(reg))

    def clear(reg: int) -> None:
        const_str_regs.discard(reg)

    for inst in proto.instructions:
        op = inst.opname
        if op == "GETGLOBAL":
            regs[inst.a] = constant_name(proto, inst.bx)
            clear(inst.a)
        elif op in {"GETFIELD", "GETFIELD_R1", "GETFIELD_MM"}:
            regs[inst.a] = field_expr(str(value(inst.b)), constant_value(proto, inst.c))
            clear(inst.a)
        elif op == "LOADK":
            constant = constant_value(proto, inst.bx)
            regs[inst.a] = constant
            if isinstance(constant, str):
                const_str_regs.add(inst.a)
            else:
                clear(inst.a)
        elif op == "MOVE":
            regs[inst.a] = value(inst.b)
            if inst.b in const_str_regs:
                const_str_regs.add(inst.a)
            else:
                clear(inst.a)
        elif op == "GETUPVAL":
            regs[inst.a] = ("upvalue", inst.b)
            clear(inst.a)
        elif op == "SELF":
            base = str(value(inst.b))
            method = self_field_value(proto, inst.c)
            regs[inst.a] = field_expr(base, method)
            regs[inst.a + 1] = base
            methods[inst.a] = (base, method)
            clear(inst.a)
            clear(inst.a + 1)
        elif op in {"CALL", "CALL_I", "CALL_C", "CALL_M", "CALL_I_R1"}:
            if inst.a in methods:
                _, method = methods.pop(inst.a)
                name_reg = inst.a + 2
                handler_reg = inst.a + 3
                if (
                    method == "registerEventHandler"
                    and inst.b >= 3
                    and name_reg in const_str_regs
                    and isinstance(regs.get(name_reg), str)
                ):
                    handler = regs.get(handler_reg)
                    if isinstance(handler, tuple) and handler[0] == "upvalue":
                        names[int(handler[1])] = sanitize_local_name(
                            regs[name_reg], f"upvalue_{handler[1]}"
                        )
                if isinstance(method, str):
                    for arg_pos, reg in enumerate(range(inst.a + 1, inst.a + max(inst.b, 1))):
                        handler = regs.get(reg)
                        if isinstance(handler, tuple) and handler[0] == "upvalue":
                            candidate = child_name_from_method_arg(method, arg_pos)
                            if candidate:
                                names.setdefault(int(handler[1]), candidate)
            else:
                callee = regs.get(inst.a)
                if isinstance(callee, str):
                    for arg_pos, reg in enumerate(range(inst.a + 1, inst.a + max(inst.b, 1))):
                        handler = regs.get(reg)
                        if isinstance(handler, tuple) and handler[0] == "upvalue":
                            candidate = child_name_from_method_arg(callee, arg_pos)
                            if candidate:
                                names.setdefault(int(handler[1]), candidate)
        elif op in {"SETFIELD", "SETFIELD_R1"}:
            handler = regs.get(inst.c)
            field = constant_value(proto, inst.b)
            if isinstance(handler, tuple) and handler[0] == "upvalue" and isinstance(field, str):
                names.setdefault(int(handler[1]), sanitize_local_name(field, f"upvalue_{handler[1]}"))
        elif op in {"SETTABLE_S", "SETTABLE_S_BK"}:
            handler = regs.get(inst.c)
            key = constant_value(proto, inst.b)
            if isinstance(handler, tuple) and handler[0] == "upvalue" and isinstance(key, str):
                names.setdefault(int(handler[1]), sanitize_local_name(key, f"upvalue_{handler[1]}"))
    return names


def child_name_from_method_arg(method: str, arg_pos: int) -> str | None:
    """Name a closure from the API argument slot it is passed to."""
    known: dict[str, dict[int, str]] = {
        "registerEventHandler": {1: "handleEvent"},
        "addCardCarousel": {2: "populateCardCarousel"},
        "ScrollableContentGrid.new": {4: "handleButtonOver", 5: "handleButtonGainFocus"},
        "table.sort": {1: "compareItems"},
    }
    if method in known and arg_pos in known[method]:
        return known[method][arg_pos]
    if arg_pos == 0 and method.startswith("set") and len(method) > 3:
        return camel_from_parts(["set", method[3:]], "setValue")
    if arg_pos == 0 and method.startswith("add") and len(method) > 3:
        return camel_from_parts(["add", method[3:]], "addValue")
    return None


def infer_parent_child_names(proto: Proto) -> dict[int, str]:
    """Infer child names from the parent instruction stream.

    This catches local helpers whose own stripped bytecode has no name, but
    whose closure is assigned to a meaningful field (`button.isSelected = f`) or
    passed to a named callback slot (`registerEventHandler("x", f)`).
    """
    regs: dict[int, Any] = {}
    closure_regs: dict[int, int] = {}
    methods: dict[int, tuple[str, str | Any]] = {}
    names: dict[int, str] = {}
    const_str_regs: set[int] = set()

    def value(reg: int) -> Any:
        return regs.get(reg, register_name(reg))

    def clear(reg: int) -> None:
        closure_regs.pop(reg, None)
        const_str_regs.discard(reg)

    def note(child_index: int | None, candidate: str | None) -> None:
        if child_index is None or not candidate:
            return
        if child_index in names:
            return
        names[child_index] = sanitize_local_name(candidate, f"inferredFunction{child_index + 1}")

    for inst in proto.instructions:
        op = inst.opname
        if op == "GETGLOBAL":
            regs[inst.a] = constant_name(proto, inst.bx)
            clear(inst.a)
        elif op == "LOADK":
            constant = constant_value(proto, inst.bx)
            regs[inst.a] = constant
            closure_regs.pop(inst.a, None)
            if isinstance(constant, str):
                const_str_regs.add(inst.a)
            else:
                const_str_regs.discard(inst.a)
        elif op in {"GETFIELD", "GETFIELD_R1", "GETFIELD_MM"}:
            regs[inst.a] = field_expr(str(value(inst.b)), constant_value(proto, inst.c))
            clear(inst.a)
        elif op == "MOVE":
            regs[inst.a] = value(inst.b)
            if inst.b in closure_regs:
                closure_regs[inst.a] = closure_regs[inst.b]
            else:
                closure_regs.pop(inst.a, None)
            if inst.b in const_str_regs:
                const_str_regs.add(inst.a)
            else:
                const_str_regs.discard(inst.a)
        elif op == "CLOSURE":
            regs[inst.a] = proto_path_name((inst.bx,))
            closure_regs[inst.a] = inst.bx
            const_str_regs.discard(inst.a)
        elif op == "SELF":
            base = str(value(inst.b))
            method = self_field_value(proto, inst.c)
            regs[inst.a] = field_expr(base, method)
            regs[inst.a + 1] = base
            methods[inst.a] = (base, method)
            clear(inst.a)
            clear(inst.a + 1)
        elif op in {"SETFIELD", "SETFIELD_R1"}:
            child_index = closure_regs.get(inst.c)
            field = constant_value(proto, inst.b)
            if isinstance(field, str):
                note(child_index, field)
        elif op == "SETTABLE_S":
            child_index = closure_regs.get(inst.c)
            key = constant_value(proto, inst.b)
            if isinstance(key, str):
                note(child_index, key)
        elif op == "SETTABLE_S_BK":
            child_index = closure_regs.get(inst.c)
            key = constant_value(proto, inst.b)
            if isinstance(key, str):
                note(child_index, key)
        elif op in {"CALL", "CALL_I", "CALL_C", "CALL_M", "CALL_I_R1"}:
            method_name: str | None = None
            if inst.a in methods:
                _base, method = methods.pop(inst.a)
                method_name = str(method)
                if method_name == "registerEventHandler" and inst.b >= 4:
                    event_name = regs.get(inst.a + 2)
                    child_index = closure_regs.get(inst.a + 3)
                    if inst.a + 2 in const_str_regs and isinstance(event_name, str):
                        note(child_index, camel_from_label(event_name, "handleEvent", "handle"))
            else:
                callee = regs.get(inst.a)
                if isinstance(callee, str):
                    method_name = callee
            if method_name:
                for arg_pos, reg in enumerate(range(inst.a + 1, inst.a + max(inst.b, 1))):
                    child_index = closure_regs.get(reg)
                    note(child_index, child_name_from_method_arg(method_name, arg_pos))
            regs.pop(inst.a, None)
            closure_regs.pop(inst.a, None)
            const_str_regs.discard(inst.a)
    return names


def guess_local_function_name(child: Proto) -> str | None:
    """Best-effort readable name for an anonymous local function.

    BO2 retail Lua does not appear to preserve local debug names, so this uses
    semantic bytecode evidence only: event strings passed to
    `registerEventHandler`, returned UI constructors, and distinctive string
    constants. Returns None when no meaningful hint exists.
    """
    insts = [inst for inst in child.instructions if inst.opname != "DATA"]

    regs: dict[int, Any] = {}
    methods: dict[int, tuple[str, str | Any]] = {}
    for inst in insts:
        if inst.opname == "LOADK":
            regs[inst.a] = constant_value(child, inst.bx)
        elif inst.opname == "GETGLOBAL":
            regs[inst.a] = constant_name(child, inst.bx)
        elif inst.opname in {"GETFIELD", "GETFIELD_R1", "GETFIELD_MM"}:
            base = regs.get(inst.b)
            field = constant_value(child, inst.c)
            regs[inst.a] = field_expr(str(base), field) if base else field
        elif inst.opname == "MOVE":
            regs[inst.a] = regs.get(inst.b)
        elif inst.opname == "SELF":
            base = regs.get(inst.b)
            method = self_field_value(child, inst.c)
            regs[inst.a] = field_expr(str(base), method) if base else method
            regs[inst.a + 1] = base
            methods[inst.a] = (str(base), method)
        elif inst.opname in {"CALL", "CALL_I", "CALL_C", "CALL_M", "CALL_I_R1"}:
            if inst.a in methods:
                _base, method = methods.pop(inst.a)
                if method == "registerEventHandler" and inst.b >= 3:
                    event_name = regs.get(inst.a + 2)
                    if isinstance(event_name, str) and event_name:
                        return camel_from_label(event_name, "handleEvent", "handle")
            regs.pop(inst.a, None)

    returned: set[int] = set()
    for inst in insts:
        if inst.opname == "RETURN" and inst.b > 1:
            returned.update(range(inst.a, inst.a + inst.b - 1))
    if not returned:
        return None
    reg_expr: dict[int, str] = {}
    constructed: dict[int, str] = {}
    for inst in insts:
        if inst.opname == "GETGLOBAL":
            reg_expr[inst.a] = constant_name(child, inst.bx)
        elif inst.opname in {"GETFIELD", "GETFIELD_R1", "GETFIELD_MM"}:
            base = reg_expr.get(inst.b)
            field = constant_value(child, inst.c)
            reg_expr[inst.a] = f"{base}.{field}" if base and isinstance(field, str) else ""
        elif inst.opname == "MOVE":
            if inst.b in constructed:
                constructed[inst.a] = constructed[inst.b]
        elif inst.opname in {"CALL", "CALL_I", "CALL_C", "CALL_M", "CALL_I_R1"}:
            callee = reg_expr.get(inst.a) or ""
            if callee:
                last = callee.rsplit(".", 1)[-1]
                owner = callee.rsplit(".", 1)[0].rsplit(".", 1)[-1] if "." in callee else ""
                if last in {"new", "New"} and owner:
                    constructed[inst.a] = "create" + owner[:1].upper() + owner[1:]
                    if inst.a in returned:
                        return constructed[inst.a]
            reg_expr.pop(inst.a, None)

    for reg in sorted(returned):
        if reg in constructed:
            return constructed[reg]

    preferred_prefixes = (
        "button_prompt_",
        "menu_",
        "aar_",
        "cac_",
        "league_",
        "player_",
        "party_",
        "zombie_",
    )
    for constant in child.constants:
        if constant.type_name != "string" or not isinstance(constant.value, str):
            continue
        value = constant.value.strip()
        if len(value) < 3 or len(value) > 64:
            continue
        lowered = value.lower()
        if lowered.startswith(preferred_prefixes):
            return camel_from_label(value, "buildElement", "build")
    return None


def resolve_root_children(
    proto: Proto,
) -> tuple[dict[int, str], dict[int, str], dict[int, list[tuple[str, Any]]]]:
    """Assign one consistent name to every root child function.

    Returns (export_names, local_names, upvalue_bindings) where:
      * export_names maps child index -> dotted export (`CoD.X.Foo`);
      * local_names maps child index -> a `local function` name for children that
        are captured as upvalues by other children;
      * upvalue_bindings maps child index -> per-upvalue binding descriptors so
        every GETUPVAL resolves to the exact same name used at the declaration.
    """
    exports = recover_root_child_exports(proto)
    parent_names = infer_parent_child_names(proto)
    insts = proto.instructions

    # Upvalues here are captured as OPEN references to parent register slots;
    # the closure that ends up in a slot may be created later in the root
    # (module-level local functions). Pre-scan every CLOSURE-to-slot assignment
    # so forward-referenced captures still resolve to the right child.
    slot_child: dict[int, int] = {}
    for inst in insts:
        if inst.opname == "CLOSURE":
            slot_child[inst.a] = inst.bx
        elif inst.opname == "MOVE" and inst.b in slot_child:
            slot_child[inst.a] = slot_child[inst.b]

    reg_expr: dict[int, str] = {}
    bindings: dict[int, list[tuple[str, Any]]] = {}
    i = 0
    while i < len(insts):
        inst = insts[i]
        op = inst.opname
        if op == "GETGLOBAL":
            reg_expr[inst.a] = constant_name(proto, inst.bx)
        elif op in {"GETFIELD", "GETFIELD_R1", "GETFIELD_MM"}:
            base = reg_expr.get(inst.b)
            field = constant_value(proto, inst.c)
            reg_expr[inst.a] = field_expr(base, field) if base else ""
        elif op == "MOVE" and inst.b in reg_expr:
            reg_expr[inst.a] = reg_expr[inst.b]
        elif op == "CLOSURE":
            ups: list[tuple[str, Any]] = []
            j = i + 1
            while j < len(insts) and insts[j].opname == "DATA":
                data = insts[j]
                if data.a == 1:
                    reg = data.c
                    if reg in slot_child:
                        ups.append(("child", slot_child[reg]))
                    elif reg_expr.get(reg):
                        ups.append(("expr", reg_expr[reg]))
                    else:
                        ups.append(("reg", reg))
                j += 1
            if ups:
                bindings[inst.bx] = ups
        i += 1

    # Children captured as upvalues need a stable local name.
    referenced: set[int] = set()
    for ups in bindings.values():
        for kind, val in ups:
            if kind == "child":
                referenced.add(int(val))

    local_names: dict[int, str] = {}
    for child_index, name in parent_names.items():
        if child_index not in exports:
            local_names.setdefault(child_index, name)

    # Event-handler names are the strongest signal: a child that registers
    # another child as a handler names it after the event string.
    for child_index in range(len(proto.children)):
        handler_names = infer_event_upvalue_names(proto.children[child_index])
        for upvalue_index, name in handler_names.items():
            ups = bindings.get(child_index, [])
            if upvalue_index < len(ups) and ups[upvalue_index][0] == "child":
                local_names.setdefault(int(ups[upvalue_index][1]), name)

    used = set(local_names.values())
    counter = 1
    for child_index in sorted(referenced):
        if child_index in exports or child_index in local_names:
            continue
        if not (0 <= child_index < len(proto.children)):
            continue
        guessed = guess_local_function_name(proto.children[child_index])
        candidate = guessed or f"inferredFunction{counter}"
        base = candidate
        suffix = 2
        while candidate in used:
            candidate = f"{base}{suffix}"
            suffix += 1
        used.add(candidate)
        local_names[child_index] = candidate
        if not guessed:
            counter += 1
    return exports, local_names, bindings


def can_use_function_statement(name: str) -> bool:
    return all(is_lua_identifier(part) for part in name.split("."))


def decompile_child_function(
    proto: Proto,
    path: tuple[int, ...],
    export_name: str | None = None,
    local_name: str | None = None,
    upvalue_names: dict[int, str] | None = None,
    names_by_path: dict[tuple[int, ...], str] | None = None,
) -> list[str]:
    name = local_name or proto_path_name(path)
    func_name = export_name or name
    is_local = export_name is None
    params = ", ".join(source_params(proto, infer=True, func_name=func_name, is_local=is_local))
    if export_name:
        if can_use_function_statement(export_name):
            lines = [f"function {export_name}({params})"]
        else:
            lines = [f"{export_name} = function({params})"]
    else:
        lines = [f"local function {name}({params})"]
    if proto.instructions:
        lines.extend(
            source_lines_for_proto(
                proto,
                path,
                "  ",
                infer_params=True,
                upvalue_names=upvalue_names,
                func_name=func_name,
                is_local=is_local,
                names_by_path=names_by_path,
            )
        )
    lines.append("end")
    return lines


def recover_root_assignments(proto: Proto) -> list[str]:
    regs: dict[int, str] = {}
    pending_lines: list[str] = []
    for inst in proto.instructions:
        if inst.opname == "GETGLOBAL":
            regs[inst.a] = constant_name(proto, inst.bx)
        elif inst.opname in {"GETFIELD", "GETFIELD_R1", "GETFIELD_MM"}:
            base = regs.get(inst.b, f"R{inst.b}")
            field = constant_name(proto, inst.c)
            regs[inst.a] = f"{base}.{field}"
        elif inst.opname == "NEWTABLE":
            regs[inst.a] = "{}"
        elif inst.opname == "CLOSURE":
            regs[inst.a] = proto_path_name((inst.bx,))
        elif inst.opname in {"SETFIELD", "SETFIELD_R1"}:
            base = regs.get(inst.a, f"R{inst.a}")
            field = constant_name(proto, inst.b)
            value = regs.get(inst.c, f"R{inst.c}")
            pending_lines.append(f"{base}.{field} = {value}")
    return pending_lines


def root_approx_statements(proto: Proto) -> list[str]:
    lines = ["local R = {}"]
    for inst in proto.instructions:
        lines.append(approx_statement(proto, inst))
    return lines


def build_naming(
    root: Proto,
) -> tuple[dict[tuple[int, ...], str], dict[tuple[int, ...], str], dict[tuple[int, ...], dict[int, str]]]:
    """Assign one consistent name to every function at every depth.

    Walks each proto that defines child closures, reusing resolve_root_children,
    so nested (depth-2+) functions and their upvalue references share the same
    name everywhere instead of leaking `fn_<a>_<b>` placeholders.
    """
    names_by_path: dict[tuple[int, ...], str] = {}
    export_by_path: dict[tuple[int, ...], str] = {}
    upvalues_by_path: dict[tuple[int, ...], dict[int, str]] = {}
    generic_counter = 0

    for path, parent in iter_protos(root):
        exports, local_names, bindings = resolve_root_children(parent)
        used: set[str] = set()

        def unique(base: str) -> str:
            candidate = base
            suffix = 2
            while candidate in used:
                candidate = f"{base}{suffix}"
                suffix += 1
            used.add(candidate)
            return candidate

        # Some child prototypes fail to parse (unknown nested descriptor), so the
        # parsed children list can be shorter than the closures referenced by the
        # bytecode. Name every index the instruction stream refers to so CLOSURE
        # references still resolve to a real name instead of an fn_<n> placeholder.
        max_index = len(parent.children)
        for idx in exports:
            max_index = max(max_index, idx + 1)
        for idx in local_names:
            max_index = max(max_index, idx + 1)
        for ups in bindings.values():
            for kind, val in ups:
                if kind == "child":
                    max_index = max(max_index, int(val) + 1)

        for child_index in range(max_index):
            cpath = (*path, child_index)
            if child_index in exports:
                export_by_path[cpath] = exports[child_index]
                names_by_path[cpath] = exports[child_index]
                used.add(exports[child_index])
            elif child_index in local_names:
                names_by_path[cpath] = unique(local_names[child_index])
            elif child_index < len(parent.children):
                guessed = guess_local_function_name(parent.children[child_index])
                if guessed:
                    names_by_path[cpath] = unique(guessed)
                else:
                    generic_counter += 1
                    names_by_path[cpath] = unique(f"inferredCallback{generic_counter}")
            else:
                generic_counter += 1
                names_by_path[cpath] = unique(f"inferredCallback{generic_counter}")

        for child_index in range(len(parent.children)):
            cpath = (*path, child_index)
            resolved: dict[int, str] = {}
            for upvalue_index, (kind, val) in enumerate(bindings.get(child_index, [])):
                if kind == "child" and 0 <= int(val) < len(parent.children):
                    sib = (*path, int(val))
                    resolved[upvalue_index] = names_by_path.get(sib) or proto_path_name(sib)
                elif kind == "expr":
                    resolved[upvalue_index] = str(val)
                else:
                    resolved[upvalue_index] = f"capturedValue{upvalue_index}"
            upvalues_by_path[cpath] = resolved

    return names_by_path, export_by_path, upvalues_by_path


def readable_lua(proto: Proto, source_name: str = "") -> str:
    lines = [
        "-- BO2 Xbox/Treyarch Lua decompile",
        "-- Decompiled from Havok/T6 bytecode. Some branch structure and local names are inferred.",
    ]
    if source_name:
        lines.append(f"-- Source payload: {source_name}")
    lines.append("")

    names_by_path, export_by_path, upvalues_by_path = build_naming(proto)

    skipped_root_values = {
        name for path, name in names_by_path.items() if len(path) == 1 and path in export_by_path
    }
    if proto.instructions:
        lines.extend(
            source_lines_for_proto(
                proto, (), "", skip_assigned_values=skipped_root_values, names_by_path=names_by_path
            )
        )
        lines.append("")

    for path, child in iter_protos(proto):
        if not path:
            continue
        export_name = export_by_path.get(path)
        local_name = names_by_path.get(path) if path not in export_by_path else None
        upvalue_names = upvalues_by_path.get(path, {})
        lines.extend(
            decompile_child_function(child, path, export_name, local_name, upvalue_names, names_by_path)
        )
        lines.append("")

    lines.append("")
    return "\n".join(lines)


def disassemble_proto(proto: Proto, indent: str = "") -> list[str]:
    lines = []
    lines.append(
        f"{indent}.proto offset=0x{proto.offset:X} line={proto.line_defined}-{proto.last_line_defined} "
        f"params={proto.param_count} upvalues={proto.upvalue_count} flags=0x{proto.proto_flags:02X} maxstack={proto.max_stack}"
    )
    lines.append(f"{indent}.constants {len(proto.constants)}")
    for c in proto.constants:
        lines.append(f"{indent}  K[{c.index:03d}] {c.type_name:<7} {format_constant(c.value)}")
    lines.append(f"{indent}.code {len(proto.instructions)}")
    for inst in proto.instructions:
        lines.append(
            f"{indent}  [{inst.index:04d}] 0x{inst.offset:06X} {inst.raw.hex(' ').upper():<11} "
            f"{inst.opname:<26} A={inst.a:03d} B={inst.b:03d} C={inst.c:03d} "
            f"Bx={inst.bx:06d} sBx={inst.sbx:+d}"
        )
    for child in proto.children:
        lines.extend(disassemble_proto(child, indent + "  "))
    return lines


def pseudo_decompile(proto: Proto) -> str:
    lines = [
        "-- BO2 Xbox/Treyarch compiled Lua bytecode",
        "-- This is a structural pseudo-decompile, not verified source.",
        "-- Constants and Havok/T6 opcode names are shown for reverse engineering.",
        "",
    ]
    string_constants = [c for c in proto.constants if c.type_name == "string"]
    if string_constants:
        lines.append("-- string constants")
        for c in string_constants:
            lines.append(f"-- K[{c.index:03d}] = {format_constant(c.value)}")
        lines.append("")
    lines.extend("-- " + line for line in disassemble_proto(proto))
    lines.append("")
    return "\n".join(lines)


def cmd_disasm(args: argparse.Namespace) -> int:
    parsed = parse_chunk(args.input)
    lines = disassemble_proto(parsed["proto"])
    text = "\n".join(lines) + "\n"
    if args.out:
        args.out.write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    if args.json:
        data = dict(parsed)
        data["proto"] = proto_to_dict(parsed["proto"])
        args.json.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return 0


def cmd_decompile(args: argparse.Namespace) -> int:
    parsed = parse_chunk(args.input)
    text = pseudo_decompile(parsed["proto"])
    args.out.write_text(text, encoding="utf-8")
    return 0


def cmd_decompile_source(args: argparse.Namespace) -> int:
    parsed = parse_chunk(args.input)
    text = readable_lua(parsed["proto"], str(args.input))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(text, encoding="utf-8")
    return 0


def cmd_decompile_json(args: argparse.Namespace) -> int:
    workspace = make_editable_workspace(args.input)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(workspace, indent=2) + "\n", encoding="utf-8")
    return 0


def cmd_decompile_asm(args: argparse.Namespace) -> int:
    workspace = make_editable_workspace(args.input)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(hksasm_from_workspace(workspace), encoding="utf-8")
    return 0


def cmd_recompile(args: argparse.Namespace) -> int:
    suffix = args.input.suffix.lower()
    if suffix == ".json":
        data = rebuild_from_workspace(args.input)
    elif suffix == ".hksasm":
        data = rebuild_from_hksasm(args.input)
    else:
        # Lossless recompile mode for raw bytecode: copy a compiled chunk back
        # out after validation. Editable source compilation is still a separate
        # milestone; JSON workspace rebuild is handled above.
        data = args.input.read_bytes()
        parse_chunk(args.input)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(data)
    return 0


def cmd_recompile_asm(args: argparse.Namespace) -> int:
    data = rebuild_from_hksasm(args.input)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(data)
    return 0


def cmd_decompile_dir(args: argparse.Namespace) -> int:
    count = 0
    skipped = 0
    failures = []
    for path in args.input.rglob("*.lua"):
        if path.read_bytes()[:4] != b"\x1bLua":
            skipped += 1
            continue
        try:
            parsed = parse_chunk(path)
        except Exception as exc:  # noqa: BLE001 - report all files, keep going.
            failures.append({"path": str(path), "error": str(exc)})
            continue
        rel = path.relative_to(args.input)
        out_path = args.out / rel.with_suffix(".pseudo.lua")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(pseudo_decompile(parsed["proto"]), encoding="utf-8")
        count += 1
    manifest = {"decompiled": count, "skipped_non_bytecode": skipped, "failed": failures}
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "decompile_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"decompiled {count} Lua bytecode files to {args.out}")
    if failures:
        print(f"failed: {len(failures)}")
    return 0 if not failures else 1


def cmd_decompile_source_dir(args: argparse.Namespace) -> int:
    count = 0
    skipped = 0
    failures = []
    for path in args.input.rglob("*.lua"):
        if path.read_bytes()[:4] != b"\x1bLua":
            skipped += 1
            continue
        try:
            parsed = parse_chunk(path)
            text = readable_lua(parsed["proto"], str(path))
        except Exception as exc:  # noqa: BLE001 - report all files, keep going.
            failures.append({"path": str(path), "error": str(exc)})
            continue
        rel = path.relative_to(args.input)
        out_path = args.out / rel.with_suffix(".readable.lua")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text, encoding="utf-8")
        count += 1
    manifest = {
        "decompiled_source": count,
        "skipped_non_bytecode": skipped,
        "failed": failures,
        "mode": "readable pseudo-source; valid Lua text with bytecode comments for unresolved operations",
    }
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "decompile_source_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {count} readable Lua files to {args.out}")
    if failures:
        print(f"failed: {len(failures)}")
    return 0 if not failures else 1


def cmd_decompile_json_dir(args: argparse.Namespace) -> int:
    count = 0
    skipped = 0
    failures = []
    for path in args.input.rglob("*.lua"):
        if path.read_bytes()[:4] != b"\x1bLua":
            skipped += 1
            continue
        try:
            workspace = make_editable_workspace(path)
        except Exception as exc:  # noqa: BLE001 - report all files, keep going.
            failures.append({"path": str(path), "error": str(exc)})
            continue
        rel = path.relative_to(args.input)
        out_path = args.out / rel.with_suffix(".edit.json")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(workspace, indent=2) + "\n", encoding="utf-8")
        count += 1
    manifest = {
        "format": "bo2-xbox-lua-edit-v1",
        "decompiled_json": count,
        "skipped_non_bytecode": skipped,
        "failed": failures,
        "note": "Edit same-length constants or instruction opcode/operands/raw_hex, then rebuild with recompile-json-dir.",
    }
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "decompile_json_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {count} editable Lua bytecode JSON files to {args.out}")
    if failures:
        print(f"failed: {len(failures)}")
    return 0 if not failures else 1


def cmd_decompile_asm_dir(args: argparse.Namespace) -> int:
    count = 0
    skipped = 0
    failures = []
    for path in args.input.rglob("*.lua"):
        if path.read_bytes()[:4] != b"\x1bLua":
            skipped += 1
            continue
        try:
            workspace = make_editable_workspace(path)
            text = hksasm_from_workspace(workspace)
        except Exception as exc:  # noqa: BLE001 - report all files, keep going.
            failures.append({"path": str(path), "error": str(exc)})
            continue
        rel = path.relative_to(args.input)
        out_path = args.out / rel.with_suffix(".hksasm")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text, encoding="utf-8")
        count += 1
    manifest = {
        "format": "BO2HKSASM v1",
        "decompiled_asm": count,
        "skipped_non_bytecode": skipped,
        "failed": failures,
        "note": "Edit .const/.inst lines, then rebuild with recompile-asm-dir.",
    }
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "decompile_asm_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {count} HKS assembly files to {args.out}")
    if failures:
        print(f"failed: {len(failures)}")
    return 0 if not failures else 1


def cmd_recompile_dir(args: argparse.Namespace) -> int:
    count = 0
    skipped = 0
    failures = []
    for path in args.input.rglob("*.lua"):
        if path.read_bytes()[:4] != b"\x1bLua":
            skipped += 1
            continue
        try:
            parse_chunk(path)
        except Exception as exc:  # noqa: BLE001 - report all files, keep going.
            failures.append({"path": str(path), "error": str(exc)})
            continue
        rel = path.relative_to(args.input)
        out_path = args.out / rel
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(path.read_bytes())
        count += 1
    manifest = {
        "recompiled": count,
        "skipped_non_bytecode": skipped,
        "failed": failures,
        "mode": "lossless bytecode re-emit; editable Lua source compilation is not implemented yet",
    }
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "recompile_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"recompiled {count} Lua bytecode files to {args.out}")
    if failures:
        print(f"failed: {len(failures)}")
    return 0 if not failures else 1


def hksasm_rel_to_lua(rel: Path) -> Path:
    return rel.with_suffix(".lua") if rel.suffix.lower() == ".hksasm" else rel


def cmd_recompile_asm_dir(args: argparse.Namespace) -> int:
    count = 0
    failures = []
    for path in args.input.rglob("*.hksasm"):
        try:
            data = rebuild_from_hksasm(path)
            workspace = workspace_from_hksasm(path)
        except Exception as exc:  # noqa: BLE001 - report all files, keep going.
            failures.append({"path": str(path), "error": str(exc)})
            continue

        source_path = Path(str(workspace.get("source_path", path.with_suffix(".lua"))))
        try:
            rel = source_path.relative_to(args.source_root) if args.source_root else path.relative_to(args.input)
        except ValueError:
            rel = hksasm_rel_to_lua(path.relative_to(args.input))
        if rel.suffix.lower() == ".hksasm":
            rel = hksasm_rel_to_lua(rel)
        out_path = args.out / rel
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(data)
        count += 1

    manifest = {
        "format": "BO2HKSASM v1",
        "recompiled_asm": count,
        "failed": failures,
        "mode": "HKS assembly rebuild through editable workspace metadata",
    }
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "recompile_asm_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"rebuilt {count} Lua bytecode files from HKS assembly to {args.out}")
    if failures:
        print(f"failed: {len(failures)}")
    return 0 if not failures else 1


def cmd_recompile_json_dir(args: argparse.Namespace) -> int:
    count = 0
    failures = []
    for path in args.input.rglob("*.edit.json"):
        try:
            data = rebuild_from_workspace(path)
            workspace = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001 - report all files, keep going.
            failures.append({"path": str(path), "error": str(exc)})
            continue

        source_path = Path(str(workspace.get("source_path", path.with_suffix(".lua"))))
        try:
            rel = source_path.relative_to(args.source_root) if args.source_root else path.relative_to(args.input)
        except ValueError:
            rel = editable_json_rel_to_lua(path.relative_to(args.input))
        if rel.suffix.lower() == ".json":
            rel = editable_json_rel_to_lua(rel)
        out_path = args.out / rel
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(data)
        count += 1

    manifest = {
        "format": "bo2-xbox-lua-edit-v1",
        "recompiled_json": count,
        "failed": failures,
        "mode": "workspace JSON rebuild; supports same-length constants and decoded/raw instruction edits",
    }
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "recompile_json_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"rebuilt {count} Lua bytecode files from editable JSON to {args.out}")
    if failures:
        print(f"failed: {len(failures)}")
    return 0 if not failures else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("disasm", help="Disassemble a compiled BO2 Lua payload")
    p.add_argument("input", type=Path)
    p.add_argument("-o", "--out", type=Path)
    p.add_argument("--json", type=Path, help="Write structured parse JSON")
    p.set_defaults(func=cmd_disasm)

    p = sub.add_parser("decompile", help="Write pseudo-Lua with constants and instruction listing")
    p.add_argument("input", type=Path)
    p.add_argument("-o", "--out", type=Path, required=True)
    p.set_defaults(func=cmd_decompile)

    p = sub.add_parser("decompile-source", help="Write readable Lua pseudo-source")
    p.add_argument("input", type=Path)
    p.add_argument("-o", "--out", type=Path, required=True)
    p.set_defaults(func=cmd_decompile_source)

    p = sub.add_parser("decompile-json", help="Write an editable bytecode workspace JSON")
    p.add_argument("input", type=Path)
    p.add_argument("-o", "--out", type=Path, required=True)
    p.set_defaults(func=cmd_decompile_json)

    p = sub.add_parser("decompile-asm", help="Write human-editable HKS assembly")
    p.add_argument("input", type=Path)
    p.add_argument("-o", "--out", type=Path, required=True)
    p.set_defaults(func=cmd_decompile_asm)

    p = sub.add_parser("recompile", help="Rebuild from JSON/HKSASM, or losslessly re-emit raw bytecode")
    p.add_argument("input", type=Path)
    p.add_argument("-o", "--out", type=Path, required=True)
    p.set_defaults(func=cmd_recompile)

    p = sub.add_parser("recompile-asm", help="Rebuild Lua bytecode from HKS assembly")
    p.add_argument("input", type=Path)
    p.add_argument("-o", "--out", type=Path, required=True)
    p.set_defaults(func=cmd_recompile_asm)

    p = sub.add_parser("decompile-dir", help="Pseudo-decompile every compiled Lua payload in a folder")
    p.add_argument("input", type=Path)
    p.add_argument("-o", "--out", type=Path, required=True)
    p.set_defaults(func=cmd_decompile_dir)

    p = sub.add_parser("decompile-source-dir", help="Write readable Lua pseudo-source for every Lua payload")
    p.add_argument("input", type=Path)
    p.add_argument("-o", "--out", type=Path, required=True)
    p.set_defaults(func=cmd_decompile_source_dir)

    p = sub.add_parser("decompile-json-dir", help="Write editable bytecode workspace JSON for every Lua payload")
    p.add_argument("input", type=Path)
    p.add_argument("-o", "--out", type=Path, required=True)
    p.set_defaults(func=cmd_decompile_json_dir)

    p = sub.add_parser("decompile-asm-dir", help="Write HKS assembly for every Lua payload")
    p.add_argument("input", type=Path)
    p.add_argument("-o", "--out", type=Path, required=True)
    p.set_defaults(func=cmd_decompile_asm_dir)

    p = sub.add_parser("recompile-dir", help="Losslessly re-emit every compiled Lua payload in a folder")
    p.add_argument("input", type=Path)
    p.add_argument("-o", "--out", type=Path, required=True)
    p.set_defaults(func=cmd_recompile_dir)

    p = sub.add_parser("recompile-json-dir", help="Rebuild Lua bytecode files from editable workspace JSON")
    p.add_argument("input", type=Path)
    p.add_argument("-o", "--out", type=Path, required=True)
    p.add_argument(
        "--source-root",
        type=Path,
        help="Original ui_lua root used to preserve output paths from source_path metadata",
    )
    p.set_defaults(func=cmd_recompile_json_dir)

    p = sub.add_parser("recompile-asm-dir", help="Rebuild Lua bytecode files from HKS assembly")
    p.add_argument("input", type=Path)
    p.add_argument("-o", "--out", type=Path, required=True)
    p.add_argument(
        "--source-root",
        type=Path,
        help="Original ui_lua root used to preserve output paths from source_path metadata",
    )
    p.set_defaults(func=cmd_recompile_asm_dir)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
