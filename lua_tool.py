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
import hashlib
import json
import math
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
    max_stack = data[offset + 0x14]
    instruction_count = data[offset + 0x18]
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
            upvalue_count=0,
            param_count=0,
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
                "note": "edit raw_hex only; opcode fields are informational in this format",
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
        raw_hex = str(edited_inst.get("raw_hex", inst.raw.hex())).replace(" ", "")
        try:
            raw = bytes.fromhex(raw_hex)
        except ValueError as exc:
            raise ParseError(f"instruction {inst.index} raw_hex is invalid") from exc
        if len(raw) != 4:
            raise ParseError(f"instruction {inst.index} raw_hex must encode exactly 4 bytes")
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


def cmd_decompile_json(args: argparse.Namespace) -> int:
    workspace = make_editable_workspace(args.input)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(workspace, indent=2) + "\n", encoding="utf-8")
    return 0


def cmd_recompile(args: argparse.Namespace) -> int:
    if args.input.suffix.lower() == ".json":
        data = rebuild_from_workspace(args.input)
    else:
        # Lossless recompile mode for raw bytecode: copy a compiled chunk back
        # out after validation. Editable source compilation is still a separate
        # milestone; JSON workspace rebuild is handled above.
        data = args.input.read_bytes()
        parse_chunk(args.input)
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
        "note": "Edit same-length constants or instruction raw_hex, then rebuild with recompile-json-dir.",
    }
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "decompile_json_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {count} editable Lua bytecode JSON files to {args.out}")
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
        "mode": "workspace JSON rebuild; supports same-length constants and raw instruction-byte edits",
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

    p = sub.add_parser("decompile-json", help="Write an editable bytecode workspace JSON")
    p.add_argument("input", type=Path)
    p.add_argument("-o", "--out", type=Path, required=True)
    p.set_defaults(func=cmd_decompile_json)

    p = sub.add_parser("recompile", help="Rebuild from workspace JSON, or losslessly re-emit raw bytecode")
    p.add_argument("input", type=Path)
    p.add_argument("-o", "--out", type=Path, required=True)
    p.set_defaults(func=cmd_recompile)

    p = sub.add_parser("decompile-dir", help="Pseudo-decompile every compiled Lua payload in a folder")
    p.add_argument("input", type=Path)
    p.add_argument("-o", "--out", type=Path, required=True)
    p.set_defaults(func=cmd_decompile_dir)

    p = sub.add_parser("decompile-json-dir", help="Write editable bytecode workspace JSON for every Lua payload")
    p.add_argument("input", type=Path)
    p.add_argument("-o", "--out", type=Path, required=True)
    p.set_defaults(func=cmd_decompile_json_dir)

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

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
