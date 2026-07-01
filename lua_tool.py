#!/usr/bin/env python3
"""Parser/disassembler/repacker for BO2 Xbox 360 Treyarch Lua UI bytecode.

This is not a full source decompiler yet. It provides the foundation we need:

- parse the observed Treyarch Lua header/type table
- parse function prototypes, instructions, constants, and nested prototypes
- emit a readable disassembly/pseudo listing
- recompile by copying bytecode chunks losslessly, with optional manifest checks

The bytecode is compiled Lua 5.1-ish data with Treyarch/Xbox additions. Until
the opcode map and control-flow rules are fully proven, "decompile" here means
structured disassembly plus constant/function inventory, not editable Lua source.
"""

from __future__ import annotations

import argparse
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

LUA51_OPCODES = [
    "MOVE",
    "LOADK",
    "LOADBOOL",
    "LOADNIL",
    "GETUPVAL",
    "GETGLOBAL",
    "GETTABLE",
    "SETGLOBAL",
    "SETUPVAL",
    "SETTABLE",
    "NEWTABLE",
    "SELF",
    "ADD",
    "SUB",
    "MUL",
    "DIV",
    "MOD",
    "POW",
    "UNM",
    "NOT",
    "LEN",
    "CONCAT",
    "JMP",
    "EQ",
    "LT",
    "LE",
    "TEST",
    "TESTSET",
    "CALL",
    "TAILCALL",
    "RETURN",
    "FORLOOP",
    "FORPREP",
    "TFORLOOP",
    "SETLIST",
    "CLOSE",
    "CLOSURE",
    "VARARG",
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
    raw: int
    opcode: int
    opname: str
    a: int
    b: int
    c: int
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


def parse_instruction(raw: int, index: int, offset: int) -> Instruction:
    # Lua 5.1 instruction field layout. Opcode names are provisional for this
    # Treyarch variant but useful for orientation while we verify differences.
    opcode = raw & 0x3F
    a = (raw >> 6) & 0xFF
    c = (raw >> 14) & 0x1FF
    b = (raw >> 23) & 0x1FF
    bx = (raw >> 14) & 0x3FFFF
    sbx = bx - 131071
    opname = LUA51_OPCODES[opcode] if opcode < len(LUA51_OPCODES) else f"OP_{opcode:02d}"
    return Instruction(index, offset, raw, opcode, opname, a, b, c, bx, sbx)


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
        raw = u32(data, offset)
        offset += 4
        instructions.append(parse_instruction(raw, i, inst_offset))

    constant_count = u32(data, offset)
    offset += 4
    constants = []
    for i in range(constant_count):
        constant, offset = parse_constant(data, offset, i)
        constants.append(constant)

    child_count = u32(data, offset)
    offset += 4
    children = []
    child_parse_errors = []
    for i in range(child_count):
        child_offset = offset
        try:
            child, offset = parse_proto(data, offset, i)
            children.append(child)
        except ParseError as exc:
            child_parse_errors.append({"index": i, "offset": child_offset, "error": str(exc)})
            break

    debug: dict[str, Any] = {}
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
        "children": [proto_to_dict(child) for child in proto.children],
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
            f"{indent}  [{inst.index:04d}] 0x{inst.offset:06X} {inst.raw:08X} "
            f"{inst.opname:<10} A={inst.a:03d} B={inst.b:03d} C={inst.c:03d} Bx={inst.bx:06d} sBx={inst.sbx:+d}"
        )
    for child in proto.children:
        lines.extend(disassemble_proto(child, indent + "  "))
    return lines


def pseudo_decompile(proto: Proto) -> str:
    lines = [
        "-- BO2 Xbox/Treyarch compiled Lua bytecode",
        "-- This is a structural pseudo-decompile, not verified source.",
        "-- Constants and provisional Lua 5.1 opcode names are shown for reverse engineering.",
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


def cmd_recompile(args: argparse.Namespace) -> int:
    # Lossless recompile mode for now: copy a compiled bytecode chunk back out.
    # This gives us a stable repack target before editable source compilation is
    # implemented.
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

    p = sub.add_parser("recompile", help="Losslessly re-emit a compiled BO2 Lua payload")
    p.add_argument("input", type=Path)
    p.add_argument("-o", "--out", type=Path, required=True)
    p.set_defaults(func=cmd_recompile)

    p = sub.add_parser("decompile-dir", help="Pseudo-decompile every compiled Lua payload in a folder")
    p.add_argument("input", type=Path)
    p.add_argument("-o", "--out", type=Path, required=True)
    p.set_defaults(func=cmd_decompile_dir)

    p = sub.add_parser("recompile-dir", help="Losslessly re-emit every compiled Lua payload in a folder")
    p.add_argument("input", type=Path)
    p.add_argument("-o", "--out", type=Path, required=True)
    p.set_defaults(func=cmd_recompile_dir)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
