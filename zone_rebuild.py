#!/usr/bin/env python3
"""Recompile edited scripts/Lua and splice them back into a decompressed T6 zone.

Round-trip design (verified against OpenAssetTools' generated T6 loaders and by
measuring real zones):

* ScriptParseTree (`.gsc`/`.csc`) and RawFile (`.lua`) share one stream layout::

      FFFFFFFF  <be32 len>  FFFFFFFF  "<asset path>\\0"  <buffer: len+1 bytes>

  i.e. a 12-byte struct ``{const char* name=-1; int len; byte* buffer=-1;}``
  followed inline by the name string and then ``len + 1`` buffer bytes.
* The zone stream has **no alignment padding** between assets (alignment is
  applied to destination memory pointers only), so a buffer can grow or shrink
  and the rest of the stream is simply shifted — no pointer relocation needed.
* The 40-byte zone prefix stores ``zone_size = filesize - 40`` at offset 0 and
  eight destination XBlock sizes at offset 8. Script/Lua buffers live in
  ``XFILE_BLOCK_VIRTUAL`` (index 5), so a net size change adjusts that block.

Splicing therefore only has to: write the new buffer, rewrite the inline ``len``
field (``= len(new_buffer) - 1``), copy everything else verbatim, and fix the two
size fields. An *identity* rebuild (replacing each buffer with its own bytes)
reproduces the zone byte-for-byte — the regression gate for this module.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import gsc_tool

ZONE_FILE = "zone_decompressed.dat"
MANIFEST_FILE = "zone_patch_manifest.json"
PREFIX_SIZE = 40
ZONE_SIZE_FIELD_OFFSET = 0
XFILE_BLOCK_VIRTUAL_INDEX = 5
VIRTUAL_BLOCK_SIZE_FIELD_OFFSET = 8 + XFILE_BLOCK_VIRTUAL_INDEX * 4
# Destination alignment of a script/rawfile buffer (byte32=32, char16=16). Used
# only as a conservative slack when growing the virtual block.
MAX_BUFFER_ALIGN = 32

_NAME_PATTERN = re.compile(rb"[\x20-\x7e]{3,}\.(?:gsc|csc|lua)", re.IGNORECASE)
_SCRIPT_MAGICS = (b"\x80GSC", b"\x80CSC")
_LUA_MAGIC = b"\x1bLua"


def _be_u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "big")


@dataclass
class ZoneRecord:
    kind: str  # 'gsc' | 'csc' | 'lua'
    name: str
    header_offset: int
    len_field_offset: int
    name_offset: int
    buffer_offset: int
    len_field_value: int

    @property
    def buffer_stream_len(self) -> int:
        return self.len_field_value + 1  # loader reads len + 1 bytes

    @property
    def buffer_end(self) -> int:
        return self.buffer_offset + self.buffer_stream_len


def read_record_at(zone: bytes, header_offset: int) -> ZoneRecord | None:
    """Validate and parse a single record at a known header offset."""
    if header_offset < 0 or header_offset + 12 > len(zone):
        return None
    if _be_u32(zone, header_offset) != 0xFFFFFFFF or _be_u32(zone, header_offset + 8) != 0xFFFFFFFF:
        return None
    length = _be_u32(zone, header_offset + 4)
    if length == 0 or length > 16 * 1024 * 1024:
        return None
    name_offset = header_offset + 12
    name_end = zone.find(b"\x00", name_offset, name_offset + 512)
    if name_end < 0:
        return None
    name = zone[name_offset:name_end].decode("ascii", "replace")
    buffer_offset = name_end + 1
    if buffer_offset + length + 1 > len(zone):
        return None
    magic = zone[buffer_offset : buffer_offset + 4]
    lowered = name.lower()
    if lowered.endswith((".gsc", ".csc")):
        if magic not in _SCRIPT_MAGICS:
            return None
        kind = "csc" if lowered.endswith(".csc") else "gsc"
    elif lowered.endswith(".lua"):
        if magic != _LUA_MAGIC:
            return None
        kind = "lua"
    else:
        return None
    return ZoneRecord(
        kind=kind,
        name=name,
        header_offset=header_offset,
        len_field_offset=header_offset + 4,
        name_offset=name_offset,
        buffer_offset=buffer_offset,
        len_field_value=length,
    )


def parse_records(zone: bytes) -> list[ZoneRecord]:
    """Locate every script/Lua record in a decompressed zone, in stream order."""
    records: list[ZoneRecord] = []
    for match in _NAME_PATTERN.finditer(zone):
        record = read_record_at(zone, match.start() - 12)
        if record is not None:
            records.append(record)
    records.sort(key=lambda r: r.buffer_offset)
    return records


def splice_zone(zone: bytes, replacements: dict[int, bytes]) -> tuple[bytes, dict[str, Any]]:
    """Return a new zone with buffers replaced by header_offset.

    ``replacements`` maps a record's ``header_offset`` to the complete new buffer
    bytes (the object the game loads; the ``len`` field is set to ``len(buf)-1``).
    """
    records = []
    for header_offset in replacements:
        record = read_record_at(zone, header_offset)
        if record is None:
            raise ValueError(f"no valid record at header offset 0x{header_offset:X}")
        records.append(record)
    records.sort(key=lambda r: r.buffer_offset)

    out = bytearray()
    cursor = 0
    total_delta = 0
    for record in records:
        new_buffer = replacements[record.header_offset]
        # Copy everything up to this buffer verbatim, then patch the inline len
        # field (which lives inside that copied span at len_field_offset).
        span = bytearray(zone[cursor : record.buffer_offset])
        struct.pack_into(">I", span, record.len_field_offset - cursor, len(new_buffer) - 1)
        out += span
        out += new_buffer
        cursor = record.buffer_end
        total_delta += len(new_buffer) - record.buffer_stream_len
    out += zone[cursor:]

    # Fix the zone-size prefix field (post-prefix stream length).
    struct.pack_into(">I", out, ZONE_SIZE_FIELD_OFFSET, len(out) - PREFIX_SIZE)
    # Conservatively adjust the virtual destination block. Over-allocation is
    # safe; under-allocation would overflow into the next block, so a per-record
    # alignment slack is added when growing.
    if total_delta != 0:
        old_virtual = _be_u32(out, VIRTUAL_BLOCK_SIZE_FIELD_OFFSET)
        slack = MAX_BUFFER_ALIGN * len(records) if total_delta > 0 else 0
        new_virtual = max(0, old_virtual + total_delta + slack)
        struct.pack_into(">I", out, VIRTUAL_BLOCK_SIZE_FIELD_OFFSET, new_virtual & 0xFFFFFFFF)

    info = {
        "records_replaced": len(records),
        "byte_delta": total_delta,
        "new_zone_size": len(out),
        "new_zone_size_field": len(out) - PREFIX_SIZE,
    }
    return bytes(out), info


def identity_rebuild(zone: bytes) -> bytes:
    """Rebuild replacing every buffer with its own bytes (regression gate)."""
    records = parse_records(zone)
    replacements = {
        record.header_offset: zone[record.buffer_offset : record.buffer_end] for record in records
    }
    rebuilt, _ = splice_zone(zone, replacements)
    return rebuilt


def verify_identity(zone: bytes) -> bool:
    """True if an identity rebuild reproduces the zone byte-for-byte."""
    return identity_rebuild(zone) == zone


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def recompile_and_rebuild(
    folder: Path,
    log: Callable[[str], None] | None = None,
    force: bool = False,
) -> dict[str, Any]:
    """Recompile changed sources under ``folder`` and rewrite ``zone_decompressed.dat``.

    Only assets whose source file changed since unpack (``source_sha256`` in the
    manifest) are recompiled; everything else stays byte-identical. The original
    zone is backed up to ``zone_decompressed.dat.orig`` on the first rebuild.
    Returns a summary dict (``changed``, ``errors``, ``byte_delta`` ...).
    """

    def _log(message: str) -> None:
        if log:
            log(message)

    folder = Path(folder)
    zone_path = folder / ZONE_FILE
    manifest_path = folder / MANIFEST_FILE
    if not zone_path.exists():
        raise FileNotFoundError(f"{ZONE_FILE} not found in {folder}")
    if not manifest_path.exists():
        raise FileNotFoundError(
            f"{MANIFEST_FILE} not found in {folder}; re-unpack with the current tool to generate it."
        )
    zone = zone_path.read_bytes()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    replacements: dict[int, bytes] = {}
    changed: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    skipped_unchanged = 0
    gsc_exe = gsc_tool.find_gsc_tool()

    for asset in manifest.get("assets", []):
        kind = asset.get("kind")
        recompiler = asset.get("recompiler")
        header_offset = asset.get("header_offset")
        source_rel = asset.get("source_rel")
        source_root = asset.get("source_root")
        if recompiler is None or header_offset is None or not source_rel or not source_root:
            continue
        source_path = folder / source_root / source_rel
        if not source_path.exists():
            continue
        current_source = source_path.read_bytes()
        baseline = asset.get("source_sha256")
        if not force and baseline and _sha256(current_source) == baseline:
            skipped_unchanged += 1
            continue

        if recompiler == "gsc-tool":
            if gsc_exe is None:
                errors.append({"name": asset.get("name"), "error": "gsc-tool not found"})
                continue
            result = gsc_tool.compile(source_path, is_client=(kind == "csc"), tool=gsc_exe)
            if not result.get("ok"):
                errors.append({"name": asset.get("name"), "error": result.get("log", "compile failed")})
                continue
            compiled_object = result["bytecode"]
        elif recompiler == "lua_tool":
            try:
                import lua_tool

                compiled_object = lua_tool.compile_source_to_bytecode(current_source)
            except Exception as exc:  # noqa: BLE001 - report, don't abort the batch
                errors.append({"name": asset.get("name"), "error": f"lua compile failed: {exc}"})
                continue
        else:
            continue

        # ScriptParseTree/RawFile buffers are stored as the compiled object
        # followed by a single null terminator; the loader reads len + 1 bytes,
        # so the new buffer is object + 0x00 and the len field becomes |object|.
        new_buffer = compiled_object + b"\x00"
        replacements[header_offset] = new_buffer
        changed.append(
            {
                "name": asset.get("name"),
                "kind": kind,
                "old_buffer_len": asset.get("buffer_stream_len"),
                "new_buffer_len": len(new_buffer),
            }
        )
        _log(f"recompiled {asset.get('name')} ({kind}): {len(new_buffer)} bytes (obj {len(compiled_object)}+1)")

    if not replacements:
        return {
            "status": "ok",
            "changed": 0,
            "skipped_unchanged": skipped_unchanged,
            "errors": errors,
            "rebuilt": False,
            "note": "No edited sources detected; zone unchanged.",
        }

    rebuilt_zone, info = splice_zone(zone, replacements)

    backup = folder / (ZONE_FILE + ".orig")
    if not backup.exists():
        backup.write_bytes(zone)
    zone_path.write_bytes(rebuilt_zone)
    _log(
        f"rebuilt {ZONE_FILE}: {len(changed)} asset(s) changed, "
        f"byte delta {info['byte_delta']:+d}, new size {info['new_zone_size']}"
    )

    return {
        "status": "ok",
        "changed": len(changed),
        "skipped_unchanged": skipped_unchanged,
        "errors": errors,
        "rebuilt": True,
        "byte_delta": info["byte_delta"],
        "new_zone_size": info["new_zone_size"],
        "backup": str(backup),
        "changed_assets": changed,
    }


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Recompile edited scripts/Lua and rebuild a decompressed zone")
    parser.add_argument("folder", type=Path, help="Unpacked FastFile folder (contains zone_decompressed.dat)")
    parser.add_argument("--force", action="store_true", help="Recompile all sources, not just changed ones")
    parser.add_argument("--verify-identity", action="store_true", help="Only check the identity-rebuild regression gate")
    args = parser.parse_args(argv)

    if args.verify_identity:
        zone = (args.folder / ZONE_FILE).read_bytes()
        ok = verify_identity(zone)
        print(f"identity rebuild byte-identical: {ok}")
        return 0 if ok else 1

    result = recompile_and_rebuild(args.folder, log=lambda m: print(m), force=args.force)
    print(json.dumps({k: v for k, v in result.items() if k != "changed_assets"}, indent=2))
    return 0 if result.get("status") == "ok" and not result.get("errors") else 1


if __name__ == "__main__":
    raise SystemExit(main())
