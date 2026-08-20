#!/usr/bin/env python3
"""
Xbox 360 Black Ops 2 fastfile scanner/unpacker scaffold.

This is intentionally a cautious reverse-engineering tool. It parses the clear
header fields that are currently understood, records unknowns, and only extracts
data when the bytes can be justified by a local parse/probe. Encrypted or
otherwise unresolved payload is dumped as raw binary when --dump-unknown is used.
"""

from __future__ import annotations

import argparse
import binascii
import collections
import hashlib
import json
import math
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import gsc_tool


# Public notes for BO2 fastfiles identify this as the Xbox 360 Salsa20 key.
# The nonce/counter/framing for the encrypted zone stream is not confirmed here,
# so the scanner only uses it for opt-in probes and does not claim decryption.
BO2_X360_SALSA20_KEY = bytes(
    [
        0x0E,
        0x50,
        0xF4,
        0x9F,
        0x41,
        0x23,
        0x17,
        0x09,
        0x60,
        0x38,
        0x66,
        0x56,
        0x22,
        0xDD,
        0x09,
        0x13,
        0x32,
        0xA2,
        0x09,
        0xBA,
        0x0A,
        0x05,
        0xA0,
        0x0E,
        0x13,
        0x77,
        0xCE,
        0xDB,
        0x0A,
        0x3C,
        0xB1,
        0xD3,
    ]
)

KNOWN_MAGIC = {b"TAff0100", b"TAffx100"}
MAGIC_COMPRESSION = {
    b"TAff0100": "deflate",
    b"TAffx100": "lzx",
}
SCRIPT_DIR = Path(__file__).resolve().parent
AUTH_HEADER_OFFSET = 0x0C
AUTH_HEADER_SIZE = 0x2C
SIGNATURE_OFFSET = 0x38
SIGNATURE_SIZE = 0x100
PAYLOAD_OFFSET = SIGNATURE_OFFSET + SIGNATURE_SIZE
XCHUNK_SIZE = 0x8000
# T6 Xbox 360 chunk-stream layout constants, verified against original TAffx100
# files in this workspace:
#  - the first decrypted XMem chunk is the 0x28-byte XFile header;
#  - following decrypted XMem chunks are at most XCHUNK_MAX_WRITE_SIZE bytes;
#  - the compressed+encrypted chunk must stay < XCHUNK_SIZE (the game asserts
#    `size < 32*1024` in db_file_load.cpp);
#  - the compressed stream is laid out in VANILLA_BUFFER_SIZE windows and a
#    4-byte chunk-size header is never allowed to straddle a window boundary
#    (measured from the start of the file); zero padding fills the gap;
#  - the file ends with a zero suffix (>= MIN, aligned to ALIGN) that the reader
#    relies on and treats as EOF.
XCHUNK_MAX_WRITE_SIZE = XCHUNK_SIZE - 0x40  # 0x7FC0
XFILE_HEADER_CHUNK_SIZE = 0x28
VANILLA_BUFFER_SIZE = 0x80000
FILE_SUFFIX_ZERO_MIN_SIZE = 0x40
FILE_SUFFIX_ZERO_ALIGN = 0x40
XCHUNK_STREAM_COUNT = 4
XCHUNK_HASH_BLOCKS = 200
SHA1_SIZE = 20
# T6 XFileBlock index for XFILE_BLOCK_VIRTUAL (per OpenAssetTools T6_Assets.h).
# ScriptParseTree/RawFile name+buffer allocations live in this destination block,
# so a recompile that changes buffer sizes must adjust this block's size field.
XFILE_BLOCK_VIRTUAL_INDEX = 5

# Windows: run child processes (the LZX helper) without flashing a console
# window. Decompressing a large fastfile spawns the helper once per chunk
# (hundreds of times), which otherwise causes a storm of white console windows
# in the packaged GUI .exe.
CREATE_NO_WINDOW = 0x08000000


def _no_window_run_kwargs() -> dict[str, Any]:
    if os.name != "nt":
        return {}
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = 0  # SW_HIDE
    return {"creationflags": CREATE_NO_WINDOW, "startupinfo": startupinfo}


def _xmem_compress_helper_path() -> Path:
    return SCRIPT_DIR / "_tools" / "xmem_compress.exe"


T6_XBLOCK_NAMES = [
    "temp",
    "runtime_virtual",
    "runtime_physical",
    "delay_virtual",
    "delay_physical",
    "virtual",
    "physical",
    "streamer_reserve",
]
T6_ASSET_TYPE_NAMES = [
    "XModelPieces",
    "PhysPreset",
    "PhysConstraints",
    "DestructibleDef",
    "XAnimParts",
    "XModel",
    "Material",
    "MaterialTechniqueSet",
    "GfxImage",
    "SndBank",
    "SndPatch",
    "clipMap_t",
    "clipMapPvs",
    "ComWorld",
    "GameWorldSp",
    "GameWorldMp",
    "MapEnts",
    "GfxWorld",
    "GfxLightDef",
    "UiMap",
    "Font_s",
    "FontIcon",
    "MenuList",
    "menuDef_t",
    "LocalizeEntry",
    "WeaponVariantDef",
    "WeaponDef",
    "WeaponVariant",
    "WeaponFull",
    "WeaponAttachment",
    "WeaponAttachmentUnique",
    "WeaponCamo",
    "SndDriverGlobals",
    "FxEffectDef",
    "FxImpactTable",
    "AiType",
    "MpType",
    "MpBody",
    "MpHead",
    "Character",
    "XModelAlias",
    "RawFile",
    "StringTable",
    "LeaderboardDef",
    "XGlobals",
    "ddlRoot_t",
    "Glasses",
    "EmblemSet",
    "ScriptParseTree",
    "KeyValuePairs",
    "VehicleDef",
    "MemoryBlock",
    "AddonMapEnts",
    "TracerDef",
    "SkinnedVertsDef",
    "Qdb",
    "Slug",
    "FootstepTableDef",
    "FootstepFXTableDef",
    "ZBarrierDef",
]


def be_u32(data: bytes, offset: int) -> int:
    return struct.unpack_from(">I", data, offset)[0]


def le_u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def printable_ascii(data: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)


def c_string(data: bytes) -> str:
    return data.split(b"\x00", 1)[0].decode("ascii", errors="replace")


def is_readable_ascii_text(value: str) -> bool:
    return bool(value) and all((ch == "\t") or (32 <= ord(ch) < 127) for ch in value)


def is_plausible_asset_name(value: str) -> bool:
    if len(value) < 3:
        return False
    if not any(ch.isalnum() for ch in value):
        return False
    return all(ch.isalnum() or ch in "._-/\\$@# +[]" for ch in value)


def resolve_direct_string_pointer(data: bytes, ptr: int) -> tuple[str | None, int | None]:
    """Resolve an observed Xbox string/name pointer that appears to be a raw offset.

    Some T6 zone pointers are packed block offsets, but several name fields in
    Xbox zones point directly to strings in the decompressed stream. Prefer the
    direct offset, then try ptr - 1 because OAT offset pointers are often +1
    encoded. Returning None means the bytes do not look like a readable string.
    """

    for candidate in (ptr, ptr - 1):
        if 0 <= candidate < len(data):
            value, _ = read_zone_cstring(data, candidate)
            if is_readable_ascii_text(value):
                return value, candidate
    return None, None


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = collections.Counter(data)
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def safe_rel_path(name: str) -> Path:
    parts = []
    for part in re.split(r"[\\/]+", name):
        cleaned = re.sub(r"[^A-Za-z0-9._ -]", "_", part).strip()
        if cleaned and cleaned not in {".", ".."}:
            parts.append(cleaned)
    return Path(*parts) if parts else Path("unnamed.bin")


def hex_sample(data: bytes, offset: int, size: int = 64) -> dict[str, Any]:
    chunk = data[offset : offset + size]
    return {
        "offset": offset,
        "size": len(chunk),
        "hex": chunk.hex(),
        "ascii": printable_ascii(chunk),
    }


def find_ascii_strings(data: bytes, base_offset: int, min_len: int = 5, limit: int = 200) -> list[dict[str, Any]]:
    pattern = rb"[\x20-\x7e]{" + str(min_len).encode("ascii") + rb",}"
    hits = []
    for match in re.finditer(pattern, data):
        hits.append({"offset": base_offset + match.start(), "value": match.group().decode("ascii", "replace")})
        if len(hits) >= limit:
            break
    return hits


def zlib_probe(data: bytes, base_offset: int, max_hits: int = 64) -> list[dict[str, Any]]:
    """Find possible zlib streams without treating random encrypted bytes as proof."""
    hits = []
    for i in range(max(0, len(data) - 1)):
        cmf, flg = data[i], data[i + 1]
        if cmf != 0x78:
            continue
        if ((cmf << 8) + flg) % 31 != 0:
            continue
        if flg not in {0x01, 0x5E, 0x9C, 0xDA}:
            continue
        entry: dict[str, Any] = {"offset": base_offset + i, "header": f"{cmf:02x}{flg:02x}"}
        try:
            obj = zlib.decompressobj()
            out = obj.decompress(data[i:], 1024 * 1024)
            out += obj.flush()
            entry.update(
                {
                    "status": "decompressed",
                    "output_prefix_size": len(out),
                    "unused_input_offset": None
                    if not obj.unused_data
                    else base_offset + len(data) - len(obj.unused_data),
                    "output_sha256_prefix": hashlib.sha256(out).hexdigest(),
                    "output_sample_hex": out[:32].hex(),
                    "output_sample_ascii": printable_ascii(out[:64]),
                }
            )
        except zlib.error as exc:
            entry.update({"status": "candidate_only", "error": str(exc)})
        hits.append(entry)
        if len(hits) >= max_hits:
            break
    return hits


def _rotl32(value: int, bits: int) -> int:
    return ((value << bits) & 0xFFFFFFFF) | (value >> (32 - bits))


def _quarterround(y0: int, y1: int, y2: int, y3: int) -> tuple[int, int, int, int]:
    y1 ^= _rotl32((y0 + y3) & 0xFFFFFFFF, 7)
    y2 ^= _rotl32((y1 + y0) & 0xFFFFFFFF, 9)
    y3 ^= _rotl32((y2 + y1) & 0xFFFFFFFF, 13)
    y0 ^= _rotl32((y3 + y2) & 0xFFFFFFFF, 18)
    return y0, y1, y2, y3


def salsa20_block(key: bytes, nonce: bytes, counter: int) -> bytes:
    if len(key) != 32:
        raise ValueError("Salsa20 key must be 32 bytes")
    if len(nonce) != 8:
        raise ValueError("Salsa20 nonce must be 8 bytes")

    const = b"expand 32-byte k"
    le = lambda b: int.from_bytes(b, "little")
    state = [
        le(const[0:4]),
        le(key[0:4]),
        le(key[4:8]),
        le(key[8:12]),
        le(key[12:16]),
        le(const[4:8]),
        le(nonce[0:4]),
        le(nonce[4:8]),
        counter & 0xFFFFFFFF,
        (counter >> 32) & 0xFFFFFFFF,
        le(const[8:12]),
        le(key[16:20]),
        le(key[20:24]),
        le(key[24:28]),
        le(key[28:32]),
        le(const[12:16]),
    ]
    x = state[:]
    for _ in range(10):
        x[0], x[4], x[8], x[12] = _quarterround(x[0], x[4], x[8], x[12])
        x[5], x[9], x[13], x[1] = _quarterround(x[5], x[9], x[13], x[1])
        x[10], x[14], x[2], x[6] = _quarterround(x[10], x[14], x[2], x[6])
        x[15], x[3], x[7], x[11] = _quarterround(x[15], x[3], x[7], x[11])
        x[0], x[1], x[2], x[3] = _quarterround(x[0], x[1], x[2], x[3])
        x[5], x[6], x[7], x[4] = _quarterround(x[5], x[6], x[7], x[4])
        x[10], x[11], x[8], x[9] = _quarterround(x[10], x[11], x[8], x[9])
        x[15], x[12], x[13], x[14] = _quarterround(x[15], x[12], x[13], x[14])
    return b"".join(((x[i] + state[i]) & 0xFFFFFFFF).to_bytes(4, "little") for i in range(16))


def salsa20_xor(data: bytes, key: bytes, nonce: bytes, counter: int = 0) -> bytes:
    out = bytearray()
    for offset in range(0, len(data), 64):
        stream = salsa20_block(key, nonce, counter + (offset // 64))
        out.extend(a ^ b for a, b in zip(data[offset : offset + 64], stream))
    return bytes(out)


def salsa20_probe(payload: bytes) -> list[dict[str, Any]]:
    """Try obvious nonce guesses only. A failed probe does not disprove Salsa20."""
    guesses = [
        ("zero", b"\x00" * 8),
        ("payload_first8", payload[:8]),
    ]
    results = []
    for name, nonce in guesses:
        decrypted = salsa20_xor(payload[:4096], BO2_X360_SALSA20_KEY, nonce)
        results.append(
            {
                "nonce_guess": name,
                "nonce_hex": nonce.hex(),
                "decrypted_entropy_4k": entropy(decrypted),
                "decrypted_sample": hex_sample(decrypted, 0, 64),
                "zlib_candidates_after_decrypt": zlib_probe(decrypted, 0, max_hits=8),
                "ascii_strings_after_decrypt": find_ascii_strings(decrypted, 0, min_len=6, limit=20),
                "confidence": "low",
            }
        )
    return results


class OatSalsa20ChunkDecryptor:
    """OAT-compatible BO2/T6 xchunk Salsa20 IV adaptation.

    OpenAssetTools seeds 200 hash blocks per stream from the fastfile name,
    uses the first 8 bytes of the current stream hash block as the Salsa20 IV,
    decrypts the chunk, hashes the decrypted chunk with SHA-1, advances the
    stream block index, and XORs the next hash block with that SHA-1 digest.
    """

    def __init__(self, zone_name: str, stream_count: int = XCHUNK_STREAM_COUNT):
        if not zone_name:
            raise ValueError("zone_name is required for OAT-compatible Salsa20 IV setup")
        self.zone_name = zone_name[:31]
        self.stream_count = stream_count
        self.block_hashes = bytearray(XCHUNK_HASH_BLOCKS * stream_count * SHA1_SIZE)
        self.indices = [0] * stream_count
        name_bytes = self.zone_name.encode("ascii", "replace")
        name_offset = 0
        for offset in range(0, len(self.block_hashes), 4):
            self.block_hashes[offset : offset + 4] = bytes([name_bytes[name_offset]]) * 4
            name_offset = (name_offset + 1) % len(name_bytes)

    def _hash_block_offset(self, stream_number: int) -> int:
        return (self.indices[stream_number] * self.stream_count * SHA1_SIZE) + (stream_number * SHA1_SIZE)

    def decrypt(self, stream_number: int, encrypted: bytes) -> tuple[bytes, bytes, bytes]:
        block_offset = self._hash_block_offset(stream_number)
        current_block = bytes(self.block_hashes[block_offset : block_offset + SHA1_SIZE])
        iv = current_block[:8]
        decrypted = salsa20_xor(encrypted, BO2_X360_SALSA20_KEY, iv)
        digest = hashlib.sha1(decrypted).digest()
        self.indices[stream_number] = (self.indices[stream_number] + 1) % XCHUNK_HASH_BLOCKS
        next_offset = self._hash_block_offset(stream_number)
        for i, value in enumerate(digest):
            self.block_hashes[next_offset + i] ^= value
        return decrypted, iv, digest

    def encrypt(self, stream_number: int, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
        """Inverse of decrypt for repacking.

        Salsa20 is a stream cipher (XOR), so encryption uses the same keystream.
        The IV chain hashes the *decrypted* (plaintext) chunk, so on the encrypt
        side we must hash the plaintext input (not the ciphertext output) to
        reproduce the exact block-hash chain the game's loader will regenerate.
        """
        block_offset = self._hash_block_offset(stream_number)
        current_block = bytes(self.block_hashes[block_offset : block_offset + SHA1_SIZE])
        iv = current_block[:8]
        ciphertext = salsa20_xor(plaintext, BO2_X360_SALSA20_KEY, iv)
        digest = hashlib.sha1(plaintext).digest()
        self.indices[stream_number] = (self.indices[stream_number] + 1) % XCHUNK_HASH_BLOCKS
        next_offset = self._hash_block_offset(stream_number)
        for i, value in enumerate(digest):
            self.block_hashes[next_offset + i] ^= value
        return ciphertext, iv, digest


def parse_xmem_lzx_headers(data: bytes, limit: int = 32) -> dict[str, Any]:
    """Parse only the XMem/LZX sub-block headers, not the compressed payload.

    OAT's XMemDecompress treats a leading 0xFF as a short-output block:
    FF dst_hi dst_lo src_hi src_lo [src bytes] [5-byte suffix].
    Otherwise the first two bytes are srcSize and dstSize is 0x8000.
    """
    blocks = []
    offset = 0
    valid = True
    error = None
    while offset < len(data) and len(blocks) < limit:
        start = offset
        high = data[offset]
        offset += 1
        suffix_size = 0
        if high == 0xFF:
            if offset + 4 > len(data):
                valid = False
                error = "not enough bytes for short-output XMem header"
                break
            dst_size = (data[offset] << 8) | data[offset + 1]
            src_size = (data[offset + 2] << 8) | data[offset + 3]
            offset += 4
            suffix_size = 5
        else:
            if offset >= len(data):
                valid = False
                error = "not enough bytes for normal XMem header"
                break
            dst_size = XCHUNK_SIZE
            src_size = (high << 8) | data[offset]
            offset += 1
        if src_size == 0 or dst_size == 0:
            valid = False
            error = f"zero src/dst size in XMem block at offset {start}"
            break
        if offset + src_size + suffix_size > len(data):
            valid = False
            error = f"XMem block at offset {start} extends past decrypted chunk"
            break
        blocks.append(
            {
                "offset": start,
                "header_size": offset - start,
                "src_size": src_size,
                "dst_size": dst_size,
                "suffix_size": suffix_size,
                "compressed_data_offset": offset,
            }
        )
        offset += src_size + suffix_size
    return {
        "valid_headers": valid and offset == len(data),
        "parsed_prefix_complete": valid,
        "parsed_bytes": offset,
        "block_count_reported": len(blocks),
        "blocks": blocks,
        "error": error,
    }


def parse_decompressed_zone_prefix(data: bytes) -> dict[str, Any]:
    if len(data) < 40:
        return {"status": "too_short", "size": len(data)}
    zone_size = be_u32(data, 0)
    external_size = be_u32(data, 4)
    block_sizes = []
    for i, name in enumerate(T6_XBLOCK_NAMES):
        offset = 8 + i * 4
        block_sizes.append({"index": i, "name": name, "size": be_u32(data, offset)})
    return {
        "status": "parsed",
        "byte_order": "big",
        "zone_size": zone_size,
        "external_size": external_size,
        "xblock_sizes": block_sizes,
        "xblock_total_size": sum(block["size"] for block in block_sizes),
        "content_offset": 40,
    }


def pointer_kind(value: int) -> str:
    if value == 0:
        return "null"
    if value == 0xFFFFFFFF:
        return "following"
    if value == 0xFFFFFFFE:
        return "insert"
    return "offset"


def read_zone_cstring(data: bytes, offset: int) -> tuple[str, int]:
    if offset >= len(data):
        raise ValueError(f"string offset 0x{offset:X} is outside decompressed zone")
    end = data.find(b"\x00", offset)
    if end < 0:
        raise ValueError(f"unterminated string at decompressed offset 0x{offset:X}")
    return data[offset:end].decode("ascii", "replace"), end + 1


def parse_following_xstring_list(data: bytes, offset: int, count: int) -> tuple[dict[str, Any], int]:
    if count < 0 or count > 1_000_000:
        raise ValueError(f"implausible XString count: {count}")
    table_size = count * 4
    if offset + table_size > len(data):
        raise ValueError("XString pointer table extends past decompressed zone")

    pointers = [be_u32(data, offset + i * 4) for i in range(count)]
    current = offset + table_size
    strings = []
    non_following = []
    for index, ptr in enumerate(pointers):
        kind = pointer_kind(ptr)
        if kind == "following":
            value, current = read_zone_cstring(data, current)
            strings.append({"index": index, "offset": current - len(value) - 1, "value": value})
        elif kind == "null":
            strings.append({"index": index, "offset": None, "value": None})
        else:
            non_following.append({"index": index, "pointer": f"0x{ptr:08X}", "kind": kind})

    return {
        "count": count,
        "pointer_table_offset": offset,
        "pointer_table_size": table_size,
        "strings": strings,
        "non_following_or_offset_pointers": non_following,
    }, current


def parse_top_level_t6_zone(data: bytes) -> dict[str, Any]:
    prefix = parse_decompressed_zone_prefix(data[:64])
    if prefix.get("status") != "parsed":
        return {"status": "no_zone_prefix", "prefix": prefix}

    offset = prefix["content_offset"]
    if offset + 24 > len(data):
        return {"status": "too_short_for_xassetlist", "content_offset": offset}

    script_count = be_u32(data, offset)
    script_ptr = be_u32(data, offset + 4)
    depend_count = be_u32(data, offset + 8)
    depend_ptr = be_u32(data, offset + 12)
    asset_count = be_u32(data, offset + 16)
    asset_ptr = be_u32(data, offset + 20)
    current = offset + 24
    result: dict[str, Any] = {
        "status": "partially_parsed",
        "xassetlist_offset": offset,
        "script_string_count": script_count,
        "script_string_pointer": f"0x{script_ptr:08X}",
        "script_string_pointer_kind": pointer_kind(script_ptr),
        "depend_count": depend_count,
        "depends_pointer": f"0x{depend_ptr:08X}",
        "depends_pointer_kind": pointer_kind(depend_ptr),
        "asset_count": asset_count,
        "assets_pointer": f"0x{asset_ptr:08X}",
        "assets_pointer_kind": pointer_kind(asset_ptr),
        "assumptions": [
            "This parser follows the first-level T6 XAssetList layout only.",
            "Following pointers (-1) are read linearly from the decompressed stream.",
            "Individual asset bodies are not parsed here.",
        ],
    }

    try:
        if script_ptr:
            if pointer_kind(script_ptr) == "following":
                script_list, current = parse_following_xstring_list(data, current, script_count)
                result["script_strings"] = script_list
            else:
                result["script_strings"] = {"status": "not_following_pointer", "count": script_count}

        if depend_ptr:
            if pointer_kind(depend_ptr) == "following":
                depends, current = parse_following_xstring_list(data, current, depend_count)
                result["depends"] = depends
            else:
                result["depends"] = {"status": "not_following_pointer", "count": depend_count}

        if asset_ptr:
            if pointer_kind(asset_ptr) == "following":
                asset_table_size = asset_count * 8
                if current + asset_table_size > len(data):
                    raise ValueError("XAsset table extends past decompressed zone")
                entries = []
                type_counts: dict[str, int] = {}
                for index in range(asset_count):
                    entry_offset = current + index * 8
                    asset_type = be_u32(data, entry_offset)
                    header_ptr = be_u32(data, entry_offset + 4)
                    type_name = (
                        T6_ASSET_TYPE_NAMES[asset_type]
                        if asset_type < len(T6_ASSET_TYPE_NAMES)
                        else f"unknown_{asset_type}"
                    )
                    type_counts[type_name] = type_counts.get(type_name, 0) + 1
                    entries.append(
                        {
                            "index": index,
                            "offset": entry_offset,
                            "type": asset_type,
                            "type_name": type_name,
                            "header_pointer": f"0x{header_ptr:08X}",
                            "header_pointer_kind": pointer_kind(header_ptr),
                        }
                    )
                result["assets"] = {
                    "table_offset": current,
                    "table_size": asset_table_size,
                    "entries": entries,
                    "entries_sample": entries[:200],
                    "entries_sample_note": "First 200 entries are duplicated here for quick reading; full entries are also present and written to sidecar files.",
                    "type_counts": dict(sorted(type_counts.items())),
                }
                current += asset_table_size
            else:
                result["assets"] = {"status": "not_following_pointer", "count": asset_count}
        result["parsed_stream_offset_after_top_level_tables"] = current
    except ValueError as exc:
        result["status"] = "parse_error"
        result["error"] = str(exc)

    return result


def safe_asset_path(name: str, default_suffix: str) -> Path:
    cleaned = name.replace("\\", "/").strip("/")
    cleaned = re.sub(r"^[A-Za-z]:", "", cleaned)
    parts = [part for part in cleaned.split("/") if part not in {"", ".", ".."}]
    if not parts:
        parts = ["unnamed"]
    leaf = parts[-1]
    if "." not in leaf and default_suffix:
        parts[-1] = leaf + default_suffix
    return Path(*parts)


def first_printable_string(data: bytes, base_offset: int = 0, min_len: int = 4) -> tuple[str | None, int | None]:
    pattern = rb"[\x20-\x7e]{" + str(min_len).encode("ascii") + rb",}"
    match = re.search(pattern, data)
    if not match:
        return None, None
    return match.group().decode("ascii", "replace"), base_offset + match.start()


def find_next_following_asset_header(data: bytes, start: int, min_gap: int = 64, max_scan: int = 0x200000) -> int | None:
    """Find a plausible next asset body start.

    Xbox T6 stream bodies observed here often begin with a following pointer
    (`FFFFFFFF`) and a small count/length field. This is a boundary heuristic,
    used only for raw range carving when the inner asset layout is not solved.
    """

    scan_end = min(len(data) - 12, start + max_scan)
    for offset in range(start + min_gap, scan_end + 1):
        if data[offset : offset + 4] != b"\xFF\xFF\xFF\xFF":
            continue
        middle = be_u32(data, offset + 4)
        third = be_u32(data, offset + 8)
        if middle > 64 * 1024 * 1024:
            continue
        if pointer_kind(third) not in {"following", "null", "offset", "insert"}:
            continue
        return offset
    return None


def extract_recoverable_prefix_assets(data: bytes, top_level: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    """Extract only simple assets encountered before the first unsupported body.

    This deliberately follows the linear "following pointer" stream only. It is
    useful for zones where ScriptParseTree/RawFile assets appear at the start of
    the asset body stream, but it stops as soon as an asset type would require a
    loader we have not modeled yet.
    """

    assets = top_level.get("assets", {})
    entries = assets.get("entries") or assets.get("entries_sample") or []
    current = top_level.get("parsed_stream_offset_after_top_level_tables")
    if not isinstance(current, int):
        return {"status": "no_top_level_stream_offset"}

    extracted_root = out_dir / "assets"
    reports: list[dict[str, Any]] = []
    stopped_reason = None
    blob_asset_dirs = {
        "ScriptParseTree": "scriptparsetree",
        "RawFile": "rawfile",
        "Slug": "slug",
        "Qdb": "qdb",
    }

    def read_following_string(ptr: int) -> tuple[str | None, int | None]:
        nonlocal current
        kind = pointer_kind(ptr)
        if kind == "null":
            return None, None
        if kind != "following":
            raise ValueError(f"unsupported string pointer {ptr:#010x} ({kind}) at stream offset 0x{current:X}")
        string_offset = current
        value, current = read_zone_cstring(data, current)
        return value, string_offset

    def read_name_pointer(ptr: int) -> tuple[str | None, int | None]:
        kind = pointer_kind(ptr)
        if kind == "null":
            return None, None
        if kind == "following":
            return read_following_string(ptr)
        if kind == "offset":
            # Xbox T6 name/string pointers observed in decompressed zones can
            # point directly at a string offset for low-address values.
            value, string_offset = resolve_direct_string_pointer(data, ptr)
            if value is not None:
                return value, string_offset
            raise ValueError(f"offset string pointer 0x{ptr:08X} does not resolve to readable text")
        raise ValueError(f"unsupported string pointer {ptr:#010x} ({kind}) at stream offset 0x{current:X}")

    try:
        for entry in entries:
            if entry.get("header_pointer_kind") != "following":
                stopped_reason = f"asset {entry.get('index')} uses non-following header pointer"
                break

            type_name = entry.get("type_name")
            asset_start = current

            if type_name == "ScriptParseTree":
                next_start = find_next_following_asset_header(data, current)
                if next_start is not None:
                    chunk = data[current:next_start]
                    printable_name, printable_offset = first_printable_string(chunk, current)
                    rel = safe_asset_path(printable_name or f"scriptparsetree_{entry.get('index'):04d}", ".bin")
                    path = extracted_root / "scriptparsetree_ranges" / rel
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(chunk)
                    reports.append(
                        {
                            "index": entry.get("index"),
                            "type_name": type_name,
                            "asset_body_offset": asset_start,
                            "range_end_offset": next_start,
                            "range_size": len(chunk),
                            "candidate_name": printable_name,
                            "candidate_name_offset": printable_offset,
                            "raw_header_hex": chunk[:32].hex(),
                            "path": str(path),
                            "sha256": hashlib.sha256(chunk).hexdigest(),
                            "extraction_confidence": "medium",
                            "confidence_reason": (
                                "Raw range carved to the next plausible following-pointer asset header. "
                                "The inner ScriptParseTree layout is still unresolved."
                            ),
                        }
                    )
                    current = next_start
                    continue

            if type_name == "MemoryBlock":
                if current + 12 > len(data):
                    raise ValueError("MemoryBlock header extends past decompressed zone")
                name_ptr = be_u32(data, current)
                record_count = be_u32(data, current + 4)
                data_ptr = be_u32(data, current + 8)
                current += 12
                name, name_offset = read_name_pointer(name_ptr)
                records_offset = current
                if record_count > 1024:
                    raise ValueError(f"implausible MemoryBlock record count {record_count}")
                records_size = record_count * 12
                if current + records_size > len(data):
                    raise ValueError("MemoryBlock records extend past decompressed zone")
                records = []
                for record_index in range(record_count):
                    record_offset = current + record_index * 12
                    records.append(
                        {
                            "index": record_index,
                            "offset": record_offset,
                            "field_0": f"0x{be_u32(data, record_offset):08X}",
                            "field_1": f"0x{be_u32(data, record_offset + 4):08X}",
                            "field_2": f"0x{be_u32(data, record_offset + 8):08X}",
                        }
                    )
                current += records_size
                labels_offset = current
                labels = []
                while len(labels) < 32:
                    if current + 12 <= len(data):
                        next_word = be_u32(data, current)
                        next_third = be_u32(data, current + 8)
                        next_length = be_u32(data, current + 4)
                        if (
                            pointer_kind(next_word) in {"following", "null"}
                            and pointer_kind(next_third) in {"following", "null", "offset", "insert"}
                            and next_length <= 64 * 1024 * 1024
                        ):
                            break
                    label, current = read_zone_cstring(data, current)
                    labels.append(label)
                    if not label and current + 12 <= len(data):
                        break
                reports.append(
                    {
                        "index": entry.get("index"),
                        "type_name": type_name,
                        "asset_body_offset": asset_start,
                        "name": name,
                        "name_offset": name_offset,
                        "record_count": record_count,
                        "data_pointer": f"0x{data_ptr:08X}",
                        "records_offset": records_offset,
                        "records_size": records_size,
                        "records_sample": records[:16],
                        "labels_offset": labels_offset,
                        "labels": labels,
                        "note": (
                            "Observed Xbox layout: 12-byte header, name string, "
                            "record_count * 12 raw records, then three label strings. "
                            "Record field semantics are still unknown."
                        ),
                    }
                )
                continue

            if type_name in blob_asset_dirs:
                if current + 12 > len(data):
                    raise ValueError(f"{type_name} header extends past decompressed zone")
                name_ptr = be_u32(data, current)
                length = be_u32(data, current + 4)
                buffer_ptr = be_u32(data, current + 8)
                current += 12
                name, name_offset = read_name_pointer(name_ptr)
                if pointer_kind(buffer_ptr) not in {"following", "null"}:
                    raise ValueError(f"unsupported {type_name} buffer pointer 0x{buffer_ptr:08X}")
                buffer_offset = None
                payload = b""
                if buffer_ptr:
                    if length > 64 * 1024 * 1024:
                        raise ValueError(f"implausible {type_name} length {length}")
                    buffer_offset = current
                    end = current + length + 1
                    if end > len(data):
                        raise ValueError(f"{type_name} buffer extends past decompressed zone")
                    payload = data[current : current + length]
                    current = end
                rel = safe_asset_path(name or f"{type_name.lower()}_{entry.get('index'):04d}", ".bin")
                path = extracted_root / blob_asset_dirs[type_name] / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload)
                reports.append(
                    {
                        "index": entry.get("index"),
                        "type_name": type_name,
                        "asset_body_offset": asset_start,
                        "name": name,
                        "name_offset": name_offset,
                        "len_field": length,
                        "buffer_offset": buffer_offset,
                        "buffer_pointer": f"0x{buffer_ptr:08X}",
                        "path": str(path),
                        "sha256": hashlib.sha256(payload).hexdigest(),
                        "extraction_confidence": "low",
                        "confidence_reason": (
                            "Prefix extractor consumes a following buffer linearly. "
                            "Xbox T6 block switching is not fully modeled yet, so payload boundaries are tentative."
                        ),
                    }
                )
                continue

            if type_name == "StringTable":
                if current + 12 > len(data):
                    raise ValueError("StringTable/observed blob header extends past decompressed zone")
                name_ptr = be_u32(data, current)
                length_or_columns = be_u32(data, current + 4)
                buffer_or_rows = be_u32(data, current + 8)
                # Several Xbox files observed here label asset type 42, which
                # OAT names StringTable, but the stream body is name/len/buffer
                # followed by a raw text payload. Treat this as a platform
                # observation, not as proof that all type-42 assets are blobs.
                if pointer_kind(buffer_or_rows) == "following" and length_or_columns <= 64 * 1024 * 1024:
                    current += 12
                    name, name_offset = read_name_pointer(name_ptr)
                    buffer_offset = current
                    end = current + length_or_columns + 1
                    if end > len(data):
                        raise ValueError("observed type-42 blob buffer extends past decompressed zone")
                    payload = data[current : current + length_or_columns]
                    current = end
                    rel = safe_asset_path(name or f"type42_blob_{entry.get('index'):04d}", ".bin")
                    path = extracted_root / "type42_observed_blob" / rel
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(payload)
                    reports.append(
                        {
                            "index": entry.get("index"),
                            "type_name": type_name,
                            "asset_body_offset": asset_start,
                            "observed_layout": "name_len_buffer",
                            "observed_layout_note": (
                                "OAT T6 enum calls type 42 StringTable, but this Xbox stream body "
                                "matches a raw blob layout in observed files."
                            ),
                            "name": name,
                            "name_offset": name_offset,
                            "len_field": length_or_columns,
                            "buffer_offset": buffer_offset,
                            "buffer_pointer": f"0x{buffer_or_rows:08X}",
                            "path": str(path),
                            "sha256": hashlib.sha256(payload).hexdigest(),
                            "extraction_confidence": "medium",
                            "confidence_reason": "The name/len/following-buffer layout and payload boundary are self-consistent.",
                        }
                    )
                    continue

                stopped_reason = (
                    f"asset {entry.get('index')} type {type_name} does not match observed blob layout "
                    "and full StringTable parsing is not implemented"
                )
                break

            stopped_reason = f"asset {entry.get('index')} type {type_name} is not implemented by prefix extractor"
            break
    except ValueError as exc:
        recovered = len([item for item in reports if item.get("path")])
        return {
            "status": "partial" if recovered else "parse_error",
            "stream_offset": current,
            "error": str(exc),
            "extracted_count": recovered,
            "processed_count": len(reports),
            "extracted": reports,
        }

    return {
        "status": "ok",
        "start_offset": top_level.get("parsed_stream_offset_after_top_level_tables"),
        "stop_offset": current,
        "extracted_count": len([item for item in reports if item.get("path")]),
        "processed_count": len(reports),
        "stopped_reason": stopped_reason,
        "extracted": reports,
    }


def write_asset_entry_tables(top_level: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    assets = top_level.get("assets", {})
    entries = assets.get("entries") or assets.get("entries_sample") or []
    if not entries:
        return {"status": "no_asset_entries"}

    tsv_path = out_dir / "asset_entries.tsv"
    jsonl_path = out_dir / "asset_entries.jsonl"
    with tsv_path.open("w", encoding="utf-8", newline="\n") as tsv, jsonl_path.open(
        "w", encoding="utf-8", newline="\n"
    ) as jsonl:
        tsv.write("index\ttable_offset\ttype\ttype_name\theader_pointer\theader_pointer_kind\n")
        for entry in entries:
            tsv.write(
                f"{entry.get('index')}\t0x{entry.get('offset', 0):08X}\t{entry.get('type')}\t"
                f"{entry.get('type_name')}\t{entry.get('header_pointer')}\t{entry.get('header_pointer_kind')}\n"
            )
            jsonl.write(json.dumps(entry, sort_keys=False) + "\n")

    return {
        "status": "ok",
        "count": len(entries),
        "tsv_path": str(tsv_path),
        "jsonl_path": str(jsonl_path),
    }


def scan_scriptparsetree_candidates(
    data: bytes,
    top_level: dict[str, Any],
    out_dir: Path,
    max_scan_bytes: int = 0x40000,
) -> dict[str, Any]:
    """Find plausible T6 ScriptParseTree structs without extracting payloads.

    This is intentionally diagnostic. A candidate is a 12-byte big-endian
    structure where the name pointer resolves to readable text, the length is
    plausible, and the buffer pointer has a known pointer marker. Payload
    extraction still needs proper block/pointer emulation.
    """

    start = top_level.get("parsed_stream_offset_after_top_level_tables")
    if not isinstance(start, int):
        return {"status": "no_top_level_stream_offset"}

    end = min(len(data) - 12, start + max_scan_bytes)
    candidates: list[dict[str, Any]] = []
    for offset in range(start, end + 1):
        name_ptr = be_u32(data, offset)
        length = be_u32(data, offset + 4)
        buffer_ptr = be_u32(data, offset + 8)
        if length > 64 * 1024 * 1024:
            continue
        if pointer_kind(buffer_ptr) not in {"following", "offset", "insert", "null"}:
            continue
        if pointer_kind(name_ptr) == "offset":
            name, name_offset = resolve_direct_string_pointer(data, name_ptr)
        elif pointer_kind(name_ptr) == "null":
            name, name_offset = None, None
        else:
            name, name_offset = None, None
        if not name or not is_plausible_asset_name(name):
            continue
        candidates.append(
            {
                "offset": offset,
                "name": name,
                "name_pointer": f"0x{name_ptr:08X}",
                "name_offset": name_offset,
                "len_field": length,
                "buffer_pointer": f"0x{buffer_ptr:08X}",
                "buffer_pointer_kind": pointer_kind(buffer_ptr),
                "raw_header_hex": data[offset : offset + 12].hex(),
            }
        )

    path = out_dir / "scriptparsetree_candidates.tsv"
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("offset_hex\toffset_dec\tname\tname_pointer\tname_offset_hex\tlen_field\tbuffer_pointer\tbuffer_pointer_kind\traw_header_hex\n")
        for item in candidates:
            name_offset = item["name_offset"]
            handle.write(
                f"0x{item['offset']:08X}\t{item['offset']}\t{item['name']}\t{item['name_pointer']}\t"
                f"{'' if name_offset is None else f'0x{name_offset:08X}'}\t{item['len_field']}\t"
                f"{item['buffer_pointer']}\t{item['buffer_pointer_kind']}\t{item['raw_header_hex']}\n"
            )

    return {
        "status": "ok",
        "scan_start": start,
        "scan_end": end,
        "max_scan_bytes": max_scan_bytes,
        "count": len(candidates),
        "path": str(path),
        "sample": candidates[:50],
        "note": "Diagnostic only; candidates are not proof of independently extractable ScriptParseTree payloads.",
    }


MENUDEF_STRING_FIELD_OFFSETS = {
    "window.name": 0,
    "font": 164,
    "allowedBinding": 312,
    "soundName": 316,
}


def _read_optional_direct_string(data: bytes, ptr: int) -> tuple[str | None, int | None]:
    if ptr == 0:
        return None, None
    if pointer_kind(ptr) != "offset":
        return None, None
    return resolve_direct_string_pointer(data, ptr)


def _looks_like_menudef_at(data: bytes, start: int) -> dict[str, Any] | None:
    if start < 0 or start + 400 > len(data):
        return None

    name_ptr = be_u32(data, start)
    name, name_offset = _read_optional_direct_string(data, name_ptr)
    if not name or not is_plausible_asset_name(name):
        return None

    item_count = be_u32(data, start + 176)
    if item_count > 1024:
        return None

    pointer_fields = {
        "onEvent": be_u32(data, start + 268),
        "onKey": be_u32(data, start + 272),
        "visibleExp": be_u32(data, start + 276),
        "allowedBinding": be_u32(data, start + 312),
        "soundName": be_u32(data, start + 316),
        "items": be_u32(data, start + 392),
    }
    if any(pointer_kind(value) not in {"null", "following", "insert", "offset"} for value in pointer_fields.values()):
        return None

    font_ptr = be_u32(data, start + 164)
    font, font_offset = _read_optional_direct_string(data, font_ptr)
    allowed, allowed_offset = _read_optional_direct_string(data, pointer_fields["allowedBinding"])
    sound, sound_offset = _read_optional_direct_string(data, pointer_fields["soundName"])

    return {
        "offset": start,
        "name": name,
        "name_pointer": f"0x{name_ptr:08X}",
        "name_offset": name_offset,
        "item_count": item_count,
        "font": font,
        "font_pointer": f"0x{font_ptr:08X}",
        "font_offset": font_offset,
        "allowed_binding": allowed,
        "allowed_binding_pointer": f"0x{pointer_fields['allowedBinding']:08X}",
        "allowed_binding_offset": allowed_offset,
        "sound_name": sound,
        "sound_name_pointer": f"0x{pointer_fields['soundName']:08X}",
        "sound_name_offset": sound_offset,
        "on_event_pointer": f"0x{pointer_fields['onEvent']:08X}",
        "on_event_pointer_kind": pointer_kind(pointer_fields["onEvent"]),
        "on_key_pointer": f"0x{pointer_fields['onKey']:08X}",
        "on_key_pointer_kind": pointer_kind(pointer_fields["onKey"]),
        "visible_exp_pointer": f"0x{pointer_fields['visibleExp']:08X}",
        "visible_exp_pointer_kind": pointer_kind(pointer_fields["visibleExp"]),
        "items_pointer": f"0x{pointer_fields['items']:08X}",
        "items_pointer_kind": pointer_kind(pointer_fields["items"]),
        "raw_header_hex": data[start : start + 64].hex(),
    }


def scan_menudef_candidates(data: bytes, top_level: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    assets = top_level.get("assets", {})
    type_counts = assets.get("type_counts", {})
    expected_count = type_counts.get("menuDef_t", 0)
    if not expected_count:
        return {"status": "no_menudef_assets", "expected_count": 0}

    string_offsets = []
    pattern = rb"[\x20-\x7e]{3,128}"
    for match in re.finditer(pattern, data):
        value = match.group().decode("ascii", "replace")
        if is_plausible_asset_name(value):
            string_offsets.append(match.start())

    candidates_by_offset: dict[int, dict[str, Any]] = {}
    for string_offset in string_offsets:
        encoded = struct.pack(">I", string_offset)
        search_from = 0
        while True:
            occurrence = data.find(encoded, search_from)
            if occurrence < 0:
                break
            for field_name, field_offset in MENUDEF_STRING_FIELD_OFFSETS.items():
                start = occurrence - field_offset
                candidate = _looks_like_menudef_at(data, start)
                if candidate is not None:
                    candidate["matched_field"] = field_name
                    candidates_by_offset.setdefault(start, candidate)
            search_from = occurrence + 1

    candidates = [candidates_by_offset[offset] for offset in sorted(candidates_by_offset)]
    path = out_dir / "menudef_candidates.tsv"
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(
            "offset_hex\toffset_dec\tname\tmatched_field\titem_count\tfont\tallowed_binding\tsound_name\t"
            "on_event_pointer\ton_key_pointer\tvisible_exp_pointer\titems_pointer\titems_pointer_kind\n"
        )
        for item in candidates:
            handle.write(
                f"0x{item['offset']:08X}\t{item['offset']}\t{item['name']}\t{item.get('matched_field')}\t"
                f"{item['item_count']}\t{item.get('font') or ''}\t{item.get('allowed_binding') or ''}\t"
                f"{item.get('sound_name') or ''}\t{item['on_event_pointer']}\t{item['on_key_pointer']}\t"
                f"{item['visible_exp_pointer']}\t{item['items_pointer']}\t{item['items_pointer_kind']}\n"
            )

    return {
        "status": "ok",
        "expected_count": expected_count,
        "count": len(candidates),
        "path": str(path),
        "sample": candidates[:50],
        "note": "Diagnostic menuDef_t struct probe based on OAT T6 struct offsets; not a full menu decompiler.",
    }


def write_asset_stream_trace(
    data: bytes,
    top_level: dict[str, Any],
    recovery: dict[str, Any],
    out_dir: Path,
) -> dict[str, Any]:
    """Write the current broad asset stream trace and an unknown window.

    This is not a full loader yet. It records the verified top-level table, the
    assets the cautious prefix extractor could step through, and the exact
    bytes where the next unimplemented loader must begin.
    """

    trace_path = out_dir / "asset_stream_trace.json"
    unknown_dir = out_dir / "assets" / "_unknown_stream_windows"
    unknown_dir.mkdir(parents=True, exist_ok=True)

    stop_offset = recovery.get("stop_offset") or recovery.get("stream_offset")
    if not isinstance(stop_offset, int):
        stop_offset = top_level.get("parsed_stream_offset_after_top_level_tables", 0)
    window = data[stop_offset : min(len(data), stop_offset + 0x1000)]
    window_path = unknown_dir / f"{stop_offset:08x}_next_unparsed.bin"
    window_path.write_bytes(window)

    trace = {
        "status": "partial",
        "start_offset": top_level.get("parsed_stream_offset_after_top_level_tables"),
        "current_stop_offset": stop_offset,
        "processed_count": recovery.get("processed_count", 0),
        "extracted_count": recovery.get("extracted_count", 0),
        "stop_reason": recovery.get("stopped_reason") or recovery.get("error"),
        "unknown_window": {
            "path": str(window_path),
            "offset": stop_offset,
            "size": len(window),
            "sha256": hashlib.sha256(window).hexdigest(),
            "first_128_bytes": hex_sample(window, 0, 128),
        },
        "processed_assets": recovery.get("extracted", []),
        "note": (
            "This trace is the current frontier for the general unpacker. "
            "Add the next asset loader here, then rerun to advance through the stream."
        ),
    }
    write_json(trace_path, trace)
    return {
        "status": "ok",
        "path": str(trace_path),
        "unknown_window_path": str(window_path),
        "current_stop_offset": stop_offset,
    }


def extract_embedded_script_blobs(data: bytes, out_dir: Path) -> dict[str, Any]:
    """Extract embedded compiled GSC/CSC blobs by local path/header pattern.

    Some Xbox T6 script blobs are not reached by the current top-level asset
    walker because they are nested inside complex assets. They are nevertheless
    locally self-describing in observed zones:

        FFFFFFFF <be length> FFFFFFFF "<path>.gsc\\0" <compiled bytes>

    or the same for `.csc`. The compiled payload commonly starts with
    `80 47 53 43` (GSC) or equivalent platform bytecode magic.
    """

    script_dir = out_dir / "assets" / "embedded_scripts"
    friendly_script_dir = out_dir / "scripts"
    source_dir = out_dir / "scripts_src"
    script_dir.mkdir(parents=True, exist_ok=True)
    friendly_script_dir.mkdir(parents=True, exist_ok=True)
    pattern = rb"[\x20-\x7e]{3,}\.(?:gsc|csc)"
    reports: list[dict[str, Any]] = []
    seen_paths: dict[str, int] = {}
    gsc_exe = gsc_tool.find_gsc_tool()
    decompiled_count = 0
    decompile_failures = 0

    for match in re.finditer(pattern, data, flags=re.IGNORECASE):
        path_offset = match.start()
        header_offset = path_offset - 12
        if header_offset < 0:
            continue
        name_ptr = be_u32(data, header_offset)
        length = be_u32(data, header_offset + 4)
        buffer_ptr = be_u32(data, header_offset + 8)
        if name_ptr != 0xFFFFFFFF or buffer_ptr != 0xFFFFFFFF:
            continue
        if length == 0 or length > 16 * 1024 * 1024:
            continue

        path_end = data.find(b"\x00", path_offset, path_offset + 512)
        if path_end < 0:
            continue
        script_name = data[path_offset:path_end].decode("ascii", "replace")
        payload_offset = path_end + 1
        payload_end = payload_offset + length
        if payload_end > len(data):
            continue
        payload = data[payload_offset:payload_end]
        if len(payload) < 4:
            continue
        if payload[:4] not in {b"\x80GSC", b"\x80CSC"}:
            # Keep the extractor conservative: a path alone is not enough.
            continue

        suffix = ".gscbin" if script_name.lower().endswith(".gsc") else ".cscbin"
        rel = safe_asset_path(script_name, suffix)
        key = str(rel).lower()
        duplicate_index = seen_paths.get(key, 0)
        seen_paths[key] = duplicate_index + 1
        if duplicate_index:
            rel = rel.with_name(f"{rel.stem}_{path_offset:08x}{rel.suffix}")
        output_path = script_dir / rel
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(payload)
        friendly_rel = safe_asset_path(script_name, Path(script_name).suffix or suffix)
        friendly_output_path = friendly_script_dir / friendly_rel
        friendly_output_path.parent.mkdir(parents=True, exist_ok=True)
        friendly_output_path.write_bytes(payload)

        # Decompile the compiled payload to editable source under scripts_src/.
        is_client = gsc_tool.is_client_script(script_name)
        source_rel = friendly_rel  # keep the original .gsc/.csc extension + tree
        source_path = source_dir / source_rel
        decompile_status = "skipped"
        decompile_log = ""
        source_sha256 = None
        if gsc_exe is not None:
            result = gsc_tool.decompile(friendly_output_path, is_client=is_client, tool=gsc_exe)
            if result.get("ok"):
                source_path.parent.mkdir(parents=True, exist_ok=True)
                source_path.write_bytes(result["source"])
                source_sha256 = hashlib.sha256(result["source"]).hexdigest()
                decompile_status = "ok"
                decompiled_count += 1
            else:
                decompile_status = "failed"
                decompile_failures += 1
            decompile_log = (result.get("log") or "")[:2000]
        else:
            decompile_status = "no_gsc_tool"

        reports.append(
            {
                "script_name": script_name,
                "instance": "client" if is_client else "server",
                "header_offset": header_offset,
                # Inline be_u32 buffer length field; the repacker patches this when
                # a recompiled payload changes size.
                "zone_length_field_offset": header_offset + 4,
                "path_offset": path_offset,
                "payload_offset": payload_offset,
                "payload_size": length,
                "payload_magic_hex": payload[:4].hex(),
                "path": str(output_path),
                "friendly_path": str(friendly_output_path),
                "source_path": str(source_path) if decompile_status == "ok" else None,
                "source_rel": str(source_rel).replace("\\", "/"),
                "source_sha256": source_sha256,
                "decompile_status": decompile_status,
                "decompile_log": decompile_log,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "extraction_confidence": "high",
                "confidence_reason": "Local following-name/following-buffer header, script path, and compiled payload magic all match.",
            }
        )

    manifest_path = out_dir / "embedded_scripts.json"
    write_json(
        manifest_path,
        {
            "status": "ok",
            "count": len(reports),
            "scripts_root": str(friendly_script_dir),
            "source_root": str(source_dir),
            "decompiled_count": decompiled_count,
            "decompile_failures": decompile_failures,
            "gsc_tool": str(gsc_exe) if gsc_exe else None,
            "note": (
                "scripts/ holds verbatim compiled Xbox bytecode payloads; scripts_src/ "
                "holds gsc-tool-decompiled editable source (.gsc=server, .csc=client)."
            ),
            "scripts": reports,
        },
    )
    return {
        "status": "ok",
        "count": len(reports),
        "manifest_path": str(manifest_path),
        "scripts_root": str(friendly_script_dir),
        "source_root": str(source_dir),
        "decompiled_count": decompiled_count,
        "decompile_failures": decompile_failures,
        "gsc_tool_found": gsc_exe is not None,
        "scripts_sample": reports[:50],
    }


def extract_embedded_lua_blobs(data: bytes, out_dir: Path) -> dict[str, Any]:
    """Extract embedded compiled Lua UI blobs by local path/header pattern.

    Xbox BO2 LUI assets observed in patch UI zones use the same simple local
    layout as compiled script blobs:

        FFFFFFFF <be length> FFFFFFFF "<path>.lua\\0" <Lua bytecode>

    The payloads observed so far start with standard-ish Lua bytecode magic
    `1B 4C 75 61`, followed by Treyarch/Xbox-specific version/format bytes.
    These are preserved as raw compiled Lua payloads, not decompiled text.
    """

    lua_dir = out_dir / "assets" / "embedded_lua"
    friendly_lua_dir = out_dir / "ui_lua"
    lua_dir.mkdir(parents=True, exist_ok=True)
    friendly_lua_dir.mkdir(parents=True, exist_ok=True)
    pattern = rb"[\x20-\x7e]{3,}\.lua"
    reports: list[dict[str, Any]] = []
    seen_paths: dict[str, int] = {}

    for match in re.finditer(pattern, data, flags=re.IGNORECASE):
        path_offset = match.start()
        header_offset = path_offset - 12
        if header_offset < 0:
            continue
        name_ptr = be_u32(data, header_offset)
        length = be_u32(data, header_offset + 4)
        buffer_ptr = be_u32(data, header_offset + 8)
        if name_ptr != 0xFFFFFFFF or buffer_ptr != 0xFFFFFFFF:
            continue
        if length == 0 or length > 16 * 1024 * 1024:
            continue

        path_end = data.find(b"\x00", path_offset, path_offset + 512)
        if path_end < 0:
            continue
        lua_name = data[path_offset:path_end].decode("ascii", "replace")
        payload_offset = path_end + 1
        payload_end = payload_offset + length
        if payload_end > len(data):
            continue
        payload = data[payload_offset:payload_end]
        if len(payload) < 4 or payload[:4] != b"\x1bLua":
            continue

        rel = safe_asset_path(lua_name, ".luac")
        key = str(rel).lower()
        duplicate_index = seen_paths.get(key, 0)
        seen_paths[key] = duplicate_index + 1
        if duplicate_index:
            rel = rel.with_name(f"{rel.stem}_{path_offset:08x}{rel.suffix}")
        output_path = lua_dir / rel
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(payload)

        friendly_rel = safe_asset_path(lua_name, ".lua")
        friendly_output_path = friendly_lua_dir / friendly_rel
        friendly_output_path.parent.mkdir(parents=True, exist_ok=True)
        friendly_output_path.write_bytes(payload)

        reports.append(
            {
                "lua_name": lua_name,
                "header_offset": header_offset,
                "path_offset": path_offset,
                "payload_offset": payload_offset,
                "payload_size": length,
                "payload_magic_hex": payload[:4].hex(),
                "path": str(output_path),
                "friendly_path": str(friendly_output_path),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "extraction_confidence": "high",
                "confidence_reason": "Local following-name/following-buffer header, Lua path, and Lua bytecode magic all match.",
            }
        )

    manifest_path = out_dir / "embedded_lua.json"
    write_json(
        manifest_path,
        {
            "status": "ok",
            "count": len(reports),
            "lua_root": str(friendly_lua_dir),
            "note": "Extracted .lua files are compiled Xbox/Treyarch Lua bytecode payloads, not decompiled Lua source text.",
            "lua_files": reports,
        },
    )
    return {
        "status": "ok",
        "count": len(reports),
        "manifest_path": str(manifest_path),
        "lua_root": str(friendly_lua_dir),
        "lua_sample": reports[:50],
    }


def extract_embedded_menu_blobs(data: bytes, out_dir: Path) -> dict[str, Any]:
    """Extract embedded `.menu` blobs verbatim by local path/pointer pattern.

    Menu payloads that use the same self-describing container as scripts/Lua:

        FFFFFFFF <be length> FFFFFFFF "<path>.menu\\0" <payload bytes>

    Per the extraction contract, `.menu` files are copied out exactly as stored.
    No attempt is made to decide whether the payload is compiled or plaintext,
    and no payload magic is required. Most BO2 UI is LUI (`.lua`); classic
    `menuDef_t` assets that are not stored as contiguous pointer blobs are not
    recovered here and still require the zone asset-stream parser.
    """

    menu_dir = out_dir / "assets" / "embedded_menu"
    friendly_menu_dir = out_dir / "menus"
    menu_dir.mkdir(parents=True, exist_ok=True)
    friendly_menu_dir.mkdir(parents=True, exist_ok=True)
    pattern = rb"[\x20-\x7e]{3,}\.menu"
    reports: list[dict[str, Any]] = []
    seen_paths: dict[str, int] = {}

    for match in re.finditer(pattern, data, flags=re.IGNORECASE):
        path_offset = match.start()
        header_offset = path_offset - 12
        if header_offset < 0:
            continue
        name_ptr = be_u32(data, header_offset)
        length = be_u32(data, header_offset + 4)
        buffer_ptr = be_u32(data, header_offset + 8)
        if name_ptr != 0xFFFFFFFF or buffer_ptr != 0xFFFFFFFF:
            continue
        if length == 0 or length > 64 * 1024 * 1024:
            continue

        path_end = data.find(b"\x00", path_offset, path_offset + 512)
        if path_end < 0:
            continue
        menu_name = data[path_offset:path_end].decode("ascii", "replace")
        payload_offset = path_end + 1
        payload_end = payload_offset + length
        if payload_end > len(data):
            continue
        payload = data[payload_offset:payload_end]

        rel = safe_asset_path(menu_name, ".menu")
        key = str(rel).lower()
        duplicate_index = seen_paths.get(key, 0)
        seen_paths[key] = duplicate_index + 1
        if duplicate_index:
            rel = rel.with_name(f"{rel.stem}_{path_offset:08x}{rel.suffix}")
        output_path = menu_dir / rel
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(payload)

        friendly_output_path = friendly_menu_dir / rel
        friendly_output_path.parent.mkdir(parents=True, exist_ok=True)
        friendly_output_path.write_bytes(payload)

        reports.append(
            {
                "menu_name": menu_name,
                "header_offset": header_offset,
                "path_offset": path_offset,
                "payload_offset": payload_offset,
                "payload_size": length,
                "payload_head_hex": payload[:16].hex(),
                "path": str(output_path),
                "friendly_path": str(friendly_output_path),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "extraction_confidence": "high",
                "confidence_reason": "Local following-name/following-buffer header and .menu path match.",
            }
        )

    manifest_path = out_dir / "embedded_menu.json"
    write_json(
        manifest_path,
        {
            "status": "ok",
            "count": len(reports),
            "menu_root": str(friendly_menu_dir),
            "note": "Extracted .menu files are copied verbatim from the zone; they are not parsed or decompiled.",
            "menu_files": reports,
        },
    )
    return {
        "status": "ok",
        "count": len(reports),
        "manifest_path": str(manifest_path),
        "menu_root": str(friendly_menu_dir),
        "menu_sample": reports[:50],
    }


def write_zone_patch_manifest(out_dir: Path) -> dict[str, Any]:
    """Consolidate every editable asset into one repack manifest.

    ScriptParseTree (`.gsc`/`.csc`) and RawFile (`.lua`) share the same 12-byte
    stream header ``{const char* name; int len; byte* buffer;}`` with the buffer
    stored as ``len + 1`` bytes in ``XFILE_BLOCK_VIRTUAL`` and no stream
    alignment padding (verified against OpenAssetTools' generated T6 loaders).
    `zone_rebuild.py` consumes this manifest to map an edited source file back to
    its exact byte range in ``zone_decompressed.dat`` and to detect which sources
    changed (via ``source_sha256``). ``.menu`` blobs are listed for reference but
    have no recompiler.
    """

    def _load(name: str) -> dict[str, Any]:
        path = out_dir / name
        if not path.exists():
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    assets: list[dict[str, Any]] = []

    for report in _load("embedded_scripts.json").get("scripts", []):
        name = report.get("script_name", "")
        size = int(report.get("payload_size") or 0)
        assets.append(
            {
                "kind": "csc" if name.lower().endswith(".csc") else "gsc",
                "name": name,
                "header_offset": report.get("header_offset"),
                "len_field_offset": report.get("zone_length_field_offset"),
                "payload_offset": report.get("payload_offset"),
                "len_field_value": size,
                "buffer_stream_len": size + 1,  # loader reads len + 1 bytes
                "block": "XFILE_BLOCK_VIRTUAL",
                "recompiler": "gsc-tool",
                "source_root": "scripts_src",
                "source_rel": report.get("source_rel"),
                "source_sha256": report.get("source_sha256"),
                "payload_sha256": report.get("sha256"),
            }
        )

    for report in _load("embedded_lua.json").get("lua_files", []):
        header_offset = report.get("header_offset")
        size = int(report.get("payload_size") or 0)
        assets.append(
            {
                "kind": "lua",
                "name": report.get("lua_name"),
                "header_offset": header_offset,
                "len_field_offset": (header_offset + 4) if header_offset is not None else None,
                "payload_offset": report.get("payload_offset"),
                "len_field_value": size,
                "buffer_stream_len": size + 1,
                "block": "XFILE_BLOCK_VIRTUAL",
                "recompiler": "lua_tool",
                # Readable Lua source is generated after unpack (in ff_app), so the
                # source path/baseline hash are filled in then.
                "source_root": "ui_lua_readable",
                "source_rel": None,
                "source_sha256": None,
                "payload_sha256": report.get("sha256"),
            }
        )

    for report in _load("embedded_menu.json").get("menu_files", []):
        header_offset = report.get("header_offset")
        size = int(report.get("payload_size") or 0)
        assets.append(
            {
                "kind": "menu",
                "name": report.get("menu_name"),
                "header_offset": header_offset,
                "len_field_offset": (header_offset + 4) if header_offset is not None else None,
                "payload_offset": report.get("payload_offset"),
                "len_field_value": size,
                "buffer_stream_len": size + 1,
                "block": "XFILE_BLOCK_VIRTUAL",
                "recompiler": None,  # no .menu compiler; verbatim only
                "source_root": None,
                "source_rel": None,
                "source_sha256": None,
                "payload_sha256": report.get("sha256"),
            }
        )

    manifest = {
        "zone_file": "zone_decompressed.dat",
        "zone_size_field_offset": 0,
        "virtual_block_size_field_offset": 8 + XFILE_BLOCK_VIRTUAL_INDEX * 4,
        "asset_count": len(assets),
        "note": (
            "Repack map for zone_rebuild.py. Edit files under scripts_src/ (and, once "
            "the Lua compiler lands, ui_lua_readable/) then repack the folder to splice "
            "recompiled buffers back into zone_decompressed.dat. Buffer stream length is "
            "len_field_value + 1; no stream alignment padding between assets."
        ),
        "assets": assets,
    }
    manifest_path = out_dir / "zone_patch_manifest.json"
    write_json(manifest_path, manifest)
    return {"status": "ok", "count": len(assets), "manifest_path": str(manifest_path)}


def augment_manifest_lua_sources(out_dir: Path) -> int:
    """Fill in editable Lua source (HKS assembly) paths + baseline hashes.

    Readable/assembly Lua is generated after the zone is unpacked (by the Lua
    tool), so the manifest's `.lua` entries start without a source mapping. This
    links each RawFile Lua asset to its `ui_lua_hksasm/<path>.hksasm` file so the
    repacker knows which edited assembly to recompile. Returns the count linked.
    """
    manifest_path = out_dir / "zone_patch_manifest.json"
    hksasm_dir = out_dir / "ui_lua_hksasm"
    if not manifest_path.exists() or not hksasm_dir.exists():
        return 0
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return 0
    linked = 0
    for asset in manifest.get("assets", []):
        if asset.get("kind") != "lua" or asset.get("source_rel"):
            continue
        name = asset.get("name")
        if not name:
            continue
        rel = safe_asset_path(name, ".lua").with_suffix(".hksasm")
        hksasm_path = hksasm_dir / rel
        if hksasm_path.exists():
            asset["source_root"] = "ui_lua_hksasm"
            asset["source_rel"] = rel.as_posix()
            asset["source_sha256"] = hashlib.sha256(hksasm_path.read_bytes()).hexdigest()
            linked += 1
    if linked:
        write_json(manifest_path, manifest)
    return linked


def build_readable_string_inventory(data: bytes, out_dir: Path, min_len: int = 5) -> dict[str, Any]:
    all_path = out_dir / "readable_strings.tsv"
    interesting_path = out_dir / "interesting_strings.tsv"
    interesting_terms = [
        "menu",
        "ui/",
        ".menu",
        ".gsc",
        ".csc",
        "maps/",
        "open ",
        "exec",
        "setdvar",
        "dvar_",
    ]
    counts = {
        "all": 0,
        "interesting": 0,
        "paths_or_scripts": 0,
    }
    pattern = rb"[\x20-\x7e]{" + str(min_len).encode("ascii") + rb",}"
    with all_path.open("w", encoding="utf-8", newline="\n") as all_file, interesting_path.open(
        "w", encoding="utf-8", newline="\n"
    ) as interesting_file:
        all_file.write("offset_hex\toffset_dec\tvalue\n")
        interesting_file.write("offset_hex\toffset_dec\tvalue\n")
        for match in re.finditer(pattern, data):
            value = match.group().decode("ascii", "replace")
            escaped = value.replace("\t", "\\t").replace("\r", "\\r").replace("\n", "\\n")
            line = f"0x{match.start():08X}\t{match.start()}\t{escaped}\n"
            all_file.write(line)
            counts["all"] += 1
            lower = value.lower()
            if any(term in lower for term in interesting_terms):
                interesting_file.write(line)
                counts["interesting"] += 1
            if any(term in lower for term in ["ui/", "maps/", ".menu", ".gsc", ".csc"]):
                counts["paths_or_scripts"] += 1

    return {
        "min_length": min_len,
        "readable_strings_path": str(all_path),
        "interesting_strings_path": str(interesting_path),
        "counts": counts,
    }


@dataclass
class Region:
    name: str
    offset: int
    size: int
    status: str
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "offset": self.offset,
            "size": self.size,
            "status": self.status,
            "notes": self.notes,
        }


class FastFileScanner:
    def __init__(self, path: Path, verbose: bool = False):
        self.path = path
        self.verbose = verbose
        self.data = path.read_bytes()
        self.regions: list[Region] = []
        self.metadata: dict[str, Any] = {
            "input": {
                "path": str(path),
                "size": len(self.data),
                "sha256": hashlib.sha256(self.data).hexdigest(),
            },
            "assumptions": [],
            "warnings": [],
            "unknowns": [],
        }

    def log(self, message: str) -> None:
        if self.verbose:
            print(message, file=sys.stderr)

    def add_region(self, name: str, offset: int, size: int, status: str, notes: list[str] | None = None) -> None:
        self.regions.append(Region(name, offset, size, status, notes or []))

    def scan(self, probe_decrypt: bool = True) -> dict[str, Any]:
        if len(self.data) < PAYLOAD_OFFSET:
            raise ValueError(f"File is too small for known BO2 auth/signature header: {len(self.data)} bytes")

        self.parse_header()
        self.scan_payload(probe_decrypt=probe_decrypt)
        self.metadata["regions"] = [region.as_dict() for region in self.regions]
        return self.metadata

    def parse_header(self) -> None:
        magic = self.data[0:8]
        version_be = be_u32(self.data, 0x08)
        version_le = le_u32(self.data, 0x08)
        auth_magic = self.data[0x0C:0x10]
        auth_build = self.data[0x10:0x14]
        reserved = self.data[0x14:0x18]
        name_raw = self.data[0x18:0x38]
        name = c_string(name_raw)

        self.metadata["header"] = {
            "magic_ascii": magic.decode("ascii", errors="replace"),
            "magic_hex": magic.hex(),
            "recognized_magic": magic in KNOWN_MAGIC,
            "compression_from_magic": MAGIC_COMPRESSION.get(magic, "unknown"),
            "version_big_endian": version_be,
            "version_little_endian": version_le,
            "selected_byte_order": "big",
            "byte_order_reason": "Version field decodes to a plausible small value in big-endian; little-endian is implausibly large.",
        }
        self.metadata["auth_header"] = {
            "offset": AUTH_HEADER_OFFSET,
            "size": AUTH_HEADER_SIZE,
            "magic_ascii": auth_magic.decode("ascii", errors="replace"),
            "magic_hex": auth_magic.hex(),
            "build_or_codec_marker_ascii": auth_build.decode("ascii", errors="replace"),
            "build_or_codec_marker_hex": auth_build.hex(),
            "reserved_0x14_0x17_hex": reserved.hex(),
            "fastfile_name": name,
            "fastfile_name_raw_hex": name_raw.hex(),
        }
        self.metadata["signature"] = {
            "offset": SIGNATURE_OFFSET,
            "size": SIGNATURE_SIZE,
            "sha256": hashlib.sha256(self.data[SIGNATURE_OFFSET:PAYLOAD_OFFSET]).hexdigest(),
            "sample": hex_sample(self.data, SIGNATURE_OFFSET, 64),
        }

        self.metadata["assumptions"].extend(
            [
                "Xbox 360 BO2 files observed here use an 8-byte TAff*100 magic at 0x00.",
                "The 32-bit version at 0x08 is treated as big-endian; common_zm.ff reads as 146 / 0x92.",
                "The clear auth/name/signature area is treated as 0x138 bytes: DB_Header 0x0C, auth/name 0x2C, signature 0x100.",
                "Payload after 0x138 is parsed as OAT-style xchunks: big-endian u32 size followed by encrypted chunk bytes.",
                "For TAffx100, chunk contents are treated as Salsa20-encrypted XMem/LZX data.",
            ]
        )

        if magic not in KNOWN_MAGIC:
            self.metadata["warnings"].append(f"Unrecognized magic {magic.hex()} at 0x00")
        if reserved != b"\x00\x00\x00\x00":
            self.metadata["warnings"].append("Reserved auth bytes at 0x14 are non-zero")
        if not name:
            self.metadata["warnings"].append("Fastfile name field is empty")

        self.add_region("db_header", 0, AUTH_HEADER_OFFSET, "parsed")
        self.add_region("auth_header_and_name", AUTH_HEADER_OFFSET, AUTH_HEADER_SIZE, "partially_parsed")
        self.add_region("signature", SIGNATURE_OFFSET, SIGNATURE_SIZE, "raw_known_region")
        self.log(f"magic={magic!r} version_be={version_be} name={name!r}")

    def scan_payload(self, probe_decrypt: bool) -> None:
        payload = self.data[PAYLOAD_OFFSET:]
        self.add_region(
            "encrypted_or_compressed_payload",
            PAYLOAD_OFFSET,
            len(payload),
            "unknown_raw",
            ["High entropy; no direct extraction attempted without verified decrypt/decompress framing."],
        )
        self.metadata["payload"] = {
            "offset": PAYLOAD_OFFSET,
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "entropy_first_64k": entropy(payload[: min(len(payload), 0x10000)]),
            "entropy_full_sample_stride": self.sampled_entropy(payload),
            "first_bytes": hex_sample(self.data, PAYLOAD_OFFSET, 64),
            "ascii_strings_in_plain_payload": find_ascii_strings(payload, PAYLOAD_OFFSET, min_len=6, limit=50),
            "zlib_candidates_in_plain_payload": zlib_probe(payload, PAYLOAD_OFFSET, max_hits=32),
        }
        self.metadata["xchunks"] = self.scan_xchunks(payload)
        self.metadata["unknowns"].extend(
            [
                "Exact meaning of auth magic PHEE is not verified.",
                "Exact meaning of marker Bs71 is not verified.",
                "Full LZX decompression is not implemented in this Python scaffold yet.",
                "Zone asset table offsets cannot be trusted until payload decryption/decompression is solved.",
            ]
        )
        if probe_decrypt:
            self.metadata["salsa20_probe"] = salsa20_probe(payload)

    def scan_xchunks(self, payload: bytes) -> dict[str, Any]:
        zone_name = self.metadata.get("auth_header", {}).get("fastfile_name", self.path.stem)
        decryptor = OatSalsa20ChunkDecryptor(zone_name)
        chunks = []
        offset = 0
        stream = 0
        total_encrypted = 0
        total_decrypted_lzx_dst_prefix = 0
        error = None

        while offset < len(payload):
            # Skip the vanilla-buffer padding before a size header (see the
            # decompress loop and VANILLA_BUFFER_SIZE for the rationale).
            vanilla_offset = (PAYLOAD_OFFSET + offset) % VANILLA_BUFFER_SIZE
            if vanilla_offset + 4 > VANILLA_BUFFER_SIZE:
                offset += VANILLA_BUFFER_SIZE - vanilla_offset
            file_offset = PAYLOAD_OFFSET + offset
            if offset + 4 > len(payload):
                error = f"trailing {len(payload) - offset} bytes where xchunk size was expected"
                break
            chunk_size = be_u32(payload, offset)
            offset += 4
            if chunk_size == 0:
                trailing = payload[offset - 4 :]
                chunks.append(
                    {
                        "index": len(chunks),
                        "stream": stream,
                        "size_field_offset": file_offset,
                        "chunk_size": 0,
                        "status": "eof_marker",
                        "trailing_bytes_after_marker": len(trailing),
                        "trailing_all_zero": all(b == 0 for b in trailing),
                    }
                )
                if all(b == 0 for b in trailing):
                    offset = len(payload)
                else:
                    error = f"non-zero data after xchunk eof marker at 0x{file_offset:08X}"
                break
            if chunk_size > XCHUNK_SIZE:
                error = f"invalid xchunk size {chunk_size} at 0x{file_offset:08X}; max is 0x{XCHUNK_SIZE:X}"
                offset -= 4
                break
            if offset + chunk_size > len(payload):
                error = f"xchunk at 0x{file_offset:08X} extends past EOF"
                offset -= 4
                break

            encrypted = payload[offset : offset + chunk_size]
            decrypted, iv, digest = decryptor.decrypt(stream, encrypted)
            lzx_headers = parse_xmem_lzx_headers(decrypted) if self.metadata["header"]["compression_from_magic"] == "lzx" else None
            if lzx_headers:
                total_decrypted_lzx_dst_prefix += sum(block["dst_size"] for block in lzx_headers["blocks"])

            chunks.append(
                {
                    "index": len(chunks),
                    "stream": stream,
                    "size_field_offset": file_offset,
                    "encrypted_data_offset": PAYLOAD_OFFSET + offset,
                    "chunk_size": chunk_size,
                    "salsa20_iv_hex": iv.hex(),
                    "decrypted_sha1_hex": digest.hex(),
                    "encrypted_sha256": hashlib.sha256(encrypted).hexdigest(),
                    "decrypted_sample": hex_sample(decrypted, 0, 32),
                    "xmem_lzx_headers": lzx_headers,
                }
            )
            total_encrypted += chunk_size
            offset += chunk_size
            stream = (stream + 1) % XCHUNK_STREAM_COUNT

        return {
            "source": "OpenAssetTools-compatible xchunk scanner",
            "stream_count": XCHUNK_STREAM_COUNT,
            "max_chunk_size": XCHUNK_SIZE,
            "payload_bytes_consumed": offset,
            "payload_size": len(payload),
            "total_encrypted_chunk_bytes": total_encrypted,
            "chunk_count": len([c for c in chunks if c.get("status") != "eof_marker"]),
            "estimated_decompressed_bytes_from_lzx_headers_prefix": total_decrypted_lzx_dst_prefix,
            "complete": error is None and offset == len(payload),
            "error": error,
            "chunks": chunks,
        }

    def sampled_entropy(self, payload: bytes) -> list[dict[str, Any]]:
        samples = []
        for offset in range(0, len(payload), 0x100000):
            chunk = payload[offset : offset + 0x10000]
            samples.append(
                {
                    "payload_relative_offset": offset,
                    "file_offset": PAYLOAD_OFFSET + offset,
                    "sample_size": len(chunk),
                    "entropy": entropy(chunk),
                    "unique_byte_values": len(set(chunk)),
                }
            )
            if len(samples) >= 32:
                break
        return samples

    def dump_unknown_regions(self, out_dir: Path) -> list[dict[str, Any]]:
        dumps = []
        unknown_dir = out_dir / "unknown"
        unknown_dir.mkdir(parents=True, exist_ok=True)
        for region in self.regions:
            if "unknown" not in region.status and region.name != "signature":
                continue
            raw = self.data[region.offset : region.offset + region.size]
            filename = f"{region.offset:08x}_{region.name}.bin"
            path = unknown_dir / filename
            path.write_bytes(raw)
            dumps.append(
                {
                    "region": region.name,
                    "offset": region.offset,
                    "size": region.size,
                    "path": str(path),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
            )
        return dumps

    def dump_decrypted_xchunks(self, out_dir: Path) -> list[dict[str, Any]]:
        zone_name = self.metadata.get("auth_header", {}).get("fastfile_name", self.path.stem)
        decryptor = OatSalsa20ChunkDecryptor(zone_name)
        payload = self.data[PAYLOAD_OFFSET:]
        xchunk_dir = out_dir / "decrypted_xchunks"
        xchunk_dir.mkdir(parents=True, exist_ok=True)
        dumps = []
        offset = 0
        stream = 0
        index = 0
        while offset + 4 <= len(payload):
            size_field_offset = PAYLOAD_OFFSET + offset
            chunk_size = be_u32(payload, offset)
            offset += 4
            if chunk_size == 0 or chunk_size > XCHUNK_SIZE or offset + chunk_size > len(payload):
                break
            encrypted = payload[offset : offset + chunk_size]
            decrypted, iv, digest = decryptor.decrypt(stream, encrypted)
            path = xchunk_dir / f"{index:06d}_stream{stream}_file{size_field_offset:08x}.xmem"
            path.write_bytes(decrypted)
            dumps.append(
                {
                    "index": index,
                    "stream": stream,
                    "size_field_offset": size_field_offset,
                    "chunk_size": chunk_size,
                    "path": str(path),
                    "salsa20_iv_hex": iv.hex(),
                    "decrypted_sha1_hex": digest.hex(),
                    "sha256": hashlib.sha256(decrypted).hexdigest(),
                }
            )
            offset += chunk_size
            stream = (stream + 1) % XCHUNK_STREAM_COUNT
            index += 1
        return dumps

    def decompress_zone_stream(
        self,
        out_dir: Path,
        helper_path: Path,
        scan_menus: bool = False,
        allow_partial_zone: bool = False,
    ) -> dict[str, Any]:
        compression = self.metadata["header"].get("compression_from_magic")
        if compression == "lzx" and not helper_path.exists():
            raise ValueError(f"LZX helper does not exist: {helper_path}")
        if compression not in {"lzx", "deflate"}:
            raise ValueError(f"unsupported zone compression mode: {compression!r}")

        zone_name = self.metadata.get("auth_header", {}).get("fastfile_name", self.path.stem)
        decryptor = OatSalsa20ChunkDecryptor(zone_name)
        payload = self.data[PAYLOAD_OFFSET:]
        out_dir.mkdir(parents=True, exist_ok=True)
        zone_path = out_dir / "zone_decompressed.dat"
        # Preserve the exact 0x138-byte clear header (magic, version, PHEE/Bs71,
        # fastfile name, and 256-byte signature blob) so the repacker can rebuild
        # a valid FastFile without having to regenerate the signature.
        (out_dir / "ff_header.bin").write_bytes(self.data[:PAYLOAD_OFFSET])
        chunks_dir = out_dir / "decompressed_xchunks"
        chunks_dir.mkdir(parents=True, exist_ok=True)

        chunk_reports = []
        offset = 0
        stream = 0
        index = 0
        total_decompressed = 0
        chunk_errors = []

        with tempfile.TemporaryDirectory(prefix="ff_xmem_") as temp_name, zone_path.open("wb") as zone_out:
            temp_dir = Path(temp_name)
            while offset + 4 <= len(payload):
                # Vanilla-buffer windowing: skip the zero padding the linker
                # inserts so a 4-byte chunk-size header never straddles a
                # VANILLA_BUFFER_SIZE boundary (measured from the file start).
                vanilla_offset = (PAYLOAD_OFFSET + offset) % VANILLA_BUFFER_SIZE
                if vanilla_offset + 4 > VANILLA_BUFFER_SIZE:
                    offset += VANILLA_BUFFER_SIZE - vanilla_offset
                    if offset + 4 > len(payload):
                        break
                size_field_offset = PAYLOAD_OFFSET + offset
                chunk_size = be_u32(payload, offset)
                offset += 4
                if chunk_size == 0:
                    break
                if chunk_size > XCHUNK_SIZE:
                    if allow_partial_zone:
                        chunk_errors.append(
                            {
                                "index": index,
                                "stream": stream,
                                "size_field_offset": size_field_offset,
                                "error": f"invalid xchunk size {chunk_size}",
                            }
                        )
                        break
                    raise ValueError(f"invalid xchunk size {chunk_size} at 0x{size_field_offset:08X}")
                if offset + chunk_size > len(payload):
                    if allow_partial_zone:
                        chunk_errors.append(
                            {
                                "index": index,
                                "stream": stream,
                                "size_field_offset": size_field_offset,
                                "error": "xchunk extends past EOF",
                            }
                        )
                        break
                    raise ValueError(f"xchunk at 0x{size_field_offset:08X} extends past EOF")

                encrypted = payload[offset : offset + chunk_size]
                decrypted, iv, digest = decryptor.decrypt(stream, encrypted)
                dec_path = chunks_dir / f"{index:06d}_stream{stream}_file{size_field_offset:08x}.bin"
                if compression == "lzx":
                    xmem_path = temp_dir / f"{index:06d}.xmem"
                    xmem_path.write_bytes(decrypted)

                    completed = subprocess.run(
                        [str(helper_path), str(xmem_path), str(dec_path)],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        **_no_window_run_kwargs(),
                    )
                    if completed.returncode != 0:
                        if allow_partial_zone:
                            chunk_errors.append(
                                {
                                    "index": index,
                                    "stream": stream,
                                    "size_field_offset": size_field_offset,
                                    "encrypted_size": chunk_size,
                                    "salsa20_iv_hex": iv.hex(),
                                    "decrypted_sha1_hex": digest.hex(),
                                    "error": completed.stderr.strip(),
                                }
                            )
                            break
                        raise ValueError(
                            "LZX helper failed for "
                            f"chunk {index} at 0x{size_field_offset:08X}: {completed.stderr.strip()}"
                        )
                    decompressed = dec_path.read_bytes()
                else:
                    # TAff0100 Xbox 360 BO2 zones observed here use the same
                    # encrypted xchunk framing as TAffx100, but the decrypted
                    # chunk body is a raw deflate stream with no zlib header.
                    try:
                        decompressed = zlib.decompress(decrypted, wbits=-15)
                    except zlib.error as exc:
                        if allow_partial_zone:
                            chunk_errors.append(
                                {
                                    "index": index,
                                    "stream": stream,
                                    "size_field_offset": size_field_offset,
                                    "encrypted_size": chunk_size,
                                    "salsa20_iv_hex": iv.hex(),
                                    "decrypted_sha1_hex": digest.hex(),
                                    "error": f"raw deflate failed: {exc}",
                                }
                            )
                            break
                        raise ValueError(
                            f"raw deflate failed for chunk {index} at 0x{size_field_offset:08X}: {exc}"
                        ) from exc
                    dec_path.write_bytes(decompressed)

                zone_out.write(decompressed)
                total_decompressed += len(decompressed)
                chunk_reports.append(
                    {
                        "index": index,
                        "stream": stream,
                        "size_field_offset": size_field_offset,
                        "encrypted_size": chunk_size,
                        "decompressed_size": len(decompressed),
                        "salsa20_iv_hex": iv.hex(),
                        "decrypted_sha1_hex": digest.hex(),
                        "decompressed_path": str(dec_path),
                    }
                )

                offset += chunk_size
                stream = (stream + 1) % XCHUNK_STREAM_COUNT
                index += 1

        assets_out = out_dir / "assets"
        if assets_out.exists():
            shutil.rmtree(assets_out)
        zone_data = zone_path.read_bytes()
        parser_warnings: list[str] = []

        try:
            top_level = parse_top_level_t6_zone(zone_data)
        except (ValueError, struct.error) as exc:
            # Keep going after exploratory table-parser failures. Embedded
            # script blobs are found by a local self-describing pattern and do
            # not require the top-level asset stream to be fully understood.
            parser_warnings.append(f"top-level zone parse failed: {exc}")
            top_level = {
                "status": "parse_failed",
                "error": str(exc),
                "parsed_stream_offset_after_top_level_tables": 0,
            }

        if top_level.get("status") == "parse_failed":
            asset_entry_tables = {"status": "skipped", "reason": "top-level zone parse failed"}
            scriptparsetree_candidates = {"status": "skipped", "reason": "top-level zone parse failed"}
            menudef_candidates = {"status": "skipped", "reason": "top-level zone parse failed"}
            recoverable_prefix_assets = {"status": "skipped", "reason": "top-level zone parse failed"}
            asset_stream_trace = {"status": "skipped", "reason": "top-level zone parse failed"}
        else:
            try:
                asset_entry_tables = write_asset_entry_tables(top_level, out_dir)
            except (OSError, ValueError, struct.error) as exc:
                parser_warnings.append(f"asset entry table write failed: {exc}")
                asset_entry_tables = {"status": "failed", "error": str(exc)}
            try:
                scriptparsetree_candidates = scan_scriptparsetree_candidates(zone_data, top_level, out_dir)
            except (OSError, ValueError, struct.error) as exc:
                parser_warnings.append(f"scriptparsetree candidate scan failed: {exc}")
                scriptparsetree_candidates = {"status": "failed", "error": str(exc)}
            if scan_menus:
                try:
                    menudef_candidates = scan_menudef_candidates(zone_data, top_level, out_dir)
                except (OSError, ValueError, struct.error) as exc:
                    parser_warnings.append(f"menuDef diagnostic scan failed: {exc}")
                    menudef_candidates = {"status": "failed", "error": str(exc)}
            else:
                menudef_candidates = {
                    "status": "skipped",
                    "reason": "Use --scan-menus to run the slower menuDef_t diagnostic probe.",
                }
            try:
                recoverable_prefix_assets = extract_recoverable_prefix_assets(zone_data, top_level, out_dir)
            except (OSError, ValueError, struct.error) as exc:
                parser_warnings.append(f"recoverable prefix asset extraction failed: {exc}")
                recoverable_prefix_assets = {"status": "failed", "error": str(exc)}
            try:
                asset_stream_trace = write_asset_stream_trace(zone_data, top_level, recoverable_prefix_assets, out_dir)
            except (OSError, ValueError, struct.error) as exc:
                parser_warnings.append(f"asset stream trace write failed: {exc}")
                asset_stream_trace = {"status": "failed", "error": str(exc)}
        embedded_scripts = extract_embedded_script_blobs(zone_data, out_dir)
        embedded_lua = extract_embedded_lua_blobs(zone_data, out_dir)
        embedded_menu = extract_embedded_menu_blobs(zone_data, out_dir)
        try:
            zone_patch_manifest = write_zone_patch_manifest(out_dir)
        except (OSError, ValueError) as exc:
            parser_warnings.append(f"zone patch manifest write failed: {exc}")
            zone_patch_manifest = {"status": "failed", "error": str(exc)}
        if top_level.get("script_strings", {}).get("strings"):
            script_strings_path = out_dir / "script_strings.txt"
            script_strings_path.write_text(
                "\n".join(
                    "" if item["value"] is None else str(item["value"])
                    for item in top_level["script_strings"]["strings"]
                )
                + "\n",
                encoding="utf-8",
            )
            top_level["script_strings"]["text_dump_path"] = str(script_strings_path)
        if top_level.get("depends", {}).get("strings"):
            depends_path = out_dir / "depends.txt"
            depends_path.write_text(
                "\n".join(
                    "" if item["value"] is None else str(item["value"])
                    for item in top_level["depends"]["strings"]
                )
                + "\n",
                encoding="utf-8",
            )
            top_level["depends"]["text_dump_path"] = str(depends_path)
        return {
            "path": str(zone_path),
            "size": len(zone_data),
            "sha256": hashlib.sha256(zone_data).hexdigest(),
            "chunk_count": len(chunk_reports),
            "total_decompressed_from_chunks": total_decompressed,
            "partial_zone": bool(chunk_errors),
            "chunk_errors": chunk_errors,
            "parser_warnings": parser_warnings,
            "prefix": parse_decompressed_zone_prefix(zone_data[:64]),
            "top_level_zone": top_level,
            "post_asset_table_window": hex_sample(
                zone_data,
                top_level.get("parsed_stream_offset_after_top_level_tables", 0)
                if isinstance(top_level.get("parsed_stream_offset_after_top_level_tables"), int)
                else 0,
                256,
            ),
            "asset_entry_tables": asset_entry_tables,
            "scriptparsetree_candidates": scriptparsetree_candidates,
            "menudef_candidates": menudef_candidates,
            "recoverable_prefix_assets": recoverable_prefix_assets,
            "asset_stream_trace": asset_stream_trace,
            "embedded_scripts": embedded_scripts,
            "embedded_lua": embedded_lua,
            "embedded_menu": embedded_menu,
            "zone_patch_manifest": zone_patch_manifest,
            "readable_string_inventory": build_readable_string_inventory(zone_data, out_dir),
            "first_64_bytes": hex_sample(zone_data, 0, 64),
            "chunks": chunk_reports,
        }


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=False), encoding="utf-8")


def build_xbox360_lzx_chunk_plan(zone_size: int) -> list[int]:
    """Split exactly like Xbox 360 LZX fastfiles: 0x28, then 0x7FC0 blocks."""

    plan: list[int] = []
    remaining = zone_size
    if remaining <= 0:
        return plan
    first_size = min(XFILE_HEADER_CHUNK_SIZE, remaining)
    plan.append(first_size)
    remaining -= first_size
    while remaining > 0:
        size = min(XCHUNK_MAX_WRITE_SIZE, remaining)
        plan.append(size)
        remaining -= size
    return plan


def fastfile_name_from_header(header: bytes, fallback: str) -> str:
    raw_name = header[0x18 : 0x18 + 32].split(b"\x00", 1)[0]
    if not raw_name:
        return fallback[:31]
    return raw_name.decode("ascii", errors="replace")[:31]


def xmem_compress_zone_records(
    zone_path: Path,
    chunk_size: int,
    first_chunk_size: int = XFILE_HEADER_CHUNK_SIZE,
    chunk_plan: list[int] | None = None,
    log=None,
) -> list[bytes]:
    """Compress a decompressed zone into per-chunk XMem/LZX records."""

    helper_path = _xmem_compress_helper_path()
    if not helper_path.exists():
        raise FileNotFoundError(
            f"{helper_path} not found. Build it with: "
            "csc.exe /platform:x86 /optimize+ /out:_tools\\xmem_compress.exe tools\\xmem_compress.cs"
        )

    with tempfile.TemporaryDirectory(prefix="ff_xmem_compress_") as temp_name:
        chunks_path = Path(temp_name) / "chunks.xmemstream"
        plan_path = Path(temp_name) / "chunk_plan.txt"
        plan_arg = ""
        if chunk_plan is not None:
            plan_path.write_text("".join(f"{size:X}\n" for size in chunk_plan), encoding="ascii")
            plan_arg = str(plan_path)
        proc = subprocess.run(
            [
                str(helper_path),
                str(zone_path.resolve()),
                str(chunks_path),
                f"{chunk_size:X}",
                "",
                f"{first_chunk_size:X}",
                plan_arg,
            ],
            cwd=str(SCRIPT_DIR),
            capture_output=True,
            text=True,
            **_no_window_run_kwargs(),
        )
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()
            raise RuntimeError(f"xmem_compress failed with exit code {proc.returncode}: {detail}")
        if log and proc.stderr.strip():
            log(proc.stderr.strip())

        data = chunks_path.read_bytes()

    records: list[bytes] = []
    offset = 0
    while offset < len(data):
        if offset + 4 > len(data):
            raise ValueError("truncated xmem_compress length prefix")
        size = struct.unpack_from("<I", data, offset)[0]
        offset += 4
        if size == 0:
            raise ValueError("xmem_compress produced an empty chunk")
        end = offset + size
        if end > len(data):
            raise ValueError("truncated xmem_compress chunk payload")
        records.append(data[offset:end])
        offset = end
    return records


def repack_fastfile_from_folder(folder: Path, out_ff: Path, log=None, recompile: bool = True) -> dict[str, Any]:
    """Rebuild a FastFile from an unpacked folder.

    The folder must contain `zone_decompressed.dat` (the full decompressed zone).
    When `recompile` is set and a `zone_patch_manifest.json` is present, edited
    sources under `scripts_src/` (GSC/CSC via gsc-tool) and `ui_lua_readable/`
    (Lua via lua_tool) are recompiled and spliced back into the zone first (see
    `zone_rebuild.recompile_and_rebuild`). Output is a `TAffx100` (LZX)
    FastFile: the zone is re-chunked, XMem/LZX-compressed, and Salsa20-encrypted with the
    same name-seeded IV chain the game regenerates. The original 0x138-byte header
    (`ff_header.bin`) is reused when present so the fastfile name and 256-byte
    signature blob are preserved. The magic is forced to `TAffx100` because we emit
    LZX chunks through Microsoft's XNA `XnaNative.dll` XMem encoder.
    """

    def _log(message: str) -> None:
        if log:
            log(message)

    zone_path = folder / "zone_decompressed.dat"
    if not zone_path.exists():
        raise FileNotFoundError(
            f"zone_decompressed.dat not found in {folder}. Repack needs a folder produced by unpacking."
        )

    recompile_result: dict[str, Any] | None = None
    if recompile and (folder / "zone_patch_manifest.json").exists():
        try:
            import zone_rebuild

            recompile_result = zone_rebuild.recompile_and_rebuild(folder, log=log)
            if recompile_result.get("changed"):
                _log(
                    f"Recompiled {recompile_result['changed']} edited source(s); "
                    f"zone byte delta {recompile_result.get('byte_delta', 0):+d}."
                )
            if recompile_result.get("errors"):
                _log(f"WARNING: {len(recompile_result['errors'])} source(s) failed to recompile; see result.")
            link_warnings = recompile_result.get("link_warnings") or []
            if link_warnings:
                # These build a .ff that the game will refuse to load, so they are
                # worth shouting about even though the repack itself succeeded.
                _log(
                    f"WARNING: {len(link_warnings)} link problem(s) in the recompiled script(s). "
                    "The .ff will build, but the map may fail to load."
                )
        except Exception as exc:  # noqa: BLE001 - repack should still work from the raw zone
            recompile_result = {"status": "failed", "error": str(exc)}
            _log(f"WARNING: recompile step failed ({exc}); repacking the zone as-is.")

    zone = zone_path.read_bytes()
    stem = out_ff.stem

    header_path = folder / "ff_header.bin"
    if header_path.exists() and header_path.stat().st_size >= PAYLOAD_OFFSET:
        header = bytearray(header_path.read_bytes()[:PAYLOAD_OFFSET])
    else:
        header = bytearray(PAYLOAD_OFFSET)
        header[0x08:0x0C] = (0x92).to_bytes(4, "big")
        header[0x0C:0x10] = b"PHEE"
        header[0x10:0x14] = b"Bs71"
        _log("ff_header.bin not found; synthesizing a minimal header (signature will be zeroed).")

    # We emit XMem/LZX chunks, so the magic must select the LZX loader path.
    header[0:8] = b"TAffx100"
    zone_name = fastfile_name_from_header(header, stem)
    name_bytes = zone_name.encode("ascii", "replace")[:31]
    header[0x18 : 0x18 + 32] = name_bytes + b"\x00" * (32 - len(name_bytes))

    encryptor = OatSalsa20ChunkDecryptor(zone_name)
    out = bytearray(header)
    chunk_plan = build_xbox360_lzx_chunk_plan(len(zone))
    _log(f"Using Xbox 360 LZX chunk split: first 0x{XFILE_HEADER_CHUNK_SIZE:X}, then 0x{XCHUNK_MAX_WRITE_SIZE:X} ({len(chunk_plan)} chunks).")

    compressed_chunks = xmem_compress_zone_records(
        zone_path,
        XCHUNK_MAX_WRITE_SIZE,
        first_chunk_size=XFILE_HEADER_CHUNK_SIZE,
        chunk_plan=chunk_plan,
        log=log,
    )
    # Reproduce the Xbox 360 LZX chunk stream exactly: first the 0x28-byte XFile
    # header chunk, then 0x7FC0-byte chunks until EOF. Each chunk is
    # XMem/LZX-compressed then Salsa20-encrypted and written as
    # [be32 size][data] cycling XCHUNK_STREAM_COUNT streams, and the 4-byte size
    # header is never allowed to straddle a VANILLA_BUFFER_SIZE window (measured
    # from the start of the file, so the offset starts at the header length).
    # The game's reader depends on this windowing and asserts size < XCHUNK_SIZE;
    # omitting it makes every load past the first 0x80000 boundary read a bogus
    # size and crash.
    vanilla_offset = len(out) % VANILLA_BUFFER_SIZE
    stream = 0
    chunk_count = 0
    for raw in compressed_chunks:
        ciphertext, _iv, _digest = encryptor.encrypt(stream, raw)
        chunk_size = len(ciphertext)
        if chunk_size >= XCHUNK_SIZE:
            raise ValueError(f"compressed chunk {chunk_count} is >= XCHUNK_SIZE: {chunk_size} bytes")
        if vanilla_offset + 4 > VANILLA_BUFFER_SIZE:
            out += b"\x00" * (VANILLA_BUFFER_SIZE - vanilla_offset)
            vanilla_offset = 0
        out += chunk_size.to_bytes(4, "big")
        out += ciphertext
        vanilla_offset = (vanilla_offset + 4 + chunk_size) % VANILLA_BUFFER_SIZE
        stream = (stream + 1) % XCHUNK_STREAM_COUNT
        chunk_count += 1
    # End-of-file zero suffix: the reader treats a zero size as EOF, and the
    # original linker pads the tail with >= FILE_SUFFIX_ZERO_MIN_SIZE zeros
    # aligned to FILE_SUFFIX_ZERO_ALIGN ("the game's reader needs it").
    out += b"\x00" * FILE_SUFFIX_ZERO_MIN_SIZE
    if len(out) % FILE_SUFFIX_ZERO_ALIGN:
        out += b"\x00" * (FILE_SUFFIX_ZERO_ALIGN - (len(out) % FILE_SUFFIX_ZERO_ALIGN))

    out_ff.write_bytes(out)
    _log(f"Repacked {chunk_count} chunk(s) -> {out_ff.name} ({len(out)} bytes)")
    return {
        "output": str(out_ff),
        "chunks": chunk_count,
        "zone_size": len(zone),
        "ff_size": len(out),
        "used_original_header": header_path.exists(),
        "recompile": recompile_result,
    }


def repack_fastfile_from_zip(zip_path: Path, out_ff: Path | None = None, log=None) -> dict[str, Any]:
    """Repack a `<name>.zip` of an unpacked folder into `<name>.ff`.

    The archive is expected to contain the unpacked folder (the one holding
    `zone_decompressed.dat`), typically named after the FastFile. Output goes to
    `<name>.ff` beside the zip unless `out_ff` is given.
    """
    import tempfile
    import zipfile

    stem = zip_path.stem
    if out_ff is None:
        out_ff = zip_path.with_suffix(".ff")

    with tempfile.TemporaryDirectory(prefix="ff_repack_") as tmp:
        tmp_dir = Path(tmp)
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(tmp_dir)
        # Locate the folder that contains zone_decompressed.dat.
        candidates = [zone.parent for zone in tmp_dir.rglob("zone_decompressed.dat")]
        if not candidates:
            raise FileNotFoundError(
                f"{zip_path.name} does not contain a zone_decompressed.dat "
                "(zip the unpacked folder produced by the unpacker)."
            )
        # Prefer a folder matching the archive name, else the shallowest one.
        folder = next((c for c in candidates if c.name == stem), None)
        if folder is None:
            folder = min(candidates, key=lambda p: len(p.parts))
        return repack_fastfile_from_folder(folder, out_ff, log=log)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        epilog="crybaby's repacker - BO2 Xbox 360 FastFile unpacker / repacker",description="Cautious Xbox 360 BO2 .ff scanner/unpacker scaffold")
    parser.add_argument("fastfile", type=Path, nargs="?", help="Input Xbox 360 BO2 .ff file to unpack")
    parser.add_argument(
        "--repack",
        type=Path,
        default=None,
        metavar="ZIP_OR_FOLDER",
        help="Repack a folder .zip (or unpacked folder) into a .ff instead of unpacking",
    )
    parser.add_argument(
        "--recompile",
        type=Path,
        default=None,
        metavar="FOLDER",
        help="Recompile edited scripts_src/ (and Lua) and splice them back into the folder's zone_decompressed.dat, without producing a .ff",
    )
    parser.add_argument(
        "--no-recompile",
        action="store_true",
        help="During --repack, do NOT recompile edited sources; repack the zone as-is",
    )
    parser.add_argument("-o", "--out", type=Path, default=None, help="Output directory (unpack) or output .ff (repack)")
    parser.add_argument("--metadata", type=Path, default=None, help="Metadata JSON path")
    parser.add_argument("--verbose", action="store_true", help="Print parse progress to stderr")
    parser.add_argument("--dump-unknown", action="store_true", help="Dump unresolved raw regions, including signature/payload")
    parser.add_argument("--dump-decrypted-xchunks", action="store_true", help="Dump Salsa20-decrypted xchunks before LZX inflate")
    parser.add_argument("--decompress-zone", action="store_true", help="Use the LZX helper to write zone_decompressed.dat")
    parser.add_argument(
        "--allow-partial-zone",
        action="store_true",
        help="Keep and scan a partial zone if a later compressed chunk fails",
    )
    parser.add_argument("--scan-menus", action="store_true", help="Run slower menuDef_t diagnostic probing")
    parser.add_argument(
        "--lzx-helper",
        type=Path,
        default=SCRIPT_DIR / "_tools" / "xmem_lzx_decompress.exe",
        help="Path to xmem_lzx_decompress helper",
    )
    parser.add_argument("--no-decrypt-probe", action="store_true", help="Skip low-confidence Salsa20 nonce probes")
    args = parser.parse_args(argv)

    if args.recompile is not None:
        import zone_rebuild

        folder = args.recompile
        if not folder.is_dir():
            print(f"error: --recompile folder does not exist: {folder}", file=sys.stderr)
            return 2
        try:
            result = zone_rebuild.recompile_and_rebuild(folder, log=lambda m: print(m, file=sys.stderr))
        except (OSError, ValueError, FileNotFoundError) as exc:
            print(f"error: recompile failed: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(result, indent=2))
        return 0 if not result.get("errors") else 1

    if args.repack is not None:
        source = args.repack
        if not source.exists():
            print(f"error: repack source does not exist: {source}", file=sys.stderr)
            return 2
        try:
            if source.is_dir():
                out_ff = args.out or source.with_suffix(".ff")
                result = repack_fastfile_from_folder(
                    source, out_ff, log=lambda m: print(m, file=sys.stderr), recompile=not args.no_recompile
                )
            else:
                result = repack_fastfile_from_zip(source, args.out, log=lambda m: print(m, file=sys.stderr))
        except (OSError, ValueError, FileNotFoundError) as exc:
            print(f"error: repack failed: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(result, indent=2))
        return 0

    if args.fastfile is None:
        parser.error("a fastfile is required unless --repack is used")
    if not args.fastfile.exists():
        print(f"error: input file does not exist: {args.fastfile}", file=sys.stderr)
        return 2
    if not args.fastfile.is_file():
        print(f"error: input path is not a file: {args.fastfile}", file=sys.stderr)
        return 2

    out_dir = args.out or Path(f"{args.fastfile.stem}_ff_scan")
    metadata_path = args.metadata or out_dir / "metadata.json"

    try:
        scanner = FastFileScanner(args.fastfile, verbose=args.verbose)
        metadata = scanner.scan(probe_decrypt=not args.no_decrypt_probe)
        out_dir.mkdir(parents=True, exist_ok=True)
        if args.dump_unknown:
            metadata["raw_dumps"] = scanner.dump_unknown_regions(out_dir)
        if args.dump_decrypted_xchunks:
            metadata["decrypted_xchunk_dumps"] = scanner.dump_decrypted_xchunks(out_dir)
        if args.decompress_zone:
            metadata["decompressed_zone"] = scanner.decompress_zone_stream(
                out_dir,
                args.lzx_helper,
                scan_menus=args.scan_menus,
                allow_partial_zone=args.allow_partial_zone,
            )
        write_json(metadata_path, metadata)
    except (OSError, ValueError, struct.error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.verbose:
        print(f"wrote metadata: {metadata_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
