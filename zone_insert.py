#!/usr/bin/env python3
"""Add whole new assets to a decompressed zone.

`reloc.py` makes an existing asset *bigger*. This makes the zone hold *more* assets, which
is a different edit: the XAssetList's asset array grows, every later allocation shifts, and
the new bodies have to land in the block the loader will read them into.

The mechanism is asset-type agnostic, which is the point of this module. Only the body
bytes differ per type, so a caller that can serialize a body can add any asset:

    zone, report = zone_insert.insert(zone, zmap, [(LOCALIZE_ENTRY, body), ...])

Four steps, in this order, because each depends on the last:

1. **Grow the asset array by n*8 bytes**, at its end, via `reloc.relocate_multi`. This is
   the part that shifts things: the array is one `assetCount * 8` read, so every later
   allocation in its block moves and every encoded pointer past it needs relocating.
   The growth is *not* rounded up to the 4 KiB allocation padding a script buffer needs --
   padding the array would leave bytes the loader never consumes and desync every body
   after it. The array's alignment is 8, its own record size.
2. **Fill the new slots** with `{u32 type, 0xFFFFFFFF}`. `relocate_multi` leaves the gap
   zeroed, and a zeroed slot is asset type 0.
3. **Append the bodies** at the end of the stream. Nothing follows the end, so this shifts
   nothing and needs no relocation -- but only if the tail really belongs to the block the
   bodies must load into, which is checked rather than assumed.
4. **Bump assetCount, the stream size and the owning XBlock size.** Step 1 already
   accounted for the array growth; only the appended bodies are still unrecorded.

What this does NOT do is resolve dependencies. A body containing an encoded pointer is
only valid if whatever it points at is really in the zone at that block and offset. For a
self-contained asset (a LocalizeEntry is two inline strings) there is nothing to resolve;
for an XModel there is a great deal, and that belongs to the caller building the body.
"""
from __future__ import annotations

import struct

import reloc

FOLLOWING = 0xFFFFFFFF
HDR = 40                    # XFile header: streamSize, externalSize, blockSize[8]
HDR_STREAM_SIZE = 0x00
HDR_BLOCKS = 0x08
ASSET_LIST_SIZE = 24        # scriptStrings(2 fields) + depends(2) + assetCount + assets
ARRAY_ALIGN = 8             # one asset-array record; see step 1


class InsertError(RuntimeError):
    pass


def parse(zone: bytes) -> dict:
    """Header and asset-array geometry of a decompressed zone."""
    if len(zone) < HDR + ASSET_LIST_SIZE:
        raise InsertError("too short to be a zone")
    stream_size = struct.unpack_from(">I", zone, HDR_STREAM_SIZE)[0]
    blocks = list(struct.unpack_from(">8I", zone, HDR_BLOCKS))
    asset_count = struct.unpack_from(">I", zone, HDR + 16)[0]
    array_off = HDR + ASSET_LIST_SIZE
    array_size = asset_count * 8
    if array_off + array_size > len(zone):
        raise InsertError(f"asset array ({asset_count} entries) runs past the end of the zone")
    return {
        "stream_size": stream_size,
        "blocks": blocks,
        "asset_count": asset_count,
        "array_offset": array_off,
        "array_size": array_size,
    }


def asset_types(zone: bytes) -> list[int]:
    info = parse(zone)
    off = info["array_offset"]
    return [struct.unpack_from(">I", zone, off + i * 8)[0] for i in range(info["asset_count"])]


def insert(zone: bytes, zmap: reloc.ZoneMap, assets, log=None) -> tuple[bytes, dict]:
    """Append `assets` -- an iterable of ``(asset_type, body_bytes)`` -- to the zone."""
    def say(msg):
        if log:
            log(msg)

    assets = list(assets)
    if not assets:
        return zone, {"added": 0, "array_delta": 0, "body_delta": 0, "relocated": 0}

    info = parse(zone)
    count, array_off, array_size = info["asset_count"], info["array_offset"], info["array_size"]
    n = len(assets)
    bodies = b"".join(body for _type, body in assets)

    # The bodies go at the end of the stream, so the block that owns the last stream byte
    # is the block they will be read into. Derive it; do not assume the virtual block.
    try:
        tail_block, tail_off = zmap.locate(len(zone) - 1)
    except ValueError as exc:
        raise InsertError(f"cannot tell which XBlock owns the end of the stream: {exc}") from exc

    array_block, array_block_off = zmap.locate(array_off)
    say(f"{count} assets, array at stream {array_off} ({array_size} bytes) in XBlock "
        f"{array_block} at 0x{array_block_off:X}; stream tail is XBlock {tail_block}")
    say(f"adding {n} asset(s): {n * 8} array bytes + {len(bodies)} body bytes")

    # 1) grow the asset array
    insertions = [(array_off + array_size, n * 8, array_block, array_block_off + array_size)]
    grown, report = reloc.relocate_multi(zone, zmap, insertions, align=ARRAY_ALIGN,
                                         log=lambda m: say("   " + m))
    if report["unresolved"]:
        raise InsertError(f"{report['unresolved']} pointer(s) could not be relocated; "
                          "the capture does not match this zone")
    out = bytearray(grown)

    # 2) fill the new slots
    slot = array_off + array_size
    for i, (asset_type, _body) in enumerate(assets):
        struct.pack_into(">2I", out, slot + i * 8, asset_type, FOLLOWING)

    # 3) append the bodies
    out += bodies

    # 4) counts and sizes
    struct.pack_into(">I", out, HDR + 16, count + n)
    new_stream = struct.unpack_from(">I", out, HDR_STREAM_SIZE)[0] + len(bodies)
    struct.pack_into(">I", out, HDR_STREAM_SIZE, new_stream)
    block_field = HDR_BLOCKS + 4 * tail_block
    new_block = struct.unpack_from(">I", out, block_field)[0] + len(bodies)
    struct.pack_into(">I", out, block_field, new_block)

    say(f"assetCount {count} -> {count + n}, stream {info['stream_size']} -> {new_stream}, "
        f"XBlock[{tail_block}] -> {new_block}")

    result = {
        "added": n,
        "array_delta": n * 8,
        "body_delta": len(bodies),
        "relocated": report["relocated"],
        "asset_count": count + n,
        "tail_block": tail_block,
        "new_zone_size": len(out),
    }
    return bytes(out), result


def verify(zone: bytes, expected_added: int, before: dict) -> None:
    """Re-parse a written zone and check it agrees with itself."""
    info = parse(zone)
    if info["asset_count"] != before["asset_count"] + expected_added:
        raise InsertError("assetCount does not reflect the inserted assets")
    if info["stream_size"] != len(zone) - HDR:
        raise InsertError(f"stream size field {info['stream_size']} does not match the "
                          f"{len(zone) - HDR} bytes after the header")
    if info["array_offset"] + info["array_size"] > len(zone):
        raise InsertError("asset array runs past the end of the zone")
