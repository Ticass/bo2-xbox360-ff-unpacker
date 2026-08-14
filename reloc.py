#!/usr/bin/env python3
"""Pointer-relocating zone rebuilder for BO2 fastfiles.

Growing an asset inside a zone shifts every later allocation in the same XBlock, which
invalidates every encoded pointer that targets past the insertion point. Encoded pointers
are stored as ((block << 29) | offset) + 1 and resolved by DB_ConvertOffsetToPointer.

Rather than reverse ~60 asset structs to find pointer fields statically, the field set is
captured from a live load (scratchpad zone_ptrs.bin) by hooking the loader's own
DB_ConvertOffsetToPointer / DB_ConvertOffsetToAlias, together with the stream->destination
map from DB_LoadXFileData / DB_LoadXFileDataNullTerminated. That is ground truth by
construction.

Record format (12 bytes, little-endian): {u32 kind, u32 a, u32 b}
  1 = DB_LoadXFileData(dest=a, size=b)
  2 = DB_ConvertOffsetToPointer(field=a, encoded=b)
  3 = DB_ConvertOffsetToAlias(field=a, encoded=b)
  4 = XBlock base (index=a, guestBase=b)
  5 = DB_LoadXFileDataNullTerminated(dest=a)   -- length recovered from the zone bytes
"""
from __future__ import annotations

import array
import struct
import pathlib

NUL = bytes([0])
DUMP = pathlib.Path("zone_ptrs.bin")
PRISTINE = pathlib.Path("patch_zm_ff_scan/zone_decompressed.dat")
HDR_STREAM_SIZE = 0x00      # zone header [0]: total stream bytes after the 40-byte header
HDR_BLOCK0 = 0x08           # zone header [2..9]: the 8 XBlock sizes


class ZoneMap:
    """Stream<->guest-address map and pointer table for one zone.

    Resolution is TEMPORAL, not just positional. XBlock 0 is a push/pop scratch block whose
    addresses are written many times during a load (one field there was seen holding five
    different encoded pointers), so a purely address-based lookup attributes a field to the
    wrong write. Records are replayed in capture order and each pointer conversion is
    resolved against the read that most recently wrote that address.
    """

    def __init__(self, dump: pathlib.Path, zone: bytes):
        raw = dump.read_bytes()
        recs = [struct.unpack_from("<3I", raw, i * 12) for i in range(len(raw) // 12)]
        self.bases = {a: b for k, a, b in recs if k == 4}
        blocks = sorted((b, i) for i, b in self.bases.items() if b)

        def block_of(addr):
            best = None
            for base, idx in blocks:
                if addr >= base and (best is None or base > best[0]):
                    best = (base, idx)
            return None if best is None else (best[1], addr - best[0])

        self.block_of = block_of
        # Per-block array: block offset -> stream offset + 1 (0 means never written).
        sizes = {}
        for idx, base in self.bases.items():
            if base:
                sizes[idx] = struct.unpack_from(">I", zone, 0x08 + 4 * idx)[0] + 0x1000
        maps = {idx: array.array("I", bytes(4 * n)) for idx, n in sizes.items()}

        self.ptrs: list[tuple[int, int, int]] = []   # (field_stream_off, encoded, field_addr)
        self.segs: list[tuple[int, int, int]] = []   # (stream_off, dest, size), capture order
        self.unstreamed = 0
        pos = 0
        for kind, a, b in recs:
            if kind in (1, 5):
                if kind == 5:
                    end = zone.find(NUL, pos)
                    size = (end - pos + 1) if end >= 0 else 1
                else:
                    size = b
                self.segs.append((pos, a, size))
                loc = block_of(a)
                if loc is not None:
                    idx, off = loc
                    m = maps.get(idx)
                    if m is not None:
                        for j in range(size):
                            if off + j < len(m):
                                m[off + j] = pos + j + 1
                pos += size
            elif kind in (2, 3):
                loc = block_of(a)
                so = 0
                if loc is not None:
                    idx, off = loc
                    m = maps.get(idx)
                    if m is not None and off < len(m):
                        so = m[off]
                if so:
                    self.ptrs.append((so - 1, b, a))
                else:
                    self.unstreamed += 1
        self.stream_end = pos


def relocate(zone: bytes, zmap: ZoneMap, insert_stream_off: int, delta: int) -> bytes:
    """Insert `delta` bytes of slack at `insert_stream_off`, fixing up all pointers.

    Returns the new zone bytes with the gap opened (caller fills it); the header and every
    affected encoded pointer are already corrected.
    """
    seg = None
    for so, dest, size in zmap.segs:
        if so <= insert_stream_off < so + size:
            seg = (so, dest, size)
            break
    if seg is None:
        raise SystemExit("insertion point 0x%X is not inside any captured read" % insert_stream_off)
    ins_guest = seg[1] + (insert_stream_off - seg[0])
    ins_block, ins_off = zmap.block_of(ins_guest)
    print("insertion: stream 0x%X -> guest %08X = block %d offset 0x%X"
          % (insert_stream_off, ins_guest, ins_block, ins_off))

    out = bytearray(zone)
    fixed = skipped = unresolved = 0
    for field_stream_off, encoded, field_addr in zmap.ptrs:
        v = encoded - 1
        tblock, toff = (v >> 29) & 7, v & 0x1FFFFFFF
        if tblock != ins_block or toff < ins_off:
            skipped += 1
            continue
        if struct.unpack_from(">I", out, field_stream_off)[0] != encoded:
            unresolved += 1
            continue
        struct.pack_into(">I", out, field_stream_off, encoded + delta)
        fixed += 1
    print("pointers: %d relocated, %d untouched (before insert / other block), "
          "%d not written from stream, %d UNRESOLVED"
          % (fixed, skipped, zmap.unstreamed, unresolved))
    if unresolved:
        print("  WARNING: %d pointers need relocation but could not be rewritten" % unresolved)

    # Open the gap.
    out[insert_stream_off:insert_stream_off] = b"\x00" * delta
    # Header: total stream size and the owning XBlock both grow.
    total = struct.unpack_from(">I", out, HDR_STREAM_SIZE)[0]
    struct.pack_into(">I", out, HDR_STREAM_SIZE, total + delta)
    bslot = HDR_BLOCK0 + 4 * ins_block
    blk = struct.unpack_from(">I", out, bslot)[0]
    struct.pack_into(">I", out, bslot, blk + delta)
    print("header: stream %d -> %d, XBlock[%d] %d -> %d"
          % (total, total + delta, ins_block, blk, blk + delta))
    return bytes(out)


if __name__ == "__main__":
    zone = PRISTINE.read_bytes()
    zmap = ZoneMap(DUMP, zone)
    print("pointers resolved %d, stream mapped %d of %d bytes"
          % (len(zmap.ptrs), zmap.stream_end, len(zone)))
    print("pointer fields not written from the stream: %d" % zmap.unstreamed)
