#!/usr/bin/env python3
"""Pointer-relocating zone rebuilder for BO2 fastfiles.

Growing an asset inside a zone shifts every later allocation in the same XBlock, which
invalidates every encoded pointer that targets past the insertion point. Encoded pointers
are stored as ``((block << 29) | offset) + 1`` and resolved by ``DB_ConvertOffsetToPointer``
(``0x822CC358``) against the destination XBlock bases.

Rather than reverse ~60 asset structs to find pointer fields statically, the field set is
captured from a live load by hooking the loader's own ``DB_ConvertOffsetToPointer`` /
``DB_ConvertOffsetToAlias``, together with the stream->destination map from
``DB_LoadXFileData`` / ``DB_LoadXFileDataNullTerminated``. That is ground truth by
construction.

Capture record format (12 bytes, little-endian): ``{u32 kind, u32 a, u32 b}``

===== ==================================================== ==========================
kind   hooked function                                      meaning
===== ==================================================== ==========================
1      ``DB_LoadXFileData(dest, size)``      0x822AD610      sequential stream read
2      ``DB_ConvertOffsetToPointer(field)``  0x822CC358      field addr + encoded value
3      ``DB_ConvertOffsetToAlias(field)``    0x822CC330      same, plus one deref
4      XBlock base                                           index + guest base
5      ``DB_LoadXFileDataNullTerminated()``  0x822AD760      string read (length implied)
===== ==================================================== ==========================

XBlock bases are read from ``*(u32*)0x832DE59C``, an array of 8-byte entries with ``.data``
first. Kind 5 must be captured too: string reads go through it, and without them ~82 KB of
the stream is unmapped and some pointer fields cannot be located.

Two requirements that are easy to get wrong, both established by measurement:

* **Resolve fields temporally, not by address.** XBlock 0 is a push/pop scratch block whose
  addresses are rewritten many times during a load (one field there was observed holding
  five different encoded pointers). Resolving by address alone attributes a field to the
  wrong write, and silently mis-attributes block-0 addresses to neighbouring block-5
  segments.
* **Round every growth up to a multiple of 4096.** The loader pads each allocation to an
  alignment boundary, so the shift later allocations experience is *not* the raw byte delta:
  a raw +4183-byte payload moved later block-5 allocations by exactly +4096. Relocating by
  the raw delta leaves every pointer 87 bytes short and crashes material loading.
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
STREAM_BLOCKS_PTR = 0x832DE59C

#: Allocation alignment the loader pads to. Growths are rounded up to a multiple of this so
#: that the shift later allocations experience equals the delta exactly, for any
#: power-of-two alignment that divides it.
ALIGN = 4096


def align_growth(raw_delta: int) -> int:
    """Round a positive byte growth up to a multiple of :data:`ALIGN`."""
    if raw_delta <= 0:
        return raw_delta
    return ((raw_delta + ALIGN - 1) // ALIGN) * ALIGN


class ZoneMap:
    """Stream<->guest-address map and pointer table for one zone.

    Resolution is TEMPORAL, not just positional -- see the module docstring.
    """

    def __init__(self, dump: pathlib.Path, zone: bytes):
        raw = pathlib.Path(dump).read_bytes()
        recs = [struct.unpack_from("<3I", raw, i * 12) for i in range(len(raw) // 12)]
        self.bases = {a: b for k, a, b in recs if k == 4}
        if not any(self.bases.values()):
            raise ValueError("capture contains no XBlock bases (kind 4 records)")
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
                sizes[idx] = struct.unpack_from(">I", zone, HDR_BLOCK0 + 4 * idx)[0] + ALIGN
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

    def locate(self, stream_off: int) -> tuple[int, int]:
        """Map a stream offset to ``(block index, block offset)``."""
        for so, dest, size in self.segs:
            if so <= stream_off < so + size:
                loc = self.block_of(dest + (stream_off - so))
                if loc is None:
                    break
                return loc
        raise ValueError("stream offset 0x%X is not inside any captured read" % stream_off)


def relocate_multi(zone: bytes, zmap: ZoneMap, insertions, log=None, align=None):
    """Open one or more aligned gaps in `zone`, relocating every affected pointer.

    `insertions` is an iterable against the *pristine* zone, each either

    * ``(stream_offset, delta)`` -- the shift threshold is derived from
      ``stream_offset`` itself, or
    * ``(stream_offset, delta, block, threshold_offset)`` -- an explicit threshold.

    Prefer the explicit form when growing an asset. The byte *after* a buffer often
    belongs to the next read, which may target a **different XBlock** entirely (a
    ScriptParseTree buffer ends in XBlock 5 but the following read went to XBlock 0),
    and deriving the threshold from it silently relocates nothing and grows the wrong
    block. Compute the threshold from the buffer's own start instead:
    ``block, off = zmap.locate(buffer_offset)`` then ``threshold = off + old_span``.

    Each delta must already be a multiple of :data:`ALIGN` (see :func:`align_growth`).
    Callers with a measured asset-specific alignment may override that check with
    ``align``; localization asset arrays, for example, are contiguous 8-byte records and
    must not receive the general 4 KiB allocation padding.
    Returns ``(new_zone_bytes, report_dict)``; the caller fills the gaps.
    """
    def say(msg):
        if log:
            log(msg)

    required_align = ALIGN if align is None else align
    if required_align <= 0:
        raise ValueError("alignment must be positive")

    plan = []
    for item in sorted(insertions, key=lambda x: x[0]):
        stream_off, delta = item[0], item[1]
        if delta <= 0:
            continue
        if delta % required_align:
            raise ValueError("growth %d at 0x%X is not a multiple of %d"
                             % (delta, stream_off, required_align))
        if len(item) >= 4:
            block, block_off = item[2], item[3]
        else:
            block, block_off = zmap.locate(stream_off)
        plan.append((stream_off, delta, block, block_off))
        say("insert %+d at stream 0x%X, shifting XBlock %d from offset 0x%X"
            % (delta, stream_off, block, block_off))
    if not plan:
        return zone, {"relocated": 0, "unresolved": 0, "insertions": 0, "byte_delta": 0}

    out = bytearray(zone)
    relocated = unresolved = 0
    for field_stream_off, encoded, _field_addr in zmap.ptrs:
        v = encoded - 1
        tblock, toff = (v >> 29) & 7, v & 0x1FFFFFFF
        # A pointer shifts by every insertion that lands at or before its target, in the
        # same block.
        shift = sum(d for _o, d, blk, boff in plan if blk == tblock and toff >= boff)
        if not shift:
            continue
        if struct.unpack_from(">I", out, field_stream_off)[0] != encoded:
            unresolved += 1
            continue
        struct.pack_into(">I", out, field_stream_off, encoded + shift)
        relocated += 1

    # Apply the gaps back-to-front so earlier offsets stay valid.
    for stream_off, delta, _blk, _boff in sorted(plan, key=lambda x: -x[0]):
        out[stream_off:stream_off] = bytes(delta)

    total_delta = sum(d for _o, d, _b, _bo in plan)
    total = struct.unpack_from(">I", out, HDR_STREAM_SIZE)[0]
    struct.pack_into(">I", out, HDR_STREAM_SIZE, total + total_delta)
    per_block: dict[int, int] = {}
    for _o, d, blk, _bo in plan:
        per_block[blk] = per_block.get(blk, 0) + d
    for blk, d in per_block.items():
        slot = HDR_BLOCK0 + 4 * blk
        old = struct.unpack_from(">I", out, slot)[0]
        struct.pack_into(">I", out, slot, old + d)
        say("XBlock[%d] %d -> %d" % (blk, old, old + d))
    say("stream size %d -> %d" % (total, total + total_delta))
    say("pointers relocated %d, unresolved %d" % (relocated, unresolved))
    if unresolved:
        say("WARNING: %d pointers need relocation but could not be rewritten" % unresolved)

    return bytes(out), {
        "relocated": relocated,
        "unresolved": unresolved,
        "insertions": len(plan),
        "byte_delta": total_delta,
    }


def relocate(zone: bytes, zmap: ZoneMap, insert_stream_off: int, delta: int) -> bytes:
    """Single-insertion convenience wrapper around :func:`relocate_multi`."""
    out, _report = relocate_multi(zone, zmap, [(insert_stream_off, delta)], log=print)
    return out


if __name__ == "__main__":
    zone = PRISTINE.read_bytes()
    zmap = ZoneMap(DUMP, zone)
    print("pointers resolved %d, stream mapped %d of %d bytes"
          % (len(zmap.ptrs), zmap.stream_end, len(zone)))
    print("pointer fields not written from the stream: %d" % zmap.unstreamed)
