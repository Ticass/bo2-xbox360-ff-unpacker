#!/usr/bin/env python3
"""Locate asset bodies in a decompressed zone, using a pointer capture as ground truth.

Asset bodies are variable-size and stored inline in array order with no index, so reaching
asset N normally means parsing bodies 0..N-1, and parsing a body means knowing that type's
exact layout including every nested allocation. That is a zone loader.

A capture makes it tractable without one. Every `DB_LoadXFileData(dest, size)` the loader
issued is recorded, in order, so the allocation boundaries are measured rather than
inferred -- and the loader consumes assets in array order, so segment order *is* asset
order. What remains is bookkeeping: deciding which segments belong to which asset.

The boundary signal used here is the asset name. Most T6 asset structs open with a
`const char* name`, and when it is inline (0xFFFFFFFF) the loader reads the string with
DB_LoadXFileDataNullTerminated -- a distinct record kind. So a fixed-size read followed by
a string read marks the start of an asset. That is a claim about the data, so
:func:`walk` checks it: the number of boundaries it finds has to equal the zone's own
assetCount, and it reports the discrepancy rather than guessing when it does not.

Capture record format (12 bytes each, little-endian) -- see reloc.py and bo2mp_hooks.cpp:
    1 = DB_LoadXFileData(dest, size)              sized read
    2 = DB_ConvertOffsetToPointer(field, encoded)
    3 = DB_ConvertOffsetToAlias(field, encoded)
    4 = XBlock base (index, guestBase)
    5 = DB_LoadXFileDataNullTerminated(dest)      string read, size found by the NUL
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

import zone_insert

KIND_READ = 1
KIND_STRING = 5


@dataclass
class Segment:
    stream_offset: int
    dest: int
    size: int
    kind: int


@dataclass
class Asset:
    index: int
    asset_type: int
    struct_offset: int          # stream offset of the fixed-size struct
    struct_size: int
    name: str | None = None
    segments: list[Segment] = field(default_factory=list)

    @property
    def end(self) -> int:
        last = self.segments[-1]
        return last.stream_offset + last.size

    @property
    def total_size(self) -> int:
        return self.end - self.struct_offset


def read_segments(capture: Path, zone: bytes) -> list[Segment]:
    """Every sized/string read, in load order, with the stream offset it consumed."""
    raw = Path(capture).read_bytes()
    segs: list[Segment] = []
    pos = 0
    for i in range(len(raw) // 12):
        kind, a, b = struct.unpack_from("<3I", raw, i * 12)
        if kind == KIND_READ:
            size = b
        elif kind == KIND_STRING:
            end = zone.find(b"\x00", pos)
            size = (end - pos + 1) if end >= 0 else 1
        else:
            continue
        segs.append(Segment(pos, a, size, kind))
        pos += size
    return segs


def walk(zone: bytes, capture: Path, log=None) -> tuple[list[Asset], dict]:
    """Split the zone's segments into per-asset bodies."""
    def say(msg):
        if log:
            log(msg)

    info = zone_insert.parse(zone)
    types = zone_insert.asset_types(zone)
    segs = read_segments(capture, zone)
    say(f"{len(segs)} segments, {info['asset_count']} assets, "
        f"array at {info['array_offset']} ({info['array_size']} bytes)")

    # Everything up to and including the asset-array read is preamble, not an asset body.
    array_end = info["array_offset"] + info["array_size"]
    start = 0
    while start < len(segs) and segs[start].stream_offset < array_end:
        start += 1

    # An asset begins at a sized read whose immediate successor is a string read: the
    # struct, then its inline name.
    starts = [i for i in range(start, len(segs) - 1)
              if segs[i].kind == KIND_READ and segs[i + 1].kind == KIND_STRING]

    assets: list[Asset] = []
    for n, i in enumerate(starts):
        stop = starts[n + 1] if n + 1 < len(starts) else len(segs)
        seg = segs[i]
        name_seg = segs[i + 1]
        name = zone[name_seg.stream_offset:name_seg.stream_offset + name_seg.size - 1]
        try:
            name = name.decode("ascii")
        except UnicodeDecodeError:
            name = None
        assets.append(Asset(
            index=n,
            asset_type=types[n] if n < len(types) else -1,
            struct_offset=seg.stream_offset,
            struct_size=seg.size,
            name=name,
            segments=segs[i:stop],
        ))

    report = {
        "segments": len(segs),
        "declared_assets": info["asset_count"],
        "found_boundaries": len(assets),
        "matches_declared": len(assets) == info["asset_count"],
    }
    say(f"found {len(assets)} asset boundaries vs {info['asset_count']} declared "
        f"-- {'MATCH' if report['matches_declared'] else 'MISMATCH'}")
    return assets, report


def find(assets: list[Asset], name: str) -> Asset | None:
    for a in assets:
        if a.name == name:
            return a
    return None


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Locate asset bodies in a zone using a capture")
    parser.add_argument("zone", type=Path)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--name", help="report just this asset")
    parser.add_argument("--type", type=int, help="list assets of this type id")
    args = parser.parse_args(argv)

    zone = args.zone.read_bytes()
    assets, report = walk(zone, args.capture, log=print)
    if args.name:
        a = find(assets, args.name)
        if a is None:
            print(f"no asset named {args.name!r}")
            return 1
        print(f"\n{a.name}: type={a.asset_type} index={a.index}")
        print(f"  struct at stream {a.struct_offset} ({a.struct_size} bytes)")
        print(f"  body spans {a.total_size} bytes over {len(a.segments)} allocation(s)")
    elif args.type is not None:
        hits = [a for a in assets if a.asset_type == args.type]
        print(f"\n{len(hits)} asset(s) of type {args.type}:")
        for a in hits[:40]:
            print(f"  {a.name}  struct={a.struct_size}B total={a.total_size}B segs={len(a.segments)}")
    return 0 if report["matches_declared"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
