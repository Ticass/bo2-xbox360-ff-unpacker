#!/usr/bin/env python3
"""Bundled pointer captures, and picking the right one for a zone.

Growing an asset needs a pointer table captured from a real load of the *same* zone
(see :mod:`reloc`). Recording one means hooking the running game, which most people
cannot do, so the captures for the common Zombies patch zones ship with the tool and
are selected automatically.

Selection is by content, never by filename: the zone's md5 first, then its size. A
capture matched only on size is still verified field by field before it is offered,
because a capture records *where* the pointer fields are and *what* they encoded, and
a zone that has been edited since the capture was taken may disagree.

A partial match is not automatically fatal. Size-neutral edits (repointing a
StringTable cell, say) change a handful of encoded values without moving any field, and
those stale entries only matter if they sit inside the range a growth would shift.
:func:`validate` reports the counts; :func:`find_for_zone` refuses anything below
``MIN_MATCH_RATIO`` and lets the caller judge the rest.
"""
from __future__ import annotations

import hashlib
import json
import os
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

MANIFEST = "manifest.json"
#: Below this fraction of matching pointer fields a capture is treated as the wrong zone.
MIN_MATCH_RATIO = 0.95


def capture_dir() -> Path:
    """Where the bundled captures live, frozen (PyInstaller) or from source."""
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        bundled = Path(meipass) / "captures"
        if bundled.exists():
            return bundled
    return Path(__file__).resolve().parent / "captures"


def load_manifest(directory: Path | None = None) -> list[dict]:
    directory = directory or capture_dir()
    path = directory / MANIFEST
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []


@dataclass
class Match:
    path: Path
    entry: dict
    matched: int
    stale: int
    exact: bool          # matched on zone md5 rather than just size

    @property
    def total(self) -> int:
        return self.matched + self.stale

    @property
    def ratio(self) -> float:
        return self.matched / self.total if self.total else 0.0

    def describe(self) -> str:
        how = "zone md5" if self.exact else "zone size"
        base = (f"{self.path.name} ({self.entry.get('title', 'unknown build')}) "
                f"matched on {how}: {self.matched}/{self.total} pointer fields")
        return base if not self.stale else base + f", {self.stale} stale"


def validate(zone: bytes, zmap) -> tuple[int, int]:
    """Count how many of a capture's pointer fields still hold the value it recorded."""
    matched = stale = 0
    for field_off, encoded, _addr in zmap.ptrs:
        if field_off + 4 <= len(zone) and struct.unpack_from(">I", zone, field_off)[0] == encoded:
            matched += 1
        else:
            stale += 1
    return matched, stale


def stale_inside_range(zone: bytes, zmap, block: int, threshold: int) -> int:
    """How many stale entries target `block` at or after `threshold`.

    Those are the only ones a growth would have relocated, so they are the only ones
    whose staleness can actually corrupt the result.
    """
    count = 0
    for field_off, encoded, _addr in zmap.ptrs:
        if field_off + 4 <= len(zone) and struct.unpack_from(">I", zone, field_off)[0] == encoded:
            continue
        v = encoded - 1
        if ((v >> 29) & 7) == block and (v & 0x1FFFFFFF) >= threshold:
            count += 1
    return count


def find_for_zone(zone: bytes, directory: Path | None = None, extra: list[Path] | None = None):
    """Best bundled capture for this zone, or None. Verified before being returned."""
    import reloc

    directory = directory or capture_dir()
    digest = hashlib.md5(zone).hexdigest()
    candidates: list[tuple[dict, Path, bool]] = []

    for entry in load_manifest(directory):
        path = directory / entry.get("file", "")
        if not path.exists():
            continue
        if entry.get("zone_md5") == digest:
            candidates.append((entry, path, True))
        elif entry.get("zone_size") == len(zone):
            candidates.append((entry, path, False))

    for path in extra or []:
        if path.exists():
            candidates.append(({"title": "user-supplied", "file": path.name}, path, False))

    candidates.sort(key=lambda c: not c[2])          # md5 matches first
    best: Match | None = None
    for entry, path, exact in candidates:
        try:
            zmap = reloc.ZoneMap(path, zone)
        except Exception:
            continue
        matched, stale = validate(zone, zmap)
        match = Match(path, entry, matched, stale, exact)
        if match.ratio < MIN_MATCH_RATIO:
            continue
        if best is None or match.matched > best.matched:
            best = match
        if exact and not stale:
            break
    return best


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="List bundled pointer captures, or pick one for a zone")
    parser.add_argument("zone", nargs="?", type=Path,
                        help="zone_decompressed.dat to match; omit to just list what ships")
    args = parser.parse_args(argv)

    directory = capture_dir()
    entries = load_manifest(directory)
    if not args.zone:
        print(f"{len(entries)} bundled capture(s) in {directory}:")
        for e in entries:
            print(f"  {e['file']}")
            print(f"      {e.get('title', '')}")
            print(f"      zone {e['zone_size']} bytes, md5 {e['zone_md5']}, "
                  f"{e['pointer_fields']} pointer fields")
            if e.get("note"):
                print(f"      {e['note']}")
        return 0

    zone = args.zone.read_bytes()
    print(f"zone: {len(zone)} bytes, md5 {hashlib.md5(zone).hexdigest()}")
    match = find_for_zone(zone, directory)
    if match is None:
        print("no bundled capture fits this zone.")
        print("Edits that keep every buffer the same size or smaller need no capture at all;")
        print("only growing one does. See the README for how to record your own.")
        return 1
    print("best match:", match.describe())
    if match.stale:
        print(f"  {match.stale} field(s) hold a different value than when the capture was taken,")
        print("  which is normal after size-neutral edits. They only matter if they fall inside")
        print("  the range your growth shifts; the rebuild checks that and refuses if so.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
