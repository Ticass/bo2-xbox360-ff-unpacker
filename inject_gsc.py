#!/usr/bin/env python3
"""Replace a ScriptParseTree payload in a decompressed BO2 zone.

The zone stream is consumed sequentially: an asset's buffer allocation eats exactly
`len` bytes from it. So the length field and the number of bytes written must agree.

Two modes:
  fit   -- new payload is <= the original; pad with zeros so nothing moves at all.
           Needs no relocation (the compiled GSC carries its own internal sizes, so
           trailing zeros are never read).
  grow  -- new payload is larger. The stream grows by delta, which means the owning
           XBlock grows too, so the 40-byte zone header must be fixed up:
             [0] (offset 0x00) = total stream size after the header
             [2..9] (0x08..0x24) = the 8 XBlock sizes; block 5 holds ~all of patch_zm
"""
import json, struct, sys, pathlib

SCAN = pathlib.Path("patch_zm_mod_scan")
ZONE = SCAN / "zone_decompressed.dat"
PRISTINE = pathlib.Path("patch_zm_ff_scan/zone_decompressed.dat")
OWNING_BLOCK = 5          # header index 2 + 5 = 7 -> offset 0x1C


def main(script_name: str, new_payload: pathlib.Path) -> None:
    meta = json.loads((pathlib.Path("patch_zm_ff_scan/embedded_scripts.json")).read_text())
    rec = next(s for s in meta["scripts"] if s["script_name"] == script_name)
    off, size, lenfield = rec["payload_offset"], rec["payload_size"], rec["zone_length_field_offset"]

    z = bytearray(PRISTINE.read_bytes())
    assert struct.unpack_from(">I", z, lenfield)[0] == size, "length field does not match payload_size"
    assert z[off:off+4] == b"\x80GSC", "payload magic missing at payload_offset"

    new = new_payload.read_bytes()
    assert new[:4] == b"\x80GSC", "new payload is not compiled T6 GSC"

    if len(new) <= size:
        body = new + b"\x00" * (size - len(new))
        z[off:off+size] = body
        delta = 0
        print("fit: %d -> %d bytes (+%d zero pad), nothing moves" % (size, len(new), size - len(new)))
    else:
        delta = len(new) - size
        z[off:off+size] = new
        struct.pack_into(">I", z, lenfield, len(new))
        # Stream total and the owning XBlock both grow by delta.
        total = struct.unpack_from(">I", z, 0)[0]
        struct.pack_into(">I", z, 0, total + delta)
        bslot = 8 + 4 * OWNING_BLOCK
        blk = struct.unpack_from(">I", z, bslot)[0]
        struct.pack_into(">I", z, bslot, blk + delta)
        print("grow: %d -> %d bytes (delta +%d)" % (size, len(new), delta))
        print("  len field   %d -> %d" % (size, len(new)))
        print("  stream size %d -> %d" % (total, total + delta))
        print("  XBlock[%d]   %d -> %d" % (OWNING_BLOCK, blk, blk + delta))

    ZONE.write_bytes(bytes(z))
    print("wrote %s (%d bytes)" % (ZONE, len(z)))


if __name__ == "__main__":
    main(sys.argv[1], pathlib.Path(sys.argv[2]))
