#!/usr/bin/env python3
"""Build patch_zm.ff with the REXGLUE mod menu compiled into _callbacksetup.gsc.

Pipeline: decompile the stock script -> thread mm_main() from codecallback_playerconnect ->
append the menu source -> compile -> open a relocated gap in the zone for the size increase
-> write the new payload and length -> repack.
"""
import json, pathlib, shutil, struct, subprocess, sys
import reloc

GSC = pathlib.Path("_tools/gsc-tool/gsc-tool.exe").resolve()
SCRIPT = "maps/mp/gametypes_zm/_callbacksetup.gsc"
WORK = pathlib.Path("_build"); MOD = pathlib.Path("patch_zm_mod_scan")


def run(args, cwd):
    p = subprocess.run([str(a) for a in args], cwd=cwd, capture_output=True, text=True)
    if p.returncode:
        sys.exit("failed: %s\n%s" % (args, (p.stderr or p.stdout)[:400]))
    return p


def main():
    meta = json.loads(pathlib.Path("patch_zm_ff_scan/embedded_scripts.json").read_text())["scripts"]
    rec = next(s for s in meta if s["script_name"] == SCRIPT)
    off, size, lenfield = rec["payload_offset"], rec["payload_size"], rec["zone_length_field_offset"]

    if WORK.exists():
        shutil.rmtree(WORK)
    WORK.mkdir()
    base = "_callbacksetup.gsc"
    shutil.copy(pathlib.Path("patch_zm_ff_scan/scripts") / SCRIPT, WORK / base)
    run([GSC, "-m", "decomp", "-g", "t6", "-s", "xb2", "-i", "server", base], WORK)
    src = (WORK / "decompiled/t6" / base).read_text()

    hook_old = "    self thread maps\mp\_audio::monitor_player_sprint();\n"
    hook_new = hook_old + "    self thread mm_main();\n"
    assert hook_old in src, "player-connect hook site not found"
    src = src.replace(hook_old, hook_new, 1)
    src += pathlib.Path("menu_body.gsc").read_text()

    (WORK / "src").mkdir()
    (WORK / "src" / base).write_text(src)
    run([GSC, "-m", "comp", "-g", "t6", "-s", "xb2", "-i", "server", base], WORK / "src")
    payload = (WORK / "src/compiled/t6" / base).read_bytes()
    assert payload[:4] == b"\x80GSC"
    # Growing the buffer shifts later allocations in the block, but the loader pads each
    # allocation to an alignment boundary, so the observed shift is NOT the raw byte delta.
    # Measured: a +4183 byte payload moved later block-5 allocations by exactly +4096, i.e.
    # 87 bytes less, which left every relocated pointer 87 bytes long and crashed material
    # loading. Rounding the delta up to a multiple of 4096 makes shift == delta exactly for
    # any power-of-two alignment that divides 4096, so no alignment probing is needed.
    ALIGN = 4096
    raw = len(payload) - size
    if raw > 0:
        delta = ((raw + ALIGN - 1) // ALIGN) * ALIGN
        payload = payload + bytes(delta - raw)
        print("payload: %d -> %d bytes (raw delta %+d, padded to %+d for alignment)"
              % (size, len(payload), raw, delta))
    else:
        delta = raw
        print("payload: %d -> %d bytes (delta %+d)" % (size, len(payload), delta))

    zone = reloc.PRISTINE.read_bytes()
    zmap = reloc.ZoneMap(reloc.DUMP, zone)
    assert struct.unpack_from(">I", zone, lenfield)[0] == size

    if delta > 0:
        zone = reloc.relocate(zone, zmap, off + size, delta)
    elif delta < 0:
        payload = payload + b"\x00" * (-delta)
        delta = 0
        print("payload smaller than original; zero-padded, no relocation needed")

    out = bytearray(zone)
    out[off:off + len(payload)] = payload
    struct.pack_into(">I", out, lenfield, len(payload))
    (MOD / "zone_decompressed.dat").write_bytes(bytes(out))
    print("zone: %d bytes -> %s" % (len(out), MOD / "zone_decompressed.dat"))


if __name__ == "__main__":
    main()
