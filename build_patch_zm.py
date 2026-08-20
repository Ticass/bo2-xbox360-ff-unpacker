#!/usr/bin/env python3
"""Rebuild patch_zm.ff from STOCK, applying every mod in one reproducible pass.

Everything is derived from the pristine zone so offsets always come from one place, and
all growing assets go through reloc.relocate_multi together -- applying growths one at a
time against an already-grown zone would look up pointer fields at stale offsets.

  size-neutral : globe/DLC table cells, the _sticky_grenade import redirect,
                 and the recompiled scripts that fit in their original buffers
  growing      : the GSC mod menu, plus client scripts whose recompiled form is bigger
"""
import json, pathlib, struct, reloc, build_stubs as bs, patch_scripts

PRIS_SCAN = pathlib.Path('patch_zm_ff_scan_new')
PRIS = PRIS_SCAN / 'zone_decompressed.dat'
OUT  = pathlib.Path('patch_zm_globe_scan/zone_decompressed.dat')

# --- size-neutral table edits (see docs/ZOMBIES_GLOBE_MAP_TABLE.md) -----------------
BASEGAME_PACK = (0xA0020331, 0x0002B5D5)   # the shared "0" string zm_transit uses
TRANSIT_BLIT  = (0xA02A71AC, 0xFE89AF8F)   # menu_zm_map_transit_blit_transit
COL11 = [2803573, 2803725, 2803877, 2804029, 2804181,
         2804333, 2804485, 2804637, 2804789, 2804941]      # mapstable mapPackTypeIndex
COL6  = [2791373, 2791525, 2791677, 2791829, 2791981,
         2792133, 2792437, 2792589, 2792741]               # gametypestable start-loc art

def main():
    zone = bytearray(PRIS.read_bytes())
    print("pristine zone: %d bytes" % len(zone))

    for off in COL11:
        struct.pack_into('>2I', zone, off, *BASEGAME_PACK)
    for off in COL6:
        struct.pack_into('>2I', zone, off, *TRANSIT_BLIT)
    print("table cells: %d pack indices + %d start-loc icons" % (len(COL11), len(COL6)))

    n = bytes(zone).count(b'maps/mp/_sticky_grenade')
    assert n == 1
    zone = bytearray(bytes(zone).replace(b'maps/mp/_sticky_grenade', b'maps/mp/zombies/_zm_bot'))
    print("sticky-grenade import redirected to a script that exists")

    meta = json.loads((PRIS_SCAN/'embedded_scripts.json').read_text())['scripts']
    byname = {s['script_name']: s for s in meta}
    plan = json.loads(pathlib.Path('stub_plan.json').read_text())

    # recompile every affected script once; classify fit vs grow
    targets = {}
    for kind in ('missing', 'arity'):
        for base, fns in plan[kind].items():
            for ext in ('.gsc', '.csc'):
                if base + ext in byname:
                    t = targets.setdefault(base+ext, {'missing': {}, 'arity': {}})
                    t[kind].update(fns)
                    break
    targets['maps/mp/zombies/_zm_utility.gsc'] = {
        'missing': {k: max(v['pc']) for k, v in json.loads(pathlib.Path('stub_list.json').read_text()).items()},
        'arity': {}}

    # Recompile every script stub_plan.json touches. An earlier run cut this down to two
    # scripts on the theory that recompiling broke the map load -- that was wrong. The
    # regression was the launch command line: "+zm" only takes effect when it is the FIRST
    # + token in --cl. Prefixing "+set r_cmdbuf_worker 0" left +devmap working (the map
    # name still reached SV_SpawnServer) but silently dropped +zm, so the game booted MP
    # and loaded en_patch_loc_mp.ff instead of en_patch_loc_zm.ff. Trimming the script set
    # only re-broke the imports these entries exist to satisfy.
    print("recompiling %d script(s)" % len(targets))

    fit, grow = {}, {}
    for name, work in sorted(targets.items()):
        rec = byname[name]
        orig = bytes(zone)[rec['payload_offset']:rec['payload_offset']+rec['payload_size']]
        inst = 'client' if name.endswith('.csc') else 'server'
        src = bs.decompile(orig, name.split('/')[-1], inst)
        for fn, hn in work['arity'].items():
            src, found = patch_scripts.widen(src, fn, hn[1])
            if not found: print("   (arity target not found: %s in %s)" % (fn, name))
        if work['missing']:
            src += patch_scripts.stubs_for(work['missing'])
        new = bs.compile_src(src, name.split('/')[-1], inst)
        (grow if len(new) > rec['payload_size'] else fit)[name] = new
        print("   %-46s %6d -> %6d %s" % (name, rec['payload_size'], len(new),
                                          "GROW" if len(new) > rec['payload_size'] else ""))
    # mod menu
    menu = pathlib.Path('menu_callbacksetup.gscc').read_bytes()
    grow['maps/mp/gametypes_zm/_callbacksetup.gsc'] = menu

    for name, blob in fit.items():
        rec = byname[name]; off, size = rec['payload_offset'], rec['payload_size']
        zone[off:off+size] = blob + b'\x00' * (size - len(blob))
    print("spliced %d in-place script(s)" % len(fit))

    # --- growing assets: one relocation pass ---------------------------------------
    zmap = reloc.ZoneMap(pathlib.Path('zone_ptrs.bin'), bytes(PRIS.read_bytes()))
    ins = []
    for name in grow:
        rec = byname[name]; off, size = rec['payload_offset'], rec['payload_size']
        delta = reloc.align_growth(len(grow[name]) - size)
        blk, boff = zmap.locate(off)                 # threshold from the buffer's OWN start
        ins.append((off + size, delta, blk, boff + size))
        print("   grow %-46s +%d (block %d)" % (name, delta, blk))
    out, report = reloc.relocate_multi(bytes(zone), zmap, ins, log=lambda m: print("   " + m))
    print("   ", report)
    assert report['unresolved'] == 0

    out = bytearray(out)
    shift = 0
    for name in sorted(grow, key=lambda n: byname[n]['payload_offset']):
        rec = byname[name]; off, size = rec['payload_offset'], rec['payload_size']
        delta = reloc.align_growth(len(grow[name]) - size)
        cur = off + shift
        blob = grow[name]
        out[cur:cur+size+delta] = blob + b'\x00' * (size + delta - len(blob))
        struct.pack_into('>I', out, rec['zone_length_field_offset'] + shift, size + delta)  # cover the ALIGNED gap: stream eats len+1 bytes
        shift += delta
    OUT.write_bytes(bytes(out))
    print("\nfinal zone: %d bytes (pristine %d, +%d)" % (len(out), len(PRIS.read_bytes()),
                                                        len(out) - len(PRIS.read_bytes())))

if __name__ == '__main__':
    main()
