#!/usr/bin/env python3
"""Add missing functions / widen signatures in compiled GSC-CSC scripts, in place.

Buried's DLC3 content calls into base scripts that this install predates, so the linker
(GscObjResolve) fails two ways:
  * the function is absent from the named script          -> append a stub
  * the function exists but declares too few parameters   -> widen its signature
    (resolution requires export.paramCount >= import.paramCount)

Both are fixed by decompile -> edit source -> recompile with gsc-tool, then splicing the
result back over the original buffer. Payloads recompile smaller than stock, so these fit
without growing the zone; the buffer size is left alone and the tail zero-padded.
"""
import json, pathlib, re, struct, sys
import build_stubs as bs

MENU_INSERT_AT, MENU_DELTA = 3285293, 8192   # mod-menu growth already present in the build

def widen(src: str, fn: str, need: int):
    """Give `fn` at least `need` parameters, preserving existing names."""
    pat = re.compile(r'^(\s*)' + re.escape(fn) + r'\s*\(([^)]*)\)\s*$', re.M)
    m = pat.search(src)
    if not m:
        return src, False
    indent, args = m.group(1), m.group(2).strip()
    cur = [a.strip() for a in args.split(',') if a.strip()]
    if len(cur) >= need:
        return src, True
    cur += ['pad%d' % i for i in range(len(cur), need)]
    return src[:m.start()] + "%s%s(%s)" % (indent, fn, ', '.join(cur)) + src[m.end():], True

def stubs_for(fns: dict) -> str:
    out = ["", "// --- added: functions Buried's DLC scripts import but this build lacks ---"]
    for name in sorted(fns):
        pc = fns[name]
        params = ", ".join("a%d" % i for i in range(pc))
        # A stub for has_/is_/can_ must answer "no" -- returning a0 makes the caller
        # believe stored data exists and it then reads garbage. get_ has nothing to give.
        # Always fail fast. "return a0" hands the caller back an unrelated argument,
        # which a loop reads as a valid item and never terminates -- zm_buried wedged in
        # Scr_StartupGameType spinning through Scr_AllocVector/MT_Alloc that way.
        # undefined/false make the caller stop instead of looping.
        ret = "false" if re.match(r'(has|is|can)_', name) else "undefined"
        out += ["", "%s(%s)" % (name, params), "{", "    return %s;" % ret, "}"]
    return "\n".join(out) + "\n"

def main():
    plan = json.loads(pathlib.Path('stub_plan.json').read_text())
    meta = json.loads(pathlib.Path('patch_zm_ff_scan_new/embedded_scripts.json').read_text())['scripts']
    byname = {s['script_name']: s for s in meta}
    pris = pathlib.Path('patch_zm_ff_scan_new/zone_decompressed.dat').read_bytes()
    zp = pathlib.Path('patch_zm_globe_scan/zone_decompressed.dat')
    zone = bytearray(zp.read_bytes()); before = len(zone)

    targets = {}
    for kind in ('missing', 'arity'):
        for base, fns in plan[kind].items():
            for ext in ('.gsc', '.csc'):
                if base + ext in byname:
                    targets.setdefault(base + ext, {'missing': {}, 'arity': {}})
                    if kind == 'missing':
                        targets[base+ext]['missing'].update(fns)
                    else:
                        targets[base+ext]['arity'].update(fns)
                    break

    ok = fail = 0
    for name, work in sorted(targets.items()):
        rec = byname[name]
        off, size = rec['payload_offset'], rec['payload_size']
        cur = off + (MENU_DELTA if off > MENU_INSERT_AT else 0)
        if zone[cur:cur+4] != b'\x80GSC':
            print("  !! %-46s bad magic at %d" % (name, cur)); fail += 1; continue
        inst = 'client' if name.endswith('.csc') else 'server'
        basename = name.split('/')[-1]
        orig = pris[off:off+size]
        try:
            src = bs.decompile(orig, basename, inst)
        except SystemExit as e:
            print("  !! %-46s decompile failed" % name); fail += 1; continue
        notes = []
        for fn, have_need in work['arity'].items():
            src, found = widen(src, fn, have_need[1])
            notes.append("%s->%d%s" % (fn, have_need[1], "" if found else "(NOT FOUND)"))
        if work['missing']:
            src += stubs_for(work['missing'])
            notes.append("+%d stub(s)" % len(work['missing']))
        try:
            new = bs.compile_src(src, basename, inst)
        except SystemExit:
            print("  !! %-46s compile failed" % name); fail += 1; continue
        if len(new) > size:
            print("  !! %-46s too big (%d > %d) -- needs relocation" % (name, len(new), size))
            fail += 1; continue
        zone[cur:cur+size] = new + b'\x00' * (size - len(new))
        print("  ok %-46s %6d -> %6d  %s" % (name, size, len(new), "; ".join(notes)))
        ok += 1
    assert len(zone) == before, "zone size changed"
    zp.write_bytes(bytes(zone))
    print("\npatched %d script(s), %d failed; zone still %d bytes" % (ok, fail, len(zone)))

if __name__ == '__main__':
    main()
