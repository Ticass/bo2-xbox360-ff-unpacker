#!/usr/bin/env python3
"""Add stub functions to a compiled GSC and recompile it.

Buried's DLC3 scripts call functions that this install's base scripts never define
(they shipped in a DLC-updated _zm_weapons/_zm_utility we do not have). Every one of
those callers includes maps/mp/zombies/_zm_utility, so defining the stubs there makes
the linker resolve them.

Each stub declares max(paramCount) parameters -- GscObjResolve requires
export.paramCount >= import.paramCount -- and returns its first argument, which is a
harmless identity for the get_*/is_* shaped calls and ignored by the rest.
"""
import json, os, pathlib, shutil, subprocess, tempfile

TOOL = os.path.abspath('_tools/gsc-tool/gsc-tool.exe')

def run(args, cwd):
    r = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        raise SystemExit("gsc-tool failed: %s" % ((r.stdout or '') + (r.stderr or ''))[:400])
    return r

def decompile(payload: bytes, basename: str, instance='server') -> str:
    tmp = tempfile.mkdtemp()
    try:
        p = os.path.join(tmp, basename)
        open(p, 'wb').write(payload)
        run([TOOL, '-m', 'decomp', '-g', 't6', '-s', 'xb2', '-i', instance, p], tmp)
        return open(os.path.join(tmp, 'decompiled', 't6', basename), encoding='utf-8',
                    errors='replace').read()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

def compile_src(text: str, basename: str, instance='server') -> bytes:
    tmp = tempfile.mkdtemp()
    try:
        p = os.path.join(tmp, basename)
        open(p, 'w', encoding='utf-8').write(text)
        run([TOOL, '-m', 'comp', '-g', 't6', '-s', 'xb2', '-i', instance, p], tmp)
        return open(os.path.join(tmp, 'compiled', 't6', basename), 'rb').read()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

def stub_text(stubs: dict) -> str:
    out = ["", "// ---------------------------------------------------------------", 
           "// Stubs for functions Buried's DLC3 scripts import but this install", 
           "// never defines. Added so GscObjResolve can link; behaviour is inert.",
           "// ---------------------------------------------------------------"]
    for name in sorted(stubs):
        pc = max(stubs[name]['pc'])
        params = ", ".join("a%d" % i for i in range(pc))
        out.append("")
        out.append("%s(%s)" % (name, params))
        out.append("{")
        out.append("    return %s;" % ("false" if name[:4] in ("has_","is_c") or name.startswith(("has_","is_","can_")) else "undefined"))
        out.append("}")
    return "\n".join(out) + "\n"

if __name__ == '__main__':
    stubs = json.loads(pathlib.Path('stub_list.json').read_text())
    meta = json.loads(pathlib.Path('patch_zm_ff_scan_new/embedded_scripts.json').read_text())['scripts']
    zone = pathlib.Path('patch_zm_ff_scan_new/zone_decompressed.dat').read_bytes()
    rec = next(s for s in meta if s['script_name'] == 'maps/mp/zombies/_zm_utility.gsc')
    orig = zone[rec['payload_offset']:rec['payload_offset'] + rec['payload_size']]
    print("original _zm_utility.gsc: %d bytes" % len(orig))
    src = decompile(orig, '_zm_utility.gsc')
    print("decompiled: %d chars" % len(src))
    patched = src + stub_text(stubs)
    out = compile_src(patched, '_zm_utility.gsc')
    pathlib.Path('_zm_utility_stubs.gscc').write_bytes(out)
    print("recompiled with %d stubs: %d bytes (original %d, delta %+d)"
          % (len(stubs), len(out), len(orig), len(out) - len(orig)))
    import gsc_link
    d = gsc_link.parse(out)
    names = {f for f, _ in d['exports']}
    missing = [s for s in stubs if s not in names]
    print("exports: %d | all stubs present: %s" % (len(names), not missing))
    if missing:
        print("MISSING:", missing)
