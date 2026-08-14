#!/usr/bin/env python3
"""Report how much headroom each embedded script has when recompiled by gsc-tool.

gsc-tool's output is consistently a little smaller than Treyarch's original compiled
payload, so an existing ScriptParseTree can often absorb added code with no zone growth at
all (see inject_gsc.py "fit" mode). Where the addition does not fit, reloc.py grows the
zone properly instead.

Run from the repo root after a scan has produced <name>_ff_scan/embedded_scripts.json.
"""
import json, pathlib, shutil, subprocess, tempfile
GSC = pathlib.Path("_tools/gsc-tool/gsc-tool.exe").resolve()
meta = json.loads(pathlib.Path("patch_zm_ff_scan/embedded_scripts.json").read_text())["scripts"]
srv = [s for s in meta if s["instance"] == "server"]
srv.sort(key=lambda s: -s["payload_size"])
targets = [s for s in srv if s["payload_size"] > 20000][:8]
for s in targets:
    blob = pathlib.Path("patch_zm_ff_scan/scripts") / s["script_name"]
    if not blob.exists():
        print("%-52s MISSING BLOB" % s["script_name"]); continue
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        base = pathlib.Path(s["script_name"]).name
        shutil.copy(blob, td / base)
        d = subprocess.run([str(GSC), "-m", "decomp", "-g", "t6", "-s", "xb2", "-i", "server", base],
                           cwd=td, capture_output=True, text=True)
        dec = list((td / "decompiled").rglob(base)) if (td / "decompiled").exists() else []
        if not dec:
            print("%-52s decompile FAILED %s" % (s["script_name"], (d.stderr or d.stdout).strip()[:60])); continue
        work = td / "w"; work.mkdir()
        shutil.copy(dec[0], work / base)
        c = subprocess.run([str(GSC), "-m", "comp", "-g", "t6", "-s", "xb2", "-i", "server", base],
                           cwd=work, capture_output=True, text=True)
        comp = list((work / "compiled").rglob(base)) if (work / "compiled").exists() else []
        if not comp:
            print("%-52s recompile FAILED %s" % (s["script_name"], (c.stderr or c.stdout).strip()[:60])); continue
        new = comp[0].stat().st_size
        print("%-52s orig=%6d recomp=%6d slack=%+6d" % (s["script_name"], s["payload_size"], new, s["payload_size"] - new))
