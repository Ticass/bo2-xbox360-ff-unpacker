#!/usr/bin/env python3
"""Link-check a compiled T6 GSC/CSC payload the way BO2's own linker would.

Editing a script and only finding out it is broken when the map refuses to load costs
a full rebuild-and-launch cycle.  This catches the two failure modes that account for
almost all of them:

* A **qualified** call (``maps\\mp\\zombies\\_zm_perks::give_perk``) has to resolve
  against a script that is actually present in the loaded zone set, and the export's
  parameter count has to be at least as large as the call site's.
* An **unqualified** call resolves against the script's own exports first.  Whatever is
  left has to be an engine builtin -- and builtins live in the executable, not in any
  script, so this tool can only list them.  Check those names against the builtin-name
  table in the XEX (searching a disassembler database for the raw ASCII of the name is
  enough).  Do not assume a name is a builtin because it "looks like one", and do not
  rule one out because it does not appear in the shipped scripts:
  ``actionslotthreebuttonpressed``, ``jumpbuttonpressed`` and ``stancebuttonpressed``
  are all real builtins that appear in none of T6's 148 shipped server scripts.

A name that is neither resolves to nothing at link time and the map fails to load.

Usage::

    python linkcheck.py compiled/t6/_callbacksetup.gsc patch_zm_ff_scan common_zm_scan

Exits non-zero if any qualified import fails to resolve.
"""
from __future__ import annotations

import argparse
import pathlib
import sys

import gsc_link


def check(payload_path: str, scans: list[str]):
    pay = pathlib.Path(payload_path).read_bytes()
    parsed = gsc_link.parse(pay)
    if parsed is None:
        sys.exit('not a compiled GSC payload: %s' % payload_path)

    own = {name: pc for name, pc in parsed['exports']}
    zones = gsc_link.load_zones(scans)
    if not zones:
        sys.exit('no scripts found in scans: %s (need <scan>/embedded_scripts.json '
                 'and <scan>/zone_decompressed.dat)' % ', '.join(scans))

    print('%s: %d exports, %d imports' % (payload_path, len(own), len(parsed['imports'])))
    print('zone set: %d scripts from %s' % (len(zones), ', '.join(scans)))

    problems = []
    builtins = set()

    for name, script, pc, _refs in parsed['imports']:
        if not script:
            if name not in own:
                builtins.add(name)
            continue

        key = script.replace(chr(92), '/') + '.gsc'
        if key not in zones:
            key_csc = script.replace(chr(92), '/') + '.csc'
            if key_csc in zones:
                key = key_csc
            else:
                problems.append((name, script, 'script not present in the zone set'))
                continue

        exports = {n: p for n, p in zones[key][1]['exports']}
        if name not in exports:
            problems.append((name, script, 'not exported by that script'))
        elif exports[name] < pc:
            problems.append((name, script,
                             'arity: export takes %d, call passes %d' % (exports[name], pc)))

    print('\nQUALIFIED IMPORT PROBLEMS: %d' % len(problems))
    for name, script, why in problems:
        print('   %-38s %-42s %s' % (name, script, why))

    print('\nnames that must be engine builtins: %d' % len(builtins))
    for name in sorted(builtins):
        print('   %s' % name)

    return problems, builtins


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('payload', help='compiled GSC/CSC payload to check')
    ap.add_argument('scans', nargs='+',
                    help='one or more unpacked zone scan directories to link against')
    ap.add_argument('--builtins-out', metavar='FILE',
                    help='write the unresolved-builtin name list here, one per line')
    args = ap.parse_args()

    problems, builtins = check(args.payload, args.scans)
    if args.builtins_out:
        pathlib.Path(args.builtins_out).write_text('\n'.join(sorted(builtins)) + '\n')

    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
