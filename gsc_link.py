"""Simulate BO2's GSC linker across a set of zones and report unresolved imports.

Layout recovered from sub_8252E938 / GscObjResolve (default_mp.xex):
  exports : base u32@28, count u16@52, stride 12, name u16@+8, paramCount u8@+10
  imports : base u32@32, count u16@54, entry = {name u16@0, file u16@2,
            refs u16@4, paramCount u8@6} then refs*4 bytes -> stride (refs+2)*4
  includes: base u32@12, count u8@60, entries u32 -> string offsets
An unqualified import resolves against the script's own exports, then its includes.
A qualified one resolves against that named script. Match needs export.pc >= import.pc.
"""
import json, pathlib, struct

def _s(pay, off):
    if off >= len(pay): return ''
    return pay[off:pay.find(b'\x00', off)].decode('ascii', 'replace')

def parse(pay):
    if len(pay) < 62 or pay[:4] != b'\x80GSC':
        return None
    d = {'exports': [], 'imports': [], 'includes': []}
    eb, ec = struct.unpack_from('>I', pay, 28)[0], struct.unpack_from('>H', pay, 52)[0]
    for i in range(ec):
        e = eb + 12*i
        if e + 12 > len(pay): break
        d['exports'].append((_s(pay, struct.unpack_from('>H', pay, e+8)[0]), pay[e+10]))
    ib, ic = struct.unpack_from('>I', pay, 32)[0], struct.unpack_from('>H', pay, 54)[0]
    e = ib
    for i in range(ic):
        if e + 8 > len(pay): break
        noff, foff = struct.unpack_from('>H', pay, e)[0], struct.unpack_from('>H', pay, e+2)[0]
        refs, pc = struct.unpack_from('>H', pay, e+4)[0], pay[e+6]
        d['imports'].append((_s(pay, noff), _s(pay, foff), pc, refs))
        e += (refs + 2) * 4
    cb, cc = struct.unpack_from('>I', pay, 12)[0], pay[60]
    for i in range(cc):
        if cb + 4*i + 4 > len(pay): break
        d['includes'].append(_s(pay, struct.unpack_from('>I', pay, cb+4*i)[0]))
    return d

def load_zones(scans):
    scripts = {}
    for scan in scans:
        p = pathlib.Path(scan)
        mp = p/'embedded_scripts.json'
        if not mp.exists(): continue
        zone = (p/'zone_decompressed.dat').read_bytes()
        for s in json.loads(mp.read_text())['scripts']:
            pay = zone[s['payload_offset']:s['payload_offset']+s['payload_size']]
            d = parse(pay)
            if d:
                scripts[s['script_name']] = (scan, d)
    return scripts


# ---------------------------------------------------------------------------
# Link checking
#
# A recompiled script that compiles cleanly can still be unloadable: BO2 resolves
# every import when the zone links, and a call that resolves to nothing takes the
# whole map down with a script error. Compiling is not the same as linking, and the
# difference costs a full rebuild-and-launch cycle to discover.
#
# The check below is a *regression* check rather than an absolute one, and that is
# deliberate. A script legitimately calls into scripts that live in other zones -- a
# patch zone's _callbacksetup calls into common_zm -- so an absolute "does everything
# resolve here" test is full of false positives. Comparing the edited payload against
# the original one from the same zone cancels those out: whatever the stock script
# already referenced is baseline, and only what the edit *added* is reported.
# ---------------------------------------------------------------------------

def index_scripts(scans):
    """Build {script_name: parsed} over one or more unpacked scan folders."""
    return {name: data for name, (_scan, data) in load_zones(scans).items()}


def _lookup(index, script):
    base = script.replace(chr(92), '/')
    for ext in ('.gsc', '.csc'):
        if base + ext in index:
            return index[base + ext]
    return None


def resolve(payload, index):
    """Classify a compiled payload's imports against an index of scripts.

    Returns ``(missing, arity, builtins)``:

    * ``missing`` -- qualified calls whose target script or function was not found
    * ``arity``   -- qualified calls passing more parameters than the export accepts
    * ``builtins``-- unqualified names not exported by the payload itself, which must
      therefore be engine builtins (this module cannot verify those; check them
      against the builtin-name table in the executable)
    """
    parsed = parse(payload)
    if parsed is None:
        return set(), set(), set()

    own = {name for name, _pc in parsed['exports']}
    missing, arity, builtins = set(), set(), set()

    for name, script, pc, _refs in parsed['imports']:
        if not script:
            if name not in own:
                builtins.add(name)
            continue
        target = _lookup(index, script)
        if target is None:
            missing.add((name, script, 'script not in the zone set'))
            continue
        exports = {n: p for n, p in target['exports']}
        if name not in exports:
            missing.add((name, script, 'not exported by that script'))
        elif exports[name] < pc:
            arity.add((name, script, exports[name], pc))

    return missing, arity, builtins


def regression(old_payload, new_payload, index):
    """Report only what an edit *added* that cannot be linked.

    Anything the stock payload already referenced is treated as baseline, so calls
    into other zones do not show up as false positives.
    """
    old_missing, old_arity, old_builtins = resolve(old_payload, index)
    new_missing, new_arity, new_builtins = resolve(new_payload, index)
    return {
        'missing': sorted(new_missing - old_missing),
        'arity': sorted(new_arity - old_arity),
        'builtins': sorted(new_builtins - old_builtins),
    }


def describe(report, name=''):
    """Render a regression report as log lines. Empty list when the edit is clean."""
    lines = []
    prefix = ('%s: ' % name) if name else ''
    for fn, script, why in report['missing']:
        lines.append('%sLINK: %s::%s does not resolve (%s)' % (prefix, script, fn, why))
    for fn, script, have, want in report['arity']:
        lines.append('%sLINK: %s::%s takes %d parameter(s), call passes %d'
                     % (prefix, script, fn, have, want))
    if report['builtins']:
        lines.append('%sLINK: new unqualified name(s), must be engine builtins: %s'
                     % (prefix, ', '.join(report['builtins'])))
    return lines
