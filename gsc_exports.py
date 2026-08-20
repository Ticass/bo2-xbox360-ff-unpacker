"""List exported function names from a compiled T6 GSC payload.

Layout recovered from sub_8252E938 (GscObjResolve's per-import search):
    exportsBase = objBase + u32@(obj+28)
    exportCount = u16@(obj+52)
    entry stride 12; the function-name string offset is a u16 at entry+8
All fields are big-endian.
"""
import struct

def exports(payload: bytes):
    if len(payload) < 56 or payload[:4] != b'\x80GSC':
        return []
    base = struct.unpack_from('>I', payload, 28)[0]
    count = struct.unpack_from('>H', payload, 52)[0]
    out = []
    for i in range(count):
        e = base + 12 * i
        if e + 12 > len(payload):
            break
        off = struct.unpack_from('>H', payload, e + 8)[0]
        if off >= len(payload):
            continue
        end = payload.find(b'\x00', off)
        out.append(payload[off:end].decode('ascii', 'replace'))
    return out
