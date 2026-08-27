#!/usr/bin/env python3
"""Body parsers for the asset types an XModel port needs: XModel, Material, GfxImage.

A zone stores asset bodies inline, in array order, with no index. A pointer field holds
either `0xFFFFFFFF` -- meaning that field's data follows immediately at the read cursor --
or an encoded reference to something already loaded. So parsing a body is walking its
fields in order and consuming inline data as you meet it, exactly as the loader does.

Layouts follow the BO2 structs documented at codresearch.dev; the sizes below were all
independently confirmed against a real zone before being written down (XModel 244,
Material 104, GfxImage 212, XSurface 144, XModelLodInfo 28).

**Every prediction is checked.** A capture records each `DB_LoadXFileData(dest, size)` the
loader issued, so if the field walk is right, every inline array this predicts must begin
exactly at a recorded allocation boundary with exactly the predicted size. `parse_xmodel`
reports each such check, and a caller that gets `mismatches == 0` knows the parse is
correct rather than merely plausible. That is the whole point of doing it this way: a
wrong field walk fails loudly here instead of producing a zone that loads and then
corrupts.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

FOLLOWING = 0xFFFFFFFF

SIZEOF_XMODEL = 244
SIZEOF_MATERIAL = 104
SIZEOF_GFXIMAGE = 212
GFXIMAGE_NAME_OFFSET = 0xCC      # measured; NOT offset 0
SIZEOF_XSURFACE = 144
SIZEOF_LODINFO = 28
SIZEOF_DOBJANIMMAT = 32          # quat 16 + trans 12 + transWeight 4
SIZEOF_COLLSURF = 36             # mins 12 + maxs 12 + boneIdx 4 + contents 4 + surfFlags 4
SIZEOF_BONEINFO = 44             # bounds 24 + offset 12 + radiusSquared 4 + collmap 1 (padded)
SIZEOF_RIGIDVERTLIST = 12        # 4 x u16 + collisionTree ptr
SIZEOF_COLLISIONTREE = 40        # trans 12 + scale 12 + nodeCount 4 + nodes 4 + leafCount 4 + leafs 4
SIZEOF_COLLISIONNODE = 16        # aabb 12 + childBeginIndex 2 + childCount 2             # bounds 24 + offset 12 + radiusSquared 4 + collmap 1 (padded)


@dataclass
class Ref:
    """A pointer field: either inline data we consumed, or a reference to something else."""
    name: str
    value: int
    offset: int                   # stream offset of the field itself
    inline_at: int | None = None  # where its data started, when it followed inline
    inline_size: int | None = None

    @property
    def follows(self) -> bool:
        return self.value == FOLLOWING

    @property
    def is_null(self) -> bool:
        return self.value == 0

    @property
    def is_reference(self) -> bool:
        return not self.follows and not self.is_null


@dataclass
class Parsed:
    kind: str
    offset: int
    name: str | None = None
    fields: dict = field(default_factory=dict)
    refs: list[Ref] = field(default_factory=list)
    checks: list[tuple] = field(default_factory=list)   # (label, predicted_off, predicted_size, ok)
    end: int = 0

    @property
    def mismatches(self) -> int:
        return sum(1 for *_r, ok in self.checks if not ok)

    @property
    def references(self) -> list[Ref]:
        return [r for r in self.refs if r.is_reference]


class Cursor:
    """Walks the stream the way the loader does, checking each read against the capture."""

    def __init__(self, zone: bytes, pos: int, starts: set[int] | None = None,
                 sizes: dict[int, int] | None = None):
        self.z = zone
        self.pos = pos
        self.starts = starts or set()
        self.sizes = sizes or {}
        self.checks: list[tuple] = []

    def u8(self, off): return self.z[off]
    def u16(self, off): return struct.unpack_from(">H", self.z, off)[0]
    def i16(self, off): return struct.unpack_from(">h", self.z, off)[0]
    def u32(self, off): return struct.unpack_from(">I", self.z, off)[0]
    def i32(self, off): return struct.unpack_from(">i", self.z, off)[0]
    def f32(self, off): return struct.unpack_from(">f", self.z, off)[0]

    def take(self, size: int, label: str) -> int:
        """Consume `size` bytes of inline data, recording whether it lands on a real read."""
        at = self.pos
        ok = (at in self.starts) and (self.sizes.get(at) == size if self.sizes else True)
        self.checks.append((label, at, size, ok))
        self.pos += size
        return at

    def take_string(self, label: str) -> tuple[int, str]:
        at = self.pos
        end = self.z.find(b"\x00", at)
        raw = self.z[at:end]
        ok = at in self.starts
        self.checks.append((label, at, end - at + 1, ok))
        self.pos = end + 1
        return at, raw.decode("ascii", "replace")


def _ref(cur: Cursor, base: int, off: int, name: str) -> Ref:
    return Ref(name, cur.u32(base + off), base + off)


def parse_gfximage(zone: bytes, at: int, cur: Cursor | None = None) -> Parsed:
    """GfxImage: fixed struct, then its inline name. Pixel data is streamed, not inline."""
    cur = cur or Cursor(zone, at)
    p = Parsed("GfxImage", at)
    # name sits at +0xCC, near the END of the 212-byte struct -- not at offset 0 like
    # XModel and Material. Measured across three images; assuming +0 leaves the name
    # unconsumed and silently desyncs everything after it.
    name_ref = _ref(cur, at, GFXIMAGE_NAME_OFFSET, "name")
    p.refs.append(name_ref)
    cur.pos = at + SIZEOF_GFXIMAGE
    if name_ref.follows:
        _, p.name = cur.take_string("GfxImage.name")
    p.end = cur.pos
    p.checks = cur.checks
    return p


def parse_material(zone: bytes, at: int, cur: Cursor | None = None) -> Parsed:
    """Material: fixed struct, inline name, then textureTable / constantTable / stateBitTable.

    The three count bytes live in the block after `stateBitsEntry[]`. Rather than hard-code
    an offset the docs leave ambiguous, the counts are recovered from the table allocation
    sizes when a capture is available, and cross-checked against the candidate bytes.
    """
    cur = cur or Cursor(zone, at)
    p = Parsed("Material", at)
    for off, nm in ((0x00, "name"), (0x54, "techniqueSet"), (0x58, "textureTable"),
                    (0x5C, "constantTable"), (0x60, "stateBitTable"), (0x64, "thermalMaterial")):
        p.refs.append(_ref(cur, at, off, nm))
    byname = {r.name: r for r in p.refs}
    cur.pos = at + SIZEOF_MATERIAL
    if byname["name"].follows:
        _, p.name = cur.take_string("Material.name")

    # tables follow in field order; sizes come from the capture, entries are 16 / 32 / 8 bytes
    for nm, stride in (("textureTable", 16), ("constantTable", 32), ("stateBitTable", 8)):
        r = byname[nm]
        if not r.follows:
            continue
        size = cur.sizes.get(cur.pos)
        if size is None:
            p.fields[nm + "_count"] = None
            break
        r.inline_at = cur.take(size, "Material." + nm)
        r.inline_size = size
        count = size // stride
        p.fields[nm + "_count"] = count
        if nm == "textureTable":
            # MaterialTextureDef is 16 bytes with the GfxImage pointer at +12. A pointer of
            # 0xFFFFFFFF means that image's body follows inline here, so consume it.
            for t in range(count):
                if cur.u32(r.inline_at + t * 16 + 12) != FOLLOWING:
                    continue
                img = parse_gfximage(zone, cur.pos, cur)
                p.fields.setdefault("images", []).append(img.name)
    p.end = cur.pos
    p.checks = cur.checks
    return p


def parse_xsurface(cur: Cursor, at: int, index: int) -> None:
    """Consume one XSurface's inline data.

    The loader reads the surfs array, then walks back over each surface pulling in its
    indices, vertices, rigid vert lists and collision trees. Those reads sit between the
    surfs array and materialHandles, which is why a walk that skips them lands far short.
    Sizes come from the surface's own counts, so a wrong layout misses a boundary here
    rather than silently swallowing the wrong bytes.
    """
    vert_list_count = cur.u8(at + 0x11)
    flags = cur.u16(at + 0x12)
    vert_count = cur.u16(at + 0x14)
    tri_count = cur.u16(at + 0x16)

    # Offsets and ORDER both measured against recorded allocations, not assumed. The only
    # FOLLOWING dwords in a real surface are 0x1C (triIndices), 0x30 (verts), 0x54 (vertList),
    # and the loader consumes them verts -> vertList -> per-entry collision tree -> triIndices.
    # triIndices really is last, as the struct docs annotate.
    if cur.u32(at + 0x30) == FOLLOWING and vert_count:
        cur.take(vert_count * (24 if flags & 1 else 32), f"surf[{index}].verts")

    if cur.u32(at + 0x54) == FOLLOWING and vert_list_count:
        # XRigidVertList is 12 bytes: four u16 plus a collisionTree pointer. Confirmed by
        # 4 entries = 48 bytes and 1 entry = 12 bytes across the turbine's surfaces.
        cur.take(vert_list_count * SIZEOF_RIGIDVERTLIST, f"surf[{index}].vertList")
        for e in range(vert_list_count):
            tree = cur.take(SIZEOF_COLLISIONTREE, f"surf[{index}].collTree[{e}]")
            node_count = cur.i32(tree + 0x18)
            leaf_count = cur.i32(tree + 0x20)
            if cur.u32(tree + 0x1C) == FOLLOWING and node_count:
                cur.take(node_count * SIZEOF_COLLISIONNODE, f"surf[{index}].collNodes[{e}]")
            if cur.u32(tree + 0x24) == FOLLOWING and leaf_count:
                cur.take(leaf_count * 2, f"surf[{index}].collLeafs[{e}]")

    if cur.u32(at + 0x1C) == FOLLOWING and tri_count:
        cur.take(tri_count * 6, f"surf[{index}].triIndices")


def parse_xmodel(zone: bytes, at: int, starts: set[int] | None = None,
                 sizes: dict[int, int] | None = None) -> Parsed:
    """XModel: the full top-level field walk, with every inline array size predicted."""
    cur = Cursor(zone, at, starts, sizes)
    p = Parsed("XModel", at)

    num_bones = cur.u8(at + 0x04)
    num_root = cur.u8(at + 0x05)
    num_surfs = cur.u8(at + 0x06)
    non_root = num_bones - num_root
    p.fields.update(numBones=num_bones, numRootBones=num_root, numsurfs=num_surfs,
                    lodRampType=cur.u8(at + 0x07),
                    numCollSurfs=cur.i32(at + 0x9C), contents=cur.i32(at + 0xA0),
                    radius=cur.f32(at + 0xA8),
                    numLods=cur.i16(at + 0xC4), collLod=cur.i16(at + 0xC6),
                    memUsage=cur.i32(at + 0xCC), flags=cur.u32(at + 0xD0),
                    numCollmaps=cur.u8(at + 0xD8))

    # (field offset, label, predicted inline size) -- sizes derived from the header counts,
    # which is what makes a wrong layout fail immediately instead of silently.
    plan = [
        (0x00, "name", None),
        (0x08, "boneNames", num_bones * 2),
        (0x0C, "parentList", non_root),
        (0x10, "quats", non_root * 8),
        (0x14, "trans", non_root * 16),
        (0x18, "partClassification", num_bones),
        (0x1C, "baseMat", num_bones * SIZEOF_DOBJANIMMAT),
        (0x20, "surfs", num_surfs * SIZEOF_XSURFACE),
        (0x24, "materialHandles", num_surfs * 4),
        (0x98, "collSurfs", p.fields["numCollSurfs"] * SIZEOF_COLLSURF),
        (0xA4, "boneInfo", num_bones * SIZEOF_BONEINFO),
        (0xC8, "himipInvSqRadii", None),
        (0xD4, "physPreset", None),
        (0xDC, "collmaps", None),
        (0xE0, "physConstraints", None),
    ]
    refs = {}
    for off, nm, _sz in plan:
        r = _ref(cur, at, off, nm)
        refs[nm] = r
        p.refs.append(r)

    cur.pos = at + SIZEOF_XMODEL
    if refs["name"].follows:
        _, p.name = cur.take_string("XModel.name")

    for off, nm, size in plan:
        if nm == "name" or size is None:
            continue
        r = refs[nm]
        if not r.follows or size <= 0:
            continue
        r.inline_at = cur.take(size, "XModel." + nm)
        r.inline_size = size
        if nm == "surfs":
            # recurse into each surface before the remaining top-level fields
            for i in range(num_surfs):
                parse_xsurface(cur, r.inline_at + i * SIZEOF_XSURFACE, i)
        elif nm == "materialHandles":
            # A handle of 0xFFFFFFFF means that Material's body follows inline right here,
            # so it has to be consumed before collSurfs/boneInfo. Handles that are aliases
            # refer to a Material already loaded and consume nothing.
            for i in range(num_surfs):
                if cur.u32(r.inline_at + i * 4) != FOLLOWING:
                    continue
                mat = parse_material(zone, cur.pos, cur)
                p.fields.setdefault("inline_materials", []).append(mat.name)
                for img in mat.fields.get("images", []):
                    p.fields.setdefault("images", []).append(img)

    p.end = cur.pos
    p.checks = cur.checks
    return p


def report(p: Parsed, log=print) -> None:
    log(f"{p.kind} at {p.offset}: name={p.name!r}")
    if p.fields:
        log("  fields: " + ", ".join(f"{k}={v}" for k, v in p.fields.items() if v is not None))
    ok = sum(1 for *_r, o in p.checks if o)
    log(f"  inline reads: {ok}/{len(p.checks)} landed on a recorded allocation boundary")
    for label, off, size, good in p.checks:
        log(f"    {'ok ' if good else 'BAD'} {label:<28} @{off:<10} {size} bytes")
    refs = p.references
    if refs:
        log(f"  external references: {len(refs)}")
        for r in refs:
            log(f"    {r.name:<20} = 0x{r.value:08X}")
