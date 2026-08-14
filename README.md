# Xbox 360 BO2 FastFile Unpacker

This is a Windows-friendly Xbox 360 Black Ops 2 `.ff` unpacker. The focus is
safe extraction and metadata, especially compiled `.gsc`/`.csc` script payloads
and compiled Treyarch/Xbox Lua UI payloads. The Lua tool can now produce
readable Lua decompiled source plus Havok/T6 structural pseudo-decompilation,
but extracted scripts remain compiled game bytecode until their respective
source decompilers/compilers are complete.

This repository contains source code only. Built `.exe` files, game fastfiles,
and extracted outputs are intentionally not committed.

## Easiest workflow

1. Run `BO2FastFileUnpacker.exe` after packaging, or run `ff_app.py` during
   development.
2. Select your BO2 game folder once. The app remembers it.
3. Drag one or more `.ff` files onto the app window, or drag them onto the
   executable. The stable drag-and-drop workflow is dragging files onto the
   executable; in-window drag/drop is currently disabled.
4. Extraction starts automatically.
5. Each output folder is created beside the source `.ff`:

```text
zombie_blabla.ff
zombie_blabla\
  metadata.json
  ff_header.bin            (original 0x138 header, used when repacking)
  zone_decompressed.dat
  embedded_scripts.json
  embedded_lua.json
  embedded_menu.json
  scripts\                 (GSC/CSC, extracted verbatim)
  menus\                   (.menu files, extracted verbatim)
  ui_lua\                  (compiled Lua bytecode)
  ui_lua_readable\         (auto-decompiled near-1:1 Lua source)
  ui_lua_decompiled\
  ui_lua_hksasm\
  assets\
```

Use **Open Selected Output** in the app to jump straight to a completed folder.
For Lua-bearing fastfiles, the result table also shows readable Lua,
decompiled listing, and HKSASM counts, with quick buttons for opening the
readable/decompiled Lua folders.

## Repacking a FastFile

The app has two options:

- **Unpack** (`Unpack .ff Files`, drag `.ff` onto the app/exe): extracts a
  fastfile to a folder named after it and auto-decompiles any Lua.
- **Repack** (`Repack .zip -> .ff`, drag a `.zip` onto the app/exe): rebuilds a
  fastfile from a zip of a previously-unpacked folder. The zip is named after the
  target fastfile, e.g. `common_zm.zip` -> `common_zm.ff` (written beside the
  zip). The zip must contain the unpacked folder (the one holding
  `zone_decompressed.dat`; keep `ff_header.bin` to preserve the original name and
  signature blob).

Repack splits `zone_decompressed.dat` exactly like Xbox 360 LZX fastfiles: the
first block is the `0x28` byte XFile header, and every following block is
`0x7FC0` bytes except the final tail. It XMem/LZX-compresses each block through
the bundled XNA-backed helper, then Salsa20-encrypts it with the same
name-seeded IV chain the game regenerates. The output uses the `TAffx100` (LZX)
format. Verified: repack -> unpack round-trips the zone byte-for-byte with zero
chunk errors.

CLI equivalents:

```powershell
python .\xbox360_ff_unpacker.py C:\GAMES\merged2\common_zm.ff --decompress-zone --allow-partial-zone
python .\xbox360_ff_unpacker.py --repack C:\path\to\common_zm.zip
python .\xbox360_ff_unpacker.py --repack C:\path\to\common_zm --out C:\path\to\common_zm.ff
```

## Main tools

- `ff_app.py`
  - Simple desktop app.
  - Saves the game folder in `%APPDATA%\BO2FastFileUnpacker\config.json`.
  - Supports dragging `.ff` files onto the executable and onto the main window.
  - Writes output beside each source file using the fastfile stem as the folder
    name.
- `xbox360_ff_unpacker.py`
  - Parses the clear fastfile header.
  - Decrypts BO2 Xbox xchunks with the observed OpenAssetTools-compatible
    Salsa20 stream setup.
  - Inflates `TAffx100` XMem/LZX chunks through `_tools/xmem_lzx_decompress.exe`.
  - Inflates `TAff0100` chunks as raw deflate.
  - Repacks as `TAffx100` through `_tools/xmem_compress.exe`.
  - Extracts high-confidence embedded compiled `.gsc`/`.csc` payloads.
  - Extracts high-confidence embedded compiled `.lua` UI payloads.
- `script_inventory.py`
  - Aggregates every `*_ff_scan/embedded_scripts.json`.
  - Writes `script_inventory.tsv`, `script_inventory.json`, and
    `script_inventory_summary.json`.
- `lua_tool.py`
  - Parses BO2 Xbox/Treyarch Lua UI bytecode.
  - Writes readable Lua decompiled source for menu/UI payload triage.
  - Writes structured Havok/T6 disassembly and pseudo-decompiled listings,
    including observed nested closure bodies.
  - Writes editable bytecode workspace JSON and rebuilds `.lua` bytecode from it.
  - Writes human-editable Havok assembly (`.hksasm`) and rebuilds `.lua`
    bytecode from it.
  - Re-emits compiled Lua bytecode losslessly for recompile/repack testing.
  - Editable Lua source recompilation is not complete yet.
- `ff_dashboard.py`
  - Starts a local browser dashboard for browsing scans, script payloads,
    hashes, fastfiles, and partial-scan warnings.

## Packaging

Build the helpers, then build a shareable Windows executable:

```powershell
powershell -ExecutionPolicy Bypass -File .\build_lzx_helper.ps1
```

```powershell
powershell -ExecutionPolicy Bypass -File .\build_windows_app.ps1 -Clean
```

The packaged executable is written to:

```text
dist\BO2FastFileUnpacker.exe
```

Users can run that executable directly or drag `.ff` files onto it. The LZX
decompress helper and XMem/LZX compress helper are bundled into the executable by
`ff_app.spec`.

Requirements for packaging:

- Python 3.11+.
- PyInstaller. `build_windows_app.ps1` installs it if missing.
- A C compiler for the helper: Visual Studio Build Tools (`cl.exe`) or MinGW-w64
  (`gcc.exe`).
- .NET Framework C# compiler (`csc.exe`) for `_tools\xmem_compress.exe`.

## Quick commands

Run the desktop app during development:

```powershell
python C:\GAMES\merged2\ff_unpacker_work\ff_app.py
```

Scan one fastfile:

```powershell
python C:\GAMES\merged2\ff_unpacker_work\xbox360_ff_unpacker.py C:\GAMES\merged2\patch_zm.ff -o C:\GAMES\merged2\ff_unpacker_work\patch_zm_ff_scan --decompress-zone --allow-partial-zone --verbose
```

Rebuild the script inventory:

```powershell
python C:\GAMES\merged2\ff_unpacker_work\script_inventory.py C:\GAMES\merged2\ff_unpacker_work
```

Start the interface:

```powershell
python C:\GAMES\merged2\ff_unpacker_work\ff_dashboard.py --host 127.0.0.1 --port 8765
```

Then open:

```text
http://127.0.0.1:8765/
```

## Current script extraction rule

Observed compiled script payloads are recovered by this local layout:

```text
FFFFFFFF <big-endian payload length> FFFFFFFF <path ending .gsc/.csc>\0 <payload bytes>
```

The payload starts with `80 47 53 43` in current samples. CSC payloads observed
so far also use that magic. Extraction confidence is high only when the markers,
length, script path, bounds, and payload magic all match.

## Current Lua UI extraction rule

Observed compiled Lua UI payloads are recovered by this local layout:

```text
FFFFFFFF <big-endian payload length> FFFFFFFF <path ending .lua>\0 <Lua bytecode payload>
```

The payload starts with `1B 4C 75 61` (`\x1bLua`). These files are written to
`ui_lua\` using their original `.lua` paths, but they are compiled Xbox/Treyarch
Lua bytecode.

The app also writes:

- `ui_lua_readable\`: readable Lua decompiled source with inferred local names
  and recovered table constructors, method calls, simple branches, and loops.
- `ui_lua_decompiled\`: constants, nested functions, and Havok/T6 opcode
  disassembly for reverse engineering.
- `ui_lua_hksasm\`: editable Havok assembly. These `.hksasm` files can be
  rebuilt with `lua_tool.py recompile-asm` or `recompile-asm-dir`.

Confirmed examples:

- `patch_ui_zm.ff`: `47` Lua UI payloads extracted.
- `patch_ui_mp.ff`: `139` Lua UI payloads extracted.

Examples include:

- `ui/t6/lobby.lua`
- `ui/t6/buttonlist.lua`
- `ui/t6/cod9button.lua`
- `ui_mp/t6/menus/publicgamelobby.lua`

## Current known limitation

`common_mp.ff` currently scans only as a partial zone. The LZX helper fails on
chunk 81 at fastfile offset `0x0010B2BC`; the scanner records this in
`common_mp_ff_scan/metadata.json` and still scans the valid prefix. No embedded
script payloads were found in that prefix.

For script extraction testing, use script-bearing files such as:

- `patch_mp.ff`
- `patch_zm.ff`
- `zm_highrise_patch.ff`
- `zm_prison_patch.ff`
- `zm_tomb_patch.ff`
- `zm_transit_dr_patch.ff`

For Lua UI extraction testing, use:

- `patch_ui_mp.ff`
- `patch_ui_zm.ff`

## Lua decompile/recompile tooling

Disassemble one compiled Lua payload:

```powershell
python .\lua_tool.py disasm path\to\buttonlist.lua -o buttonlist.disasm.txt --json buttonlist.json
```

Write a pseudo-decompiled listing:

```powershell
python .\lua_tool.py decompile path\to\buttonlist.lua -o buttonlist.pseudo.lua
```

Write readable Lua decompiled source:

```powershell
python .\lua_tool.py decompile-source path\to\buttonlist.lua -o buttonlist.readable.lua
```

Pseudo-decompile a folder:

```powershell
python .\lua_tool.py decompile-dir path\to\ui_lua -o path\to\ui_lua_decompiled
```

Write readable decompiled source for a folder:

```powershell
python .\lua_tool.py decompile-source-dir path\to\ui_lua -o path\to\ui_lua_readable
```

Write editable bytecode JSON for one payload:

```powershell
python .\lua_tool.py decompile-json path\to\buttonlist.lua -o buttonlist.edit.json
```

Rebuild bytecode from editable JSON:

```powershell
python .\lua_tool.py recompile buttonlist.edit.json -o buttonlist.rebuilt.lua
```

Batch editable JSON workflow:

```powershell
python .\lua_tool.py decompile-json-dir path\to\ui_lua -o path\to\ui_lua_edit_json
python .\lua_tool.py recompile-json-dir path\to\ui_lua_edit_json -o path\to\ui_lua_rebuilt --source-root path\to\ui_lua
```

Write editable Havok assembly for one payload:

```powershell
python .\lua_tool.py decompile-asm path\to\buttonlist.lua -o buttonlist.hksasm
```

Rebuild bytecode from Havok assembly:

```powershell
python .\lua_tool.py recompile-asm buttonlist.hksasm -o buttonlist.rebuilt.lua
```

Batch assembly workflow:

```powershell
python .\lua_tool.py decompile-asm-dir path\to\ui_lua -o path\to\ui_lua_hksasm
python .\lua_tool.py recompile-asm-dir path\to\ui_lua_hksasm -o path\to\ui_lua_rebuilt --source-root path\to\ui_lua
```

Losslessly re-emit compiled bytecode:

```powershell
python .\lua_tool.py recompile path\to\buttonlist.lua -o buttonlist.recompiled.lua
```

Editable JSON rebuild currently supports same-length string constant edits,
boolean/number constant edits, decoded instruction edits (`opname`, `a`, `b`,
`c`, `bx`, `sbx`), and raw 4-byte instruction edits. The compiler patches the
original byte array by offset and preserves all unknown Havok fields.
The `.hksasm` workflow exposes the same editable fields in a line-oriented text
format and embeds compressed workspace metadata at EOF for safe rebuilding.
Length-changing string edits, adding/removing constants, adding/removing
instructions, and compiling readable Lua source are not implemented yet.

## GSC/CSC decompile and full recompile round-trip

On unpack, every embedded GSC/CSC script is decompiled to editable source under
`scripts_src/` (verbatim compiled payloads remain in `scripts/`). This uses the
vendored `gsc-tool`, which is **not** committed — fetch it first:

```powershell
python .\fetch_gsc_tool.py   # downloads _tools/gsc-tool/gsc-tool.exe (xensik, v1.4.10)
```

To edit and rebuild a working `.ff`:

1. Unpack a `.ff` (drag it onto the app, or run the unpacker).
2. Edit files under `<name>_ff_scan/scripts_src/` (GSC/CSC source) and/or
   `<name>_ff_scan/ui_lua_hksasm/` (Lua HKS assembly).
3. Repack by dropping the unpacked folder (or its `.zip`) onto the app, or:

```powershell
python .\xbox360_ff_unpacker.py --repack path\to\<name>_ff_scan -o rebuilt.ff
```

Only sources whose contents changed since unpack are recompiled; everything else
is spliced back byte-for-byte. GSC/CSC support arbitrary edits (gsc-tool is a real
compiler). Lua edits use the lossless HKS-assembly path (same-length constant /
instruction edits). To recompile in place without producing a `.ff`:

```powershell
python .\xbox360_ff_unpacker.py --recompile path\to\<name>_ff_scan
```

The original zone is backed up to `zone_decompressed.dat.orig` on first rebuild.

### Loading rebuilt fastfiles (signature note)

The FastFile header carries an **RSA-2048 signature** (256 bytes at 0x38) that
only Treyarch can generate, so an edited zone cannot be re-signed and a **stock**
retail xex rejects it. This is cryptographic, not a tooling gap, and is equally
true under Xenia (Xenia runs the real xex).

Everything else the loader needs is reproduced correctly — the repacker rebuilds
the Salsa20 IV chain and the per-chunk SHA-1 integrity chain, verified byte-for-byte
by re-unpacking the output. So a rebuilt `.ff` loads in **retail T6** when the xex
has the fastfile signature check patched to always pass (a one-function NOP /
force-valid). In BO2 that patched MP executable (e.g. `default_mp_patched.xex`)
runs **both multiplayer and Zombies**. This is still the retail T6 game, not a
reimplementation such as Plutonium. Keep the rebuilt file's name identical to the
original — the IV chain is seeded from the fastfile name (rebuild `patch_zm.ff` as
`patch_zm.ff`).

The function to patch is **`sub_822AA908` at `0x822AA908`** (retail `default_mp.xex`); force
it to return 1. It is the RSA verify itself: SHA-256 over the whole 16,000-byte accumulated
hash-block table at `0x82CBC444`, against the 256-byte signature staged at `0x82CBC344`.

Be aware that **an unpatched load does not report an error**. `DB_AuthLoad_End`
(`0x822AAA28`) responds to a failed verify by adding 2048 to `g_copyInfoCount`
(`0x82DEA1AC`), so `DB_PostLoadXZone` later walks 2048 never-written entries and dereferences
a null — the title dies seconds later, several zones on, inside
`DB_LinkXAssetEntry -> DB_GetXAssetName`, with nothing in the stack pointing at the
signature. If you are chasing a crash like that, check the signature patch first. Note also
that `DB_AuthLoad_CheckHeaders` (`0x822AAAC0`) is **not** the check — its result only feeds
tamper telemetry. Full detail in `FF_RE_NOTES.md`.

## Growing assets: pointer relocation

Editing a zone in place is easy; making an asset **bigger** is not. Zone pointers are stored
as `((block << 29) | offset) + 1` and resolved against the destination XBlock bases, so
growing an allocation shifts every later allocation in that block and invalidates every
encoded pointer past it. `reloc.py` handles that.

It needs a captured pointer table, `zone_ptrs.bin`, recorded from one real load of the stock
zone. The capture comes from hooking four loader functions in the running game:

| Address | Function | Recorded |
| --- | --- | --- |
| `0x822AD610` | `DB_LoadXFileData(dest, size)` | stream-to-address map |
| `0x822AD760` | `DB_LoadXFileDataNullTerminated(dest)` | string reads (needed, or ~82 KB is unmapped) |
| `0x822CC358` | `DB_ConvertOffsetToPointer(field)` | pointer field + encoded value |
| `0x822CC330` | `DB_ConvertOffsetToAlias(field)` | same, plus one deref |

Records are 12 bytes, `{u32 kind, u32 a, u32 b}`; XBlock bases (`kind 4`) are read from
`*(u32*)0x832DE59C`. `reloc.py`'s docstring documents the format so any hooking setup can
produce it.

Two things that are easy to get wrong, both documented in `FF_RE_NOTES.md`:

- **Resolve fields temporally, not by address.** XBlock 0 is a reused scratch block; one
  field there held five different encoded pointers during a single load.
- **Round the growth up to a multiple of 4096.** The loader pads allocations to an alignment
  boundary, so a raw +4183-byte payload shifted later allocations by only +4096. Relocating
  by the raw delta leaves every pointer 87 bytes long and crashes material loading.

```bash
# 1. capture zone_ptrs.bin from a stock load (see the hook table above)
# 2. inspect coverage -- both numbers should be complete
python reloc.py
#   pointers resolved 11731, stream mapped 7295715 of 7295715 bytes
#   pointer fields not written from the stream: 0
```

`inject_gsc.py` replaces a ScriptParseTree payload. It has two modes: **fit** (new payload is
smaller or equal - zero-pad it, nothing moves, no relocation) and **grow** (larger - go
through `reloc.py`). Use `gsc_slack.py` to see how much headroom each script already has,
since gsc-tool output is consistently smaller than Treyarch's compiler:

```bash
python gsc_slack.py
#   maps/mp/_createfx.gsc                orig= 47458 recomp= 39014 slack= +8444
#   maps/mp/zombies/_zm_utility.gsc      orig= 69331 recomp= 64815 slack= +4516
```

## Example: a GSC mod menu

`build_menu.py` is an end-to-end example. It decompiles
`maps/mp/gametypes_zm/_callbacksetup.gsc`, threads `mm_main()` from
`codecallback_playerconnect`, appends `menu_body.gsc`, recompiles, grows the zone through the
relocator, and rewrites the length field:

```bash
python build_menu.py
#   payload: 5746 -> 13938 bytes (raw delta +4183, padded to +8192 for alignment)
#   pointers: 129 relocated, 11602 untouched, 0 not written from stream, 0 UNRESOLVED
#   header: stream 7295675 -> 7303867, XBlock[5] 7286801 -> 7294993
python xbox360_ff_unpacker.py --repack patch_zm_mod_scan --no-recompile --out patch_zm.ff
```

`menu_body.gsc` is a small menu - god mode, no clip, infinite ammo - opened with aim + knife,
navigated with the d-pad, toggled with use.

**Status:** the grown zone loads, the zone-health canary matches stock exactly, and the map
reaches gameplay with players connecting and spawning through the modified script. The menu
panel itself has **not** been confirmed on screen yet; its HUD elements set
`hidewheninmenu = 1`, so verifying it needs the game window focused from launch (otherwise
the title auto-pauses on focus change and the panel is hidden by design). Treat the menu's
on-screen behaviour as untested.
