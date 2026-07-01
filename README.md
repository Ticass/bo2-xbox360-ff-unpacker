# Xbox 360 BO2 FastFile Unpacker

This is a Windows-friendly Xbox 360 Black Ops 2 `.ff` unpacker. The focus is
safe extraction and metadata, especially compiled `.gsc`/`.csc` script payloads
and compiled Treyarch/Xbox Lua UI payloads. The Lua tool can now produce
Havok/T6 structural pseudo-decompilation, but extracted scripts remain compiled
game bytecode until their respective source decompilers/compilers are complete.

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
  zone_decompressed.dat
  embedded_scripts.json
  embedded_lua.json
  scripts\
  ui_lua\
  assets\
```

Use **Open Selected Output** in the app to jump straight to a completed folder.

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
  - Extracts high-confidence embedded compiled `.gsc`/`.csc` payloads.
  - Extracts high-confidence embedded compiled `.lua` UI payloads.
- `script_inventory.py`
  - Aggregates every `*_ff_scan/embedded_scripts.json`.
  - Writes `script_inventory.tsv`, `script_inventory.json`, and
    `script_inventory_summary.json`.
- `lua_tool.py`
  - Parses BO2 Xbox/Treyarch Lua UI bytecode.
  - Writes structured Havok/T6 disassembly and pseudo-decompiled listings,
    including observed nested closure bodies.
  - Writes editable bytecode workspace JSON and rebuilds `.lua` bytecode from it.
  - Re-emits compiled Lua bytecode losslessly for recompile/repack testing.
  - Editable Lua source recompilation is not complete yet.
- `ff_dashboard.py`
  - Starts a local browser dashboard for browsing scans, script payloads,
    hashes, fastfiles, and partial-scan warnings.

## Packaging

Build the LZX helper, then build a shareable Windows executable:

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
helper is bundled into the executable by `ff_app.spec`.

Requirements for packaging:

- Python 3.11+.
- PyInstaller. `build_windows_app.ps1` installs it if missing.
- A C compiler for the helper: Visual Studio Build Tools (`cl.exe`) or MinGW-w64
  (`gcc.exe`).

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
Lua bytecode, not readable Lua source yet.

The app also writes pseudo-decompiled listings to `ui_lua_decompiled\`. These
files expose constants, nested functions, and Havok/T6 opcode disassembly for
reverse engineering. They are not yet valid editable source code.

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

Pseudo-decompile a folder:

```powershell
python .\lua_tool.py decompile-dir path\to\ui_lua -o path\to\ui_lua_decompiled
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

Losslessly re-emit compiled bytecode:

```powershell
python .\lua_tool.py recompile path\to\buttonlist.lua -o buttonlist.recompiled.lua
```

Editable JSON rebuild currently supports same-length string constant edits,
boolean/number constant edits, decoded instruction edits (`opname`, `a`, `b`,
`c`, `bx`, `sbx`), and raw 4-byte instruction edits. The compiler patches the
original byte array by offset and preserves all unknown Havok fields.
Length-changing string edits, adding/removing constants, adding/removing
instructions, and compiling readable Lua source are not implemented yet.
