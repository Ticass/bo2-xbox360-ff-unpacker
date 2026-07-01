# Xbox 360 BO2 FastFile Unpacker

This is a Windows-friendly Xbox 360 Black Ops 2 `.ff` unpacker. The focus is
safe extraction and metadata, especially compiled `.gsc`/`.csc` script payloads.
The scripts are still compiled/encrypted game payloads; this tool does not
decompile them yet.

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
- `script_inventory.py`
  - Aggregates every `*_ff_scan/embedded_scripts.json`.
  - Writes `script_inventory.tsv`, `script_inventory.json`, and
    `script_inventory_summary.json`.
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
