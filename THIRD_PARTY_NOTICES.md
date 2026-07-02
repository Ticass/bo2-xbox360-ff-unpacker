# Third-Party Notices

## LZX decompressor

`tools/lzx.c` and `tools/lzx.h` are copied from OpenAssetTools' third-party LZX
source, which identifies itself as a modified version of Wine/cabextract/unlzx
LZX decompression code.

The file headers state that the LZX code is available under the GNU General
Public License, version 2 or later.

Source reference noted by the file headers:

https://gitlab.winehq.org/wine/wine/-/blob/fcc40a07909dc7626b6d1e2ec73f823d828a47e8/dlls/itss/lzx.c

## OpenAssetTools reference

OpenAssetTools was used as a reverse-engineering reference for Xbox/Xenon T6
fastfile constants, xchunk framing, and compression/decryption behavior. The
OpenAssetTools repository itself is not vendored here.

https://github.com/Laupetin/OpenAssetTools

## gsc-tool (GSC/CSC decompiler + compiler)

The pipeline shells out to xensik's `gsc-tool` to decompile and recompile T6
(Black Ops II) GSC/CSC scripts for Xbox 360 (`-g t6 -s xb2`). The executable is
downloaded into `_tools/gsc-tool/gsc-tool.exe` and is not committed to this repo
(`_tools/` is gitignored). Run `fetch_gsc_tool.py` (or download the
`windows-x64-release.zip` asset from the release page) to obtain it.

Version pinned: 1.4.10. License: GPL-3.0.

https://github.com/xensik/gsc-tool
