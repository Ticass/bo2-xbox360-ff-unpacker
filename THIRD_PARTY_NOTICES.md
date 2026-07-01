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
