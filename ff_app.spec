# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path

root = Path(SPECPATH)

a = Analysis(
    [str(root / "ff_app.py")],
    pathex=[str(root)],
    binaries=[],
    datas=[
        (str(root / "_tools" / "xmem_lzx_decompress.exe"), "_tools"),
        # gsc-tool (GSC/CSC decompiler+compiler). Fetch with fetch_gsc_tool.py
        # before building; bundled so the frozen app can decompile/recompile scripts.
        (str(root / "_tools" / "gsc-tool" / "gsc-tool.exe"), "gsc-tool"),
    ],
    hiddenimports=["gsc_tool", "zone_rebuild"],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="BO2FastFileUnpacker",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
