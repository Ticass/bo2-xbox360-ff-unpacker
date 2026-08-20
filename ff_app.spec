# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path

root = Path(SPECPATH)

BRAND = "crybaby's repacker"
APP_VERSION = "1.4.0"

a = Analysis(
    [str(root / "ff_app.py")],
    pathex=[str(root)],
    binaries=[],
    datas=[
        (str(root / "_tools" / "xmem_lzx_decompress.exe"), "_tools"),
        (str(root / "_tools" / "xmem_compress.exe"), "_tools"),
        # gsc-tool (GSC/CSC decompiler+compiler). Fetch with fetch_gsc_tool.py
        # before building; bundled so the frozen app can decompile/recompile scripts.
        (str(root / "_tools" / "gsc-tool" / "gsc-tool.exe"), "gsc-tool"),
    ],
    # gsc_link is imported lazily inside zone_rebuild._link_check; name it here so a
    # refactor cannot silently drop the link checker out of the frozen build.
    hiddenimports=["gsc_tool", "zone_rebuild", "gsc_link"],
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
    name="crybabys-repacker",
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
    version=str(root / "version_info.txt"),
)
