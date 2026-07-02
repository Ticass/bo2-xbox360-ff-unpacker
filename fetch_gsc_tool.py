#!/usr/bin/env python3
"""Download the vendored gsc-tool executable into _tools/gsc-tool/.

gsc-tool (https://github.com/xensik/gsc-tool) is GPL-3.0 and is not committed to
this repo (`_tools/` is gitignored). This helper fetches the pinned release for
the current platform so the GSC/CSC decompile/recompile path works out of the box.

    python fetch_gsc_tool.py
"""

from __future__ import annotations

import io
import os
import platform
import stat
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

VERSION = "1.4.10"
BASE = f"https://github.com/xensik/gsc-tool/releases/download/{VERSION}"


def _asset_for_platform() -> tuple[str, str]:
    """Return (asset_filename, exe_name) for the running platform."""
    machine = platform.machine().lower()
    is_arm = machine in {"arm64", "aarch64"}
    if os.name == "nt":
        return (f"windows-{'arm64' if is_arm else 'x64'}-release.zip", "gsc-tool.exe")
    if sys.platform == "darwin":
        return (f"macos-{'arm64' if is_arm else 'amd64'}-release.tar.gz", "gsc-tool")
    return (f"linux-{'arm64' if is_arm else 'amd64'}-release.tar.gz", "gsc-tool")


def main() -> int:
    asset, exe_name = _asset_for_platform()
    url = f"{BASE}/{asset}"
    dest_dir = Path(__file__).resolve().parent / "_tools" / "gsc-tool"
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / exe_name

    print(f"Downloading gsc-tool {VERSION} for this platform:\n  {url}")
    with urllib.request.urlopen(url) as response:  # noqa: S310 - trusted GitHub release
        blob = response.read()

    if asset.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            member = next(n for n in zf.namelist() if n.endswith(exe_name))
            dest.write_bytes(zf.read(member))
    else:
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
            member = next(m for m in tf.getmembers() if m.name.endswith(exe_name))
            extracted = tf.extractfile(member)
            if extracted is None:
                print("error: could not read gsc-tool from archive", file=sys.stderr)
                return 1
            dest.write_bytes(extracted.read())

    if os.name != "nt":
        dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    print(f"Installed: {dest} ({dest.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
