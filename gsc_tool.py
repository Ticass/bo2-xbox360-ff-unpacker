#!/usr/bin/env python3
"""Wrapper around the vendored xensik/gsc-tool for T6 (BO2) Xbox 360 GSC/CSC.

gsc-tool (https://github.com/xensik/gsc-tool) natively supports Treyarch T6 on
Xbox 360, both directions:

    decompile:  gsc-tool -m decomp -g t6 -s xb2 -i server|client <blob>
    compile:    gsc-tool -m comp   -g t6 -s xb2 -i server|client <source>

`.gsc` payloads are the *server* instance, `.csc` the *client* instance.

Output quirk: gsc-tool always writes to ``<cwd>/{decompiled,compiled}/<game>/``
keyed on the input file's *basename only* (it discards the input's directory).
To avoid basename collisions between scripts that share a name in different
folders, every invocation runs in its own private temp directory and the single
result is then handed back to the caller as bytes.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

GAME = "t6"
SYSTEM = "xb2"  # Xbox 360 (big-endian). gsc-tool handles the byte order for us.
CREATE_NO_WINDOW = 0x08000000


def _no_window_run_kwargs() -> dict[str, Any]:
    """Suppress the console window when spawning gsc-tool from the GUI .exe."""
    if os.name != "nt":
        return {}
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = 0  # SW_HIDE
    return {"creationflags": CREATE_NO_WINDOW, "startupinfo": startupinfo}


def find_gsc_tool(explicit: Path | None = None) -> Path | None:
    """Locate the bundled gsc-tool executable (or one on PATH)."""
    exe = "gsc-tool.exe" if os.name == "nt" else "gsc-tool"
    here = Path(__file__).resolve().parent
    candidates: list[Path] = []
    if explicit:
        candidates.append(explicit)
    candidates += [
        here / "_tools" / "gsc-tool" / exe,
        here / "_tools" / exe,
    ]
    meipass = getattr(sys, "_MEIPASS", None)  # PyInstaller one-file bundle
    if meipass:
        candidates += [
            Path(meipass) / "gsc-tool" / exe,
            Path(meipass) / exe,
        ]
    for candidate in candidates:
        if candidate and candidate.exists():
            return candidate
    found = shutil.which("gsc-tool")
    return Path(found) if found else None


def is_client_script(name: str) -> bool:
    """`.csc`/`.cscbin` are client scripts; everything else is treated as server."""
    lowered = name.lower()
    return lowered.endswith(".csc") or lowered.endswith(".cscbin")


def _run(mode: str, src: Path, is_client: bool, tool: Path, t6fixup: bool) -> tuple[bytes | None, str]:
    """Run one gsc-tool invocation. Returns (output_bytes | None, log)."""
    with tempfile.TemporaryDirectory(prefix="gsctool_") as tmp:
        cmd = [
            str(tool),
            "-m", mode,
            "-g", GAME,
            "-s", SYSTEM,
            "-i", "client" if is_client else "server",
        ]
        if t6fixup and mode == "decomp":
            cmd.append("--t6fixup")
        cmd.append(str(src.resolve()))
        try:
            proc = subprocess.run(
                cmd,
                cwd=tmp,
                capture_output=True,
                text=True,
                **_no_window_run_kwargs(),
            )
        except OSError as exc:
            return None, f"gsc-tool spawn failed: {exc}"
        subdir = "decompiled" if mode == "decomp" else "compiled"
        produced = Path(tmp) / subdir / GAME / src.name
        log = (proc.stdout or "").strip()
        if proc.stderr:
            log = (log + "\n" + proc.stderr.strip()).strip()
        if proc.returncode != 0 or not produced.exists():
            return None, log or f"gsc-tool exited {proc.returncode} with no output"
        return produced.read_bytes(), log


def decompile(src: Path, is_client: bool | None = None, tool: Path | None = None) -> dict[str, Any]:
    """Decompile a compiled GSC/CSC blob to source text.

    Retries with ``--t6fixup`` if the first pass fails (some blobs come from
    older/broken compilers). Returns a result dict with ``ok``/``source``/``log``.
    """
    tool = tool or find_gsc_tool()
    if tool is None:
        return {"ok": False, "log": "gsc-tool executable not found"}
    if is_client is None:
        is_client = is_client_script(src.name)
    data, log = _run("decomp", src, is_client, tool, t6fixup=False)
    if data is None:
        data, log2 = _run("decomp", src, is_client, tool, t6fixup=True)
        if data is not None:
            log = f"{log}\n[retried with --t6fixup]\n{log2}".strip()
        else:
            return {"ok": False, "log": f"{log}\n[--t6fixup also failed]\n{log2}".strip()}
    return {"ok": True, "source": data, "is_client": is_client, "log": log}


def compile(src: Path, is_client: bool | None = None, tool: Path | None = None) -> dict[str, Any]:
    """Compile GSC/CSC source text back to a bytecode blob.

    Returns a result dict with ``ok``/``bytecode``/``log``.
    """
    tool = tool or find_gsc_tool()
    if tool is None:
        return {"ok": False, "log": "gsc-tool executable not found"}
    if is_client is None:
        is_client = is_client_script(src.name)
    data, log = _run("comp", src, is_client, tool, t6fixup=False)
    if data is None:
        return {"ok": False, "log": log}
    return {"ok": True, "bytecode": data, "is_client": is_client, "log": log}
