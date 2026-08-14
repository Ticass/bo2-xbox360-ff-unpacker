#!/usr/bin/env python3
"""User-facing desktop app for the Xbox 360 BO2 fastfile unpacker."""

from __future__ import annotations

import ctypes
import json
import os
import queue
import struct
import sys
import threading
import traceback
from types import SimpleNamespace
from pathlib import Path
from tkinter import BOTH, END, LEFT, RIGHT, X, filedialog, messagebox, ttk
import tkinter as tk

from lua_tool import cmd_decompile_asm_dir, cmd_decompile_dir, cmd_decompile_source_dir
from xbox360_ff_unpacker import (
    FastFileScanner,
    augment_manifest_lua_sources,
    repack_fastfile_from_folder,
    repack_fastfile_from_zip,
    write_json,
)


BRAND = "crybaby's repacker"
APP_VERSION = "1.3.0"
APP_NAME = f"{BRAND} - BO2 Xbox 360 FastFile Unpacker"
CONFIG_PATH = Path.home() / "AppData" / "Roaming" / "BO2FastFileUnpacker" / "config.json"
WM_DROPFILES = 0x0233
GWLP_WNDPROC = -4
ENABLE_EXPERIMENTAL_WINDOW_DROP = False


def app_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def bundled_root() -> Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)  # type: ignore[attr-defined]
    return Path(__file__).resolve().parent


def default_lzx_helper() -> Path:
    return bundled_root() / "_tools" / "xmem_lzx_decompress.exe"


def load_config() -> dict:
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def save_config(config: dict) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")


def ff_output_dir(path: Path) -> Path:
    return path.with_suffix("")


def extract_fastfile(path: Path, lzx_helper: Path, log) -> dict:
    if path.suffix.lower() != ".ff":
        raise ValueError(f"Not a .ff file: {path}")
    if not path.exists():
        raise FileNotFoundError(path)

    out_dir = ff_output_dir(path)
    metadata_path = out_dir / "metadata.json"
    log(f"Reading {path.name}")

    scanner = FastFileScanner(path, verbose=False)
    metadata = scanner.scan(probe_decrypt=True)
    out_dir.mkdir(parents=True, exist_ok=True)

    log(f"Unpacking {path.name} -> {out_dir.name}\\")
    metadata["decompressed_zone"] = scanner.decompress_zone_stream(
        out_dir,
        lzx_helper,
        scan_menus=False,
        allow_partial_zone=True,
    )
    write_json(metadata_path, metadata)

    decompressed_zone = metadata.get("decompressed_zone", {})
    embedded_scripts = decompressed_zone.get("embedded_scripts", {})
    scripts = embedded_scripts.get("count", 0)
    scripts_decompiled = embedded_scripts.get("decompiled_count", 0)
    scripts_decompile_failures = embedded_scripts.get("decompile_failures", 0)
    gsc_tool_found = embedded_scripts.get("gsc_tool_found", False)
    lua_files = decompressed_zone.get("embedded_lua", {}).get("count", 0)
    menu_files = decompressed_zone.get("embedded_menu", {}).get("count", 0)
    partial = decompressed_zone.get("partial_zone", False)
    chunk_errors = decompressed_zone.get("chunk_errors", [])
    lua_decompiled = 0
    lua_decompile_out = out_dir / "ui_lua_decompiled"
    lua_readable = 0
    lua_readable_out = out_dir / "ui_lua_readable"
    lua_asm = 0
    lua_asm_out = out_dir / "ui_lua_hksasm"
    if lua_files:
        log(f"Generating readable Lua decompile for {path.name}")
        try:
            cmd_decompile_source_dir(SimpleNamespace(input=out_dir / "ui_lua", out=lua_readable_out))
            manifest = json.loads((lua_readable_out / "decompile_source_manifest.json").read_text(encoding="utf-8"))
            lua_readable = int(manifest.get("decompiled_source") or 0)
        except Exception:
            lua_readable = 0
        log(f"Generating Lua pseudo-decompile listings for {path.name}")
        try:
            cmd_decompile_dir(SimpleNamespace(input=out_dir / "ui_lua", out=lua_decompile_out))
            manifest = json.loads((lua_decompile_out / "decompile_manifest.json").read_text(encoding="utf-8"))
            lua_decompiled = int(manifest.get("decompiled") or 0)
        except Exception:
            lua_decompiled = 0
        log(f"Generating editable Lua HKS assembly for {path.name}")
        try:
            cmd_decompile_asm_dir(SimpleNamespace(input=out_dir / "ui_lua", out=lua_asm_out))
            manifest = json.loads((lua_asm_out / "decompile_asm_manifest.json").read_text(encoding="utf-8"))
            lua_asm = int(manifest.get("decompiled_asm") or 0)
        except Exception:
            lua_asm = 0
        # Link RawFile Lua assets to their editable HKS assembly in the repack manifest.
        try:
            augment_manifest_lua_sources(out_dir)
        except Exception:
            pass
    result_readme = out_dir / "README_EXTRACT_RESULT.txt"
    if scripts or lua_files or menu_files:
        found_lines = [
            f"Compiled GSC/CSC script payloads extracted: {scripts}",
            f"GSC/CSC scripts decompiled to source (scripts_src): {scripts_decompiled}"
            + (f" ({scripts_decompile_failures} failed)" if scripts_decompile_failures else ""),
            f"Compiled Lua UI payloads extracted: {lua_files}",
            f"Menu (.menu) payloads extracted: {menu_files}",
        ]
        folder_lines = []
        if scripts:
            folder_lines.extend(["Open the scripts folder for verbatim compiled .gsc/.csc payloads:", str(out_dir / "scripts"), ""])
            if scripts_decompiled:
                folder_lines.extend(["Open the scripts_src folder for decompiled, editable GSC/CSC source:", str(out_dir / "scripts_src"), ""])
            elif not gsc_tool_found:
                folder_lines.extend(["GSC/CSC decompile skipped: gsc-tool executable was not found under _tools/gsc-tool/.", ""])
        if menu_files:
            folder_lines.extend(["Open the menus folder for extracted .menu payloads:", str(out_dir / "menus"), ""])
        if lua_files:
            folder_lines.extend(["Open the ui_lua folder for extracted .lua bytecode payloads:", str(out_dir / "ui_lua"), ""])
            folder_lines.extend(["Open the ui_lua_readable folder for readable Lua decompile:", str(lua_readable_out), ""])
            folder_lines.extend(["Open the ui_lua_decompiled folder for pseudo-decompiled listings:", str(lua_decompile_out), ""])
            folder_lines.extend(["Open the ui_lua_hksasm folder for editable Havok assembly:", str(lua_asm_out), ""])
        result_readme.write_text(
            "\n".join(
                [
                    f"FastFile: {path}",
                    f"Status: {'partial scan' if partial else 'complete scan'}",
                    "",
                    *found_lines,
                    "",
                    *folder_lines,
                    "Note: scripts/ holds verbatim compiled GSC/CSC bytecode; scripts_src/ holds decompiled, editable GSC/CSC source (gsc-tool). ui_lua holds compiled Lua bytecode.",
                    "Lua readable files are decompiled source with inferred local names/control flow; .hksasm files are editable bytecode assembly.",
                    "Edit files under scripts_src/ (and Lua) then repack the folder to recompile them back into a working .ff.",
                    "",
                ]
            ),
            encoding="utf-8",
        )
    else:
        reason = "No embedded GSC/CSC payloads matched the current extractor."
        if partial and chunk_errors:
            reason = (
                "This scan is partial because decompression stopped before the whole FastFile was readable. "
                "No embedded GSC/CSC payloads were found before that stop point."
            )
        result_readme.write_text(
            "\n".join(
                [
                    f"FastFile: {path}",
                    f"Status: {'partial scan' if partial else 'complete scan'}",
                    "Compiled script payloads extracted: 0",
                    "Compiled Lua UI payloads extracted: 0",
                    "",
                    reason,
                    "",
                    "Try script-bearing files such as patch_mp.ff, patch_zm.ff, or map patch FastFiles.",
                    "Try UI Lua-bearing files such as patch_ui_zm.ff or patch_ui_mp.ff.",
                    "Technical metadata is in metadata.json.",
                    "",
                ]
            ),
            encoding="utf-8",
        )
    return {
        "source": str(path),
        "output": str(out_dir),
        "metadata": str(metadata_path),
        "scripts": scripts,
        "scripts_decompiled": scripts_decompiled,
        "lua_files": lua_files,
        "menu_files": menu_files,
        "lua_decompiled": lua_decompiled,
        "lua_readable": lua_readable,
        "lua_asm": lua_asm,
        "partial": partial,
        "readme": str(result_readme),
    }


class WindowsDropTarget:
    """Minimal WM_DROPFILES support without external dependencies."""

    def __init__(self, root: tk.Tk, callback):
        self.root = root
        self.callback = callback
        self.hwnd = root.winfo_id()
        self.old_proc = None
        self.new_proc = None
        if os.name == "nt":
            self.install()

    def install(self) -> None:
        shell32 = ctypes.windll.shell32
        user32 = ctypes.windll.user32
        shell32.DragAcceptFiles(self.hwnd, True)

        if struct.calcsize("P") == 8:
            wndproc_type = ctypes.WINFUNCTYPE(
                ctypes.c_longlong,
                ctypes.c_void_p,
                ctypes.c_uint,
                ctypes.c_void_p,
                ctypes.c_void_p,
            )
            set_window_long = user32.SetWindowLongPtrW
            call_window_proc = user32.CallWindowProcW
            set_window_long.restype = ctypes.c_void_p
            call_window_proc.restype = ctypes.c_longlong
        else:
            wndproc_type = ctypes.WINFUNCTYPE(
                ctypes.c_long,
                ctypes.c_void_p,
                ctypes.c_uint,
                ctypes.c_void_p,
                ctypes.c_void_p,
            )
            set_window_long = user32.SetWindowLongW
            call_window_proc = user32.CallWindowProcW
            set_window_long.restype = ctypes.c_void_p
            call_window_proc.restype = ctypes.c_long

        def wndproc(hwnd, msg, wparam, lparam):
            if msg == WM_DROPFILES:
                count = shell32.DragQueryFileW(wparam, 0xFFFFFFFF, None, 0)
                paths = []
                for index in range(count):
                    length = shell32.DragQueryFileW(wparam, index, None, 0)
                    buffer = ctypes.create_unicode_buffer(length + 1)
                    shell32.DragQueryFileW(wparam, index, buffer, length + 1)
                    paths.append(Path(buffer.value))
                shell32.DragFinish(wparam)
                self.root.after(0, lambda: self.callback(paths))
                return 0
            return call_window_proc(self.old_proc, hwnd, msg, wparam, lparam)

        self.new_proc = wndproc_type(wndproc)
        self.old_proc = set_window_long(self.hwnd, GWLP_WNDPROC, self.new_proc)

    def uninstall(self) -> None:
        if os.name != "nt" or not self.old_proc:
            return
        ctypes.windll.user32.SetWindowLongPtrW(self.hwnd, GWLP_WNDPROC, self.old_proc)


class FastFileApp:
    def __init__(self, root: tk.Tk, startup_files: list[Path]):
        self.root = root
        self.config = load_config()
        self.game_folder = tk.StringVar(value=self.config.get("game_folder", ""))
        self.status_text = tk.StringVar(value="Select your game folder, then choose .ff files or drag them onto the executable.")
        self.progress_text = tk.StringVar(value="")
        self.progress_value = tk.DoubleVar(value=0)
        self.work_queue: queue.Queue = queue.Queue()
        self.pending_files: list[Path] = []
        self.results: list[dict] = []
        self.worker: threading.Thread | None = None
        self.drop_target: WindowsDropTarget | None = None
        self.closing = False

        self.build_ui()
        self.root.update_idletasks()
        # Dragging files onto the packaged .exe is stable because Windows passes
        # dropped file paths as argv. Tk window-level drag/drop on Windows needs
        # message subclassing or an extra native extension; keep the subclass
        # disabled until it is fully proven to avoid unclosable flashing windows.
        if ENABLE_EXPERIMENTAL_WINDOW_DROP:
            self.drop_target = WindowsDropTarget(root, self.on_drop)
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.poll_worker()

        if startup_files:
            self.root.after(250, lambda: self.add_files(startup_files, auto_start=True))

    def build_ui(self) -> None:
        self.root.title(f"{APP_NAME}  v{APP_VERSION}")
        self.root.geometry("920x620")
        self.root.minsize(760, 520)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background="#111317")
        style.configure("Panel.TFrame", background="#181b21", relief="flat")
        style.configure("TLabel", background="#111317", foreground="#f4f6f8", font=("Segoe UI", 10))
        style.configure("Muted.TLabel", background="#111317", foreground="#aeb6c2")
        style.configure("Title.TLabel", font=("Segoe UI", 20, "bold"))
        style.configure("Drop.TLabel", background="#181b21", foreground="#dfe8f2", font=("Segoe UI", 14, "bold"))
        style.configure("TButton", font=("Segoe UI", 10), padding=(12, 7))
        style.configure("Accent.TButton", background="#2f80ed", foreground="#ffffff")
        style.configure("Horizontal.TProgressbar", background="#2f80ed", troughcolor="#282d36")
        style.configure("Treeview", background="#181b21", fieldbackground="#181b21", foreground="#f4f6f8", rowheight=28)
        style.configure("Treeview.Heading", background="#242934", foreground="#dce3ec", font=("Segoe UI", 9, "bold"))

        outer = ttk.Frame(self.root, padding=22)
        outer.pack(fill=BOTH, expand=True)

        header = ttk.Frame(outer)
        header.pack(fill=X)
        title_box = ttk.Frame(header)
        title_box.pack(side=LEFT)
        ttk.Label(title_box, text=BRAND, style="Title.TLabel").pack(anchor="w")
        ttk.Label(title_box, text=f"BO2 Xbox 360 FastFile unpacker / repacker  ·  v{APP_VERSION}",
                  style="Muted.TLabel").pack(anchor="w")
        ttk.Button(header, text="Select Game Folder", style="Accent.TButton", command=self.select_game_folder).pack(side=RIGHT)

        folder_row = ttk.Frame(outer)
        folder_row.pack(fill=X, pady=(14, 18))
        ttk.Label(folder_row, text="Game folder", style="Muted.TLabel").pack(anchor="w")
        folder_box = ttk.Frame(folder_row)
        folder_box.pack(fill=X, pady=(5, 0))
        self.folder_entry = ttk.Entry(folder_box, textvariable=self.game_folder)
        self.folder_entry.pack(side=LEFT, fill=X, expand=True)
        ttk.Button(folder_box, text="Save", command=self.save_game_folder_from_entry).pack(side=RIGHT, padx=(8, 0))

        drop = ttk.Frame(outer, style="Panel.TFrame", padding=28)
        drop.pack(fill=X)
        ttk.Label(drop, text="Drag .ff files here to unpack, or an unpacked folder / .zip to repack", style="Drop.TLabel").pack(anchor="center")
        ttk.Label(
            drop,
            text="Unpack: each .ff extracts to a folder beside it (decompiled GSC/CSC in scripts_src, .menu, Lua). "
            "Repack: drop the unpacked folder (or its .zip) to recompile edited scripts_src/ and Lua and rebuild the .ff.",
            background="#181b21",
            foreground="#aeb6c2",
            wraplength=760,
            justify="center",
        ).pack(anchor="center", pady=(6, 16))
        actions = ttk.Frame(drop, style="Panel.TFrame")
        actions.pack(anchor="center")
        ttk.Button(actions, text="Unpack .ff Files", style="Accent.TButton", command=self.choose_files).pack(side=LEFT, padx=4)
        ttk.Button(actions, text="Extract All From Game Folder", command=self.extract_all_from_game_folder).pack(side=LEFT, padx=4)
        ttk.Button(actions, text="Repack .zip -> .ff", command=self.choose_zip).pack(side=LEFT, padx=4)

        status_row = ttk.Frame(outer)
        status_row.pack(fill=X, pady=(18, 8))
        ttk.Label(status_row, textvariable=self.status_text).pack(side=LEFT)
        ttk.Label(status_row, textvariable=self.progress_text, style="Muted.TLabel").pack(side=RIGHT)

        self.progress = ttk.Progressbar(outer, variable=self.progress_value, maximum=100)
        self.progress.pack(fill=X)

        table_frame = ttk.Frame(outer)
        table_frame.pack(fill=BOTH, expand=True, pady=(16, 10))
        self.tree = ttk.Treeview(
            table_frame,
            columns=("status", "scripts", "lua_readable", "lua_decompiled", "lua_asm", "output"),
            show="headings",
        )
        self.tree.heading("status", text="Status")
        self.tree.heading("scripts", text="Scripts / Lua")
        self.tree.heading("lua_readable", text="Readable Lua")
        self.tree.heading("lua_decompiled", text="Decompiled")
        self.tree.heading("lua_asm", text="HKSASM")
        self.tree.heading("output", text="Output")
        self.tree.column("status", width=135, anchor="w")
        self.tree.column("scripts", width=85, anchor="center")
        self.tree.column("lua_readable", width=95, anchor="center")
        self.tree.column("lua_decompiled", width=90, anchor="center")
        self.tree.column("lua_asm", width=75, anchor="center")
        self.tree.column("output", width=430, anchor="w")
        self.tree.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side=RIGHT, fill="y")
        self.tree.configure(yscrollcommand=scrollbar.set)

        footer = ttk.Frame(outer)
        footer.pack(fill=X)
        ttk.Button(footer, text="Open Selected Output", command=self.open_selected_output).pack(side=LEFT)
        ttk.Button(footer, text="Open Decompiled Scripts", command=lambda: self.open_selected_subfolder("scripts_src")).pack(side=LEFT, padx=(8, 0))
        ttk.Button(footer, text="Open Readable Lua", command=lambda: self.open_selected_subfolder("ui_lua_readable")).pack(side=LEFT, padx=(8, 0))
        ttk.Button(footer, text="Open Decompiled Lua", command=lambda: self.open_selected_subfolder("ui_lua_decompiled")).pack(side=LEFT, padx=(8, 0))
        ttk.Button(footer, text="Clear List", command=self.clear_list).pack(side=LEFT, padx=(8, 0))

    def select_game_folder(self) -> None:
        initial = self.game_folder.get() if Path(self.game_folder.get()).exists() else str(Path.home())
        folder = filedialog.askdirectory(title="Select BO2 game folder", initialdir=initial)
        if folder:
            self.set_game_folder(folder)

    def save_game_folder_from_entry(self) -> None:
        folder = self.game_folder.get().strip()
        if not folder:
            messagebox.showwarning(APP_NAME, "Choose a game folder first.")
            return
        self.set_game_folder(folder)

    def set_game_folder(self, folder: str) -> None:
        path = Path(folder).resolve()
        if not path.exists() or not path.is_dir():
            messagebox.showerror(APP_NAME, f"Folder does not exist:\n{path}")
            return
        self.game_folder.set(str(path))
        self.config["game_folder"] = str(path)
        save_config(self.config)
        count = len(list(path.glob("*.ff")))
        self.status_text.set(f"Game folder saved. Found {count} .ff files.")

    def choose_files(self) -> None:
        initial = self.game_folder.get() if Path(self.game_folder.get()).exists() else str(Path.home())
        names = filedialog.askopenfilenames(
            title="Choose .ff files",
            initialdir=initial,
            filetypes=[("FastFiles", "*.ff"), ("All files", "*.*")],
        )
        self.add_files([Path(name) for name in names], auto_start=True)

    def extract_all_from_game_folder(self) -> None:
        folder = Path(self.game_folder.get())
        if not folder.exists():
            messagebox.showwarning(APP_NAME, "Select your game folder first.")
            return
        files = sorted(folder.glob("*.ff"))
        if not files:
            messagebox.showinfo(APP_NAME, "No .ff files were found in the selected folder.")
            return
        self.add_files(files, auto_start=True)

    def on_drop(self, paths: list[Path]) -> None:
        ffs = [p for p in paths if p.suffix.lower() == ".ff"]
        # A .zip of an unpacked folder, or an unpacked folder itself (containing
        # zone_decompressed.dat), can be repacked -> recompiled -> .ff.
        repackables = [p for p in paths if p.suffix.lower() == ".zip"]
        repackables += [p for p in paths if p.is_dir() and (p / "zone_decompressed.dat").exists()]
        if ffs:
            self.add_files(ffs, auto_start=True)
        if repackables:
            self.add_repack_files(repackables)
        if not ffs and not repackables:
            self.status_text.set("Drop .ff files to unpack, or an unpacked folder / its .zip to repack.")

    def choose_zip(self) -> None:
        initial = self.game_folder.get() if Path(self.game_folder.get()).exists() else str(Path.home())
        names = filedialog.askopenfilenames(
            title="Choose folder .zip files to repack into .ff",
            initialdir=initial,
            filetypes=[("Zip archives", "*.zip"), ("All files", "*.*")],
        )
        self.add_repack_files([Path(name) for name in names])

    def add_repack_files(self, paths: list[Path]) -> None:
        sources = [
            p.resolve()
            for p in paths
            if p.exists()
            and (
                (p.suffix.lower() == ".zip")
                or (p.is_dir() and (p / "zone_decompressed.dat").exists())
            )
        ]
        if not sources:
            self.status_text.set("Drop an unpacked folder (with zone_decompressed.dat) or its .zip to repack.")
            return
        for path in sources:
            out_ff = (path if path.is_dir() else path.with_suffix("")).with_suffix(".ff")
            self.tree.insert("", END, iid=f"repack::{path}", values=("Queued (repack)", "-", "-", "-", "-", str(out_ff)))
        if self.worker and self.worker.is_alive():
            messagebox.showinfo(APP_NAME, "A job is already running. Try again once it finishes.")
            return
        self.worker = threading.Thread(target=self.repack_run, args=(sources,), daemon=True)
        self.worker.start()

    def repack_run(self, sources: list[Path]) -> None:
        total = len(sources)
        for index, path in enumerate(sources, 1):
            self.work_queue.put(("repack_start", path, index, total))
            try:
                if path.is_dir():
                    # Recompile edited scripts_src/ (and Lua) then rebuild + repack.
                    out_ff = path.with_suffix(".ff")
                    result = repack_fastfile_from_folder(
                        path, out_ff, log=lambda msg: self.work_queue.put(("log", msg)), recompile=True
                    )
                else:
                    result = repack_fastfile_from_zip(path, None, log=lambda msg: self.work_queue.put(("log", msg)))
                self.work_queue.put(("repack_done", path, result, index, total))
            except Exception as exc:  # noqa: BLE001 - surface a friendly error, keep going.
                self.work_queue.put(("repack_error", path, str(exc), traceback.format_exc(), index, total))
        self.work_queue.put(("finished",))

    def add_files(self, paths: list[Path], auto_start: bool = True) -> None:
        files = []
        for path in paths:
            if path.suffix.lower() == ".ff" and path.exists():
                files.append(path.resolve())
        if not files:
            self.status_text.set("Drop or choose one or more .ff files.")
            return

        known = {str(path) for path in self.pending_files}
        for path in files:
            if str(path) in known:
                continue
            self.pending_files.append(path)
            item_id = str(path)
            self.tree.insert("", END, iid=item_id, values=("Queued", "-", "-", "-", "-", str(ff_output_dir(path))))

        self.status_text.set(f"Queued {len(files)} file(s).")
        if auto_start:
            self.start_extraction()

    def start_extraction(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        if not self.pending_files:
            return
        self.progress_value.set(0)
        self.worker = threading.Thread(target=self.worker_run, daemon=True)
        self.worker.start()

    def worker_run(self) -> None:
        files = list(self.pending_files)
        total = len(files)
        helper = default_lzx_helper()
        for index, path in enumerate(files, 1):
            self.work_queue.put(("start", path, index, total))
            try:
                result = extract_fastfile(path, helper, lambda msg: self.work_queue.put(("log", msg)))
                self.work_queue.put(("done", path, result, index, total))
            except Exception as exc:  # noqa: BLE001 - show friendly error and keep batch moving.
                self.work_queue.put(("error", path, str(exc), traceback.format_exc(), index, total))
        self.work_queue.put(("finished",))

    def poll_worker(self) -> None:
        if self.closing:
            return
        while True:
            try:
                event = self.work_queue.get_nowait()
            except queue.Empty:
                break
            self.handle_worker_event(event)
        self.root.after(120, self.poll_worker)

    def handle_worker_event(self, event) -> None:
        kind = event[0]
        if kind == "start":
            _, path, index, total = event
            self.status_text.set(f"Extracting {path.name}")
            self.progress_text.set(f"{index} of {total}")
            self.progress_value.set(((index - 1) / total) * 100)
            self.tree.set(str(path), "status", "Extracting")
        elif kind == "log":
            self.status_text.set(event[1])
        elif kind == "done":
            _, path, result, index, total = event
            scripts = result.get("scripts", 0)
            lua_files = result.get("lua_files", 0)
            lua_readable = result.get("lua_readable", 0)
            lua_decompiled = result.get("lua_decompiled", 0)
            lua_asm = result.get("lua_asm", 0)
            if scripts:
                status = "Partial" if result.get("partial") else "Complete"
            elif lua_files:
                status = "Partial - Lua only" if result.get("partial") else "Lua extracted"
            else:
                status = "Partial - no scripts" if result.get("partial") else "No scripts found"
            self.tree.set(str(path), "status", status)
            self.tree.set(str(path), "scripts", f"{scripts} / {lua_files}")
            self.tree.set(str(path), "lua_readable", str(lua_readable) if lua_files else "-")
            self.tree.set(str(path), "lua_decompiled", str(lua_decompiled) if lua_files else "-")
            self.tree.set(str(path), "lua_asm", str(lua_asm) if lua_files else "-")
            self.tree.set(str(path), "output", result["output"])
            self.results.append(result)
            self.progress_value.set((index / total) * 100)
            if scripts:
                self.status_text.set(
                    f"Finished {path.name}. Extracted {scripts} script, {lua_files} Lua payload(s), "
                    f"{lua_readable} readable Lua file(s), "
                    f"and {lua_asm} editable HKSASM file(s)."
                )
            elif lua_files:
                self.status_text.set(
                    f"Finished {path.name}. Extracted {lua_files} Lua UI payload(s), "
                    f"{lua_readable} readable Lua file(s), "
                    f"and {lua_asm} editable HKSASM file(s)."
                )
            else:
                self.status_text.set(f"Finished {path.name}. No GSC/CSC or Lua payloads were found.")
        elif kind == "error":
            _, path, error, details, index, total = event
            self.tree.set(str(path), "status", "Error")
            self.tree.set(str(path), "scripts", "-")
            self.tree.set(str(path), "lua_readable", "-")
            self.tree.set(str(path), "lua_decompiled", "-")
            self.tree.set(str(path), "lua_asm", "-")
            self.tree.set(str(path), "output", error)
            self.progress_value.set((index / total) * 100)
            self.status_text.set(f"Error extracting {path.name}: {error}")
            (ff_output_dir(path) / "error.txt").parent.mkdir(parents=True, exist_ok=True)
            (ff_output_dir(path) / "error.txt").write_text(details, encoding="utf-8")
        elif kind == "repack_start":
            _, path, index, total = event
            self.status_text.set(f"Repacking {path.name}")
            self.progress_text.set(f"{index} of {total}")
            self.progress_value.set(((index - 1) / total) * 100)
            self.tree.set(f"repack::{path}", "status", "Repacking")
        elif kind == "repack_done":
            _, path, result, index, total = event
            recompile = result.get("recompile") or {}
            changed = recompile.get("changed", 0) if isinstance(recompile, dict) else 0
            self.tree.set(f"repack::{path}", "status", "Repacked")
            self.tree.set(f"repack::{path}", "scripts", f"{result.get('chunks', 0)} chunks")
            if changed:
                self.tree.set(f"repack::{path}", "lua_readable", f"{changed} recompiled")
            self.tree.set(f"repack::{path}", "output", result["output"])
            self.progress_value.set((index / total) * 100)
            recompile_note = ""
            if isinstance(recompile, dict):
                if changed:
                    recompile_note = f" Recompiled {changed} edited source(s)."
                if recompile.get("errors"):
                    recompile_note += f" {len(recompile['errors'])} failed to recompile."
            self.status_text.set(
                f"Repacked {path.name} -> {Path(result['output']).name} "
                f"({result.get('chunks', 0)} chunks, {result.get('ff_size', 0)} bytes).{recompile_note}"
            )
        elif kind == "repack_error":
            _, path, error, details, index, total = event
            self.tree.set(f"repack::{path}", "status", "Repack error")
            self.tree.set(f"repack::{path}", "output", error)
            self.progress_value.set((index / total) * 100)
            self.status_text.set(f"Error repacking {path.name}: {error}")
        elif kind == "finished":
            self.pending_files.clear()
            self.progress_text.set("Done")
            self.status_text.set("Done. Select a row and open its output folder, or find the new .ff beside the .zip.")

    def selected_output(self) -> Path | None:
        selected = self.tree.selection()
        if not selected:
            return None
        value = self.tree.set(selected[0], "output")
        path = Path(value)
        return path if path.exists() else None

    def open_selected_output(self) -> None:
        path = self.selected_output()
        if path is None:
            messagebox.showinfo(APP_NAME, "Select a completed output row first.")
            return
        # Repack rows point at a .ff file; open its containing folder instead.
        target = path if path.is_dir() else path.parent
        os.startfile(target)  # type: ignore[attr-defined]

    def open_selected_subfolder(self, folder_name: str) -> None:
        path = self.selected_output()
        if path is None:
            messagebox.showinfo(APP_NAME, "Select a completed output folder first.")
            return
        target = path / folder_name
        if not target.exists():
            messagebox.showinfo(APP_NAME, f"{folder_name} was not created for the selected fastfile.")
            return
        os.startfile(target)  # type: ignore[attr-defined]

    def clear_list(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.results.clear()
        self.pending_files.clear()
        self.progress_value.set(0)
        self.progress_text.set("")
        self.status_text.set("Ready. Choose .ff files or drag them onto the executable.")

    def close(self) -> None:
        self.closing = True
        try:
            if self.drop_target:
                self.drop_target.uninstall()
        except Exception:
            pass
        self.root.quit()
        self.root.destroy()


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    startup_files = [Path(arg) for arg in argv if Path(arg).suffix.lower() == ".ff"]
    startup_zips = [Path(arg) for arg in argv if Path(arg).suffix.lower() == ".zip"]
    root = tk.Tk()
    app = FastFileApp(root, startup_files)
    if startup_zips:
        root.after(300, lambda: app.add_repack_files(startup_zips))
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
