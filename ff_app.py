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
from pathlib import Path
from tkinter import BOTH, END, LEFT, RIGHT, X, filedialog, messagebox, ttk
import tkinter as tk

from xbox360_ff_unpacker import FastFileScanner, write_json


APP_NAME = "BO2 Xbox 360 FastFile Unpacker"
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

    scripts = metadata.get("decompressed_zone", {}).get("embedded_scripts", {}).get("count", 0)
    partial = metadata.get("decompressed_zone", {}).get("partial_zone", False)
    chunk_errors = metadata.get("decompressed_zone", {}).get("chunk_errors", [])
    result_readme = out_dir / "README_EXTRACT_RESULT.txt"
    if scripts:
        result_readme.write_text(
            "\n".join(
                [
                    f"FastFile: {path}",
                    f"Status: {'partial scan' if partial else 'complete scan'}",
                    f"Compiled script payloads extracted: {scripts}",
                    "",
                    "Open the scripts folder for the extracted .gsc/.csc payloads:",
                    str(out_dir / "scripts"),
                    "",
                    "Important: these .gsc/.csc files are compiled Xbox bytecode payloads, not decompiled source text yet.",
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
                    "",
                    reason,
                    "",
                    "Try script-bearing files such as patch_mp.ff, patch_zm.ff, or map patch FastFiles.",
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
            self.drop_target = WindowsDropTarget(root, self.add_files)
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.poll_worker()

        if startup_files:
            self.root.after(250, lambda: self.add_files(startup_files, auto_start=True))

    def build_ui(self) -> None:
        self.root.title(APP_NAME)
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
        ttk.Label(header, text="BO2 Xbox 360 FastFile Unpacker", style="Title.TLabel").pack(side=LEFT)
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
        ttk.Label(drop, text="Choose .ff files or drag them onto the executable", style="Drop.TLabel").pack(anchor="center")
        ttk.Label(
            drop,
            text="Extraction starts automatically. Each output folder is created beside its source file.",
            background="#181b21",
            foreground="#aeb6c2",
        ).pack(anchor="center", pady=(6, 16))
        actions = ttk.Frame(drop, style="Panel.TFrame")
        actions.pack(anchor="center")
        ttk.Button(actions, text="Choose .ff Files", style="Accent.TButton", command=self.choose_files).pack(side=LEFT, padx=4)
        ttk.Button(actions, text="Extract All From Game Folder", command=self.extract_all_from_game_folder).pack(side=LEFT, padx=4)

        status_row = ttk.Frame(outer)
        status_row.pack(fill=X, pady=(18, 8))
        ttk.Label(status_row, textvariable=self.status_text).pack(side=LEFT)
        ttk.Label(status_row, textvariable=self.progress_text, style="Muted.TLabel").pack(side=RIGHT)

        self.progress = ttk.Progressbar(outer, variable=self.progress_value, maximum=100)
        self.progress.pack(fill=X)

        table_frame = ttk.Frame(outer)
        table_frame.pack(fill=BOTH, expand=True, pady=(16, 10))
        self.tree = ttk.Treeview(table_frame, columns=("status", "scripts", "output"), show="headings")
        self.tree.heading("status", text="Status")
        self.tree.heading("scripts", text="Scripts")
        self.tree.heading("output", text="Output")
        self.tree.column("status", width=150, anchor="w")
        self.tree.column("scripts", width=90, anchor="center")
        self.tree.column("output", width=620, anchor="w")
        self.tree.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side=RIGHT, fill="y")
        self.tree.configure(yscrollcommand=scrollbar.set)

        footer = ttk.Frame(outer)
        footer.pack(fill=X)
        ttk.Button(footer, text="Open Selected Output", command=self.open_selected_output).pack(side=LEFT)
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
            self.tree.insert("", END, iid=item_id, values=("Queued", "-", str(ff_output_dir(path))))

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
            if scripts:
                status = "Partial" if result.get("partial") else "Complete"
            else:
                status = "Partial - no scripts" if result.get("partial") else "No scripts found"
            self.tree.set(str(path), "status", status)
            self.tree.set(str(path), "scripts", str(scripts))
            self.tree.set(str(path), "output", result["output"])
            self.results.append(result)
            self.progress_value.set((index / total) * 100)
            if scripts:
                self.status_text.set(f"Finished {path.name}. Extracted {scripts} script payload(s).")
            else:
                self.status_text.set(f"Finished {path.name}. No GSC/CSC payloads were found.")
        elif kind == "error":
            _, path, error, details, index, total = event
            self.tree.set(str(path), "status", "Error")
            self.tree.set(str(path), "scripts", "-")
            self.tree.set(str(path), "output", error)
            self.progress_value.set((index / total) * 100)
            self.status_text.set(f"Error extracting {path.name}: {error}")
            (ff_output_dir(path) / "error.txt").parent.mkdir(parents=True, exist_ok=True)
            (ff_output_dir(path) / "error.txt").write_text(details, encoding="utf-8")
        elif kind == "finished":
            self.pending_files.clear()
            self.progress_text.set("Done")
            self.status_text.set("Extraction complete. Select a row and open its output folder.")

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
            messagebox.showinfo(APP_NAME, "Select a completed output folder first.")
            return
        os.startfile(path)  # type: ignore[attr-defined]

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
    root = tk.Tk()
    FastFileApp(root, startup_files)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
