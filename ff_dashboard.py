#!/usr/bin/env python3
"""Local web interface for the Xbox 360 BO2 fastfile unpacker workspace."""

from __future__ import annotations

import argparse
import html
import json
import mimetypes
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


ROOT = Path(__file__).resolve().parent
UNPACKER = ROOT / "xbox360_ff_unpacker.py"
INVENTORY = ROOT / "script_inventory.py"
CONFIG_PATH = Path.home() / "AppData" / "Roaming" / "BO2FastFileUnpacker" / "config.json"


def read_json(path: Path, fallback):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return fallback


def write_json_file(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def load_config() -> dict:
    return read_json(CONFIG_PATH, {})


def save_config(config: dict) -> None:
    write_json_file(CONFIG_PATH, config)


def game_root() -> Path:
    configured = load_config().get("game_folder")
    if configured and Path(configured).exists():
        return Path(configured).resolve()
    return ROOT.parent.resolve()


def scan_dirs() -> list[dict]:
    rows = []
    candidates = list(ROOT.glob("*_ff_scan"))
    current_game_root = game_root()
    candidates.extend(path for path in current_game_root.iterdir() if path.is_dir() and (path / "metadata.json").exists())
    seen = set()
    for scan_dir in sorted(candidates):
        if scan_dir.resolve() in seen:
            continue
        seen.add(scan_dir.resolve())
        metadata = read_json(scan_dir / "metadata.json", {})
        embedded = read_json(scan_dir / "embedded_scripts.json", {})
        dz = metadata.get("decompressed_zone", {}) if isinstance(metadata, dict) else {}
        rows.append(
            {
                "name": scan_dir.name,
                "path": str(scan_dir),
                "source_fastfile": metadata.get("input", {}).get("path", ""),
                "scripts": int(embedded.get("count") or 0),
                "status": dz.get("top_level_zone", {}).get("status", "unknown"),
                "partial_zone": bool(dz.get("partial_zone")),
                "chunk_errors": dz.get("chunk_errors", []),
                "parser_warnings": dz.get("parser_warnings", []),
            }
        )
    return rows


def collected_scripts() -> list[dict]:
    rows = []
    for scan in scan_dirs():
        scan_dir = Path(scan["path"])
        manifest = read_json(scan_dir / "embedded_scripts.json", {})
        for script in manifest.get("scripts", []):
            script_name = str(script.get("script_name") or "")
            rows.append(
                {
                    "scan": scan_dir.name,
                    "source_fastfile": scan.get("source_fastfile", ""),
                    "script_name": script_name,
                    "kind": Path(script_name).suffix.lower().lstrip("."),
                    "payload_size": int(script.get("payload_size") or 0),
                    "payload_magic_hex": str(script.get("payload_magic_hex") or ""),
                    "sha256": str(script.get("sha256") or ""),
                    "path": str(script.get("path") or ""),
                    "extraction_confidence": str(script.get("extraction_confidence") or ""),
                }
            )
    return rows


def scripts_summary() -> dict:
    rows = collected_scripts()
    by_kind: dict[str, int] = {}
    names = set()
    hashes = set()
    by_scan: dict[str, int] = {}
    for row in rows:
        by_kind[row["kind"]] = by_kind.get(row["kind"], 0) + 1
        names.add(row["script_name"])
        hashes.add(row["sha256"])
        by_scan[row["scan"]] = by_scan.get(row["scan"], 0) + 1
    return {
        "total_rows": len(rows),
        "total_scripts": len(rows),
        "unique_script_names": len(names),
        "unique_payload_hashes": len(hashes),
        "by_scan": dict(sorted(by_scan.items())),
        "by_kind": dict(sorted(by_kind.items())),
    }


def fastfiles() -> list[dict]:
    scanned_sources = {
        Path(row["source_fastfile"]).name.lower()
        for row in scan_dirs()
        if row.get("source_fastfile")
    }
    rows = []
    for path in sorted(game_root().glob("*.ff")):
        rows.append(
            {
                "name": path.name,
                "path": str(path),
                "size": path.stat().st_size,
                "scanned": path.name.lower() in scanned_sources,
            }
        )
    return rows


def run_inventory() -> dict:
    completed = subprocess.run(
        [sys.executable, str(INVENTORY), str(ROOT)],
        cwd=str(game_root()),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return {
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def safe_fastfile(name: str) -> Path:
    candidate = (game_root() / name).resolve()
    if candidate.parent != game_root().resolve() or candidate.suffix.lower() != ".ff":
        raise ValueError("fastfile must be a .ff file in the game root")
    if not candidate.exists():
        raise ValueError(f"fastfile not found: {name}")
    return candidate


def scan_fastfile(name: str, allow_partial: bool = True) -> dict:
    ff_path = safe_fastfile(name)
    out_dir = ff_path.with_suffix("")
    cmd = [
        sys.executable,
        str(UNPACKER),
        str(ff_path),
        "-o",
        str(out_dir),
        "--decompress-zone",
        "--verbose",
    ]
    if allow_partial:
        cmd.append("--allow-partial-zone")
    completed = subprocess.run(
        cmd,
        cwd=str(game_root()),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    inv = run_inventory()
    return {
        "command": cmd,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "inventory": inv,
    }


INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>BO2 Xbox 360 FF Unpacker</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #101114;
      --panel: #181a20;
      --panel-2: #20242c;
      --text: #f1f2f4;
      --muted: #aeb4c0;
      --line: #343946;
      --accent: #49b6ff;
      --ok: #6ee7a8;
      --warn: #ffd166;
      --bad: #ff7a7a;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font: 14px/1.45 "Segoe UI", system-ui, sans-serif;
    }
    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      padding: 18px 24px;
      border-bottom: 1px solid var(--line);
      background: #13151a;
      position: sticky;
      top: 0;
      z-index: 2;
    }
    h1 { margin: 0; font-size: 18px; font-weight: 650; }
    main { padding: 20px 24px 32px; }
    .stats {
      display: grid;
      grid-template-columns: repeat(5, minmax(120px, 1fr));
      gap: 10px;
      margin-bottom: 18px;
    }
    .stat, .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
    }
    .stat { padding: 14px; }
    .stat b { display: block; font-size: 22px; margin-bottom: 3px; }
    .stat span, label, .muted { color: var(--muted); }
    .toolbar {
      display: grid;
      grid-template-columns: 1fr 180px 160px 140px;
      gap: 10px;
      margin-bottom: 12px;
    }
    .setup {
      display: grid;
      grid-template-columns: 1fr 140px;
      gap: 10px;
      align-items: end;
      padding: 14px;
      margin-bottom: 14px;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
    }
    .dropzone {
      padding: 22px;
      margin-bottom: 14px;
      text-align: center;
      background: #151a21;
      border: 1px dashed #536173;
      border-radius: 8px;
    }
    .dropzone strong { display: block; font-size: 18px; margin-bottom: 5px; }
    input, select, button {
      min-height: 36px;
      border-radius: 6px;
      border: 1px solid var(--line);
      background: var(--panel-2);
      color: var(--text);
      padding: 0 10px;
      font: inherit;
    }
    button {
      cursor: pointer;
      background: #263241;
      border-color: #3b4b5f;
    }
    button:hover { border-color: var(--accent); }
    .layout {
      display: grid;
      grid-template-columns: minmax(280px, 380px) 1fr;
      gap: 16px;
      align-items: start;
    }
    .panel h2 {
      margin: 0;
      padding: 12px 14px;
      border-bottom: 1px solid var(--line);
      font-size: 14px;
    }
    table { width: 100%; border-collapse: collapse; }
    th, td {
      text-align: left;
      padding: 9px 10px;
      border-bottom: 1px solid var(--line);
      vertical-align: top;
    }
    th {
      position: sticky;
      top: 73px;
      background: var(--panel);
      z-index: 1;
      color: var(--muted);
      font-weight: 600;
    }
    tr:hover td { background: rgba(255,255,255,0.03); }
    .scroll { max-height: calc(100vh - 250px); overflow: auto; }
    .pill {
      display: inline-flex;
      align-items: center;
      height: 22px;
      padding: 0 8px;
      border: 1px solid var(--line);
      border-radius: 999px;
      color: var(--muted);
      white-space: nowrap;
    }
    .ok { color: var(--ok); }
    .warn { color: var(--warn); }
    .bad { color: var(--bad); }
    code { color: #c9e7ff; word-break: break-all; }
    @media (max-width: 980px) {
      .stats, .toolbar, .layout { grid-template-columns: 1fr; }
      th { position: static; }
    }
  </style>
</head>
<body>
  <header>
    <h1>BO2 Xbox 360 Fastfile Unpacker</h1>
    <button id="refresh">Refresh</button>
  </header>
  <main>
    <section class="stats" id="stats"></section>
    <section class="setup">
      <label>Game installation folder
        <input id="gameFolder" placeholder="C:\GAMES\merged2">
      </label>
      <button id="saveFolder">Save Folder</button>
    </section>
    <section class="dropzone">
      <strong>Drag files onto the desktop executable, or choose a FastFile below</strong>
      <span class="muted">Browser security hides dropped file paths. The stable drag-and-drop path is dropping .ff files onto BO2FastFileUnpacker.exe. Scans launched here use the saved game folder and write output beside each source file.</span>
    </section>
    <section class="toolbar">
      <input id="query" placeholder="Filter scripts by name, hash, or fastfile">
      <select id="kind">
        <option value="">All script types</option>
        <option value="gsc">GSC</option>
        <option value="csc">CSC</option>
      </select>
      <select id="scanSelect"></select>
      <button id="scanBtn">Scan Selected</button>
    </section>
    <section class="layout">
      <div class="panel">
        <h2>Fastfile Scans</h2>
        <div class="scroll"><table id="scans"></table></div>
      </div>
      <div class="panel">
        <h2>Extracted Scripts</h2>
        <div class="scroll"><table id="scripts"></table></div>
      </div>
    </section>
  </main>
  <script>
    const state = { summary: {}, scripts: [], scans: [], fastfiles: [], config: {} };
    const $ = (id) => document.getElementById(id);
    const esc = (s) => String(s ?? "").replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    const size = (n) => {
      n = Number(n || 0);
      if (n > 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + " MB";
      if (n > 1024) return (n / 1024).toFixed(1) + " KB";
      return n + " B";
    };
    async function api(path) {
      const res = await fetch(path);
      if (!res.ok) throw new Error(await res.text());
      return res.json();
    }
    async function load() {
      const [summary, scripts, scans, fastfiles] = await Promise.all([
        api("/api/summary"), api("/api/scripts"), api("/api/scans"), api("/api/fastfiles")
      ]);
      const config = await api("/api/config");
      Object.assign(state, { summary, scripts, scans, fastfiles, config });
      render();
    }
    function renderStats() {
      const s = state.summary || {};
      $("stats").innerHTML = [
        ["Scripts", s.total_scripts],
        ["Unique Names", s.unique_script_names],
        ["Unique Hashes", s.unique_payload_hashes],
        ["GSC", s.by_kind?.gsc || 0],
        ["CSC", s.by_kind?.csc || 0],
      ].map(([label, value]) => `<div class="stat"><b>${esc(value || 0)}</b><span>${esc(label)}</span></div>`).join("");
    }
    function renderScans() {
      $("scans").innerHTML = `<thead><tr><th>Scan</th><th>Scripts</th><th>Status</th></tr></thead><tbody>` +
        state.scans.map(row => {
          const cls = row.partial_zone || row.chunk_errors?.length ? "warn" : "ok";
          const status = row.partial_zone ? "partial" : (row.status || "ok");
          return `<tr><td><code>${esc(row.name)}</code><br><span class="muted">${esc(row.source_fastfile)}</span></td><td>${esc(row.scripts)}</td><td><span class="${cls}">${esc(status)}</span></td></tr>`;
        }).join("") + `</tbody>`;
    }
    function renderFastfileSelect() {
      $("scanSelect").innerHTML = state.fastfiles.map(ff => {
        const label = `${ff.scanned ? "✓ " : ""}${ff.name} (${size(ff.size)})`;
        return `<option value="${esc(ff.name)}">${esc(label)}</option>`;
      }).join("");
    }
    function renderScripts() {
      const q = $("query").value.toLowerCase();
      const kind = $("kind").value;
      const rows = state.scripts.filter(row => {
        if (kind && row.kind !== kind) return false;
        const blob = `${row.script_name} ${row.scan} ${row.source_fastfile} ${row.sha256}`.toLowerCase();
        return !q || blob.includes(q);
      }).slice(0, 1000);
      $("scripts").innerHTML = `<thead><tr><th>Script</th><th>Source</th><th>Size</th><th>Hash</th></tr></thead><tbody>` +
        rows.map(row => `<tr><td><code>${esc(row.script_name)}</code><br><span class="pill">${esc(row.kind)}</span></td><td>${esc(row.scan)}<br><span class="muted">${esc(row.source_fastfile)}</span></td><td>${size(row.payload_size)}</td><td><code>${esc(String(row.sha256).slice(0, 16))}</code></td></tr>`).join("") +
        `</tbody>`;
    }
    function render() {
      $("gameFolder").value = state.config.game_folder || "";
      renderStats();
      renderScans();
      renderFastfileSelect();
      renderScripts();
    }
    $("query").addEventListener("input", renderScripts);
    $("kind").addEventListener("change", renderScripts);
    $("refresh").addEventListener("click", load);
    $("saveFolder").addEventListener("click", async () => {
      const folder = $("gameFolder").value.trim();
      if (!folder) return alert("Enter your BO2 game folder path first.");
      const result = await api(`/api/config?game_folder=${encodeURIComponent(folder)}`);
      if (result.error) return alert(result.error);
      await load();
    });
    $("scanBtn").addEventListener("click", async () => {
      const name = $("scanSelect").value;
      $("scanBtn").disabled = true;
      $("scanBtn").textContent = "Scanning...";
      try {
        const result = await api(`/api/scan?file=${encodeURIComponent(name)}`);
        if (result.returncode !== 0) alert(result.stderr || "scan failed");
        await load();
      } finally {
        $("scanBtn").disabled = false;
        $("scanBtn").textContent = "Scan Selected";
      }
    });
    load().catch(err => {
      document.body.innerHTML = `<main><h1>Dashboard error</h1><pre>${esc(err.stack || err)}</pre></main>`;
    });
  </script>
</body>
</html>
"""


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "FFDashboard/0.1"

    def send_json(self, data, status: int = 200) -> None:
        raw = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def send_text(self, text: str, status: int = 200, content_type: str = "text/html; charset=utf-8") -> None:
        raw = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/":
                self.send_text(INDEX_HTML)
            elif parsed.path == "/api/summary":
                self.send_json(scripts_summary())
            elif parsed.path == "/api/scripts":
                self.send_json(collected_scripts())
            elif parsed.path == "/api/scans":
                self.send_json(scan_dirs())
            elif parsed.path == "/api/fastfiles":
                self.send_json(fastfiles())
            elif parsed.path == "/api/config":
                query = parse_qs(parsed.query)
                if "game_folder" in query:
                    folder = Path(query["game_folder"][0]).resolve()
                    if not folder.exists() or not folder.is_dir():
                        self.send_json({"error": f"folder does not exist: {folder}"}, status=400)
                        return
                    config = load_config()
                    config["game_folder"] = str(folder)
                    save_config(config)
                    self.send_json(config)
                else:
                    self.send_json(load_config())
            elif parsed.path == "/api/reindex":
                self.send_json(run_inventory())
            elif parsed.path == "/api/scan":
                query = parse_qs(parsed.query)
                name = query.get("file", [""])[0]
                self.send_json(scan_fastfile(name, allow_partial=True))
            elif parsed.path.startswith("/files/"):
                rel = parsed.path.removeprefix("/files/")
                target = (ROOT / rel).resolve()
                if ROOT.resolve() not in target.parents and target != ROOT.resolve():
                    raise ValueError("path escapes dashboard root")
                content_type = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(target.stat().st_size))
                self.end_headers()
                self.wfile.write(target.read_bytes())
            else:
                self.send_text("not found", 404, "text/plain; charset=utf-8")
        except Exception as exc:  # noqa: BLE001 - report interface errors to the browser.
            self.send_json({"error": str(exc), "type": type(exc).__name__}, status=500)

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()

    run_inventory()
    httpd = ThreadingHTTPServer((args.host, args.port), DashboardHandler)
    url = f"http://{args.host}:{args.port}/"
    print(f"serving dashboard at {html.escape(url)}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
