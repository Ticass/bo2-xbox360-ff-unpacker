#!/usr/bin/env python3
"""Build a cross-fastfile inventory of extracted compiled GSC/CSC payloads.

This does not interpret or decrypt script bytecode. It only aggregates the
high-confidence raw payloads emitted by xbox360_ff_unpacker.py so we can compare
which fastfiles carry which compiled script blobs.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def source_fastfile(scan_dir: Path) -> str:
    metadata_path = scan_dir / "metadata.json"
    if not metadata_path.exists():
        return ""
    try:
        metadata = load_json(metadata_path)
    except (OSError, json.JSONDecodeError):
        return ""
    input_path = metadata.get("input", {}).get("path")
    return str(input_path or "")


def collect_scripts(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for manifest_path in sorted(root.glob("*_ff_scan/embedded_scripts.json")):
        scan_dir = manifest_path.parent
        try:
            manifest = load_json(manifest_path)
        except (OSError, json.JSONDecodeError) as exc:
            rows.append(
                {
                    "scan": scan_dir.name,
                    "source_fastfile": source_fastfile(scan_dir),
                    "script_name": "",
                    "kind": "",
                    "payload_size": 0,
                    "payload_magic_hex": "",
                    "sha256": "",
                    "path": "",
                    "status": "manifest_error",
                    "error": str(exc),
                }
            )
            continue

        ff_path = source_fastfile(scan_dir)
        for script in manifest.get("scripts", []):
            script_name = str(script.get("script_name") or "")
            suffix = Path(script_name).suffix.lower().lstrip(".")
            rows.append(
                {
                    "scan": scan_dir.name,
                    "source_fastfile": ff_path,
                    "script_name": script_name,
                    "kind": suffix,
                    "payload_size": int(script.get("payload_size") or 0),
                    "payload_magic_hex": str(script.get("payload_magic_hex") or ""),
                    "sha256": str(script.get("sha256") or ""),
                    "header_offset": int(script.get("header_offset") or 0),
                    "path_offset": int(script.get("path_offset") or 0),
                    "payload_offset": int(script.get("payload_offset") or 0),
                    "path": str(script.get("path") or ""),
                    "extraction_confidence": str(script.get("extraction_confidence") or ""),
                    "status": "ok",
                    "error": "",
                }
            )
    return rows


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    ok_rows = [row for row in rows if row.get("status") == "ok"]
    by_scan: dict[str, int] = {}
    by_kind: dict[str, int] = {}
    by_script: dict[str, set[str]] = {}
    by_hash: dict[str, int] = {}

    for row in ok_rows:
        scan = str(row["scan"])
        kind = str(row["kind"])
        script_name = str(row["script_name"])
        sha256 = str(row["sha256"])
        by_scan[scan] = by_scan.get(scan, 0) + 1
        by_kind[kind] = by_kind.get(kind, 0) + 1
        by_script.setdefault(script_name, set()).add(scan)
        by_hash[sha256] = by_hash.get(sha256, 0) + 1

    return {
        "total_rows": len(rows),
        "total_scripts": len(ok_rows),
        "unique_script_names": len(by_script),
        "unique_payload_hashes": len(by_hash),
        "by_scan": dict(sorted(by_scan.items())),
        "by_kind": dict(sorted(by_kind.items())),
        "duplicates_by_name": {
            name: sorted(scans)
            for name, scans in sorted(by_script.items())
            if len(scans) > 1
        },
        "duplicates_by_payload_hash": {
            sha256: count for sha256, count in sorted(by_hash.items()) if count > 1
        },
    }


def write_outputs(root: Path, rows: list[dict[str, Any]]) -> None:
    json_path = root / "script_inventory.json"
    tsv_path = root / "script_inventory.tsv"
    summary_path = root / "script_inventory_summary.json"

    json_path.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")

    fieldnames = [
        "scan",
        "source_fastfile",
        "script_name",
        "kind",
        "payload_size",
        "payload_magic_hex",
        "sha256",
        "header_offset",
        "path_offset",
        "payload_offset",
        "path",
        "extraction_confidence",
        "status",
        "error",
    ]
    with tsv_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, delimiter="\t", extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    summary_path.write_text(json.dumps(summarize(rows), indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "root",
        nargs="?",
        default=Path(__file__).resolve().parent,
        type=Path,
        help="Folder containing *_ff_scan directories.",
    )
    args = parser.parse_args()

    root = args.root.resolve()
    if not root.exists():
        parser.error(f"root does not exist: {root}")

    rows = collect_scripts(root)
    write_outputs(root, rows)
    summary = summarize(rows)
    print(
        f"indexed {summary['total_scripts']} scripts from "
        f"{len(summary['by_scan'])} scan directories"
    )
    print(f"unique names: {summary['unique_script_names']}")
    print(f"unique payload hashes: {summary['unique_payload_hashes']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
