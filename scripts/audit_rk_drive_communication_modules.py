#!/usr/bin/env python3
"""Hash-check RK Drive bundles and emit source-free communication/API ledgers.

The public JavaScript is read into memory only. This script never executes it,
opens WebHID, requests browser permission, or sends device data. Its API rows
are lexical callsite candidates, not a complete control-flow graph.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import re
import sys
from pathlib import Path
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "docs" / "rk-drive-js-manifest.csv"
MODULE_CSV = ROOT / "docs" / "rk-drive-communication-module-audit-2026-10-19.csv"
API_CSV = ROOT / "docs" / "rk-drive-webhid-api-callsite-candidates-2026-10-19.csv"
USER_AGENT = "static-rk-research-audit/1.0"

API_PATTERNS = {
    "navigator.hid": rb"navigator\.hid",
    "HID.requestDevice": rb"\.requestDevice\(",
    "HID.getDevices": rb"\.getDevices\(",
    "HIDDevice.receiveFeatureReport": rb"\.receiveFeatureReport\(",
    "HIDDevice.sendFeatureReport": rb"\.sendFeatureReport\(",
    "HIDDevice.sendReport": rb"\.sendReport\(",
    "HIDDevice.open": rb"\.device\.open\(",
    "HIDDevice.close": rb"\.device\.close\(",
    "HIDDevice.forget": rb"\.device\.forget\(",
    "inputreport.addEventListener": rb"\.addEventListener\(\"inputreport\"",
    "inputreport.removeEventListener": rb"\.removeEventListener\(\"inputreport\"",
    "hid.disconnect.addEventListener": rb"\.addEventListener\(\"disconnect\"",
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch(url: str) -> bytes:
    request = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(request, timeout=60) as response:
        return response.read()


def occurrences(data: bytes, pattern: bytes) -> list[int]:
    return [match.start() for match in re.finditer(pattern, data)]


def read_manifest() -> list[dict[str, str]]:
    with MANIFEST.open("r", encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()
    if not args.overwrite and (MODULE_CSV.exists() or API_CSV.exists()):
        raise SystemExit("output exists; pass --overwrite to replace it")

    rows = read_manifest()
    entry_rows = [row for row in rows if row["entry"].lower() == "true"]
    if len(entry_rows) != 1:
        raise SystemExit("manifest must contain exactly one entry bundle")
    entry_meta = entry_rows[0]
    entry = fetch(entry_meta["url"])
    if len(entry) != int(entry_meta["bytes"]) or digest(entry) != entry_meta["sha256"]:
        raise SystemExit("entry bundle identity differs from the dated manifest")

    module_rows: list[dict[str, str | int]] = []
    api_rows: list[dict[str, str | int]] = []
    for meta in rows:
        if meta["entry"].lower() == "true":
            continue
        content = fetch(meta["url"])
        actual_hash = digest(content)
        if len(content) != int(meta["bytes"]) or actual_hash != meta["sha256"]:
            raise SystemExit(f"bundle identity differs from the dated manifest: {meta['url']}")
        name = meta["url"].rsplit("/", 1)[-1]
        worker_needle = f'new Worker(new URL("/assets/{name}",import.meta.url))'.encode()
        worker_offsets = occurrences(entry, re.escape(worker_needle))
        # Preserve the independently observed scheduler facts as source-free
        # labels; the exact, hash-checked bytes remain the reproduction source.
        module_rows.append({
            "bundle_url": meta["url"],
            "bytes": len(content),
            "sha256": actual_hash,
            "worker_constructor_count_in_entry": len(worker_offsets),
            "known_message_strings_found": ";".join(
                command for command in
                ("start", "stop", "report", "heartbeat", "finish", "timeout",
                 "getReport", "stopGet", "wait", "run", "configure", "packet")
                if b'"' + command.encode() + b'"' in content
            ),
        })

    for api, pattern in API_PATTERNS.items():
        for offset in occurrences(entry, pattern):
            api_rows.append({
                "bundle_url": entry_meta["url"],
                "bundle_sha256": entry_meta["sha256"],
                "api_candidate": api,
                "file_offset": f"0x{offset:x}",
                "evidence_kind": "literal call/name candidate in hash-pinned minified bundle",
            })

    write_csv(MODULE_CSV, module_rows)
    write_csv(API_CSV, api_rows)
    print(f"entry bytes={len(entry)} sha256={digest(entry)}")
    print(f"communication modules verified={len(module_rows)}")
    for row in module_rows:
        print(f"{row['bundle_url']} workers={row['worker_constructor_count_in_entry']} sha256={row['sha256']}")
    for api in API_PATTERNS:
        print(f"{api}: {sum(row['api_candidate'] == api for row in api_rows)} byte occurrences")
    print(f"wrote {MODULE_CSV.relative_to(ROOT)}")
    print(f"wrote {API_CSV.relative_to(ROOT)}")
    return 0


def write_csv(path: Path, rows: list[dict[str, str | int]]) -> None:
    if not rows:
        raise SystemExit(f"refusing to write an empty ledger: {path.name}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    sys.exit(main())
