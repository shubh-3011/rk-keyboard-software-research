#!/usr/bin/env python3
"""Reconcile the 2026-10-19 RK firmware selector snapshot with local artifacts.

Static-only: this script can download listed files into an ignored research
directory, hash/classify their bytes, and inventory PE/archive metadata. It
never executes a downloaded file, extracts an archive, talks to HID, or writes
to a device.

Example:
  python scripts/audit_rk_firmware_catalog.py --download
  python scripts/audit_rk_firmware_catalog.py --inventory-only
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import hashlib
import json
import os
import pathlib
import re
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import Counter, defaultdict

try:
    import pefile
except ImportError:  # PE fields remain blank if pefile is not installed.
    pefile = None


ROOT = pathlib.Path(__file__).resolve().parents[1]
CATALOG = ROOT / "docs" / "rk-official-download-selector-catalog-2026-10-19.csv"
DEFAULT_RESEARCH_ROOT = ROOT.parent / ".research"
DEFAULT_DOWNLOAD_DIR = DEFAULT_RESEARCH_ROOT / "rk-firmware-catalog-2026-10-19"
ARTIFACT_CSV = ROOT / "docs" / "rk-firmware-artifact-inventory-2026-10-19.csv"
ROW_CSV = ROOT / "docs" / "rk-firmware-selector-row-coverage-2026-10-19.csv"
QMK_HEX_SOURCE_CSV = ROOT / "docs" / "rk-qmk-selector-artifact-audit-2026-10-19.csv"
QMK_HEX_CSV = ROOT / "docs" / "rk-qmk-hex-firmware-artifact-inventory-2026-10-19.csv"
MAX_BYTES = 512 * 1024 * 1024


def load_rows() -> list[dict[str, str]]:
    with CATALOG.open("r", encoding="utf-8-sig", newline="") as f:
        return [
            {**r, "_source_csv_line": str(line_number)}
            for line_number, r in enumerate(csv.DictReader(f), 2)
            if r["catalog"] == "firmware"
        ]


def load_qmk_hex_rows() -> list[dict[str, str]]:
    with QMK_HEX_SOURCE_CSV.open("r", encoding="utf-8-sig", newline="") as f:
        return [
            r for r in csv.DictReader(f)
            if r["catalog"] == "qmk" and r.get("artifact_extension") == ".hex" and r.get("listed_file_url")
        ]


def url_basename(url: str) -> str:
    name = pathlib.PurePosixPath(urllib.parse.urlparse(url).path).name
    if not name:
        return "firmware-artifact"
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name)[:180]


def grouped_artifacts(rows: list[dict[str, str]]) -> list[dict[str, object]]:
    by_url: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        if row.get("listed_file_url", "").strip():
            by_url[row["listed_file_url"].strip()].append(row)
    result: list[dict[str, object]] = []
    for url, group in sorted(by_url.items()):
        fields = (
            "selector_model_id", "selector_model", "record_id", "record_name",
            "product_version_id", "product_version", "attribute_id", "attribute",
            "language_id", "language", "pid", "description",
        )
        result.append({
            "url": url,
            "filename": url_basename(url),
            "source_csv_lines": ",".join(
                row.get("_source_csv_line", "") for row in rows
                if row.get("listed_file_url", "").strip() == url
            ),
            "catalog_row_count": len([row for row in rows if row.get("listed_file_url", "").strip() == url]),
            **{k: " | ".join(sorted({row.get(k, "") for row in group if row.get(k, "")})) for k in fields},
            "source_rows": group,
        })
    return result


def existing_candidates(urls: list[str], research_root: pathlib.Path) -> dict[str, pathlib.Path]:
    """Find already present binaries by URL basename suffix, including S98's prefixed names."""
    targets = {url_basename(url).casefold(): url for url in urls}
    matches: dict[str, pathlib.Path] = {}
    if not research_root.exists():
        return matches
    # Prefer prior catalog-specific material, then other local research trees.
    files = (p for p in research_root.rglob("*") if p.is_file())
    for path in files:
        name = path.name.casefold()
        for basename, url in targets.items():
            if name == basename or ("." in basename and name.endswith(basename)):
                matches.setdefault(url, path)
    return matches


def fetch_one(url: str, dest: pathlib.Path) -> tuple[str, str, str]:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != "en.rkgaming.com":
        return "blocked_nonofficial_url", "", ""
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and dest.stat().st_size:
        return "already_downloaded", str(dest), ""
    request = urllib.request.Request(url, headers={"User-Agent": "RK-static-catalog-audit/1.0"})
    temp = dest.with_suffix(dest.suffix + ".part")
    try:
        with urllib.request.urlopen(request, timeout=25) as response, temp.open("wb") as out:
            final_host = urllib.parse.urlparse(response.geturl()).hostname or ""
            if final_host != "en.rkgaming.com":
                temp.unlink(missing_ok=True)
                return "redirected_off_domain", str(response.geturl()), final_host
            total = 0
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_BYTES:
                    temp.unlink(missing_ok=True)
                    return "exceeds_512MiB_limit", "", ""
                out.write(chunk)
        if not total:
            temp.unlink(missing_ok=True)
            return "empty_response", "", ""
        os.replace(temp, dest)
        return "downloaded", str(dest), str(total)
    except urllib.error.HTTPError as exc:
        temp.unlink(missing_ok=True)
        return f"http_{exc.code}", "", str(exc.reason)
    except Exception as exc:  # retain the exact transport failure in the ledger
        temp.unlink(missing_ok=True)
        return "download_error", "", f"{type(exc).__name__}: {exc}"


def digest(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def research_relative_path(path: pathlib.Path | None, research_root: pathlib.Path) -> str:
    if path is None:
        return ""
    try:
        rel = path.resolve().relative_to(research_root.resolve()).as_posix()
        return ".research/" + rel
    except ValueError:
        return "[outside research cache]"


def identify(path: pathlib.Path) -> dict[str, str]:
    result = {
        "size_bytes": "", "sha256": "", "sniffed_type": "unknown",
        "artifact_class": "unclassified", "pe_machine": "", "pe_entrypoint_rva": "",
        "pe_sections": "", "pe_import_dlls": "", "pe_import_symbols": "",
        "pe_overlay_size": "", "pe_overlay_marker_hex": "", "hid_setupapi_imports": "",
        "archive_member_count": "", "archive_member_names_sample": "",
    }
    size = path.stat().st_size
    result["size_bytes"] = str(size)
    result["sha256"] = digest(path)
    with path.open("rb") as f:
        head = f.read(512)
    if head.startswith(b"MZ"):
        result["sniffed_type"] = "PE/DOS executable signature"
        result["artifact_class"] = "Windows PE package; updater role unresolved by direct imports"
        if pefile:
            try:
                pe = pefile.PE(str(path), fast_load=True)
                pe.parse_data_directories(
                    directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
                )
                result["pe_machine"] = f"0x{pe.FILE_HEADER.Machine:04X}"
                result["pe_entrypoint_rva"] = f"0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:X}"
                result["pe_sections"] = str(len(pe.sections))
                overlay_offset = pe.get_overlay_data_start_offset()
                result["pe_overlay_size"] = str(size - overlay_offset) if overlay_offset is not None else "0"
                if overlay_offset is not None and overlay_offset < size:
                    with path.open("rb") as f:
                        f.seek(overlay_offset)
                        result["pe_overlay_marker_hex"] = f.read(16).hex()
                names: list[str] = []
                dlls: set[str] = set()
                if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        dll = entry.dll.decode("ascii", "replace")
                        dlls.add(dll)
                        for imp in entry.imports:
                            if imp.name:
                                names.append(imp.name.decode("ascii", "replace"))
                result["pe_import_dlls"] = "|".join(sorted(dlls))
                result["pe_import_symbols"] = str(len(names))
                interesting = {n.casefold() for n in names}
                result["hid_setupapi_imports"] = "yes" if interesting & {
                    "hidd_getattributes", "hidd_getpreparseddata", "hidd_getproductstring",
                    "hidd_getmanufacturerstring", "setupdienumdeviceinterfaces", "setupdigetclassdevs_a",
                    "setupdigetclassdevs_w", "hidp_getcaps", "hidp_getbuttoncaps",
                } else "no direct import observed"
                if result["hid_setupapi_imports"] == "yes":
                    result["artifact_class"] = "Windows PE updater package (direct HID/SetupAPI imports)"
            except Exception as exc:
                result["sniffed_type"] += f" (PE parse error: {type(exc).__name__})"
    elif head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06") or head.startswith(b"PK\x07\x08"):
        result["sniffed_type"] = "ZIP archive"
        result["artifact_class"] = "archive package; members inventoried, not extracted"
        try:
            with zipfile.ZipFile(path) as z:
                members = z.infolist()
                result["archive_member_count"] = str(len(members))
                result["archive_member_names_sample"] = " | ".join(m.filename for m in members[:30])
        except Exception:
            result["sniffed_type"] = "ZIP-like signature (archive parse failed)"
    elif head.startswith(b"Rar!\x1a\x07\x00") or head.startswith(b"Rar!\x1a\x07\x01\x00"):
        result["sniffed_type"] = "RAR archive"
        result["artifact_class"] = "archive package; contents not expanded"
    elif head.startswith(b":") and b"\n" in head and re.search(rb"(?m)^:[0-9A-Fa-f]{8}[0-9A-Fa-f]{2}", head):
        result["sniffed_type"] = "Intel HEX text"
        result["artifact_class"] = "text-encoded firmware image candidate"
    elif head.startswith(b"\x7fELF"):
        result["sniffed_type"] = "ELF executable/image"
        result["artifact_class"] = "binary image or firmware tool; needs target-specific analysis"
    elif head.startswith(b"\x55\xaa"):
        result["sniffed_type"] = "legacy boot-sector-like image"
        result["artifact_class"] = "raw firmware/image candidate"
    elif len(head) >= 4 and head[:4] == b"SINO":
        result["sniffed_type"] = "SINO-prefixed data"
        result["artifact_class"] = "firmware container candidate"
    else:
        result["sniffed_type"] = f"opaque binary ({head[:16].hex()})"
        result["artifact_class"] = "firmware/image candidate based on selector category; format unresolved"
    # File extensions remain catalog metadata; they do not override the
    # content-based role assessment above.
    return result


def row_key(r: dict[str, str]) -> tuple[str, ...]:
    return tuple(r.get(k, "") for k in (
        "selector_model_id", "record_id", "product_version_id", "attribute_id", "language_id", "pid"
    ))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--download", action="store_true", help="fetch listed official URLs into ignored .research")
    parser.add_argument("--inventory-only", action="store_true", help="hash/classify files already present, no network")
    parser.add_argument("--download-dir", type=pathlib.Path, default=DEFAULT_DOWNLOAD_DIR)
    parser.add_argument("--research-root", type=pathlib.Path, default=DEFAULT_RESEARCH_ROOT)
    parser.add_argument("--jobs", type=int, default=6)
    args = parser.parse_args()
    rows = load_rows()
    artifacts = grouped_artifacts(rows)
    urls = [str(a["url"]) for a in artifacts]
    local = existing_candidates(urls, args.research_root)
    statuses: dict[str, tuple[str, str, str]] = {}
    if args.download:
        jobs = min(max(1, args.jobs), 12)
        with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
            futures = {
                pool.submit(fetch_one, url, args.download_dir / url_basename(url)): url
                for url in urls
                if url not in local
            }
            for future in concurrent.futures.as_completed(futures):
                url = futures[future]
                statuses[url] = future.result()
    else:
        statuses = {url: ("inventory_only", "", "") for url in urls}

    inventory: list[dict[str, str]] = []
    path_for_url: dict[str, pathlib.Path] = {}
    for artifact in artifacts:
        url = str(artifact["url"])
        candidates = [local[url]] if url in local else []
        dest = args.download_dir / url_basename(url)
        if dest.is_file() and dest not in candidates:
            candidates.insert(0, dest)
        path = candidates[0] if candidates else None
        if path:
            path_for_url[url] = path
            observed = identify(path)
            if url in local and path.resolve() == dest.resolve():
                file_status = "cached_local_artifact"
            elif url in local:
                file_status = "preexisting_research_artifact"
            else:
                file_status = statuses.get(url, ("downloaded", "", ""))[0]
        else:
            observed = {k: "" for k in (
                "size_bytes", "sha256", "sniffed_type", "artifact_class", "pe_machine",
                "pe_entrypoint_rva", "pe_sections", "pe_import_dlls", "pe_import_symbols",
                "pe_overlay_size", "pe_overlay_marker_hex", "hid_setupapi_imports",
                "archive_member_count", "archive_member_names_sample",
            )}
            file_status = statuses.get(url, ("not_present", "", ""))[0]
        row = {k: str(artifact.get(k, "")) for k in (
            "filename", "url", "catalog_row_count", "source_csv_lines", "selector_model_id", "selector_model",
            "record_id", "record_name", "product_version_id", "product_version", "attribute_id",
            "attribute", "language_id", "language", "pid", "description",
        )}
        row["local_path"] = research_relative_path(path, args.research_root)
        row["acquisition_status"] = file_status
        row["transport_detail"] = statuses.get(url, ("", "", ""))[2]
        row.update(observed)
        inventory.append(row)

    ARTIFACT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with ARTIFACT_CSV.open("w", encoding="utf-8", newline="") as f:
        fields = list(inventory[0]) if inventory else []
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(inventory)

    # Propagate acquisition status to duplicate selector rows with the same
    # product tuple where the API supplied a blank URL in duplicate rows.
    artifact_by_key: dict[tuple[str, ...], list[dict[str, str]]] = defaultdict(list)
    inv_by_url = {r["url"]: r for r in inventory}
    for row in rows:
        if row.get("listed_file_url", "").strip():
            artifact_by_key[row_key(row)].append(inv_by_url[row["listed_file_url"].strip()])
    row_output: list[dict[str, str]] = []
    for row in rows:
        url = row.get("listed_file_url", "").strip()
        inv = inv_by_url.get(url) if url else None
        if not inv:
            candidates = artifact_by_key.get(row_key(row), [])
            inv = candidates[0] if len({c["url"] for c in candidates}) == 1 else None
        result = {k: v for k, v in row.items() if not k.startswith("_")}
        result["source_csv_line"] = row.get("_source_csv_line", "")
        result["resolved_artifact_url"] = inv["url"] if inv else ""
        result["artifact_filename"] = inv["filename"] if inv else ""
        result["artifact_acquisition_status"] = inv["acquisition_status"] if inv else "no_unique_artifact_url_for_tuple"
        result["artifact_sha256"] = inv["sha256"] if inv else ""
        result["artifact_type"] = inv["sniffed_type"] if inv else ""
        result["artifact_class"] = inv["artifact_class"] if inv else ""
        row_output.append(result)
    with ROW_CSV.open("w", encoding="utf-8", newline="") as f:
        fields = list(row_output[0]) if row_output else []
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(row_output)

    # Keep the public QMK HEX selector subset distinct from the 118 firmware
    # URLs above. Its seven URLs have their own acquisition and coverage count.
    qmk_rows = load_qmk_hex_rows()
    qmk_by_url: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in qmk_rows:
        qmk_by_url[row["listed_file_url"].strip()].append(row)
    qmk_statuses: dict[str, tuple[str, str, str]] = {}
    qmk_inventory: list[dict[str, str]] = []
    qmk_local = existing_candidates(list(qmk_by_url), args.research_root)
    if args.download:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(max(1, args.jobs), 12)) as pool:
            futures = {
                pool.submit(
                    fetch_one, url,
                    args.download_dir / "qmk-hex" / url_basename(url),
                ): url
                for url in qmk_by_url if url not in qmk_local
            }
            for future in concurrent.futures.as_completed(futures):
                url = futures[future]
                qmk_statuses[url] = future.result()
    else:
        qmk_statuses = {url: ("inventory_only", "", "") for url in qmk_by_url}
    for url, group in sorted(qmk_by_url.items()):
        dest = args.download_dir / "qmk-hex" / url_basename(url)
        path = qmk_local.get(url) or (dest if dest.is_file() else None)
        observed = identify(path) if path else {}
        qmk_inventory.append({
            "selector_subset": "QMK HEX firmware images (separate from firmware selector)",
            "url": url,
            "filename": url_basename(url),
            "selector_models": " | ".join(sorted({r.get("selector_model", "") for r in group})),
            "modes": " | ".join(sorted({r.get("product_version", "") for r in group})),
            "pids": " | ".join(sorted({r.get("pid", "") for r in group})),
            "catalog_row_count": str(len(group)),
            "local_path": research_relative_path(path, args.research_root),
            "acquisition_status": (
                "cached_local_artifact" if url in qmk_local and path and path.resolve() == dest.resolve()
                else "preexisting_research_artifact" if url in qmk_local
                else qmk_statuses.get(url, ("downloaded", "", ""))[0]
            ),
            "transport_detail": qmk_statuses.get(url, ("", "", ""))[2],
            **{k: observed.get(k, "") for k in (
                "size_bytes", "sha256", "sniffed_type", "artifact_class", "pe_machine",
                "pe_entrypoint_rva", "pe_sections", "pe_import_dlls", "pe_import_symbols",
                "pe_overlay_size", "pe_overlay_marker_hex", "hid_setupapi_imports", "archive_member_count",
                "archive_member_names_sample",
            )},
        })
    with QMK_HEX_CSV.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(qmk_inventory[0]) if qmk_inventory else [])
        writer.writeheader()
        writer.writerows(qmk_inventory)

    counts = Counter(r["acquisition_status"] for r in inventory)
    downloaded = sum(bool(r["sha256"]) for r in inventory)
    covered_urls = len(inventory)
    covered_rows = sum(bool(r["artifact_sha256"]) for r in row_output)
    print(json.dumps({
        "catalog": str(CATALOG), "firmware_selector_rows": len(rows),
        "rows_with_nonempty_listed_url": sum(bool(r.get("listed_file_url", "").strip()) for r in rows),
        "unique_artifact_urls": covered_urls, "urls_with_local_bytes_and_sha256": downloaded,
        "url_coverage_percent": round(100 * downloaded / covered_urls, 2) if covered_urls else 0,
        "row_coverage_percent_of_all_firmware_rows": round(100 * covered_rows / len(row_output), 2) if row_output else 0,
        "acquisition_status_counts": counts, "artifact_classes": Counter(r["artifact_class"] for r in inventory if r["artifact_class"]),
        "artifact_csv": str(ARTIFACT_CSV), "row_csv": str(ROW_CSV),
        "qmk_hex_unique_urls": len(qmk_inventory),
        "qmk_hex_urls_with_local_bytes_and_sha256": sum(bool(r["sha256"]) for r in qmk_inventory),
        "qmk_hex_url_coverage_percent": round(
            100 * sum(bool(r["sha256"]) for r in qmk_inventory) / len(qmk_inventory), 2
        ) if qmk_inventory else 0,
        "qmk_hex_acquisition_status_counts": Counter(r["acquisition_status"] for r in qmk_inventory),
        "qmk_hex_artifact_csv": str(QMK_HEX_CSV),
        "download_dir": str(args.download_dir),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
