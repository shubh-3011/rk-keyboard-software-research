#!/usr/bin/env python3
"""Audit the dated RK keyboard QMK selector snapshot without running artifacts.

The optional --fetch mode downloads only the selector's .zip source packages and
.json definitions to a caller-selected cache. It deliberately leaves .hex rows
unfetched so firmware-image analysis remains a separate workstream. Archives
are listed and read as data; this script never extracts or executes their files.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = ROOT / "docs" / "rk-official-download-selector-catalog-2026-10-19.csv"
DEFAULT_ROWS = ROOT / "docs" / "rk-qmk-selector-artifact-audit-2026-10-19.csv"
DEFAULT_MEMBERS = ROOT / "docs" / "rk-qmk-source-archive-members-2026-10-19.csv"
ALLOWED_HOST = "en.rkgaming.com"
MAX_DOWNLOAD_BYTES = 200 * 1024 * 1024
SOURCE_SUFFIXES = {
    ".c", ".h", ".cpp", ".hpp", ".cc", ".hh", ".mk", ".md", ".txt",
    ".json", ".yaml", ".yml", ".xml", ".py", ".sh", ".bat", ".ps1",
    ".toml", ".ini", ".cfg", ".conf", ".rules", ".ld", ".s", ".S", ".inc",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_url_name(url: str) -> tuple[str, str]:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != ALLOWED_HOST:
        raise ValueError(f"refusing URL outside https://{ALLOWED_HOST}: {url}")
    if not parsed.path.startswith("/media/files/"):
        raise ValueError(f"refusing non-media selector URL: {url}")
    name = PurePosixPath(parsed.path).name
    if not name or name in {".", ".."}:
        raise ValueError(f"URL has no safe filename: {url}")
    ext = PurePosixPath(name).suffix.lower()
    return name, ext


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8-sig") as stream:
        return list(csv.DictReader(stream))


def fetch_bytes(url: str) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "rk-keyboard-software-research/1.0 (static catalog audit)"},
    )
    with urllib.request.urlopen(request, timeout=45) as response:
        final = urllib.parse.urlparse(response.geturl())
        if final.scheme != "https" or final.hostname != ALLOWED_HOST:
            raise ValueError(f"download redirected outside official host: {response.geturl()}")
        body = response.read(MAX_DOWNLOAD_BYTES + 1)
    if len(body) > MAX_DOWNLOAD_BYTES:
        raise ValueError(f"download exceeds {MAX_DOWNLOAD_BYTES} byte audit bound")
    return body


def artifact_path(cache: Path, url: str) -> Path:
    name, _ = safe_url_name(url)
    return cache / name


def collect_artifact(url: str, cache: Path | None, do_fetch: bool) -> tuple[bytes | None, str]:
    _, ext = safe_url_name(url)
    if ext == ".hex":
        return None, "not acquired; HEX firmware-image rows are reserved for the separate firmware audit"
    if ext not in {".zip", ".json"}:
        return None, f"not acquired; unsupported selector artifact extension {ext or '(none)'}"
    if cache is None:
        return None, "metadata only; no artifact cache supplied"

    path = artifact_path(cache, url)
    if path.is_file():
        data = path.read_bytes()
        return data, "cached local artifact"
    if not do_fetch:
        return None, "listed artifact not present in selected cache"

    try:
        data = fetch_bytes(url)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return data, "downloaded from official listed URL; static inspection only"
    except (OSError, ValueError, urllib.error.URLError, TimeoutError) as exc:
        return None, f"fetch failed: {type(exc).__name__}: {exc}"


def inspect_json(data: bytes) -> tuple[str, str, str]:
    try:
        obj = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return "invalid JSON or non-UTF-8", "", f"parse error: {type(exc).__name__}"
    if isinstance(obj, dict):
        keys = ";".join(sorted(str(k) for k in obj.keys()))
        shape = "object"
    elif isinstance(obj, list):
        keys = ""
        shape = f"array[{len(obj)}]"
    else:
        keys = ""
        shape = type(obj).__name__
    if isinstance(obj, dict):
        # Summarize declarative fields without treating them as proof of a
        # compatible physical revision or a built firmware image.
        metadata = []
        for key in ("keyboard_name", "manufacturer", "maintainer", "processor", "bootloader"):
            if key in obj and isinstance(obj[key], (str, int, float, bool)):
                metadata.append(f"{key}={obj[key]}")
        layouts = obj.get("layouts")
        if isinstance(layouts, dict):
            for layout_name, definition in sorted(layouts.items()):
                entries = definition.get("layout") if isinstance(definition, dict) else None
                metadata.append(f"layout={layout_name}:{len(entries) if isinstance(entries, list) else 'unknown'}")
        matrix = obj.get("matrix_pins")
        if isinstance(matrix, dict):
            metadata.append(f"matrix={len(matrix.get('rows', []))}x{len(matrix.get('cols', []))}")
        rgb = obj.get("rgb_matrix")
        if isinstance(rgb, dict):
            led_layout = rgb.get("layout")
            metadata.append(f"rgb_driver={rgb.get('driver', 'unspecified')}")
            if isinstance(led_layout, list):
                metadata.append(f"rgb_leds={len(led_layout)}")
        dynamic = obj.get("dynamic_keymap")
        if isinstance(dynamic, dict) and "layer_count" in dynamic:
            metadata.append(f"dynamic_layers={dynamic['layer_count']}")
        features = obj.get("features")
        if isinstance(features, dict):
            enabled = sorted(key for key, value in features.items() if value is True)
            metadata.append(f"enabled_features={','.join(enabled)}")
        note = "; ".join(metadata)
    else:
        note = ""
    return shape, keys, note


def inspect_zip(data: bytes, url: str) -> tuple[str, str, list[dict[str, str]]]:
    try:
        from io import BytesIO

        with zipfile.ZipFile(BytesIO(data)) as archive:
            infos = archive.infolist()
            files = [item for item in infos if not item.is_dir()]
            if sum(item.file_size for item in files) > 50 * 1024 * 1024 or any(item.file_size > 20 * 1024 * 1024 for item in files):
                raise ValueError("archive exceeds static inventory size bounds")
            extensions = Counter(PurePosixPath(item.filename).suffix.lower() or "[no extension]" for item in files)
            top = sorted({PurePosixPath(item.filename).parts[0] for item in files if PurePosixPath(item.filename).parts})
            summary = (
                f"{len(files)} files; {len(infos)-len(files)} directories; "
                f"top-level={';'.join(top[:20])}; extensions="
                + ";".join(f"{key}:{extensions[key]}" for key in sorted(extensions))
            )
            root = PurePosixPath(files[0].filename).parts[0] if files else ""
            keyboard_json_name = f"{root}/keyboard.json" if root else ""
            embedded_json_hash = ""
            try:
                embedded_json_hash = sha256(archive.read(keyboard_json_name))
            except KeyError:
                pass
            rows = []
            for item in infos:
                if item.is_dir():
                    continue
                path = PurePosixPath(item.filename)
                name = path.name.lower()
                suffix = path.suffix.lower()
                if suffix in {".hex", ".bin", ".uf2", ".elf", ".map", ".eep", ".dfu"}:
                    classification = "firmware/build output or binary; member name only"
                elif suffix in SOURCE_SUFFIXES:
                    classification = "source/config/documentation member; not executed"
                else:
                    classification = "other archive member; not executed"
                rows.append({
                    "artifact_url": url,
                    "member_path": item.filename,
                    "member_size": str(item.file_size),
                    "compressed_size": str(item.compress_size),
                    "crc32": f"{item.CRC:08x}",
                    "member_sha256": sha256(archive.read(item)),
                    "classification": classification,
                })
            return summary, embedded_json_hash, rows
    except (zipfile.BadZipFile, OSError) as exc:
        return f"not a readable ZIP: {type(exc).__name__}", "", []


def write_rows(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0].keys()), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT, help="dated selector CSV")
    parser.add_argument("--output", type=Path, default=DEFAULT_ROWS, help="row-level QMK artifact CSV")
    parser.add_argument("--members-output", type=Path, default=DEFAULT_MEMBERS, help="ZIP member inventory CSV")
    parser.add_argument("--artifact-cache", type=Path, help="local cache containing (or receiving) ZIP/JSON artifacts")
    parser.add_argument("--fetch", action="store_true", help="download only missing ZIP/JSON files from their official listed URLs")
    args = parser.parse_args()

    source_rows = [row for row in read_csv(args.input) if row.get("catalog", "").lower() == "qmk"]
    if len(source_rows) != 83:
        raise SystemExit(f"expected 83 QMK selector rows in {args.input}, found {len(source_rows)}")
    if args.fetch and args.artifact_cache is None:
        raise SystemExit("--fetch requires --artifact-cache <directory>")
    if args.artifact_cache:
        args.artifact_cache.mkdir(parents=True, exist_ok=True)

    prefetched: dict[str, tuple[bytes | None, str]] = {}
    if args.fetch:
        urls = sorted({
            row.get("listed_file_url", "")
            for row in source_rows
            if row.get("listed_file_url", "") and PurePosixPath(urllib.parse.urlparse(row["listed_file_url"]).path).suffix.lower() in {".zip", ".json"}
        })
        def fetch_one(url: str) -> tuple[str, bytes | None, str]:
            data, status = collect_artifact(url, args.artifact_cache, True)
            return url, data, status
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(fetch_one, url) for url in urls]
            for future in as_completed(futures):
                url, data, status = future.result()
                prefetched[url] = (data, status)

    result_rows: list[dict[str, str]] = []
    member_rows: list[dict[str, str]] = []
    acquisition_counts: Counter[str] = Counter()
    for row in source_rows:
        source_row = dict(row)
        source_row["selector_snapshot_acquisition_status"] = source_row.pop("acquisition_status", "")
        url = row.get("listed_file_url", "")
        if not url:
            result_rows.append({**source_row, "artifact_extension": "", "artifact_sha256": "", "artifact_bytes": "", "acquisition_status": "no listed artifact URL", "acquisition_result": "no listed artifact URL", "static_shape": "", "static_fields": "", "static_note": "", "embedded_keyboard_json_sha256": "", "matching_source_zip_count": "", "matching_source_zip_record_ids": ""})
            continue
        name, ext = safe_url_name(url)
        if url in prefetched:
            data, status = prefetched[url]
        else:
            data, status = collect_artifact(url, args.artifact_cache, False)
        acquisition_counts[status.split(";")[0]] += 1
        digest = sha256(data) if data is not None else ""
        shape = fields = note = embedded_json_hash = ""
        if data is not None and ext == ".json":
            shape, fields, note = inspect_json(data)
        elif data is not None and ext == ".zip":
            shape, embedded_json_hash, new_members = inspect_zip(data, url)
            member_rows.extend(new_members)
            fields = "archive directory only; member classification does not imply code was understood"
        result_rows.append({
            **source_row,
            "artifact_filename": name,
            "artifact_extension": ext,
            "artifact_sha256": digest,
            "artifact_bytes": str(len(data)) if data is not None else "",
            "acquisition_status": status,
            "acquisition_result": status,
            "static_shape": shape,
            "static_fields": fields,
            "static_note": note,
            "embedded_keyboard_json_sha256": embedded_json_hash,
            "matching_source_zip_count": "",
            "matching_source_zip_record_ids": "",
        })

    embedded: dict[str, list[dict[str, str]]] = {}
    for row in result_rows:
        if row.get("artifact_extension") == ".zip" and row.get("embedded_keyboard_json_sha256"):
            embedded.setdefault(row["embedded_keyboard_json_sha256"], []).append(row)
    for row in result_rows:
        if row.get("artifact_extension") == ".json" and row.get("artifact_sha256"):
            matches = embedded.get(row["artifact_sha256"], [])
            row["matching_source_zip_count"] = str(len(matches))
            row["matching_source_zip_record_ids"] = ";".join(match.get("record_id", "") for match in matches)

    write_rows(args.output, result_rows)
    write_rows(args.members_output, member_rows)
    unique_urls = {row.get("listed_file_url", "") for row in source_rows if row.get("listed_file_url", "")}
    print(f"QMK selector rows: {len(source_rows)}")
    print(f"Unique listed URLs: {len(unique_urls)}")
    print(f"Rows by type: {dict(Counter(row.get('qmk_type_label', '') for row in source_rows))}")
    print(f"Rows by model: {dict(Counter(row.get('selector_model', '') for row in source_rows))}")
    print(f"Acquisition outcomes: {dict(acquisition_counts)}")
    print(f"Wrote: {args.output}")
    print(f"Wrote: {args.members_output}")
    print("No HEX firmware images were fetched; no archive member was extracted to disk or executed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
