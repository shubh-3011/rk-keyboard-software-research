#!/usr/bin/env python3
"""Validate a carved RK macOS ASAR and compare its members with Windows ASAR.

Only reads the DMG and the supplied Windows app.asar. APFS is reconstructed to
a temporary file by the existing standard-library audit helper; no archive
member contents are written out. The CSV contains member names and hashes only.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import mmap
import struct
import tempfile
from pathlib import Path
from typing import Any

from audit_rk_f99_macos_dmg import materialize_partition, read_dmg


DEFAULT_MAC_ASAR_OFFSET = 23_875_584


def parse_header(image: mmap.mmap, offset: int, label: str) -> tuple[dict[str, Any], int, int]:
    """Return ASAR header object, JSON start, and payload start."""
    if offset < 0 or offset + 16 > len(image):
        raise ValueError(f"{label}: ASAR header is outside the image")
    first, pickle_size, string_size, json_size = struct.unpack_from("<4I", image, offset)
    # The observed RK header is a Pickle string: 4-byte pickle payload length,
    # 4-byte string length, then UTF-8 JSON. Validate all nested sizes.
    if first != 4 or pickle_size != string_size + 4 or string_size != json_size + 4:
        raise ValueError(
            f"{label}: invalid ASAR Pickle lengths at {offset}: "
            f"{first}, {pickle_size}, {string_size}, {json_size}"
        )
    json_start = offset + 16
    json_end = json_start + json_size
    if json_end > len(image):
        raise ValueError(f"{label}: ASAR JSON extends past image end")
    try:
        header = json.loads(image[json_start:json_end].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label}: ASAR header JSON is invalid: {error}") from error
    if not isinstance(header, dict) or not isinstance(header.get("files"), dict):
        raise ValueError(f"{label}: ASAR JSON has no root files tree")
    return header, json_start, json_end


def collect_entries(tree: dict[str, Any], prefix: str = "") -> dict[str, dict[str, Any]]:
    entries: dict[str, dict[str, Any]] = {}
    for name, value in tree.items():
        path = f"{prefix}/{name}" if prefix else name
        if not isinstance(value, dict):
            entries[path] = {"kind": "invalid", "metadata": value}
            continue
        if isinstance(value.get("files"), dict):
            children = value["files"]
            if children:
                entries.update(collect_entries(children, path))
            else:
                entries[path] = {"kind": "directory", "metadata": value}
            continue
        if "link" in value:
            entries[path] = {"kind": "link", "metadata": value}
        elif value.get("unpacked"):
            entries[path] = {"kind": "unpacked", "metadata": value}
        elif "size" in value and "offset" in value:
            entries[path] = {"kind": "file", "metadata": value}
        else:
            entries[path] = {"kind": "metadata", "metadata": value}
    return entries


def archive_extent(entries: dict[str, dict[str, Any]], payload_start: int, label: str, image_size: int) -> int:
    max_end = 0
    for path, entry in entries.items():
        if entry["kind"] != "file":
            continue
        meta = entry["metadata"]
        try:
            rel_offset, size = int(meta["offset"]), int(meta["size"])
        except (TypeError, ValueError) as error:
            raise ValueError(f"{label}: invalid member extent for {path}") from error
        if rel_offset < 0 or size < 0 or payload_start + rel_offset + size > image_size:
            raise ValueError(f"{label}: member extent outside image: {path}")
        max_end = max(max_end, rel_offset + size)
    return max_end


def payload_range_summary(entries: dict[str, dict[str, Any]]) -> dict[str, int]:
    ranges = []
    for path, entry in entries.items():
        if entry["kind"] != "file":
            continue
        meta = entry["metadata"]
        start, size = int(meta["offset"]), int(meta["size"])
        if size:
            ranges.append((start, start + size, path))
    ranges.sort()
    max_end = max((end for _start, end, _path in ranges), default=0)
    covered_end = 0
    overlap_bytes = 0
    gap_bytes = 0
    for start, end, _path in ranges:
        if start > covered_end:
            gap_bytes += start - covered_end
        elif start < covered_end:
            overlap_bytes += max(0, min(covered_end, end) - start)
        covered_end = max(covered_end, end)
    return {
        "file_ranges": len(ranges),
        "payload_bytes_claimed": sum(end - start for start, end, _path in ranges),
        "payload_max_end": max_end,
        "payload_gap_bytes": gap_bytes,
        "payload_overlap_bytes": overlap_bytes,
    }


def sha256_range(image: mmap.mmap, start: int, size: int) -> str:
    digest = hashlib.sha256()
    end = start + size
    if start < 0 or size < 0 or end > len(image):
        raise ValueError(f"Invalid hash range {start}+{size} in {len(image)}-byte image")
    cursor = start
    while cursor < end:
        next_cursor = min(end, cursor + 1024 * 1024)
        digest.update(image[cursor:next_cursor])
        cursor = next_cursor
    return digest.hexdigest()


def member_hash(image: mmap.mmap, payload_start: int, entry: dict[str, Any], label: str, path: str) -> str:
    meta = entry["metadata"]
    start = payload_start + int(meta["offset"])
    size = int(meta["size"])
    digest = sha256_range(image, start, size)
    integrity = meta.get("integrity")
    if isinstance(integrity, dict) and str(integrity.get("algorithm", "")).lower() == "sha256":
        declared = integrity.get("hash")
        if declared and str(declared).lower() != digest:
            raise ValueError(f"{label}: ASAR integrity hash mismatch for {path}")
        block_size = integrity.get("blockSize")
        blocks = integrity.get("blocks")
        if block_size and isinstance(blocks, list):
            actual_blocks = [
                sha256_range(image, start + position, min(int(block_size), size - position))
                for position in range(0, size, int(block_size))
            ]
            if [str(item).lower() for item in blocks] != actual_blocks:
                raise ValueError(f"{label}: ASAR block-integrity hash mismatch for {path}")
    return digest


def inspect_archive(image: mmap.mmap, offset: int, label: str) -> dict[str, Any]:
    header, json_start, payload_start = parse_header(image, offset, label)
    entries = collect_entries(header["files"])
    max_payload_end = archive_extent(entries, payload_start, label, len(image))
    payload_ranges = payload_range_summary(entries)
    if payload_ranges["payload_gap_bytes"] or payload_ranges["payload_overlap_bytes"]:
        raise ValueError(
            f"{label}: ASAR member payload is not a gap-free, non-overlapping span: {payload_ranges}"
        )
    if payload_ranges["payload_max_end"] != max_payload_end or payload_ranges["payload_bytes_claimed"] != max_payload_end:
        raise ValueError(f"{label}: ASAR payload range accounting is inconsistent: {payload_ranges}")
    hashes: dict[str, str] = {}
    for path, entry in entries.items():
        if entry["kind"] == "file":
            hashes[path] = member_hash(image, payload_start, entry, label, path)
    extent_length = payload_start - offset + max_payload_end
    extent_hash = sha256_range(image, offset, extent_length)
    package = entries.get("package.json")
    package_data: dict[str, Any] = {}
    if package and package["kind"] == "file":
        start = payload_start + int(package["metadata"]["offset"])
        size = int(package["metadata"]["size"])
        package_data = json.loads(image[start:start + size].decode("utf-8"))
    return {
        "label": label,
        "offset": offset,
        "header_prefix_hex": image[offset:offset + 16].hex(),
        "json_start": json_start,
        "json_size": struct.unpack_from("<I", image, offset + 12)[0],
        "payload_start": payload_start,
        "max_payload_end": max_payload_end,
        "extent_length": extent_length,
        "extent_sha256": extent_hash,
        "entries": entries,
        "hashes": hashes,
        "package": package_data,
        "payload_ranges": payload_ranges,
        "image": image,
    }


def compare_entries(mac: dict[str, Any], windows: dict[str, Any], output: Path) -> tuple[dict[str, int], dict[str, int]]:
    fields = [
        "path", "comparison", "mac_kind", "windows_kind", "mac_size",
        "windows_size", "mac_offset", "windows_offset", "mac_sha256",
        "windows_sha256", "newline_normalized_same", "mac_integrity_sha256",
        "windows_integrity_sha256", "mac_link_target", "windows_link_target",
    ]
    counts: dict[str, int] = {}
    newline_counts = {"yes": 0, "no": 0}
    all_paths = sorted(set(mac["entries"]) | set(windows["entries"]))
    with output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for path in all_paths:
            m = mac["entries"].get(path)
            w = windows["entries"].get(path)
            mkind = m["kind"] if m else "absent"
            wkind = w["kind"] if w else "absent"
            mmeta = m["metadata"] if m else {}
            wmeta = w["metadata"] if w else {}
            mhash = mac["hashes"].get(path, "")
            whash = windows["hashes"].get(path, "")
            if m is None:
                status = "windows_only"
            elif w is None:
                status = "macos_only"
            elif mkind != wkind:
                status = "kind_changed"
            elif mkind == "file":
                status = "identical" if mhash == whash else "content_changed"
            elif mkind == "link":
                status = "identical" if mmeta.get("link") == wmeta.get("link") else "link_target_changed"
            elif mkind == "unpacked":
                status = "unpacked_member_metadata"
            elif mkind == "directory":
                status = "directory_both"
            else:
                status = "metadata_both"
            counts[status] = counts.get(status, 0) + 1
            mintegrity = mmeta.get("integrity", {}) if isinstance(mmeta.get("integrity"), dict) else {}
            wintegrity = wmeta.get("integrity", {}) if isinstance(wmeta.get("integrity"), dict) else {}
            newline_normalized_same = ""
            if m and w and mkind == "file" and wkind == "file" and mhash != whash:
                mstart = mac["payload_start"] + int(mmeta["offset"])
                wstart = windows["payload_start"] + int(wmeta["offset"])
                mdata = mac["image"][mstart:mstart + int(mmeta["size"])].replace(b"\r\n", b"\n")
                wdata = windows["image"][wstart:wstart + int(wmeta["size"])].replace(b"\r\n", b"\n")
                newline_normalized_same = "yes" if mdata == wdata else "no"
                newline_counts[newline_normalized_same] += 1
            writer.writerow({
                "path": path,
                "comparison": status,
                "mac_kind": mkind,
                "windows_kind": wkind,
                "mac_size": mmeta.get("size", "") if m else "",
                "windows_size": wmeta.get("size", "") if w else "",
                "mac_offset": mmeta.get("offset", "") if m else "",
                "windows_offset": wmeta.get("offset", "") if w else "",
                "mac_sha256": mhash,
                "windows_sha256": whash,
                "newline_normalized_same": newline_normalized_same,
                "mac_integrity_sha256": mintegrity.get("hash", ""),
                "windows_integrity_sha256": wintegrity.get("hash", ""),
                "mac_link_target": mmeta.get("link", "") if m else "",
                "windows_link_target": wmeta.get("link", "") if w else "",
            })
    return counts, newline_counts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dmg", type=Path, help="official RK F99 macOS DMG")
    parser.add_argument("windows_asar", type=Path, help="previously extracted Windows app.asar")
    parser.add_argument("--mac-asar-offset", type=lambda value: int(value, 0), default=DEFAULT_MAC_ASAR_OFFSET,
                        help="candidate ASAR start offset in reconstructed APFS partition (default: 23875584)")
    parser.add_argument("--csv-out", type=Path, required=True, help="member-name/hash comparison CSV")
    args = parser.parse_args()
    dmg_path = args.dmg.resolve()
    windows_path = args.windows_asar.resolve()
    output = args.csv_out.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)

    dmg_header, entries = read_dmg(dmg_path)
    apfs_entry = next((entry for entry in entries if "Apple_APFS" in str(entry["name"])), None)
    if apfs_entry is None:
        raise ValueError("No Apple_APFS blkx partition found")
    with dmg_path.open("rb") as source, tempfile.TemporaryFile(mode="w+b") as partition:
        materialize_partition(source, int(dmg_header["data_fork_offset"]), apfs_entry, partition)
        partition.flush()
        with mmap.mmap(partition.fileno(), 0, access=mmap.ACCESS_READ) as mac_image:
            mac = inspect_archive(mac_image, args.mac_asar_offset, "macOS")
            with windows_path.open("rb") as windows_file:
                with mmap.mmap(windows_file.fileno(), 0, access=mmap.ACCESS_READ) as windows_image:
                    windows = inspect_archive(windows_image, 0, "Windows")
                    counts, newline_counts = compare_entries(mac, windows, output)
                    windows_file_sha256 = sha256_range(windows_image, 0, len(windows_image))

    print(json.dumps({
        "macos": {key: mac[key] for key in ("offset", "header_prefix_hex", "json_start", "json_size", "payload_start", "max_payload_end", "extent_length", "extent_sha256")},
        "macos_payload_ranges": mac["payload_ranges"],
        "windows": {key: windows[key] for key in ("offset", "header_prefix_hex", "json_start", "json_size", "payload_start", "max_payload_end", "extent_length", "extent_sha256")},
        "windows_payload_ranges": windows["payload_ranges"],
        "macos_package": {key: mac["package"].get(key) for key in ("name", "version", "main")},
        "windows_package": {key: windows["package"].get(key) for key in ("name", "version", "main")},
        "windows_archive_sha256": windows_file_sha256,
        "member_counts": {"macos": len(mac["entries"]), "windows": len(windows["entries"]), "rows": sum(counts.values())},
        "member_comparison": dict(sorted(counts.items())),
        "raw_changed_normalized_comparison": newline_counts,
        "macos_content_hashes_verified_against_embedded_integrity": sum(
            bool(entry["metadata"].get("integrity")) for entry in mac["entries"].values() if entry["kind"] == "file"
        ),
        "windows_content_hashes_verified_against_embedded_integrity": sum(
            bool(entry["metadata"].get("integrity")) for entry in windows["entries"].values() if entry["kind"] == "file"
        ),
        "csv": str(output),
        "limitations": [
            "ASAR offsets were validated against the carved physical byte range, not an APFS pathname.",
            "Entries marked unpacked are outside the ASAR payload and are compared by metadata only.",
            "This comparison does not establish runtime behavior or app-bundle file attribution.",
        ],
    }, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
