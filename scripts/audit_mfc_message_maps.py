#!/usr/bin/env python3
"""Extract recovered MFC message-map arrays from the hash-pinned RK PE.

This parser does not execute or modify the input binary. The supplied evidence
CSV contains map descriptor and entry-array VAs recovered during static
analysis; this script decodes the six-DWORD AFX_MSGMAP_ENTRY records at each
listed entries base and writes a normalized CSV.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import struct
import sys
from collections import defaultdict
from pathlib import Path


EXPECTED_SHA256 = "c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6"
ENTRY_SIZE = 24
MAX_ENTRIES = 4096

MESSAGE_NAMES = {
    0x000F: "WM_PAINT",
    0x0011: "WM_QUERYENDSESSION",
    0x0014: "WM_ERASEBKGND",
    0x0020: "WM_SETCURSOR",
    0x0037: "WM_QUERYDRAGICON",
    0x0046: "WM_WINDOWPOSCHANGING",
    0x0053: "WM_HELP",
    0x0111: "WM_COMMAND",
    0x0112: "WM_SYSCOMMAND",
    0x0113: "WM_TIMER",
    0x0201: "WM_LBUTTONDOWN",
    0x0202: "WM_LBUTTONUP",
    0x0219: "WM_DEVICECHANGE",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def va_to_offset(data: bytes, va: int) -> tuple[int, bool]:
    if data[:2] != b"MZ":
        raise ValueError("input does not have an MZ header")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("input does not have a PE signature")
    section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    optional = pe_offset + 24
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic != 0x10B:
        raise ValueError(f"expected PE32 image (optional header 0x{magic:04X})")
    image_base = struct.unpack_from("<I", data, optional + 28)[0]
    section_table = optional + optional_size

    for index in range(section_count):
        offset = section_table + index * 40
        virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from(
            "<IIII", data, offset + 8
        )
        characteristics = struct.unpack_from("<I", data, offset + 36)[0]
        start_va = image_base + virtual_address
        delta = va - start_va
        if 0 <= delta < max(virtual_size, raw_size):
            if delta >= raw_size:
                raise ValueError(f"VA 0x{va:08X} falls in an unbacked section tail")
            file_offset = raw_pointer + delta
            if file_offset >= len(data):
                raise ValueError(f"VA 0x{va:08X} maps beyond end of file")
            return file_offset, bool(characteristics & 0x20000000)
    raise ValueError(f"VA 0x{va:08X} does not map to a section")


def read_map_evidence(path: Path) -> list[dict[str, int | str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    groups: dict[tuple[int, int], set[str]] = defaultdict(set)
    for row in rows:
        descriptor = int(row["map_descriptor_va"], 16)
        entries = int(row["entries_base_va"], 16)
        groups[(descriptor, entries)].add(row["owner_class"])
    return [
        {
            "map_descriptor_va": descriptor,
            "entries_base_va": entries,
            "owner_classes": "; ".join(sorted(owners)),
        }
        for (descriptor, entries), owners in sorted(groups.items(), key=lambda item: item[0][1])
    ]


def extract(data: bytes, maps: list[dict[str, int | str]]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for map_info in maps:
        descriptor = int(map_info["map_descriptor_va"])
        entries_base = int(map_info["entries_base_va"])
        offset, executable = va_to_offset(data, entries_base)
        if executable:
            raise ValueError(f"entry array at 0x{entries_base:08X} maps to executable section")

        found_sentinel = False
        for index in range(MAX_ENTRIES):
            record_offset = offset + index * ENTRY_SIZE
            if record_offset + ENTRY_SIZE > len(data):
                raise ValueError(f"entry array at 0x{entries_base:08X} runs past end of file")
            message, code, first_id, last_id, signature, handler = struct.unpack_from(
                "<6I", data, record_offset
            )
            if not any((message, code, first_id, last_id, signature, handler)):
                found_sentinel = True
                break
            entry_va = entries_base + index * ENTRY_SIZE
            _, handler_is_executable = va_to_offset(data, handler)
            if not handler_is_executable:
                raise ValueError(
                    f"handler 0x{handler:08X} at entry 0x{entry_va:08X} is outside executable sections"
                )
            rows.append(
                {
                    "owner_classes": map_info["owner_classes"],
                    "map_descriptor_va": f"0x{descriptor:08X}",
                    "entries_base_va": f"0x{entries_base:08X}",
                    "entry_index": str(index),
                    "entry_va": f"0x{entry_va:08X}",
                    "message_hex": f"0x{message:04X}",
                    "message_name": MESSAGE_NAMES.get(message, ""),
                    "code_hex": f"0x{code:08X}",
                    "id_hex": f"0x{first_id:08X}",
                    "last_id_hex": f"0x{last_id:08X}",
                    "signature_hex": f"0x{signature:08X}",
                    "handler_va": f"0x{handler:08X}",
                }
            )
        if not found_sentinel:
            raise ValueError(f"no all-zero sentinel found for map at 0x{entries_base:08X}")
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pe", required=True, type=Path, help="hash-matched DeviceDriver.exe")
    parser.add_argument(
        "--map-evidence",
        type=Path,
        default=Path("docs/rk-mfc-map-owner-evidence.csv"),
        help="CSV of recovered map descriptor and entries-base VAs",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("docs/rk-mfc-message-map-entries.csv"),
        help="normalized CSV output path",
    )
    parser.add_argument(
        "--expected-sha256",
        default=EXPECTED_SHA256,
        help="expected PE SHA-256 (defaults to the documented installed 4.06 hash)",
    )
    args = parser.parse_args()

    digest = sha256(args.pe)
    if digest.lower() != args.expected_sha256.lower():
        raise ValueError(f"PE SHA-256 mismatch: expected {args.expected_sha256}, got {digest}")

    data = args.pe.read_bytes()
    maps = read_map_evidence(args.map_evidence)
    rows = extract(data, maps)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "owner_classes",
        "map_descriptor_va",
        "entries_base_va",
        "entry_index",
        "entry_va",
        "message_hex",
        "message_name",
        "code_hex",
        "id_hex",
        "last_id_hex",
        "signature_hex",
        "handler_va",
    ]
    with args.output.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    command_rows = sum(row["message_hex"] == "0x0111" for row in rows)
    print(
        f"PE SHA-256 {digest}; decoded {len(maps)} map arrays and {len(rows)} entries "
        f"({command_rows} WM_COMMAND, {len(rows) - command_rows} other); wrote {args.output}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, struct.error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
