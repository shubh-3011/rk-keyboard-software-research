#!/usr/bin/env python3
"""Decode the hash-pinned 4.6 CLedDlg map and selected static paths.

The tool reads PE bytes only. It does not load or execute the vendor image.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import struct
import sys
from pathlib import Path


EXPECTED_SHA256 = "8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9"
IMAGE_BASE = 0x00400000
MAP_ACCESSOR_VA = 0x004234D0
MAP_DESCRIPTOR_VA = 0x005D5640
MAP_ENTRIES_VA = 0x005D54C0
MAP_TYPE_DESCRIPTOR_VA = 0x0061A1B0
MAP_COL_VA = 0x005ED0C0
ENTRY_SIZE = 24


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def pe_sections(data: bytes) -> tuple[int, list[dict[str, int | str]]]:
    if data[:2] != b"MZ":
        raise ValueError("input has no MZ signature")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("input has no PE signature")
    section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    optional = pe_offset + 24
    if struct.unpack_from("<H", data, optional)[0] != 0x10B:
        raise ValueError("expected a PE32 image")
    image_base = struct.unpack_from("<I", data, optional + 28)[0]
    if image_base != IMAGE_BASE:
        raise ValueError(f"unexpected image base 0x{image_base:08X}")
    section_table = optional + optional_size
    sections: list[dict[str, int | str]] = []
    for index in range(section_count):
        offset = section_table + 40 * index
        name = data[offset : offset + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from(
            "<IIII", data, offset + 8
        )
        characteristics = struct.unpack_from("<I", data, offset + 36)[0]
        sections.append(
            {
                "name": name,
                "va": image_base + virtual_address,
                "virtual_size": virtual_size,
                "raw_size": raw_size,
                "raw_pointer": raw_pointer,
                "executable": bool(characteristics & 0x20000000),
            }
        )
    return image_base, sections


def va_to_offset(va: int, sections: list[dict[str, int | str]]) -> tuple[int, bool]:
    for section in sections:
        start = int(section["va"])
        delta = va - start
        if 0 <= delta < max(int(section["virtual_size"]), int(section["raw_size"])):
            if delta >= int(section["raw_size"]):
                raise ValueError(f"VA 0x{va:08X} lies in an unbacked section tail")
            return int(section["raw_pointer"]) + delta, bool(section["executable"])
    raise ValueError(f"VA 0x{va:08X} is outside mapped sections")


def bytes_at(data: bytes, sections: list[dict[str, int | str]], va: int, count: int) -> bytes:
    offset, _ = va_to_offset(va, sections)
    return data[offset : offset + count]


def decode(data: bytes, sections: list[dict[str, int | str]]) -> list[dict[str, str]]:
    accessor = bytes_at(data, sections, MAP_ACCESSOR_VA, 6)
    if accessor != bytes.fromhex("B8 40 56 5D 00 C3"):
        raise ValueError(f"unexpected CLedDlg map accessor bytes: {accessor.hex(' ')}")

    descriptor_offset, _ = va_to_offset(MAP_DESCRIPTOR_VA, sections)
    base_getter, entries_va = struct.unpack_from("<II", data, descriptor_offset)
    if (base_getter, entries_va) != (0x00481025, MAP_ENTRIES_VA):
        raise ValueError("CLedDlg map descriptor does not match recovered values")
    if bytes_at(data, sections, base_getter, 6) != bytes.fromhex("B8 24 82 5A 00 C3"):
        raise ValueError("base-map getter does not return the expected base descriptor")

    vtable_col, _ = va_to_offset(0x005D5830, sections)
    if struct.unpack_from("<I", data, vtable_col)[0] != MAP_COL_VA:
        raise ValueError("CLedDlg vtable does not point to the recovered COL")
    col_offset, _ = va_to_offset(MAP_COL_VA, sections)
    type_descriptor = struct.unpack_from("<I", data, col_offset + 12)[0]
    if type_descriptor != MAP_TYPE_DESCRIPTOR_VA:
        raise ValueError("RTTI COL type-descriptor pointer changed")
    type_offset, _ = va_to_offset(type_descriptor + 8, sections)
    type_name = data[type_offset : type_offset + 32].split(b"\0", 1)[0].decode("ascii")
    if type_name != ".?AVCLedDlg@@":
        raise ValueError(f"unexpected RTTI name {type_name!r}")

    expected = {
        0x0481: 0x00424660,
        0x0482: 0x00424570,
        0x0113: 0x00427380,
    }
    rows: list[dict[str, str]] = []
    entries_offset, _ = va_to_offset(MAP_ENTRIES_VA, sections)
    saw_sentinel = False
    for index in range(256):
        row_offset = entries_offset + index * ENTRY_SIZE
        if row_offset + ENTRY_SIZE > len(data):
            raise ValueError("message map extends beyond the input")
        values = struct.unpack_from("<6I", data, row_offset)
        if not any(values):
            saw_sentinel = True
            break
        message, code, first_id, last_id, signature, handler = values
        _, executable = va_to_offset(handler, sections)
        if not executable:
            raise ValueError(f"handler 0x{handler:08X} is outside executable sections")
        if message in expected and expected[message] != handler:
            raise ValueError(f"unexpected handler for message 0x{message:04X}")
        rows.append(
            {
                "binary_sha256": EXPECTED_SHA256,
                "owner_class": type_name,
                "map_accessor_va": f"0x{MAP_ACCESSOR_VA:08X}",
                "map_descriptor_va": f"0x{MAP_DESCRIPTOR_VA:08X}",
                "entries_base_va": f"0x{MAP_ENTRIES_VA:08X}",
                "entry_va": f"0x{MAP_ENTRIES_VA + index * ENTRY_SIZE:08X}",
                "entry_index": str(index),
                "message_hex": f"0x{message:04X}",
                "code_hex": f"0x{code:08X}",
                "first_id_hex": f"0x{first_id:08X}",
                "last_id_hex": f"0x{last_id:08X}",
                "signature_hex": f"0x{signature:08X}",
                "handler_va": f"0x{handler:08X}",
                "handler_executable": str(executable).lower(),
            }
        )
    if not saw_sentinel:
        raise ValueError("no all-zero message-map sentinel found")
    if len(rows) != 15:
        raise ValueError(f"expected 15 CLedDlg entries, found {len(rows)}")
    if set(expected) - {int(row["message_hex"], 16) for row in rows}:
        raise ValueError("one or more expected CLedDlg message rows are missing")

    direct_edges = {
        0x00424637: bytes.fromhex("E8 C4 CA FD FF"),
        0x00424786: bytes.fromhex("E8 75 C9 FD FF"),
    }
    for va, expected_bytes in direct_edges.items():
        if bytes_at(data, sections, va, len(expected_bytes)) != expected_bytes:
            raise ValueError(f"unexpected ApplySetting queue call bytes at 0x{va:08X}")
    if bytes_at(data, sections, 0x00418AC5, 5) != bytes.fromhex("68 82 04 00 00"):
        raise ValueError("message 0x0482 producer bytes changed")
    if bytes_at(data, sections, 0x00418B54, 5) != bytes.fromhex("68 81 04 00 00"):
        raise ValueError("message 0x0481 producer bytes changed")
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pe", required=True, type=Path, help="hash-pinned DeviceDriver.exe")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("docs/rk-v4.6-cleddlg-message-map.csv"),
        help="decoded message-map CSV path",
    )
    args = parser.parse_args()
    digest = sha256(args.pe)
    if digest.lower() != EXPECTED_SHA256:
        raise ValueError(f"PE hash mismatch: expected {EXPECTED_SHA256}, got {digest}")
    data = args.pe.read_bytes()
    _, sections = pe_sections(data)
    rows = decode(data, sections)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    print(f"{digest}: decoded {len(rows)} RTTI-attributed CLedDlg entries to {args.output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, struct.error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
