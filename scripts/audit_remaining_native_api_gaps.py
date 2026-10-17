#!/usr/bin/env python3
"""Re-scan exact pointer references for unresolved RK 4.06 import paths.

This is a static byte-reference candidate finder, not a disassembler or a
proof that an import is unused. It verifies the package-matched SHA-256 hashes
before scanning so the address evidence cannot silently drift to another
binary. GNU objdump/control-flow review remains necessary to classify hits.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import struct
from pathlib import Path

import pefile


EXPECTED = {
    "Update.exe": "27894463b0dfe5bc3f5dc19d4d3351d9dfb692c402bf277bde3889d37e4a206c",
    "unins000.exe": "b4ca28b192d5a50307d2b28f3323b58b39cb51edd6682e75706cac2dd69a4a14",
}

# These are the ten unresolved import rows identified by the 4.06 gap ledger.
# Descriptor and pointer-table targets are included to show whether the
# imported thunk is merely stored as data or whether the record itself has an
# inbound absolute reference.
TARGETS = {
    "Update.exe": [
        ("LoadLibraryA", "IAT slot", 0x005603FC),
        ("LoadLibraryA", "import thunk entry", 0x0041743E),
        ("GetModuleHandleA", "IAT slot", 0x00560404),
        ("GetModuleHandleA", "import thunk entry", 0x004165AC),
        ("Kernel32 ANSI loader descriptor", "descriptor base", 0x00561DD4),
        ("Comctl32 ANSI loader descriptor", "descriptor base", 0x00562220),
        ("Comdlg32 ANSI loader descriptor", "descriptor base", 0x005645AC),
        ("property-sheet Comctl32 ANSI descriptor", "descriptor base", 0x00584510),
        ("Kernel32 Unicode loader descriptor", "descriptor base", 0x00561DCC),
        ("Comctl32 Unicode loader descriptor", "descriptor base", 0x00562218),
        ("Comdlg32 Unicode loader descriptor", "descriptor base", 0x005645A4),
        ("property-sheet Comctl32 Unicode descriptor", "descriptor base", 0x00584508),
        ("shared descriptor resolver", "function entry", 0x00416570),
        ("Kernel32 ANSI module name pointer", "descriptor field", 0x00561DF8),
        ("Comctl32 ANSI module name pointer", "descriptor field", 0x005621C8),
        ("Comdlg32 ANSI module name pointer", "descriptor field", 0x005645D0),
    ],
    "unins000.exe": [
        ("EnableScrollBar", "fallback pointer global", 0x0050209C),
        ("EnableScrollBar", "fallback thunk entry", 0x0040976C),
        ("ShowScrollBar", "fallback pointer global", 0x005020A0),
        ("ShowScrollBar", "fallback thunk entry", 0x00409BB4),
        ("GetScrollRange", "fallback pointer global", 0x005020A4),
        ("GetScrollRange", "fallback thunk entry", 0x004098CC),
        ("GetScrollInfo", "fallback pointer global", 0x005020A8),
        ("GetScrollInfo", "fallback thunk entry", 0x004098BC),
        ("GetScrollPos", "fallback pointer global", 0x005020AC),
        ("GetScrollPos", "fallback thunk entry", 0x004098C4),
        ("SetScrollPos", "fallback pointer global", 0x005020B0),
        ("SetScrollPos", "fallback thunk entry", 0x00409B64),
        ("SetScrollInfo", "fallback pointer global", 0x005020B4),
        ("SetScrollInfo", "fallback thunk entry", 0x00409B5C),
        ("SetScrollRange", "fallback pointer global", 0x005020B8),
        ("SetScrollRange", "fallback thunk entry", 0x00409B6C),
    ],
}


def section_for_offset(pe: pefile.PE, offset: int):
    for section in pe.sections:
        start = section.PointerToRawData
        end = start + section.SizeOfRawData
        if start <= offset < end:
            name = section.Name.rstrip(b"\0").decode("ascii", "replace")
            va = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress + offset - start
            return name, va
    return "overlay", ""


def references(data: bytes, value: int):
    needle = struct.pack("<I", value)
    result = []
    pos = 0
    while True:
        pos = data.find(needle, pos)
        if pos < 0:
            break
        result.append(pos)
        pos += 1  # Include overlapping unaligned byte matches as candidates.
    return result


def main() -> int:
    repo = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input-dir",
        type=Path,
        default=repo.parent / "_rk_analysis" / "inputs",
        help="directory containing the locally obtained package-matched PE snapshots",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=repo / "docs" / "rk-remaining-api-reference-scan.csv",
        help="CSV output path",
    )
    args = parser.parse_args()

    rows = []
    for filename, expected_hash in EXPECTED.items():
        path = args.input_dir / filename
        if not path.is_file():
            parser.error(f"missing local snapshot: {path}")
        data = path.read_bytes()
        actual_hash = hashlib.sha256(data).hexdigest()
        if actual_hash != expected_hash:
            parser.error(
                f"hash mismatch for {path}: expected {expected_hash}, got {actual_hash}"
            )
        pe = pefile.PE(data=data, fast_load=True)
        for import_name, target_kind, target_va in TARGETS[filename]:
            hits = references(data, target_va)
            if not hits:
                rows.append(
                    {
                        "binary": filename,
                        "sha256": actual_hash,
                        "import_or_object": import_name,
                        "target_kind": target_kind,
                        "target_va": f"0x{target_va:08X}",
                        "raw_file_offset": "",
                        "raw_reference_va": "",
                        "section": "",
                        "file_offset_alignment_mod4": "",
                        "raw_hit_count_for_target": 0,
                        "interpretation": "no exact little-endian DWORD occurrence in image bytes",
                    }
                )
                continue
            for offset in hits:
                section, reference_va = section_for_offset(pe, offset)
                rows.append(
                    {
                        "binary": filename,
                        "sha256": actual_hash,
                        "import_or_object": import_name,
                        "target_kind": target_kind,
                        "target_va": f"0x{target_va:08X}",
                        "raw_file_offset": f"0x{offset:08X}",
                        "raw_reference_va": f"0x{reference_va:08X}" if reference_va else "",
                        "section": section,
                        "file_offset_alignment_mod4": offset % 4,
                        "raw_hit_count_for_target": len(hits),
                        "interpretation": "candidate only; review instruction/data context",
                    }
                )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(rows[0])
    with args.output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote {len(rows)} evidence rows to {args.output}")
    print("Verified hashes:")
    for name, digest in EXPECTED.items():
        print(f"  {name}: {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
