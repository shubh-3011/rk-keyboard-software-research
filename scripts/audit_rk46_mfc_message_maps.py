#!/usr/bin/env python3
"""Inventory strict x86 MFC message-map accessor candidates in RK 4.6.

This is a bounded byte-pattern and structure parser. It scans executable PE
sections for `mov eax, imm32; ret`, then retains only accessors whose target
is a plausible AFX_MSGMAP descriptor with a terminated six-DWORD entry array
and executable handler addresses. RTTI owner names are joined only where an
accessor reference is preceded by an MSVC Complete Object Locator. It does
not execute the target or prove runtime message dispatch.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import struct
import sys
from dataclasses import dataclass
from pathlib import Path


EXPECTED_SHA256 = "8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9"
ENTRY_SIZE = 24
MAX_ENTRIES = 4096
MAX_VTABLE_SLOTS = 128

MESSAGE_NAMES = {
    0x0001: "WM_CREATE",
    0x0002: "WM_DESTROY",
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
    0x0200: "WM_MOUSEMOVE",
    0x0201: "WM_LBUTTONDOWN",
    0x0202: "WM_LBUTTONUP",
    0x0203: "WM_LBUTTONDBLCLK",
    0x0204: "WM_RBUTTONDOWN",
    0x0205: "WM_RBUTTONUP",
    0x0219: "WM_DEVICECHANGE",
}


@dataclass(frozen=True)
class Section:
    name: str
    start_va: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    executable: bool

    @property
    def end_va(self) -> int:
        return self.start_va + max(self.virtual_size, self.raw_size)


@dataclass(frozen=True)
class Entry:
    va: int
    message: int
    code: int
    first_id: int
    last_id: int
    signature: int
    handler: int


class PEImage:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.data = path.read_bytes()
        if self.data[:2] != b"MZ":
            raise ValueError("input does not have an MZ header")
        pe_offset = struct.unpack_from("<I", self.data, 0x3C)[0]
        if self.data[pe_offset : pe_offset + 4] != b"PE\0\0":
            raise ValueError("input does not have a PE signature")
        self.section_count = struct.unpack_from("<H", self.data, pe_offset + 6)[0]
        optional_size = struct.unpack_from("<H", self.data, pe_offset + 20)[0]
        optional = pe_offset + 24
        if struct.unpack_from("<H", self.data, optional)[0] != 0x10B:
            raise ValueError("expected a PE32 image")
        self.image_base = struct.unpack_from("<I", self.data, optional + 28)[0]
        self.section_table = optional + optional_size
        self.sections: list[Section] = []
        for index in range(self.section_count):
            off = self.section_table + index * 40
            raw_name = self.data[off : off + 8].split(b"\0", 1)[0]
            virtual_size, rva, raw_size, raw_offset = struct.unpack_from(
                "<IIII", self.data, off + 8
            )
            characteristics = struct.unpack_from("<I", self.data, off + 36)[0]
            self.sections.append(
                Section(
                    name=raw_name.decode("ascii", "replace"),
                    start_va=self.image_base + rva,
                    virtual_size=virtual_size,
                    raw_offset=raw_offset,
                    raw_size=raw_size,
                    executable=bool(characteristics & 0x20000000),
                )
            )

    def section_for_va(self, va: int) -> Section | None:
        return next((section for section in self.sections if section.start_va <= va < section.end_va), None)

    def va_to_offset(self, va: int) -> int:
        section = self.section_for_va(va)
        if section is None:
            raise ValueError(f"VA 0x{va:08X} is outside mapped sections")
        delta = va - section.start_va
        if delta >= section.raw_size:
            raise ValueError(f"VA 0x{va:08X} falls in an unbacked section tail")
        offset = section.raw_offset + delta
        if offset >= len(self.data):
            raise ValueError(f"VA 0x{va:08X} maps beyond end of file")
        return offset

    def read_u32_va(self, va: int) -> int:
        return struct.unpack_from("<I", self.data, self.va_to_offset(va))[0]

    def read_type_name_from_col(self, col_va: int) -> str | None:
        try:
            col_offset = self.va_to_offset(col_va)
            signature, _offset, _cd_offset, type_desc_va, _class_desc = struct.unpack_from(
                "<5I", self.data, col_offset
            )
            if signature not in (0, 1):
                return None
            type_desc_offset = self.va_to_offset(type_desc_va)
        except (ValueError, struct.error):
            return None
        name = self.data[type_desc_offset + 8 : type_desc_offset + 520].split(b"\0", 1)[0]
        if not (name.startswith(b".?AV") or name.startswith(b".?AU")):
            return None
        return name.decode("ascii", "replace")

    def owner_evidence(self, accessor_va: int) -> list[tuple[str, int, int]]:
        evidence: set[tuple[str, int, int]] = set()
        needle = struct.pack("<I", accessor_va)
        for section in self.sections:
            if section.executable:
                continue
            start = section.raw_offset
            end = start + section.raw_size
            pos = start
            while True:
                ref_offset = self.data.find(needle, pos, end)
                if ref_offset < 0:
                    break
                pos = ref_offset + 1
                ref_va = section.start_va + (ref_offset - section.raw_offset)
                if ref_va & 3:
                    continue
                for slot_index in range(MAX_VTABLE_SLOTS):
                    col_pointer_va = ref_va - (slot_index + 1) * 4
                    try:
                        col_va = self.read_u32_va(col_pointer_va)
                    except ValueError:
                        continue
                    owner = self.read_type_name_from_col(col_va)
                    if not owner:
                        continue
                    vtable_start_va = col_pointer_va + 4
                    try:
                        slot_values = [
                            self.read_u32_va(slot_va)
                            for slot_va in range(vtable_start_va, ref_va + 1, 4)
                        ]
                    except ValueError:
                        continue
                    if all(
                        (target_section := self.section_for_va(value)) is not None
                        and target_section.executable
                        for value in slot_values
                    ):
                        evidence.add((owner, col_va, ref_va))
                        break
        return sorted(evidence)


def parse_entries(image: PEImage, entries_va: int) -> list[Entry]:
    section = image.section_for_va(entries_va)
    if section is None or section.executable:
        raise ValueError("message array is outside non-executable section data")
    start = image.va_to_offset(entries_va)
    rows: list[Entry] = []
    found_sentinel = False
    for index in range(MAX_ENTRIES):
        offset = start + index * ENTRY_SIZE
        if offset + ENTRY_SIZE > section.raw_offset + section.raw_size:
            break
        values = struct.unpack_from("<6I", image.data, offset)
        if not any(values):
            found_sentinel = True
            break
        handler_section = image.section_for_va(values[5])
        if handler_section is None or not handler_section.executable:
            raise ValueError(f"handler 0x{values[5]:08X} is outside executable sections")
        rows.append(Entry(entries_va + index * ENTRY_SIZE, *values))
    if not found_sentinel or not rows:
        raise ValueError("message array has no bounded all-zero terminator")
    return rows


def discover_maps(image: PEImage) -> list[dict[str, object]]:
    maps: dict[tuple[int, int, int], dict[str, object]] = {}
    for section in image.sections:
        if not section.executable:
            continue
        blob = image.data[section.raw_offset : section.raw_offset + section.raw_size]
        for offset in range(max(0, len(blob) - 5)):
            if blob[offset] != 0xB8 or blob[offset + 5] != 0xC3:
                continue
            accessor_va = section.start_va + offset
            descriptor_va = struct.unpack_from("<I", blob, offset + 1)[0]
            try:
                descriptor_offset = image.va_to_offset(descriptor_va)
                descriptor_section = image.section_for_va(descriptor_va)
                if descriptor_section is None or descriptor_section.executable:
                    continue
                base_getter_va, entries_va = struct.unpack_from("<II", image.data, descriptor_offset)
                base_section = image.section_for_va(base_getter_va)
                if base_section is None or not base_section.executable:
                    continue
                entries = parse_entries(image, entries_va)
            except (ValueError, struct.error):
                continue
            key = (accessor_va, descriptor_va, entries_va)
            owner_evidence = image.owner_evidence(accessor_va)
            maps[key] = {
                "accessor_va": accessor_va,
                "descriptor_va": descriptor_va,
                "base_getter_va": base_getter_va,
                "entries_va": entries_va,
                "entries": entries,
                "owner_evidence": owner_evidence,
            }
    return sorted(maps.values(), key=lambda row: int(row["accessor_va"]))


def write_outputs(maps: list[dict[str, object]], summary_path: Path, entries_path: Path) -> None:
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    entries_path.parent.mkdir(parents=True, exist_ok=True)
    with summary_path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(
            [
                "accessor_va",
                "descriptor_va",
                "base_getter_va",
                "entries_va",
                "entry_count",
                "rtti_vtable_types",
                "rtti_vtable_evidence",
            ]
        )
        for row in maps:
            evidence = row["owner_evidence"]
            owners = sorted({item[0] for item in evidence})
            evidence_text = ";".join(f"{owner}@COL:{col:08X}@REF:{ref:08X}" for owner, col, ref in evidence)
            writer.writerow(
                [
                    f"0x{int(row['accessor_va']):08X}",
                    f"0x{int(row['descriptor_va']):08X}",
                    f"0x{int(row['base_getter_va']):08X}",
                    f"0x{int(row['entries_va']):08X}",
                    len(row["entries"]),
                    ";".join(owners),
                    evidence_text,
                ]
            )
    with entries_path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(
            [
                "accessor_va",
                "descriptor_va",
                "entries_va",
                "rtti_vtable_types",
                "entry_index",
                "entry_va",
                "message_hex",
                "message_name",
                "code_hex",
                "first_id_hex",
                "last_id_hex",
                "signature_hex",
                "handler_va",
            ]
        )
        for row in maps:
            owners = sorted({item[0] for item in row["owner_evidence"]})
            for index, entry in enumerate(row["entries"]):
                writer.writerow(
                    [
                        f"0x{int(row['accessor_va']):08X}",
                        f"0x{int(row['descriptor_va']):08X}",
                        f"0x{int(row['entries_va']):08X}",
                        ";".join(owners),
                        index,
                        f"0x{entry.va:08X}",
                        f"0x{entry.message:04X}",
                        MESSAGE_NAMES.get(entry.message, ""),
                        f"0x{entry.code:08X}",
                        f"0x{entry.first_id:08X}",
                        f"0x{entry.last_id:08X}",
                        f"0x{entry.signature:08X}",
                        f"0x{entry.handler:08X}",
                    ]
                )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pe", required=True, type=Path, help="hash-pinned 4.6 DeviceDriver.exe")
    parser.add_argument("--summary", required=True, type=Path, help="output map summary CSV")
    parser.add_argument("--entries", required=True, type=Path, help="output flattened entry CSV")
    args = parser.parse_args()
    digest = hashlib.sha256(args.pe.read_bytes()).hexdigest()
    if digest != EXPECTED_SHA256:
        print(f"input SHA-256 mismatch: {digest}", file=sys.stderr)
        return 2
    image = PEImage(args.pe)
    maps = discover_maps(image)
    if not maps:
        print("no strict MFC message-map accessors found", file=sys.stderr)
        return 1
    write_outputs(maps, args.summary, args.entries)
    owner_count = sum(bool(row["owner_evidence"]) for row in maps)
    entry_count = sum(len(row["entries"]) for row in maps)
    print(
        f"{digest}: {len(maps)} strict accessor/table candidates, "
        f"{owner_count} with RTTI owner evidence, {entry_count} entries; "
        f"wrote {args.summary} and {args.entries}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
