#!/usr/bin/env python3
"""Verify the V4.6 CDevRKKB vtable and emit a conservative static ledger.

Reads the hash-pinned DeviceDriver.exe as PE bytes only. It does not start RK
software, open a device interface, send a HID report, or interact with firmware.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
from pathlib import Path

import pefile


EXPECTED_SHA256 = "8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9"
IMAGE_BASE = 0x00400000
VTABLE_VA = 0x005D410C
CONSTRUCTOR_SITE_VA = 0x00413D46
EXPECTED_TARGETS = [
    0x00413D50, 0x00413DD0, 0x0040D710, 0x0044B310, 0x0040D700,
    0x00413D90, 0x00413DA0, 0x00414840, 0x0040DEB0, 0x00413D00,
    0x0040D710, 0x0040D700, 0x0043E950, 0x0043E950, 0x0040D710,
    0x0043E950, 0x0044B310, 0x00414930, 0x00414080, 0x0040D720,
    0x0043E950, 0x0040D740, 0x0040D740, 0x0040D750, 0x0040D780,
    0x0040D7A0,
]

ROWS = [
    ("scalar deleting destructor", "proven", "0x00413D50 closes the primary handle at +0x04, clears state, restores the CHidDev vtable, and conditionally calls the object deallocator when argument bit 0 is set.", "The wrapper's presence is proven; destructor call timing was not observed at runtime."),
    ("descriptor-driven HID discovery/open", "proven", "0x00413DD0 scans the compiled descriptor table, compares VID/PID and HID usage/report-size fields, then calls the CreateFileW import for a matching path and stores the returned handle at +0x04.", "This is an open-capable static path. No physical interface was opened and the table's complete model provenance is not established here."),
    ("zero-return method", "proven", "Target 0x0040D710 is `xor eax,eax; ret`.", "The exact inherited interface method name is unresolved."),
    ("one-return method with one stack argument", "proven", "Target 0x0044B310 is `mov eax,1; ret 4`.", "The exact inherited interface method name is unresolved."),
    ("one-return method", "proven", "Target 0x0040D700 is `mov eax,1; ret`.", "The exact inherited interface method name is unresolved."),
    ("primary HID handle getter", "proven", "Target 0x00413D90 returns the DWORD at object offset +0x04.", "Static object state only; no live handle was obtained."),
    ("primary HID handle close/reset", "proven", "Target 0x00413DA0 calls the CloseHandle import for +0x04 when nonzero and clears +0x04 and the connection word at +0x22.", "Cleanup path was not executed."),
    ("zero-return method with one stack argument", "proven", "Target 0x00414840 returns zero after its stack-cookie check and uses `ret 4`.", "The precise inherited interface name is unresolved."),
    ("stored-path/handle availability probe", "inferred", "Target 0x0040DEB0 tries CreateFileW on the stored path at +0x22 and closes that temporary handle; when no path is stored it calls helper 0x00590A20 with the primary handle.", "The helper's user-visible purpose and the returned state meaning are unresolved. No path or device was opened."),
    ("VID/PID equality check", "proven", "Target 0x00413D00 compares two supplied values with the object's 16-bit fields at +0x24C and +0x24E.", "This compares configured identifiers; it does not uniquely identify a physical model or revision."),
    ("zero-return method", "proven", "Target 0x0040D710 is `xor eax,eax; ret`.", "The exact inherited interface method name is unresolved."),
    ("one-return method", "proven", "Target 0x0040D700 is `mov eax,1; ret`.", "The exact inherited interface method name is unresolved."),
    ("zero-return method with two stack arguments", "proven", "Target 0x0043E950 is `xor eax,eax; ret 8`.", "The exact inherited interface method name is unresolved."),
    ("zero-return method with two stack arguments", "proven", "Target 0x0043E950 is `xor eax,eax; ret 8`.", "The exact inherited interface method name is unresolved."),
    ("zero-return method", "proven", "Target 0x0040D710 is `xor eax,eax; ret`.", "The exact inherited interface method name is unresolved."),
    ("zero-return method with two stack arguments", "proven", "Target 0x0043E950 is `xor eax,eax; ret 8`.", "The exact inherited interface method name is unresolved."),
    ("one-return method with one stack argument", "proven", "Target 0x0044B310 is `mov eax,1; ret 4`.", "The exact inherited interface method name is unresolved."),
    ("ApplySetting", "proven", "Target 0x00414930 contains the 0x14, 0x02, and 0x01 flag-gated matrix-information, LED-data, layer/macro/matrix paths and calls the shared RKKB writer at 0x00413F60.", "Static serializer reachability only. UI signal source, argument construction, payload field meanings, per-model gates, and firmware acceptance remain unresolved."),
    ("short parameter-frame writer (semantic name unresolved)", "inferred", "Target 0x00414080 returns early while object +0x238 is busy; otherwise it builds one of two short frames, including a `06 00` prefix on one branch, and calls 0x00413F60.", "The four argument meanings, frame schema, virtual callsites, UI origin, and firmware meaning are unresolved."),
    ("zero-return method with one stack argument", "proven", "Target 0x0040D720 is `xor eax,eax; ret 4`.", "The exact inherited interface method name is unresolved."),
    ("zero-return method with two stack arguments", "proven", "Target 0x0043E950 is `xor eax,eax; ret 8`.", "The exact inherited interface method name is unresolved."),
    ("zero-return method with four stack arguments", "proven", "Target 0x0040D740 is `xor eax,eax; ret 0x10`.", "The exact inherited interface method name is unresolved."),
    ("zero-return method with four stack arguments", "proven", "Target 0x0040D740 is `xor eax,eax; ret 0x10`.", "The exact inherited interface method name is unresolved."),
    ("cancel request signal", "proven", "Target 0x0040D750 sets object flag +0x28C when readiness field +0x288 is nonzero, then signals event +0x290 if present.", "Worker observation and user-visible cancellation meaning were not tested."),
    ("cancel reset signal", "proven", "Target 0x0040D780 clears +0x28C and signals event +0x290 if present.", "The matching worker/event lifecycle was not run."),
    ("cancel-state query", "proven", "Target 0x0040D7A0 returns the DWORD at object offset +0x28C.", "State meaning beyond the paired set/clear methods is unresolved."),
]


def read_va(pe: pefile.PE, data: bytes, va: int, size: int) -> bytes:
    offset = pe.get_offset_from_rva(va - pe.OPTIONAL_HEADER.ImageBase)
    return data[offset : offset + size]


def read_u32(pe: pefile.PE, data: bytes, va: int) -> int:
    raw = read_va(pe, data, va, 4)
    if len(raw) != 4:
        raise ValueError(f"truncated PE data at 0x{va:08X}")
    return int.from_bytes(raw, "little")


def read_c_string(pe: pefile.PE, data: bytes, va: int) -> str:
    return read_va(pe, data, va, 512).split(b"\0", 1)[0].decode("ascii", errors="replace")


def require_bytes(pe: pefile.PE, data: bytes, va: int, expected: bytes, label: str) -> None:
    actual = read_va(pe, data, va, len(expected))
    if actual != expected:
        raise SystemExit(f"{label} mismatch at 0x{va:08X}: got {actual.hex()}")


def validate_rtti_and_routes(pe: pefile.PE, data: bytes) -> None:
    col_va = read_u32(pe, data, VTABLE_VA - 4)
    signature = read_u32(pe, data, col_va)
    type_va = read_u32(pe, data, col_va + 12)
    if signature != 0 or read_c_string(pe, data, type_va + 8) != ".?AVCDevRKKB@@":
        raise SystemExit("vtable RTTI does not identify the expected x86 CDevRKKB class")

    constructor = read_va(pe, data, CONSTRUCTOR_SITE_VA, 6)
    if constructor[:2] != b"\xC7\x06" or int.from_bytes(constructor[2:], "little") != VTABLE_VA:
        raise SystemExit(f"constructor vtable install mismatch at 0x{CONSTRUCTOR_SITE_VA:08X}")

    signatures = [
        (0x004149B9, bytes.fromhex("f6 84 24 b8 10 00 00 14"), "ApplySetting mask 0x14 gate"),
        (0x00414B42, bytes.fromhex("f6 84 24 b8 10 00 00 02"), "ApplySetting mask 0x02 gate"),
        (0x00414C9B, bytes.fromhex("f6 84 24 b8 10 00 00 01"), "ApplySetting mask 0x01 gate"),
        (0x004149EA, bytes.fromhex("c6 84 24 a4 08 00 00 03 c6 84 24 a5 08 00 00 7e"), "matrix-information frame marker"),
        (0x00414B9F, bytes.fromhex("c6 84 24 a4 08 00 00 02 c6 84 24 a5 08 00 00 29"), "LED-data frame marker"),
        (0x00415174, bytes.fromhex("c6 44 24 18 04 c6 44 24 19 00"), "macro-staging prefix"),
    ]
    for va, expected, label in signatures:
        require_bytes(pe, data, va, expected, label)


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--driver",
        type=Path,
        default=root.parent / ".research" / "rk4_6_official_extract_20261015" / "app" / "DeviceDriver.exe",
    )
    parser.add_argument("--output", type=Path, default=root / "docs" / "rk-v4.6-cdevrkbb-vtable-map.csv")
    args = parser.parse_args()

    data = args.driver.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256:
        raise SystemExit(f"DeviceDriver.exe SHA-256 mismatch: {digest}")
    pe = pefile.PE(data=data, fast_load=False)
    if pe.OPTIONAL_HEADER.ImageBase != IMAGE_BASE:
        raise SystemExit(f"unexpected image base: 0x{pe.OPTIONAL_HEADER.ImageBase:08X}")
    validate_rtti_and_routes(pe, data)

    targets = [read_u32(pe, data, VTABLE_VA + slot * 4) for slot in range(len(EXPECTED_TARGETS))]
    if targets != EXPECTED_TARGETS:
        raise SystemExit("CDevRKKB vtable contents differ from the reviewed 26-slot ledger")
    for target in targets:
        section = pe.get_section_by_rva(target - IMAGE_BASE)
        if section is None or not section.IMAGE_SCN_MEM_EXECUTE:
            raise SystemExit(f"vtable target is not in an executable PE section: 0x{target:08X}")

    marker_va = VTABLE_VA + len(targets) * 4
    marker = read_va(pe, data, marker_va, 64).decode("utf-16le", errors="replace")
    if not marker.startswith("stream_unit.txt"):
        raise SystemExit(f"unexpected data after vtable extent at 0x{marker_va:08X}: {marker!r}")
    if len(ROWS) != len(targets):
        raise SystemExit("row count differs from vtable entry count")

    rows = [
        {
            "slot_index": index,
            "vtable_offset": f"+0x{index * 4:02X}",
            "entry_va": f"0x{VTABLE_VA + index * 4:08X}",
            "target_va": f"0x{target:08X}",
            "role": role,
            "status": status,
            "static_evidence": evidence,
            "scope_limit": limits,
        }
        for index, (target, (role, status, evidence, limits)) in enumerate(zip(targets, ROWS))
    ]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    counts = {key: sum(row["status"] == key for row in rows) for key in ("proven", "inferred", "unresolved")}
    print(f"verified SHA-256 {digest}; CDevRKKB RTTI, constructor install, and {len(rows)} slots")
    print(f"wrote {args.output}; proven={counts['proven']}, inferred={counts['inferred']}, unresolved={counts['unresolved']}")


if __name__ == "__main__":
    main()
