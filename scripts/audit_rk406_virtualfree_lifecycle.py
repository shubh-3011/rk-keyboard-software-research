#!/usr/bin/env python3
"""Verify the hash-pinned RK 4.06 VirtualFree reservation lifecycle evidence.

This verifier reads the PE image only. It checks the exact package hash,
relevant imports, selected instruction bytes, and direct relative-call targets,
then regenerates the row-level evidence ledger. It does not execute the binary.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import struct
from pathlib import Path

import pefile


EXPECTED_SHA256 = "c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6"
EXPECTED_SIZE = 2_326_528
IMAGE_BASE = 0x00400000

# Exact byte sequences are instruction-aligned facts copied from the selected
# objdump disassembly ranges. This ledger is evidence, not a complete CFG.
FACTS = [
    (0x0057939E, "8B FF", "hotpatch prologue", "Two-byte entry shim immediately precedes the helper prologue."),
    (0x005793A0, "55 8B EC 83 EC 10", "free helper entry", "Frame setup for the helper containing both VirtualFree calls."),
    (0x005795BC, "A1 70 98 60 00", "descriptor source", "Loads the active region descriptor pointer from global 0x00609870."),
    (0x005795CF, "8B 35 68 E2 59 00", "VirtualFree IAT load", "Loads ESI from VirtualFree IAT VA 0x0059E268."),
    (0x005795D5, "68 00 40 00 00", "decommit type", "Pushes 0x4000, the third stdcall argument: MEM_DECOMMIT."),
    (0x005795DA, "C1 E1 0F", "segment address index", "Shifts the segment index left by 15 bits (32 KiB)."),
    (0x005795DD, "03 48 0C", "segment base addition", "Adds descriptor field +0x0C, the stored VirtualAlloc reservation base."),
    (0x005795E0, "BB 00 80 00 00", "segment size", "Loads 0x8000 (32 KiB) for the decommit size."),
    (0x005795E5, "53", "decommit argument", "Pushes 32 KiB as VirtualFree dwSize."),
    (0x005795E6, "51", "decommit argument", "Pushes computed segment address as VirtualFree lpAddress."),
    (0x005795E7, "FF D6", "VirtualFree decommit call", "Calls the ESI function pointer loaded from the VirtualFree IAT."),
    (0x005795FB, "09 50 08", "segment bitmap update", "Sets the current segment bit in descriptor field +0x08 after decommit."),
    (0x00579636, "83 78 08 FF", "whole-region release gate", "Compares all 32 segment-state bits against 0xFFFFFFFF."),
    (0x0057963A, "75 65", "whole-region release branch", "Skips reservation release unless the descriptor bitmap is all ones."),
    (0x0057963C, "53", "release type argument", "Pushes preserved 0x8000, the third argument: MEM_RELEASE."),
    (0x0057963D, "6A 00", "release size argument", "Pushes zero as required for MEM_RELEASE."),
    (0x0057963F, "FF 70 0C", "release base argument", "Pushes the original reservation base from descriptor +0x0C."),
    (0x00579642, "FF D6", "VirtualFree release call", "Calls VirtualFree with (reservation base, 0, MEM_RELEASE)."),
    (0x00579644, "A1 70 98 60 00", "post-call continuation", "Overwrites EAX immediately; the VirtualFree return value is not checked here."),
    (0x00579654, "FF 15 C4 E2 59 00", "metadata cleanup", "Calls HeapFree after the full-reservation branch for descriptor +0x10 metadata."),
    (0x005796B3, "C3", "free helper return", "Return instruction at the end of the bounded helper body."),
    (0x00579704, "68 C4 41 00 00", "region metadata size", "Pushes 0x41C4 bytes for per-region HeapAlloc metadata."),
    (0x00579711, "FF 15 C8 E2 59 00", "region metadata allocation", "Calls HeapAlloc for the per-region metadata object."),
    (0x0057971E, "6A 04", "reservation protection", "Pushes PAGE_READWRITE (0x04) as VirtualAlloc's fourth argument."),
    (0x00579720, "68 00 20 00 00", "reservation type", "Pushes MEM_RESERVE (0x2000) as VirtualAlloc's third argument."),
    (0x00579725, "68 00 00 10 00", "reservation size", "Pushes 0x100000 (1 MiB) as VirtualAlloc's second argument."),
    (0x0057972A, "57", "reservation address", "Pushes null as VirtualAlloc's first argument."),
    (0x0057972B, "FF 15 90 E2 59 00", "VirtualAlloc reserve call", "Calls VirtualAlloc to reserve a 1 MiB region."),
    (0x00579731, "89 46 0C", "reservation base store", "Stores the returned reservation base in region descriptor +0x0C."),
    (0x0057974A, "83 4E 08 FF", "initial segment bitmap", "Initializes descriptor +0x08 to all ones before segment commits."),
    (0x00579764, "8B FF 55 8B EC", "commit helper entry", "Entry shim and frame setup for the segment-commit helper."),
    (0x005797A3, "6A 04", "commit protection", "Pushes PAGE_READWRITE (0x04) as VirtualAlloc's fourth argument."),
    (0x005797A7, "68 00 10 00 00", "commit type", "Pushes MEM_COMMIT (0x1000) as VirtualAlloc's third argument."),
    (0x005797AC, "C1 E7 0F", "committed segment address", "Computes segmentIndex * 32 KiB before adding the reservation base."),
    (0x005797AF, "03 79 0C", "committed segment base", "Adds descriptor +0x0C reservation base to the segment offset."),
    (0x005797B2, "68 00 80 00 00", "committed segment size", "Pushes 0x8000 (32 KiB) as VirtualAlloc dwSize."),
    (0x005797B7, "57", "committed segment address argument", "Pushes the computed segment base as VirtualAlloc lpAddress."),
    (0x005797B8, "FF 15 90 E2 59 00", "VirtualAlloc commit call", "Calls VirtualAlloc to commit the selected 32 KiB segment."),
    (0x00579862, "21 50 08", "active segment bitmap update", "Clears the selected segment bit after the commit helper succeeds."),
    (0x00579C0F, "E8 A0 FA FF FF", "descriptor growth caller", "Direct relative call target is 0x005796B4, descriptor-array growth."),
    (0x00579C25, "E8 3A FB FF FF", "segment commit caller", "Direct relative call target is 0x00579764, the segment-commit helper."),
    (0x0056E799, "E8 00 AC 00 00", "free helper caller", "Direct relative call target is 0x0057939E."),
    (0x00570C99, "E8 00 87 00 00", "free helper caller", "Direct relative call target is 0x0057939E."),
    (0x00570CE6, "E8 B3 86 00 00", "free helper caller", "Direct relative call target is 0x0057939E."),
]

IMPORTS = {
    "VirtualFree": 0x0059E268,
    "VirtualAlloc": 0x0059E290,
    "HeapReAlloc": 0x0059E2A4,
    "HeapFree": 0x0059E2C4,
    "HeapAlloc": 0x0059E2C8,
}


def normalized_name(value: bytes | str) -> str:
    if isinstance(value, bytes):
        value = value.decode("ascii", "replace")
    return value.rstrip("\x00")


def main() -> int:
    repo = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--binary",
        type=Path,
        default=repo.parent / "_rk_analysis" / "inputs" / "DeviceDriver.exe",
        help="hash-pinned installed 4.06 DeviceDriver.exe snapshot",
    )
    parser.add_argument(
        "--ledger",
        type=Path,
        default=repo / "docs" / "rk-406-virtualfree-reservation-lifecycle-evidence-2026-10-25.csv",
        help="output evidence ledger path",
    )
    args = parser.parse_args()

    data = args.binary.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256:
        parser.error(f"hash mismatch: expected {EXPECTED_SHA256}, got {digest}")
    if len(data) != EXPECTED_SIZE:
        parser.error(f"size mismatch: expected {EXPECTED_SIZE}, got {len(data)}")

    pe = pefile.PE(data=data, fast_load=False)
    if pe.FILE_HEADER.Machine != 0x14C or pe.OPTIONAL_HEADER.ImageBase != IMAGE_BASE:
        parser.error("unexpected PE architecture or image base")
    imported = {}
    for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = normalized_name(descriptor.dll).lower()
        for entry in descriptor.imports:
            if entry.name:
                imported[(dll, normalized_name(entry.name))] = entry.address
    for symbol, expected_va in IMPORTS.items():
        actual = imported.get(("kernel32.dll", symbol))
        if actual != expected_va:
            parser.error(f"unexpected {symbol} IAT VA: expected {expected_va:#010x}, got {actual!r}")

    verified = []
    for va, byte_text, role, fact in FACTS:
        expected = bytes.fromhex(byte_text)
        rva = va - pe.OPTIONAL_HEADER.ImageBase
        try:
            offset = pe.get_offset_from_rva(rva)
        except pefile.PEFormatError as exc:
            parser.error(f"VA {va:#010x} does not map to file data: {exc}")
        actual = data[offset : offset + len(expected)]
        if actual != expected:
            parser.error(
                f"byte mismatch at {va:#010x}: expected {expected.hex(' ')}, got {actual.hex(' ')}"
            )
        verified.append((va, expected.hex(" ").upper(), role, fact, offset))

    # Validate all relative-call targets in the ledger, not just their bytes.
    for va, raw, role, fact, _offset in verified:
        if role == "free helper caller":
            call = bytes.fromhex(raw)
            target = va + 5 + struct.unpack("<i", call[1:5])[0]
            if target != 0x0057939E:
                parser.error(f"unexpected free-helper call target at {va:#010x}: {target:#010x}")
        elif role == "descriptor growth caller":
            target = va + 5 + struct.unpack("<i", bytes.fromhex(raw)[1:5])[0]
            if target != 0x005796B4:
                parser.error(f"unexpected descriptor-growth target: {target:#010x}")
        elif role == "segment commit caller":
            target = va + 5 + struct.unpack("<i", bytes.fromhex(raw)[1:5])[0]
            if target != 0x00579764:
                parser.error(f"unexpected segment-commit target: {target:#010x}")

    iat_va = IMPORTS["VirtualFree"]
    needle = struct.pack("<I", iat_va)
    hits = []
    start = 0
    while True:
        pos = data.find(needle, start)
        if pos < 0:
            break
        hits.append(pos)
        start = pos + 1
    if len(hits) != 1:
        parser.error(f"expected one raw VirtualFree IAT DWORD occurrence, found {len(hits)}")
    hit_va = pe.OPTIONAL_HEADER.ImageBase + pe.get_rva_from_offset(hits[0])
    if hit_va != 0x005795D1:
        parser.error(f"unexpected raw IAT operand location: {hit_va:#010x}")

    args.ledger.parent.mkdir(parents=True, exist_ok=True)
    with args.ledger.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(["binary_sha256", "va", "raw_file_offset", "instruction_bytes", "evidence_role", "static_fact", "limit"])
        for va, raw, role, fact, offset in verified:
            writer.writerow([
                digest,
                f"0x{va:08X}",
                f"0x{offset:08X}",
                raw,
                role,
                fact,
                "Exact bytes verified; interpretation is static and does not prove execution or API success.",
            ])

    print(f"PASS: hash-pinned {len(data):,}-byte x86 PE verified ({digest}).")
    print(f"PASS: {len(IMPORTS)} relevant Kernel32 imports resolve to the documented IAT VAs.")
    print(f"PASS: {len(verified)} instruction/data facts and direct helper-call targets verified.")
    print("PASS: VirtualFree IAT address has one raw image occurrence at 0x005795D1.")
    print(f"Wrote evidence ledger: {args.ledger}")
    print("Limit: byte and import checks do not prove runtime reachability or API success.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
