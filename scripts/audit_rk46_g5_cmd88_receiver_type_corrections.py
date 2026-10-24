#!/usr/bin/env python3
"""Verify the hash-pinned V4.6 command-0x88 receiver-type corrections.

The script reads a PE image only. It does not execute the image or interact
with a keyboard, HID interface, updater, or bootloader.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import struct
import sys
from pathlib import Path

import pefile

EXPECTED_SIZE = 2_418_176
EXPECTED_SHA256 = "8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9"
IMAGE_BASE = 0x00400000
OUTPUT = Path("docs/rk-v4.6-g5-command88-receiver-type-corrections-evidence-2026-10-25.csv")

GUARDS = {
    0x004A5C9E: bytes.fromhex("BE 40 4F 5B 00"),
    0x004A5CC7: bytes.fromhex("53 56 E8 ED 62 FE FF"),
    0x004A5CD0: bytes.fromhex("85 C0 74 30 8B C8 E8 B2 80 04 00"),
    0x004FCB2B: bytes.fromhex(
        "FF B1 1C 03 00 00 E8 9F FF F7 FF 50 68 40 4F 5B 00 "
        "E8 7A F4 F8 FF 59 59 C3"
    ),
    0x004A8052: bytes.fromhex("6A 01 53 8B CF E8 79 E3 FF FF"),
    0x004FE0B9: bytes.fromhex("E8 6D EA FF FF 50 8B CF E8 0F 83 FA FF"),
    0x004A641E: bytes.fromhex("83 7D 0C 00 89 45 F0 0F 84 A8 00 00 00"),
    0x004A64D3: bytes.fromhex("8B CE E8 B3 78 04 00"),
    0x004A63DF: bytes.fromhex("8B 75 08"),
}

EXPECTED_CALLS = {
    0x004A5CD6: 0x004EDD8D,
    0x004A8057: 0x004A63D5,
    0x004FE0C1: 0x004A63D5,
}


def fail(message: str) -> None:
    raise ValueError(message)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path, help="Hash-pinned V4.6 DeviceDriver.exe")
    parser.add_argument("--output", type=Path, default=OUTPUT, help="Evidence CSV output")
    parser.add_argument("--overwrite", action="store_true", help="Replace the evidence CSV")
    args = parser.parse_args()

    data = args.image.resolve().read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if len(data) != EXPECTED_SIZE or digest != EXPECTED_SHA256:
        fail(f"unexpected PE size/hash: size={len(data)} sha256={digest}")

    pe = pefile.PE(data=data, fast_load=False)
    if int(pe.FILE_HEADER.Machine) != 0x014C or int(pe.OPTIONAL_HEADER.Magic) != 0x010B:
        fail("expected x86 PE32")
    if int(pe.OPTIONAL_HEADER.ImageBase) != IMAGE_BASE:
        fail("unexpected preferred image base")

    def get_bytes(va: int, size: int) -> bytes:
        offset = int(pe.get_offset_from_rva(va - IMAGE_BASE))
        return data[offset : offset + size]

    for va, expected in GUARDS.items():
        actual = get_bytes(va, len(expected))
        if actual != expected:
            fail(f"byte guard mismatch at {va:#010x}: {actual.hex(' ')}")

    for call_va, expected_target in EXPECTED_CALLS.items():
        raw = get_bytes(call_va, 5)
        if raw[0] != 0xE8:
            fail(f"expected relative call at {call_va:#010x}")
        displacement = struct.unpack("<i", raw[1:])[0]
        target = call_va + 5 + displacement
        if target != expected_target:
            fail(f"call at {call_va:#010x} targets {target:#010x}, expected {expected_target:#010x}")

    output = args.output.resolve()
    if output.exists() and not args.overwrite:
        fail(f"refusing to replace existing evidence CSV: {output}; pass --overwrite")
    output.parent.mkdir(parents=True, exist_ok=True)
    rows = [
        ("1", "0x004A5C9E", "BE 40 4F 5B 00", "Loads runtime-class descriptor 0x005B4F40 before the second branch's type filter.", "proven static"),
        ("2", "0x004A5CC7", "53 56 E8 ED 62 FE FF", "Passes the candidate and CPaneDivider descriptor to runtime-class filter 0x0048BFBB.", "proven static"),
        ("3", "0x004A5CD0", "85 C0 74 30 8B C8 E8 B2 80 04 00", "On non-null filtered pointer, moves it into ECX and calls relay 0x004EDD8D at 0x004A5CD6.", "proven static"),
        ("4", "0x004FCB2B", "FF B1 1C 03 00 00 E8 9F FF F7 FF 50 68 40 4F 5B 00 E8 7A F4 F8 FF 59 59 C3", "Returns the accessor result only through the CPaneDivider runtime-class filter.", "proven static"),
        ("5", "0x004A8052", "6A 01 53 8B CF E8 79 E3 FF FF", "Direct caller passes arg1 from the filtered helper and literal 1 as arg2; this skips the callee's zero-only relay branch.", "proven static"),
        ("6", "0x004FE0B9", "E8 6D EA FF FF 50 8B CF E8 0F 83 FA FF", "Direct caller pushes the filtered CPaneDivider pointer as arg1; arg2 is not explicitly pushed here.", "proven static"),
        ("7", "0x004A641E", "83 7D 0C 00 89 45 F0 0F 84 A8 00 00 00", "The relay path in 0x004A63D5 is gated on arg2 being zero.", "proven static"),
        ("8", "0x004A64D3", "8B CE E8 B3 78 04 00", "The zero branch passes the caller-provided arg1 in ESI as the relay receiver.", "proven static"),
        ("9", "0x004A63DF", "8B 75 08", "The function saves arg1 into ESI, the receiver later forwarded at 0x004A64D3.", "proven static"),
    ]
    with output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(("evidence_id", "va", "bytes", "claim", "classification"))
        writer.writerows(rows)

    print("PASS: pinned V4.6 PE, CPaneDivider filter before 0x004A5CD6, and both direct callers/branch gates for 0x004A64D5 verified.")
    print(f"SHA-256: {digest}")
    print(f"Evidence rows written: {len(rows)} -> {output}")
    print("Scope limit: static caller paths only; computed callers, branch execution, and runtime virtual targets are unresolved.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, pefile.PEFormatError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
