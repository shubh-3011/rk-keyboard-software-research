#!/usr/bin/env python3
"""Verify the installed updater's dongle-pairing checkbox dataflow statically.

This script reads a hash-pinned PE image and never launches it or accesses a
keyboard, receiver, serial port, or bootloader.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import sys

import pefile


EXPECTED_SHA256 = "27894463b0dfe5bc3f5dc19d4d3351d9dfb692c402bf277bde3889d37e4a206c"
IMAGE_BASE = 0x00400000
HANDLER_VA = 0x0040C2D0
GLOBAL_VA = 0x005C5F09
HANDLER_BYTES = bytes.fromhex(
    "6a00 6a00 68f0000000 ffb1948e0000 ff15ac085600 85c0 "
    "0f9505095f5c00 c3"
)
GLOBAL_OPERAND_OFFSET = 26


def default_binary() -> Path:
    repo_root = Path(__file__).resolve().parents[1]
    workspace_root = repo_root.parent
    return (
        workspace_root
        / ".research"
        / "rk4_6_official_extract_20261015"
        / "app"
        / "Dev"
        / "01AF"
        / "Update.exe"
    )


def occurrences(data: bytes, needle: bytes) -> list[int]:
    offsets: list[int] = []
    start = 0
    while True:
        offset = data.find(needle, start)
        if offset < 0:
            return offsets
        offsets.append(offset)
        start = offset + 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--binary",
        type=Path,
        default=default_binary(),
        help="hash-pinned installed Update.exe snapshot",
    )
    args = parser.parse_args()
    binary = args.binary.resolve()
    if not binary.is_file():
        parser.error(f"updater snapshot not found: {binary}")

    image = binary.read_bytes()
    digest = hashlib.sha256(image).hexdigest()
    if digest != EXPECTED_SHA256:
        parser.error(f"unexpected updater SHA-256: {digest}")

    pe = pefile.PE(data=image, fast_load=False)
    if pe.OPTIONAL_HEADER.Magic != 0x10B or pe.OPTIONAL_HEADER.ImageBase != IMAGE_BASE:
        parser.error("expected the pinned x86 PE32 image base 0x00400000")

    handler_rva = HANDLER_VA - IMAGE_BASE
    handler_file_offset = pe.get_offset_from_rva(handler_rva)
    actual_handler = image[handler_file_offset : handler_file_offset + len(HANDLER_BYTES)]
    if actual_handler != HANDLER_BYTES:
        parser.error(
            "the pinned handler bytes at 0x0040C2D0 differ from the audited sequence: "
            f"{actual_handler.hex(' ')}"
        )

    global_rva = GLOBAL_VA - IMAGE_BASE
    reference_bytes = GLOBAL_VA.to_bytes(4, "little")
    raw_references = occurrences(image, reference_bytes)
    expected_operand_offset = handler_file_offset + GLOBAL_OPERAND_OFFSET
    if raw_references != [expected_operand_offset]:
        parser.error(
            "expected the global address to occur once, as the handler's setne operand; "
            f"found file offsets {[hex(offset) for offset in raw_references]}"
        )

    section = pe.get_section_by_rva(global_rva)
    if section is None:
        parser.error("pairing flag global is not mapped by a PE section")
    section_name = section.Name.rstrip(b"\0").decode("ascii", errors="replace")
    section_delta = global_rva - section.VirtualAddress
    if section_delta < section.SizeOfRawData or section_delta >= section.Misc_VirtualSize:
        parser.error("pairing flag is not in the section's zero-filled virtual tail")

    print(f"Verified updater SHA-256: {digest}")
    print(
        f"Verified handler bytes: VA 0x{HANDLER_VA:08X}, "
        f"file offset 0x{handler_file_offset:X}"
    )
    print(
        f"Verified single direct address occurrence: VA 0x{GLOBAL_VA:08X}, "
        f"file offset 0x{expected_operand_offset:X} (handler operand)"
    )
    print(
        f"Verified global storage: {section_name} RVA 0x{global_rva:X}, "
        f"section offset 0x{section_delta:X}, beyond raw size 0x{section.SizeOfRawData:X}"
    )
    print("Static conclusion: one direct byte store is present; no second direct reference is present.")
    print("Scope limit: computed aliases or unobserved runtime behavior are not ruled out.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
