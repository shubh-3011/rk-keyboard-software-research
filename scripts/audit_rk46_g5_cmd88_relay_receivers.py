#!/usr/bin/env python3
"""Verify the hash-pinned V4.6 command-0x88 relay receiver evidence.

This script reads a PE file only. It does not execute the image or interact
with HID, a keyboard, an updater, or a bootloader.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from pathlib import Path

import capstone
import pefile
from capstone.x86 import X86_OP_IMM

EXPECTED_SIZE = 2_418_176
EXPECTED_SHA256 = "8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9"
IMAGE_BASE = 0x00400000
RELAY = 0x004EDD8D
CALLERS = {
    0x004A5521: bytes.fromhex("E8 67 88 04 00"),
    0x004A587F: bytes.fromhex("E8 09 85 04 00"),
    0x004A5CD6: bytes.fromhex("E8 B2 80 04 00"),
    0x004A64D5: bytes.fromhex("E8 B3 78 04 00"),
    0x004A700B: bytes.fromhex("E8 7D 6D 04 00"),
    0x004A90B7: bytes.fromhex("E8 D1 4C 04 00"),
    0x004A9316: bytes.fromhex("E8 72 4A 04 00"),
    0x004A9952: bytes.fromhex("E8 36 44 04 00"),
}
ENTRY_GUARDS = {
    0x004A54DE: bytes.fromhex("8B FF 55 8B EC 51 51 53"),
    0x004A585D: bytes.fromhex("8B FF 55 8B EC 51"),
    0x004A5B8E: bytes.fromhex("8B FF 55 8B EC 83 EC 10"),
    0x004A63D5: bytes.fromhex("8B FF 55 8B EC 83 EC 34"),
    0x004A6D8F: bytes.fromhex("8B FF 55 8B EC 83 EC 28"),
    0x004A8FB6: bytes.fromhex("68 94 00 00 00 B8 7E 34 59 00 E8 22 F2 0C 00"),
    0x004A9230: bytes.fromhex("68 9C 00 00 00 B8 C7 34 59 00 E8 A8 EF 0C 00"),
    0x004A95B2: bytes.fromhex("6A 7C B8 03 35 59 00 E8 F6 EB 0C 00"),
    0x004EE952: bytes.fromhex("6A 00 B8 E6 7B 59 00 E8 56 98 08 00 8B F1"),
}
BYTE_GUARDS = {
    0x004EDD8D: bytes.fromhex("8D 81 38 01 00 00 83 38 00 74 09 8B 00 8B 10 8B C8 FF 62 70 33 C0 C3"),
    0x004EDC52: bytes.fromhex("89 9E 38 01 00 00"),
    0x004EE106: bytes.fromhex("C7 06 64 4F 5B 00"),
    0x004EE9C3: bytes.fromhex("68 90 B5 5B 00 E8 EE D5 F9 FF"),
    0x004EE9D6: bytes.fromhex("89 86 38 01 00 00"),
    0x00518AEC: bytes.fromhex("6A 04 B8 2F 93 59 00 E8 BC F6 05 00 8B F1"),
    0x00518B02: bytes.fromhex("C7 06 B4 B5 5B 00"),
    0x00411030: bytes.fromhex("83 B9 38 02 00 00 00 74 05 33 C0 C2 08 00"),
}
DWORD_GUARDS = {
    0x005B4F40: 0x005B4F30,  # CPaneDivider name pointer
    0x005B4F44: 0x0000013C,  # size
    0x005B4F4C: 0x004EE783,  # creator
    0x005B4F50: 0x005B8DB4,  # CBasePane base
    0x005B51E4: 0x004EE952,  # CPaneDivider vtable +0x280
    0x005BB590: 0x005BB578,  # CPaneContainerManager name pointer
    0x005BB594: 0x00000050,  # size
    0x005BB59C: 0x005194AA,  # creator
    0x005BB624: 0x00518C91,  # manager vtable +0x70
    0x005D3D7C: 0x00411030,  # G5 vtable +0x70
}
STRING_GUARDS = {
    0x005B4F30: b"CPaneDivider",
    0x005BB578: b"CPaneContainerManager",
}


def fail(message: str) -> None:
    raise ValueError(message)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path, help="Hash-pinned V4.6 DeviceDriver.exe")
    args = parser.parse_args()

    data = args.image.resolve().read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if len(data) != EXPECTED_SIZE or digest != EXPECTED_SHA256:
        print(
            f"Refusing unexpected PE: size={len(data)} sha256={digest}; "
            f"expected size={EXPECTED_SIZE} sha256={EXPECTED_SHA256}",
            file=sys.stderr,
        )
        return 2

    pe = pefile.PE(data=data, fast_load=False)
    if int(pe.FILE_HEADER.Machine) != 0x014C or int(pe.OPTIONAL_HEADER.Magic) != 0x010B:
        print("Refusing unexpected architecture; expected x86 PE32", file=sys.stderr)
        return 2
    if int(pe.OPTIONAL_HEADER.ImageBase) != IMAGE_BASE:
        print("Refusing unexpected preferred image base", file=sys.stderr)
        return 2

    def file_offset(va: int) -> int:
        return int(pe.get_offset_from_rva(va - IMAGE_BASE))

    def read_va(va: int, length: int) -> bytes:
        offset = file_offset(va)
        return data[offset : offset + length]

    def read_u32(va: int) -> int:
        return struct.unpack("<I", read_va(va, 4))[0]

    for va, expected in ENTRY_GUARDS.items():
        actual = read_va(va, len(expected))
        if actual != expected:
            fail(f"entry guard mismatch at 0x{va:08X}: {actual.hex(' ')}")
    for va, expected in BYTE_GUARDS.items():
        actual = read_va(va, len(expected))
        if actual != expected:
            fail(f"byte guard mismatch at 0x{va:08X}: {actual.hex(' ')}")
    for va, expected in DWORD_GUARDS.items():
        actual = read_u32(va)
        if actual != expected:
            fail(f"dword mismatch at 0x{va:08X}: 0x{actual:08X}")
    for va, expected in STRING_GUARDS.items():
        actual = read_va(va, len(expected) + 1)
        if actual != expected + b"\0":
            fail(f"runtime-class name mismatch at 0x{va:08X}: {actual!r}")

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    md.skipdata = True
    direct_calls: list[int] = []
    for section in pe.sections:
        if not int(section.Characteristics) & 0x20000000:
            continue
        start = IMAGE_BASE + int(section.VirtualAddress)
        for instruction in md.disasm(bytes(section.get_data()), start):
            if (
                instruction.mnemonic == "call"
                and instruction.operands
                and instruction.operands[0].type == X86_OP_IMM
                and int(instruction.operands[0].imm) == RELAY
            ):
                direct_calls.append(int(instruction.address))

    if sorted(direct_calls) != sorted(CALLERS):
        fail(
            "direct-call census mismatch: "
            + ", ".join(f"0x{x:08X}" for x in sorted(direct_calls))
        )
    for va, expected in CALLERS.items():
        actual = read_va(va, len(expected))
        if actual != expected:
            fail(f"caller bytes mismatch at 0x{va:08X}: {actual.hex(' ')}")

    print(
        "OK: pinned V4.6 PE, 8 direct relay callers, separate caller frame "
        "starts, CPaneDivider +0x138 initialization/type assignment, "
        "CPaneContainerManager slot +0x70, and G5 wrapper slot +0x70 verified."
    )
    print(f"SHA-256: {digest}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, pefile.PEFormatError, ValueError) as exc:
        print(f"verification failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
