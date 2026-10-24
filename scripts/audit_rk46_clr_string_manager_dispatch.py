#!/usr/bin/env python3
"""Verify a bounded 4.6 CClrPanelDlg indirect-dispatch trace.

This static verifier checks a hash-pinned PE, the existing MFC map ledger,
the handler's selector and vtable call, the MSVC RTTI chain for the vtable,
and the called helper's exact bytes. It never launches the RK program or
accesses a keyboard or updater.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

import pefile


EXPECTED_SHA256 = "8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9"
IMAGE_BASE = 0x00400000


def file_offset(pe: pefile.PE, va: int) -> int:
    rva = va - int(pe.OPTIONAL_HEADER.ImageBase)
    for section in pe.sections:
        start = int(section.VirtualAddress)
        end = start + max(int(section.Misc_VirtualSize), int(section.SizeOfRawData))
        if start <= rva < end:
            return int(section.PointerToRawData) + rva - start
    raise ValueError(f"VA outside mapped sections: 0x{va:08X}")


def read_va(pe: pefile.PE, data: bytes, va: int, size: int) -> bytes:
    offset = file_offset(pe, va)
    value = data[offset : offset + size]
    if len(value) != size:
        raise ValueError(f"truncated read at 0x{va:08X}")
    return value


def u32(pe: pefile.PE, data: bytes, va: int) -> int:
    return struct.unpack("<I", read_va(pe, data, va, 4))[0]


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--binary",
        type=Path,
        default=root.parent / ".research" / "rk4_6_official_extract_20261015" / "app" / "DeviceDriver.exe",
    )
    parser.add_argument(
        "--message-map",
        type=Path,
        default=root / "docs" / "rk-v4.6-mfc-message-map-entries.csv",
    )
    args = parser.parse_args()

    data = args.binary.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256:
        parser.error(f"SHA-256 mismatch: expected {EXPECTED_SHA256}, got {digest}")
    pe = pefile.PE(data=data, fast_load=True)
    if int(pe.OPTIONAL_HEADER.ImageBase) != IMAGE_BASE or int(pe.FILE_HEADER.Machine) != 0x14C:
        parser.error("expected the hash-pinned PE32 x86 image at base 0x00400000")

    message_map = args.message_map.read_text(encoding="utf-8-sig")
    expected_row = (
        "0x004065D0,0x005D0AD8,0x005D0A00,.?AVCClrPanelDlg@@,6,"
        "0x005D0A90,0x0801,,0x00000000,0x00000000,0x00000000,0x0000000E,0x004065E0"
    )
    if expected_row not in message_map:
        raise SystemExit("CClrPanelDlg message 0x0801 map row not found")

    checks = {
        0x00406609: bytes.fromhex("8d 83 89 f7 ff ff 83 f8 02 77 7e"),
        0x0040662E: bytes.fromhex("8b 10 8b c8 8b 42 0c ff d0"),
        0x00477DED: bytes.fromhex("33 d2 8d 41 10 42 f0 0f c1 10 8d 41 04 c3"),
    }
    for va, expected in checks.items():
        actual = read_va(pe, data, va, len(expected))
        if actual != expected:
            raise SystemExit(f"byte mismatch at 0x{va:08X}: got {actual.hex(' ')}")

    vtable = 0x005A711C
    locator = u32(pe, data, vtable - 4)
    method = u32(pe, data, vtable + 0x0C)
    if locator != 0x005E4A38 or method != 0x00477DED:
        raise SystemExit("vtable locator or slot +0x0C target mismatch")
    type_descriptor = u32(pe, data, locator + 0x0C)
    type_name = read_va(pe, data, type_descriptor + 8, len(b".?AVCAfxStringMgr@@\0"))
    if type_name != b".?AVCAfxStringMgr@@\0":
        raise SystemExit(f"unexpected RTTI type descriptor: {type_name!r}")

    helper = read_va(pe, data, 0x00477DED, 14)
    print(f"Verified hash {digest}")
    print("Verified CClrPanelDlg message 0x0801 -> 0x004065E0 and selector range 0x0877..0x0879")
    print(f"Verified vtable 0x{vtable:08X} slot +0x0C -> 0x{method:08X} (RTTI CAfxStringMgr)")
    print(f"Verified helper bytes {helper.hex(' ')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
