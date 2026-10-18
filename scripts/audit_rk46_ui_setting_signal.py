#!/usr/bin/env python3
"""Check the hash-pinned V4.6 Apply/Restore UI-to-queue static evidence.

Reads DeviceDriver.exe as PE bytes only. It does not run RK software, open a
device interface, send a report, or modify the keyboard.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

import pefile


EXPECTED_SHA256 = "8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9"
EXPECTED = {
    0x0040A833: bytes.fromhex(
        "8d b5 54 1c 00 00 b8 44 74 64 00 8b fe 8b cd e8 69 78 04 00"
    ),
    0x0040A88A: bytes.fromhex(
        "8d bd d8 1d 00 00 b8 50 74 64 00 8b cd e8 14 78 04 00"
    ),
    0x004445EE: bytes.fromhex(
        "b9 44 74 64 00 c7 44 24 70 0b 00 00 00 e8 20 15 fc ff"
    ),
    0x00444741: bytes.fromhex(
        "b9 50 74 64 00 c7 44 24 70 11 00 00 00 e8 cd 13 fc ff"
    ),
    0x0040AC7D: bytes.fromhex(
        "8d 87 54 1c 00 00 85 c0 74 03 8b 40 20 3b d0 0f 84 1b 06 00 00"
    ),
    0x0040AC92: bytes.fromhex(
        "8d 87 d8 1d 00 00 85 c0 74 03 8b 40 20 3b d0 0f 84 06 06 00 00"
    ),
    0x0040B2AD: bytes.fromhex(
        "8b f7 e8 8c 05 00 00 83 3d 34 a2 62 00 00 74 0a 6a 01 e8 3c 5e ff ff"
    ),
}


def read_va(pe: pefile.PE, data: bytes, va: int, size: int) -> bytes:
    offset = pe.get_offset_from_rva(va - pe.OPTIONAL_HEADER.ImageBase)
    return data[offset : offset + size]


def read_utf16z(pe: pefile.PE, data: bytes, va: int) -> str:
    raw = read_va(pe, data, va, 256)
    end = next(
        (i for i in range(0, len(raw) - 1, 2) if raw[i : i + 2] == b"\0\0"),
        len(raw),
    )
    return raw[:end].decode("utf-16le")


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--driver",
        type=Path,
        default=root.parent
        / ".research"
        / "rk4_6_official_extract_20261015"
        / "app"
        / "DeviceDriver.exe",
    )
    args = parser.parse_args()

    data = args.driver.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256:
        raise SystemExit(f"DeviceDriver.exe SHA-256 mismatch: {digest}")
    pe = pefile.PE(data=data, fast_load=True)
    if pe.OPTIONAL_HEADER.ImageBase != 0x00400000:
        raise SystemExit("unexpected PE image base")

    for va, expected in EXPECTED.items():
        actual = read_va(pe, data, va, len(expected))
        if actual != expected:
            raise SystemExit(f"instruction bytes differ at 0x{va:08X}")

    for va, expected in ((0x005DC1E8, "tc_restore"), (0x005DC220, "tc_apply")):
        actual = read_utf16z(pe, data, va)
        if actual != expected:
            raise SystemExit(f"expected UTF-16 {expected!r} at 0x{va:08X}, got {actual!r}")

    print(f"Verified {len(EXPECTED)} code slices and both localization keys.")
    print(f"DeviceDriver.exe SHA-256: {digest}")


if __name__ == "__main__":
    main()
