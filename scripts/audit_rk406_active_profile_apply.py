#!/usr/bin/env python3
"""Verify the conditional RK 4.06 active-profile Apply dispatch statically.

Reads a hash-pinned PE and the source-free installed profile-family map. It
does not launch RK software or access a keyboard.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
from pathlib import Path

import pefile


EXPECTED_SHA256 = "c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6"
IMAGE_BASE = 0x00400000
ACTIVE_ROOT = 0x0062B380
G5_VTABLE = 0x005CBA2C
G5_APPLY_TARGET = 0x00411B90
S98_CODES = {"0174", "01AF", "01BF", "0223", "0224", "022B", "022F", "0230"}

BYTE_ANCHORS = {
    0x004011E6: "a180b3620085c07405833800752a",
    0x0040128E: "8b168b523c6a0050a188b362005157508bceffd2",
    0x00446617: "33c0663b450a751e",
    0x00446630: "8bf0e869c9fcff",
    0x0044663D: "68e0020000e8bf920200",
    0x0044665D: "50e84d86fcff",
    0x004466B9: "893d80b36200",
    0x004466C1: "33d2e868310100a380b36200",
    0x00465BC1: "893580b36200",
    0x00465E13: "a380b36200",
    0x0044792A: "891d80b36200",
}

# Every decoded .text instruction with a direct absolute operand for the
# active-root global 0x0062B380 in this pinned build. Distinct data globals at
# 0x0062B384 and 0x0062B388 are intentionally excluded.
ACTIVE_ROOT_REFERENCES = {
    0x0040109A: "a180b36200",
    0x004011E6: "a180b3620085c07405833800752a",
    0x0040354D: "a180b36200",
    0x00403660: "a180b36200",
    0x004038B4: "a180b36200",
    0x00404387: "a180b36200",
    0x0040B601: "393580b36200",
    0x0040B7C1: "8b3580b36200",
    0x0042251B: "8b3d80b36200",
    0x00422720: "a180b36200",
    0x004228BF: "a180b36200",
    0x00439217: "8b3580b36200",
    0x00439C54: "8b3d80b36200",
    0x004466B9: "893d80b36200",
    0x004466C8: "a380b36200",
    0x004477DC: "a180b36200",
    0x0044792A: "891d80b36200",
    0x00457079: "a180b36200",
    0x00458D46: "a180b36200",
    0x004593F5: "a180b36200",
    0x00465568: "8b0d80b36200",
    0x00465BC1: "893580b36200",
    0x00465E13: "a380b36200",
    0x00466471: "8b3d80b36200",
    0x004667D2: "a180b36200",
    0x0046D3AE: "a180b36200",
}


def read_va(pe: pefile.PE, image: bytes, va: int, size: int) -> bytes:
    if pe.OPTIONAL_HEADER.ImageBase != IMAGE_BASE:
        raise ValueError("expected x86 image base 0x00400000")
    offset = pe.get_offset_from_rva(va - IMAGE_BASE)
    result = image[offset : offset + size]
    if len(result) != size:
        raise ValueError(f"truncated image at VA 0x{va:08X}")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path, help="installed 4.06 DeviceDriver.exe")
    parser.add_argument(
        "--profile-map",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "docs" / "rk-profile-driver-family-map.csv",
        help="source-free profile-to-family CSV",
    )
    args = parser.parse_args()
    binary = args.binary.resolve()
    if not binary.is_file():
        parser.error(f"PE not found: {binary}")

    image = binary.read_bytes()
    digest = hashlib.sha256(image).hexdigest()
    if digest != EXPECTED_SHA256:
        parser.error(f"unexpected DeviceDriver.exe SHA-256: {digest}")
    pe = pefile.PE(data=image, fast_load=False)
    if pe.FILE_HEADER.Machine != 0x14C or pe.OPTIONAL_HEADER.Magic != 0x10B:
        parser.error("expected a 32-bit x86 PE32 image")

    for va, expected_hex in BYTE_ANCHORS.items():
        expected = bytes.fromhex(expected_hex)
        actual = read_va(pe, image, va, len(expected))
        if actual != expected:
            parser.error(
                f"bytes differ at VA 0x{va:08X}: expected {expected.hex(' ')}, "
                f"got {actual.hex(' ')}"
            )

    for va, expected_hex in ACTIVE_ROOT_REFERENCES.items():
        expected = bytes.fromhex(expected_hex)
        actual = read_va(pe, image, va, len(expected))
        if actual != expected:
            parser.error(
                f"active-root reference differs at VA 0x{va:08X}: "
                f"expected {expected.hex(' ')}, got {actual.hex(' ')}"
            )

    slot_va = G5_VTABLE + 0x3C
    slot_target = int.from_bytes(read_va(pe, image, slot_va, 4), "little")
    if slot_target != G5_APPLY_TARGET:
        parser.error(
            f"CDevG5KB vtable +0x3C expected 0x{G5_APPLY_TARGET:08X}, "
            f"got 0x{slot_target:08X}"
        )

    with args.profile_map.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = {row["profile_code"].upper(): row for row in csv.DictReader(handle)}
    missing = S98_CODES - rows.keys()
    if missing:
        parser.error(f"S98 profile rows are missing from the map: {sorted(missing)}")
    invalid = {
        code: (rows[code]["fw_raw"], rows[code]["static_handler"])
        for code in sorted(S98_CODES)
        if rows[code]["fw_raw"] != "1" or rows[code]["static_handler"] != "CDevG5KB"
    }
    if invalid:
        parser.error(f"S98 profile-to-family rows changed: {invalid}")

    print(f"Verified DeviceDriver.exe SHA-256: {digest}")
    print(f"Verified {len(BYTE_ANCHORS)} constructor, worker, and active-root byte anchors.")
    print(f"Verified the {len(ACTIVE_ROOT_REFERENCES)} listed direct active-root reference instructions.")
    print(f"Verified CDevG5KB vtable +0x3C -> 0x{slot_target:08X}.")
    print(f"Verified {len(S98_CODES)} S98 profile rows select the static CDevG5KB branch.")
    print("This is a conditional static route; runtime active profile and device behavior remain unobserved.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
