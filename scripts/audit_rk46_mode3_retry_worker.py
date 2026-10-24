#!/usr/bin/env python3
"""Verify the pinned RK 4.06 updater's mode-3 retry-to-transfer path.

This is an offline, static PE-byte/import audit. It never launches the target,
opens a device interface, or sends a device report.

Run from the repository root with Python and pefile installed:

    python scripts/audit_rk46_mode3_retry_worker.py \
        --binary ".research/rk46-extract-full/app/Dev/01AF/Update.exe"
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import sys

import pefile


EXPECTED_SHA256 = "27894463b0dfe5bc3f5dc19d4d3351d9dfb692c402bf277bde3889d37e4a206c"
EXPECTED_SIZE = 2_109_952
IMAGE_BASE = 0x00400000

# Exact bytes at the virtual addresses named in the companion report. The
# tuples are (VA, expected hex bytes, evidence label). Facts intentionally
# cover branch gates and call edges rather than claiming whole-program CFG
# coverage.
BYTE_FACTS: tuple[tuple[int, str, str], ...] = (
    (0x0040A17D, "80be6c8e000000", "mode3-worker entry flag gate"),
    (0x0040A19B, "0f8590020000", "alternate entry when +0x8E6C is nonzero"),
    (0x0040A1A7, "bf07000000", "retry counter initialization"),
    (0x0040A1B2, "6808040000", "mode3 long feature length 0x408"),
    (0x0040A1B7, "83f903", "mode selector comparison"),
    (0x0040A1BC, "ba21100000", "mode3 PID 0x1021"),
    (0x0040A1C1, "b903060000", "mode3 VID 0x0603"),
    (0x0040A1C6, "e865c5ffff", "first long-interface search"),
    (0x0040A1CB, "ba21100000", "mode3 short-interface PID 0x1021"),
    (0x0040A1D0, "b903060000", "mode3 short-interface VID 0x0603"),
    (0x0040A1D5, "eb13", "short-interface search setup branch"),
    (0x0040A1ED, "a3145f5c00", "stores long handle global"),
    (0x0040A1F2, "e809c7ffff", "short-interface search"),
    (0x0040A1F7, "a3185f5c00", "stores short handle global"),
    (0x0040A1FC, "83f8ff", "short handle invalid sentinel comparison"),
    (0x0040A201, "833d145f5c00ff", "long handle invalid sentinel comparison"),
    (0x0040A208, "0f85d7000000", "both initial handles found branch"),
    (0x0040A27B, "68d0070000", "two-second delay argument"),
    (0x0040A280, "ffd3", "Sleep call through loaded import"),
    (0x0040A282, "6802080000", "fallback long feature length 0x802"),
    (0x0040A287, "ba20100000", "fallback PID 0x1020"),
    (0x0040A28C, "b903060000", "fallback VID 0x0603"),
    (0x0040A291, "e89ac4ffff", "fallback long-interface search"),
    (0x0040A2A3, "b903060000", "fallback short-interface VID 0x0603"),
    (0x0040A2A8, "e853c6ffff", "fallback short-interface search"),
    (0x0040A2AD, "a3185f5c00", "stores fallback short handle"),
    (0x0040A2B2, "83f8ff", "fallback short handle invalid sentinel comparison"),
    (0x0040A2B7, "833d145f5c00ff", "fallback long handle invalid sentinel comparison"),
    (0x0040A2BE, "0f85d1000000", "both fallback handles found branch"),
    (0x0040A2CA, "8bc7", "loads retry counter for post-decrement test"),
    (0x0040A2CC, "4f", "decrements retry counter"),
    (0x0040A2CD, "85c0", "tests pre-decrement retry value"),
    (0x0040A2CF, "0f84ec000000", "zero retry value exits to terminal status"),
    (0x0040A2D5, "a1786f5c00", "reloads selected VID before retry"),
    (0x0040A35A, "e801f4ffff", "status-probe call"),
    (0x0040A35F, "84c0", "tests status-probe result"),
    (0x0040A361, "0f8509020000", "nonzero probe result returns from worker"),
    (0x0040A367, "a10c5f5c00", "loads update mode after failed probe"),
    (0x0040A370, "83f803", "mode-3 fallback gate"),
    (0x0040A373, "0f85f7010000", "other nonzero modes return"),
    (0x0040A379, "68e8030000", "one-second fallback delay argument"),
    (0x0040A37E, "ffd3", "Sleep call before mode-switch helper"),
    (0x0040A382, "c6866e8e000000", "clears object transition flag"),
    (0x0040A389, "e8f2010000", "calls mode-switch/fallback helper"),
    (0x0040A399, "56", "passes dialog object as CreateThread parameter"),
    (0x0040A39A, "68d06b4000", "sets transfer worker start address"),
    (0x0040A3B4, "ff1580045600", "CreateThread IAT call from retry success"),
    (0x00409797, "66c70705c9", "status report begins with 05 C9"),
    (0x0040979C, "c6470260", "status report third byte is 60"),
    (0x004097A8, "ff15d8015600", "status report HidD_SetFeature call"),
    (0x004097BE, "c745fc05000000", "status-poll counter initialization"),
    (0x004097D0, "68e8030000", "one-second status-poll delay"),
    (0x0040980D, "ff15c8015600", "status HidD_GetFeature call"),
    (0x0040981F, "803e60", "checks response byte zero for 0x60"),
    (0x00409824, "8ac8", "loads response byte two"),
    (0x00409826, "84c9", "tests response byte two"),
    (0x00409828, "7452", "zero response byte branches to accepted-status path"),
    (0x00409888, "c605085f5c0001", "sets status gate after qualifying response"),
    (0x0040992D, "68206c4000", "sets secondary worker start address"),
    (0x0040993D, "ff1580045600", "CreateThread IAT call from status probe"),
    (0x0040A603, "6a06", "allocates six-byte transition report buffer"),
    (0x0040A610, "33c9", "zeros register used to seed fallback retry count"),
    (0x0040A63B, "c60005", "transition report byte zero is 0x05"),
    (0x0040A644, "c6400175", "transition report byte one is 0x75"),
    (0x0040A648, "388f6c8e0000", "mode-switch object-flag gate"),
    (0x0040A654, "8d5903", "seeds fallback-loop counter to three"),
    (0x0040A662, "833d0c5f5c0003", "mode-3 short-selector gate"),
    (0x0040A671, "80bf6f8e000001", "additional +0x8E6F selector gate"),
    (0x0040A67F, "b903060000", "special short selector VID 0x0603"),
    (0x0040A684, "e877c2ffff", "special 0x1021 short-interface search"),
    (0x0040A69F, "8b15746f5c00", "fallback short selector uses global PID"),
    (0x0040A6A5, "8b0d786f5c00", "fallback short selector uses global VID"),
    (0x0040A6AB, "e850c2ffff", "selected short-interface search"),
    (0x0040A74D, "ff351c5f5c00", "pushes discovered feature-report length"),
    (0x0040A75A, "ff15d8015600", "mode-switch HidD_SetFeature call"),
    (0x0040A760, "68b80b0000", "three-second fallback delay argument"),
    (0x0040A765, "ff1538035600", "Sleep IAT call after mode-switch report"),
    (0x0040A76B, "6802080000", "mode-switch fallback long length 0x802"),
    (0x0040A770, "ba20100000", "mode-switch fallback PID 0x1020"),
    (0x0040A775, "b903060000", "mode-switch fallback VID 0x0603"),
    (0x0040A77A, "e8b1bfffff", "mode-switch fallback long-interface search"),
    (0x0040A791, "e86ac1ffff", "mode-switch fallback short-interface search"),
    (0x0040A79B, "83f8ff", "mode-switch fallback short handle comparison"),
    (0x0040A7A0, "833d145f5c00ff", "mode-switch fallback long handle comparison"),
    (0x0040A7A7, "0f8586000000", "both mode-switch fallback handles found"),
    (0x0040A7AD, "8bc3", "loads local fallback-loop counter"),
    (0x0040A7AF, "4b", "decrements local fallback-loop counter"),
    (0x0040A7B0, "85c0", "tests pre-decrement fallback-loop value"),
    (0x0040A7B2, "0f85a8feffff", "fallback search loop edge"),
    (0x0040A838, "68d06b4000", "sets mode-switch transfer worker start address"),
    (0x0040A841, "ff1580045600", "CreateThread IAT call from mode-switch helper"),
    (0x00406C10, "e87b540000", "transfer worker calls dispatcher wrapper"),
    (0x0040C093, "8d8e60010000", "dispatcher wrapper passes object +0x160"),
    (0x0040C099, "e8a269ffff", "dispatcher wrapper calls section dispatcher"),
    (0x00402A51, "833d0c5f5c0003", "section dispatcher mode-3 branch"),
    (0x00402AB5, "5e", "mode-3 dispatch cleanup before section jump"),
    (0x00402AB6, "e925020000", "mode-3 C-section transfer edge"),
    (0x00403505, "ff15d8015600", "B-section HidD_SetFeature call"),
    (0x0040308C, "ff15c8015600", "B-section HidD_GetFeature verification call"),
    (0x004036BD, "ff15d8015600", "C-section HidD_SetFeature call"),
    (0x0040389C, "ff15c8015600", "C-section HidD_GetFeature verification call"),
)

EXPECTED_IMPORTS: dict[int, tuple[str, str]] = {
    0x005601C4: ("hid.dll", "hidp_getcaps"),
    0x005601C8: ("hid.dll", "hidd_getfeature"),
    0x005601D0: ("hid.dll", "hidd_getattributes"),
    0x005601D8: ("hid.dll", "hidd_setfeature"),
    0x005601DC: ("hid.dll", "hidd_getpreparseddata"),
    0x00560298: ("kernel32.dll", "createfilew"),
    0x005602CC: ("kernel32.dll", "readfile"),
    0x005602D0: ("kernel32.dll", "writefile"),
    0x00560338: ("kernel32.dll", "sleep"),
    0x00560480: ("kernel32.dll", "createthread"),
    0x005604E0: ("setupapi.dll", "setupdigetdeviceinterfacedetailw"),
    0x005604E8: ("setupapi.dll", "setupdienumdeviceinterfaces"),
    0x005604EC: ("setupapi.dll", "setupdigetclassdevsw"),
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True, help="hash-pinned Update.exe")
    args = parser.parse_args()

    data = args.binary.read_bytes()
    digest = sha256(data)
    require(len(data) == EXPECTED_SIZE, f"unexpected file size: {len(data)}")
    require(digest == EXPECTED_SHA256, f"unexpected SHA-256: {digest}")
    pe = pefile.PE(data=data, fast_load=False)
    require(pe.FILE_HEADER.Machine == 0x014C, "expected x86 PE machine 0x014C")
    require(pe.OPTIONAL_HEADER.ImageBase == IMAGE_BASE, "unexpected PE image base")

    def read_va(va: int, size: int) -> bytes:
        rva = va - IMAGE_BASE
        offset = pe.get_offset_from_rva(rva)
        require(0 <= offset <= len(data) - size,
                f"VA 0x{va:08X} does not map to {size} raw bytes")
        return data[offset:offset + size]

    for va, expected_hex, label in BYTE_FACTS:
        expected = bytes.fromhex(expected_hex)
        actual = read_va(va, len(expected))
        require(actual == expected,
                f"{label} at 0x{va:08X}: expected {expected.hex()}, got {actual.hex()}")

    imports: dict[int, tuple[str, str]] = {}
    for library in pe.DIRECTORY_ENTRY_IMPORT:
        dll = library.dll.decode("ascii", errors="replace").lower()
        for entry in library.imports:
            name = entry.name.decode("ascii", errors="replace").lower() if entry.name else f"ordinal_{entry.ordinal}"
            imports[entry.address] = (dll, name)
    for va, expected in EXPECTED_IMPORTS.items():
        actual = imports.get(va)
        require(actual == expected,
                f"IAT 0x{va:08X}: expected {expected!r}, got {actual!r}")

    print(
        f"Verified {len(BYTE_FACTS)} exact instruction-byte facts and "
        f"{len(EXPECTED_IMPORTS)} IAT mappings for {args.binary} "
        f"(size {len(data):,}, SHA-256 {digest}, x86 image base 0x{IMAGE_BASE:08X})."
    )
    print("Static bytes/imports only; updater execution and device behavior were not tested.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, pefile.PEFormatError, RuntimeError) as error:
        print(f"audit failed: {error}", file=sys.stderr)
        raise SystemExit(1)
