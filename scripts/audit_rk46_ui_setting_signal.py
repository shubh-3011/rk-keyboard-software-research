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
    0x00418890: bytes.fromhex(
        "3d 84 00 00 00 7d 26 85 c0 7d 0a 8b 81 80 00 00 00 85 c0 7c 18 "
        "8d 04 c0 6a 01 89 94 81 ac 00 00 00 8b 41 20 6a 00 50 ff 15 44 67 5a 00 c3"
    ),
    0x0041ED44: bytes.fromhex(
        "8b 8d ac 21 00 00 e8 41 9b ff ff 83 3d 34 a2 62 00 00 74 0a "
        "6a 01 e8 a1 23 fe ff"
    ),
    0x0041F184: bytes.fromhex(
        "8b 89 ac 21 00 00 e8 01 97 ff ff 83 3d 34 a2 62 00 00 74 0a "
        "6a 01 e8 61 1f fe ff"
    ),
    0x0041ED62: bytes.fromhex("8b 15 fc a1 62 00 52 e8 32 20 04 00"),
    0x0041F1A2: bytes.fromhex("8b 15 fc a1 62 00 52 e8 f2 1b 04 00"),
    0x00460E0E: bytes.fromhex(
        "6a 00 68 80 00 00 00 6a 02 6a 00 6a 03 68 00 00 00 c0 "
        "8d 54 24 20 52 ff 15 74 64 5a 00"
    ),
    0x00460E92: bytes.fromhex(
        "6a 00 8d 54 24 10 52 68 14 5f 00 00 50 57 c7 44 24 20 "
        "00 00 00 00 ff d3"
    ),
    0x00456573: bytes.fromhex("8b 2d e0 63 5a 00"),
    0x0045669F: bytes.fromhex(
        "8d 8c 24 70 05 00 00 51 6a 00 68 24 fc 5d 00 68 44 00 5d 00 ff d5"
    ),
    0x004566C9: bytes.fromhex("a3 34 a2 62 00"),
    0x0045654D: bytes.fromhex(
        "68 8c fb 5d 00 68 b8 54 63 00 68 88 02 5d 00"
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
    parser.add_argument("--config", type=Path)
    args = parser.parse_args()

    data = args.driver.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256:
        raise SystemExit(f"DeviceDriver.exe SHA-256 mismatch: {digest}")
    pe = pefile.PE(data=data, fast_load=False)
    if pe.OPTIONAL_HEADER.ImageBase != 0x00400000:
        raise SystemExit("unexpected PE image base")

    for va, expected in EXPECTED.items():
        actual = read_va(pe, data, va, len(expected))
        if actual != expected:
            raise SystemExit(f"instruction bytes differ at 0x{va:08X}")

    for va, expected in (
        (0x005DC1E8, "tc_restore"),
        (0x005DC220, "tc_apply"),
        (0x005DFC24, "ApplyNow"),
        (0x005D0044, "OPT"),
        (0x005DFB8C, "cfg.ini"),
        (0x005D0288, "%s%s"),
        (0x005CFD8C, "%s%04X\\%s"),
        (0x005E1814, "pro.dct"),
    ):
        actual = read_utf16z(pe, data, va)
        if actual != expected:
            raise SystemExit(f"expected UTF-16 {expected!r} at 0x{va:08X}, got {actual!r}")

    has_profile_int = any(
        entry.dll.lower() == b"kernel32.dll"
        and imp.name == b"GetPrivateProfileIntW"
        and imp.address == 0x005A63E0
        for entry in pe.DIRECTORY_ENTRY_IMPORT
        for imp in entry.imports
    )
    if not has_profile_int:
        raise SystemExit("KERNEL32!GetPrivateProfileIntW import not found at 0x005A63E0")

    has_invalidate_rect = any(
        entry.dll.lower() == b"user32.dll"
        and imp.name == b"InvalidateRect"
        and imp.address == 0x005A6744
        for entry in pe.DIRECTORY_ENTRY_IMPORT
        for imp in entry.imports
    )
    if not has_invalidate_rect:
        raise SystemExit("USER32!InvalidateRect import not found at 0x005A6744")

    expected_file_apis = {
        (b"CreateFileW", 0x005A6474),
        (b"WriteFile", 0x005A646C),
    }
    found_file_apis = {
        (imp.name, imp.address)
        for entry in pe.DIRECTORY_ENTRY_IMPORT
        if entry.dll.lower() == b"kernel32.dll"
        for imp in entry.imports
    }
    if not expected_file_apis <= found_file_apis:
        raise SystemExit("KERNEL32!CreateFileW/WriteFile imports do not match expected IATs")

    config_path = args.config or args.driver.with_name("Cfg.ini")
    config_data = config_path.read_bytes()
    config_digest = hashlib.sha256(config_data).hexdigest()
    expected_config_digest = "ab9c84bb951bcfec99e18e0c6a77ece913e14376265c33276e3b176c030b6cc5"
    if config_digest != expected_config_digest:
        raise SystemExit(f"Cfg.ini SHA-256 mismatch: {config_digest}")
    config_text = config_data.decode("utf-16")
    section = ""
    apply_now = None
    for line in config_text.splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().casefold()
        elif section == "opt" and "=" in line:
            key, value = line.split("=", 1)
            if key.strip().casefold() == "applynow":
                apply_now = value.strip()
    if apply_now != "1":
        raise SystemExit(f"expected packaged [OPT] ApplyNow=1, got {apply_now!r}")

    print(
        f"Verified {len(EXPECTED)} code slices, UI/config strings, API imports, and Cfg.ini."
    )
    print(f"DeviceDriver.exe SHA-256: {digest}")
    print(f"Cfg.ini SHA-256: {config_digest} ([OPT] ApplyNow={apply_now})")


if __name__ == "__main__":
    main()
