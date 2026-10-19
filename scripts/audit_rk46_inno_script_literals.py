#!/usr/bin/env python3
"""Search the hash-pinned RK 4.6 setup bytes for known script identifiers.

This is a bounded literal-string screen. It does not parse Inno Setup's
compiled script format and a miss does not prove that callback code is absent.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


EXPECTED_SHA256 = "47A1FC21C3AF548B93FA40D499584ABECB3341E62B15948AE537B78CA987AAD8"
NEEDLES = (
    "InitializeSetup",
    "InitializeUninstall",
    "MyAfterInstall",
    "MyAfterInstall2",
    "CurUninstallStepChanged",
    "InitializeUninstallProgressForm",
    "SetupInit",
    "LangIndex",
    "RK Keyboard",
    "RK RGB Keyboard",
    "RKKB",
)


def offsets(haystack: bytes, needle: bytes) -> list[int]:
    """Return all byte offsets, case-insensitively, for an ASCII needle."""
    haystack = haystack.lower()
    needle = needle.lower()
    found: list[int] = []
    start = 0
    while (offset := haystack.find(needle, start)) >= 0:
        found.append(offset)
        start = offset + 1
    return found


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("setup", type=Path, help="official RK 4.6 setup executable")
    args = parser.parse_args()

    data = args.setup.read_bytes()
    digest = hashlib.sha256(data).hexdigest().upper()
    print(f"size_bytes={len(data)}")
    print(f"sha256={digest}")
    if digest != EXPECTED_SHA256:
        parser.error("input hash does not match the documented RK 4.6 setup")

    for text in NEEDLES:
        variants = (
            ("ascii", text.encode("ascii")),
            ("utf16le", text.encode("utf-16le")),
        )
        for encoding, needle in variants:
            locations = offsets(data, needle)
            rendered = ",".join(f"0x{offset:X}" for offset in locations) or "none"
            print(f"{encoding}\t{text}\t{rendered}")


if __name__ == "__main__":
    main()
