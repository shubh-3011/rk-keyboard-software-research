#!/usr/bin/env python3
"""Verify the four SHAppBarMessage edge probes in the pinned RK 4.6 PE."""

from __future__ import annotations

import argparse
import csv
import hashlib
from pathlib import Path

import pefile

EXPECTED_SHA256 = "8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9"
EXPECTED_SIZE = 2_418_176
IMAGE_BASE = 0x00400000
IAT_SLOT = 0x005A6544

FACTS: dict[int, tuple[str, str]] = {
    0x00490004: ("6a245f57", "Allocates a 0x24-byte APPBARDATA local and pushes its address."),
    0x00490010: ("899eb4010000", "Clears the receiver's edge-result mask at object +0x1B4."),
    0x0049001E: ("8d85c4feffff", "Loads the address of the local APPBARDATA structure."),
    0x00490025: ("89bdc4feffff", "Sets APPBARDATA.cbSize to 0x24."),
    0x0049002B: ("8b3d44655a00", "Loads the indirect target from IAT slot 0x005A6544."),
    0x00490033: ("c785d0feffff03000000", "Sets APPBARDATA.uEdge to 3 (ABE_BOTTOM)."),
    0x0049003D: ("ffd7", "Calls the imported SHAppBarMessage pointer with message 7."),
    0x00490043: ("838eb401000008", "If the call returns nonzero, sets result-mask bit 0x08."),
    0x00490053: ("c785d0feffff01000000", "Sets APPBARDATA.uEdge to 1 (ABE_TOP)."),
    0x0049005D: ("ffd7", "Calls the same SHAppBarMessage pointer with message 7."),
    0x00490063: ("838eb401000004", "If the call returns nonzero, sets result-mask bit 0x04."),
    0x00490073: ("899dd0feffff", "Sets APPBARDATA.uEdge to 0 (ABE_LEFT)."),
    0x00490079: ("ffd7", "Calls the same SHAppBarMessage pointer with message 7."),
    0x0049007F: ("838eb401000001", "If the call returns nonzero, sets result-mask bit 0x01."),
    0x0049008F: ("c785d0feffff02000000", "Sets APPBARDATA.uEdge to 2 (ABE_RIGHT)."),
    0x00490099: ("ffd7", "Calls the same SHAppBarMessage pointer with message 7."),
    0x0049009F: ("838eb401000002", "If the call returns nonzero, sets result-mask bit 0x02."),
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    data = args.binary.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if len(data) != EXPECTED_SIZE or digest != EXPECTED_SHA256:
        raise SystemExit("input size/SHA-256 mismatch")
    pe = pefile.PE(data=data)
    if pe.OPTIONAL_HEADER.ImageBase != IMAGE_BASE or pe.FILE_HEADER.Machine != 0x14C:
        raise SystemExit("expected x86 PE at preferred base")
    iat = {entry.address: (library.dll.decode(errors="replace"),
                           entry.name.decode(errors="replace") if entry.name else "")
           for library in pe.DIRECTORY_ENTRY_IMPORT for entry in library.imports}
    if iat.get(IAT_SLOT) != ("SHELL32.dll", "SHAppBarMessage"):
        raise SystemExit(f"unexpected IAT mapping: {iat.get(IAT_SLOT)!r}")

    def raw(va: int, size: int) -> bytes:
        offset = pe.get_offset_from_rva(va - IMAGE_BASE)
        return data[offset:offset + size]

    rows = []
    for va, (expected_hex, note) in FACTS.items():
        expected = bytes.fromhex(expected_hex)
        actual = raw(va, len(expected))
        if actual != expected:
            raise SystemExit(f"0x{va:08X}: expected {expected.hex()}, got {actual.hex()}")
        rows.append({"binary_sha256": digest, "evidence_va": f"0x{va:08X}",
                     "bytes": actual.hex().upper(), "observation": note,
                     "scope": "static bytes/import table; function execution and appbar state unobserved"})
    rows.append({"binary_sha256": digest, "evidence_va": f"0x{IAT_SLOT:08X}", "bytes": "",
                 "observation": "IAT slot resolves to SHELL32.dll!SHAppBarMessage.",
                 "scope": "static import table; runtime API call and return unobserved"})
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=("binary_sha256", "evidence_va", "bytes", "observation", "scope"))
        writer.writeheader()
        writer.writerows(rows)
    print(f"Verified {len(FACTS)} instruction facts and SHAppBarMessage IAT mapping for four edge probes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
