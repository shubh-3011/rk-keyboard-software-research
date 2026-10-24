#!/usr/bin/env python3
"""Verify selected 4.6 profile persistence facts against the pinned PE bytes.

This is a static byte verifier. It neither runs DeviceDriver.exe nor accesses a
keyboard. Requires pefile (as do the neighboring PE audit scripts).
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import struct
from pathlib import Path

import pefile


EXPECTED_SHA256 = "8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9"
EXPECTED_SIZE = 2_418_176
IMAGE_BASE = 0x00400000

INT_WRITES = {
    0x00486975,
    0x004970B4, 0x004970CD, 0x004970E8, 0x004970FE,
    0x0049711A, 0x00497136, 0x00497154, 0x00497173,
    0x00497189, 0x0049719F, 0x004971B5, 0x004971CB,
    0x004971E1, 0x004971F7, 0x0049720D, 0x00497223,
    0x0049723F, 0x00497275,
    0x00497F28, 0x00497F53, 0x00497F6C,
}
STRING_WRITES = {0x00497077}

IMPORTS = {
    0x005A6000: ("advapi32.dll", "RegOpenKeyExW"),
    0x005A6018: ("advapi32.dll", "RegCreateKeyExW"),
    0x005A601C: ("advapi32.dll", "RegSetValueExW"),
    0x005A6024: ("advapi32.dll", "RegCloseKey"),
    0x005A6030: ("advapi32.dll", "RegDeleteKeyW"),
    0x005A6034: ("advapi32.dll", "RegDeleteValueW"),
    0x005A6484: ("kernel32.dll", "WritePrivateProfileStringW"),
}

BYTES = {
    0x00489450: "83 7e 54 00",
    0x00489472: "ff 15 1c 60 5a 00",
    0x004894A9: "ff 15 84 64 5a 00",
    0x004894C5: "83 79 54 00",
    0x004894E6: "ff 15 30 60 5a 00",
    0x00489506: "ff 15 34 60 5a 00",
    0x0048952B: "ff 15 1c 60 5a 00",
    0x0048954F: "ff 15 84 64 5a 00",
    0x00489321: "ff 15 00 60 5a 00",
    0x00486975: "e8 bd 2a 00 00",
    0x004869A5: "e8 9b ff ff ff",
    0x00497077: "e8 44 24 ff ff",
    0x004882AE: "e8 b2 fb 00 00",
    0x00497EA9: "e8 46 f1 ff ff",
}

WIDE_STRINGS = {
    0x005A9DDC: "Settings",
    0x005A9DF0: "PreviewPages",
    0x005AA628: "software",
    0x005ABC28: "Visible",
    0x005ABC38: "%s-Bar%d",
    0x005ABC4C: "%s-Summary",
    0x005ABC64: "XPos",
    0x005ABC70: "YPos",
    0x005ABC7C: "MRUWidth",
    0x005ABC90: "Docking",
    0x005ABCA0: "MRUDockID",
    0x005ABCB4: "MRUDockLeftPos",
    0x005ABCD4: "MRUDockRightPos",
    0x005ABCF4: "MRUDockTopPos",
    0x005ABD10: "MRUDockBottomPos",
    0x005ABD34: "MRUFloatStyle",
    0x005ABD50: "MRUFloatXPos",
    0x005ABD6C: "MRUFloatYPos",
    0x005ABD88: "BarID",
    0x005ABD94: "Horz",
    0x005ABDA0: "Floating",
    0x005ABDB4: "Bars",
    0x005ABDC0: "ScreenCX",
    0x005ABDD4: "ScreenCY",
    0x005ABDE8: "Bar#%d",
}


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--exe",
        type=Path,
        default=Path(__file__).resolve().parents[2]
        / ".research/rk4_6_official_extract_20261015/app/DeviceDriver.exe",
    )
    ap.add_argument(
        "--evidence",
        type=Path,
        default=Path(__file__).resolve().parents[1]
        / "docs/rk-v4.6-profile-persistence-wrapper-evidence-2026-10-25.csv",
    )
    args = ap.parse_args()
    data = args.exe.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256 or len(data) != EXPECTED_SIZE:
        fail(f"binary identity mismatch: sha256={digest}, size={len(data)}")
    pe = pefile.PE(data=data, fast_load=False)
    if pe.OPTIONAL_HEADER.ImageBase != IMAGE_BASE:
        fail("unexpected image base")

    def off(va: int) -> int:
        return pe.get_offset_from_rva(va - IMAGE_BASE)

    for va, encoded in BYTES.items():
        expected = bytes.fromhex(encoded)
        actual = data[off(va):off(va) + len(expected)]
        if actual != expected:
            fail(f"instruction bytes differ at 0x{va:08X}: {actual.hex(' ')}")

    actual_imports = {}
    for desc in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = desc.dll.decode("ascii").lower()
        for imp in desc.imports:
            if imp.name:
                actual_imports[imp.address] = (dll, imp.name.decode("ascii"))
    for va, expected in IMPORTS.items():
        if actual_imports.get(va) != expected:
            fail(f"import mismatch at 0x{va:08X}: {actual_imports.get(va)!r}")

    for va, expected in WIDE_STRINGS.items():
        encoded = expected.encode("utf-16le") + b"\x00\x00"
        if data[off(va):off(va) + len(encoded)] != encoded:
            fail(f"UTF-16 literal mismatch at 0x{va:08X}: expected {expected!r}")

    # Validate every row in the human-readable evidence ledger against the
    # same hash-pinned file, so edits to the CSV cannot silently drift.
    with args.evidence.open(newline="", encoding="utf-8-sig") as stream:
        evidence = list(csv.DictReader(stream))
    if not evidence:
        fail("evidence ledger is empty")
    for row_number, row in enumerate(evidence, start=2):
        if row.get("sha256", "").lower() != digest:
            fail(f"evidence row {row_number} has a different binary hash")
        try:
            va = int(row["va"], 16)
        except (KeyError, ValueError):
            fail(f"evidence row {row_number} has an invalid VA")
        value = row.get("bytes_or_data", "")
        kind = row.get("kind", "")
        if kind == "string":
            expected = value.encode("utf-16le") + b"\x00\x00"
        elif kind in {"instruction", "callsite"}:
            try:
                expected = bytes.fromhex(value)
            except ValueError:
                fail(f"evidence row {row_number} has invalid instruction bytes")
        else:
            fail(f"evidence row {row_number} has unsupported kind {kind!r}")
        actual = data[off(va):off(va) + len(expected)]
        if actual != expected:
            fail(f"evidence row {row_number} does not match the pinned PE at 0x{va:08X}")

    # Enumerate E8 rel32 encodings in PE sections marked executable. These
    # bytes validate the listed direct edge set but do not constitute CFG proof.
    calls: dict[int, set[int]] = {0x00489437: set(), 0x004894C0: set()}
    for sec in pe.sections:
        if not (sec.Characteristics & 0x20000000):
            continue
        start = sec.PointerToRawData
        blob = data[start:start + sec.SizeOfRawData]
        section_va = IMAGE_BASE + sec.VirtualAddress
        for idx in range(max(0, len(blob) - 4)):
            if blob[idx] != 0xE8:
                continue
            source = section_va + idx
            target = source + 5 + struct.unpack_from("<i", blob, idx + 1)[0]
            if target in calls:
                calls[target].add(source)
    if calls[0x00489437] != INT_WRITES:
        fail(f"WriteProfileInt callsite set changed: {sorted(hex(x) for x in calls[0x00489437])}")
    if calls[0x004894C0] != STRING_WRITES:
        fail(f"WriteProfileString callsite set changed: {sorted(hex(x) for x in calls[0x004894C0])}")

    print(f"PASS: pinned PE identity {digest} ({len(data)} bytes)")
    print(f"PASS: verified {len(BYTES)} instruction guards, {len(IMPORTS)} imports, {len(WIDE_STRINGS)} UTF-16 literals")
    print(f"PASS: validated {len(evidence)} evidence rows against the pinned PE")
    print(f"PASS: {len(INT_WRITES)} direct E8 encodings to 0x00489437; {len(STRING_WRITES)} to 0x004894C0")
    print("Static bytes only; no execution, CFG completeness, API success, or device effect is asserted.")


if __name__ == "__main__":
    main()
