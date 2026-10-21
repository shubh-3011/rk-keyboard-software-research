#!/usr/bin/env python3
"""Reproduce a bounded register-mediated +0x68 call-pattern census.

The scan is static and hash-pinned. It does not execute DeviceDriver.exe or
communicate with a keyboard. Candidate matches are heuristic; the classification
column only reflects the evidence recorded in the linked audit.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
from pathlib import Path
import re
import subprocess
import sys


EXPECTED_SHA256 = "c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6"
ENTRY_RE = re.compile(r"^\s*([0-9a-fA-F]+):\s*((?:[0-9a-fA-F]{2}\s+)+)(\S.*)$")
LOAD_RE = re.compile(r"mov\s+(e[a-z]{2}),dword ptr \[(e[a-z]{2})\+0x68\]")

EARLIER_RESOLVED = {
    0x00401E92,
    0x00401F1E,
    0x00401FB5,
    0x00402059,
    0x004020FD,
    0x0040217A,
    0x004051AC,
}

DRAW_TEXT_RESOLVED = {
    0x00406F00,
    0x00406F4C,
    0x00406F95,
    0x00408CF6,
    0x00408D71,
    0x00408DEC,
    0x00408E7C,
    0x00408F45,
    0x00409022,
    0x004090F4,
    0x00409176,
    0x0041C4D9,
    0x0041C5C2,
    0x0041C6B8,
    0x0041C7A6,
    0x0041C88A,
    0x0041C91E,
    0x0041CBA8,
    0x0041E332,
    0x0041E408,
    0x0041E4CD,
    0x0041E596,
    0x0041E65F,
    0x0041CC73,
    0x0041CFAB,
    0x0041E728,
    0x0041E7C9,
    0x00421B49,
    0x00421BE1,
    0x00421C87,
    0x00421D7C,
    0x00421E12,
    0x00421EA8,
    0x00421F45,
    0x00421FDD,
    0x0042205D,
    0x004269DC,
    0x00426A61,
    0x00426AE6,
    0x00426B61,
    0x00426BED,
    0x00426C68,
    0x00426CE3,
    0x00426D5E,
    0x00426F54,
    0x00426FC7,
    0x00433DDA,
    0x00433E83,
    0x0043526A,
    0x0044AE80,
}


def disassemble(binary: Path, objdump: str) -> list[tuple[int, str]]:
    result = subprocess.run(
        [objdump, "-d", "-Mintel", "-j", ".text", str(binary)],
        check=True,
        capture_output=True,
        text=True,
        errors="replace",
    )
    instructions: list[tuple[int, str]] = []
    for line in result.stdout.splitlines():
        match = ENTRY_RE.match(line)
        if match:
            instructions.append(
                (int(match.group(1), 16), " ".join(match.group(3).lower().split()))
            )
    if not instructions:
        raise RuntimeError("objdump produced no parseable .text instructions")
    return instructions


def find_candidates(instructions: list[tuple[int, str]]) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    for index, (load_va, asm) in enumerate(instructions):
        match = LOAD_RE.fullmatch(asm)
        if not match:
            continue
        target_register, receiver_register = match.groups()
        for call_index in range(index + 1, min(index + 4, len(instructions))):
            call_va, call_asm = instructions[call_index]
            if call_asm == f"call {target_register}":
                candidates.append(
                    {
                        "slot_load_va": f"0x{load_va:08X}",
                        "call_va": f"0x{call_va:08X}",
                        "loaded_register": target_register.upper(),
                        "receiver_register": receiver_register.upper(),
                    }
                )
                break
    return candidates


def run() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path, help="hash-verified 4.06 DeviceDriver.exe")
    parser.add_argument("--objdump", default="objdump", help="GNU objdump executable")
    parser.add_argument("--out", type=Path, help="CSV output path; defaults to stdout")
    args = parser.parse_args()
    if not args.binary.is_file():
        parser.error(f"binary not found: {args.binary}")
    digest = hashlib.sha256(args.binary.read_bytes()).hexdigest()
    if digest != EXPECTED_SHA256:
        parser.error(f"binary SHA-256 mismatch: expected {EXPECTED_SHA256}, got {digest}")

    candidates = find_candidates(disassemble(args.binary, args.objdump))
    call_vas = {int(row["call_va"], 16) for row in candidates}
    if len(candidates) != 90 or len(call_vas) != len(candidates):
        raise RuntimeError(f"expected 90 unique pattern matches, found {len(candidates)}")
    if not EARLIER_RESOLVED <= call_vas:
        raise RuntimeError("the seven earlier-resolved calls are not all present in the scan")
    if len(DRAW_TEXT_RESOLVED) != 50 or not DRAW_TEXT_RESOLVED <= call_vas:
        raise RuntimeError("the 50 documented DrawTextW calls do not match the scan")
    if EARLIER_RESOLVED & DRAW_TEXT_RESOLVED:
        raise RuntimeError("earlier-resolved and later DrawTextW classifications overlap")

    for row in candidates:
        call_va = int(row["call_va"], 16)
        if call_va in EARLIER_RESOLVED:
            row["classification"] = "previously resolved; non-G5 vtable path"
            row["evidence"] = "docs/rk-406-cdevg5-vtable-audit.md: expanded decoded-callsite sweep"
        elif call_va in DRAW_TEXT_RESOLVED:
            row["classification"] = "resolved false positive; USER32!DrawTextW"
            row["evidence"] = "docs/rk-406-cdevg5-vtable-audit.md: constructor/vtable/ABI trace"
        else:
            row["classification"] = "unclassified candidate pattern"
            row["evidence"] = "receiver/target provenance has not been established"

    unclassified = sum(row["classification"] == "unclassified candidate pattern" for row in candidates)
    if unclassified != 33:
        raise RuntimeError(f"expected 33 unclassified pattern matches, found {unclassified}")

    fields = [
        "slot_load_va",
        "call_va",
        "loaded_register",
        "receiver_register",
        "classification",
        "evidence",
    ]
    out = args.out.open("w", newline="", encoding="utf-8") if args.out else sys.stdout
    try:
        writer = csv.DictWriter(out, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(candidates)
    finally:
        if args.out:
            out.close()
    print(
        "Scanned 90 register-mediated +0x68 patterns in .text: "
        "7 previously resolved, 50 documented DrawTextW false positives, "
        "33 unclassified.",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
