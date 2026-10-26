#!/usr/bin/env python3
"""Verify the installed 4.06 brightness setter after normalizing record bases.

Static file inspection only. Optional REA objdump Evidence corroborates exact
selected lines; its partial output must never be treated as whole-image CFG.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
import re
import struct

import capstone
import pefile

SHA256 = "c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6"
CANONICAL_BASE = 0x2140
ALIAS_BASE = 0x2138
STRIDE = 0x30

# Exact instruction facts, not guesses based on an unaligned byte-pattern sweep.
FACTS = [
    (0x00425442, "8b3d88b36200", "selected config", "EDI receives the selected config pointer"),
    (0x00425453, "8baf3c210000", "row selection", "EBP receives config+0x213C selected row"),
    (0x00425459, "83fd1e", "special row", "Row 0x1E takes a separate branch"),
    (0x004254D1, "8d446d00", "row scale", "EAX = row * 3"),
    (0x004254D5, "c1e004", "row scale", "EAX = row * 0x30"),
    (0x004254DF, "8d9c3838210000", "alias base", "EBX = config+0x2138+row*0x30"),
    (0x004254EB, "8d8e6c1a0000", "brightness child", "ECX = CLedDlg+0x1A6C"),
    (0x004254F4, "e827860200", "getter call", "Calls slider getter 0x0044DB20"),
    (0x004254F9, "89430c", "brightness write", "Stores getter EAX at alias+0x0C = canonical record+0x04"),
    (0x004254F1, "894308", "speed write", "Alias+0x08 = canonical record+0x00"),
    (0x00425505, "895318", "palette write", "Alias+0x18 = canonical record+0x10"),
    (0x00425514, "894334", "other write", "Alias+0x34 = canonical record+0x2C"),
    (0x0044DB20, "8b81a0090000", "getter value", "Reads child+0x9A0 selected position"),
    (0x0044DB26, "8b9198090000", "getter lower bound", "Reads child+0x998"),
    (0x0044DB2E, "8bb9b0000000", "getter mapping", "Reads optional value-list count at child+0xB0"),
    (0x0044DB47, "3bc2", "getter range", "When no value list, compares selection with lower bound"),
    (0x0044DB4B, "3b819c090000", "getter range", "Compares selection with upper bound child+0x99C"),
    (0x0044DB59, "8b8481b4000000", "getter mapping", "Optional table maps selected position to stored value"),
    (0x0045A4FB, "8d8540210000", "canonical base", "Initializer starts records at config+0x2140"),
    (0x0045A505, "894804", "default brightness", "Initializer writes DefBri-derived value at canonical+0x04"),
    (0x0045A53F, "83c030", "initializer stride", "Advances canonical record by 0x30"),
    (0x00424BCA, "8b841144210000", "UI read", "Reads config+0x2144+row*0x30"),
    (0x00424BD1, "8dbc1138210000", "refresh alias", "Refresh also forms config+0x2138+row*0x30"),
    (0x00424BD8, "0fb68854186100", "UI translation", "Maps brightness index through LightUI"),
    (0x00424FF3, "8b460c", "control restore", "Refresh reads alias+0x0C to restore brightness slider"),
    (0x00424FF7, "8d8bc01a0000", "embedded slider", "Restores child+0x54 subobject at dialog+0x1AC0"),
    (0x00424FFD, "e8ce750200", "selection setter", "Calls selection setter 0x0044C5D0"),
    (0x0044D15A, "8bd9", "mouse receiver", "WM_LBUTTONUP routine retains slider this in EBX"),
    (0x0044D18C, "8d7354", "embedded control", "ESI = slider+0x54"),
    (0x0044D22F, "6a00", "selection update", "Selection setter argument flag zero"),
    (0x0044D231, "8bc7", "selection update", "EAX = selected value EDI"),
    (0x0044D233, "8bce", "selection update", "ECX = slider+0x54"),
    (0x0044D235, "e896f3ffff", "selection update", "Calls 0x0044C5D0 before notifying parent"),
    (0x0044C63E, "89be4c090000", "selection state", "Stores selected position at subobject+0x94C = slider+0x9A0"),
    (0x0044D28B, "8b8be0090000", "selector", "Parent-notification lParam comes from slider+0x9E0"),
    (0x0044D292, "57", "notification value", "Pushes selected value EDI as wParam"),
    (0x0044D293, "6800080000", "notification", "Pushes private message 0x0800"),
    (0x0044D299, "ff1538e75900", "notification", "Calls USER32 PostMessageW IAT"),
    (0x004236B3, "6895000000", "child selector", "Construction passes selector 0x95"),
    (0x004236BB, "8db76c1a0000", "child construction", "Construction uses dialog+0x1A6C"),
    (0x004236D9, "e862ca0200", "child initializer", "Calls child setup helper 0x00450140"),
    (0x0045040B, "8996e0090000", "selector storage", "Child setup stores selector to child+0x9E0"),
    (0x0042219F, "e87c000000", "parent formatter", "0x0800 parent handler calls formatter"),
    (0x004221A6, "e895320000", "parent setter", "0x0800 parent handler calls corrected state-copy helper"),
    (0x004221F2, "b802000000", "apply mask", "Eligible branch prepares mask 2"),
    (0x004221F7, "e884eefdff", "apply signal", "Calls deferred Apply signal 0x00401080"),
    (0x00422202, "e8e9890300", "local persistence", "Calls pro.dct writer 0x0045ABF0 under guards"),
    (0x00411A9B, "8b941944210000", "G5/3632 consumer", "Reads same config+0x2144+row*0x30 brightness index"),
    (0x00411AA2, "8a8268186100", "hardware translation", "Maps index through LightHW"),
    (0x00411AA8, "88465e", "serialized field", "Writes translated byte to packer output+0x5E"),
    (0x00413CBA, "8d8c3140210000", "RKKB canonical base", "RKKB forms config+0x2140+row*0x30"),
    (0x00413CCA, "8b4104", "RKKB consumer", "Reads brightness at canonical+0x04"),
    (0x00413CD4, "0fb69068186100", "RKKB translation", "Maps brightness index through LightHW"),
]


def canonical_offset(base_displacement: int, member_displacement: int) -> int:
    """Offsets must be compared relative to the same config/row base."""
    return base_displacement + member_displacement - CANONICAL_BASE


def main() -> None:
    repo = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path(r"C:\Program Files (x86)\RK Keyboard Software\DeviceDriver.exe"))
    parser.add_argument("--rea-evidence", type=Path)
    parser.add_argument("--output", type=Path, required=True, help="new output directory")
    args = parser.parse_args()
    data = args.binary.read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA256:
        parser.error("This analysis applies only to the exact installed 4.06 binary")
    pe = pefile.PE(data=data)
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    rows, evidence = [], None
    if args.rea_evidence:
        record_bytes = args.rea_evidence.read_bytes()
        evidence = json.loads(record_bytes.decode("utf-8-sig"))
        if evidence["operation"] != "inspect_with_objdump" or evidence["subject"]["digest"]["sha256"] != SHA256:
            parser.error("REA subject/operation mismatch")
        raw = evidence["raw_result"]
        if raw["artifact_sha256_after"] != SHA256 or raw["artifact_changed"] is not False:
            parser.error("REA artifact changed or lacks matching post-run identity")
    for address, hex_bytes, role, conclusion in FACTS:
        expected = bytes.fromhex(hex_bytes)
        actual = pe.get_data(address - pe.OPTIONAL_HEADER.ImageBase, len(expected))
        if actual != expected:
            raise ValueError(f"Instruction mismatch at {address:#x}: {actual.hex()} != {hex_bytes}")
        instructions = list(decoder.disasm(actual, address))
        if len(instructions) != 1 or instructions[0].size != len(expected):
            raise ValueError(f"Fact is not exactly one decoded instruction: {address:#x}")
        instruction = instructions[0]
        rea_line = ""
        if evidence:
            lines = re.findall(rf"^\s*{address:x}:.*$", evidence["normalized_result"]["stdout"], re.MULTILINE)
            # Selected instructions are <=7 bytes, so objdump does not wrap them.
            if len(lines) != 1 or not re.search(r"\b" + r"\s+".join(f"{b:02x}" for b in expected) + r"\b", lines[0]):
                raise ValueError(f"REA did not retain the selected exact instruction: {address:#x}")
            rea_line = lines[0].strip()
        rows.append({"binary_sha256": SHA256, "va": f"0x{address:08X}", "bytes": hex_bytes,
                     "instruction": f"{instruction.mnemonic} {instruction.op_str}", "role": role,
                     "conclusion": conclusion, "rea_line": rea_line})
    read = lambda address, size: pe.get_data(address - pe.OPTIONAL_HEADER.ImageBase, size)
    maps = []
    for address, message, target in ((0x005D5E00, 0x0202, 0x0044D150),
                                     (0x005D5E30, 0x0800, 0x0044DA80),
                                     (0x005CD030, 0x0800, 0x00422190)):
        row = struct.unpack("<6I", read(address, 24))
        if row[0] != message or row[5] != target:
            raise ValueError(f"MFC map mismatch at {address:#x}")
        maps.append({"va": f"0x{address:08X}", "message": f"0x{message:04X}", "target": f"0x{target:08X}"})
    normalized = {f"0x{offset:02X}": f"0x{canonical_offset(ALIAS_BASE, offset):02X}" for offset in (8, 12, 24, 52)}
    assert canonical_offset(ALIAS_BASE, 12) == 4
    assert 0x54 + 0x94C == 0x9A0
    summary = {"binary_sha256": SHA256, "instruction_facts": len(rows), "mfc_rows": maps,
               "canonical_record_base": "config+0x2140+row*0x30", "setter_alias_base": "config+0x2138+row*0x30",
               "alias_member_to_canonical_member": normalized,
               "conclusion": "Selected-row UI state-copy helper writes canonical brightness offset +0x04; prior negative claim was a base-normalization error.",
               "limitations": ["Static conditional paths only; runtime event delivery and physical brightness remain unobserved.",
                               "The getter optionally translates a selection through a value table; its invocation is proven, not every possible control configuration.",
                               "UI-to-worker continuation is guard-dependent and concrete runtime family remains unknown."]}
    if evidence:
        summary["rea_source"] = {"evidence_id": evidence["evidence_id"],
                                 "record_sha256": hashlib.sha256(record_bytes).hexdigest(),
                                 "completion_status": evidence["raw_result"]["completion_status"],
                                 "output_truncated": evidence["raw_result"]["output_truncated"],
                                 "limitations": evidence["limitations"],
                                 "retention": "Full partial-output record retained locally; selected exact lines in instructions.csv are derived excerpts, not replacement canonical Evidence."}
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    with (args.output / "instructions.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(f"Verified {len(rows)} exact instructions, {len(maps)} MFC rows; alias+0x0C equals record+0x04.")
    pe.close()


if __name__ == "__main__":
    main()
