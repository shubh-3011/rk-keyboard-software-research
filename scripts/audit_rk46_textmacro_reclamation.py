#!/usr/bin/env python3
"""Verify the RK 4.6 text-macro orphan-record cleanup path from PE bytes only."""

from __future__ import annotations

import argparse
import csv
import hashlib
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
import pefile

EXPECTED_SHA256 = "8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9"
EXPECTED_SIZE = 2_418_176

# Exact instruction bytes, stage, and their bounded static observation.
FACTS = {
    0x00401AD0: ("53", "cleanup-helper", "Record-reference cleanup helper entry."),
    0x00401AD4: ("bdc4d36000", "cleanup-helper", "Begins scanning the 50-record table at 0x0060D3C4."),
    0x00401AE0: ("8b5d00", "cleanup-helper", "Loads the current record key."),
    0x00401AE3: ("85db", "cleanup-helper", "Zero record keys skip the reference scan and fill."),
    0x00401AE7: ("8b3dcc9d6100", "cleanup-helper", "Loads linked-list root 0x00619DCC."),
    0x00401AED: ("85ff", "cleanup-helper", "A null list root takes the record-fill path."),
    0x00401AF1: ("8b07", "cleanup-helper", "Loads the current node's referenced mapping base."),
    0x00401AF3: ("85c0", "cleanup-helper", "Null mapping bases advance to the next list node."),
    0x00401AF7: ("33f6", "cleanup-helper", "Initializes the category index."),
    0x00401AF9: ("8d5038", "cleanup-helper", "Starts category mapping cells at base +0x38."),
    0x00401B04: ("81385b00000a", "cleanup-helper", "Checks mapping-cell dword for tag 0x0A00005B."),
    0x00401B0C: ("3b5808", "cleanup-helper", "Compares record key with mapping-cell +0x40."),
    0x00401B0F: ("74 2f", "cleanup-helper", "A matching tag and key branch skips clearing the record."),
    0x00401B12: ("83c010", "cleanup-helper", "Advances by one 0x10-byte mapping cell."),
    0x00401B15: ("81f984000000", "cleanup-helper", "Bounds the cell loop at 0x84 entries."),
    0x00401B1D: ("46", "cleanup-helper", "Advances the category index."),
    0x00401B1E: ("81c240080000", "cleanup-helper", "Advances by 0x840 bytes to the next category."),
    0x00401B24: ("83fe04", "cleanup-helper", "Bounds the category loop at four categories."),
    0x00401B29: ("8b7f04", "cleanup-helper", "Advances to the next linked-list node."),
    0x00401B30: ("6804040000", "cleanup-helper", "Passes 0x404 bytes to the fill helper."),
    0x00401B35: ("6a00", "cleanup-helper", "Passes a zero fill byte."),
    0x00401B37: ("55", "cleanup-helper", "Passes the current record as the fill destination."),
    0x00401B38: ("e8b36a1700", "cleanup-helper", "Calls fill helper 0x005785F0."),
    0x00401B40: ("81c504040000", "cleanup-helper", "Advances by the 0x404-byte record stride."),
    0x00401B46: ("81fd8c9c6100", "cleanup-helper", "Stops at exclusive table end 0x00619C8C."),
    0x005785F0: ("8b54240c", "zero-fill-helper", "Loads requested fill length."),
    0x005785F4: ("8b4c2404", "zero-fill-helper", "Loads fill destination."),
    0x005785FC: ("33c0", "zero-fill-helper", "Initializes fill value to zero."),
    0x005785FE: ("8a442408", "zero-fill-helper", "Loads the caller-provided fill byte."),
    0x00578602: ("84c0", "zero-fill-helper", "Selects the optimized path only for zero fill."),
    0x00578606: ("81fa00010000", "zero-fill-helper", "Checks the 0x100-byte optimized-fill threshold."),
    0x0057860E: ("833dc87a640000", "zero-fill-helper", "Checks the fast-fill configuration flag."),
    0x00578617: ("e93ebe0000", "zero-fill-helper", "Large configured fills branch to aligned XMM zero-fill path."),
    0x0057861C: ("57", "zero-fill-helper", "Fallback fill path begins."),
    0x0057864F: ("f3ab", "zero-fill-helper", "Fallback path fills DWORDs with the replicated fill byte."),
    0x00578655: ("8807", "zero-fill-helper", "Fallback path fills trailing bytes."),
    0x00584415: ("660fefc0", "aligned-zero-fill", "Clears XMM0 for the aligned fast path."),
    0x00584423: ("660f7f07", "aligned-zero-fill", "Stores a zeroed 16-byte block."),
    0x00584445: ("660f7f4770", "aligned-zero-fill", "Stores the eighth zeroed 16-byte block in a 0x80-byte batch."),
    0x0058444A: ("8dbf80000000", "aligned-zero-fill", "Advances the destination by a full 0x80-byte batch."),
    0x005844AD: ("f3aa", "aligned-zero-fill", "Fills trailing bytes with zero."),
    0x005844BC: ("33c0", "aligned-zero-fill", "Unaligned fast-path prefix fill also uses zero."),
    0x00403812: ("803db3b8620000", "callsite-config-change", "Tests global byte 0x0062B8B3."),
    0x0040381B: ("e8b0e2ffff", "callsite-config-change", "Calls cleanup after the nonzero configuration-flag branch."),
    0x0041D087: ("380db3b86200", "callsite-current-cell", "Tests global byte 0x0062B8B3."),
    0x0041CFEA: ("837d0c02", "callsite-current-cell", "CKeyDlg handler compares its second explicit argument with 2."),
    0x0041CFF1: ("0f8589000000", "callsite-current-cell", "The non-2 argument branch reaches the local selection handler path."),
    0x0041D080: ("8b4d08", "callsite-current-cell", "Loads the first explicit handler argument."),
    0x0041D083: ("85c9", "callsite-current-cell", "Tests the first explicit handler argument."),
    0x0041D085: ("757f", "callsite-current-cell", "Nonzero first arguments bypass the selected-cell cleanup path."),
    0x0041D09A: ("817c38385b00000a", "callsite-current-cell", "Checks selected cell tag 0x0A00005B."),
    0x0041D0A2: ("7505", "callsite-current-cell", "Skips cleanup when the selected cell has a different tag."),
    0x0041D0A4: ("e8274afeff", "callsite-current-cell", "Calls cleanup for the matching-tag branch."),
    0x00421627: ("381db3b86200", "callsite-picker-command", "Tests global byte 0x0062B8B3."),
    0x0042162D: ("7416", "callsite-picker-command", "Skips cleanup when the global flag is zero."),
    0x0042162F: ("83bdac11000005", "callsite-picker-command", "Tests picker state against numeric state 5."),
    0x00421636: ("740d", "callsite-picker-command", "Skips cleanup in picker state 5."),
    0x00421638: ("813f5b00000a", "callsite-picker-command", "Checks the selected cell tag."),
    0x0042163E: ("7505", "callsite-picker-command", "Skips cleanup for a different selected-cell tag."),
    0x00421640: ("e88b04feff", "callsite-picker-command", "Calls cleanup for the matching-tag branch."),
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def run() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    data = args.binary.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    require(len(data) == EXPECTED_SIZE and digest == EXPECTED_SHA256,
            "input size/SHA-256 mismatch")
    pe = pefile.PE(data=data)
    base = pe.OPTIONAL_HEADER.ImageBase
    require(base == 0x00400000 and pe.FILE_HEADER.Machine == 0x14C,
            "expected x86 PE at preferred base")
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)

    def read(va: int, size: int) -> bytes:
        offset = pe.get_offset_from_rva(va - base)
        result = data[offset:offset + size]
        require(len(result) == size, f"unavailable bytes at 0x{va:08X}")
        return result

    evidence = []
    for va, (expected_hex, phase, observation) in FACTS.items():
        expected = bytes.fromhex(expected_hex)
        actual = read(va, len(expected))
        require(actual == expected, f"instruction bytes changed at 0x{va:08X}")
        insn = next(decoder.disasm(read(va, 15), va, count=1), None)
        require(insn is not None and insn.size == len(expected),
                f"expected complete instruction at 0x{va:08X}")
        evidence.append({"binary_sha256": digest, "va": f"0x{va:08X}",
                         "bytes": actual.hex().upper(),
                         "instruction": f"{insn.mnemonic} {insn.op_str}".strip(),
                         "phase": phase, "observation": observation,
                         "scope": "static exact instruction; call/runtime outcomes unobserved"})

    direct_calls = set()
    for section in pe.sections:
        if section.Characteristics & 0x20000000:
            start = base + section.VirtualAddress
            for insn in decoder.disasm(section.get_data(), start):
                if insn.mnemonic == "call" and insn.op_str.lower() == "0x401ad0":
                    direct_calls.add(insn.address)
    expected_calls = {0x0040381B, 0x0041D0A4, 0x00421640}
    require(direct_calls == expected_calls,
            f"linear executable-section direct-call census changed: {sorted(direct_calls)}")
    root = Path(__file__).resolve().parents[1]
    map_csv = root / "docs" / "rk-v4.6-mfc-message-map-entries.csv"
    with map_csv.open("r", encoding="utf-8-sig", newline="") as stream:
        handlers = [row for row in csv.DictReader(stream)
                    if row.get("handler_va") == "0x0041CF20"]
    require(len(handlers) == 1 and
            (handlers[0]["rtti_vtable_types"], handlers[0]["message_hex"])
            == (".?AVCKeyDlg@@", "0x0477"),
            "existing MFC ledger does not identify 0x0041CF20 as CKeyDlg message 0x0477")
    for va in sorted(direct_calls):
        evidence.append({"binary_sha256": digest, "va": f"0x{va:08X}",
                         "bytes": read(va, 5).hex().upper(), "instruction": "call 0x00401AD0",
                         "phase": "direct-caller-census",
                         "observation": "Direct-call operand found by byte-linear sweep of executable sections; not a CFG completeness claim.",
                         "scope": "static linear instruction sweep; runtime reachability unobserved"})

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(evidence[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(evidence)
    print(f"Verified {len(FACTS)} instruction guards and three direct-call candidates in the executable-section linear sweep.")
    print("Static only: list identity, runtime execution, file persistence, and actual record reclamation remain unobserved.")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
