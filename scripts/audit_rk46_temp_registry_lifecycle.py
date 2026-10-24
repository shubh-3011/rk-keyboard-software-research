#!/usr/bin/env python3
"""Verify the RK 4.6 CMenuHash temporary-handle lifecycle from static PE bytes.

Requires pefile and Capstone. No PE execution, Windows API invocation, registry
access, or device access occurs. The failure witness treats calls as atomic
fall-through edges; it is not a symbolic execution of their side effects.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
from pathlib import Path
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_IMM
import pefile

EXPECTED_SHA256 = "8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9"
EXPECTED_SIZE = 2_418_176

# Exact instruction bytes, phase, and the bounded observation they support.
FACTS = {
    0x0049C242: ("8b81100b0000", "factory-guard", "First helper reads second object's +0xB10 field, without a validity/type check."),
    0x0049C248: ("c3", "factory-guard", "Returns that field as the factory's first guard result."),
    0x005A3E71: ("c70508796400bccf5d00", "application", "Global application object receives COemDrvApp vptr."),
    0x00486EC6: ("e978270000", "application", "App slot +0x54 method tail-jumps to message loop 0x00489643."),
    0x00489B3A: ("e90cfeffff", "application", "App slot +0x5C tail-jumps to message retrieval helper."),
    0x0048995F: ("ff152c675a00", "application", "Calls imported GetMessageW."),
    0x00489967: ("7425", "application", "Zero GetMessageW return branches to return without setting EAX to one."),
    0x00489697: ("8b06", "application", "Loop loads receiver vptr from ESI."),
    0x0048969B: ("ff505c", "application", "Calls receiver virtual slot +0x5C."),
    0x004896A4: ("7429", "application", "Zero return selects exit branch at 0x004896CF."),
    0x004896CF: ("ff5068", "application", "Exit branch dispatches app slot +0x68."),
    0x00448579: ("e941f30300", "application", "Application cleanup tail-dispatches to 0x004878BF."),
    0x004878C4: ("e8c08c0000", "application", "Base cleanup calls 0x00490589."),
    0x00490593: ("b954dd6100", "bulk-release", "Selects global CMenuHash at 0x0061DD54."),
    0x00490598: ("e82fbb0400", "bulk-release", "Calls bulk handle release at 0x004DC0CC."),
    0x004DC0E4: ("8d7e04", "bulk-release", "Selects embedded map at this+4."),
    0x004DC0F5: ("e89afeffff", "bulk-release", "Iterator returns next key/value pair."),
    0x004DC0FA: ("ff75f8", "bulk-release", "Passes iterator value as handle."),
    0x004DC0FD: ("ff15b8645a00", "bulk-release", "Calls imported CloseHandle on that value."),
    0x004DC107: ("75de", "bulk-release", "Loops while iterator position is nonzero."),
    0x004DC10D: ("e8f5ba0100", "bulk-release", "Clears map storage after close loop."),
    0x004DC004: ("8b4604", "iterator", "Reads node value at +4."),
    0x004DC00C: ("8901", "iterator", "Copies value to caller output pointer."),
    0x004DC2A3: ("e86f53fcff", "single-release", "Looks up handle by supplied menu key."),
    0x004DC2AF: ("ff15b8645a00", "single-release", "Closes found handle; return is not tested here."),
    0x004DC2BB: ("e855feffff", "single-release", "Removes map key after close attempt."),
    0x00551A3C: ("b954dd6100", "toolbar-command", "Selects global CMenuHash."),
    0x00551A41: ("e845a8f8ff", "toolbar-command", "Command handler calls single-key release with EDI menu."),
    0x00551A47: ("ff159c675a00", "toolbar-command", "Then calls DestroyMenu for the same EDI value."),
    0x005A497B: ("b954dd6100", "global-lifetime", "Selects the global registry before construction."),
    0x005A4980: ("e81677f3ff", "global-lifetime", "Calls CMenuHash constructor."),
    0x005A4985: ("68e9575a00", "global-lifetime", "Passes destructor callback address to registrar."),
    0x005A57EE: ("e9c568f3ff", "global-lifetime", "Callback tail-jumps to storage destructor."),
    0x004DC0C7: ("e93bbb0100", "global-lifetime", "Destructor tail-jumps to map storage cleanup, not bulk close."),
    0x004F7C34: ("e827f4f7ff", "map-storage", "Frees bucket-array allocation."),
    0x004F7C46: ("e8fbabfbff", "map-storage", "Frees allocation-chain blocks."),
    0x004A1631: ("8b4004", "lookup", "Reads existing node's value field."),
    0x004A1637: ("8901", "lookup", "Copies value into caller local without removing node."),
    0x004DC300: ("e81253fcff", "replacement", "Looks up prior handle for requested key."),
    0x004DC30C: ("ff15b8645a00", "replacement", "Closes prior value before attempting replacement file."),
    0x004DC380: ("ff1574645a00", "replacement", "Calls CreateFileW for delete-on-close temporary file."),
    0x004DC38B: ("83feff", "replacement", "Compares new handle with INVALID_HANDLE_VALUE."),
    0x004DC38E: ("0f84f1000000", "replacement", "Open failure branches directly to string cleanup."),
    0x004DC40A: ("e81f5ffcff", "replacement", "Successful serialization obtains map value address."),
    0x004DC415: ("8930", "replacement", "Successful path stores new handle in map value."),
    0x004DC49B: ("33c0", "replacement", "Failure cleanup returns zero."),
    0x004DC4A2: ("c20800", "replacement", "Factory returns, removing two caller arguments."),
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def run() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--witness-out", type=Path)
    args = parser.parse_args()
    data = args.binary.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    require(len(data) == EXPECTED_SIZE and digest == EXPECTED_SHA256, "input size/SHA-256 mismatch")
    pe = pefile.PE(data=data)
    base = pe.OPTIONAL_HEADER.ImageBase
    require(base == 0x400000 and pe.FILE_HEADER.Machine == 0x14C, "expected x86 PE at preferred base")
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True

    def read(va: int, size: int) -> bytes:
        offset = pe.get_offset_from_rva(va - base)
        result = data[offset:offset + size]
        require(len(result) == size, f"unavailable bytes at 0x{va:08X}")
        return result

    def words(va: int, count: int) -> tuple[int, ...]:
        return struct.unpack(f"<{count}I", read(va, count * 4))

    def instruction(va: int):
        result = next(decoder.disasm(read(va, 15), va, count=1), None)
        require(result is not None, f"undecodable instruction at 0x{va:08X}")
        return result

    imports = {entry.address: entry.name.decode("ascii") for group in pe.DIRECTORY_ENTRY_IMPORT
               for entry in group.imports if entry.name}
    for address, name in ((0x5A64B8, "CloseHandle"), (0x5A6474, "CreateFileW"), (0x5A679C, "DestroyMenu"), (0x5A672C, "GetMessageW")):
        require(imports.get(address) == name, f"IAT mismatch: {name}")
    for table, col, descriptor, name in (
        (0x5B2FEC, 0x5E7ABC, 0x608F8C, b".?AVCMenuHash@@\0"),
        (0x5B2FDC, 0x5E7A70, 0x608F58, b".?AV?$CMap@PAUHMENU__@@AAPAU1@PAXAAPAX@@\0"),
        (0x5DCFBC, 0x5ED640, 0x61A3F0, b".?AVCOemDrvApp@@\0"),
    ):
        require(words(table - 4, 1) == (col,), "RTTI COL pointer changed")
        require(words(col + 12, 1) == (descriptor,), "RTTI TypeDescriptor pointer changed")
        require(read(descriptor + 8, len(name)) == name, "RTTI class name changed")
    require(words(0x5DCFBC + 0x68, 1) == (0x448530,), "application cleanup virtual target changed")
    require(words(0x5DCFBC + 0x54, 1) == (0x486EA8,), "application run virtual target changed")
    require(words(0x5DCFBC + 0x5C, 1) == (0x489B3A,), "application message-pump target changed")
    require(words(0x5C3580, 6) == (0x111, 0, 0x40F0, 0x40F0, 0x39, 0x55181F), "toolbar WM_COMMAND map changed")

    rows = []
    for va, (expected_hex, phase, observation) in FACTS.items():
        expected = bytes.fromhex(expected_hex)
        require(read(va, len(expected)) == expected, f"instruction bytes changed at 0x{va:08X}")
        insn = instruction(va)
        require(insn.size == len(expected), f"guard is not a complete instruction at 0x{va:08X}")
        rows.append({"binary_sha256": digest, "va": f"0x{va:08X}", "bytes": expected.hex().upper(),
                     "instruction": f"{insn.mnemonic} {insn.op_str}".strip(), "phase": phase,
                     "observation": observation, "evidence": "static exact instruction; no runtime observation"})

    # One selected intraprocedural witness: nonzero second-object +0xB10
    # field, existing cache key, then replacement CreateFileW failure.
    # Calls are not recursively executed.
    choices = {0x4DC2E7: False, 0x4DC307: False, 0x4DC38E: True}
    pc = 0x4DC2CC
    witness = []
    for _ in range(250):
        insn = instruction(pc)
        branch_choice = ""
        if insn.mnemonic.startswith("ret"):
            next_pc = None
        elif insn.mnemonic.startswith("j"):
            require(insn.operands[0].type == X86_OP_IMM, "unresolved witness jump")
            if insn.mnemonic == "jmp":
                next_pc = insn.operands[0].imm
                branch_choice = f"unconditional -> 0x{next_pc:08X}"
            else:
                require(pc in choices, f"unselected witness branch at 0x{pc:08X}")
                if choices[pc]:
                    next_pc = insn.operands[0].imm
                    branch_choice = f"taken -> 0x{next_pc:08X}"
                else:
                    next_pc = pc + insn.size
                    branch_choice = f"fallthrough -> 0x{next_pc:08X}"
        else:
            next_pc = pc + insn.size
        witness.append({"binary_sha256": digest, "va": f"0x{pc:08X}",
                        "bytes": insn.bytes.hex().upper(),
                        "instruction": f"{insn.mnemonic} {insn.op_str}".strip(),
                        "branch_choice": branch_choice,
                        "scope": "selected local branch path; calls treated atomically"})
        if next_pc is None:
            break
        pc = next_pc
    else:
        raise RuntimeError("failure witness did not reach a bounded return")
    visited = {int(row["va"], 16) for row in witness}
    require({0x4DC30C, 0x4DC380, 0x4DC485, 0x4DC49B, 0x4DC4A2} <= visited, "failure witness misses expected edges")
    require(not {0x4DC40A, 0x4DC415} & visited, "failure witness unexpectedly updates cached handle")

    def write_csv(path: Path, records: list[dict[str, str]]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(records[0]), lineterminator="\n")
            writer.writeheader()
            writer.writerows(records)

    write_csv(args.out, rows)
    if args.witness_out:
        write_csv(args.witness_out, witness)
    print(f"Verified {len(rows)} lifecycle instruction guards, RTTI/MFC/import bridges, and {len(witness)}-instruction replacement-failure witness.")
    print("Static only: cleanup execution, API success, handle reuse, and concurrent mutation remain unobserved.")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
