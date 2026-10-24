#!/usr/bin/env python3
"""Verify the bounded static S98 01BF All Start-to-worker call path.

Reads a hash-pinned PE as data only. It does not launch the updater, access HID,
send reports, or modify firmware. The output CSV records exact resource and
instruction bytes; static reachability is not runtime evidence.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import struct
import sys
from pathlib import Path

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_IMM

from audit_dialog_resources import parse_dialog


EXPECTED_SHA256 = "475e8d7b97adfbd861c3b7b16721ad598df04095b81228e381319b6be23129e6"
EXPECTED_SIZE = 2_140_176
EXPECTED_TEXT_SHA256 = "3643f4d710a296b62598d3d8b71c7dd9dcab049ebbb540588b11757ccd5f03ed"
IMAGE_BASE = 0x00400000
RESOURCE_RVA = 0x001E62E8
RESOURCE_RAW_OFFSET = 0x001D8AE8
RESOURCE_SIZE = 1672
RESOURCE_SHA256 = "b6ced0626e42b9a5346c01e1e1fe2b00a97b5e8f23a5c20f4dad7d7ff0779c7b"
MAP_DESCRIPTOR_VA = 0x0058DC1C
MAP_ENTRIES_VA = 0x0058DC28
MAP_ROW_VA = 0x0058DC88
MAP_ROW = (0x111, 0, 1, 1, 0x3A, 0x004096A0)

# Address -> expected bytes, explanation. Bytes are instruction starts, not
# assertions that execution occurred.
FACTS: dict[int, tuple[str, str]] = {
    0x00407350: ("b81cdc5800c3", "GetMessageMap returns map descriptor VA 0x0058DC1C."),
    0x00407C4F: ("e88c210000", "Dialog initialization calls the 16-slot event/thread initializer 0x00409DE0."),
    0x004096BB: ("80be60e45b0000", "All Start handler checks the per-slot connection/status byte before setup."),
    0x004096C9: ("833cb520e45b0000", "All Start handler checks per-slot status DWORD for zero."),
    0x004096E1: ("e84a000000", "Eligible slot path calls setup routine 0x00409730."),
    0x0040975B: ("c7049d20e45b0001000000", "Per-slot setup marks the slot state as 1."),
    0x004097D6: ("ffb698e85b00", "Loads the per-slot event handle from slot record +0x418."),
    0x004097DC: ("ff159ca25500", "Per-slot setup calls the SetEvent IAT slot 0x0055A29C."),
    0x00409DE1: ("8b1d8ca25500", "Worker initializer loads CreateEventW from IAT slot 0x0055A28C."),
    0x00409E18: ("ffd3", "Worker initializer calls CreateEventW for the current slot."),
    0x00409E23: ("68509e4000", "Pushes app worker callback 0x00409E50 for the thread wrapper."),
    0x00409E2B: ("e805240000", "Passes callback/slot arguments into MFC thread factory 0x0040C235."),
    0x00409E30: ("81c61c040000", "Advances slot records by 0x41C bytes."),
    0x00409E36: ("81fe542a5c00", "Initializer loop stops at the bound for 16 slot records."),
    0x0040C179: ("894638", "CWinThread constructor stores callback pointer in object +0x38."),
    0x0040C17C: ("8b450c", "CWinThread constructor loads callback parameter from its argument."),
    0x0040C185: ("894634", "CWinThread constructor stores callback parameter in object +0x34."),
    0x0040C25D: ("e8f8feffff", "Thread factory constructs the CWinThread wrapper at 0x0040C15A."),
    0x0040C277: ("e84f030000", "Thread factory calls its MFC start routine 0x0040C5CB."),
    0x0040C63F: ("50", "Pushes the address of the thread parameter block for AfxBeginThread."),
    0x0040C640: ("6826cb4000", "Passes wrapper entry 0x0040CB26 to AfxBeginThread."),
    0x0040C64B: ("e8405c1200", "Calls AfxBeginThread helper 0x00532290."),
    0x005322FE: ("ff15f4a25500", "MFC helper calls the CreateThread IAT slot 0x0055A2F4."),
    0x0040CB3E: ("8b7b04", "MFC wrapper obtains the CWinThread object from its start argument."),
    0x0040CC19: ("8b4738", "MFC wrapper loads stored app callback from CWinThread object +0x38."),
    0x0040CC20: ("ff7734", "MFC wrapper pushes stored app callback parameter from object +0x34."),
    0x0040CC23: ("ffd0", "MFC wrapper invokes the stored app callback indirectly."),
    0x00409ED3: ("ffb718040000", "App worker waits on its slot event at record +0x418."),
    0x00409ED9: ("ff1588a25500", "App worker calls WaitForSingleObject through IAT slot 0x0055A288."),
    0x00409F60: ("e8cb7bffff", "After the event wait, app worker calls 0x00401B30."),
    0x00401C3E: ("e8cd030000", "Worker/update routine 0x00401B30 calls 0x00402010."),
    0x004025B4: ("e8d7060000", "The 0x00402010 worker calls the payload-transfer routine 0x00402C90."),
    0x004025B9: ("84c0", "The worker tests the transfer routine's AL result."),
    0x004025BB: ("750e", "A successful transfer result branches to the post-transfer path."),
    0x004025C4: ("83f805", "The worker compares the failed-transfer retry counter with five."),
    0x004025C7: ("7cdd", "The failed-transfer loop can retry the transfer while the counter is below five."),
    0x00402C90: ("558bec81ec2c080000a1c0d15a0033c5", "Transfer routine 0x00402C90 opens a stack frame and reserves its report buffer."),
    0x00402CE4: ("c70305570000", "Transfer routine initializes its first feature report with command prefix 05 57."),
    0x00402CF0: ("ff15e0a15500", "Transfer routine sends the 05 57 report through HID.DLL!HidD_SetFeature."),
    0x00402D20: ("66c7060677", "Transfer routine initializes each payload report with prefix 06 77."),
    0x00402DC5: ("8b15fce35b00", "Transfer routine loads the staged host-image byte length from global 0x005BE3FC."),
    0x00402DE6: ("a1f8e35b00", "Transfer routine loads the staged host-image pointer from global 0x005BE3F8."),
    0x00402E36: ("ff15e0a15500", "Transfer routine sends a payload report through HID.DLL!HidD_SetFeature."),
    0x00402F29: ("ff15e0a15500", "Transfer routine's terminal path calls HID.DLL!HidD_SetFeature."),
    0x00402F51: ("ff15e0a15500", "Transfer routine's final report call also targets HID.DLL!HidD_SetFeature."),
    0x0040265F: ("e84c030000", "After a successful transfer return, the worker calls verifier 0x004029B0."),
    0x004026FD: ("e87e010000", "Routine 0x00402010 calls read-to-command helper 0x00402880."),
    0x004028C1: ("66c7060572", "Helper initializes the six-byte feature buffer with prefix 05 72."),
    0x004028C6: ("8b35c8a15500", "Helper loads HidD_GetFeature from IAT slot 0x0055A1C8."),
    0x004028CD: ("ffd6", "Helper makes its first indirect HidD_GetFeature call."),
    0x004028F5: ("ffd6", "Helper makes its second indirect HidD_GetFeature call."),
    0x0040295A: ("ffd7", "Helper sends the later 05 77 report through its SetFeature pointer."),
}

CALL_EDGES = {
    0x00407C4F: 0x00409DE0,
    0x004096E1: 0x00409730,
    0x00409E2B: 0x0040C235,
    0x0040C25D: 0x0040C15A,
    0x0040C277: 0x0040C5CB,
    0x0040C64B: 0x00532290,
    0x00409F60: 0x00401B30,
    0x00401C3E: 0x00402010,
    0x004025B4: 0x00402C90,
    0x0040265F: 0x004029B0,
    0x004026FD: 0x00402880,
}

EXPECTED_IMPORTS = {
    0x0055A28C: ("KERNEL32.dll", "CreateEventW"),
    0x0055A288: ("KERNEL32.dll", "WaitForSingleObject"),
    0x0055A29C: ("KERNEL32.dll", "SetEvent"),
    0x0055A2F4: ("KERNEL32.dll", "CreateThread"),
    0x0055A1C8: ("HID.DLL", "HidD_GetFeature"),
    0x0055A1E0: ("HID.DLL", "HidD_SetFeature"),
}


def locate_dialog(pe: pefile.PE) -> tuple[int, int, bytes]:
    for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if resource_type.id != 5:  # RT_DIALOG
            continue
        for resource_name in resource_type.directory.entries:
            if resource_name.id != 102:
                continue
            for language in resource_name.directory.entries:
                if language.id == 1028:
                    info = language.data.struct
                    rva = int(info.OffsetToData)
                    size = int(info.Size)
                    return rva, size, pe.get_data(rva, size)
    raise ValueError("RT_DIALOG #102 language 1028 was not found")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True, help="hash-pinned 01BF updater PE")
    parser.add_argument("--out", type=Path, required=True, help="evidence CSV output path")
    args = parser.parse_args()

    data = args.binary.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if len(data) != EXPECTED_SIZE or digest != EXPECTED_SHA256:
        raise SystemExit(f"input size/SHA-256 mismatch: {len(data)} bytes, {digest}")
    pe = pefile.PE(data=data)
    if pe.OPTIONAL_HEADER.ImageBase != IMAGE_BASE or pe.FILE_HEADER.Machine != 0x14C:
        raise SystemExit("expected x86 PE at preferred base 0x00400000")
    text_section = next((section for section in pe.sections if section.Name.rstrip(bytes([0])) == b".text"), None)
    if text_section is None or hashlib.sha256(text_section.get_data()).hexdigest() != EXPECTED_TEXT_SHA256:
        raise SystemExit(".text section hash mismatch")

    resource_rva, resource_size, resource = locate_dialog(pe)
    resource_hash = hashlib.sha256(resource).hexdigest()
    if (resource_rva != RESOURCE_RVA or resource_size != RESOURCE_SIZE
            or resource_hash != RESOURCE_SHA256
            or pe.get_offset_from_rva(resource_rva) != RESOURCE_RAW_OFFSET):
        raise SystemExit("dialog resource address/size/hash mismatch")
    dialog = parse_dialog(resource)
    start_controls = [control for control in dialog["controls"] if control["id"] == 1]
    if (not dialog["extended"] or dialog["title"] != "Update Tool"
            or dialog["item_count"] != 40 or len(start_controls) != 1
            or start_controls[0]["class"] != "BUTTON"
            or start_controls[0]["caption"] != "全部開始"):
        raise SystemExit("dialog #102 title/control metadata mismatch")

    def raw_va(va: int, size: int) -> bytes:
        return data[pe.get_offset_from_rva(va - IMAGE_BASE):pe.get_offset_from_rva(va - IMAGE_BASE) + size]

    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    for va, (hex_bytes, note) in FACTS.items():
        expected = bytes.fromhex(hex_bytes)
        actual = raw_va(va, len(expected))
        if actual != expected:
            raise SystemExit(f"0x{va:08X}: expected {expected.hex()}, got {actual.hex()}")

    for callsite, expected_target in CALL_EDGES.items():
        instruction = next(decoder.disasm(raw_va(callsite, 5), callsite, count=1), None)
        if (instruction is None or instruction.mnemonic != "call" or len(instruction.operands) != 1
                or instruction.operands[0].type != X86_OP_IMM
                or instruction.operands[0].imm != expected_target):
            raise SystemExit(f"call-edge mismatch at 0x{callsite:08X}")

    map_offset = pe.get_offset_from_rva(MAP_DESCRIPTOR_VA - IMAGE_BASE)
    descriptor = struct.unpack_from("<2I", data, map_offset)
    if descriptor != (0x00415EB6, MAP_ENTRIES_VA):
        raise SystemExit(f"MFC message-map descriptor mismatch: {descriptor!r}")
    row_offset = pe.get_offset_from_rva(MAP_ROW_VA - IMAGE_BASE)
    row = struct.unpack_from("<6I", data, row_offset)
    if row != MAP_ROW:
        raise SystemExit(f"MFC All Start row mismatch: {row!r}")

    imports = {
        entry.address: (
            library.dll.decode(errors="replace"),
            entry.name.decode(errors="replace") if entry.name else "",
        )
        for library in pe.DIRECTORY_ENTRY_IMPORT
        for entry in library.imports
    }
    for slot, expected in EXPECTED_IMPORTS.items():
        if imports.get(slot) != expected:
            raise SystemExit(f"IAT mismatch at 0x{slot:08X}: {imports.get(slot)!r}")

    scope = "static file evidence only; no updater execution, HID access, report transmission, or firmware write"
    rows: list[dict[str, str]] = [
        {"binary_sha256": digest, "evidence_va": "file", "bytes": "", "observation": f"{len(data)}-byte PE32 x86 package; .text SHA-256 {EXPECTED_TEXT_SHA256}.", "scope": scope},
        {"binary_sha256": digest, "evidence_va": f"RVA 0x{RESOURCE_RVA:08X} / file 0x{RESOURCE_RAW_OFFSET:08X}", "bytes": "", "observation": f"RT_DIALOG #102 lang 1028; {resource_size} bytes; SHA-256 {resource_hash}; title={dialog['title']!r}; controls={dialog['item_count']}.", "scope": scope},
        {"binary_sha256": digest, "evidence_va": "resource control #1", "bytes": "", "observation": "BUTTON caption is 全部開始 (All Start); its ID is 1.", "scope": scope},
        {"binary_sha256": digest, "evidence_va": f"0x{MAP_DESCRIPTOR_VA:08X}", "bytes": raw_va(MAP_DESCRIPTOR_VA, 8).hex().upper(), "observation": f"MFC map descriptor points to base map 0x00415EB6 and entries 0x{MAP_ENTRIES_VA:08X}.", "scope": scope},
        {"binary_sha256": digest, "evidence_va": f"0x{MAP_ROW_VA:08X}", "bytes": raw_va(MAP_ROW_VA, 24).hex().upper(), "observation": "AFX_MSGMAP_ENTRY {WM_COMMAND=0x111, code=0, id=1..1, signature=0x3A, handler=0x004096A0}.", "scope": scope},
    ]
    for va, (hex_bytes, note) in FACTS.items():
        rows.append({"binary_sha256": digest, "evidence_va": f"0x{va:08X}", "bytes": raw_va(va, len(bytes.fromhex(hex_bytes))).hex().upper(), "observation": note, "scope": scope})
    for slot, (_, name) in EXPECTED_IMPORTS.items():
        rows.append({"binary_sha256": digest, "evidence_va": f"0x{slot:08X}", "bytes": "", "observation": f"IAT resolves to {imports[slot][0]}!{name}.", "scope": scope})

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=("binary_sha256", "evidence_va", "bytes", "observation", "scope"))
        writer.writeheader()
        writer.writerows(rows)
    print(f"Verified package/resource hashes, All Start MFC map row, {len(FACTS)} instruction byte facts, {len(CALL_EDGES)} direct call edges, and {len(EXPECTED_IMPORTS)} IAT mappings.")
    print(f"Wrote {len(rows)} evidence rows to {args.out}")
    print("Static chain reaches the 0x00402C90 host-image transfer routine and post-transfer verification conditionally; runtime execution and device effects remain unobserved.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
