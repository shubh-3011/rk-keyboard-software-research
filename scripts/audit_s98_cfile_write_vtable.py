#!/usr/bin/env python3
"""Verify the S98 01BF updater's RTTI-identified CFile::Write boundary."""

from __future__ import annotations

import argparse
import csv
import hashlib
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_IMM, CS_OP_MEM
import pefile

EXPECTED_SHA256 = "475e8d7b97adfbd861c3b7b16721ad598df04095b81228e381319b6be23129e6"
EXPECTED_SIZE = 2_140_176
EXPECTED_TEXT_SHA256 = "3643f4d710a296b62598d3d8b71c7dd9dcab049ebbb540588b11757ccd5f03ed"
IMAGE_BASE = 0x00400000
VTABLE = 0x0055F878
WRITE_METHOD = 0x0042D26F
WRITE_IAT = 0x0055A378
EXPECTED_VPTR_STORES = [0x0042C9E4, 0x0042CA10, 0x0042CA9A]
EXPECTED_VCALLS_3C = [
    0x0040E2A6, 0x0041298C, 0x004129AF, 0x00417D1A, 0x00419A29,
    0x0041CA16, 0x0041CD65, 0x00424963, 0x00438532, 0x0043954B,
    0x004396B0, 0x00439B11, 0x0043A6E0, 0x0043A8D9, 0x0045F267,
    0x0047006D, 0x004710BE, 0x004906C3, 0x004C51CD, 0x004C51F1,
    0x004DB0B1, 0x00507CB8, 0x00507CD5, 0x00507CEA,
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    data = args.binary.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if len(data) != EXPECTED_SIZE or digest != EXPECTED_SHA256:
        raise SystemExit("input size/SHA-256 mismatch")
    pe = pefile.PE(data=data)
    if pe.OPTIONAL_HEADER.ImageBase != IMAGE_BASE or pe.FILE_HEADER.Machine != 0x14C:
        raise SystemExit("expected x86 PE at preferred base")

    text = next((s for s in pe.sections if s.Name.rstrip(b"\0") == b".text"), None)
    rdata = next((s for s in pe.sections if s.Name.rstrip(b"\0") == b".rdata"), None)
    if text is None or rdata is None:
        raise SystemExit("expected .text and .rdata sections")
    if hashlib.sha256(text.get_data()).hexdigest() != EXPECTED_TEXT_SHA256:
        raise SystemExit(".text SHA-256 mismatch")

    def raw(va: int, size: int) -> bytes:
        offset = pe.get_offset_from_rva(va - IMAGE_BASE)
        return data[offset:offset + size]

    def u32(va: int) -> int:
        return struct.unpack("<I", raw(va, 4))[0]

    def c_string(va: int, limit: int = 256) -> bytes:
        return raw(va, limit).split(b"\0", 1)[0]

    def text_va(va: int) -> bool:
        rva = va - IMAGE_BASE
        return text.VirtualAddress <= rva < text.VirtualAddress + max(text.Misc_VirtualSize, text.SizeOfRawData)

    # The word before this vftable is the MSVC Complete Object Locator pointer.
    col = u32(VTABLE - 4)
    col_fields = [u32(col + offset) for offset in (0, 4, 8, 12, 16)]
    if col_fields[:3] != [0, 0, 0]:
        raise SystemExit(f"unexpected x86 Complete Object Locator header: {col_fields[:3]}")
    type_descriptor, hierarchy = col_fields[3], col_fields[4]
    type_name = c_string(type_descriptor + 8)
    if type_name != b".?AVCFile@@":
        raise SystemExit(f"unexpected vtable RTTI name: {type_name!r}")

    hierarchy_fields = [u32(hierarchy + offset) for offset in (0, 4, 8, 12)]
    base_count, base_array = hierarchy_fields[2], hierarchy_fields[3]
    base_names = []
    for index in range(base_count):
        base_descriptor = u32(base_array + index * 4)
        base_type = u32(base_descriptor)
        base_names.append(c_string(base_type + 8))
    if base_names != [b".?AVCFile@@", b".?AVCObject@@"]:
        raise SystemExit(f"unexpected CFile hierarchy: {base_names!r}")

    # Count consecutive entries that point into executable code.
    vtable_entries: list[int] = []
    for index in range(64):
        entry = u32(VTABLE + index * 4)
        if not text_va(entry):
            break
        vtable_entries.append(entry)
    if len(vtable_entries) != 22 or vtable_entries[15] != WRITE_METHOD:
        raise SystemExit("CFile vtable length or slot-15 Write method mismatch")

    iat = {
        imp.address: (
            library.dll.decode(errors="replace").upper(),
            imp.name.decode(errors="replace") if imp.name else "",
        )
        for library in pe.DIRECTORY_ENTRY_IMPORT
        for imp in library.imports
    }
    if iat.get(WRITE_IAT) != ("KERNEL32.DLL", "WriteFile"):
        raise SystemExit(f"unexpected WriteFile IAT mapping: {iat.get(WRITE_IAT)!r}")
    if raw(WRITE_METHOD, 10) != bytes.fromhex("558bec56578b7d0c8bf1"):
        raise SystemExit("CFile::Write parameter/setup bytes mismatch")
    if raw(WRITE_METHOD + 0x0E, 19) != bytes.fromhex("6a008d450c5057ff7508ff7604ff1578a35500"):
        raise SystemExit("CFile::WriteFile argument/IAT sequence mismatch")
    if raw(WRITE_METHOD + 0x39, 6) != bytes.fromhex("5f5e5dc20800"):
        raise SystemExit("CFile::Write successful-return sequence mismatch")

    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    instructions = list(decoder.disasm(text.get_data(), IMAGE_BASE + text.VirtualAddress))
    direct_wrapper_calls = [
        ins.address for ins in instructions
        if ins.mnemonic == "call" and ins.operands
        and ins.operands[0].type == CS_OP_IMM and ins.operands[0].imm == WRITE_METHOD
    ]
    if direct_wrapper_calls:
        raise SystemExit(f"unexpected direct calls to CFile::Write: {direct_wrapper_calls!r}")

    vptr_stores = [
        ins.address for ins in instructions
        if ins.mnemonic == "mov" and len(ins.operands) == 2
        and ins.operands[0].type == CS_OP_MEM
        and ins.operands[0].mem.disp == 0
        and ins.operands[1].type == CS_OP_IMM
        and ins.operands[1].imm == VTABLE
    ]
    if vptr_stores != EXPECTED_VPTR_STORES:
        raise SystemExit(f"CFile vptr-store census mismatch: {[hex(x) for x in vptr_stores]}")

    virtual_slot_calls = [
        ins.address for ins in instructions
        if ins.mnemonic == "call" and ins.operands
        and ins.operands[0].type == CS_OP_MEM
        and ins.operands[0].mem.disp == 0x3C
    ]
    if virtual_slot_calls != EXPECTED_VCALLS_3C:
        raise SystemExit(
            "+0x3c indirect-call census mismatch: "
            f"{[hex(x) for x in virtual_slot_calls]}"
        )

    wrapper_pointer = struct.pack("<I", WRITE_METHOD)
    wrapper_hits = []
    cursor = 0
    while (cursor := data.find(wrapper_pointer, cursor)) >= 0:
        wrapper_hits.append(cursor)
        cursor += len(wrapper_pointer)
    expected_wrapper_file_offset = pe.get_offset_from_rva(VTABLE + 15 * 4 - IMAGE_BASE)
    if wrapper_hits != [expected_wrapper_file_offset]:
        raise SystemExit(f"unexpected raw CFile::Write pointer locations: {[hex(x) for x in wrapper_hits]}")

    rows = [
        ("binary", "SHA-256", digest, "Hash-pinned S98 01BF updater executable."),
        ("RTTI", f"0x{col:08X}", type_name.decode(), "x86 Complete Object Locator identifies CFile."),
        ("RTTI hierarchy", f"0x{hierarchy:08X}", " -> ".join(x.decode() for x in base_names), "Static base descriptors identify CFile and CObject."),
        ("vtable", f"0x{VTABLE:08X}", f"{len(vtable_entries)} code entries", "CFile vftable begins at this .rdata address."),
        ("vtable slot", f"0x{VTABLE + 15 * 4:08X}", f"0x{WRITE_METHOD:08X}", "Slot 15 (+0x3c) points to the WriteFile wrapper."),
        ("import", f"0x{WRITE_IAT:08X}", "KERNEL32.DLL!WriteFile", "Import table identity; runtime execution is unobserved."),
        ("direct caller census", f"0x{WRITE_METHOD:08X}", "0 direct calls", "No direct relative call to this entry occurs in decoded .text."),
        ("vptr installation", ";".join(f"0x{x:08X}" for x in vptr_stores), "3 stores", "Static mov-immediate stores install this vftable."),
        ("indirect call census", "+0x3c", f"{len(virtual_slot_calls)} candidates", "Receiver class and signature are unresolved per candidate."),
    ]
    rows.extend(("indirect candidate", f"0x{va:08X}", "call [reg+0x3c]", "Candidate only; not attributed to CFile without receiver proof.")
                for va in virtual_slot_calls)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(("evidence_kind", "evidence_va", "observation", "scope"))
        writer.writerows(rows)

    print(f"Verified {len(vtable_entries)} CFile vtable entries; slot +0x3c is 0x{WRITE_METHOD:08X}.")
    print(f"Verified zero direct wrapper callers, {len(vptr_stores)} vptr stores, and {len(virtual_slot_calls)} generic +0x3c call candidates.")
    print("The indirect candidates are not attributed to CFile::Write without receiver and argument proof.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
