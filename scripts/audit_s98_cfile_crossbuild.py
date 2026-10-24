#!/usr/bin/env python3
"""Compare the RTTI-identified S98 CFile::Write boundary in two updater builds."""

from __future__ import annotations

import argparse
import csv
import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_MEM
import pefile


IMAGE_BASE = 0x00400000
VTABLE = 0x0055F878
WRITE_IAT = 0x0055A378


@dataclass(frozen=True)
class Build:
    label: str
    sha256: str
    text_sha256: str
    size: int
    method: int
    write_call: int


BUILDS = (
    Build(
        "01BF", "475e8d7b97adfbd861c3b7b16721ad598df04095b81228e381319b6be23129e6",
        "3643f4d710a296b62598d3d8b71c7dd9dcab049ebbb540588b11757ccd5f03ed",
        2_140_176, 0x0042D26F, 0x0042D28A,
    ),
    Build(
        "0223", "399020b7b66fda67cc6c69ae81336d67024204cbc9e15ffabde26a2cccd072ca",
        "bfc4506d668ee1ff8809a0455abd5f589545e45ff1d0b358a5fe3d4871e85ff2",
        2_140_176, 0x0042CFDD, 0x0042CFF8,
    ),
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--01bf-binary", required=True, type=Path)
    parser.add_argument("--0223-binary", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    paths = (args.__dict__["01bf_binary"], args.__dict__["0223_binary"])
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    evidence: list[tuple[str, str, str, str, str]] = []
    observed_text_hashes: list[str] = []

    for build, path in zip(BUILDS, paths, strict=True):
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if len(data) != build.size or digest != build.sha256:
            raise SystemExit(f"{build.label}: input size/SHA-256 mismatch")
        pe = pefile.PE(data=data)
        if pe.FILE_HEADER.Machine != 0x14C or pe.OPTIONAL_HEADER.ImageBase != IMAGE_BASE:
            raise SystemExit(f"{build.label}: expected x86 PE at 0x00400000")

        sections = {section.Name.rstrip(b"\0"): section for section in pe.sections}
        text = sections.get(b".text")
        if text is None:
            raise SystemExit(f"{build.label}: missing .text section")
        text_hash = hashlib.sha256(text.get_data()).hexdigest()
        if text_hash != build.text_sha256:
            raise SystemExit(f"{build.label}: .text SHA-256 mismatch")
        observed_text_hashes.append(text_hash)

        def raw(va: int, size: int) -> bytes:
            offset = pe.get_offset_from_rva(va - IMAGE_BASE)
            return data[offset:offset + size]

        def u32(va: int) -> int:
            return struct.unpack("<I", raw(va, 4))[0]

        def c_string(va: int, size: int = 256) -> bytes:
            return raw(va, size).split(b"\0", 1)[0]

        def is_text_va(va: int) -> bool:
            rva = va - IMAGE_BASE
            return text.VirtualAddress <= rva < text.VirtualAddress + max(
                text.Misc_VirtualSize, text.SizeOfRawData
            )

        col = u32(VTABLE - 4)
        col_fields = [u32(col + offset) for offset in (0, 4, 8, 12, 16)]
        if col_fields[:3] != [0, 0, 0]:
            raise SystemExit(f"{build.label}: unexpected x86 Complete Object Locator")
        type_descriptor, hierarchy = col_fields[3], col_fields[4]
        type_name = c_string(type_descriptor + 8)
        if type_name != b".?AVCFile@@":
            raise SystemExit(f"{build.label}: unexpected RTTI type {type_name!r}")

        hierarchy_fields = [u32(hierarchy + offset) for offset in (0, 4, 8, 12)]
        base_count, base_array = hierarchy_fields[2], hierarchy_fields[3]
        base_names = []
        for index in range(base_count):
            base_descriptor = u32(base_array + index * 4)
            base_names.append(c_string(u32(base_descriptor) + 8))
        if base_names != [b".?AVCFile@@", b".?AVCObject@@"]:
            raise SystemExit(f"{build.label}: unexpected CFile hierarchy {base_names!r}")

        vtable_entries = []
        for index in range(64):
            entry = u32(VTABLE + index * 4)
            if not is_text_va(entry):
                break
            vtable_entries.append(entry)
        if len(vtable_entries) != 22 or vtable_entries[15] != build.method:
            raise SystemExit(f"{build.label}: CFile vtable slot/length mismatch")

        imports = {
            imp.address: (
                library.dll.decode(errors="replace").upper(),
                imp.name.decode(errors="replace") if imp.name else "",
            )
            for library in pe.DIRECTORY_ENTRY_IMPORT
            for imp in library.imports
        }
        if imports.get(WRITE_IAT) != ("KERNEL32.DLL", "WriteFile"):
            raise SystemExit(f"{build.label}: WriteFile IAT identity mismatch")

        instructions = list(decoder.disasm(text.get_data(), IMAGE_BASE + text.VirtualAddress))
        write_calls = [
            ins.address for ins in instructions
            if ins.mnemonic == "call" and ins.operands
            and ins.operands[0].type == CS_OP_MEM
            and ins.operands[0].mem.base == 0
            and ins.operands[0].mem.index == 0
            and ins.operands[0].mem.disp == WRITE_IAT
        ]
        if write_calls != [build.write_call]:
            raise SystemExit(f"{build.label}: WriteFile import-call census mismatch: {write_calls!r}")

        method_bytes = raw(build.method, 0x50)
        method_instructions = list(decoder.disasm(method_bytes, build.method))
        method_mnemonics = [(ins.mnemonic, ins.op_str) for ins in method_instructions]
        required = [
            ("mov", "edi, dword ptr [ebp + 0xc]"),
            ("mov", "esi, ecx"),
            ("push", "dword ptr [ebp + 8]"),
            ("push", "dword ptr [esi + 4]"),
            ("call", "dword ptr [0x55a378]"),
            ("ret", "8"),
        ]
        cursor = 0
        for fact in required:
            try:
                cursor = method_mnemonics.index(fact, cursor) + 1
            except ValueError as error:
                raise SystemExit(f"{build.label}: CFile::Write instruction shape mismatch at {fact}") from error

        generic_slot_calls = [
            ins.address for ins in instructions
            if ins.mnemonic == "call" and ins.operands
            and ins.operands[0].type == CS_OP_MEM
            and ins.operands[0].mem.disp == 0x3C
        ]
        if len(generic_slot_calls) != 24:
            raise SystemExit(
                f"{build.label}: expected 24 generic +0x3c call candidates, "
                f"found {len(generic_slot_calls)}"
            )
        evidence.extend([
            ("binary", build.label, "SHA-256", digest, "Hash-pinned updater executable."),
            ("code", build.label, ".text SHA-256", text_hash, "Distinct code-section profile; hash does not imply behavior equivalence."),
            ("RTTI", build.label, f"COL 0x{col:08X}", type_name.decode(), "MSVC Complete Object Locator TypeDescriptor names CFile."),
            ("RTTI hierarchy", build.label, f"0x{hierarchy:08X}", " -> ".join(name.decode() for name in base_names), "Static base descriptors identify CFile and CObject."),
            ("vtable", build.label, f"0x{VTABLE:08X}", f"{len(vtable_entries)} executable entries", "Same vtable address and entry count in both builds."),
            ("vtable slot", build.label, f"slot 15 / +0x3C", f"0x{build.method:08X}", "CFile Write method slot, independently resolved in each image."),
            ("import", build.label, f"IAT 0x{WRITE_IAT:08X}", "KERNEL32.DLL!WriteFile", "Import-table identity."),
            ("implementation", build.label, f"0x{build.method:08X}", f"call at 0x{build.write_call:08X}; ret 8", "Static instruction shape uses ECX object, buffer/count stack arguments, and the object's handle field."),
            ("generic virtual calls", build.label, "+0x3C", f"{len(generic_slot_calls)} sites", "Same candidate census; each receiver's runtime class is not proven by this comparison."),
        ])

    if len(set(observed_text_hashes)) != len(BUILDS):
        raise SystemExit("expected distinct .text hashes for the two code builds")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(("evidence_kind", "build", "address_or_field", "observation", "scope"))
        writer.writerows(evidence)
    print("Verified both hash-pinned S98 updater builds: CFile RTTI, 22-entry vtable, slot +0x3C, and WriteFile wrapper shape.")
    print("Both have distinct .text hashes and 24 generic +0x3C call candidates; runtime receiver identity remains unresolved by this comparison.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
