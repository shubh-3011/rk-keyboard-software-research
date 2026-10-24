#!/usr/bin/env python3
"""Verify a hash-pinned R99 CreateFileA-to-CH375 call path.

This reads the supplied RK Driver.exe as PE data and disassembles its
executable section. It does not launch the program or open any device.
Requires the repository's existing pefile and capstone packages.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import sys
from dataclasses import dataclass
from pathlib import Path

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM


EXPECTED_SHA256 = "61dd118400a4652ba053db6ceb87cdd865e183f59822948ea9018da218aec2e5"
EXPECTED_CREATEFILE_IAT = 0x0057B0A8
EXPECTED_DIRECT_CALLS = (0x0041AED9, 0x00475020, 0x00475358)
EXPECTED_CREATEFILE_THUNK = 0x00487760
DEFAULT_OUTPUT = Path("docs/rk-r99-createfile-ch375-path-evidence-2026-10-25.csv")


@dataclass(frozen=True)
class Evidence:
    address: int
    claim: str
    classification: str = "proven statically"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def format_instruction(instruction) -> str:
    return f"{instruction.mnemonic} {instruction.op_str}".strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path, help="hash-matched R99 RK Driver.exe")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help=f"evidence CSV (default: {DEFAULT_OUTPUT})")
    parser.add_argument("--overwrite", action="store_true", help="replace the exact named evidence CSV")
    args = parser.parse_args()

    binary = args.binary.resolve()
    output = args.output.resolve()
    if not binary.is_file():
        parser.error(f"binary not found: {binary}")
    if output.exists() and not args.overwrite:
        parser.error(f"refusing to replace existing output: {output}; pass --overwrite")

    digest = sha256(binary)
    if digest != EXPECTED_SHA256:
        raise ValueError(f"input hash mismatch: {digest}; expected {EXPECTED_SHA256}")

    pe = pefile.PE(str(binary), fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    if pe.FILE_HEADER.Machine != 0x014C or pe.OPTIONAL_HEADER.ImageBase != 0x00400000:
        raise ValueError("unexpected machine or image base")

    createfile_imports = [
        item.address
        for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
        for item in descriptor.imports
        if descriptor.dll.lower() == b"kernel32.dll" and item.name == b"CreateFileA"
    ]
    if createfile_imports != [EXPECTED_CREATEFILE_IAT]:
        raise ValueError(f"unexpected CreateFileA IAT entries: {createfile_imports!r}")

    expected_helper_imports = {
        b"CH375SetExclusive": 0x0057B03C,
        b"CH375SetTimeout": 0x0057B038,
        b"CH375WriteData": 0x0057B034,
        b"CH375ReadData": 0x0057B030,
    }
    found_helper_imports = {
        item.name: item.address
        for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
        if descriptor.dll.lower() == b"ch375dll.dll"
        for item in descriptor.imports
        if item.name in expected_helper_imports
    }
    if found_helper_imports != expected_helper_imports:
        raise ValueError(f"unexpected CH375 helper IAT entries: {found_helper_imports!r}")

    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    decoded = []
    for section in pe.sections:
        if section.Characteristics & 0x20000000:
            address = int(pe.OPTIONAL_HEADER.ImageBase) + int(section.VirtualAddress)
            decoded.extend(decoder.disasm(section.get_data(), address))
    by_address = {instruction.address: instruction for instruction in decoded}

    direct_calls = tuple(
        instruction.address
        for instruction in decoded
        if instruction.mnemonic == "call"
        and len(instruction.operands) == 1
        and instruction.operands[0].type == X86_OP_MEM
        and instruction.operands[0].mem.base == 0
        and instruction.operands[0].mem.index == 0
        and instruction.operands[0].mem.disp == EXPECTED_CREATEFILE_IAT
    )
    if direct_calls != EXPECTED_DIRECT_CALLS:
        raise ValueError(f"CreateFileA direct-call census changed: {tuple(hex(x) for x in direct_calls)}")

    def require(address: int, expected: str) -> None:
        instruction = by_address.get(address)
        if instruction is None or format_instruction(instruction) != expected:
            actual = "missing" if instruction is None else format_instruction(instruction)
            raise ValueError(f"instruction mismatch at 0x{address:08x}: {actual!r}, expected {expected!r}")

    landmarks = {
        0x0041AE48: "lea eax, [ecx + 5]",
        0x0041AE66: "mov ecx, 0x4348",
        0x0041AE56: "call 0x401000",
        0x0041AE61: "call 0x401006",
        0x0041AE6B: "cmp ax, cx",
        0x0041AE73: "cmp eax, 0x55e0",
        0x0041AE7B: "call 0x40100c",
        0x0041AE80: "mov edx, edi",
        0x0041AE89: "mov byte ptr [edx + eax - 1], cl",
        0x0041AEB2: "cmp esi, 0x10",
        0x0041AEC4: "push 0",
        0x0041AEC6: "push 0x80",
        0x0041AECB: "push 3",
        0x0041AECD: "push 0",
        0x0041AECF: "push 3",
        0x0041AED1: "push 0xc0000000",
        0x0041AED6: "push dword ptr [ebp - 4]",
        0x0041AED9: "call dword ptr [0x57b0a8]",
        0x0041AEDF: "mov esi, eax",
        0x0041AEE1: "cmp esi, -1",
        0x0041AEE4: "jne 0x41aeef",
        0x0041AEE8: "or eax, eax",
        0x0041AEEF: "push 1",
        0x0041AEF1: "push esi",
        0x0041AEF2: "call 0x401018",
        0x0041AEF7: "push 0x3e8",
        0x0041AEFC: "push 0x3e8",
        0x0041AF01: "push esi",
        0x0041AF02: "call 0x40101e",
        0x0041AF17: "mov eax, esi",
        0x0041AA99: "call 0x41ae40",
        0x0041AA9E: "mov dword ptr [edi], eax",
        0x0041AAA0: "test eax, eax",
        0x0041AAA2: "je 0x41ac6b",
        0x0041AABE: "push ecx",
        0x0041AABF: "push dword ptr [edi]",
        0x0041AACB: "call 0x41af20",
        0x0041AF49: "mov dword ptr [esp + 8], 0x281",
        0x0041AF55: "mov dword ptr [esp + 4], 4",
        0x0041AF64: "call 0x401024",
        0x0041AF8D: "push eax",
        0x0041AF98: "push esi",
        0x0041AFA1: "call 0x40102a",
        0x0041B009: "mov dword ptr [esp + 8], 0x283",
        0x0041B01D: "push eax",
        0x0041B023: "push esi",
        0x0041B024: "call 0x401024",
        0x0041B0D6: "call 0x401024",
    }
    for address, expected in landmarks.items():
        require(address, expected)

    for address, expected in {
        0x00401018: "jmp dword ptr [0x57b03c]",
        0x0040101E: "jmp dword ptr [0x57b038]",
        0x00401024: "jmp dword ptr [0x57b034]",
        0x0040102A: "jmp dword ptr [0x57b030]",
        EXPECTED_CREATEFILE_THUNK: "jmp dword ptr [0x57b0a8]",
    }.items():
        require(address, expected)

    createfile_arguments = {
        0x0041AEC4: "template handle is null",
        0x0041AEC6: "flags and attributes are 0x80 (FILE_ATTRIBUTE_NORMAL)",
        0x0041AECB: "creation disposition is 3 (OPEN_EXISTING)",
        0x0041AECD: "security attributes are null",
        0x0041AECF: "share mode is 3 (read and write sharing)",
        0x0041AED1: "desired access is 0xC0000000 (GENERIC_READ | GENERIC_WRITE)",
        0x0041AED6: "filename pointer is the first path in the object buffer",
    }
    evidence = [
        Evidence(EXPECTED_CREATEFILE_IAT, "KERNEL32!CreateFileA import-table entry; sole IAT VA in this image"),
        *[Evidence(address, "direct CreateFileA IAT call; other direct paths are outside this focused trace") for address in direct_calls],
        Evidence(EXPECTED_CREATEFILE_THUNK, "one-instruction IAT tail-jump thunk for CreateFileA"),
        Evidence(0x0041AA99, "R99 worker calls the CH375-path opener at 0x0041AE40"),
        Evidence(0x0041AE48, "opener's path-list base is object+5"),
        Evidence(0x0041AE56, "enumeration calls CH375OpenDevice(index)"),
        Evidence(0x0041AE61, "enumeration calls CH375GetUsbID(index)"),
        Evidence(0x0041AE66, "VID comparison immediate is 0x4348"),
        Evidence(0x0041AE6B, "VID low-word comparison uses 0x4348"),
        Evidence(0x0041AE73, "PID high-word comparison uses 0x55E0"),
        Evidence(0x0041AE7B, "matching candidate calls CH375GetDeviceName(index) before copying its path"),
        Evidence(0x0041AE89, "returned device-name bytes are copied into the opener's inline path list"),
        Evidence(0x0041AEB2, "candidate loop terminates at 16 helper indices"),
        *[Evidence(address, claim) for address, claim in createfile_arguments.items()],
        Evidence(0x0041AED9, "CreateFileA result is copied to ESI"),
        Evidence(0x0041AEE1, "opener compares returned handle against -1"),
        Evidence(0x0041AEF2, "returned handle and exclusive flag 1 are passed to CH375SetExclusive"),
        Evidence(0x0041AF02, "returned handle and two 1000 values are passed to CH375SetTimeout"),
        Evidence(0x0041AF17, "opener returns ESI, the CreateFileA result, in EAX"),
        Evidence(0x0041AA9E, "worker stores opener result in its object handle field"),
        Evidence(0x0041AAA0, "worker tests the handle only for zero before its nonzero path"),
        Evidence(0x0041AACB, "worker passes stored handle to the transfer routine at 0x0041AF20"),
        Evidence(0x0041AF49, "transfer routine constructs request dword 0x281"),
        Evidence(0x0041AF55, "transfer routine supplies a four-byte request length"),
        Evidence(0x0041AF64, "transfer routine calls CH375WriteData"),
        Evidence(0x0041AFA1, "transfer routine calls CH375ReadData after the write branch"),
        Evidence(0x0041B009, "separate worker constructs request dword 0x283"),
        Evidence(0x0041B024, "separate worker calls CH375WriteData"),
        Evidence(0x0041B0D6, "chunked worker calls CH375WriteData"),
    ]

    fieldnames = ["binary", "binary_sha256", "evidence_id", "address_va", "file_offset", "bytes", "instruction", "claim", "classification"]
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        for index, item in enumerate(evidence, 1):
            instruction = by_address.get(item.address)
            if instruction:
                offset = pe.get_offset_from_rva(item.address - int(pe.OPTIONAL_HEADER.ImageBase))
                raw = instruction.bytes.hex(" ")
                text = format_instruction(instruction)
            else:
                offset = ""
                raw = ""
                text = ""
            writer.writerow({
                "binary": binary.name,
                "binary_sha256": digest,
                "evidence_id": f"R99-CFA-{index:02d}",
                "address_va": f"0x{item.address:08x}",
                "file_offset": f"0x{offset:x}" if offset != "" else "",
                "bytes": raw,
                "instruction": text,
                "claim": item.claim,
                "classification": item.classification,
            })

    print(f"Input SHA-256: {digest}")
    print(f"CreateFileA IAT VA: 0x{EXPECTED_CREATEFILE_IAT:08x}")
    print(f"CreateFileA direct callsites: {', '.join(f'0x{x:08x}' for x in direct_calls)}")
    print(f"Evidence rows written: {len(evidence)} -> {output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, pefile.PEFormatError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(2)
