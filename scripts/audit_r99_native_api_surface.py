#!/usr/bin/env python3
"""Inventory R99 package PE imports and direct IAT call/jump candidates.

This is a static linear sweep, not a control-flow graph. It does not execute
the package or prove that a candidate instruction is reachable.
Requires the existing Python packages pefile and capstone.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import sys
from pathlib import Path

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG


IMPORTS_NAME = "rk-r99-native-api-imports.csv"
CALLS_NAME = "rk-r99-native-api-callsite-candidates.csv"
SYSCALLS_NAME = "rk-r99-native-syscall-candidates.csv"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def decode_name(value: bytes | None) -> str:
    return value.decode("ascii", "replace") if value else ""


def imports_for(pe: pefile.PE, kind: str):
    directory = "DIRECTORY_ENTRY_IMPORT" if kind == "normal" else "DIRECTORY_ENTRY_DELAY_IMPORT"
    for descriptor in getattr(pe, directory, []):
        dll = decode_name(descriptor.dll)
        for item in descriptor.imports:
            yield {
                "dll": dll,
                "api": decode_name(item.name) or (f"ordinal_{item.ordinal}" if item.ordinal else ""),
                "ordinal": item.ordinal if item.ordinal is not None else "",
                "iat_va": int(item.address),
                "iat_rva": int(item.address) - int(pe.OPTIONAL_HEADER.ImageBase),
                "kind": kind,
            }


def executable_sections(pe: pefile.PE):
    for section in pe.sections:
        if section.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
            name = section.Name.rstrip(b"\0").decode("ascii", "replace")
            yield name, section


def scan_pe(path: Path, root: Path):
    binary_hash = sha256(path)
    pe = pefile.PE(str(path), fast_load=True)
    pe.parse_data_directories(
        directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
        ]
    )
    if pe.FILE_HEADER.Machine != 0x14C:
        raise ValueError(f"expected x86 PE, got machine 0x{pe.FILE_HEADER.Machine:04x}")

    imports = list(imports_for(pe, "normal")) + list(imports_for(pe, "delay"))
    by_iat = {item["iat_va"]: item for item in imports}
    disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
    disassembler.detail = True

    decoded = []
    for section_name, section in executable_sections(pe):
        va = int(pe.OPTIONAL_HEADER.ImageBase) + int(section.VirtualAddress)
        for instruction in disassembler.disasm(section.get_data(), va):
            file_offset = pe.get_offset_from_rva(instruction.address - int(pe.OPTIONAL_HEADER.ImageBase))
            decoded.append((section_name, instruction, file_offset))

    # A thunk is recognized only when its first decoded instruction jumps
    # through an exact imported IAT slot.
    thunk_to_import = {}
    for _section, instruction, _offset in decoded:
        if instruction.mnemonic != "jmp" or len(instruction.operands) != 1:
            continue
        operand = instruction.operands[0]
        if operand.type == X86_OP_MEM and operand.mem.base == 0 and operand.mem.index == 0:
            item = by_iat.get(int(operand.mem.disp))
            if item:
                thunk_to_import[instruction.address] = item

    call_rows = []
    syscall_rows = []
    register_indirect = 0
    direct_calls = 0
    for section_name, instruction, file_offset in decoded:
        mnemonic = instruction.mnemonic
        if mnemonic in {"call", "jmp"}:
            is_call = mnemonic == "call"
            if is_call:
                direct_calls += 1
            item = None
            candidate_type = ""
            if len(instruction.operands) == 1:
                operand = instruction.operands[0]
                if operand.type == X86_OP_MEM and operand.mem.base == 0 and operand.mem.index == 0:
                    item = by_iat.get(int(operand.mem.disp))
                    if item:
                        candidate_type = "call-through-IAT" if is_call else "tail-jump-through-IAT"
                elif operand.type == X86_OP_IMM and is_call:
                    item = thunk_to_import.get(int(operand.imm))
                    if item:
                        candidate_type = "call-to-one-instruction-IAT-thunk"
                elif operand.type == X86_OP_REG:
                    register_indirect += 1
            if item:
                call_rows.append(
                    {
                        "binary": path.relative_to(root).as_posix(),
                        "binary_sha256": binary_hash,
                        "candidate_type": candidate_type,
                        "api": f"{item['dll']}!{item['api']}",
                        "import_kind": item["kind"],
                        "instruction_va": f"0x{instruction.address:08x}",
                        "instruction_rva": f"0x{instruction.address - int(pe.OPTIONAL_HEADER.ImageBase):08x}",
                        "file_offset": f"0x{file_offset:x}",
                        "section": section_name,
                        "bytes": instruction.bytes.hex(" "),
                        "disassembly": f"{instruction.mnemonic} {instruction.op_str}".strip(),
                    }
                )

        if mnemonic == "sysenter" or (mnemonic == "int" and instruction.operands and
                                       instruction.operands[0].type == X86_OP_IMM and
                                       instruction.operands[0].imm == 0x2E):
            syscall_rows.append(
                {
                    "binary": path.relative_to(root).as_posix(),
                    "binary_sha256": binary_hash,
                    "instruction": mnemonic,
                    "instruction_va": f"0x{instruction.address:08x}",
                    "instruction_rva": f"0x{instruction.address - int(pe.OPTIONAL_HEADER.ImageBase):08x}",
                    "file_offset": f"0x{file_offset:x}",
                    "section": section_name,
                    "bytes": instruction.bytes.hex(" "),
                    "disassembly": f"{instruction.mnemonic} {instruction.op_str}".strip(),
                }
            )

    import_rows = [
        {
            "binary": path.relative_to(root).as_posix(),
            "binary_sha256": binary_hash,
            "machine": f"0x{pe.FILE_HEADER.Machine:04x}",
            "dll": item["dll"],
            "api": item["api"],
            "ordinal": item["ordinal"],
            "import_kind": item["kind"],
            "iat_va": f"0x{item['iat_va']:08x}",
            "iat_rva": f"0x{item['iat_rva']:08x}",
        }
        for item in imports
    ]
    return import_rows, call_rows, syscall_rows, {
        "binary": path.relative_to(root).as_posix(),
        "sha256": binary_hash,
        "imports": len(imports),
        "decoded_instructions": len(decoded),
        "iat_call_or_tailjump_candidates": len(call_rows),
        "register_indirect_call_or_jumps_unresolved": register_indirect,
        "direct_syscall_candidates": len(syscall_rows),
        "linear_sweep_call_instructions": direct_calls,
    }


def write_csv(path: Path, rows: list[dict], fields: list[str], overwrite: bool):
    if path.exists() and not overwrite:
        raise FileExistsError(f"refusing to replace existing file: {path}; pass --overwrite to replace it")
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path, help="extracted R99 app directory")
    parser.add_argument("--output-dir", required=True, type=Path, help="existing output directory")
    parser.add_argument("--overwrite", action="store_true", help="replace only the three named output CSVs")
    args = parser.parse_args()
    root = args.root.resolve()
    output_dir = args.output_dir.resolve()
    if not root.is_dir() or not output_dir.is_dir():
        parser.error("--root and --output-dir must be existing directories")

    paths = sorted(p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in {".exe", ".dll", ".sys"})
    imports, calls, syscalls, summaries = [], [], [], []
    for path in paths:
        binary_imports, binary_calls, binary_syscalls, summary = scan_pe(path, root)
        imports.extend(binary_imports)
        calls.extend(binary_calls)
        syscalls.extend(binary_syscalls)
        summaries.append(summary)

    write_csv(output_dir / IMPORTS_NAME, imports,
              ["binary", "binary_sha256", "machine", "dll", "api", "ordinal", "import_kind", "iat_va", "iat_rva"],
              args.overwrite)
    write_csv(output_dir / CALLS_NAME, calls,
              ["binary", "binary_sha256", "candidate_type", "api", "import_kind", "instruction_va", "instruction_rva", "file_offset", "section", "bytes", "disassembly"],
              args.overwrite)
    write_csv(output_dir / SYSCALLS_NAME, syscalls,
              ["binary", "binary_sha256", "instruction", "instruction_va", "instruction_rva", "file_offset", "section", "bytes", "disassembly"],
              args.overwrite)

    print(f"PE files scanned: {len(summaries)}")
    print(f"Import rows: {len(imports)}; direct IAT call/tail-jump candidates: {len(calls)}; direct syscall candidates: {len(syscalls)}")
    for item in summaries:
        print("|".join(f"{key}={value}" for key, value in item.items()))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, pefile.PEFormatError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(2)
