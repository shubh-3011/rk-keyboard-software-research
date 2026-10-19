#!/usr/bin/env python3
"""Statically inventory the F99 mi-hid Windows native addon.

The script reads PE structures and code bytes only. It never loads the addon,
starts the vendor application, opens a HID interface, or sends a report.
Imported-call and raw syscall-byte records are candidates, not reachability
proofs. Requires pefile and capstone from requirements-audit.txt.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import sys
from pathlib import Path

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP


MODULE_STRINGS = ("hid.dll", "cfgmgr32.dll")
DYNAMIC_EXPORTS = (
    "HidD_GetHidGuid", "HidD_GetAttributes", "HidD_GetSerialNumberString",
    "HidD_GetManufacturerString", "HidD_GetProductString", "HidD_SetFeature",
    "HidD_GetFeature", "HidD_GetInputReport", "HidD_GetIndexedString",
    "HidD_GetPreparsedData", "HidD_FreePreparsedData", "HidP_GetCaps",
    "HidD_SetNumInputBuffers", "CM_Locate_DevNodeW", "CM_Get_Parent",
    "CM_Get_DevNode_PropertyW", "CM_Get_Device_Interface_PropertyW",
    "CM_Get_Device_Interface_List_SizeW", "CM_Get_Device_Interface_ListW",
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def string_offsets(data: bytes, value: str) -> list[tuple[int, str]]:
    found = []
    for encoding in ("ascii", "utf-16le"):
        pattern = value.encode(encoding) + (b"\0\0" if encoding == "utf-16le" else b"\0")
        start = 0
        while True:
            offset = data.find(pattern, start)
            if offset < 0:
                break
            found.append((offset, encoding))
            start = offset + 1
    return sorted(set(found))


def imports(pe: pefile.PE, digest: str, path: Path) -> list[dict[str, str | int]]:
    rows = []
    base = int(pe.OPTIONAL_HEADER.ImageBase)
    for kind, attr in (("normal", "DIRECTORY_ENTRY_IMPORT"), ("delay", "DIRECTORY_ENTRY_DELAY_IMPORT")):
        for descriptor in getattr(pe, attr, []):
            dll = descriptor.dll.decode("ascii", "replace")
            for entry in descriptor.imports:
                name = entry.name.decode("ascii", "replace") if entry.name else ""
                if not name:
                    name = f"ordinal_{entry.ordinal}" if entry.ordinal is not None else ""
                va = int(entry.address)
                rva = va - base
                try:
                    file_offset = pe.get_offset_from_rva(rva)
                except pefile.PEFormatError:
                    file_offset = ""
                rows.append({
                    "package_path": str(path),
                    "package_sha256": digest,
                    "machine": f"0x{pe.FILE_HEADER.Machine:04x}",
                    "dll": dll,
                    "api": name,
                    "ordinal": entry.ordinal if entry.ordinal is not None else "",
                    "import_kind": kind,
                    "iat_va": f"0x{va:016x}",
                    "iat_rva": f"0x{rva:08x}",
                    "iat_file_offset": f"0x{file_offset:x}" if file_offset != "" else "",
                })
    return rows


def code_ledgers(pe: pefile.PE, digest: str, path: Path, import_rows: list[dict]) -> tuple[list[dict], list[dict]]:
    base = int(pe.OPTIONAL_HEADER.ImageBase)
    by_iat = {int(row["iat_va"], 16): row for row in import_rows}
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    call_rows: list[dict] = []
    syscall_rows: list[dict] = []
    for section in pe.sections:
        if not section.Characteristics & 0x20000000:
            continue
        section_name = section.Name.rstrip(b"\0").decode("ascii", "replace")
        section_rva = int(section.VirtualAddress)
        section_va = base + section_rva
        raw = section.get_data()
        for insn in md.disasm(raw, section_va):
            if insn.mnemonic in {"call", "jmp"} and insn.operands:
                op = insn.operands[0]
                target = None
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP and op.mem.index == 0:
                    target = insn.address + insn.size + int(op.mem.disp)
                if target in by_iat:
                    imported = by_iat[target]
                    rva = insn.address - base
                    file_offset = pe.get_offset_from_rva(rva)
                    call_rows.append({
                        "package_path": str(path),
                        "package_sha256": digest,
                        "dll": imported["dll"],
                        "api": imported["api"],
                        "import_kind": imported["import_kind"],
                        "instruction_va": f"0x{insn.address:016x}",
                        "instruction_rva": f"0x{rva:08x}",
                        "file_offset": f"0x{file_offset:x}",
                        "section": section_name,
                        "bytes": insn.bytes.hex(" "),
                        "disassembly": f"{insn.mnemonic} {insn.op_str}".strip(),
                        "evidence_limit": "decoded direct IAT call/tail-jump candidate; reachability not established",
                    })
            is_syscall = insn.mnemonic in {"syscall", "sysenter"} or (
                insn.mnemonic == "int" and insn.operands
                and insn.operands[0].type == X86_OP_IMM
                and int(insn.operands[0].imm) == 0x2E
            )
            if is_syscall:
                rva = insn.address - base
                syscall_rows.append({
                    "package_path": str(path),
                    "package_sha256": digest,
                    "instruction_va": f"0x{insn.address:016x}",
                    "instruction_rva": f"0x{rva:08x}",
                    "file_offset": f"0x{pe.get_offset_from_rva(rva):x}",
                    "section": section_name,
                    "bytes": insn.bytes.hex(" "),
                    "disassembly": f"{insn.mnemonic} {insn.op_str}".strip(),
                    "evidence_limit": "decoded instruction candidate in linear sweep; reachability not established",
                })
    return call_rows, syscall_rows


def write_csv(path: Path, rows: list[dict], fields: list[str], overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise FileExistsError(f"refusing to replace existing file: {path}; pass --overwrite")
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True, help="extracted mi-hid.node PE file")
    parser.add_argument("--output-dir", type=Path, required=True, help="directory for generated CSV ledgers")
    parser.add_argument("--overwrite", action="store_true", help="replace only the five generated F99 native-HID CSV ledgers")
    args = parser.parse_args()
    binary = args.binary.resolve()
    output_dir = args.output_dir.resolve()
    if not binary.is_file():
        parser.error("--binary must be an existing file")
    output_dir.mkdir(parents=True, exist_ok=True)
    raw = binary.read_bytes()
    digest = sha256(raw)
    pe = pefile.PE(data=raw, fast_load=False)
    if pe.FILE_HEADER.Machine != 0x8664 or pe.OPTIONAL_HEADER.Magic != 0x20B:
        raise ValueError("expected a PE32+ x64 native addon")
    pe.parse_data_directories(directories=[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
    ])
    import_rows = imports(pe, digest, binary)
    call_rows, syscall_rows = code_ledgers(pe, digest, binary, import_rows)

    dynamic_rows = []
    for value in (*MODULE_STRINGS, *DYNAMIC_EXPORTS):
        for offset, encoding in string_offsets(raw, value):
            dynamic_rows.append({
                "package_path": str(binary),
                "package_sha256": digest,
                "string": value,
                "encoding": encoding,
                "file_offset": f"0x{offset:x}",
                "evidence_limit": "module/export-name string; dynamic resolution/call use requires code-path confirmation",
            })

    raw_syscall_rows = []
    marker = b"\x0f\x05"
    start = 0
    while True:
        offset = raw.find(marker, start)
        if offset < 0:
            break
        raw_syscall_rows.append({
            "package_path": str(binary),
            "package_sha256": digest,
            "file_offset": f"0x{offset:x}",
            "raw_bytes": "0f 05",
            "classification": "raw byte pair only; not a decoded syscall instruction",
        })
        start = offset + 1

    stem = "rk-f99-native-hid"
    write_csv(output_dir / f"{stem}-imports-2026-10-19.csv", import_rows, list(import_rows[0]) if import_rows else ["api"], args.overwrite)
    write_csv(output_dir / f"{stem}-callsite-candidates-2026-10-19.csv", call_rows, list(call_rows[0]) if call_rows else ["api"], args.overwrite)
    write_csv(output_dir / f"{stem}-dynamic-api-symbols-2026-10-19.csv", dynamic_rows, list(dynamic_rows[0]) if dynamic_rows else ["string"], args.overwrite)
    write_csv(output_dir / f"{stem}-syscall-candidates-2026-10-19.csv", syscall_rows, list(syscall_rows[0]) if syscall_rows else ["instruction_va"], args.overwrite)
    write_csv(output_dir / f"{stem}-raw-0f05-candidates-2026-10-19.csv", raw_syscall_rows, list(raw_syscall_rows[0]) if raw_syscall_rows else ["file_offset"], args.overwrite)
    print(f"SHA-256: {digest}")
    print(f"PE: x64 ImageBase=0x{int(pe.OPTIONAL_HEADER.ImageBase):x} entrypoint_rva=0x{int(pe.OPTIONAL_HEADER.AddressOfEntryPoint):x} size={len(raw)}")
    for key in sorted({(str(row["dll"]), str(row["import_kind"])) for row in import_rows}):
        dll, kind = key
        count = sum(1 for row in import_rows if row["dll"] == dll and row["import_kind"] == kind)
        print(f"{kind} imports from {dll}: {count}")
    print(f"Total normal/delay import rows: {len(import_rows)}")
    print(f"Decoded direct IAT call/tail-jump candidates: {len(call_rows)}")
    print(f"Dynamic module/export-name strings: {len(dynamic_rows)}")
    print(f"Decoded syscall candidates: {len(syscall_rows)}; raw 0f 05 pairs: {len(raw_syscall_rows)}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, pefile.PEFormatError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(2)
