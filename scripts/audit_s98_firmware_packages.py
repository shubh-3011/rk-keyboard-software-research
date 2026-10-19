#!/usr/bin/env python3
"""Statically inventory the eight public S98 Tri-mode RGB updater packages.

Reads PE files and code bytes only. It never launches an updater, opens a HID
interface, or sends anything to a keyboard. Imported-API callsites are linear
sweep candidates, not a reachability proof. Requires pefile and capstone from
requirements-audit.txt.
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
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
from audit_dialog_resources import parse_dialog


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def decode(value: bytes | None) -> str:
    return value.decode("ascii", "replace") if value else ""


def import_rows(pe: pefile.PE, package: str, digest: str) -> list[dict[str, str | int]]:
    rows = []
    for kind, attr in (("normal", "DIRECTORY_ENTRY_IMPORT"), ("delay", "DIRECTORY_ENTRY_DELAY_IMPORT")):
        for descriptor in getattr(pe, attr, []):
            dll = decode(descriptor.dll)
            for imported in descriptor.imports:
                rows.append({
                    "package": package,
                    "package_sha256": digest,
                    "machine": f"0x{pe.FILE_HEADER.Machine:04x}",
                    "dll": dll,
                    "api": decode(imported.name) or (f"ordinal_{imported.ordinal}" if imported.ordinal else ""),
                    "ordinal": imported.ordinal if imported.ordinal is not None else "",
                    "import_kind": kind,
                    "iat_va": f"0x{int(imported.address):08x}",
                    "iat_rva": f"0x{int(imported.address) - int(pe.OPTIONAL_HEADER.ImageBase):08x}",
                    "iat_va_int": int(imported.address),
                })
    return rows


def selector_records(path: Path) -> dict[str, dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    result: dict[str, dict[str, str]] = {}
    for row in rows:
        if (row.get("catalog") != "firmware" or row.get("selector_model") != "S98"
                or not row.get("listed_file_url")):
            continue
        filename = row["listed_file_url"].rsplit("/", 1)[-1].casefold()
        result[filename] = row
    return result


def package_record(path: Path, selector: dict[str, str] | None) -> tuple[dict, list[dict], str, list[bytes]]:
    raw = path.read_bytes()
    digest = sha256(raw)
    pe = pefile.PE(data=raw, fast_load=False)
    if pe.FILE_HEADER.Machine != 0x14C or pe.OPTIONAL_HEADER.Magic != 0x10B:
        raise ValueError(f"expected PE32 x86 package: {path.name}")
    pe.parse_data_directories(
        directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
        ]
    )
    sections = []
    raw_end = int(pe.OPTIONAL_HEADER.SizeOfHeaders)
    for section in pe.sections:
        name = section.Name.rstrip(b"\0").decode("ascii", "replace")
        data = section.get_data()
        raw_end = max(raw_end, int(section.PointerToRawData) + int(section.SizeOfRawData))
        sections.append({
            "package": path.name,
            "package_sha256": digest,
            "section": name,
            "rva": f"0x{int(section.VirtualAddress):08x}",
            "raw_offset": f"0x{int(section.PointerToRawData):08x}",
            "raw_size": int(section.SizeOfRawData),
            "characteristics": f"0x{int(section.Characteristics):08x}",
            "section_sha256": sha256(data),
        })

    overlay = raw[raw_end:]
    header_ok = len(overlay) >= 16 and overlay[:2] == b"\x5a\xa5" and overlay[2:6] == b"SINO"
    if header_ok:
        vid = int.from_bytes(overlay[6:8], "big")
        pid = int.from_bytes(overlay[8:10], "big")
        payload_size = int.from_bytes(overlay[10:12], "big")
        ciphertext_offset = 12
        ciphertext = overlay[ciphertext_offset:ciphertext_offset + payload_size]
        trailer = overlay[ciphertext_offset + payload_size:]
        trailer_hex = trailer.hex()
        layout_matches = len(ciphertext) == payload_size and len(trailer) == 4
    else:
        vid = pid = payload_size = 0
        ciphertext_offset = 0
        ciphertext = b""
        trailer_hex = ""
        layout_matches = False

    imports = import_rows(pe, path.name, digest)
    version_fixed = getattr(pe, "VS_FIXEDFILEINFO", [])
    if version_fixed:
        fixed = version_fixed[0]
        file_version = ".".join(str(x) for x in (
            fixed.FileVersionMS >> 16, fixed.FileVersionMS & 0xFFFF,
            fixed.FileVersionLS >> 16, fixed.FileVersionLS & 0xFFFF,
        ))
        product_version = ".".join(str(x) for x in (
            fixed.ProductVersionMS >> 16, fixed.ProductVersionMS & 0xFFFF,
            fixed.ProductVersionLS >> 16, fixed.ProductVersionLS & 0xFFFF,
        ))
    else:
        file_version = product_version = ""

    security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
    resource_count = 0
    def count_resources(node):
        nonlocal resource_count
        for entry in node.entries:
            if hasattr(entry, "directory") and entry.directory is not None:
                count_resources(entry.directory)
            else:
                resource_count += 1
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        count_resources(pe.DIRECTORY_ENTRY_RESOURCE)

    record = {
        "package": path.name,
        "selector_model": selector.get("selector_model", "") if selector else "",
        "product_version": selector.get("product_version", "") if selector else "",
        "attribute": selector.get("attribute", "") if selector else "",
        "language": selector.get("language", "") if selector else "",
        "selector_pid": selector.get("pid", "") if selector else "",
        "selector_url": selector.get("listed_file_url", "") if selector else "",
        "size_bytes": len(raw),
        "sha256": digest,
        "machine": f"0x{pe.FILE_HEADER.Machine:04x}",
        "pe_timestamp_utc_epoch": int(pe.FILE_HEADER.TimeDateStamp),
        "entrypoint_rva": f"0x{int(pe.OPTIONAL_HEADER.AddressOfEntryPoint):08x}",
        "file_version": file_version,
        "product_version_resource": product_version,
        "imports_count": len(imports),
        "resource_leaf_count": resource_count,
        "overlay_offset": f"0x{raw_end:x}",
        "overlay_size": len(overlay),
        "overlay_header_hex": overlay[:12].hex() if overlay else "",
        "overlay_marker": "5AA5SINO" if header_ok else "",
        "vid_header_be": f"0x{vid:04X}" if header_ok else "",
        "pid_header_be": f"0x{pid:04X}" if header_ok else "",
        "payload_size_header_be": payload_size if header_ok else "",
        "ciphertext_offset_from_overlay": ciphertext_offset if header_ok else "",
        "ciphertext_size": len(ciphertext),
        "ciphertext_sha256": sha256(ciphertext) if ciphertext else "",
        "trailer_size": len(overlay) - ciphertext_offset - len(ciphertext) if header_ok else "",
        "trailer_hex": trailer_hex,
        "record_layout_matches_header": str(layout_matches).lower(),
        "security_directory_offset": int(security.VirtualAddress),
        "security_directory_size": int(security.Size),
    }
    return record, sections, sha256(raw), [s.get_data() for s in pe.sections if s.Characteristics & 0x20000000]


def dialog_rows(path: Path, digest: str) -> list[dict]:
    pe = pefile.PE(str(path), fast_load=False)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
    rows = []
    for type_entry in getattr(getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None), "entries", []):
        if type_entry.id != 5:  # RT_DIALOG
            continue
        for name_entry in type_entry.directory.entries:
            for language_entry in name_entry.directory.entries:
                resource = language_entry.data.struct
                data = pe.get_data(resource.OffsetToData, resource.Size)
                base = {
                    "package": path.name,
                    "package_sha256": digest,
                    "resource_id": str(name_entry.name) if name_entry.name is not None else str(name_entry.id),
                    "language_id": language_entry.id,
                }
                try:
                    dialog = parse_dialog(data)
                except (IndexError, ValueError, struct.error) as exc:
                    rows.append({**base, "record_type": "parse_error", "parse_status": str(exc)})
                    continue
                common = {
                    **base,
                    "dialog_format": "DLGTEMPLATEEX" if dialog["extended"] else "DLGTEMPLATE",
                    "dialog_title": dialog["title"],
                    "dialog_window_class": dialog["window_class"],
                    "dialog_style_hex": f"0x{dialog['style']:08X}",
                    "dialog_rect": ",".join(map(str, dialog["rect"])),
                    "dialog_font": dialog["font"],
                    "declared_control_count": dialog["item_count"],
                    "parse_status": f"parsed {len(dialog['controls'])} controls; consumed {dialog['bytes_consumed']}/{len(data)} bytes",
                }
                if not dialog["controls"]:
                    rows.append({**common, "record_type": "dialog"})
                for control in dialog["controls"]:
                    rows.append({
                        **common,
                        "record_type": "control",
                        "control_index": control["index"],
                        "control_id_hex": f"0x{control['id']:08X}",
                        "control_class": control["class"],
                        "caption": control["caption"],
                        "control_rect": ",".join(map(str, control["rect"])),
                    })
    return rows


def code_candidates(path: Path, package_hash: str, text_hash: str, imports: list[dict]) -> tuple[list[dict], list[dict], int]:
    pe = pefile.PE(str(path), fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"], pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"]])
    by_iat = {int(row["iat_va_int"]): row for row in imports}
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    calls: list[dict] = []
    syscalls: list[dict] = []
    indirect = 0
    for section in pe.sections:
        if not section.Characteristics & 0x20000000:
            continue
        section_name = section.Name.rstrip(b"\0").decode("ascii", "replace")
        base = int(pe.OPTIONAL_HEADER.ImageBase) + int(section.VirtualAddress)
        for instruction in md.disasm(section.get_data(), base):
            if instruction.mnemonic in {"call", "jmp"} and instruction.operands:
                operand = instruction.operands[0]
                imported = None
                if operand.type == X86_OP_MEM and operand.mem.base == 0 and operand.mem.index == 0:
                    imported = by_iat.get(int(operand.mem.disp))
                elif operand.type == X86_OP_REG:
                    indirect += 1
                if imported:
                    calls.append({
                        "text_sha256": text_hash,
                        "representative_package": path.name,
                        "package_sha256": package_hash,
                        "dll": imported["dll"],
                        "api": imported["api"],
                        "import_kind": imported["import_kind"],
                        "instruction_va": f"0x{instruction.address:08x}",
                        "instruction_rva": f"0x{instruction.address - int(pe.OPTIONAL_HEADER.ImageBase):08x}",
                        "file_offset": f"0x{pe.get_offset_from_rva(instruction.address - int(pe.OPTIONAL_HEADER.ImageBase)):x}",
                        "section": section_name,
                        "bytes": instruction.bytes.hex(" "),
                        "disassembly": f"{instruction.mnemonic} {instruction.op_str}".strip(),
                        "evidence_limit": "linear-sweep imported-IAT call/tail-jump candidate; reachability not established",
                    })
            if instruction.mnemonic == "sysenter" or (
                instruction.mnemonic == "int" and instruction.operands
                and instruction.operands[0].type == X86_OP_IMM
                and int(instruction.operands[0].imm) == 0x2E
            ):
                syscalls.append({
                    "text_sha256": text_hash,
                    "representative_package": path.name,
                    "package_sha256": package_hash,
                    "instruction_va": f"0x{instruction.address:08x}",
                    "instruction_rva": f"0x{instruction.address - int(pe.OPTIONAL_HEADER.ImageBase):08x}",
                    "file_offset": f"0x{pe.get_offset_from_rva(instruction.address - int(pe.OPTIONAL_HEADER.ImageBase)):x}",
                    "section": section_name,
                    "bytes": instruction.bytes.hex(" "),
                    "disassembly": f"{instruction.mnemonic} {instruction.op_str}".strip(),
                    "evidence_limit": "linear-sweep raw syscall-byte candidate; reachability not established",
                })
    return calls, syscalls, indirect


def write_csv(path: Path, rows: list[dict], fields: list[str], overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise FileExistsError(f"refusing to replace existing file: {path}; pass --overwrite")
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-dir", type=Path, required=True, help="directory containing the downloaded S98 package EXEs")
    parser.add_argument("--selector-csv", type=Path, required=True, help="dated RK selector snapshot CSV")
    parser.add_argument("--output-dir", type=Path, required=True, help="existing or new directory for audit CSVs")
    parser.add_argument("--overwrite", action="store_true", help="replace only the generated S98 CSV files")
    args = parser.parse_args()
    package_dir = args.package_dir.resolve()
    output_dir = args.output_dir.resolve()
    if not package_dir.is_dir() or not args.selector_csv.is_file():
        parser.error("--package-dir must exist and --selector-csv must be a file")
    output_dir.mkdir(parents=True, exist_ok=True)
    selector = selector_records(args.selector_csv)
    packages = sorted(p for p in package_dir.glob("*.exe") if p.is_file())
    if not packages:
        parser.error("no .exe package files found")

    manifest, sections, imports, dialogs = [], [], [], []
    by_text: dict[str, tuple[Path, str, list[dict]]] = {}
    for path in packages:
        selector_row = next((row for filename, row in selector.items() if path.name.casefold().endswith(filename)), None)
        record, section_rows, digest, _code_data = package_record(path, selector_row)
        manifest.append(record)
        sections.extend(section_rows)
        package_imports = import_rows(pefile.PE(str(path), fast_load=False), path.name, digest)
        imports.extend({k: v for k, v in row.items() if k != "iat_va_int"} for row in package_imports)
        dialogs.extend(dialog_rows(path, digest))
        text_row = next((row for row in section_rows if row["section"] == ".text"), None)
        if text_row:
            by_text.setdefault(str(text_row["section_sha256"]), (path, digest, package_imports))

    calls, syscalls, indirect_total = [], [], 0
    for text_hash, (representative, digest, package_imports) in by_text.items():
        call_rows, syscall_rows, indirect = code_candidates(representative, digest, text_hash, package_imports)
        calls.extend(call_rows)
        syscalls.extend(syscall_rows)
        indirect_total += indirect

    prefix = "rk-s98"
    write_csv(output_dir / f"{prefix}-firmware-package-manifest-2026-10-19.csv", manifest, list(manifest[0]), args.overwrite)
    write_csv(output_dir / f"{prefix}-firmware-section-hashes-2026-10-19.csv", sections, list(sections[0]), args.overwrite)
    write_csv(output_dir / f"{prefix}-firmware-native-api-imports-2026-10-19.csv", imports, list(imports[0]), args.overwrite)
    write_csv(output_dir / f"{prefix}-firmware-native-api-callsite-candidates-2026-10-19.csv", calls, list(calls[0]) if calls else ["text_sha256"], args.overwrite)
    write_csv(output_dir / f"{prefix}-firmware-native-syscall-candidates-2026-10-19.csv", syscalls, list(syscalls[0]) if syscalls else ["text_sha256"], args.overwrite)
    write_csv(output_dir / f"{prefix}-firmware-dialog-resources-2026-10-19.csv", dialogs, list(dialogs[0]) if dialogs else ["package"], args.overwrite)
    print(f"Packages: {len(manifest)}; distinct .text builds: {len(by_text)}")
    print(f"Section rows: {len(sections)}; import rows: {len(imports)}")
    print(f"Dialog/control rows: {len(dialogs)}")
    print(f"Direct IAT call/tail-jump candidates: {len(calls)}; register-indirect call/jump candidates: {indirect_total}; decoded direct syscall candidates: {len(syscalls)}")
    for row in manifest:
        print(f"{row['package']}|sha256={row['sha256']}|vid={row['vid_header_be']}|pid={row['pid_header_be']}|payload={row['ciphertext_size']}|trailer={row['trailer_hex']}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, pefile.PEFormatError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(2)
