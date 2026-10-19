#!/usr/bin/env python3
"""In-memory static audit of selected embedded updater payloads.

The script reads hash-pinned parent packages, verifies embedded resource ranges,
then parses the resource byte slices in memory. It never writes, extracts,
loads, or executes a payload and never contacts a device. Optional Capstone use
is limited to a linear sweep of executable sections; every such call record is
explicitly a candidate, not a validated path.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import struct
import sys
from collections import Counter
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import audit_rk_clr_metadata_static as parent_parser  # noqa: E402

ROOT = HERE.parent
INVENTORY = ROOT / "docs" / "rk-firmware-clr-profile-inventory-2026-10-20.csv"
ARTIFACTS = ROOT / "docs" / "rk-firmware-artifact-inventory-2026-10-19.csv"
OUT = {
    "lineage": ROOT / "docs" / "rk-embedded-payload-parent-child-ledger-2026-10-20.csv",
    "images": ROOT / "docs" / "rk-embedded-payload-image-summary-2026-10-20.csv",
    "sections": ROOT / "docs" / "rk-embedded-payload-section-ledger-2026-10-20.csv",
    "imports": ROOT / "docs" / "rk-embedded-payload-import-ledger-2026-10-20.csv",
    "exports": ROOT / "docs" / "rk-embedded-payload-export-ledger-2026-10-20.csv",
    "resources": ROOT / "docs" / "rk-embedded-payload-resource-ledger-2026-10-20.csv",
    "strings": ROOT / "docs" / "rk-embedded-payload-string-ledger-2026-10-20.csv",
    "calls": ROOT / "docs" / "rk-embedded-payload-linear-call-candidates-2026-10-20.csv",
    "issues": ROOT / "docs" / "rk-embedded-payload-parse-issues-2026-10-20.csv",
}

RESOURCE_NAMES = {
    "WestberryFlasher.executable.wb32_f022_hid_dfu_updater_V0.0.5.exe": "updater-helper-v0.0.5",
    "WestberryFlasher.executable.libhidapi-0.dll": "libhidapi",
    "WestberryFlasher.executable.libusb-1.0.dll": "libusb",
}

EMPTY_COLUMNS = {
    "lineage": ["parent_filename", "parent_models", "parent_package_sha256", "parent_manifest_token", "parent_manifest_row_file_offset", "resource_name", "payload_family", "parent_resource_rva", "parent_resource_entry_file_offset", "parent_payload_file_offset", "parent_payload_length", "child_payload_sha256", "range_status"],
    "images": ["payload_family", "child_payload_sha256", "length", "parse_status", "machine", "architecture", "pe_format", "image_base", "entrypoint_rva", "section_count", "import_dll_count", "import_symbol_count", "delay_import_count", "export_count", "resource_count", "ascii_string_count", "utf16_string_count", "capstone_version", "sweep_instruction_count", "sweep_candidate_count", "sweep_status", "parse_issue"],
    "sections": ["payload_family", "child_payload_sha256", "name", "virtual_address", "virtual_size", "raw_file_offset", "raw_size", "characteristics", "executable", "readable", "writable"],
    "imports": ["payload_family", "child_payload_sha256", "dll_name", "import_name", "ordinal", "hint", "lookup_rva", "iat_rva", "iat_file_offset", "descriptor_file_offset", "delay_import", "evidence_class"],
    "exports": ["payload_family", "child_payload_sha256", "ordinal", "name", "function_rva", "forwarder", "directory_file_offset", "evidence_class"],
    "resources": ["payload_family", "child_payload_sha256", "resource_path", "data_rva", "child_file_offset", "length", "codepage", "payload_sha256", "status", "evidence_class"],
    "strings": ["payload_family", "child_payload_sha256", "encoding", "child_file_offset", "parent_representative_file_offset", "length_bytes", "value", "match_tags", "evidence_class"],
    "calls": ["payload_family", "child_payload_sha256", "machine", "section_name", "child_file_offset", "parent_representative_file_offset", "rva", "instruction_bytes", "mnemonic", "operand_text", "candidate_kind", "target_rva", "target_import_dll", "target_import_name", "target_export_name", "evidence_class"],
    "issues": ["payload_family", "child_payload_sha256", "parse_stage", "issue", "child_file_offset"],
}


class ParseIssue(Exception):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def u(data: bytes, off: int, size: int) -> int:
    if off < 0 or size < 0 or off + size > len(data):
        raise ParseIssue(f"out-of-range read file+0x{off:X} size=0x{size:X}")
    return int.from_bytes(data[off:off + size], "little")


def cstring(data: bytes, offset: int, limit: int | None = None) -> str:
    end_limit = min(len(data), limit if limit is not None else len(data))
    if offset < 0 or offset >= end_limit:
        raise ParseIssue(f"invalid c-string offset 0x{offset:X}")
    end = data.find(b"\0", offset, end_limit)
    if end < 0:
        raise ParseIssue(f"unterminated c-string at 0x{offset:X}")
    return data[offset:end].decode("ascii", "replace")


def parse_pe(data: bytes) -> dict[str, Any]:
    if data[:2] != b"MZ":
        raise ParseIssue("missing MZ header")
    pe_off = u(data, 0x3C, 4)
    if data[pe_off:pe_off + 4] != b"PE\0\0":
        raise ParseIssue("missing PE signature")
    coff = pe_off + 4
    machine, section_count = struct.unpack_from("<HH", data, coff)
    timestamp, symptr, symcount = struct.unpack_from("<III", data, coff + 4)
    optional_size, characteristics = struct.unpack_from("<HH", data, coff + 16)
    opt = coff + 20
    if optional_size < 96 or opt + optional_size > len(data):
        raise ParseIssue("invalid optional header bounds")
    magic = u(data, opt, 2)
    if magic == 0x10B:
        image_base = u(data, opt + 28, 4)
        directory_count_off, directory_off = opt + 92, opt + 96
        pe_format = "PE32"
        thunk_width, ordinal_flag = 4, 0x80000000
    elif magic == 0x20B:
        image_base = u(data, opt + 24, 8)
        directory_count_off, directory_off = opt + 108, opt + 112
        pe_format = "PE32+"
        thunk_width, ordinal_flag = 8, 0x8000000000000000
    else:
        raise ParseIssue(f"unsupported optional-header magic 0x{magic:X}")
    entry_rva = u(data, opt + 16, 4)
    section_align = u(data, opt + 32, 4)
    file_align = u(data, opt + 36, 4)
    size_headers = u(data, opt + 60, 4)
    subsystem = u(data, opt + 68, 2)
    directory_count = min(u(data, directory_count_off, 4), 16)
    directories = []
    for index in range(directory_count):
        rva, size = struct.unpack_from("<II", data, directory_off + index * 8)
        directories.append({"index": index, "rva": rva, "size": size})
    sections = []
    sec_off = opt + optional_size
    if sec_off + section_count * 40 > len(data):
        raise ParseIssue("section table exceeds file")
    for index in range(section_count):
        off = sec_off + index * 40
        name = data[off:off + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        vsize, va, raw_size, raw_off, reloc_off, line_off = struct.unpack_from("<IIIIII", data, off + 8)
        reloc_count, line_count, flags = struct.unpack_from("<HHI", data, off + 32)
        if raw_size and raw_off + raw_size > len(data):
            raise ParseIssue(f"section {name!r} raw range exceeds file")
        sections.append({
            "name": name, "virtual_size": vsize, "virtual_address": va,
            "raw_size": raw_size, "raw_file_offset": raw_off,
            "characteristics": flags,
        })

    def rva_to_file(rva: int, size: int = 1) -> int:
        if rva < size_headers and rva + size <= size_headers and rva + size <= len(data):
            return rva
        for section in sections:
            start = section["virtual_address"]
            extent = max(section["virtual_size"], section["raw_size"])
            if start <= rva < start + extent:
                delta = rva - start
                if delta + size > section["raw_size"]:
                    raise ParseIssue(f"RVA 0x{rva:X} is not fully file-backed")
                file_off = section["raw_file_offset"] + delta
                if file_off + size > len(data):
                    raise ParseIssue(f"RVA 0x{rva:X} maps past end of payload")
                return file_off
        raise ParseIssue(f"RVA 0x{rva:X} is unmapped")

    def directory(index: int) -> dict[str, int]:
        return directories[index] if index < len(directories) else {"index": index, "rva": 0, "size": 0}

    if section_count < 1:
        raise ParseIssue("PE has no sections")
    return {
        "pe_offset": pe_off, "machine": machine, "section_count": section_count,
        "timestamp": timestamp, "characteristics": characteristics,
        "optional_magic": magic, "pe_format": pe_format,
        "image_base": image_base, "entrypoint_rva": entry_rva,
        "section_alignment": section_align, "file_alignment": file_align,
        "size_headers": size_headers, "subsystem": subsystem,
        "directories": directories, "sections": sections,
        "thunk_width": thunk_width, "ordinal_flag": ordinal_flag,
        "rva_to_file": rva_to_file,
    }


def parse_imports(data: bytes, pe: dict[str, Any], directory_index: int = 1, delay: bool = False) -> tuple[list[dict[str, Any]], int]:
    directory = pe["directories"][directory_index] if directory_index < len(pe["directories"]) else {"rva": 0, "size": 0}
    if not directory["rva"] or not directory["size"]:
        return [], 0
    start = pe["rva_to_file"](directory["rva"], min(directory["size"], 1))
    width = pe["thunk_width"]
    ordinal_flag = pe["ordinal_flag"]
    entries: list[dict[str, Any]] = []
    descriptors = 0
    cursor = start
    descriptor_size = 32 if delay else 20
    max_descriptors = min(directory["size"] // descriptor_size + 1, 4096)
    for _ in range(max_descriptors):
        if cursor + descriptor_size > len(data):
            raise ParseIssue("import descriptor exceeds file")
        raw = data[cursor:cursor + descriptor_size]
        if not any(raw):
            break
        descriptors += 1
        if delay:
            attrs, name_rva, module_handle, iat_rva, int_rva, bound_iat, unload_iat, stamp = struct.unpack_from("<IIIIIIII", data, cursor)
            if not attrs & 1:
                raise ParseIssue("delay import descriptor uses VA fields; unresolved without relocations")
            lookup_rva = int_rva or iat_rva
        else:
            lookup_rva, timestamp, chain, name_rva, iat_rva = struct.unpack_from("<IIIII", data, cursor)
            lookup_rva = lookup_rva or iat_rva
        first_iat_rva = iat_rva
        name_off = pe["rva_to_file"](name_rva, 1)
        dll = cstring(data, name_off)
        thunk_rva = lookup_rva
        for _idx in range(65536):
            thunk_off = pe["rva_to_file"](thunk_rva, width)
            value = int.from_bytes(data[thunk_off:thunk_off + width], "little")
            if value == 0:
                break
            iat_slot_rva = first_iat_rva + (_idx * width)
            if value & ordinal_flag:
                entries.append({
                    "dll_name": dll, "import_name": "", "ordinal": value & 0xFFFF,
                    "hint": "", "lookup_rva": f"0x{thunk_rva:08X}",
                    "iat_rva": f"0x{iat_slot_rva:08X}", "iat_file_offset": f"0x{pe['rva_to_file'](iat_slot_rva, width):X}",
                    "descriptor_file_offset": f"0x{cursor:X}", "delay_import": delay,
                })
            else:
                hint_name_off = pe["rva_to_file"](value, 3)
                hint = u(data, hint_name_off, 2)
                import_name = cstring(data, hint_name_off + 2)
                entries.append({
                    "dll_name": dll, "import_name": import_name, "ordinal": "",
                    "hint": hint, "lookup_rva": f"0x{thunk_rva:08X}",
                    "iat_rva": f"0x{iat_slot_rva:08X}", "iat_file_offset": f"0x{pe['rva_to_file'](iat_slot_rva, width):X}",
                    "descriptor_file_offset": f"0x{cursor:X}", "delay_import": delay,
                })
            thunk_rva += width
        else:
            raise ParseIssue(f"import thunk list for {dll} exceeds cap")
        cursor += descriptor_size
    return entries, descriptors


def parse_exports(data: bytes, pe: dict[str, Any]) -> list[dict[str, Any]]:
    directory = pe["directories"][0] if pe["directories"] else {"rva": 0, "size": 0}
    if not directory["rva"] or directory["size"] < 40:
        return []
    start = pe["rva_to_file"](directory["rva"], 40)
    _, timestamp, major, minor, name_rva, ordinal_base, function_count, name_count, functions_rva, names_rva, ordinals_rva = struct.unpack_from("<IIHHIIIIIII", data, start)
    if function_count > 1_000_000 or name_count > function_count:
        raise ParseIssue("export counts exceed bounds")
    fn_off = pe["rva_to_file"](functions_rva, function_count * 4) if function_count else 0
    name_off = pe["rva_to_file"](names_rva, name_count * 4) if name_count else 0
    ord_off = pe["rva_to_file"](ordinals_rva, name_count * 2) if name_count else 0
    names_by_index: dict[int, list[str]] = {}
    for i in range(name_count):
        rva = u(data, name_off + i * 4, 4)
        n = cstring(data, pe["rva_to_file"](rva, 1))
        ordinal_index = u(data, ord_off + i * 2, 2)
        names_by_index.setdefault(ordinal_index, []).append(n)
    out = []
    for i in range(function_count):
        rva = u(data, fn_off + i * 4, 4)
        if not rva:
            continue
        forwarder = ""
        if directory["rva"] <= rva < directory["rva"] + directory["size"]:
            forwarder = cstring(data, pe["rva_to_file"](rva, 1))
        names = names_by_index.get(i, []) or [""]
        for name in names:
            out.append({
                "ordinal": ordinal_base + i, "name": name,
                "function_rva": f"0x{rva:08X}", "forwarder": forwarder,
                "directory_file_offset": f"0x{start:X}",
            })
    return out


def parse_resources(data: bytes, pe: dict[str, Any]) -> list[dict[str, Any]]:
    directory = pe["directories"][2] if len(pe["directories"]) > 2 else {"rva": 0, "size": 0}
    if not directory["rva"] or not directory["size"]:
        return []
    base_rva = directory["rva"]
    base_off = pe["rva_to_file"](base_rva, min(directory["size"], 16))
    limit_off = min(len(data), base_off + directory["size"])
    out: list[dict[str, Any]] = []
    visited: set[int] = set()

    def label(raw: int) -> str:
        if raw & 0x80000000:
            rel = raw & 0x7FFFFFFF
            off = base_off + rel
            length = u(data, off, 2)
            if length > 4096 or off + 2 + length * 2 > limit_off:
                raise ParseIssue("invalid resource directory name range")
            return data[off + 2:off + 2 + length * 2].decode("utf-16le", "replace")
        return f"#{raw & 0xFFFF}"

    def visit(relative: int, path: tuple[str, ...], depth: int) -> None:
        if depth > 5 or relative in visited:
            return
        visited.add(relative)
        off = base_off + relative
        if off + 16 > limit_off:
            raise ParseIssue("resource directory header outside bounds")
        named, ids = struct.unpack_from("<HH", data, off + 12)
        count = named + ids
        if count > 10000 or off + 16 + count * 8 > limit_off:
            raise ParseIssue("resource directory entries outside bounds")
        for i in range(count):
            entry_off = off + 16 + i * 8
            name_raw, child_raw = struct.unpack_from("<II", data, entry_off)
            node_name = label(name_raw)
            new_path = path + (node_name,)
            rel = child_raw & 0x7FFFFFFF
            if child_raw & 0x80000000:
                visit(rel, new_path, depth + 1)
                continue
            data_entry_off = base_off + rel
            if data_entry_off + 16 > limit_off:
                raise ParseIssue("resource data-entry exceeds resource directory")
            data_rva, size, codepage, reserved = struct.unpack_from("<IIII", data, data_entry_off)
            payload_off = pe["rva_to_file"](data_rva, size) if size else pe["rva_to_file"](data_rva, 0)
            payload = data[payload_off:payload_off + size]
            out.append({
                "resource_path": "/".join(new_path), "data_rva": f"0x{data_rva:08X}",
                "child_file_offset": f"0x{payload_off:X}", "length": size,
                "codepage": codepage, "payload_sha256": sha(payload),
                "status": "range-mapped-and-hashed-in-memory; not extracted",
            })

    visit(0, (), 0)
    return out


STRING_TAGS = (
    ("HID/USB", re.compile(r"hid|usb|winusb|libusb|hidapi|setupapi|deviceio|vid_|pid_|\\\\\\.\\\\" , re.I)),
    ("firmware/update", re.compile(r"firmware|dfu|bootloader|flash|update|updater|keyboard", re.I)),
    ("device/model IDs", re.compile(r"VID_|PID_|0x[0-9a-f]{4}|vendor|product", re.I)),
    ("files/process", re.compile(r"\.dll|\.exe|\.sys|\\\\|createfile|deviceiocontrol|loadlibrary|procaddress", re.I)),
    ("serial/ports", re.compile(r"serial|com[0-9]|baud|port", re.I)),
)


def scan_strings(data: bytes, min_chars: int = 5) -> list[dict[str, Any]]:
    out = []
    # Printable ASCII candidates, retaining exact byte offsets.
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_chars)
    for match in pattern.finditer(data):
        value = match.group().decode("ascii", "replace")
        tags = [label for label, rx in STRING_TAGS if rx.search(value)]
        out.append({"encoding": "ASCII", "child_file_offset": match.start(), "length_bytes": len(match.group()), "value": value, "match_tags": " | ".join(tags)})
    # UTF-16LE printable candidates at either-byte alignment; skip ASCII-only runs already reported.
    for align in (0, 1):
        start = align
        run_start = None
        chars = []
        while start + 1 < len(data):
            code = data[start] | (data[start + 1] << 8)
            printable = code in (9, 10, 13) or 0x20 <= code <= 0x7E or (code >= 0xA0 and not 0xD800 <= code <= 0xDFFF)
            if printable:
                if run_start is None:
                    run_start = start
                    chars = []
                chars.append(chr(code))
            else:
                if run_start is not None and len(chars) >= min_chars:
                    value = "".join(chars)
                    tags = [label for label, rx in STRING_TAGS if rx.search(value)]
                    out.append({"encoding": "UTF-16LE", "child_file_offset": run_start, "length_bytes": len(chars) * 2, "value": value, "match_tags": " | ".join(tags)})
                run_start = None
                chars = []
            start += 2
        if run_start is not None and len(chars) >= min_chars:
            value = "".join(chars)
            tags = [label for label, rx in STRING_TAGS if rx.search(value)]
            out.append({"encoding": "UTF-16LE", "child_file_offset": run_start, "length_bytes": len(chars) * 2, "value": value, "match_tags": " | ".join(tags)})
    # Multiple alignments can produce duplicate or overlapping hits; retain each distinct range.
    dedup = {(r["encoding"], r["child_file_offset"], r["length_bytes"], r["value"]): r for r in out}
    return sorted(dedup.values(), key=lambda r: (r["child_file_offset"], r["encoding"], r["length_bytes"]))


def candidate_calls(data: bytes, pe: dict[str, Any], imports: list[dict[str, Any]], exports: list[dict[str, Any]], lineage: dict[str, Any], capstone_info: dict[str, Any] | None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if capstone_info is None:
        return [], {"status": "capstone-unavailable", "instructions": 0, "candidates": 0, "version": ""}
    from capstone import (  # type: ignore
        Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_GRP_CALL,
    )
    from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP  # type: ignore
    if pe["machine"] not in {0x14C, 0x8664}:
        return [], {"status": f"unsupported-machine-0x{pe['machine']:04X}", "instructions": 0, "candidates": 0, "version": capstone_info["version"]}
    mode = CS_MODE_32 if pe["optional_magic"] == 0x10B else CS_MODE_64
    md = Cs(CS_ARCH_X86, mode)
    md.detail = True
    md.skipdata = True
    iat = {}
    for imp in imports:
        rva = int(imp["iat_rva"], 16)
        iat[rva] = (imp["dll_name"], imp["import_name"], imp["ordinal"])
    exp_by_rva = {int(e["function_rva"], 16): e["name"] for e in exports if e.get("name")}
    rows = []
    total_insn = 0
    for section in pe["sections"]:
        if not section["characteristics"] & 0x20000000:
            continue
        raw_off = section["raw_file_offset"]
        raw_size = section["raw_size"]
        code = data[raw_off:raw_off + raw_size]
        base_va = pe["image_base"] + section["virtual_address"]
        for ins in md.disasm(code, base_va):
            total_insn += 1
            if ins.id == 0:
                continue
            is_call = ins.group(CS_GRP_CALL)
            is_jump = ins.mnemonic.lower() in {"jmp", "ljmp"}
            if not is_call and not is_jump:
                continue
            target_rva = ""
            target_import = ("", "", "")
            target_export = ""
            candidate_kind = "linear-sweep-call-candidate" if is_call else "linear-sweep-indirect-jump-candidate"
            if ins.operands:
                op = ins.operands[0]
                if op.type == X86_OP_IMM:
                    target_va = int(op.imm)
                    target_rva_int = target_va - pe["image_base"]
                    if 0 <= target_rva_int < 0x100000000:
                        target_rva = f"0x{target_rva_int:08X}"
                        target_export = exp_by_rva.get(target_rva_int, "")
                        candidate_kind = "linear-sweep-direct-call-candidate" if is_call else "linear-sweep-direct-jump-candidate"
                elif op.type == X86_OP_MEM:
                    if op.mem.base == X86_REG_RIP:
                        target_va = ins.address + ins.size + op.mem.disp
                    elif op.mem.base == 0 and op.mem.index == 0:
                        target_va = op.mem.disp
                    else:
                        target_va = None
                    if target_va is not None:
                        target_rva_int = target_va - pe["image_base"]
                        if 0 <= target_rva_int < 0x100000000:
                            target_rva = f"0x{target_rva_int:08X}"
                            target_import = iat.get(target_rva_int, ("", "", ""))
                            if target_import[0]:
                                candidate_kind = "linear-sweep-IAT-call-candidate" if is_call else "linear-sweep-IAT-jump-candidate"
            parent_offset = lineage.get("representative_payload_file_offset", 0) + (raw_off + (ins.address - base_va))
            rows.append({
                "payload_family": lineage["payload_family"], "child_payload_sha256": lineage["child_payload_sha256"],
                "machine": f"0x{pe['machine']:04X}", "section_name": section["name"],
                "child_file_offset": f"0x{raw_off + (ins.address - base_va):X}",
                "parent_representative_file_offset": f"0x{parent_offset:X}",
                "rva": f"0x{ins.address - pe['image_base']:08X}",
                "instruction_bytes": bytes(ins.bytes).hex(), "mnemonic": ins.mnemonic,
                "operand_text": ins.op_str, "candidate_kind": candidate_kind,
                "target_rva": target_rva, "target_import_dll": target_import[0],
                "target_import_name": target_import[1] or (f"ordinal-{target_import[2]}" if target_import[2] else ""),
                "target_export_name": target_export,
                "evidence_class": "Capstone linear sweep over executable-section bytes; boundaries may be desynchronized; no CFG/path validation",
            })
    return rows, {"status": "linear-sweep-only", "instructions": total_insn, "candidates": len(rows), "version": capstone_info["version"]}


def write_csv(path: Path, rows: list[dict[str, Any]], key: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = list(dict.fromkeys(k for row in rows for k in row)) or EMPTY_COLUMNS[key]
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--research-root", type=Path, default=parent_parser.RESEARCH_ROOT)
    args = parser.parse_args()
    try:
        import capstone  # type: ignore
        capstone_info: dict[str, Any] | None = {"version": getattr(capstone, "__version__", "unknown")}
    except ImportError:
        capstone_info = None

    artifact_rows = {r["sha256"]: r for r in parent_parser.csv_rows(ARTIFACTS) if r.get("sha256")}
    package_rows = parent_parser.csv_rows(INVENTORY)
    lineage_rows: list[dict[str, Any]] = []
    images: dict[str, dict[str, Any]] = {}
    sections_out: list[dict[str, Any]] = []
    imports_out: list[dict[str, Any]] = []
    exports_out: list[dict[str, Any]] = []
    resources_out: list[dict[str, Any]] = []
    strings_out: list[dict[str, Any]] = []
    calls_out: list[dict[str, Any]] = []
    issues_out: list[dict[str, Any]] = []

    # Parse parent resource tables afresh and verify the referenced byte ranges.
    child_families: dict[str, dict[str, Any]] = {}
    for package in package_rows:
        parent_path = parent_parser.resolve_package(package, artifact_rows, args.research_root)
        parent_data = parent_path.read_bytes()
        expected_parent_sha = package["representative_sha256"]
        actual_parent_sha = sha(parent_data)
        if actual_parent_sha != expected_parent_sha:
            raise SystemExit(f"parent SHA-256 mismatch for {parent_path}")
        pe = parent_parser.parse_pe(parent_data)
        root = parent_parser.parse_metadata_root(parent_data, pe)
        tables = parent_parser.metadata_tables(parent_data, root)
        for row in tables["tables"].get(40, []):
            resource_name = row.get("NameText", "")
            family = RESOURCE_NAMES.get(resource_name)
            if not family:
                continue
            if row.get("Implementation", 0) != 0:
                issues_out.append({"payload_family": family, "child_payload_sha256": "", "parse_stage": "parent-resource", "issue": "resource is not embedded in parent package", "child_file_offset": ""})
                continue
            rva = pe["resources_rva"] + row["Offset"] if pe.get("resources_rva") else 0
            entry_off = pe["rva_to_offset"](rva, 4)
            length = int.from_bytes(parent_data[entry_off:entry_off + 4], "little")
            if row["Offset"] + 4 + length > pe["resources_size"]:
                raise SystemExit(f"embedded resource exceeds parent CLI directory: {parent_path} {resource_name}")
            payload_off = entry_off + 4
            child_bytes = parent_data[payload_off:payload_off + length]
            child_sha = sha(child_bytes)
            entry = {
                "parent_filename": parent_path.name, "parent_models": package.get("models", ""),
                "parent_package_sha256": expected_parent_sha,
                "parent_manifest_token": row["_token"],
                "parent_manifest_row_file_offset": f"0x{row['_metadata_file_offset']:X}",
                "resource_name": resource_name, "payload_family": family,
                "parent_resource_rva": f"0x{rva:08X}",
                "parent_resource_entry_file_offset": f"0x{entry_off:X}",
                "parent_payload_file_offset": f"0x{payload_off:X}",
                "parent_payload_length": length, "child_payload_sha256": child_sha,
                "range_status": "parent hash verified; length prefix validated; child slice hashed in memory; not written",
            }
            lineage_rows.append(entry)
            existing = child_families.get(child_sha)
            if existing and existing["payload_family"] != family:
                raise SystemExit("same child hash appears under multiple resource-family labels")
            if not existing:
                child_families[child_sha] = {
                    "payload_family": family, "child_payload_sha256": child_sha,
                    "length": length, "data": child_bytes,
                    "representative_payload_file_offset": payload_off,
                    "representative_parent_filename": parent_path.name,
                    "representative_parent_package_sha256": expected_parent_sha,
                }
            elif existing["length"] != length:
                raise SystemExit("same child hash has inconsistent length")

    for child_sha, lineage in child_families.items():
        data = lineage["data"]
        family = lineage["payload_family"]
        image_row = {
            "payload_family": family, "child_payload_sha256": child_sha,
            "length": len(data), "parse_status": "ok",
            "representative_parent_filename": lineage["representative_parent_filename"],
            "representative_parent_package_sha256": lineage["representative_parent_package_sha256"],
            "representative_parent_payload_file_offset": f"0x{lineage['representative_payload_file_offset']:X}",
        }
        try:
            pe = parse_pe(data)
            architecture = {0x14C: "x86", 0x8664: "x86-64", 0x1C0: "ARM", 0xAA64: "ARM64"}.get(pe["machine"], "unknown")
            imports, import_desc_count = parse_imports(data, pe, 1, False)
            delay_imports, delay_desc_count = parse_imports(data, pe, 13, True)
            imports.extend(delay_imports)
            exports = parse_exports(data, pe)
            child_resources = parse_resources(data, pe)
            strings = scan_strings(data)
            sweep_rows, sweep_summary = candidate_calls(data, pe, imports, exports, lineage, capstone_info)
            calls_out.extend(sweep_rows)
            images[child_sha] = image_row
            image_row.update({
                "machine": f"0x{pe['machine']:04X}", "architecture": architecture,
                "pe_format": pe["pe_format"], "image_base": f"0x{pe['image_base']:X}",
                "entrypoint_rva": f"0x{pe['entrypoint_rva']:08X}",
                "section_count": len(pe["sections"]),
                "import_dll_count": len({imp["dll_name"].lower() for imp in imports}),
                "import_symbol_count": len(imports), "delay_import_count": len(delay_imports),
                "export_count": len(exports), "resource_count": len(child_resources),
                "ascii_string_count": sum(s["encoding"] == "ASCII" for s in strings),
                "utf16_string_count": sum(s["encoding"] == "UTF-16LE" for s in strings),
                "capstone_version": sweep_summary["version"],
                "sweep_instruction_count": sweep_summary["instructions"],
                "sweep_candidate_count": sweep_summary["candidates"],
                "sweep_status": sweep_summary["status"],
                "parse_issue": "",
            })
            for section in pe["sections"]:
                flags = section["characteristics"]
                sections_out.append({
                    "payload_family": family, "child_payload_sha256": child_sha,
                    **section, "virtual_address": f"0x{section['virtual_address']:08X}",
                    "raw_file_offset": f"0x{section['raw_file_offset']:X}",
                    "characteristics": f"0x{flags:08X}",
                    "executable": bool(flags & 0x20000000),
                    "readable": bool(flags & 0x40000000),
                    "writable": bool(flags & 0x80000000),
                })
            for imp in imports:
                imports_out.append({
                    "payload_family": family, "child_payload_sha256": child_sha,
                    **imp, "evidence_class": "PE import-table declaration; not proof of use or call execution",
                })
            for exp in exports:
                exports_out.append({
                    "payload_family": family, "child_payload_sha256": child_sha,
                    **exp, "evidence_class": "PE export-table declaration; not proof of call or availability at runtime",
                })
            for resource in child_resources:
                resources_out.append({
                    "payload_family": family, "child_payload_sha256": child_sha,
                    **resource, "evidence_class": "PE resource directory location and in-memory hash; payload not extracted",
                })
            for string in strings:
                parent_file_offset = lineage["representative_payload_file_offset"] + string["child_file_offset"]
                strings_out.append({
                    "payload_family": family, "child_payload_sha256": child_sha,
                    "encoding": string["encoding"],
                    "child_file_offset": f"0x{string['child_file_offset']:X}",
                    "parent_representative_file_offset": f"0x{parent_file_offset:X}",
                    "length_bytes": string["length_bytes"], "value": string["value"],
                    "match_tags": string["match_tags"],
                    "evidence_class": "printable-byte string candidate; not proof of use or call path",
                })
        except (ParseIssue, struct.error, IndexError, KeyError, ValueError) as exc:
            image_row["parse_status"] = "unresolved"
            image_row["parse_issue"] = str(exc)
            images[child_sha] = image_row
            issues_out.append({"payload_family": family, "child_payload_sha256": child_sha, "parse_stage": "PE-or-static-inventory", "issue": str(exc), "child_file_offset": ""})

    image_rows = list(images.values())
    payload_family_counts = Counter(x["payload_family"] for x in lineage_rows)
    for key, output in OUT.items():
        rows = {
            "lineage": lineage_rows, "images": image_rows, "sections": sections_out,
            "imports": imports_out, "exports": exports_out, "resources": resources_out,
            "strings": strings_out, "calls": calls_out, "issues": issues_out,
        }[key]
        write_csv(output, rows, key)
    print(json.dumps({
        "parent_resource_links": len(lineage_rows),
        "unique_child_payloads": len(child_families),
        "payload_families": dict(payload_family_counts),
        "parsed_payloads": sum(r.get("parse_status") == "ok" for r in image_rows),
        "section_rows": len(sections_out), "import_rows": len(imports_out),
        "export_rows": len(exports_out), "resource_rows": len(resources_out),
        "string_rows": len(strings_out), "linear_call_candidates": len(calls_out),
        "issues": len(issues_out), "capstone_version": capstone_info["version"] if capstone_info else "unavailable",
        "outputs": {k: str(v) for k, v in OUT.items()},
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
