#!/usr/bin/env python3
"""Hash-pinned static call-path pass for non-S98 RK firmware PE profiles.

Reads PE bytes and the committed static inventories. It never runs a vendor
package, extracts an archive/payload, opens HID, or sends data to hardware.
Direct-entrypoint reachability is a conservative bounded x86 CFG walk, not a
proof of runtime execution; unresolved indirect control flow is retained.

Requires pefile and capstone from requirements-audit.txt.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import struct
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RESEARCH_ROOT = ROOT.parent / ".research"
FAMILY_CSV = ROOT / "docs" / "rk-firmware-pe-code-families-2026-10-20.csv"
PACKAGE_CSV = ROOT / "docs" / "rk-firmware-pe-package-detail-2026-10-20.csv"
ARTIFACT_CSV = ROOT / "docs" / "rk-firmware-artifact-inventory-2026-10-19.csv"
OUT = {
    "profiles": ROOT / "docs" / "rk-firmware-pe-call-path-profile-inventory-2026-10-20.csv",
    "clr": ROOT / "docs" / "rk-firmware-clr-profile-inventory-2026-10-20.csv",
    "calls": ROOT / "docs" / "rk-firmware-pe-import-callsite-evidence-2026-10-20.csv",
    "reachability": ROOT / "docs" / "rk-firmware-pe-entrypoint-import-reachability-2026-10-20.csv",
    "gates": ROOT / "docs" / "rk-firmware-pe-model-pid-callsite-candidates-2026-10-20.csv",
    "indirect": ROOT / "docs" / "rk-firmware-pe-unresolved-indirect-call-evidence-2026-10-20.csv",
}
MAX_BLOCKS_PER_ROOT = 250_000
MAX_INSTRUCTIONS_PER_ROOT = 500_000
MAX_CALL_DEPTH = 48


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        fieldnames = list(dict.fromkeys(key for row in rows for key in row))
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def resolve_artifact(row: dict[str, str], research_root: Path) -> Path:
    rel = row.get("local_path", "")
    if rel.startswith(".research/"):
        path = research_root / Path(rel[len(".research/"):])
        if path.is_file():
            return path
    fallback = list(research_root.rglob(row["filename"]))
    for path in fallback:
        if path.is_file():
            return path
    raise FileNotFoundError(f"no local research-cache file for {row.get('filename')}")


def label(value: bytes | None) -> str:
    return value.decode("ascii", "replace") if value else ""


def data_offset(pe: pefile.PE, rva: int) -> int | None:
    try:
        return int(pe.get_offset_from_rva(rva))
    except Exception:
        return None


def import_inventory(pe: pefile.PE) -> tuple[dict[int, dict[str, str]], list[dict[str, str]]]:
    by_iat: dict[int, dict[str, str]] = {}
    rows: list[dict[str, str]] = []
    for kind, attr in (("normal", "DIRECTORY_ENTRY_IMPORT"), ("delay", "DIRECTORY_ENTRY_DELAY_IMPORT")):
        for descriptor in getattr(pe, attr, []) or []:
            dll = label(descriptor.dll)
            for imp in descriptor.imports:
                api = label(imp.name) or (f"ordinal_{imp.ordinal}" if imp.ordinal is not None else "")
                row = {"dll": dll, "api": api, "import_kind": kind, "iat_va": f"0x{int(imp.address):08X}"}
                by_iat[int(imp.address)] = row
                rows.append(row)
    return by_iat, sorted(rows, key=lambda r: (r["dll"].casefold(), r["api"].casefold(), r["import_kind"]))


def api_category(dll: str, api: str) -> str:
    dll_cf = dll.casefold()
    api_cf = api.casefold()
    if dll_cf == "hid.dll" or api_cf.startswith(("hidd_", "hidp_")):
        return "HID"
    if dll_cf == "setupapi.dll" or api_cf.startswith("setupdi"):
        return "SetupAPI"
    if dll_cf in {"winusb.dll", "libusb-1.0.dll"} or api_cf.startswith("winusb_"):
        return "WinUSB/USB"
    if api_cf in {
        "setcommstate", "getcommstate", "setcommtimeouts", "getcommtimeouts",
        "setcommmask", "getcommmask", "setupcomm", "escapecommfunction",
        "purgecomm", "clearcommerror", "waitcommevent", "getcommmodemstatus",
        "getcommproperties", "getcommconfig", "setcommconfig",
    }:
        return "serial-specific API"
    if api_cf in {"createfilea", "createfilew", "readfile", "writefile", "deviceiocontrol", "getoverlappedresult"}:
        return "generic file/device I/O (transport unresolved)"
    return "other"


def exec_sections(pe: pefile.PE) -> list[dict[str, Any]]:
    result = []
    for section in pe.sections:
        if not int(section.Characteristics) & 0x20000000:
            continue
        data = section.get_data()
        if not data:
            continue
        va = int(pe.OPTIONAL_HEADER.ImageBase) + int(section.VirtualAddress)
        result.append({
            "name": section.Name.rstrip(b"\0").decode("ascii", "replace"),
            "va": va,
            "rva": int(section.VirtualAddress),
            "raw_offset": int(section.PointerToRawData),
            "size": len(data),
            "data": data,
            "sha256": sha(data),
        })
    return result


def section_for_va(sections: list[dict[str, Any]], address: int) -> dict[str, Any] | None:
    for section in sections:
        if section["va"] <= address < section["va"] + section["size"]:
            return section
    return None


def imported_iat_target(ins: Any, iat: dict[int, dict[str, str]]) -> dict[str, str] | None:
    if not ins.operands or ins.operands[0].type != X86_OP_MEM:
        return None
    operand = ins.operands[0]
    if operand.mem.base != 0 or operand.mem.index != 0:
        return None
    return iat.get(int(operand.mem.disp) & 0xFFFFFFFF)


def callsite_record(ins: Any, section: dict[str, Any], image_base: int, imported: dict[str, str], package_hash: str, filename: str) -> dict[str, str]:
    rva = int(ins.address) - image_base
    offset = data_offset_from_rva(rva, section, image_base)
    return {
        "package_sha256": package_hash,
        "filename": filename,
        "section": section["name"],
        "instruction_va": f"0x{int(ins.address):08X}",
        "instruction_rva": f"0x{rva:08X}",
        "file_offset": f"0x{offset:08X}" if offset is not None else "",
        "instruction_bytes": ins.bytes.hex(" "),
        "disassembly": f"{ins.mnemonic} {ins.op_str}".strip(),
        "branch_kind": ins.mnemonic,
        "import_dll": imported["dll"],
        "import_api": imported["api"],
        "import_kind": imported["import_kind"],
        "iat_va": imported["iat_va"],
        "api_class": api_category(imported["dll"], imported["api"]),
    }


def data_offset_from_rva(rva: int, section: dict[str, Any], image_base: int) -> int | None:
    section_rva = section["rva"]
    if not section_rva <= rva < section_rva + section["size"]:
        return None
    return int(section.get("raw_offset", 0)) + rva - section_rva if section.get("raw_offset") is not None else None


def exports(pe: pefile.PE) -> list[dict[str, Any]]:
    result = []
    for symbol in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", []) or []:
        rva = int(symbol.address)
        if rva == 0 or getattr(symbol, "forwarder", None):
            continue
        name = label(getattr(symbol, "name", None))
        result.append({"name": name, "ordinal": int(symbol.ordinal), "rva": rva})
    return result


def static_entrypoint_walk(
    pe: pefile.PE,
    roots: list[tuple[str, int]],
    sections: list[dict[str, Any]],
    iat: dict[int, dict[str, str]],
    package_hash: str,
    filename: str,
) -> tuple[set[int], dict[int, dict[str, Any]], list[dict[str, str]], dict[str, Any]]:
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    instruction_addresses: set[int] = set()
    reachable_imports: dict[int, dict[str, Any]] = {}
    unresolved: dict[int, dict[str, str]] = {}
    root_summaries = []
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    for root_label, root_va in roots:
        queue = deque([(root_va, (root_va,))])
        visited_blocks: set[int] = set()
        visited_instructions: set[int] = set()
        decoded_count = 0
        stop_reason = "queue-exhausted"
        while queue and len(visited_blocks) < MAX_BLOCKS_PER_ROOT and decoded_count < MAX_INSTRUCTIONS_PER_ROOT:
            start, call_path = queue.popleft()
            sec = section_for_va(sections, start)
            if sec is None:
                continue
            if start in visited_blocks:
                continue
            visited_blocks.add(start)
            address = start
            while decoded_count < MAX_INSTRUCTIONS_PER_ROOT:
                sec = section_for_va(sections, address)
                if sec is None or address in visited_instructions:
                    break
                offset = address - sec["va"]
                chunk = sec["data"][offset:offset + 15]
                ins_list = list(md.disasm(chunk, address, count=1))
                if not ins_list:
                    stop_reason = "undecodable-byte"
                    break
                ins = ins_list[0]
                visited_instructions.add(address)
                instruction_addresses.add(address)
                decoded_count += 1
                imported = imported_iat_target(ins, iat)
                if imported and ins.mnemonic in {"call", "jmp"}:
                    item = reachable_imports.setdefault(int(ins.address), {
                        "site": callsite_record(ins, sec, image_base, imported, package_hash, filename),
                        "roots": set(),
                        "paths": [],
                    })
                    item["roots"].add(root_label)
                    path_text = " -> ".join(f"0x{va - image_base:08X}" for va in call_path)
                    item["paths"].append(path_text + f" -> {imported['api']}@0x{int(ins.address) - image_base:08X}")
                if ins.mnemonic in {"ret", "retf", "retn", "iret", "iretd"}:
                    break
                if ins.mnemonic == "call":
                    if ins.operands and ins.operands[0].type == X86_OP_IMM:
                        target = int(ins.operands[0].imm) & 0xFFFFFFFF
                        if section_for_va(sections, target) and len(call_path) < MAX_CALL_DEPTH:
                            queue.append((target, call_path + (target,)))
                    elif not imported:
                        unresolved[int(ins.address)] = {
                            "package_sha256": package_hash, "filename": filename,
                            "instruction_va": f"0x{int(ins.address):08X}",
                            "instruction_rva": f"0x{int(ins.address) - image_base:08X}",
                            "section": sec["name"], "instruction_bytes": ins.bytes.hex(" "),
                            "disassembly": f"{ins.mnemonic} {ins.op_str}".strip(),
                            "flow": "entrypoint-rooted indirect call target unresolved",
                        }
                    address += ins.size
                    continue
                if ins.mnemonic in {"jmp", "ljmp"}:
                    if imported:
                        break
                    if ins.operands and ins.operands[0].type == X86_OP_IMM:
                        target = int(ins.operands[0].imm) & 0xFFFFFFFF
                        if section_for_va(sections, target):
                            queue.append((target, call_path))
                        break
                    unresolved[int(ins.address)] = {
                        "package_sha256": package_hash, "filename": filename,
                        "instruction_va": f"0x{int(ins.address):08X}",
                        "instruction_rva": f"0x{int(ins.address) - image_base:08X}",
                        "section": sec["name"], "instruction_bytes": ins.bytes.hex(" "),
                        "disassembly": f"{ins.mnemonic} {ins.op_str}".strip(),
                        "flow": "entrypoint-rooted indirect jump target unresolved",
                    }
                    break
                is_conditional = ins.mnemonic.startswith("j") and ins.mnemonic != "jmp" or ins.mnemonic.startswith("loop")
                if is_conditional:
                    imm = next((int(op.imm) & 0xFFFFFFFF for op in ins.operands if op.type == X86_OP_IMM), None)
                    if imm is not None and section_for_va(sections, imm):
                        queue.append((imm, call_path))
                address += ins.size
        if queue:
            stop_reason = "configured-static-walk-limit"
        root_summaries.append({
            "root": root_label,
            "root_rva": f"0x{root_va - image_base:08X}",
            "visited_blocks": len(visited_blocks),
            "decoded_instructions": decoded_count,
            "root_walk_status": stop_reason,
        })
    unresolved_rows = list(unresolved.values())
    return instruction_addresses, reachable_imports, unresolved_rows, {"roots": root_summaries}


def parse_clr(pe: pefile.PE) -> dict[str, Any]:
    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]]
    rva, size = int(directory.VirtualAddress), int(directory.Size)
    out: dict[str, Any] = {
        "clr_directory_rva": f"0x{rva:08X}" if rva else "",
        "clr_directory_size": size,
        "clr_header_size": "",
        "runtime_major": "", "runtime_minor": "",
        "metadata_rva": "", "metadata_size": "", "metadata_version": "",
        "metadata_streams": "", "clr_flags": "", "clr_entrypoint": "",
        "clr_entrypoint_kind": "", "managed_native_header_rva": "", "managed_native_header_size": "",
    }
    if not rva or size < 72:
        return out
    data = pe.get_data(rva, 72)
    if len(data) < 72:
        return out
    values = struct.unpack_from("<IHH" + "I" * 16, data, 0)
    cb, major, minor = values[:3]
    meta_rva, meta_size, flags, entrypoint = values[3:7]
    native_rva, native_size = values[17:19]
    out.update({
        "clr_header_size": cb,
        "runtime_major": major, "runtime_minor": minor,
        "metadata_rva": f"0x{meta_rva:08X}", "metadata_size": meta_size,
        "clr_flags": f"0x{flags:08X}",
        "clr_entrypoint": f"0x{entrypoint:08X}",
        "clr_entrypoint_kind": "native-rva" if flags & 0x10 else "managed-token",
        "managed_native_header_rva": f"0x{native_rva:08X}" if native_rva else "",
        "managed_native_header_size": native_size,
    })
    if meta_rva and meta_size:
        metadata = pe.get_data(meta_rva, min(meta_size, 64 * 1024 * 1024))
        if len(metadata) >= 20 and metadata[:4] == b"BSJB":
            version_len = struct.unpack_from("<I", metadata, 12)[0]
            version_start, version_end = 16, min(16 + version_len, len(metadata))
            version = metadata[version_start:version_end].split(b"\0", 1)[0].decode("ascii", "replace")
            pos = 16 + ((version_len + 3) & ~3)
            streams = []
            if pos + 4 <= len(metadata):
                count = struct.unpack_from("<H", metadata, pos + 2)[0]
                pos += 4
                for _ in range(min(count, 64)):
                    if pos + 8 > len(metadata):
                        break
                    stream_offset, stream_size = struct.unpack_from("<II", metadata, pos)
                    pos += 8
                    end = metadata.find(b"\0", pos, min(pos + 32, len(metadata)))
                    if end < 0:
                        break
                    name = metadata[pos:end].decode("ascii", "replace")
                    pos = (end + 4) & ~3
                    streams.append(f"{name}@0x{stream_offset:x}+0x{stream_size:x}")
            out["metadata_version"] = version
            out["metadata_streams"] = " | ".join(streams)
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--research-root", type=Path, default=DEFAULT_RESEARCH_ROOT)
    args = parser.parse_args()
    family_rows = read_csv(FAMILY_CSV)
    package_rows = read_csv(PACKAGE_CSV)
    artifact_rows = read_csv(ARTIFACT_CSV)
    details_by_profile = defaultdict(list)
    for row in package_rows:
        details_by_profile[row["executable_section_fingerprint"]].append(row)
    artifacts_by_hash = {row["sha256"]: row for row in artifact_rows if row.get("sha256")}

    target_profiles = [r for r in family_rows if r["s98_executable_code_match"] != "yes"]
    profile_rows_out: list[dict[str, Any]] = []
    clr_rows_out: list[dict[str, Any]] = []
    call_rows_out: list[dict[str, Any]] = []
    reach_rows_out: list[dict[str, Any]] = []
    gate_rows_out: list[dict[str, Any]] = []
    indirect_rows_out: list[dict[str, Any]] = []

    for family in target_profiles:
        profile_hash = family["executable_section_fingerprint"]
        detail = next((r for r in details_by_profile[profile_hash] if r["package_sha256"] == family["representative_sha256"]), details_by_profile[profile_hash][0])
        artifact = artifacts_by_hash.get(detail["package_sha256"])
        if artifact is None:
            raise SystemExit(f"no artifact inventory row for {detail['package_sha256']}")
        path = resolve_artifact(artifact, args.research_root)
        raw = path.read_bytes()
        observed_hash = sha(raw)
        if observed_hash != detail["package_sha256"]:
            raise SystemExit(f"representative hash mismatch: {path} expected={detail['package_sha256']} actual={observed_hash}")
        pe = pefile.PE(data=raw, fast_load=False)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
        ])
        iat, imports = import_inventory(pe)
        sections = exec_sections(pe)
        exports_found = exports(pe)
        image_base = int(pe.OPTIONAL_HEADER.ImageBase)
        entrypoint_rva = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        entrypoint_va = image_base + entrypoint_rva if entrypoint_rva else 0
        clr = detail["clr_header_present"].lower() == "true"
        selector_pid_text = family.get("pids", "")
        pid_set = {x.upper() for x in re.findall(r"(?i)(?<![0-9a-f])[0-9a-f]{4}(?![0-9a-f])", selector_pid_text)}
        overlay_pid = detail.get("overlay_pid_be", "")
        if overlay_pid:
            pid_set.add(overlay_pid.removeprefix("0x").upper())
        match_values = {int(x, 16) for x in pid_set}
        match_values.add(0x258A)

        roots: list[tuple[str, int]] = []
        if entrypoint_va:
            roots.append(("entrypoint", entrypoint_va))
        for exported in exports_found:
            roots.append(("export:" + (exported["name"] or f"ordinal_{exported['ordinal']}"), image_base + exported["rva"]))
        if not roots and sections:
            roots.append(("no-entrypoint-export-roots", sections[0]["va"]))

        reachable_ins: set[int] = set()
        reachable_imports: dict[int, dict[str, Any]] = {}
        root_meta: dict[str, Any] = {"roots": []}
        unresolved: list[dict[str, str]] = []
        if not clr:
            reachable_ins, reachable_imports, unresolved, root_meta = static_entrypoint_walk(
                pe, roots, sections, iat, detail["package_sha256"], path.name
            )

        # The full executable sections are scanned once more linearly so
        # callsites missed by the entrypoint-rooted CFG remain visible.
        linear_sites: dict[int, dict[str, str]] = {}
        cmp_candidates: list[dict[str, str]] = []
        if not clr:
            md = Cs(CS_ARCH_X86, CS_MODE_32)
            md.detail = True
            for section in sections:
                for ins in md.disasm(section["data"], section["va"]):
                    imported = imported_iat_target(ins, iat)
                    if imported and ins.mnemonic in {"call", "jmp"}:
                        linear_sites[int(ins.address)] = callsite_record(ins, section, image_base, imported, detail["package_sha256"], path.name)
                    if ins.mnemonic == "cmp":
                        for operand in ins.operands:
                            if operand.type == X86_OP_IMM:
                                value = int(operand.imm) & 0xFFFFFFFF
                                if value in match_values:
                                    file_off = None
                                    try:
                                        file_off = int(pe.get_offset_from_rva(int(ins.address) - image_base))
                                    except Exception:
                                        pass
                                    cmp_candidates.append({
                                        "profile_fingerprint": profile_hash,
                                        "package_sha256": detail["package_sha256"],
                                        "filename": path.name,
                                        "section": section["name"],
                                        "instruction_va": f"0x{int(ins.address):08X}",
                                        "instruction_rva": f"0x{int(ins.address) - image_base:08X}",
                                        "file_offset": f"0x{file_off:08X}" if file_off is not None else "",
                                        "instruction_bytes": ins.bytes.hex(" "),
                                        "disassembly": f"{ins.mnemonic} {ins.op_str}",
                                        "compared_value": f"0x{value:X}",
                                        "matches_selector_pid": str(value in {int(x, 16) for x in pid_set if re.fullmatch(r"[0-9A-Fa-f]{4}", x)}).lower(),
                                        "reachable_from_entrypoint_or_export": str(int(ins.address) in reachable_ins).lower(),
                                        "evidence_class": "linear-sweep immediate comparison candidate; semantic role and branch outcome unproven",
                                    })

        for address, call in sorted(linear_sites.items()):
            reachable = reachable_imports.get(address)
            call_rows_out.append({
                "profile_fingerprint": profile_hash,
                **call,
                "entrypoint_or_export_reachable": "yes" if reachable else "not-observed-by-static-root-walk",
                "reachable_root_labels": " | ".join(sorted(reachable["roots"])) if reachable else "",
                "reachable_call_chain": min(reachable["paths"], key=len) if reachable and reachable["paths"] else "",
                "evidence_class": "imported call/jump candidate from linear disassembly; static-root reachability recorded separately",
            })
        for site, reachable in sorted(reachable_imports.items()):
            call = reachable["site"]
            reach_rows_out.append({
                "profile_fingerprint": profile_hash,
                **call,
                "root_labels": " | ".join(sorted(reachable["roots"])),
                "entrypoint_call_chain": min(reachable["paths"], key=len) if reachable["paths"] else "",
                "evidence_class": "decoded through direct entrypoint/export-rooted CFG; runtime execution not observed",
            })
        gate_rows_out.extend(cmp_candidates)
        indirect_rows_out.extend(unresolved)

        clr_info = parse_clr(pe) if clr else {}
        normal_imports = [r for r in imports if r["import_kind"] == "normal"]
        api_classes = defaultdict(set)
        for imp in imports:
            category = api_category(imp["dll"], imp["api"])
            if category != "other":
                api_classes[category].add(imp["dll"] + "!" + imp["api"])
        profile_record = {
            "profile_fingerprint": profile_hash,
            "representative_sha256": detail["package_sha256"],
            "filename": path.name,
            "models": family.get("models", ""),
            "selector_pids": selector_pid_text,
            "clr_header_present": str(clr).lower(),
            "machine": f"0x{int(pe.FILE_HEADER.Machine):04X}",
            "image_base": f"0x{image_base:08X}",
            "entrypoint_rva": f"0x{entrypoint_rva:08X}" if entrypoint_rva else "",
            "export_count": len(exports_found),
            "exports": " | ".join(x["name"] or f"ordinal_{x['ordinal']}" for x in exports_found),
            "executable_sections": " | ".join(f"{s['name']}@0x{s['rva']:08X}+0x{s['size']:X} sha256={s['sha256']}" for s in sections),
            "import_count": len(imports),
            "normal_import_count": len(normal_imports),
            "clr_runtime_imports": " | ".join(sorted(imp["dll"] + "!" + imp["api"] for imp in imports)) if clr else "",
            "imported_hid_apis": " | ".join(sorted(api_classes.get("HID", set()))),
            "imported_setupapi_apis": " | ".join(sorted(api_classes.get("SetupAPI", set()))),
            "imported_winusb_apis": " | ".join(sorted(api_classes.get("WinUSB/USB", set()))),
            "imported_serial_specific_apis": " | ".join(sorted(api_classes.get("serial-specific API", set()))),
            "generic_file_device_io_apis": " | ".join(sorted(api_classes.get("generic file/device I/O (transport unresolved)", set()))),
            "linear_import_callsite_count": len(linear_sites),
            "entrypoint_rooted_import_callsite_count": len(reachable_imports),
            "unresolved_reachable_indirect_transfer_count": len(unresolved),
            "pid_or_vid_cmp_candidates": len(cmp_candidates),
            **clr_info,
        }
        profile_rows_out.append(profile_record)
        if clr:
            clr_rows_out.append(profile_record.copy())

    for key, path in OUT.items():
        rows = {
            "profiles": profile_rows_out,
            "clr": clr_rows_out,
            "calls": call_rows_out,
            "reachability": reach_rows_out,
            "gates": gate_rows_out,
            "indirect": indirect_rows_out,
        }[key]
        write_csv(path, rows)
    summary = {
        "non_s98_profiles": len(target_profiles),
        "native_profiles_traced": sum(r["clr_header_present"] == "false" for r in profile_rows_out),
        "clr_profiles_inventoried": len(clr_rows_out),
        "linear_import_callsite_candidates": len(call_rows_out),
        "entrypoint_or_export_rooted_import_candidates": len(reach_rows_out),
        "pid_vid_compare_candidates": len(gate_rows_out),
        "unresolved_reachable_indirect_transfers": len(indirect_rows_out),
        "outputs": {k: str(v) for k, v in OUT.items()},
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
