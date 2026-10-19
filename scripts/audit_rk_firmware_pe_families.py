#!/usr/bin/env python3
"""Static family analysis for acquired RK firmware-selector PE packages.

Reads only the locally acquired artifacts and the dated CSV ledgers. It does
not execute vendor code, extract archive payloads, access HID, or write to a
device. Strings and instruction rows are candidates, not proof of reachability.

Requires pefile and capstone from requirements-audit.txt.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86_const import X86_OP_IMM


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RESEARCH_ROOT = ROOT.parent / ".research"
ARTIFACT_CSV = ROOT / "docs" / "rk-firmware-artifact-inventory-2026-10-19.csv"
S98_MANIFEST = ROOT / "docs" / "rk-s98-firmware-package-manifest-2026-10-19.csv"
OUT = {
    "hash_families": ROOT / "docs" / "rk-firmware-package-hash-families-2026-10-20.csv",
    "pe_packages": ROOT / "docs" / "rk-firmware-pe-package-detail-2026-10-20.csv",
    "pe_families": ROOT / "docs" / "rk-firmware-pe-code-families-2026-10-20.csv",
    "imports": ROOT / "docs" / "rk-firmware-pe-import-family-api-ledger-2026-10-20.csv",
    "resources": ROOT / "docs" / "rk-firmware-pe-resource-ledger-2026-10-20.csv",
    "strings": ROOT / "docs" / "rk-firmware-pe-semantic-string-candidates-2026-10-20.csv",
    "gates": ROOT / "docs" / "rk-firmware-pe-model-gate-candidates-2026-10-20.csv",
}
_STRING_CACHE: dict[str, list[tuple[str, str]]] = {}
_SEMANTIC_CACHE: dict[str, list[tuple[str, str, str]]] = {}
_MODEL_PATTERN_CACHE: dict[tuple[str, ...], re.Pattern[str]] = {}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalized_pid_candidates(value: str) -> set[str]:
    return {match.upper() for match in re.findall(r"(?i)(?<![0-9a-f])[0-9a-f]{4}(?![0-9a-f])", value)}


def csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: list[dict[str, Any]], columns: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = columns or (list(rows[0]) if rows else [])
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def decode(value: bytes | None) -> str:
    return value.decode("utf-8", "replace") if value else ""


def path_for_artifact(row: dict[str, str], research_root: Path) -> Path | None:
    rel = row.get("local_path", "")
    if rel.startswith(".research/"):
        candidate = research_root / Path(rel[len(".research/"):])
        if candidate.is_file():
            return candidate
    filename = row.get("filename", "")
    if filename:
        # The suffix fallback supports inventories made from a prior cache path.
        candidates = list(research_root.rglob(filename))
        for candidate in candidates:
            if candidate.is_file():
                return candidate
    return None


def named_or_numeric(entry: Any) -> str:
    name = getattr(entry, "name", None)
    if name is not None:
        value = getattr(name, "string", name)
        if isinstance(value, bytes):
            return value.decode("utf-8", "replace")
        return str(value)
    ident = getattr(entry, "id", None)
    return str(ident) if ident is not None else ""


def resource_leaves(pe: pefile.PE) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if root is None:
        return rows

    def visit(node: Any, parts: list[str]) -> None:
        for entry in getattr(node, "entries", []):
            label = named_or_numeric(entry)
            next_parts = parts + [label]
            directory = getattr(entry, "directory", None)
            data_entry = getattr(entry, "data", None)
            if directory is not None:
                visit(directory, next_parts)
            elif data_entry is not None:
                item = data_entry.struct
                size = int(item.Size)
                data = pe.get_data(int(item.OffsetToData), size)
                type_value = parts[0] if parts else ""
                rows.append({
                    "resource_type": type_value,
                    "resource_type_name": {
                        "3": "RT_ICON", "4": "RT_MENU", "5": "RT_DIALOG",
                        "6": "RT_STRING", "10": "RT_RCDATA", "11": "RT_MESSAGETABLE",
                        "14": "RT_GROUP_ICON", "16": "RT_VERSION", "24": "RT_MANIFEST",
                    }.get(type_value, ""),
                    "resource_name": next_parts[1] if len(next_parts) > 1 else "",
                    "language": next_parts[2] if len(next_parts) > 2 else "",
                    "resource_path": "/".join(next_parts),
                    "rva": f"0x{int(item.OffsetToData):08x}",
                    "size_bytes": size,
                    "sha256": sha(data),
                    "data": data,
                })

    visit(root, [])
    return rows


def version_strings(pe: pefile.PE) -> dict[str, str]:
    values: dict[str, str] = {}
    for file_info in getattr(pe, "FileInfo", []) or []:
        for entry in file_info:
            if getattr(entry, "Key", b"") != b"StringFileInfo":
                continue
            for table in getattr(entry, "StringTable", []) or []:
                for key, value in getattr(table, "entries", {}).items():
                    values[decode(key)] = decode(value).rstrip("\x00")
    return values


def import_rows(pe: pefile.PE) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for kind, attr in (("normal", "DIRECTORY_ENTRY_IMPORT"), ("delay", "DIRECTORY_ENTRY_DELAY_IMPORT")):
        for descriptor in getattr(pe, attr, []) or []:
            dll = decode(descriptor.dll)
            for imported in descriptor.imports:
                api = decode(imported.name)
                if not api and imported.ordinal is not None:
                    api = f"ordinal_{imported.ordinal}"
                rows.append({"import_kind": kind, "dll": dll, "api": api})
    return sorted(rows, key=lambda r: (r["import_kind"], r["dll"].casefold(), r["api"].casefold()))


def strings_in(data: bytes) -> list[tuple[str, str]]:
    digest = sha(data)
    if digest in _STRING_CACHE:
        return _STRING_CACHE[digest]
    found: set[tuple[str, str]] = set()
    for match in re.finditer(rb"[\x20-\x7e]{4,}", data):
        value = match.group().decode("ascii", "replace").strip()
        if value:
            found.add(("ascii", value))
    for match in re.finditer(rb"(?:[\x20-\x7e]\x00){4,}", data):
        value = match.group()[::2].decode("ascii", "replace").strip()
        if value:
            found.add(("utf16le-ascii", value))
    result = sorted(found)
    _STRING_CACHE[digest] = result
    return result


def model_pattern(models: list[str]) -> re.Pattern[str]:
    key = tuple(sorted(set(models)))
    cached = _MODEL_PATTERN_CACHE.get(key)
    if cached is not None:
        return cached
    alternatives = []
    for index, model in enumerate(key):
        tokens = re.findall(r"[A-Z0-9]+", model.upper())
        if tokens:
            expr = r"[\W_]*".join(re.escape(token) for token in tokens)
            alternatives.append(r"(?<![A-Z0-9])(?P<m" + str(index) + ">" + expr + r")(?![A-Z0-9])")
    compiled = re.compile("|".join(alternatives) or r"(?!)", re.IGNORECASE)
    _MODEL_PATTERN_CACHE[key] = compiled
    return compiled


def semantically_relevant(text: str, models: list[str], pids: set[str]) -> list[str]:
    tags: list[str] = []
    if re.search(r"(?i)\b(?:royal\s+kludge|rk\s+gaming|keyboard|firmware|update\s+tool|serial\s+number|bootloader|hid|sino)\b", text):
        tags.append("software-or-device-term")
    models_by_group = {f"m{i}": model for i, model in enumerate(sorted(set(models)))}
    for match in model_pattern(models).finditer(text):
        matched = match.lastgroup
        if matched in models_by_group:
            tags.append("selector-model:" + models_by_group[matched])
    hex_tokens = {x.upper().removeprefix("0X") for x in re.findall(r"(?i)(?<![0-9a-f])(?:0x)?[0-9a-f]{4}(?![0-9a-f])", text)}
    if hex_tokens & {x.upper().removeprefix("0X") for x in pids}:
        tags.append("selector-pid-literal")
    return sorted(set(tags))


def semantic_strings(data: bytes, models: list[str], pids: set[str]) -> list[tuple[str, str, str]]:
    digest = sha(data)
    cached = _SEMANTIC_CACHE.get(digest)
    if cached is None:
        cached = []
        for encoding, value in strings_in(data):
            tags = semantically_relevant(value, models, pids)
            if tags:
                cached.append((encoding, value, ";".join(tags)))
        _SEMANTIC_CACHE[digest] = cached
    return cached


def overlay_fields(raw: bytes, end_of_pe: int) -> dict[str, Any]:
    overlay = raw[end_of_pe:]
    item: dict[str, Any] = {
        "overlay_offset": end_of_pe,
        "overlay_size": len(overlay),
        "overlay_sha256": sha(overlay) if overlay else "",
        "overlay_marker": "",
        "overlay_vid_be": "",
        "overlay_pid_be": "",
        "overlay_declared_payload_size": "",
        "overlay_payload_sha256": "",
        "overlay_trailer_size": "",
        "overlay_layout_candidate": "no",
    }
    if len(overlay) >= 12 and overlay[:6] == b"\x5a\xa5SINO":
        size = int.from_bytes(overlay[10:12], "big")
        payload = overlay[12:12 + size]
        trailer = overlay[12 + size:]
        item.update({
            "overlay_marker": "5AA5SINO",
            "overlay_vid_be": f"0x{int.from_bytes(overlay[6:8], 'big'):04X}",
            "overlay_pid_be": f"0x{int.from_bytes(overlay[8:10], 'big'):04X}",
            "overlay_declared_payload_size": size,
            "overlay_payload_sha256": sha(payload) if payload else "",
            "overlay_trailer_size": len(trailer),
            "overlay_layout_candidate": "yes" if len(payload) == size and len(trailer) == 4 else "partial-or-different-layout",
        })
    return item


def parse_one(path: Path, source_rows: list[dict[str, str]], known_models: list[str], known_pids: set[str]) -> dict[str, Any]:
    raw = path.read_bytes()
    digest = sha(raw)
    pe = pefile.PE(data=raw, fast_load=False)
    pe.parse_data_directories(directories=[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
    ])
    imports = import_rows(pe)
    resources = resource_leaves(pe)
    sections: list[dict[str, Any]] = []
    file_end = int(pe.OPTIONAL_HEADER.SizeOfHeaders)
    executable_hashes: list[tuple[str, str, int]] = []
    for section in pe.sections:
        name = section.Name.rstrip(b"\0").decode("ascii", "replace")
        data = section.get_data()
        pointer, size = int(section.PointerToRawData), int(section.SizeOfRawData)
        if size and pointer:
            file_end = max(file_end, pointer + size)
        executable = bool(int(section.Characteristics) & 0x20000000)
        section_digest = sha(data)
        sections.append({"name": name, "size": size, "hash": section_digest, "executable": executable})
        if executable:
            executable_hashes.append((name, section_digest, size))
    exec_fingerprint = sha(json.dumps(executable_hashes, separators=(",", ":")).encode())
    section_fingerprint = sha(json.dumps([(s["name"], s["size"], s["hash"]) for s in sections], separators=(",", ":")).encode())
    resource_fingerprint = sha(json.dumps([
        (r["resource_type"], r["resource_name"], r["language"], r["size_bytes"], r["sha256"])
        for r in resources
    ], separators=(",", ":")).encode())
    import_fingerprint = sha(json.dumps(imports, separators=(",", ":")).encode())
    clr_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]]
    clr_header_present = int(clr_dir.VirtualAddress) != 0 and int(clr_dir.Size) != 0
    rows = source_rows
    selector_pids = {r.get("pid", "").upper().removeprefix("0X") for r in rows if r.get("pid")}
    comparable_selector_pids = set().union(*(normalized_pid_candidates(r.get("pid", "")) for r in rows)) if rows else set()
    overlay = overlay_fields(raw, min(file_end, len(raw)))
    version = version_strings(pe)
    fixed = (getattr(pe, "VS_FIXEDFILEINFO", []) or [None])[0]
    if fixed:
        file_ver = ".".join(str(x) for x in (fixed.FileVersionMS >> 16, fixed.FileVersionMS & 0xffff, fixed.FileVersionLS >> 16, fixed.FileVersionLS & 0xffff))
        product_ver = ".".join(str(x) for x in (fixed.ProductVersionMS >> 16, fixed.ProductVersionMS & 0xffff, fixed.ProductVersionLS >> 16, fixed.ProductVersionLS & 0xffff))
    else:
        file_ver = product_ver = ""
    hid_apis = sorted({
        r["api"] for r in imports
        if r["dll"].casefold() in {"hid.dll", "setupapi.dll"}
        or r["api"].casefold().startswith(("hidd_", "hidp_", "setupdi"))
    })
    manifest_bits: list[str] = []
    for resource in resources:
        if resource["resource_type"] == "24":
            try:
                text = resource["data"].decode("utf-8", "replace")
            except Exception:
                text = ""
            for pattern in (r"requestedExecutionLevel[^>]*", r"uiAccess\s*=\s*\"[^\"]+\"", r"level\s*=\s*\"[^\"]+\""):
                manifest_bits.extend(re.findall(pattern, text, re.IGNORECASE))

    semantic_hits: list[dict[str, str]] = []
    for section in pe.sections:
        sec_name = section.Name.rstrip(b"\0").decode("ascii", "replace")
        data = section.get_data()
        for encoding, value, tags in semantic_strings(data, known_models, known_pids):
            semantic_hits.append({"source": "section:" + sec_name, "source_sha256": sha(data), "encoding": encoding, "text": value, "tags": tags})
    for resource in resources:
        if resource["resource_type"] not in {"5", "6", "10", "16", "24"} and int(resource["size_bytes"]) > 262144:
            continue
        for encoding, value, tags in semantic_strings(resource["data"], known_models, known_pids):
            semantic_hits.append({"source": "resource:" + resource["resource_path"], "source_sha256": resource["sha256"], "encoding": encoding, "text": value, "tags": tags})
    # Search only a short overlay prefix for visible markers. The appended
    # payload remains opaque and is never decoded, transformed, or extracted.
    ov_start = int(overlay["overlay_offset"])
    overlay_prefix = raw[ov_start:ov_start + min(int(overlay["overlay_size"]), 512)]
    for encoding, value, tags in semantic_strings(overlay_prefix, known_models, known_pids):
        semantic_hits.append({"source": "overlay-prefix", "source_sha256": sha(overlay_prefix), "encoding": encoding, "text": value, "tags": tags})

    unique_hits = {(r["source"], r["encoding"], r["text"], r["tags"]): r for r in semantic_hits}
    selector_summary = "; ".join(sorted({
        " / ".join(x for x in (r.get("selector_model", ""), r.get("product_version", ""), r.get("language", ""), r.get("pid", "")) if x)
        for r in rows
    }))
    selected_models = sorted({r.get("selector_model", "") for r in rows if r.get("selector_model")})
    selected_languages = sorted({r.get("language", "") for r in rows if r.get("language")})
    overlay_pid = overlay.get("overlay_pid_be", "")
    pid_gate = (
        "no-decodable-overlay-pid" if not overlay_pid
        else "no-comparable-selector-pid" if not comparable_selector_pids
        else "matches-selector-pid" if overlay_pid.removeprefix("0x").upper() in comparable_selector_pids
        else "does-not-match-selector-pid"
    )
    file_infos = {key: version.get(key, "") for key in ("CompanyName", "FileDescription", "FileVersion", "InternalName", "OriginalFilename", "ProductName", "ProductVersion")}
    record = {
        "package_sha256": digest,
        "filename": path.name,
        "size_bytes": len(raw),
        "selector_models": " | ".join(selected_models),
        "selector_languages": " | ".join(selected_languages),
        "selector_pids": " | ".join(sorted(selector_pids)),
        "comparable_selector_pids_hex": " | ".join(sorted(comparable_selector_pids)),
        "selector_records": selector_summary,
        "selector_url_count": len({r.get("url", "") for r in rows if r.get("url")}),
        "machine": f"0x{int(pe.FILE_HEADER.Machine):04X}",
        "pe_magic": f"0x{int(pe.OPTIONAL_HEADER.Magic):04X}",
        "clr_header_present": str(clr_header_present).lower(),
        "pe_timestamp_epoch": int(pe.FILE_HEADER.TimeDateStamp),
        "entrypoint_rva": f"0x{int(pe.OPTIONAL_HEADER.AddressOfEntryPoint):08X}",
        "subsystem": int(pe.OPTIONAL_HEADER.Subsystem),
        "file_version_fixed": file_ver,
        "product_version_fixed": product_ver,
        **{k.lower(): v for k, v in file_infos.items()},
        "section_count": len(sections),
        "section_fingerprint": section_fingerprint,
        "executable_section_fingerprint": exec_fingerprint,
        "executable_section_names": " | ".join(n for n, _, _ in executable_hashes),
        "resource_leaf_count": len(resources),
        "resource_fingerprint": resource_fingerprint,
        "import_count": len(imports),
        "import_fingerprint": import_fingerprint,
        "import_dlls": " | ".join(sorted({r["dll"] for r in imports})),
        "hid_setupapi_api_names": " | ".join(hid_apis),
        "manifest_execution_literals": " | ".join(sorted(set(manifest_bits))),
        **overlay,
        "overlay_pid_selector_relation": pid_gate,
    }
    return {
        "record": record,
        "imports": imports,
        "resources": [{k: v for k, v in resource.items() if k != "data"} for resource in resources],
        "semantic_hits": list(unique_hits.values()),
        "pe": pe,
        "raw": raw,
        "path": path,
        "rows": rows,
    }


def compare_s98(research_root: Path) -> tuple[dict[str, str], dict[str, list[str]]]:
    baseline_dir = research_root / "rk-selector-software-2026-10-19" / "S98-firmware-packages"
    s98_hashes: dict[str, str] = {}
    if not baseline_dir.is_dir():
        return {}, {}
    for path in sorted(baseline_dir.glob("*.exe")):
        raw = path.read_bytes()
        if raw[:2] != b"MZ":
            continue
        pe = pefile.PE(data=raw, fast_load=True)
        exec_sections = []
        for section in pe.sections:
            if int(section.Characteristics) & 0x20000000:
                exec_sections.append((section.Name.rstrip(b"\0").decode("ascii", "replace"), sha(section.get_data()), int(section.SizeOfRawData)))
        fingerprint = sha(json.dumps(exec_sections, separators=(",", ":")).encode())
        s98_hashes[sha(raw)] = fingerprint
    file_hash_to_exec = {key: value for key, value in s98_hashes.items()}
    exec_to_s98: dict[str, list[str]] = defaultdict(list)
    for file_hash, fingerprint in s98_hashes.items():
        exec_to_s98[fingerprint].append(file_hash)
    return file_hash_to_exec, dict(exec_to_s98)


def gate_candidates(details: dict[str, Any], selector_pid_set: set[int], family_seen: set[str]) -> list[dict[str, Any]]:
    record = details["record"]
    fingerprint = record["executable_section_fingerprint"]
    if fingerprint in family_seen:
        return []
    family_seen.add(fingerprint)
    if record["clr_header_present"] == "true":
        return [{
            "executable_section_fingerprint": fingerprint,
            "representative_sha256": record["package_sha256"],
            "representative_filename": record["filename"],
            "section": "",
            "instruction_va": "",
            "instruction_rva": "",
            "bytes": "",
            "disassembly": "",
            "compared_value": "",
            "matches_known_selector_pid": "",
            "candidate_scope": "managed CLR image; native x86 linear-sweep comparison scan skipped",
        }]
    pe: pefile.PE = details["pe"]
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    rows: list[dict[str, Any]] = []
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    selector_pid_set = {x for x in selector_pid_set if x}
    for section in pe.sections:
        if not int(section.Characteristics) & 0x20000000:
            continue
        sec_name = section.Name.rstrip(b"\0").decode("ascii", "replace")
        base = image_base + int(section.VirtualAddress)
        for ins in md.disasm(section.get_data(), base):
            if ins.mnemonic != "cmp":
                continue
            imm_values = [int(op.imm) for op in ins.operands if op.type == X86_OP_IMM]
            for value in imm_values:
                if value in selector_pid_set or value == 0x258A:
                    rows.append({
                        "executable_section_fingerprint": fingerprint,
                        "representative_sha256": record["package_sha256"],
                        "representative_filename": record["filename"],
                        "section": sec_name,
                        "instruction_va": f"0x{ins.address:08X}",
                        "instruction_rva": f"0x{ins.address - image_base:08X}",
                        "bytes": ins.bytes.hex(" "),
                        "disassembly": f"{ins.mnemonic} {ins.op_str}",
                        "compared_value": f"0x{value:X}",
                        "matches_known_selector_pid": str(value in selector_pid_set).lower(),
                        "candidate_scope": "linear sweep immediate comparison candidate; function boundary, data/code separation, and reachability not established",
                    })
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--research-root", type=Path, default=DEFAULT_RESEARCH_ROOT)
    args = parser.parse_args()
    inv_rows = csv_rows(ARTIFACT_CSV)
    acquired = [r for r in inv_rows if r.get("sha256") and r.get("local_path")]
    hash_groups: dict[str, list[dict[str, str]]] = defaultdict(list)
    model_names = sorted({r.get("selector_model", "") for r in acquired if r.get("selector_model")})
    known_pids = {r.get("pid", "").upper().removeprefix("0X") for r in acquired if r.get("pid")}
    all_paths: dict[str, Path] = {}
    missing: list[str] = []
    for row in acquired:
        path = path_for_artifact(row, args.research_root)
        if path is None:
            missing.append(row.get("filename", ""))
            continue
        digest = sha(path.read_bytes())
        if digest != row["sha256"]:
            raise SystemExit(f"SHA-256 mismatch for {path}: inventory={row['sha256']} local={digest}")
        item = dict(row)
        item["_path"] = str(path)
        hash_groups[digest].append(item)
        all_paths[digest] = path

    hash_rows: list[dict[str, Any]] = []
    for digest, group in sorted(hash_groups.items()):
        first = group[0]
        hash_rows.append({
            "sha256": digest,
            "filename_variants": " | ".join(sorted({r.get("filename", "") for r in group})),
            "selector_url_count": len({r.get("url", "") for r in group}),
            "inventory_row_count": len(group),
            "selector_models": " | ".join(sorted({r.get("selector_model", "") for r in group if r.get("selector_model")})),
            "modes": " | ".join(sorted({r.get("product_version", "") for r in group if r.get("product_version")})),
            "languages": " | ".join(sorted({r.get("language", "") for r in group if r.get("language")})),
            "pids": " | ".join(sorted({r.get("pid", "") for r in group if r.get("pid")})),
            "size_bytes": first.get("size_bytes", ""),
            "sniffed_type": first.get("sniffed_type", ""),
            "artifact_class": first.get("artifact_class", ""),
            "family_members": " | ".join(sorted({r.get("filename", "") for r in group})),
        })

    rows_by_hash: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in acquired:
        rows_by_hash[row["sha256"]].append(row)
    # Compare only the executable-section hashes with the eight previously
    # audited S98 files; do not retain all parsed PE objects in memory.
    _, s98_exec_to_hash = compare_s98(args.research_root)
    pe_family_rows: list[dict[str, Any]] = []
    import_rows_out: list[dict[str, Any]] = []
    resource_rows_out: list[dict[str, Any]] = []
    string_rows_out: list[dict[str, Any]] = []
    gate_rows_out: list[dict[str, Any]] = []
    gate_family_seen: set[str] = set()
    family_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    family_imports_written: set[str] = set()
    selector_pid_ints = {int(x, 16) for x in known_pids if re.fullmatch(r"[0-9A-Fa-f]{4}", x)}
    pe_package_rows: list[dict[str, Any]] = []
    pe_candidates = [(digest, path) for digest, path in sorted(all_paths.items()) if path.read_bytes()[:2] == b"MZ"]
    for package_index, (digest, path) in enumerate(pe_candidates, 1):
        details = parse_one(path, rows_by_hash[digest], model_names, known_pids)
        rec = details["record"]
        fingerprint = rec["executable_section_fingerprint"]
        rec["s98_code_family_match"] = "yes" if fingerprint in s98_exec_to_hash else "no"
        rec["s98_matching_hashes"] = " | ".join(sorted(s98_exec_to_hash.get(fingerprint, [])))
        pe_package_rows.append(rec)
        family_groups[fingerprint].append(rec)
        for resource in details["resources"]:
            resource_rows_out.append({
                "package_sha256": rec["package_sha256"],
                "filename": rec["filename"],
                "selector_models": rec["selector_models"],
                "selector_pids": rec["selector_pids"],
                **resource,
            })
        for hit in details["semantic_hits"]:
            string_rows_out.append({"package_sha256": rec["package_sha256"], "filename": rec["filename"], **hit})
        if fingerprint not in family_imports_written:
            family_imports_written.add(fingerprint)
            for imp in details["imports"]:
                import_rows_out.append({
                    "executable_section_fingerprint": fingerprint,
                    "representative_sha256": rec["package_sha256"],
                    "representative_filename": rec["filename"],
                    **imp,
                })
            gate_rows_out.extend(gate_candidates(details, selector_pid_ints | {0x258A}, gate_family_seen))
        # Drop heavy PE and source-byte references before parsing the next file.
        details.clear()
        if package_index % 20 == 0:
            print(f"parsed PE packages: {package_index}/{len(pe_candidates)}", flush=True)

    for fingerprint, group in sorted(family_groups.items()):
        representative = group[0]
        family_s98 = bool(s98_exec_to_hash.get(fingerprint))
        sha_list = sorted({d["package_sha256"] for d in group})
        pe_family_rows.append({
            "executable_section_fingerprint": fingerprint,
            "unique_package_hash_count": len(sha_list),
            "selector_url_count": sum(int(d["selector_url_count"]) for d in group),
            "package_sha256s": " | ".join(sha_list),
            "representative_sha256": representative["package_sha256"],
            "representative_filename": representative["filename"],
            "models": " | ".join(sorted({m for d in group for m in d["selector_models"].split(" | ") if m})),
            "pids": " | ".join(sorted({p for d in group for p in d["selector_pids"].split(" | ") if p})),
            "s98_executable_code_match": "yes" if family_s98 else "no",
            "s98_hashes_for_same_code": " | ".join(sorted(s98_exec_to_hash.get(fingerprint, []))),
            "executable_sections": representative["executable_section_names"],
            "import_count": representative["import_count"],
            "import_fingerprint": representative["import_fingerprint"],
            "resource_fingerprints_seen": " | ".join(sorted({d["resource_fingerprint"] for d in group})),
            "overlay_markers_seen": " | ".join(sorted({d["overlay_marker"] or "none" for d in group})),
            "overlay_vids_seen": " | ".join(sorted({d["overlay_vid_be"] for d in group if d["overlay_vid_be"]})),
            "overlay_pids_seen": " | ".join(sorted({d["overlay_pid_be"] for d in group if d["overlay_pid_be"]})),
        })

    write_csv(OUT["hash_families"], hash_rows)
    write_csv(OUT["pe_packages"], pe_package_rows)
    write_csv(OUT["pe_families"], pe_family_rows)
    write_csv(OUT["imports"], import_rows_out)
    write_csv(OUT["resources"], resource_rows_out)
    write_csv(OUT["strings"], string_rows_out)
    write_csv(OUT["gates"], gate_rows_out)

    print(json.dumps({
        "inventory_unique_urls_with_hash": len(acquired),
        "locally_resolved_files": sum(len(group) for group in hash_groups.values()),
        "unique_full_package_sha256_families": len(hash_groups),
        "duplicate_hash_groups": sum(len(g) > 1 for g in hash_groups.values()),
        "pe_unique_file_hashes": len(pe_package_rows),
        "pe_executable_section_families": len(family_groups),
        "pe_families_matching_s98_executable_sections": sum(f["s98_executable_code_match"] == "yes" for f in pe_family_rows),
        "pe_packages_with_sino_overlay": sum(bool(d["overlay_marker"]) for d in pe_package_rows),
        "pe_packages_with_selector_pid_matching_overlay": sum(d["overlay_pid_selector_relation"] == "matches-selector-pid" for d in pe_package_rows),
        "missing_local_files": missing,
        "outputs": {k: str(v) for k, v in OUT.items()},
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
