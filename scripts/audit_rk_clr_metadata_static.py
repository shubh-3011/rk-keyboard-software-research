#!/usr/bin/env python3
"""Read-only parser for CLI metadata in hash-pinned RK updater images.

This script never loads a CLR assembly or executes any vendor code. It parses
PE/CLI headers and ECMA-335 metadata tables from raw bytes with Python stdlib.
Method bodies are only header-parsed to record RVA/file offsets and bounded
code lengths; IL is not disassembled.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import struct
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
RESEARCH_ROOT = ROOT.parent / ".research"
INVENTORY = ROOT / "docs" / "rk-firmware-clr-profile-inventory-2026-10-20.csv"
ARTIFACTS = ROOT / "docs" / "rk-firmware-artifact-inventory-2026-10-19.csv"
OUT = {
    "rows": ROOT / "docs" / "rk-firmware-clr-metadata-row-ledger-2026-10-20.csv",
    "names": ROOT / "docs" / "rk-firmware-clr-target-name-ledger-2026-10-20.csv",
    "images": ROOT / "docs" / "rk-firmware-clr-metadata-image-summary-2026-10-20.csv",
}

# ECMA-335 table column schemas. This pass needs all standard tables through
# AssemblyRef so row offsets can be computed correctly. Unsupported tables
# before AssemblyRef cause a clear unresolved result instead of guessed offsets.
SCHEMAS: dict[int, list[tuple[str, str]]] = {
    0: [("Generation", "u2"), ("Name", "str"), ("Mvid", "guid"), ("EncId", "guid"), ("EncBaseId", "guid")],
    1: [("ResolutionScope", "coded:ResolutionScope"), ("TypeName", "str"), ("TypeNamespace", "str")],
    2: [("Flags", "u4"), ("TypeName", "str"), ("TypeNamespace", "str"), ("Extends", "coded:TypeDefOrRef"), ("FieldList", "table:4"), ("MethodList", "table:6")],
    3: [("Field", "table:4")],
    4: [("Flags", "u2"), ("Name", "str"), ("Signature", "blob")],
    5: [("Method", "table:6")],
    6: [("RVA", "u4"), ("ImplFlags", "u2"), ("Flags", "u2"), ("Name", "str"), ("Signature", "blob"), ("ParamList", "table:8")],
    7: [("Param", "table:8")],
    8: [("Flags", "u2"), ("Sequence", "u2"), ("Name", "str")],
    9: [("Class", "table:2"), ("Interface", "coded:TypeDefOrRef")],
    10: [("Class", "coded:MemberRefParent"), ("Name", "str"), ("Signature", "blob")],
    11: [("Type", "u2"), ("Parent", "coded:HasConstant"), ("Value", "blob")],
    12: [("Parent", "coded:HasCustomAttribute"), ("Type", "coded:CustomAttributeType"), ("Value", "blob")],
    13: [("Parent", "coded:HasFieldMarshal"), ("NativeType", "blob")],
    14: [("Action", "u2"), ("Parent", "coded:HasDeclSecurity"), ("PermissionSet", "blob")],
    15: [("PackingSize", "u2"), ("ClassSize", "u4"), ("Parent", "table:2")],
    16: [("Offset", "u4"), ("Field", "table:4")],
    17: [("Signature", "blob")],
    18: [("Parent", "table:2"), ("EventList", "table:20")],
    19: [("Event", "table:20")],
    20: [("EventFlags", "u2"), ("Name", "str"), ("EventType", "coded:TypeDefOrRef")],
    21: [("Parent", "table:2"), ("PropertyList", "table:23")],
    22: [("Property", "table:23")],
    23: [("Flags", "u2"), ("Name", "str"), ("Type", "blob")],
    24: [("Semantics", "u2"), ("Method", "table:6"), ("Association", "coded:HasSemantics")],
    25: [("Class", "table:2"), ("MethodBody", "coded:MethodDefOrRef"), ("MethodDeclaration", "coded:MethodDefOrRef")],
    26: [("Name", "str")],
    27: [("Signature", "blob")],
    28: [("MappingFlags", "u2"), ("MemberForwarded", "coded:MemberForwarded"), ("ImportName", "str"), ("ImportScope", "table:26")],
    29: [("RVA", "u4"), ("Field", "table:4")],
    30: [("Token", "u4"), ("FuncCode", "u4")],
    31: [("Token", "u4")],
    32: [("HashAlgId", "u4"), ("MajorVersion", "u2"), ("MinorVersion", "u2"), ("BuildNumber", "u2"), ("RevisionNumber", "u2"), ("Flags", "u4"), ("PublicKey", "blob"), ("Name", "str"), ("Culture", "str")],
    33: [("Processor", "u4")],
    34: [("OSPlatformId", "u4"), ("OSMajorVersion", "u4"), ("OSMinorVersion", "u4")],
    35: [("MajorVersion", "u2"), ("MinorVersion", "u2"), ("BuildNumber", "u2"), ("RevisionNumber", "u2"), ("Flags", "u4"), ("PublicKeyOrToken", "blob"), ("Name", "str"), ("Culture", "str"), ("HashValue", "blob")],
    36: [("Processor", "u4"), ("AssemblyRef", "table:35")],
    37: [("OSPlatformId", "u4"), ("OSMajorVersion", "u4"), ("OSMinorVersion", "u4"), ("AssemblyRef", "table:35")],
    38: [("Flags", "u4"), ("Name", "str"), ("HashValue", "blob")],
    39: [("Flags", "u4"), ("TypeDefId", "u4"), ("TypeName", "str"), ("TypeNamespace", "str"), ("Implementation", "coded:Implementation")],
    40: [("Offset", "u4"), ("Flags", "u4"), ("Name", "str"), ("Implementation", "coded:Implementation")],
    41: [("NestedClass", "table:2"), ("EnclosingClass", "table:2")],
    42: [("Number", "u2"), ("Flags", "u2"), ("Owner", "coded:TypeOrMethodDef"), ("Name", "str")],
    43: [("Method", "coded:MethodDefOrRef"), ("Instantiation", "blob")],
    44: [("Owner", "table:42"), ("Constraint", "coded:TypeDefOrRef")],
}

CODED: dict[str, tuple[int, list[int | None]]] = {
    "ResolutionScope": (2, [0, 26, 35, 1]),
    "TypeDefOrRef": (2, [2, 1, 27]),
    "HasConstant": (2, [4, 8, 23]),
    "HasCustomAttribute": (5, [6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43]),
    "CustomAttributeType": (3, [None, None, 6, 10, None]),
    "HasFieldMarshal": (1, [4, 8]),
    "HasDeclSecurity": (2, [2, 6, 32]),
    "MemberRefParent": (3, [2, 1, 26, 6, 27]),
    "HasSemantics": (1, [20, 23]),
    "MethodDefOrRef": (1, [6, 10]),
    "MemberForwarded": (1, [4, 6]),
    "Implementation": (2, [38, 35, 39]),
    "TypeOrMethodDef": (1, [2, 6]),
}

TARGET_PATTERNS = (
    ("HID-token", re.compile(r"(?<![a-z0-9])hid(?![a-z0-9])", re.I)),
    ("HID-api", re.compile(r"(?:hidd_|hidp_|hidclass|hidlibrary|hidsharp)", re.I)),
    ("USB", re.compile(r"usb", re.I)),
    ("serial", re.compile(r"serial", re.I)),
    ("communications-port", re.compile(r"commport|comport", re.I)),
    ("keyboard", re.compile(r"keyboard", re.I)),
    ("SetupAPI", re.compile(r"setupapi", re.I)),
    ("WinUSB", re.compile(r"winusb", re.I)),
    ("device", re.compile(r"device", re.I)),
    ("System.IO.Ports", re.compile(r"system\.io\.ports", re.I)),
)
MAX_RESOURCE_HASH_SIZE = 16 * 1024 * 1024


class ParseIssue(Exception):
    pass


def u(data: bytes, offset: int, size: int) -> int:
    if offset < 0 or offset + size > len(data):
        raise ParseIssue(f"read outside file at 0x{offset:X} for {size} bytes")
    return int.from_bytes(data[offset:offset + size], "little")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = list(dict.fromkeys(key for row in rows for key in row))
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def resolve_package(row: dict[str, str], artifacts: dict[str, dict[str, str]], research_root: Path) -> Path:
    item = artifacts.get(row["representative_sha256"])
    if not item:
        raise ParseIssue(f"missing artifact inventory hash {row['representative_sha256']}")
    rel = item.get("local_path", "")
    if rel.startswith(".research/"):
        candidate = research_root / rel[len(".research/"):]
        if candidate.is_file():
            return candidate
    name = item.get("filename", row.get("filename", ""))
    found = list(research_root.rglob(name))
    if found:
        return found[0]
    raise ParseIssue(f"no cached package file for {name}")


def parse_pe(data: bytes) -> dict[str, Any]:
    if data[:2] != b"MZ":
        raise ParseIssue("missing DOS MZ signature")
    peoff = u(data, 0x3C, 4)
    if data[peoff:peoff + 4] != b"PE\0\0":
        raise ParseIssue("missing PE signature")
    coff = peoff + 4
    machine, section_count = struct.unpack_from("<HH", data, coff)
    opt_size = u(data, coff + 16, 2)
    opt = coff + 20
    magic = u(data, opt, 2)
    if magic == 0x10B:
        dd_off = opt + 96
        num_dirs_off = opt + 92
    elif magic == 0x20B:
        dd_off = opt + 112
        num_dirs_off = opt + 108
    else:
        raise ParseIssue(f"unsupported optional-header magic 0x{magic:X}")
    image_base = u(data, opt + (28 if magic == 0x10B else 24), 4 if magic == 0x10B else 8)
    size_headers = u(data, opt + 60, 4)
    num_dirs = u(data, num_dirs_off, 4)
    if num_dirs <= 14:
        raise ParseIssue("PE has no CLI data-directory entry")
    cli_rva, cli_size = struct.unpack_from("<II", data, dd_off + 14 * 8)
    sec_off = opt + opt_size
    sections = []
    for index in range(section_count):
        off = sec_off + index * 40
        name = data[off:off + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from("<IIII", data, off + 8)
        sections.append({"name": name, "rva": virtual_address, "vsize": virtual_size, "raw_size": raw_size, "raw_offset": raw_offset})

    def rva_to_offset(rva: int, length: int = 1) -> int:
        if rva < size_headers and rva + length <= size_headers and rva + length <= len(data):
            return rva
        for section in sections:
            start = section["rva"]
            if start <= rva < start + max(section["vsize"], section["raw_size"]):
                delta = rva - start
                if delta + length > section["raw_size"]:
                    raise ParseIssue(f"RVA 0x{rva:X} is not fully file-backed")
                offset = section["raw_offset"] + delta
                if offset + length > len(data):
                    raise ParseIssue(f"mapped RVA 0x{rva:X} falls past end of file")
                return offset
        raise ParseIssue(f"RVA 0x{rva:X} is not mapped by a PE section")

    cli_off = rva_to_offset(cli_rva, min(cli_size, 72))
    if cli_size < 16:
        raise ParseIssue("CLI header is shorter than required metadata fields")
    cli_header_size = u(data, cli_off, 4)
    metadata_rva, metadata_size = struct.unpack_from("<II", data, cli_off + 8)
    resources_rva, resources_size = struct.unpack_from("<II", data, cli_off + 24)
    metadata_off = rva_to_offset(metadata_rva, metadata_size)
    return {
        "machine": machine, "image_base": image_base, "sections": sections,
        "cli_rva": cli_rva, "cli_file_offset": cli_off, "cli_header_size": cli_header_size,
        "metadata_rva": metadata_rva, "metadata_size": metadata_size,
        "resources_rva": resources_rva, "resources_size": resources_size,
        "metadata_file_offset": metadata_off, "rva_to_offset": rva_to_offset,
    }


def parse_metadata_root(data: bytes, pe: dict[str, Any]) -> dict[str, Any]:
    base = pe["metadata_file_offset"]
    limit = base + pe["metadata_size"]
    if data[base:base + 4] != b"BSJB":
        raise ParseIssue("CLI metadata root signature is not BSJB")
    major, minor = struct.unpack_from("<HH", data, base + 4)
    version_len = u(data, base + 12, 4)
    if version_len > 4096 or base + 16 + version_len + 4 > limit:
        raise ParseIssue("invalid metadata version-string length")
    version = data[base + 16:base + 16 + version_len].split(b"\0", 1)[0].decode("ascii", "replace")
    pos = base + 16 + ((version_len + 3) & ~3)
    flags, stream_count = struct.unpack_from("<HH", data, pos)
    pos += 4
    streams = {}
    stream_headers = []
    for _ in range(stream_count):
        if pos + 8 > limit:
            raise ParseIssue("metadata stream header exceeds metadata bounds")
        rel_off, size = struct.unpack_from("<II", data, pos)
        pos += 8
        end = data.find(b"\0", pos, min(pos + 64, limit))
        if end < 0:
            raise ParseIssue("unterminated metadata stream name")
        name = data[pos:end].decode("ascii", "replace")
        pos = (end + 4) & ~3
        if rel_off + size > pe["metadata_size"]:
            raise ParseIssue(f"stream {name} exceeds metadata root")
        streams[name] = {"relative_offset": rel_off, "size": size, "file_offset": base + rel_off}
        stream_headers.append(f"{name}@0x{rel_off:X}+0x{size:X}")
    table_name = "#~" if "#~" in streams else "#-" if "#-" in streams else None
    if table_name is None:
        raise ParseIssue("metadata has neither #~ nor #- tables stream")
    return {
        "major": major, "minor": minor, "flags": flags, "version": version,
        "streams": streams, "stream_description": " | ".join(stream_headers),
        "tables_stream_name": table_name,
        "custom_stream_names": sorted(set(streams) - {"#~", "#-", "#Strings", "#US", "#GUID", "#Blob"}),
    }


def compressed_uint(data: bytes, offset: int, end: int) -> tuple[int, int]:
    if offset >= end:
        raise ParseIssue("truncated compressed unsigned integer")
    first = data[offset]
    if first & 0x80 == 0:
        return first, offset + 1
    if first & 0xC0 == 0x80:
        if offset + 2 > end:
            raise ParseIssue("truncated two-byte compressed integer")
        return ((first & 0x3F) << 8) | data[offset + 1], offset + 2
    if first & 0xE0 == 0xC0:
        if offset + 4 > end:
            raise ParseIssue("truncated four-byte compressed integer")
        return ((first & 0x1F) << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3], offset + 4
    raise ParseIssue("invalid compressed unsigned integer prefix")


def metadata_tables(data: bytes, root: dict[str, Any]) -> dict[str, Any]:
    table_stream = root["streams"][root["tables_stream_name"]]
    start = table_stream["file_offset"]
    end = start + table_stream["size"]
    if start + 24 > end:
        raise ParseIssue("tables stream header is truncated")
    reserved, major, minor, heap_sizes, reserved2 = struct.unpack_from("<IBBBB", data, start)
    valid, sorted_mask = struct.unpack_from("<QQ", data, start + 8)
    pos = start + 24
    row_counts: dict[int, int] = {}
    for table_id in range(64):
        if valid & (1 << table_id):
            if pos + 4 > end:
                raise ParseIssue("row-count vector exceeds tables stream")
            row_counts[table_id] = u(data, pos, 4)
            pos += 4
    unsupported_before_assemblyref = [t for t in row_counts if t <= 35 and t not in SCHEMAS]
    if unsupported_before_assemblyref:
        raise ParseIssue("unsupported metadata table ids before AssemblyRef: " + ",".join(map(str, unsupported_before_assemblyref)))
    strings = root["streams"].get("#Strings")
    blobs = root["streams"].get("#Blob")
    if not strings or not blobs:
        raise ParseIssue("required #Strings or #Blob heap absent")

    def width(kind: str) -> int:
        if kind == "u1": return 1
        if kind == "u2": return 2
        if kind == "u4": return 4
        if kind == "str": return 4 if heap_sizes & 0x01 else 2
        if kind == "guid": return 4 if heap_sizes & 0x02 else 2
        if kind == "blob": return 4 if heap_sizes & 0x04 else 2
        if kind.startswith("table:"):
            target = int(kind.split(":")[1])
            return 4 if row_counts.get(target, 0) >= 0x10000 else 2
        if kind.startswith("coded:"):
            tag_bits, targets = CODED[kind.split(":", 1)[1]]
            max_rows = max((row_counts.get(t, 0) for t in targets if t is not None), default=0)
            return 2 if max_rows < (1 << (16 - tag_bits)) else 4
        raise ParseIssue(f"unknown column type {kind}")

    table_offsets: dict[int, int] = {}
    table_sizes: dict[int, int] = {}
    cursor = pos
    for table_id in sorted(row_counts):
        schema = SCHEMAS.get(table_id)
        if schema is None:
            if table_id <= 35:
                raise ParseIssue(f"no schema for table {table_id}")
            continue
        row_size = sum(width(kind) for _, kind in schema)
        table_offsets[table_id] = cursor
        table_sizes[table_id] = row_size
        total = row_size * row_counts[table_id]
        if cursor + total > end:
            raise ParseIssue(f"table {table_id} rows exceed tables stream")
        cursor += total

    def read_heap_string(index: int) -> tuple[str, int | None]:
        if index == 0:
            return "", None
        heap_start = strings["file_offset"]
        heap_end = heap_start + strings["size"]
        absolute = heap_start + index
        if absolute >= heap_end:
            raise ParseIssue(f"string heap index 0x{index:X} outside heap")
        terminator = data.find(b"\0", absolute, min(heap_end, absolute + 65536))
        if terminator < 0:
            raise ParseIssue(f"unterminated string at #Strings+0x{index:X}")
        return data[absolute:terminator].decode("utf-8", "replace"), absolute

    def read_heap_blob(index: int) -> dict[str, Any]:
        if index == 0:
            return {"offset": None, "size": 0, "sha256": "", "preview": "", "status": "null-index"}
        heap_start = blobs["file_offset"]
        heap_end = heap_start + blobs["size"]
        absolute = heap_start + index
        try:
            length, payload = compressed_uint(data, absolute, heap_end)
            if payload + length > heap_end:
                raise ParseIssue("blob payload exceeds #Blob heap")
            value = data[payload:payload + length]
            return {
                "offset": absolute, "payload_offset": payload, "size": length,
                "sha256": sha(value), "preview": value[:64].hex(),
                "truncated": len(value) > 64, "status": "ok",
            }
        except ParseIssue as exc:
            return {"offset": absolute, "payload_offset": None, "size": "", "sha256": "", "preview": "", "truncated": "", "status": str(exc)}

    raw_tables: dict[int, list[dict[str, Any]]] = {}
    anomalies: list[str] = []
    for table_id in row_counts:
        schema = SCHEMAS.get(table_id)
        if schema is None:
            continue
        rows = []
        row_size = table_sizes[table_id]
        row_start = table_offsets[table_id]
        for rid in range(1, row_counts[table_id] + 1):
            offset = row_start + (rid - 1) * row_size
            values: dict[str, Any] = {}
            col = offset
            for name, kind in schema:
                size = width(kind)
                values[name] = u(data, col, size)
                col += size
            values["_metadata_file_offset"] = offset
            values["_raw_row_hex"] = data[offset:offset + row_size].hex()
            values["_rid"] = rid
            values["_token"] = f"0x{table_id:02X}{rid:06X}"
            for name, kind in schema:
                val = values[name]
                if kind == "str":
                    decoded, heap_off = read_heap_string(val)
                    values[name + "Text"] = decoded
                    values[name + "HeapFileOffset"] = heap_off
                elif kind == "blob":
                    values[name + "Blob"] = read_heap_blob(val)
                elif kind.startswith("coded:"):
                    coded_name = kind.split(":", 1)[1]
                    bits, targets = CODED[coded_name]
                    tag = val & ((1 << bits) - 1)
                    target = targets[tag] if tag < len(targets) else None
                    target_rid = val >> bits
                    values[name + "Decoded"] = {
                        "table": target,
                        "rid": target_rid,
                        "token": f"0x{target:02X}{target_rid:06X}" if target is not None and target_rid else "",
                    }
                    if val and (target is None or target_rid < 1 or target_rid > row_counts.get(target, 0)):
                        anomalies.append(f"table {table_id} row {rid} {name}: invalid coded index 0x{val:X}")
                elif kind == "blob":
                    blob_status = values[name + "Blob"].get("status")
                    if blob_status not in {"ok", "null-index"}:
                        anomalies.append(f"table {table_id} row {rid} {name}: {blob_status}")
            rows.append(values)
        raw_tables[table_id] = rows

    return {
        "reserved": reserved, "major": major, "minor": minor,
        "heap_sizes": heap_sizes, "reserved2": reserved2,
        "valid_mask": f"0x{valid:016X}", "sorted_mask": f"0x{sorted_mask:016X}",
        "row_counts": row_counts, "tables": raw_tables,
        "table_stream_file_offset": start, "table_stream_size": table_stream["size"],
        "unsupported_table_ids": [t for t in row_counts if t not in SCHEMAS],
        "anomalies": anomalies,
    }


def table_token(table_id: int, rid: int) -> str:
    return f"0x{table_id:02X}{rid:06X}" if rid else ""


def coded_token(value: dict[str, Any]) -> str:
    return value.get("token", "") if value else ""


def parse_user_strings(data: bytes, stream: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    """Scan #US heap entries without interpreting or executing ldstr uses."""
    start = stream["file_offset"]
    end = start + stream["size"]
    offset = 1 if stream["size"] else 0
    found: list[dict[str, Any]] = []
    issues: list[str] = []
    scanned = 0
    while start + offset < end:
        entry_index = offset
        absolute = start + offset
        try:
            length, payload = compressed_uint(data, absolute, end)
            if length == 0:
                offset = payload - start
                continue
            next_absolute = payload + length
            if next_absolute <= absolute or next_absolute > end:
                raise ParseIssue("#US entry has invalid length/bounds")
            string_bytes = data[payload:next_absolute - 1]
            if len(string_bytes) % 2:
                raise ParseIssue("#US UTF-16 payload has odd byte count")
            text_value = string_bytes.decode("utf-16le", "replace")
            kind_byte = data[next_absolute - 1]
            if entry_index >= (1 << 24):
                raise ParseIssue("#US heap offset exceeds metadata token range")
            scanned += 1
            searchable = text_value
            matched = [label for label, pattern in TARGET_PATTERNS if pattern.search(searchable)]
            if matched:
                found.append({
                    "heap_index": entry_index,
                    "token": f"0x70{entry_index:06X}",
                    "entry_file_offset": absolute,
                    "payload_file_offset": payload,
                    "payload_bytes": string_bytes,
                    "text": text_value,
                    "kind_byte": kind_byte,
                    "match_patterns": " | ".join(matched),
                })
            offset = next_absolute - start
        except (ParseIssue, UnicodeError) as exc:
            issues.append(f"#US+0x{entry_index:X}: {exc}")
            break
    return found, issues


def method_body(data: bytes, rva: int, rva_to_offset: Any) -> dict[str, Any]:
    if rva == 0:
        return {"method_body_file_offset": "", "method_body_kind": "no-rva", "method_body_code_size": "", "method_body_status": "abstract-or-runtime-implemented-or-missing-body"}
    try:
        offset = rva_to_offset(rva, 1)
        first = data[offset]
        if first & 0x03 == 0x02:
            code_size = first >> 2
            header_size = 1
            kind = "tiny"
            flags = 0x02
            max_stack = 8
            local_sig_token = 0
            rva_to_offset(rva, header_size + code_size)
        elif first & 0x03 == 0x03:
            rva_to_offset(rva, 12)
            first_word, max_stack, code_size, local_sig_token = struct.unpack_from("<HHII", data, offset)
            header_words = first_word >> 12
            header_size = header_words * 4
            flags = first_word & 0x0FFF
            if header_words < 3 or header_size > 64 or code_size > 1_048_576:
                raise ParseIssue(f"invalid or excessive fat method header words={header_words} code_size={code_size}")
            rva_to_offset(rva, header_size + code_size)
            kind = "fat"
        else:
            raise ParseIssue(f"unknown method header low bits 0x{first & 3:X}")
        if code_size > 1_048_576:
            raise ParseIssue(f"method body exceeds static cap ({code_size} bytes)")
        # Map code start separately; code bytes are not disassembled or exported.
        code_file_offset = rva_to_offset(rva, header_size) + header_size
        return {
            "method_body_file_offset": f"0x{offset:X}",
            "method_il_file_offset": f"0x{code_file_offset:X}",
            "method_body_kind": kind,
            "method_body_code_size": code_size,
            "method_body_header_size": header_size,
            "method_body_flags": f"0x{flags:03X}",
            "method_body_max_stack": max_stack,
            "method_body_local_sig_token": f"0x{local_sig_token:08X}" if local_sig_token else "",
            "method_body_status": "header-validated; IL not disassembled",
        }
    except ParseIssue as exc:
        return {"method_body_file_offset": "", "method_body_kind": "unresolved", "method_body_code_size": "", "method_body_status": str(exc)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--research-root", type=Path, default=RESEARCH_ROOT)
    args = parser.parse_args()
    packages = csv_rows(INVENTORY)
    artifacts = {r["sha256"]: r for r in csv_rows(ARTIFACTS) if r.get("sha256")}
    all_rows: list[dict[str, Any]] = []
    target_rows: list[dict[str, Any]] = []
    image_rows: list[dict[str, Any]] = []
    unresolved = []

    target_tables = {1, 2, 4, 6, 10, 26, 28, 32, 35, 40}
    display_names = {1: "TypeRef", 2: "TypeDef", 4: "Field", 6: "MethodDef", 10: "MemberRef", 26: "ModuleRef", 28: "ImplMap", 32: "Assembly", 35: "AssemblyRef", 40: "ManifestResource"}
    for package in packages:
        path = resolve_package(package, artifacts, args.research_root)
        data = path.read_bytes()
        observed = sha(data)
        expected = package["representative_sha256"]
        if observed != expected:
            raise SystemExit(f"SHA-256 mismatch for {path}: expected {expected}, got {observed}")
        image: dict[str, Any] = {
            "filename": path.name, "models": package.get("models", ""),
            "package_sha256": expected, "parse_status": "ok",
        }
        try:
            pe = parse_pe(data)
            root = parse_metadata_root(data, pe)
            tables = metadata_tables(data, root)
            us_matches, us_issues = parse_user_strings(data, root["streams"]["#US"]) if "#US" in root["streams"] else ([], ["#US stream absent"])
            tabs = tables["tables"]
            typedefs = tabs.get(2, [])
            typeref = tabs.get(1, [])
            methods = tabs.get(6, [])
            fields = tabs.get(4, [])
            modrefs = tabs.get(26, [])

            typedef_name = {}
            for row in typedefs:
                ns = row.get("TypeNamespaceText", "")
                name = row.get("TypeNameText", "")
                typedef_name[row["_rid"]] = f"{ns}.{name}" if ns else name
            typeref_name = {}
            for row in typeref:
                ns = row.get("TypeNamespaceText", "")
                name = row.get("TypeNameText", "")
                typeref_name[row["_rid"]] = f"{ns}.{name}" if ns else name
            module_name = {row["_rid"]: row.get("NameText", "") for row in modrefs}

            # Determine MethodDef owner from TypeDef.MethodList list starts.
            method_owner: dict[int, str] = {}
            method_count = len(methods)
            for i, owner in enumerate(typedefs):
                start_rid = owner["MethodList"]
                next_rid = typedefs[i + 1]["MethodList"] if i + 1 < len(typedefs) else method_count + 1
                if start_rid < 1 or start_rid > method_count + 1 or next_rid < start_rid or next_rid > method_count + 1:
                    continue
                for rid in range(start_rid, next_rid):
                    method_owner[rid] = typedef_name.get(owner["_rid"], "")

            member_name: dict[tuple[int, int], str] = {}
            member_types: dict[tuple[int, int], str] = {}
            for row in methods:
                member_name[(6, row["_rid"])] = row.get("NameText", "")
                member_types[(6, row["_rid"])] = method_owner.get(row["_rid"], "")
            for row in fields:
                member_name[(4, row["_rid"])] = row.get("NameText", "")

            for table_id in sorted(target_tables):
                rows = tabs.get(table_id, [])
                if not rows:
                    continue
                for row in rows:
                    if table_id in {1, 2}:
                        name = row.get("TypeNameText", "")
                        namespace = row.get("TypeNamespaceText", "")
                    else:
                        name = row.get("NameText", row.get("ImportNameText", ""))
                        namespace = ""
                    full_name = f"{namespace}.{name}" if namespace else name
                    rva = row.get("RVA", 0) if table_id == 6 else 0
                    body = method_body(data, rva, pe["rva_to_offset"]) if table_id == 6 else {}
                    parent_token = ""
                    parent_name = ""
                    if table_id == 1:
                        decoded = row.get("ResolutionScopeDecoded", {})
                        parent_token = coded_token(decoded)
                    elif table_id == 2:
                        decoded = row.get("ExtendsDecoded", {})
                        parent_token = coded_token(decoded)
                        target_table, target_rid = decoded.get("table"), decoded.get("rid", 0)
                        if target_table == 1:
                            parent_name = typeref_name.get(target_rid, "")
                        elif target_table == 2:
                            parent_name = typedef_name.get(target_rid, "")
                    elif table_id == 10:
                        decoded = row.get("ClassDecoded", {})
                        parent_token = coded_token(decoded)
                        target_table, target_rid = decoded.get("table"), decoded.get("rid", 0)
                        if target_table == 1:
                            parent_name = typeref_name.get(target_rid, "")
                        elif target_table == 2:
                            parent_name = typedef_name.get(target_rid, "")
                        elif target_table == 26:
                            parent_name = module_name.get(target_rid, "")
                        elif target_table == 6:
                            parent_name = member_types.get((6, target_rid), "") + "." + member_name.get((6, target_rid), "")
                    elif table_id == 28:
                        decoded = row.get("MemberForwardedDecoded", {})
                        parent_token = coded_token(decoded)
                        target_table, target_rid = decoded.get("table"), decoded.get("rid", 0)
                        parent_name = member_name.get((target_table, target_rid), "")
                        if target_table == 6 and target_rid:
                            parent_name = (member_types.get((6, target_rid), "") + "." + parent_name).strip(".")
                    elif table_id == 40:
                        decoded = row.get("ImplementationDecoded", {})
                        parent_token = coded_token(decoded)
                        target_table, target_rid = decoded.get("table"), decoded.get("rid", 0)
                        if target_table == 35:
                            parent_name = next((item.get("NameText", "") for item in tabs.get(35, []) if item["_rid"] == target_rid), "")
                        elif target_table == 38:
                            parent_name = next((item.get("NameText", "") for item in tabs.get(38, []) if item["_rid"] == target_rid), "")
                    elif table_id == 6:
                        parent_name = method_owner.get(row["_rid"], "")
                    if table_id == 6:
                        full_name = f"{parent_name}.{name}" if parent_name else name
                    elif table_id == 10:
                        full_name = f"{parent_name}::{name}" if parent_name else name
                    elif table_id == 28:
                        module_index = row.get("ImportScope", 0)
                        parent_name = (parent_name + " in ") if parent_name else ""
                        parent_name += module_name.get(module_index, "")

                    resource_evidence = {}
                    if table_id == 40:
                        resource_rva = pe["resources_rva"] + row["Offset"] if pe["resources_rva"] else 0
                        if not parent_token and resource_rva:
                            try:
                                resource_offset = pe["rva_to_offset"](resource_rva, 4)
                                payload_len = u(data, resource_offset, 4)
                                if row["Offset"] + 4 + payload_len > pe["resources_size"]:
                                    raise ParseIssue("manifest resource length exceeds CLI resources directory")
                                if payload_len > MAX_RESOURCE_HASH_SIZE:
                                    raise ParseIssue(f"embedded resource {payload_len} bytes exceeds hash cap")
                                resource_hash = sha(data[resource_offset + 4:resource_offset + 4 + payload_len])
                                resource_evidence = {
                                    "resource_rva": f"0x{resource_rva:08X}",
                                    "resource_entry_file_offset": f"0x{resource_offset:X}",
                                    "resource_payload_file_offset": f"0x{resource_offset + 4:X}",
                                    "resource_payload_length": payload_len,
                                    "resource_payload_sha256": resource_hash,
                                    "resource_status": "embedded; length prefix validated; payload hashed in place; not extracted",
                                }
                            except ParseIssue as exc:
                                resource_evidence = {"resource_rva": f"0x{resource_rva:08X}", "resource_status": "unresolved: " + str(exc)}

                    blobs = []
                    for column, key in (("Signature", "SignatureBlob"), ("PublicKey", "PublicKeyBlob"), ("PublicKeyOrToken", "PublicKeyOrTokenBlob"), ("HashValue", "HashValueBlob")):
                        if key in row:
                            blobs.append((column, row[key]))
                    sig = next((v for k, v in blobs if k == "Signature"), {})
                    common = {
                        "filename": path.name, "models": package.get("models", ""),
                        "package_sha256": expected, "table_id": table_id,
                        "table": display_names.get(table_id, f"Table{table_id}"),
                        "rid": row["_rid"], "metadata_token": row["_token"],
                        "metadata_file_offset": f"0x{row['_metadata_file_offset']:X}",
                        "raw_row_hex": row["_raw_row_hex"],
                        "metadata_row_sha256": sha(bytes.fromhex(row["_raw_row_hex"])),
                        "name": name, "namespace": namespace, "full_name": full_name,
                        "parent_or_scope_token": parent_token, "parent_or_scope_name": parent_name,
                        "flags": f"0x{row['Flags']:08X}" if "Flags" in row else "",
                        "impl_flags": f"0x{row['ImplFlags']:04X}" if "ImplFlags" in row else "",
                        "rva": f"0x{rva:08X}" if rva else "",
                        "signature_blob_index": row.get("Signature", "") if "Signature" in row else "",
                        "signature_blob_file_offset": f"0x{sig['payload_offset']:X}" if sig.get("payload_offset") is not None else "",
                        "signature_blob_size": sig.get("size", ""),
                        "signature_blob_sha256": sig.get("sha256", ""),
                        "signature_blob_hex_preview": sig.get("preview", ""),
                        "signature_blob_truncated": sig.get("truncated", ""),
                        "mapping_flags": f"0x{row['MappingFlags']:04X}" if "MappingFlags" in row else "",
                        "import_name": row.get("ImportNameText", ""),
                        "import_name_heap_file_offset": f"0x{row['ImportNameHeapFileOffset']:X}" if row.get("ImportNameHeapFileOffset") else "",
                        "module_ref": module_name.get(row.get("ImportScope", 0), "") if table_id == 28 else "",
                        "method_body_file_offset": body.get("method_body_file_offset", ""),
                        "method_il_file_offset": body.get("method_il_file_offset", ""),
                        "method_body_kind": body.get("method_body_kind", ""),
                        "method_body_code_size": body.get("method_body_code_size", ""),
                        "method_body_status": body.get("method_body_status", ""),
                        "resource_offset": row.get("Offset", "") if table_id == 40 else "",
                        "resource_flags": f"0x{row['Flags']:08X}" if table_id == 40 else "",
                        "row_status": "unresolved-method-body" if body.get("method_body_kind") == "unresolved" else "parsed",
                        **resource_evidence,
                    }
                    for col, blob in blobs:
                        common[col.lower() + "_blob_file_offset"] = f"0x{blob['payload_offset']:X}" if blob.get("payload_offset") is not None else ""
                        common[col.lower() + "_blob_size"] = blob.get("size", "")
                        common[col.lower() + "_blob_sha256"] = blob.get("sha256", "")
                        common[col.lower() + "_blob_hex_preview"] = blob.get("preview", "")
                    all_rows.append(common)

                    searchable = " ".join([common["name"], common["namespace"], common["full_name"], common["parent_or_scope_name"], common["import_name"], common["module_ref"]])
                    matched = [label for label, pattern in TARGET_PATTERNS if pattern.search(searchable)]
                    if matched:
                        target_rows.append({
                            "filename": path.name, "models": package.get("models", ""), "package_sha256": expected,
                            "table": common["table"], "metadata_token": common["metadata_token"],
                            "metadata_file_offset": common["metadata_file_offset"], "name": common["name"],
                            "metadata_row_sha256": common["metadata_row_sha256"],
                            "full_name": common["full_name"], "parent_or_scope_token": parent_token,
                            "parent_or_scope_name": parent_name, "import_name": common["import_name"],
                            "module_ref": common["module_ref"], "rva": common["rva"],
                            "resource_rva": common.get("resource_rva", ""),
                            "resource_entry_file_offset": common.get("resource_entry_file_offset", ""),
                            "resource_payload_file_offset": common.get("resource_payload_file_offset", ""),
                            "resource_payload_length": common.get("resource_payload_length", ""),
                            "resource_payload_sha256": common.get("resource_payload_sha256", ""),
                            "resource_status": common.get("resource_status", ""),
                            "method_body_file_offset": common["method_body_file_offset"],
                            "match_patterns": " | ".join(matched),
                            "evidence_class": "metadata-name match; does not establish call reachability or runtime use",
                        })

            for item in us_matches:
                target_rows.append({
                    "filename": path.name, "models": package.get("models", ""), "package_sha256": expected,
                    "table": "UserString", "metadata_token": item["token"],
                    "metadata_file_offset": f"0x{item['entry_file_offset']:X}",
                    "user_string_payload_file_offset": f"0x{item['payload_file_offset']:X}",
                    "user_string_heap_index": f"0x{item['heap_index']:X}",
                    "name": item["text"], "full_name": item["text"],
                    "parent_or_scope_token": "", "parent_or_scope_name": "",
                    "import_name": "", "module_ref": "", "rva": "",
                    "method_body_file_offset": "", "raw_user_string_hex_preview": item["payload_bytes"][:96].hex(),
                    "user_string_utf16_sha256": sha(item["payload_bytes"]),
                    "user_string_kind_byte": f"0x{item['kind_byte']:02X}",
                    "match_patterns": item["match_patterns"],
                    "evidence_class": "#US heap entry; token proves string is present, not that code uses it",
                })

            # Summary includes table counts, metadata hashes, heap stats, and bounds.
            image.update({
                "metadata_version": root["version"], "metadata_file_offset": f"0x{pe['metadata_file_offset']:X}",
                "metadata_rva": f"0x{pe['metadata_rva']:08X}", "metadata_size": pe["metadata_size"],
                "cli_resources_rva": f"0x{pe['resources_rva']:08X}" if pe["resources_rva"] else "",
                "cli_resources_size": pe["resources_size"],
                "tables_stream": root["tables_stream_name"],
                "tables_stream_file_offset": f"0x{tables['table_stream_file_offset']:X}",
                "tables_stream_size": tables["table_stream_size"],
                "metadata_streams": root["stream_description"],
                "user_string_heap_size": (root["streams"]["#US"]["size"] if "#US" in root["streams"] else 0),
                "target_user_string_count": len(us_matches),
                "metadata_tables_valid_mask": tables["valid_mask"],
                "metadata_tables_sorted_mask": tables["sorted_mask"],
                "custom_metadata_stream_names": " | ".join(root["custom_stream_names"]),
                "table_row_counts_json": json.dumps({str(k): v for k, v in sorted(tables["row_counts"].items())}, sort_keys=True),
                "assemblyref_count": tables["row_counts"].get(35, 0),
                "typedef_count": tables["row_counts"].get(2, 0),
                "methoddef_count": tables["row_counts"].get(6, 0),
                "memberref_count": tables["row_counts"].get(10, 0),
                "implmap_count": tables["row_counts"].get(28, 0),
                "manifestresource_count": tables["row_counts"].get(40, 0),
                "target_name_match_count": sum(1 for row in target_rows if row["package_sha256"] == expected),
                "unsupported_metadata_table_ids": ",".join(map(str, tables["unsupported_table_ids"])),
                "parse_status": "ok",
            })
            unresolved_reasons = []
            if root["custom_stream_names"]:
                unresolved_reasons.append("custom metadata streams: " + ",".join(root["custom_stream_names"]))
            if tables["unsupported_table_ids"]:
                unresolved_reasons.append("unsupported metadata table ids: " + ",".join(map(str, tables["unsupported_table_ids"])))
            if tables["anomalies"]:
                unresolved_reasons.extend(tables["anomalies"])
            if us_issues:
                unresolved_reasons.extend(us_issues)
            body_issues = [row for row in all_rows if row["package_sha256"] == expected and row["table_id"] == 6 and row["method_body_kind"] == "unresolved"]
            if body_issues:
                unresolved_reasons.append(f"{len(body_issues)} method body header(s) unresolved")
            image["unresolved_reason_count"] = len(unresolved_reasons)
            image["unresolved_reasons"] = " | ".join(unresolved_reasons)
            if unresolved_reasons:
                image["parse_status"] = "parsed-with-unresolved-metadata-or-methods"
        except (ParseIssue, struct.error, IndexError, KeyError, ValueError) as exc:
            image["parse_status"] = "unresolved"
            image["parse_issue"] = str(exc)
            unresolved.append({"filename": path.name, "models": package.get("models", ""), "package_sha256": expected, "parse_issue": str(exc)})
        image_rows.append(image)

    for key, path in OUT.items():
        write_csv(path, {"rows": all_rows, "names": target_rows, "images": image_rows}[key])
    print(json.dumps({
        "images": len(image_rows), "parsed_images": sum(row["parse_status"] == "ok" for row in image_rows),
        "metadata_rows": len(all_rows), "target_name_rows": len(target_rows), "unresolved_images": unresolved,
        "outputs": {name: str(path) for name, path in OUT.items()},
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
