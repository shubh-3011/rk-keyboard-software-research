#!/usr/bin/env python3
"""Hash-pinned, read-only IL instruction and call-reference inventory.

Uses the existing stdlib PE/CLI metadata parser, reads method bodies as bytes,
and never loads a CLR assembly or extracts embedded resources. It linearly
decodes bounded IL bodies, resolves metadata-token operands where supported,
and deliberately makes no control-flow reachability claim.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import struct
import sys
from collections import Counter
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import audit_rk_clr_metadata_static as base  # noqa: E402

ROOT = HERE.parent
INVENTORY = ROOT / "docs" / "rk-firmware-clr-profile-inventory-2026-10-20.csv"
ARTIFACTS = ROOT / "docs" / "rk-firmware-artifact-inventory-2026-10-19.csv"
OUT = {
    "calls": ROOT / "docs" / "rk-firmware-clr-il-call-reference-ledger-2026-10-20.csv",
    "tokens": ROOT / "docs" / "rk-firmware-clr-il-token-reference-ledger-2026-10-20.csv",
    "methods": ROOT / "docs" / "rk-firmware-clr-il-method-summary-2026-10-20.csv",
    "images": ROOT / "docs" / "rk-firmware-clr-il-image-summary-2026-10-20.csv",
    "issues": ROOT / "docs" / "rk-firmware-clr-il-decode-issues-2026-10-20.csv",
}
EMPTY_COLUMNS = {
    "calls": ["filename", "models", "package_sha256", "method_token", "method_full_name", "method_metadata_file_offset", "method_rva", "method_body_file_offset", "method_il_file_offset", "method_body_kind", "method_body_code_size", "method_il_sha256", "opcode", "il_offset", "instruction_file_offset", "instruction_raw_hex", "operand_file_offset", "metadata_token", "resolved_target", "resolution_status", "signature_or_target_kind", "feature_tags", "evidence_scope"],
    "tokens": ["filename", "models", "package_sha256", "method_token", "method_full_name", "method_metadata_file_offset", "method_rva", "method_body_file_offset", "method_il_file_offset", "method_body_kind", "method_body_code_size", "method_il_sha256", "opcode", "operand_kind", "il_offset", "instruction_file_offset", "instruction_raw_hex", "operand_file_offset", "metadata_token", "resolved_name", "resolution_status", "literal_value", "literal_matches_manifest_resource", "feature_tags", "evidence_scope"],
    "methods": ["filename", "models", "package_sha256", "method_token", "method_full_name", "method_metadata_file_offset", "method_rva", "method_body_file_offset", "method_il_file_offset", "method_body_kind", "method_body_code_size", "method_il_sha256", "instruction_count", "call_reference_count", "token_reference_count", "decode_status", "feature_tags"],
    "images": ["filename", "models", "package_sha256", "parse_status", "metadata_version", "method_count", "methods_decoded", "methods_unresolved", "instruction_count", "call_reference_count", "token_reference_count", "calli_count", "unresolved_call_target_count", "feature_tag_counts_json", "method_body_status_counts_json"],
    "issues": ["filename", "models", "package_sha256", "method_token", "method_full_name", "method_metadata_file_offset", "method_rva", "method_body_file_offset", "method_il_file_offset", "method_body_kind", "method_body_code_size", "method_il_sha256", "il_offset", "issue_kind", "issue"],
}


class ILIssue(Exception):
    pass


OPS: dict[int, tuple[str, str]] = {}


def addop(code: int, name: str, operand: str = "none") -> None:
    OPS[code] = (name, operand)


def addrange(start: int, names: list[str], operand: str = "none") -> None:
    for index, name in enumerate(names):
        addop(start + index, name, operand)


addrange(0x00, ["nop", "break"])
addrange(0x02, ["ldarg.0", "ldarg.1", "ldarg.2", "ldarg.3", "ldloc.0", "ldloc.1", "ldloc.2", "ldloc.3", "stloc.0", "stloc.1", "stloc.2", "stloc.3"])
addrange(0x0E, ["ldarg.s", "ldarga.s", "starg.s", "ldloc.s", "ldloca.s", "stloc.s"], "shortvar")
addop(0x14, "ldnull")
addrange(0x15, ["ldc.i4.m1", "ldc.i4.0", "ldc.i4.1", "ldc.i4.2", "ldc.i4.3", "ldc.i4.4", "ldc.i4.5", "ldc.i4.6", "ldc.i4.7", "ldc.i4.8"])
addop(0x1F, "ldc.i4.s", "shorti")
addop(0x20, "ldc.i4", "i4")
addop(0x21, "ldc.i8", "i8")
addop(0x22, "ldc.r4", "r4")
addop(0x23, "ldc.r8", "r8")
addop(0x25, "dup")
addop(0x26, "pop")
addop(0x27, "jmp", "method")
addop(0x28, "call", "method")
addop(0x29, "calli", "sig")
addop(0x2A, "ret")
addrange(0x2B, ["br.s", "brfalse.s", "brtrue.s", "beq.s", "bge.s", "bgt.s", "ble.s", "blt.s", "bne.un.s", "bge.un.s", "bgt.un.s", "ble.un.s", "blt.un.s"], "br.s")
addrange(0x38, ["br", "brfalse", "brtrue", "beq", "bge", "bgt", "ble", "blt", "bne.un", "bge.un", "bgt.un", "ble.un", "blt.un"], "br")
addop(0x45, "switch", "switch")
addrange(0x46, ["ldind.i1", "ldind.u1", "ldind.i2", "ldind.u2", "ldind.i4", "ldind.u4", "ldind.i8", "ldind.i", "ldind.r4", "ldind.r8", "ldind.ref"])
addrange(0x51, ["stind.ref", "stind.i1", "stind.i2", "stind.i4", "stind.i8", "stind.r4", "stind.r8"])
addrange(0x58, ["add", "sub", "mul", "div", "div.un", "rem", "rem.un", "and", "or", "xor", "shl", "shr", "shr.un", "neg", "not"])
addrange(0x67, ["conv.i1", "conv.i2", "conv.i4", "conv.i8", "conv.r4", "conv.r8", "conv.u4", "conv.u8"])
addrange(0x6F, ["callvirt"], "method")
addrange(0x70, ["cpobj", "ldobj"], "type")
addop(0x72, "ldstr", "string")
addop(0x73, "newobj", "method")
addrange(0x74, ["castclass", "isinst"], "type")
addop(0x76, "conv.r.un")
addop(0x79, "unbox", "type")
addop(0x7A, "throw")
addrange(0x7B, ["ldfld", "ldflda", "stfld", "ldsfld", "ldsflda", "stsfld"], "field")
addop(0x81, "stobj", "type")
addrange(0x82, ["conv.ovf.i1.un", "conv.ovf.i2.un", "conv.ovf.i4.un", "conv.ovf.i8.un", "conv.ovf.u1.un", "conv.ovf.u2.un", "conv.ovf.u4.un", "conv.ovf.u8.un", "conv.ovf.i.un", "conv.ovf.u.un"])
addop(0x8C, "box", "type")
addop(0x8D, "newarr", "type")
addop(0x8E, "ldlen")
addop(0x8F, "ldelema", "type")
addrange(0x90, ["ldelem.i1", "ldelem.u1", "ldelem.i2", "ldelem.u2", "ldelem.i4", "ldelem.u4", "ldelem.i8", "ldelem.i", "ldelem.r4", "ldelem.r8", "ldelem.ref"])
addrange(0x9B, ["stelem.i", "stelem.i1", "stelem.i2", "stelem.i4", "stelem.i8", "stelem.r4", "stelem.r8", "stelem.ref"])
addrange(0xA3, ["ldelem", "stelem"], "type")
addop(0xA5, "unbox.any", "type")
addrange(0xB3, ["conv.ovf.i1", "conv.ovf.u1", "conv.ovf.i2", "conv.ovf.u2", "conv.ovf.i4", "conv.ovf.u4", "conv.ovf.i8", "conv.ovf.u8"])
addop(0xC2, "refanyval", "type")
addop(0xC3, "ckfinite")
addop(0xC6, "mkrefany", "type")
addop(0xD0, "ldtoken", "tok")
addrange(0xD1, ["conv.u2", "conv.u1", "conv.i", "conv.ovf.i", "conv.ovf.u", "add.ovf", "add.ovf.un", "mul.ovf", "mul.ovf.un", "sub.ovf", "sub.ovf.un"])
addop(0xDC, "endfinally")
addop(0xDD, "leave", "br")
addop(0xDE, "leave.s", "br.s")
addop(0xDF, "stind.i")
addop(0xE0, "conv.u")

FE_OPS = {
    0x00: ("arglist", "none"), 0x01: ("ceq", "none"), 0x02: ("cgt", "none"),
    0x03: ("cgt.un", "none"), 0x04: ("clt", "none"), 0x05: ("clt.un", "none"),
    0x06: ("ldftn", "method"), 0x07: ("ldvirtftn", "method"),
    0x09: ("ldarg", "var"), 0x0A: ("ldarga", "var"), 0x0B: ("starg", "var"),
    0x0C: ("ldloc", "var"), 0x0D: ("ldloca", "var"), 0x0E: ("stloc", "var"),
    0x0F: ("localloc", "none"), 0x11: ("endfilter", "none"),
    0x12: ("unaligned.", "shorti"), 0x13: ("volatile.", "none"),
    0x14: ("tail.", "none"), 0x15: ("initobj", "type"), 0x16: ("constrained.", "type"),
    0x17: ("cpblk", "none"), 0x18: ("initblk", "none"), 0x1A: ("rethrow", "none"),
    0x1C: ("sizeof", "type"), 0x1D: ("refanytype", "none"), 0x1E: ("readonly.", "none"),
}
for second, spec in FE_OPS.items():
    OPS[0xFE00 | second] = spec

TOKEN_OPS = {"method", "field", "type", "tok", "string", "sig"}
CALL_OPS = {"call", "callvirt", "newobj", "jmp", "ldftn", "ldvirtftn", "calli"}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def inthex(value: str) -> int:
    return int(value, 16) if value else 0


def token_for(table: int, rid: int) -> str:
    return f"0x{table:02X}{rid:06X}" if rid else ""


def build_user_strings(data: bytes, stream: dict[str, Any]) -> dict[int, dict[str, Any]]:
    start, end = stream["file_offset"], stream["file_offset"] + stream["size"]
    offset = 1 if stream["size"] else 0
    result = {}
    while start + offset < end:
        index = offset
        absolute = start + offset
        length, payload = base.compressed_uint(data, absolute, end)
        if length == 0:
            offset = payload - start
            continue
        stop = payload + length
        if stop > end or length < 1:
            raise ILIssue(f"invalid #US entry at heap offset 0x{index:X}")
        raw = data[payload:stop - 1]
        if len(raw) % 2:
            raise ILIssue(f"odd UTF-16 #US entry at heap offset 0x{index:X}")
        result[index] = {
            "text": raw.decode("utf-16le", "replace"), "file_offset": absolute,
            "payload_file_offset": payload, "raw": raw, "sha256": sha(raw),
            "kind_byte": data[stop - 1],
        }
        offset = stop - start
    return result


def build_resolvers(tables: dict[str, Any], strings: dict[int, dict[str, Any]]) -> dict[str, Any]:
    tabs = tables["tables"]
    type_names: dict[tuple[int, int], str] = {}
    for table_id in (1, 2):
        for row in tabs.get(table_id, []):
            ns, name = row.get("TypeNamespaceText", ""), row.get("TypeNameText", "")
            type_names[(table_id, row["_rid"])] = f"{ns}.{name}" if ns else name
    modules = {r["_rid"]: r.get("NameText", "") for r in tabs.get(26, [])}
    method_owner: dict[int, str] = {}
    methods = tabs.get(6, [])
    typedefs = tabs.get(2, [])
    for i, owner in enumerate(typedefs):
        first = owner.get("MethodList", 0)
        following = typedefs[i + 1].get("MethodList", len(methods) + 1) if i + 1 < len(typedefs) else len(methods) + 1
        if 1 <= first <= following <= len(methods) + 1:
            for rid in range(first, following):
                method_owner[rid] = type_names.get((2, owner["_rid"]), "")

    methods_by_rid = {r["_rid"]: r for r in methods}
    fields_by_rid = {r["_rid"]: r for r in tabs.get(4, [])}
    typerefs_by_rid = {r["_rid"]: r for r in tabs.get(1, [])}
    typedefs_by_rid = {r["_rid"]: r for r in typedefs}
    members_by_rid = {r["_rid"]: r for r in tabs.get(10, [])}
    methodspec_by_rid = {r["_rid"]: r for r in tabs.get(43, [])}

    def resolve(table: int, rid: int, seen: set[tuple[int, int]] | None = None) -> dict[str, str]:
        seen = set() if seen is None else seen
        key = (table, rid)
        if key in seen:
            return {"name": "", "status": "cyclic-resolution"}
        seen.add(key)
        if table == 0x70:
            item = strings.get(rid)
            return {"name": item["text"], "status": "resolved-#US"} if item else {"name": "", "status": "invalid-#US-token"}
        if table == 6:
            row = methods_by_rid.get(rid)
            if not row: return {"name": "", "status": "invalid-MethodDef-token"}
            owner = method_owner.get(rid, "")
            name = row.get("NameText", "")
            return {"name": f"{owner}::{name}" if owner else name, "status": "resolved-MethodDef"}
        if table == 10:
            row = members_by_rid.get(rid)
            if not row: return {"name": "", "status": "invalid-MemberRef-token"}
            parent = row.get("ClassDecoded", {})
            parent_table, parent_rid = parent.get("table"), parent.get("rid", 0)
            parent_name = ""
            if parent_table in (1, 2):
                parent_name = type_names.get((parent_table, parent_rid), "")
            elif parent_table == 6:
                parent_name = resolve(6, parent_rid, seen)["name"]
            elif parent_table == 26:
                parent_name = modules.get(parent_rid, "")
            elif parent_table == 27:
                parent_name = f"TypeSpec#{parent_rid}"
            name = row.get("NameText", "")
            return {"name": f"{parent_name}::{name}" if parent_name else name, "status": "resolved-MemberRef"}
        if table == 0x2B:
            row = methodspec_by_rid.get(rid)
            if not row: return {"name": "", "status": "invalid-MethodSpec-token"}
            base_ref = row.get("MethodDecoded", {})
            target_table, target_rid = base_ref.get("table"), base_ref.get("rid", 0)
            if target_table not in (6, 10):
                return {"name": f"MethodSpec#{rid}", "status": "unresolved-MethodSpec-base"}
            resolved = resolve(target_table, target_rid, seen)
            return {"name": resolved["name"] + " [MethodSpec]", "status": "resolved-MethodSpec->" + resolved["status"]}
        if table == 4:
            row = fields_by_rid.get(rid)
            return {"name": row.get("NameText", ""), "status": "resolved-Field"} if row else {"name": "", "status": "invalid-Field-token"}
        if table in (1, 2):
            name = type_names.get((table, rid))
            return {"name": name or "", "status": "resolved-TypeRef" if table == 1 and name else "resolved-TypeDef" if name else "invalid-Type-token"}
        if table == 17:
            return {"name": f"StandAloneSig#{rid}", "status": "resolved-StandAloneSig" if rid <= len(tabs.get(17, [])) else "invalid-StandAloneSig-token"}
        if table == 27:
            return {"name": f"TypeSpec#{rid}", "status": "resolved-TypeSpec" if rid <= len(tabs.get(27, [])) else "invalid-TypeSpec-token"}
        return {"name": f"token-table-0x{table:02X}#{rid}", "status": "unsupported-token-table"}

    return {
        "resolve": resolve, "methods": methods_by_rid, "method_owner": method_owner,
        "type_names": type_names, "tabs": tabs,
    }


def decode_method(data: bytes, code_offset: int, code_size: int) -> list[dict[str, Any]]:
    end = code_offset + code_size
    if code_offset < 0 or end > len(data):
        raise ILIssue("method IL range extends beyond file")
    pos = code_offset
    decoded: list[dict[str, Any]] = []
    while pos < end:
        insn_offset = pos
        first = data[pos]
        pos += 1
        if first == 0xFE:
            if pos >= end:
                raise ILIssue(f"truncated two-byte opcode at IL+0x{insn_offset - code_offset:X}")
            second = data[pos]
            pos += 1
            code = 0xFE00 | second
        else:
            code = first
        spec = OPS.get(code)
        if spec is None:
            raise ILIssue(f"unsupported or invalid opcode 0x{code:04X} at IL+0x{insn_offset - code_offset:X}")
        name, operand_kind = spec
        operand_file_offset = pos
        operand_value: Any = ""
        token = 0
        if operand_kind == "shorti":
            if pos + 1 > end: raise ILIssue("truncated short inline integer")
            operand_value = struct.unpack_from("<b", data, pos)[0]; pos += 1
        elif operand_kind == "i4":
            if pos + 4 > end: raise ILIssue("truncated inline integer")
            operand_value = struct.unpack_from("<i", data, pos)[0]; pos += 4
        elif operand_kind == "i8":
            if pos + 8 > end: raise ILIssue("truncated inline int64")
            operand_value = struct.unpack_from("<q", data, pos)[0]; pos += 8
        elif operand_kind == "r4":
            if pos + 4 > end: raise ILIssue("truncated inline float32")
            operand_value = struct.unpack_from("<f", data, pos)[0]; pos += 4
        elif operand_kind == "r8":
            if pos + 8 > end: raise ILIssue("truncated inline float64")
            operand_value = struct.unpack_from("<d", data, pos)[0]; pos += 8
        elif operand_kind == "shortvar":
            if pos + 1 > end: raise ILIssue("truncated short variable index")
            operand_value = data[pos]; pos += 1
        elif operand_kind == "var":
            if pos + 2 > end: raise ILIssue("truncated variable index")
            operand_value = struct.unpack_from("<H", data, pos)[0]; pos += 2
        elif operand_kind == "br.s":
            if pos + 1 > end: raise ILIssue("truncated short branch target")
            delta = struct.unpack_from("<b", data, pos)[0]; pos += 1
            operand_value = f"IL+0x{pos - code_offset + delta:X}"
        elif operand_kind == "br":
            if pos + 4 > end: raise ILIssue("truncated branch target")
            delta = struct.unpack_from("<i", data, pos)[0]; pos += 4
            operand_value = f"IL+0x{pos - code_offset + delta:X}"
        elif operand_kind == "switch":
            if pos + 4 > end: raise ILIssue("truncated switch count")
            count = struct.unpack_from("<I", data, pos)[0]; pos += 4
            if count > code_size // 4 or pos + count * 4 > end:
                raise ILIssue(f"invalid/excessive switch target count {count}")
            deltas = struct.unpack_from("<" + "i" * count, data, pos) if count else ()
            pos += count * 4
            base_offset = pos - code_offset
            operand_value = " | ".join(f"IL+0x{base_offset + delta:X}" for delta in deltas)
        elif operand_kind in TOKEN_OPS:
            if pos + 4 > end: raise ILIssue(f"truncated {operand_kind} metadata token")
            token = struct.unpack_from("<I", data, pos)[0]; pos += 4
            operand_value = f"0x{token:08X}"
        decoded.append({
            "opcode": name, "operand_kind": operand_kind, "operand": operand_value,
            "token": token, "instruction_file_offset": insn_offset,
            "instruction_raw_hex": data[insn_offset:pos].hex(),
            "operand_file_offset": operand_file_offset,
            "il_offset": insn_offset - code_offset, "instruction_size": pos - insn_offset,
        })
    starts = {ins["il_offset"] for ins in decoded}
    for ins in decoded:
        if ins["operand_kind"] in {"br.s", "br"}:
            targets = [ins["operand"]]
        elif ins["operand_kind"] == "switch":
            targets = ins["operand"].split(" | ") if ins["operand"] else []
        else:
            continue
        for target in targets:
            relative = int(target.removeprefix("IL+0x"), 16)
            if relative not in starts:
                raise ILIssue(f"invalid branch target {target} from IL+0x{ins['il_offset']:X}")
    return decoded


def feature_tags(name: str, literal: str = "") -> list[str]:
    text = (name + " " + literal).lower()
    tags = []
    if any(s in text for s in ("getmanifestresourcestream", "getmanifestresourcenames", "getmanifestresourceinfo", "resourcemanager", "resourcereader")):
        tags.append("embedded-resource-api")
    if any(s in text for s in ("file::writeall", "file::create", "filestream", "file::open", "directory::createdirectory", "path::combine", "gettempfilename", "gettemppath")):
        tags.append("file-io-or-extraction-candidate")
    if any(s in text for s in ("process::start", "processstartinfo")):
        tags.append("process-launch-candidate")
    if any(s in text for s in ("system.management", "managementobjectsearcher", "managementeventwatcher", "win32_pnpentity", "deviceid like 'usb%'")):
        tags.append("device-discovery-candidate")
    if any(s in text for s in ("loadlibrary", "getprocaddress", "nativeLibrary::load", "assembly::loadfrom", "assembly::loadfile", "assembly::load(")):
        tags.append("dynamic-native-or-managed-load-candidate")
    if any(s in text for s in ("libusb", "libhidapi", "hidapi", "winusb", ".dll")):
        tags.append("native-payload-name-or-api")
    if any(s in text for s in ("vendorid", "productid", "vid", "pid", "getdevicetype", "getdeviceid", "enumeratedevices", "usbdevicemonitor")):
        tags.append("model-or-device-selection-candidate")
    return tags


def write_csv(path: Path, rows: list[dict[str, Any]], kind: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    columns = list(dict.fromkeys(k for row in rows for k in row)) or EMPTY_COLUMNS[kind]
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--research-root", type=Path, default=base.RESEARCH_ROOT)
    args = parser.parse_args()
    artifact_rows = {r["sha256"]: r for r in base.csv_rows(ARTIFACTS) if r.get("sha256")}
    packages = base.csv_rows(INVENTORY)
    call_rows: list[dict[str, Any]] = []
    token_rows: list[dict[str, Any]] = []
    method_rows: list[dict[str, Any]] = []
    image_rows: list[dict[str, Any]] = []
    issue_rows: list[dict[str, Any]] = []

    for package in packages:
        path = base.resolve_package(package, artifact_rows, args.research_root)
        data = path.read_bytes()
        expected_sha = package["representative_sha256"]
        observed_sha = sha(data)
        if observed_sha != expected_sha:
            raise SystemExit(f"SHA-256 mismatch for {path}: expected {expected_sha}, observed {observed_sha}")
        image = {
            "filename": path.name, "models": package.get("models", ""),
            "package_sha256": expected_sha, "parse_status": "ok",
        }
        try:
            pe = base.parse_pe(data)
            root = base.parse_metadata_root(data, pe)
            tables = base.metadata_tables(data, root)
            resolvers = build_resolvers(tables, build_user_strings(data, root["streams"]["#US"]))
            tabs = resolvers["tabs"]
            manifest_names = {r.get("NameText", "") for r in tabs.get(40, [])}
            methods = tabs.get(6, [])
            instruction_total = 0
            calls_this_image = 0
            methods_decoded = 0
            methods_unresolved = 0
            feature_counts: Counter[str] = Counter()
            method_body_errors: Counter[str] = Counter()

            for method in methods:
                rid = method["_rid"]
                owner = resolvers["method_owner"].get(rid, "")
                name = method.get("NameText", "")
                method_full = f"{owner}::{name}" if owner else name
                method_token = token_for(6, rid)
                body = base.method_body(data, method.get("RVA", 0), pe["rva_to_offset"])
                base_row = {
                    "filename": path.name, "models": package.get("models", ""),
                    "package_sha256": expected_sha, "method_token": method_token,
                    "method_full_name": method_full,
                    "method_metadata_file_offset": f"0x{method['_metadata_file_offset']:X}",
                    "method_rva": f"0x{method['RVA']:08X}" if method.get("RVA") else "",
                    "method_body_file_offset": body.get("method_body_file_offset", ""),
                    "method_il_file_offset": body.get("method_il_file_offset", ""),
                    "method_body_kind": body.get("method_body_kind", ""),
                    "method_body_code_size": body.get("method_body_code_size", ""),
                    "method_il_sha256": sha(data[inthex(body.get("method_il_file_offset", "")):inthex(body.get("method_il_file_offset", "")) + int(body.get("method_body_code_size", 0))])
                    if body.get("method_il_file_offset") else "",
                }
                if body.get("method_body_kind") in ("no-rva", "unresolved"):
                    status = body.get("method_body_status", "missing-body")
                    methods_unresolved += body.get("method_body_kind") == "unresolved"
                    method_body_errors[status] += 1
                    method_rows.append({**base_row, "instruction_count": 0, "call_reference_count": 0, "token_reference_count": 0, "decode_status": status, "feature_tags": ""})
                    if body.get("method_body_kind") == "unresolved":
                        issue_rows.append({**base_row, "il_offset": "", "issue_kind": "method-body-header", "issue": status})
                    continue

                il_file_offset = inthex(body.get("method_il_file_offset", ""))
                il_size = int(body.get("method_body_code_size", 0))
                try:
                    instructions = decode_method(data, il_file_offset, il_size)
                except ILIssue as exc:
                    methods_unresolved += 1
                    message = str(exc)
                    method_body_errors["IL-decode-issue"] += 1
                    issue_rows.append({**base_row, "il_offset": message.split(" at IL+")[-1].split(":")[0] if "IL+" in message else "", "issue_kind": "IL-decode", "issue": message})
                    method_rows.append({**base_row, "instruction_count": 0, "call_reference_count": 0, "token_reference_count": 0, "decode_status": "unresolved: " + message, "feature_tags": ""})
                    continue
                instruction_total += len(instructions)
                methods_decoded += 1
                call_count = 0
                token_count = 0
                method_features: set[str] = set()
                for ins in instructions:
                    operand_kind = ins["operand_kind"]
                    token = ins["token"]
                    resolved = {"name": "", "status": "not-a-token"}
                    string_value = ""
                    if operand_kind in TOKEN_OPS:
                        token_count += 1
                        table, token_rid = (token >> 24) & 0xFF, token & 0x00FFFFFF
                        resolved = resolvers["resolve"](table, token_rid)
                        if operand_kind == "string" and resolved["status"] == "resolved-#US":
                            string_value = resolved["name"]
                        tags = feature_tags(resolved["name"], string_value)
                        literal_resource_match = string_value in manifest_names if string_value else False
                        if literal_resource_match:
                            tags.append("literal-matches-manifest-resource-name")
                        method_features.update(tags)
                        feature_counts.update(tags)
                        if ins["opcode"] in CALL_OPS:
                            call_count += 1
                            calls_this_image += 1
                            call_rows.append({
                                **base_row,
                                "opcode": ins["opcode"], "il_offset": f"0x{ins['il_offset']:X}",
                                "instruction_file_offset": f"0x{ins['instruction_file_offset']:X}",
                                "instruction_raw_hex": ins["instruction_raw_hex"],
                                "operand_file_offset": f"0x{ins['operand_file_offset']:X}",
                                "metadata_token": ins["operand"], "resolved_target": resolved["name"],
                                "resolution_status": resolved["status"],
                                "signature_or_target_kind": operand_kind,
                                "feature_tags": " | ".join(tags),
                                "evidence_scope": "linear IL token reference only; no reachability or runtime claim",
                            })
                        token_rows.append({
                            **base_row,
                            "opcode": ins["opcode"], "operand_kind": operand_kind,
                            "il_offset": f"0x{ins['il_offset']:X}",
                            "instruction_file_offset": f"0x{ins['instruction_file_offset']:X}",
                            "instruction_raw_hex": ins["instruction_raw_hex"],
                            "operand_file_offset": f"0x{ins['operand_file_offset']:X}",
                            "metadata_token": ins["operand"], "resolved_name": resolved["name"],
                            "resolution_status": resolved["status"], "literal_value": string_value,
                            "literal_matches_manifest_resource": literal_resource_match,
                            "feature_tags": " | ".join(tags),
                            "evidence_scope": "linear IL token reference only; no reachability or runtime claim",
                        })
                    elif ins["opcode"] in CALL_OPS:
                        call_count += 1
                        calls_this_image += 1
                        call_rows.append({
                            **base_row,
                            "opcode": ins["opcode"], "il_offset": f"0x{ins['il_offset']:X}",
                            "instruction_file_offset": f"0x{ins['instruction_file_offset']:X}",
                            "operand_file_offset": f"0x{ins['operand_file_offset']:X}",
                            "metadata_token": "", "resolved_target": "indirect call signature",
                            "resolution_status": "calli-signature-only",
                            "signature_or_target_kind": operand_kind,
                            "feature_tags": "", "evidence_scope": "linear IL token reference only; no reachability or runtime claim",
                        })
                method_rows.append({
                    **base_row, "instruction_count": len(instructions),
                    "call_reference_count": call_count, "token_reference_count": token_count,
                    "decode_status": "decoded-linearly; control flow not analyzed",
                    "feature_tags": " | ".join(sorted(method_features)),
                })

            image.update({
                "metadata_version": root["version"],
                "method_count": len(methods), "methods_decoded": methods_decoded,
                "methods_unresolved": methods_unresolved,
                "instruction_count": instruction_total,
                "call_reference_count": calls_this_image,
                "token_reference_count": sum(1 for r in token_rows if r["package_sha256"] == expected_sha),
                "calli_count": sum(1 for r in call_rows if r["package_sha256"] == expected_sha and r["opcode"] == "calli"),
                "unresolved_call_target_count": sum(1 for r in call_rows if r["package_sha256"] == expected_sha and not r["resolution_status"].startswith("resolved-")),
                "feature_tag_counts_json": json.dumps(dict(sorted(feature_counts.items())), sort_keys=True),
                "method_body_status_counts_json": json.dumps(dict(sorted(method_body_errors.items())), sort_keys=True),
                "parse_status": "ok" if methods_unresolved == 0 else "decoded-with-unresolved-methods",
            })
        except (base.ParseIssue, ILIssue, struct.error, IndexError, KeyError, ValueError) as exc:
            image["parse_status"] = "unresolved-image"
            image["parse_issue"] = str(exc)
        image_rows.append(image)

    for key, output in OUT.items():
        rows = {"calls": call_rows, "tokens": token_rows, "methods": method_rows, "images": image_rows, "issues": issue_rows}[key]
        write_csv(output, rows, key)
    print(json.dumps({
        "images": len(image_rows),
        "parsed_images": sum(r.get("parse_status") in ("ok", "decoded-with-unresolved-methods") for r in image_rows),
        "methods": len(method_rows), "decoded_methods": sum(r.get("decode_status", "").startswith("decoded-linearly") for r in method_rows),
        "call_references": len(call_rows), "token_references": len(token_rows),
        "decode_issues": len(issue_rows),
        "outputs": {k: str(v) for k, v in OUT.items()},
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
