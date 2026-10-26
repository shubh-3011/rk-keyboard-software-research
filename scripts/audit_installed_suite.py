#!/usr/bin/env python3
"""Revalidate the finite installed RK snapshot; never execute RK or access HID.

Requires pefile (requirements-audit.txt). REA resource Evidence must already
exist: use inspect-pe-resources once per installed PE, saving JSON locally.
Only hashes, structural metadata and existing static-reference addresses are
exported, not vendor payloads, translated strings, artwork or firmware.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path, PureWindowsPath
import re
from xml.etree import ElementTree as ET

import pefile


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def safe_relative(value: str) -> str:
    path = PureWindowsPath(value)
    if not value or path.drive or path.root or ".." in path.parts or ":" in value:
        raise ValueError(f"Unsafe relative path: {value!r}")
    return path.as_posix()


def indexed(rows: list[dict[str, str]], fields: tuple[str, ...]) -> dict:
    result = {}
    for row in rows:
        key = tuple(row[field].casefold() for field in fields)
        if key in result:
            raise ValueError(f"Duplicate ledger identity: {key}")
        result[key] = row
    return result


def group_for(relative: str) -> str:
    parts = relative.split("/")
    lower = [p.casefold() for p in parts]
    if len(parts) == 1:
        return "Root application, config, and installer files"
    if lower[0] == "font":
        return "Font files"
    if lower[0] == "skins":
        return "Skins and UI chrome"
    if lower[0] == "text" and lower[-1] == "text.xml":
        return "UI localization XML"
    if lower[0] == "et":
        return "Global ET effect-pattern data"
    if lower[0] == "cartoon":
        return "Global Cartoon effect-pattern data"
    if lower[0] == "dev":
        if lower[-1] == "kb.ini":
            return "Per-profile KB.ini configuration"
        if lower[-1] in {"keyimg.png", "kbled.png"}:
            return "Per-profile keyboard artwork"
        if lower[-1] == "screen.gif":
            return "Per-profile screen GIF samples"
        if lower[-1].endswith(".upf"):
            return "Per-profile firmware package"
        if lower[-1] == "update.exe":
            return "Per-profile updater executable"
        if lower[-1] == "led.xml":
            return ("Generic localized LED dictionaries" if len(parts) == 3
                    else "Profile-localized LED dictionaries")
        if "et" in lower[2:] or "cartoon" in lower[2:]:
            return "Per-profile ET/Cartoon pattern files"
    raise ValueError(f"Unclassified installed path (do not silently ignore): {relative}")


def xml_shape(data: bytes, relative: str) -> dict:
    text = data.decode("utf-16" if data.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig")
    status, defect = "well-formed", None
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        # Exactly the documented defect, never a generic XML repair.
        if relative != "Text/Japanese/text.xml" or text.count("/tc_screen1>") != 1 or "</tc_screen1>" in text:
            raise ValueError(f"Unrecognized XML defect in {relative}: {exc}") from exc
        root = ET.fromstring(text.replace("/tc_screen1>", "</tc_screen1>"))
        status, defect = "malformed; metrics use in-memory normalization", str(exc)
    keys = [element.tag for element in root.iter() if len(element) == 0]
    return {"raw_status": status, "raw_defect": defect, "leaf_count": len(keys),
            "unique_leaf_count": len(set(keys)),
            "key_set_sha256": sha("\n".join(sorted(set(keys))).encode("utf-8"))}


def imported_rows(data: bytes, relative: str) -> tuple[dict, list[dict]]:
    pe = pefile.PE(data=data)
    rows = []
    for kind, attr in (("ordinary", "DIRECTORY_ENTRY_IMPORT"), ("delay", "DIRECTORY_ENTRY_DELAY_IMPORT")):
        for descriptor in getattr(pe, attr, []):
            for item in descriptor.imports:
                rows.append({"binary": relative, "binary_sha256": sha(data), "kind": kind,
                             "dll": descriptor.dll.decode("ascii"),
                             "api": item.name.decode("ascii") if item.name else f"ordinal_{item.ordinal}",
                             "iat_rva": f"0x{item.address - pe.OPTIONAL_HEADER.ImageBase:08X}"})
    metadata = {"path": relative, "sha256": sha(data), "bytes": len(data),
                "machine": pe.FILE_HEADER.Machine,
                "image_base": f"0x{pe.OPTIONAL_HEADER.ImageBase:08X}",
                "entrypoint_rva": f"0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08X}",
                "imports": dict(Counter(row["kind"] for row in rows))}
    pe.close()
    return metadata, rows


def resource_summary(record: dict, data: bytes) -> dict:
    if record["operation"] != "inspect_pe_resources" or record["subject"]["digest"]["sha256"] != sha(data):
        raise ValueError("REA operation or subject digest mismatch")
    result = record["normalized_result"]
    if result["artifact"]["sha256"] != sha(data) or result["artifact"]["bytes"] != len(data):
        raise ValueError("REA artifact identity mismatch")
    if result["coverage"]["status"] != "complete":
        raise ValueError("REA resource inventory is incomplete")
    resources = result["resources"]
    if result["coverage"]["resources"] != len(resources):
        raise ValueError("REA resource count mismatch")
    for resource in resources:
        payload = resource["payload"]
        offset, size = payload["location"]["offset"], payload["location"]["bytes"]
        if offset < 0 or size < 0 or offset + size > len(data):
            raise ValueError("REA payload range is outside the binary")
        if sha(data[offset:offset + size]) != payload["sha256"]:
            raise ValueError("REA resource payload digest mismatch")
    return {"evidence_id": record["evidence_id"], "provider": record["provider"],
            "resource_count": len(resources), "coverage": result["coverage"],
            "limitations": record["limitations"],
            "type_counts": dict(sorted(Counter(str(r["type"].get("id", r["type"].get("name")))
                                               for r in resources).items()))}


def audit(root: Path, repo: Path, evidence_dir: Path) -> tuple[dict, list[dict], list[dict], dict[str, bytes]]:
    manifest = read_csv(repo / "docs/rk-installed-package-manifest.csv")
    expected = indexed(manifest, ("relative_path",))
    actual = {}
    contents = {}
    for path in root.rglob("*"):
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            if not path.resolve().is_relative_to(root.resolve()):
                raise ValueError(f"File resolves outside installation: {relative}")
            key = (relative.casefold(),)
            if key in actual:
                raise ValueError(f"Case-colliding installed path: {relative}")
            actual[key] = relative
            contents[relative] = path.read_bytes()
    if set(expected) != set(actual):
        raise ValueError(f"Manifest membership mismatch: missing={set(expected)-set(actual)}, extra={set(actual)-set(expected)}")
    groups = {}
    files = []
    for key, row in expected.items():
        relative = safe_relative(row["relative_path"])
        if actual[key] != relative:
            raise ValueError(f"Manifest path spelling mismatch: {relative}")
        data = contents[relative]
        if len(data) != int(row["size_bytes"]) or sha(data) != row["sha256"].lower():
            raise ValueError(f"Installed bytes differ from manifest: {relative}")
        group = group_for(relative)
        total = groups.setdefault(group, {"files": 0, "bytes": 0})
        total["files"] += 1
        total["bytes"] += len(data)
        files.append({"relative_path": relative, "size_bytes": len(data), "sha256": sha(data), "group": group})
    saved_groups = read_csv(repo / "docs/rk-resource-group-inventory.csv")
    if {r["resource_group"]: {"files": int(r["file_count"]), "bytes": int(r["bytes"])} for r in saved_groups} != groups:
        raise ValueError("Fresh group census differs from saved group ledger")

    locales = []
    for row in read_csv(repo / "docs/rk-localization-file-inventory.csv"):
        relative = safe_relative(row["resource_path"])
        data = contents[relative]
        shape = xml_shape(data, relative)
        if sha(data) != row["sha256"] or shape["leaf_count"] != int(row["in_memory_leaf_key_count"]):
            raise ValueError(f"Localization ledger mismatch: {relative}")
        locales.append({"path": relative, "family": row["family"], "locale": row["locale"],
                        "sha256": sha(data), **shape})
    if {r["path"] for r in locales} != {p for p in contents if p.lower().endswith(".xml")}:
        raise ValueError("Localization inventory does not cover all installed XML")

    cfg = contents["Cfg.ini"].decode("utf-16")
    named = re.findall(r"^\s*DevName\d+\s*=\s*([0-9A-Fa-f]{4})\s*,\s*(.+?)\s*$", cfg, re.MULTILINE)
    named_map = {code.upper(): name.strip() for code, name in named}
    if len(named_map) != len(named):
        raise ValueError("Duplicate named profile")
    catalog = json.loads((repo / "models.json").read_text(encoding="utf-8"))
    if named_map != {m["code"]: m["name"] for m in catalog["models"]}:
        raise ValueError("Catalog name/code identity differs from Cfg.ini")
    # Hexadecimal profile identity is case-insensitive; manifest spelling is not.
    profile_codes = {p.split("/")[1].upper() for p in contents if p.lower().endswith("/kb.ini")}
    if profile_codes != set(named_map) | {p["code"] for p in catalog["unregisteredProfiles"]}:
        raise ValueError("Catalog profile membership mismatch")
    family_rows = read_csv(repo / "docs/rk-profile-driver-family-map.csv")
    if len(family_rows) != len(named_map) or {r["profile_code"]: r["model_name"] for r in family_rows} != named_map:
        raise ValueError("Family ledger identity mismatch")

    xrefs = indexed(read_csv(repo / "docs/rk-native-api-xrefs.csv"), ("binary", "dll", "api", "iat_rva"))
    evidence = {}
    for path in sorted(evidence_dir.glob("*.json")):
        record = json.loads(path.read_text(encoding="utf-8-sig"))
        if record.get("operation") == "inspect_pe_resources":
            digest = record["subject"]["digest"]["sha256"]
            if digest in evidence:
                raise ValueError(f"Duplicate REA subject: {digest}")
            evidence[digest] = (path, record)
    binaries, imports, matched, retained = [], [], set(), {}
    for relative, data in sorted(contents.items()):
        if not data.startswith(b"MZ"):
            continue
        metadata, rows = imported_rows(data, relative)
        for row in rows:
            key = (Path(relative).name.casefold(), row["dll"].casefold(), row["api"].casefold(), row["iat_rva"].casefold())
            if key not in xrefs or key in matched:
                raise ValueError(f"Import missing or duplicated in saved xref ledger: {key}")
            matched.add(key)
            for field in ("direct_call_iat_sites", "iat_thunk_sites", "direct_calls_to_iat_thunk",
                          "tail_jumps_to_iat_thunk", "other_iat_reference_sites"):
                row[field] = xrefs[key][field]
            row["reference_basis"] = "existing static scan; not rescanned instructions or runtime"
        path, record = evidence[sha(data)]
        record_path = f"rea/{sha(data)}.json"
        retained[record_path] = path.read_bytes()
        metadata["rea_resources"] = {**resource_summary(record, data), "record_sha256": sha(retained[record_path]),
                                     "record_file": record_path}
        binaries.append(metadata)
        imports.extend(rows)
    if matched != set(xrefs):
        raise ValueError("Saved xref ledger contains imports absent from installed PEs")
    summary = {"schema_version": 1, "scope": "installed Cfg.ini Ver=0x406 byte snapshot, not every RK release",
               "safety": "offline only; no vendor execution, HID, serial, network capture, startup changes or firmware writes",
               "source_ledgers": {name: sha((repo / name).read_bytes()) for name in (
                   "docs/rk-installed-package-manifest.csv", "docs/rk-resource-group-inventory.csv",
                   "docs/rk-localization-file-inventory.csv", "docs/rk-native-api-xrefs.csv",
                   "docs/rk-profile-driver-family-map.csv", "models.json")},
               "files": len(files), "bytes": sum(f["size_bytes"] for f in files),
               "groups": dict(sorted(groups.items())), "localization": locales,
               "profiles": {"named": len(named_map), "kb_ini": len(profile_codes),
                            "unregistered": sorted(profile_codes - set(named_map)),
                            "static_families": dict(Counter(r["static_handler"] for r in family_rows)),
                            "hardware_compatibility": "not established"},
               "binaries": binaries, "import_rows": len(imports),
               "limitations": ["Resource completeness applies only to PE resource trees, not code or UI workflows.",
                               "Profile names/codes and membership are rechecked; full tuple semantics are not.",
                               "Import identities are freshly parsed; callsite lists reuse the hashed prior ledger.",
                               "Static references do not establish reachability, execution, device acceptance or parity."]}
    return summary, sorted(files, key=lambda r: r["relative_path"]), imports, retained


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rk-root", required=True, type=Path)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--rea-evidence", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path, help="output directory (use a fresh directory for each audit)")
    args = parser.parse_args()
    if not args.rk_root.is_dir() or not args.rea_evidence.is_dir():
        parser.error("Installation and REA Evidence directories must exist")
    summary, files, imports, retained = audit(args.rk_root, args.repo, args.rea_evidence)
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "rea").mkdir()
    for relative, data in retained.items():
        (args.output / relative).write_bytes(data)
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    for filename, rows in (("files.csv", files), ("imports.csv", imports)):
        with (args.output / filename).open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
    print(f"Verified {summary['files']} files, {len(summary['groups'])} groups, "
          f"{summary['profiles']['named']} named profiles, {len(summary['localization'])} XML files, "
          f"{len(summary['binaries'])} PE resource trees, {summary['import_rows']} import rows.")


if __name__ == "__main__":
    main()
