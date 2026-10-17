#!/usr/bin/env python3
"""Audit installed RK KB.ini profiles without launching the vendor utility.

Reads Cfg.ini, Dev/*/KB.ini, models.json and the existing field inventory,
then writes exhaustive field, record-shape, key-label, and S98-variant CSVs.
It never opens a device or executes any RK binary.
"""

from __future__ import annotations

import argparse
import collections
import csv
import json
import re
from pathlib import Path
from typing import Any


def read_text(path: Path) -> str:
    raw = path.read_bytes()
    encoding = "utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8"
    return raw.decode(encoding, errors="replace")


def split_value(raw: str) -> tuple[str, str]:
    value, marker, comment = raw.partition(";")
    return value.strip(), comment.strip() if marker else ""


def parse_ini(path: Path) -> tuple[dict[str, list[dict[str, Any]]], dict[str, list[dict[str, Any]]]]:
    """Return ordered assignments and per-section comments preceding them."""
    sections: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    comments: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    section = ""
    pending: list[str] = []
    for number, line in enumerate(read_text(path).splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        match = re.fullmatch(r"\[([^]]+)\]", stripped)
        if match:
            section = match.group(1).strip().upper()
            pending = []
            continue
        if stripped.startswith(";"):
            pending.append(stripped[1:].strip())
            continue
        if stripped.startswith("#"):
            pending = []
            continue
        if "=" not in stripped:
            pending = []
            continue
        key, raw_value = stripped.split("=", 1)
        value, inline_comment = split_value(raw_value)
        key = key.strip()
        sections[section].append({
            "key": key,
            "value": value,
            "inline_comment": inline_comment,
            "line": number,
        })
        comments[section].append({
            "key": key,
            "comments_before": list(pending),
            "line": number,
        })
        pending = []
    return dict(sections), dict(comments)


def parse_number(token: str) -> int | str:
    token = token.strip()
    try:
        return int(token, 0)
    except ValueError:
        try:
            return int(token, 10)
        except ValueError:
            return token


def parse_tuple(raw: str) -> list[int | str]:
    return [parse_number(part) for part in raw.split(",")]


def json_compact(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def token_type(value: str) -> str:
    if re.fullmatch(r"[-+]?0[xX][0-9a-fA-F]+", value):
        return "hex-integer"
    if re.fullmatch(r"[-+]?\d+", value):
        return "decimal-integer"
    return "text"


def load_config(cfg_path: Path) -> tuple[dict[str, str], set[str], str]:
    text = read_text(cfg_path)
    names: dict[str, str] = {}
    for line in text.splitlines():
        match = re.match(r"\s*DevName\d+\s*=\s*([0-9A-Fa-f]{4})\s*,\s*(.+?)\s*$", line)
        if match:
            names[match.group(1).upper()] = match.group(2).strip()
    pid_match = re.search(r"(?im)^\s*PID\s*=\s*(.*?)\s*$", text)
    pids = set()
    if pid_match:
        pids = {part.strip().upper().removeprefix("0X").zfill(4)
                for part in pid_match.group(1).split(",") if part.strip()}
    vid_match = re.search(r"(?im)^\s*VID\s*=\s*(.*?)\s*$", text)
    default_vid = vid_match.group(1).strip() if vid_match else ""
    return names, pids, default_vid


def parse_model_map(path: Path) -> dict[str, dict[str, Any]]:
    with path.open(encoding="utf-8") as stream:
        data = json.load(stream)
    return {item["code"].upper(): item
            for item in [*data.get("models", []), *data.get("unregisteredProfiles", [])]}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rk-root", type=Path,
                        default=Path(r"C:\Program Files (x86)\RK Keyboard Software"))
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    rk_root = args.rk_root
    repo = args.repo

    names, pids, default_vid = load_config(rk_root / "Cfg.ini")
    paths = sorted((rk_root / "Dev").glob("*/KB.ini"), key=lambda path: path.parent.name.upper())
    profiles: dict[str, dict[str, Any]] = {}
    for path in paths:
        code = path.parent.name.upper()
        sections, preceding = parse_ini(path)
        profiles[code] = {
            "path": path,
            "sections": sections,
            "preceding": preceding,
            "name": names.get(code, "(unregistered; no DevName entry in Cfg.ini)"),
        }

    model_map = parse_model_map(repo / "models.json")
    handler_map: dict[str, dict[str, str]] = {}
    with (repo / "docs" / "rk-profile-driver-family-map.csv").open(encoding="utf-8", newline="") as stream:
        handler_map = {row["profile_code"].upper(): row for row in csv.DictReader(stream)}
    binary_coverage: dict[str, str] = {}
    inventory_path = repo / "docs" / "rk-profile-option-field-inventory.csv"
    if inventory_path.exists():
        with inventory_path.open(encoding="utf-8", newline="") as stream:
            binary_coverage = {row["option"].casefold(): row["individual_static_key_literal_in_DeviceDriver"]
                               for row in csv.DictReader(stream)}

    # Exhaustive [OPT] field inventory: exact post-comment values, every
    # profile containing or omitting each key, raw type shapes, and comments.
    field_values: dict[str, collections.Counter[str]] = collections.defaultdict(collections.Counter)
    field_comments: dict[str, collections.Counter[str]] = collections.defaultdict(collections.Counter)
    field_profiles: dict[str, set[str]] = collections.defaultdict(set)
    field_types: dict[str, collections.Counter[str]] = collections.defaultdict(collections.Counter)
    field_widths: dict[str, collections.Counter[int]] = collections.defaultdict(collections.Counter)
    field_duplicates: collections.Counter[str] = collections.Counter()
    for code, profile in profiles.items():
        seen: set[str] = set()
        for item in profile["sections"].get("OPT", []):
            key, value = item["key"], item["value"]
            if key.casefold() in seen:
                field_duplicates[key] += 1
            seen.add(key.casefold())
            field_profiles[key.casefold()].add(code)
            field_values[key.casefold()][value] += 1
            kind = "comma-list" if "," in value else token_type(value)
            field_types[key.casefold()][kind] += 1
            if "," in value:
                tokens = [part.strip() for part in value.split(",")]
                field_widths[key.casefold()][len(tokens)] += 1
                for token in tokens:
                    field_types[key.casefold()][f"list-token:{token_type(token)}"] += 1
            if item["inline_comment"]:
                field_comments[key.casefold()][item["inline_comment"]] += 1

    codes = set(profiles)
    fields: list[dict[str, Any]] = []
    for folded in sorted(field_values):
        display_name = next(item["key"] for p in profiles.values()
                            for item in p["sections"].get("OPT", [])
                            if item["key"].casefold() == folded)
        present = field_profiles[folded]
        vocab = field_values[folded]
        fields.append({
            "section": "OPT",
            "field": display_name,
            "profiles_present": len(present),
            "present_profile_codes_json": json_compact(sorted(present)),
            "profiles_omitted": len(codes - present),
            "omitted_profile_codes_json": json_compact(sorted(codes - present)),
            "duplicate_assignments": field_duplicates[display_name],
            "raw_type_counts_json": json_compact(dict(sorted(field_types[folded].items()))),
            "comma_list_width_counts_json": json_compact(dict(sorted(field_widths[folded].items()))),
            "raw_value_vocabulary_and_counts_json": json_compact(dict(sorted(vocab.items()))),
            "inline_comment_vocabulary_and_counts_json": json_compact(dict(sorted(field_comments[folded].items()))),
            "individual_static_key_literal_in_DeviceDriver": binary_coverage.get(folded, "not indexed"),
        })
    write_csv(repo / "docs" / "rk-profile-schema-fields.csv", [
        "section", "field", "profiles_present", "present_profile_codes_json",
        "profiles_omitted", "omitted_profile_codes_json", "duplicate_assignments",
        "raw_type_counts_json", "comma_list_width_counts_json",
        "raw_value_vocabulary_and_counts_json", "inline_comment_vocabulary_and_counts_json",
        "individual_static_key_literal_in_DeviceDriver",
    ], fields)

    # Every source key label and its tuple, including zero-sized keys omitted
    # from the drawable layout projection in models.json.
    labels: list[dict[str, Any]] = []
    for code, profile in profiles.items():
        labels_by_key = {entry["key"].upper(): entry["comments_before"]
                         for entry in profile["preceding"].get("KEY", [])}
        for item in profile["sections"].get("KEY", []):
            if not re.fullmatch(r"K\d+", item["key"], re.IGNORECASE):
                continue
            labels.append({
                "profile_code": code,
                "record_key": item["key"].upper(),
                "source_comment_lines_json": json_compact(labels_by_key.get(item["key"].upper(), [])),
                "inline_comment": item["inline_comment"],
                "source_line": item["line"],
            })
    write_csv(repo / "docs" / "rk-profile-key-records.csv", [
        "profile_code", "record_key", "source_comment_lines_json", "inline_comment", "source_line",
    ], labels)

    # Per-profile coverage and tuple arity for [KEY], [FN1], and [FN2].
    shapes: list[dict[str, Any]] = []
    for code, profile in profiles.items():
        for section in ("KEY", "FN1", "FN2"):
            items = profile["sections"].get(section, [])
            ids: list[int] = []
            widths: collections.Counter[int] = collections.Counter()
            token_types: collections.Counter[str] = collections.Counter()
            duplicates = collections.Counter()
            for item in items:
                key_match = re.fullmatch(r"K(\d+)", item["key"], re.IGNORECASE)
                if not key_match:
                    continue
                ids.append(int(key_match.group(1)))
                cells = [part.strip() for part in item["value"].split(",")]
                widths[len(cells)] += 1
                for cell in cells:
                    token_types[token_type(cell)] += 1
                duplicates[item["key"].upper()] += 1
            unique_ids = sorted(set(ids))
            min_id, max_id = (unique_ids[0], unique_ids[-1]) if unique_ids else ("", "")
            missing_inside = ([number for number in range(min_id, max_id + 1)
                               if number not in set(unique_ids)] if unique_ids else [])
            shapes.append({
                "profile_code": code,
                "profile_name": profile["name"],
                "registered_in_Cfg_ini": str(code in names).lower(),
                "section": section,
                "section_present": str(bool(items)).lower(),
                "assignment_count": len(items),
                "record_key_min": min_id,
                "record_key_max": max_id,
                "record_keys_contiguous_between_min_max": str(not missing_inside).lower(),
                "missing_record_keys_inside_range_json": json_compact(missing_inside),
                "tuple_width_counts_json": json_compact(dict(sorted(widths.items()))),
                "cell_lexical_type_counts_json": json_compact(dict(sorted(token_types.items()))),
                "duplicate_record_keys_json": json_compact({key: count for key, count in duplicates.items() if count > 1}),
            })
    write_csv(repo / "docs" / "rk-profile-section-shapes.csv", [
        "profile_code", "profile_name", "registered_in_Cfg_ini", "section", "section_present",
        "assignment_count", "record_key_min", "record_key_max",
        "record_keys_contiguous_between_min_max", "missing_record_keys_inside_range_json",
        "tuple_width_counts_json", "cell_lexical_type_counts_json", "duplicate_record_keys_json",
    ], shapes)

    # Cross-check the decoded data shipped in models.json against every
    # source assignment, with lexical values kept separate from inferred types.
    option_mismatches: list[str] = []
    mapping_mismatches: list[str] = []
    tuple_counts: collections.Counter[str] = collections.Counter()
    for code, profile in profiles.items():
        model = model_map.get(code, {})
        data = model.get("profileData", {})
        options = {item["key"]: item["value"] for item in profile["sections"].get("OPT", [])}
        if data.get("options", {}) != options:
            option_mismatches.append(code)
        expected_base = {item["key"].upper(): parse_tuple(item["value"])
                         for item in profile["sections"].get("KEY", [])}
        if data.get("baseMappings", {}) != expected_base:
            mapping_mismatches.append(f"{code}:KEY")
        expected_fn = {
            section: {item["key"].upper(): parse_tuple(item["value"])
                      for item in profile["sections"].get(section, [])}
            for section in ("FN1", "FN2") if profile["sections"].get(section)
        }
        if data.get("fnMappings", {}) != expected_fn:
            mapping_mismatches.append(f"{code}:FN")
        for key, value in options.items():
            if re.fullmatch(r"LedOpt\d+", key, re.IGNORECASE):
                values = parse_tuple(value)
                tuple_counts[f"LedOpt arity {len(values)}"] += 1
        tuple_counts["KEY rows"] += len(expected_base)
        tuple_counts["FN1 rows"] += len(expected_fn.get("FN1", {}))
        tuple_counts["FN2 rows"] += len(expected_fn.get("FN2", {}))

    # Focused S98 comparison against the 022F profile, retaining exact raw
    # strings and reporting all option differences rather than normalizing.
    s98_codes = [code for code, name in names.items() if "S98" in name.upper()]
    baseline = {item["key"]: item["value"]
                for item in profiles.get("022F", {}).get("sections", {}).get("OPT", [])}
    s98_rows: list[dict[str, Any]] = []
    for code in sorted(s98_codes):
        profile = profiles[code]
        options = {item["key"]: item["value"] for item in profile["sections"].get("OPT", [])}
        model = model_map.get(code, {})
        diffs = {
            key: {"022F": baseline.get(key), code: options.get(key)}
            for key in sorted(set(baseline) | set(options))
            if baseline.get(key) != options.get(key)
        }
        fn1 = len(profile["sections"].get("FN1", []))
        fn2 = len(profile["sections"].get("FN2", []))
        led_slots = sorted(int(match.group(1)) for key in options
                           if (match := re.fullmatch(r"LedOpt(\d+)", key, re.IGNORECASE)))
        row = handler_map.get(code, {})
        s98_rows.append({
            "profile_code": code,
            "profile_name": names[code],
            "Psd_raw_KB_ini": options.get("Psd", ""),
            "Fw_raw_KB_ini": options.get("Fw", "(omitted)"),
            "RGBKb_raw": options.get("RGBKb", ""),
            "LayoutKeyNum_raw": options.get("LayoutKeyNum", "(omitted)"),
            "KEY_assignment_rows": len(profile["sections"].get("KEY", [])),
            "drawable_key_rectangles_in_models_json": model.get("drawableKeyCount", ""),
            "LayerNum_raw": options.get("LayerNum", "(omitted)"),
            "FN1_rows": fn1,
            "FN2_rows": fn2,
            "ShowScreen_raw": options.get("ShowScreen", ""),
            "RGBScreen_raw": options.get("RGBScreen", ""),
            "screen_dimensions_raw": options.get("siScreen", ""),
            "MaxScreenFrame_raw": options.get("MaxScreenFrame", ""),
            "LedOpt_slots_json": json_compact(led_slots),
            "static_handler_from_map": row.get("static_handler", "unmapped"),
            "handler_mapping_confidence": "high for initial Fw-based direct-profile family selection; wireless follow-on remains conditional/unresolved" if row else "unmapped",
            "raw_option_differences_vs_022F_json": json_compact(diffs),
        })
    write_csv(repo / "docs" / "rk-s98-profile-variants.csv", [
        "profile_code", "profile_name", "Psd_raw_KB_ini", "Fw_raw_KB_ini", "RGBKb_raw",
        "LayoutKeyNum_raw", "KEY_assignment_rows", "drawable_key_rectangles_in_models_json",
        "LayerNum_raw", "FN1_rows", "FN2_rows", "ShowScreen_raw", "RGBScreen_raw",
        "screen_dimensions_raw", "MaxScreenFrame_raw", "LedOpt_slots_json",
        "static_handler_from_map", "handler_mapping_confidence", "raw_option_differences_vs_022F_json",
    ], s98_rows)

    print(f"Installed KB.ini files: {len(profiles)}; Cfg.ini DevName rows: {len(names)}; PID list entries: {len(pids)}")
    print(f"Folders without DevName: {json_compact(sorted(set(profiles) - set(names)))}")
    print(f"DevName rows without KB.ini: {json_compact(sorted(set(names) - set(profiles)))}")
    print(f"Cfg default VID: {default_vid}; profile OPT VID fields: {sum('VID' in {i['key'] for i in p['sections'].get('OPT', [])} for p in profiles.values())}; DevTy fields: {sum('DevTy' in {i['key'] for i in p['sections'].get('OPT', [])} for p in profiles.values())}")
    print(f"Unique OPT fields: {len(field_values)}; OPT assignments: {sum(sum(c.values()) for c in field_values.values())}; duplicate field assignments: {sum(field_duplicates.values())}")
    print(f"models.json exact option mismatches: {len(option_mismatches)}; mapping mismatches: {len(mapping_mismatches)}")
    print(f"Mapping row counts: {json_compact(dict(tuple_counts))}")
    print(f"Generated rows: fields={len(fields)}, key records={len(labels)}, section profiles={len(shapes)}, S98 variants={len(s98_rows)}")
    print(f"Outputs: docs/rk-profile-schema-fields.csv, docs/rk-profile-key-records.csv, docs/rk-profile-section-shapes.csv, docs/rk-s98-profile-variants.csv")


if __name__ == "__main__":
    main()
