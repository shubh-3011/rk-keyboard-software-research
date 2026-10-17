#!/usr/bin/env python3
"""Compare RK UI and LED-label XML resources without modifying either tree."""

from __future__ import annotations

import argparse
import csv
import hashlib
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path


LOCALES = {"en", "sc", "tw", "Russian", "Turkish", "Japanese", "Korean"}
PROFILE_LOCALE_PATH = re.compile(
    r"^Dev/[0-9A-Fa-f]{4}/(en|sc|tw|Russian|Turkish|Japanese|Korean)/led\.xml$"
)
PROFILE_SIDE_LOCALE_PATH = re.compile(
    r"^Dev/[0-9A-Fa-f]{4}/SideLed/(en|sc|tw|Russian|Turkish|Japanese|Korean)/led\.xml$"
)
GENERIC_LOCALE_PATH = re.compile(
    r"^Dev/(en|sc|tw|Russian|Turkish|Japanese|Korean)/led\.xml$"
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def resource_class(path: str) -> str | None:
    if re.fullmatch(r"Text/(en|sc|tw|Russian|Turkish|Japanese|Korean)/text\.xml", path):
        return "ui_text"
    if GENERIC_LOCALE_PATH.fullmatch(path):
        return "generic_led_labels"
    if PROFILE_SIDE_LOCALE_PATH.fullmatch(path):
        return "profile_side_led_labels"
    if PROFILE_LOCALE_PATH.fullmatch(path):
        return "profile_led_labels"
    return None


def display_path(element: ET.Element) -> str:
    """Make a stable element path, adding sibling indices only for duplicates."""
    chain: list[str] = []
    current = element
    while current is not None:
        parent = parents.get(current)
        name = current.tag.rsplit("}", 1)[-1]
        if parent is not None:
            same = [child for child in list(parent) if child.tag == current.tag]
            if len(same) > 1:
                name += f"[{same.index(current) + 1}]"
        chain.append(name)
        current = parent
    return "/".join(reversed(chain))


def parse_xml(path: Path) -> tuple[dict[str, str], dict[str, str]]:
    raw = path.read_bytes()
    meta = {
        "sha256": sha256(raw),
        "bytes": str(len(raw)),
        "raw_status": "well-formed XML",
        "normalization_note": "",
        "raw_error": "",
    }
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as first_error:
        meta["raw_status"] = "malformed XML"
        meta["raw_error"] = str(first_error)
        # Both installed and extracted Japanese locale files contain this exact
        # missing '<' typo. Repair only an in-memory string for comparable keys;
        # never write the repaired bytes to disk.
        try:
            text = raw.decode("utf-16")
        except UnicodeError:
            text = raw.decode("utf-8-sig")
        broken = "/tc_screen1>"
        if text.count(broken) == 1:
            text = text.replace(broken, "</tc_screen1>", 1)
            try:
                root = ET.fromstring(text)
                meta["normalization_note"] = (
                    "In-memory-only exact repair: /tc_screen1> -> </tc_screen1>; "
                    "source bytes remain unchanged."
                )
            except ET.ParseError as repaired_error:
                meta["raw_error"] += f"; in-memory repair failed: {repaired_error}"
                return {}, meta
        else:
            return {}, meta

    # Build a parent map so duplicate sibling element names can be disambiguated.
    global parents
    parents = {child: parent for parent in root.iter() for child in list(parent)}
    values: dict[str, str] = {}
    for element in root.iter():
        if len(list(element)) == 0:
            key = display_path(element)
            values[key] = "".join(element.itertext()).strip()
    return values, meta


def discover(root: Path) -> dict[str, tuple[Path, str]]:
    found: dict[str, tuple[Path, str]] = {}
    for file in root.rglob("*.xml"):
        rel = file.relative_to(root).as_posix()
        kind = resource_class(rel)
        if kind:
            found[rel] = (file, kind)
    return found


def side_values(file_info: tuple[Path, str] | None) -> tuple[dict[str, str], dict[str, str]]:
    if file_info is None:
        return {}, {
            "sha256": "",
            "bytes": "",
            "raw_status": "file absent",
            "normalization_note": "",
            "raw_error": "",
        }
    return parse_xml(file_info[0])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installed-root", required=True, type=Path,
                        help="Installed 4.06 package root")
    parser.add_argument("--candidate-root", required=True, type=Path,
                        help="Extracted V4.6-labeled package app root")
    parser.add_argument("--output", required=True, type=Path,
                        help="Destination CSV")
    args = parser.parse_args()

    installed_root = args.installed_root.resolve()
    candidate_root = args.candidate_root.resolve()
    if not installed_root.is_dir() or not candidate_root.is_dir():
        parser.error("both package roots must be existing directories")

    old_files = discover(installed_root)
    new_files = discover(candidate_root)
    paths = sorted(set(old_files) | set(new_files), key=str.casefold)
    fields = [
        "resource_path", "resource_class", "locale", "profile_code", "key",
        "change", "installed_raw_status", "candidate_raw_status",
        "installed_value", "candidate_value", "installed_sha256",
        "candidate_sha256", "installed_bytes", "candidate_bytes",
        "installed_normalization_note", "candidate_normalization_note",
        "installed_raw_error", "candidate_raw_error",
    ]
    rows: list[dict[str, str]] = []

    for rel in paths:
        old_info = old_files.get(rel)
        new_info = new_files.get(rel)
        kind = (old_info or new_info)[1]
        old_values, old_meta = side_values(old_info)
        new_values, new_meta = side_values(new_info)
        keys = sorted(set(old_values) | set(new_values), key=str.casefold)
        if not keys:
            keys = ["__FILE__"]
        parts = rel.split("/")
        locale = parts[-2]
        profile_code = parts[1] if kind == "profile_led_labels" else ""
        for key in keys:
            old_value = old_values.get(key, "")
            new_value = new_values.get(key, "")
            if old_info is None:
                change = "added_file" if key == "__FILE__" else "added_file_key"
            elif new_info is None:
                change = "removed_file" if key == "__FILE__" else "removed_file_key"
            elif key == "__FILE__":
                change = "parse_unavailable"
            elif key not in old_values:
                change = "added_key"
            elif key not in new_values:
                change = "removed_key"
            elif old_value != new_value:
                change = "value_changed"
            else:
                change = "unchanged"
            rows.append({
                "resource_path": rel,
                "resource_class": kind,
                "locale": locale,
                "profile_code": profile_code,
                "key": key,
                "change": change,
                "installed_raw_status": old_meta["raw_status"],
                "candidate_raw_status": new_meta["raw_status"],
                "installed_value": old_value,
                "candidate_value": new_value,
                "installed_sha256": old_meta["sha256"],
                "candidate_sha256": new_meta["sha256"],
                "installed_bytes": old_meta["bytes"],
                "candidate_bytes": new_meta["bytes"],
                "installed_normalization_note": old_meta["normalization_note"],
                "candidate_normalization_note": new_meta["normalization_note"],
                "installed_raw_error": old_meta["raw_error"],
                "candidate_raw_error": new_meta["raw_error"],
            })

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    totals = Counter(row["change"] for row in rows)
    print(f"Compared {len(old_files)} installed and {len(new_files)} candidate XML resources.")
    print(f"Wrote {len(rows)} key/file rows to {args.output}")
    print("Change rows: " + ", ".join(f"{key}={value}" for key, value in sorted(totals.items())))
    return 0


if __name__ == "__main__":
    parents: dict[ET.Element, ET.Element] = {}
    sys.exit(main())
