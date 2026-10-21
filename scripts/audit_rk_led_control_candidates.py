#!/usr/bin/env python3
"""Map installed RK 4.06 profile options to localized LED UI label candidates.

This is an offline configuration/resource analysis. It does not launch RK
software, inspect a running process, or access a keyboard.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


EXPECTED_DRIVER_SHA256 = "c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6"


def read_text(path: Path) -> str:
    raw = path.read_bytes()
    encoding = "utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
    return raw.decode(encoding, errors="replace")


def parse_ini(path: Path) -> dict[str, dict[str, str]]:
    sections: dict[str, dict[str, str]] = {}
    section = ""
    for raw_line in read_text(path).splitlines():
        line = raw_line.strip()
        if not line or line.startswith((";", "#")):
            continue
        match = re.fullmatch(r"\[([^]]+)\]", line)
        if match:
            section = match.group(1).strip().casefold()
            sections.setdefault(section, {})
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip().casefold()
        value = value.partition(";")[0].strip()
        sections.setdefault(section, {})[key] = value
    return sections


def parse_integer(value: str, *, default: int) -> int:
    value = value.strip()
    if not value:
        return default
    try:
        return int(value, 0)
    except ValueError:
        try:
            return int(value, 10)
        except ValueError:
            return default


def get_driver_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_names(cfg_path: Path) -> dict[str, str]:
    names: dict[str, str] = {}
    for line in read_text(cfg_path).splitlines():
        match = re.match(r"\s*DevName\d+\s*=\s*([0-9A-Fa-f]{4})\s*,\s*(.+?)\s*$", line)
        if match:
            names[match.group(1).upper()] = match.group(2).strip()
    return names


def load_label_dictionary(path: Path) -> dict[str, str]:
    tree = ET.parse(path)
    labels: dict[str, str] = {}
    config = tree.find("./config")
    if config is None:
        return labels
    for child in config:
        if child.tag and child.text is not None:
            labels[child.tag] = child.text.strip()
    return labels


def main() -> int:
    repo = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--rk-root",
        type=Path,
        default=Path(r"C:\Program Files (x86)\RK Keyboard Software"),
        help="installed RK software root containing Cfg.ini, DeviceDriver.exe, and Dev/",
    )
    parser.add_argument("--locale", default="en", help="LED label locale directory, such as en or sc")
    parser.add_argument(
        "--out",
        type=Path,
        default=repo / "docs" / "rk-led-control-candidates-4.06-en.csv",
        help="output CSV path (default: docs/rk-led-control-candidates-4.06-en.csv)",
    )
    parser.add_argument(
        "--expected-driver-sha256",
        default=EXPECTED_DRIVER_SHA256,
        help="expected DeviceDriver.exe SHA-256; defaults to the hash-pinned installed 4.06 image",
    )
    args = parser.parse_args()

    root = args.rk_root.resolve()
    driver = root / "DeviceDriver.exe"
    cfg = root / "Cfg.ini"
    dev_root = root / "Dev"
    if not driver.is_file() or not cfg.is_file() or not dev_root.is_dir():
        parser.error(f"expected an RK installation with DeviceDriver.exe, Cfg.ini, and Dev/: {root}")

    driver_sha256 = get_driver_sha256(driver)
    expected_sha256 = args.expected_driver_sha256.casefold()
    if driver_sha256.casefold() != expected_sha256:
        parser.error(
            f"DeviceDriver.exe hash mismatch: got {driver_sha256}, expected {expected_sha256}; "
            "refusing to apply 4.06 code rules to a different binary"
        )

    names = load_names(cfg)
    generic_path = dev_root / args.locale / "led.xml"
    if not generic_path.is_file():
        parser.error(f"generic LED dictionary does not exist for locale {args.locale!r}: {generic_path}")
    generic_labels = load_label_dictionary(generic_path)

    rows: list[dict[str, object]] = []
    profile_count = 0
    profile_mask_present = 0
    suppressed_count = 0
    unmasked_empty_label_count = 0
    label_families: dict[str, int] = {}

    for ini_path in sorted(dev_root.glob("*/KB.ini"), key=lambda path: path.parent.name.upper()):
        profile_code = ini_path.parent.name.upper()
        if not re.fullmatch(r"[0-9A-F]{4}", profile_code):
            continue
        profile_count += 1
        options = parse_ini(ini_path).get("opt", {})
        fw = parse_integer(options.get("fw", ""), default=0)
        rgb_kb = parse_integer(options.get("rgbkb", ""), default=0)
        led_mask = parse_integer(options.get("ledmask", ""), default=0)
        if "ledmask" in options:
            profile_mask_present += 1

        if fw != 0:
            family = "tc_eft"
        elif rgb_kb != 0:
            family = "tc_led_mode"
        else:
            family = "tc_led"
        label_families[family] = label_families.get(family, 0) + 1

        profile_dictionary = ini_path.parent / args.locale / "led.xml"
        if profile_dictionary.is_file():
            dictionary_path = profile_dictionary
            labels = load_label_dictionary(profile_dictionary)
        else:
            dictionary_path = generic_path
            labels = generic_labels

        for slot in range(1, 25):
            bit_index = slot - 1
            mask_bit_set = bool(led_mask & (1 << bit_index))
            label_key = f"{family}{slot}"
            label = labels.get(label_key, "")
            if mask_bit_set:
                suppressed_count += 1
            elif not label:
                unmasked_empty_label_count += 1
            rows.append({
                "driver_sha256": driver_sha256,
                "profile_code": profile_code,
                "profile_name": names.get(profile_code, "(unregistered in Cfg.ini)"),
                "registered_in_cfg": profile_code in names,
                "locale": args.locale,
                "Fw_raw": options.get("fw", "(omitted; code default 0)"),
                "RGBKb_raw": options.get("rgbkb", "(omitted; code default 0)"),
                "LedMask_raw": options.get("ledmask", "(omitted; code default 0)"),
                "label_family": family,
                "slot_suffix": slot,
                "mask_bit_index_zero_based": bit_index,
                "label_key": label_key,
                "label_text": label,
                "dictionary_path": dictionary_path.relative_to(root).as_posix(),
                "mask_bit_set": mask_bit_set,
                "passes_static_mask_filter": not mask_bit_set,
                "localized_label_present": bool(label),
            })

    if not rows:
        parser.error(f"no Dev/*/KB.ini profiles found under {dev_root}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    fields = list(rows[0])
    with args.out.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    print(f"driver_sha256={driver_sha256}")
    print(f"profiles={profile_count} registered={sum(code in names for code in {row['profile_code'] for row in rows})}")
    print(f"candidate_rows={len(rows)} profile_LedMask_present={profile_mask_present}")
    print(f"family_profile_counts={label_families}")
    print(f"mask_suppressed_candidates={suppressed_count}")
    print(f"unmasked_candidates_with_empty_label={unmasked_empty_label_count}")
    print(f"output={args.out.resolve()}")
    print("Interpretation: a mask pass is a static candidate path, not proof a control appeared or was used at runtime.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeError, ET.ParseError, csv.Error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
