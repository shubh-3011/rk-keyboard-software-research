#!/usr/bin/env python3
"""Extract read-only model layouts and profile data from an installed RK app.

The generated JSON contains model names, layout rectangles, capability
metadata, and decoded profile fields. A companion CSV records the static
profile-to-handler selector and raw wireless identity fields. Neither output
copies the RK executable, firmware, report payloads, or image assets.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from pathlib import Path
from xml.etree import ElementTree


def read_text(path: Path) -> str:
    raw = path.read_bytes()
    encoding = "utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8"
    return raw.decode(encoding, errors="replace")


def parse_sections(text: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {"": []}
    current = ""
    for line in text.splitlines():
        match = re.match(r"\s*\[([^]]+)\]\s*$", line)
        if match:
            current = match.group(1).strip().upper()
            sections.setdefault(current, [])
        else:
            sections.setdefault(current, []).append(line)
    return sections


def parse_options(lines: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in lines:
        value = line.split(";", 1)[0].strip()
        if not value or value.startswith("#") or "=" not in value:
            continue
        key, item = value.split("=", 1)
        result[key.strip()] = item.strip()
    return result


def number(value: str | None, fallback: int = 0) -> int:
    if value is None:
        return fallback
    try:
        return int(value.strip(), 0)
    except ValueError:
        try:
            return int(value.strip(), 10)
        except ValueError:
            return fallback


def model_family(name: str) -> str:
    match = re.search(r"(?i)(?:RK[\s-]*)?([A-Z]?\d{2,3})", name)
    return match.group(1).upper() if match else "RK"


def model_region(name: str) -> str:
    upper = name.upper()
    for suffix, label in (
        ("ISO RETURN", "ISO"),
        (" DE KEYBOARD", "DE"),
        (" FR KEYBOARD", "FR"),
        (" ES KEYBOARD", "ES"),
        (" TH KEYBOARD", "TH"),
        (" RU KEYBOARD", "RU"),
        (" UK KEYBOARD", "UK"),
    ):
        if suffix in upper:
            return label
    return "ANSI"


def parse_value_list(value: str) -> list[object]:
    """Preserve a comma-separated profile value, decoding integer tokens when possible."""
    values: list[object] = []
    for part in value.split(","):
        item = part.strip()
        if not item:
            values.append("")
            continue
        try:
            values.append(int(item, 0))
        except ValueError:
            try:
                values.append(int(item, 10))
            except ValueError:
                values.append(item)
    return values


def assignments(lines: list[str]) -> dict[str, list[object]]:
    """Read K-number assignment records without assuming the meaning of each field."""
    result: dict[str, list[object]] = {}
    for line in lines:
        match = re.match(r"\s*(K\d+)\s*=\s*(.*?)\s*$", line, re.IGNORECASE)
        if match:
            result[match.group(1).upper()] = parse_value_list(match.group(2))
    return result


def extract_lighting_labels(rk_root: Path, code: str) -> dict[str, list[dict[str, str]]]:
    """Preserve profile-local LED labels without assigning protocol semantics."""
    labels: dict[str, list[dict[str, str]]] = {}
    profile_dir = rk_root / "Dev" / code
    for path in sorted(profile_dir.glob("*/led.xml")):
        locale = path.parent.name
        try:
            root = ElementTree.fromstring(read_text(path))
        except ElementTree.ParseError:
            continue
        entries = [
            {"key": node.tag, "label": node.text.strip()}
            for node in root.iter()
            if len(node) == 0 and node.text and node.text.strip()
        ]
        if entries:
            labels[locale] = entries
    return labels


def extract_keys(lines: list[str]) -> tuple[list[dict[str, object]], int, int]:
    keys: list[dict[str, object]] = []
    label = ""
    rightmost = bottom = 0
    for line in lines:
        stripped = line.strip()
        if stripped.startswith(";"):
            label = stripped[1:].strip()
            continue
        match = re.match(r"K(\d+)\s*=\s*(.*)", stripped, re.IGNORECASE)
        if not match:
            continue
        fields = [part.strip() for part in match.group(2).split(",")]
        if len(fields) < 4:
            label = ""
            continue
        try:
            x, y, x2, y2 = (int(part, 0) for part in fields[:4])
        except ValueError:
            try:
                x, y, x2, y2 = (int(part, 10) for part in fields[:4])
            except ValueError:
                label = ""
                continue
        if x2 > x and y2 > y:
            caption = (label or f"Key {match.group(1)}").replace("_", " ")
            keys.append({
                "id": f"K{int(match.group(1))}",
                "label": caption,
                "x": x,
                "y": y,
                "w": x2 - x,
                "h": y2 - y,
            })
            rightmost = max(rightmost, x2)
            bottom = max(bottom, y2)
        label = ""
    return keys, rightmost, bottom


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--rk-root",
        type=Path,
        default=Path(r"C:\Program Files (x86)\RK Keyboard Software"),
        help="RK Keyboard Software install directory",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "models.json",
    )
    parser.add_argument(
        "--driver-map-output",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "docs" / "rk-profile-driver-family-map.csv",
        help="write the installed profile-to-handler selection map",
    )
    args = parser.parse_args()

    cfg_path = args.rk_root / "Cfg.ini"
    cfg_sections = parse_sections(read_text(cfg_path))
    cfg_options = parse_options(cfg_sections.get("OPT", []))
    supported_pids = {
        value.strip().upper().removeprefix("0X").zfill(4)
        for value in cfg_options.get("PID", "").split(",")
        if value.strip()
    }

    names: dict[str, str] = {}
    for line in cfg_sections.get("OPT", []):
        match = re.match(r"\s*DevName\d+\s*=\s*([0-9A-Fa-f]{4})\s*,\s*(.+?)\s*$", line)
        if match:
            names[match.group(1).upper()] = match.group(2).strip()

    models: list[dict[str, object]] = []
    layouts: dict[str, dict[str, object]] = {}
    profile_field_names: set[str] = set()
    for code, name in names.items():
        ini_path = args.rk_root / "Dev" / code / "KB.ini"
        if not ini_path.is_file():
            continue
        sections = parse_sections(read_text(ini_path))
        options = parse_options(sections.get("OPT", []))
        profile_field_names.update(options)
        keys, width, height = extract_keys(sections.get("KEY", []))
        layer_count = number(options.get("LayerNum"), 0)
        if not layer_count:
            fn_layers = [
                number(section.removeprefix("FN"))
                for section in sections
                if re.fullmatch(r"FN\d+", section)
            ]
            layer_count = 1 + max(fn_layers, default=0)
        layer_count = max(1, min(layer_count, 8))
        screen_width, screen_height = [
            number(part)
            for part in (options.get("siScreen", "0,0").split(",") + ["0", "0"])[:2]
        ]
        mode_slots = sorted(
            int(match.group(1))
            for key in options
            if (match := re.fullmatch(r"LedOpt(\d+)", key, re.IGNORECASE))
        )
        led_modes = [
            {"slot": slot, "values": parse_value_list(options[f"LedOpt{slot}"])}
            for slot in mode_slots
            if f"LedOpt{slot}" in options
        ]
        wireless_id = options.get("PID_Wireless", "")
        wireless_id = wireless_id.upper().removeprefix("0X").zfill(4) if wireless_id else ""
        wireless_vid = options.get("VID_Wireless", "")
        wireless_vid = wireless_vid.upper().removeprefix("0X").zfill(4) if wireless_vid else ""
        layout = {"width": width, "height": height, "keys": keys}
        layout_signature = json.dumps(layout, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        layout_id = hashlib.sha256(layout_signature.encode("utf-8")).hexdigest()[:12]
        layouts[layout_id] = layout
        models.append({
            "code": code,
            "name": name,
            "family": model_family(name),
            "region": model_region(name),
            "isDirectPid": code in supported_pids,
            "keyCount": number(options.get("LayoutKeyNum"), len(keys)),
            "drawableKeyCount": len(keys),
            "layoutId": layout_id,
            "features": {
                "rgb": number(options.get("RGBKb")) != 0,
                "lightingModeSlots": mode_slots,
                "lightingModes": led_modes,
                "layers": ["Base"] + [f"Fn {index}" for index in range(1, layer_count)],
                "screen": {
                    "width": screen_width,
                    "height": screen_height,
                    "maxFrames": number(options.get("MaxScreenFrame")),
                    "rgb": number(options.get("RGBScreen")) != 0,
                } if number(options.get("ShowScreen")) != 0 else None,
                "macroBuffers": number(options.get("MacroBufferNum")),
                "wirelessProductId": wireless_id or None,
                "wirelessVendorId": wireless_vid or None,
            },
            # Preserve all decoded configuration and mapping rows from the
            # installed profile. Unknown values stay raw evidence; the parser
            # does not imply that Keydeck can send or safely apply them.
            "profileData": {
                "options": options,
                "baseMappings": assignments(sections.get("KEY", [])),
                "fnMappings": {
                    section: assignments(lines)
                    for section, lines in sections.items()
                    if re.fullmatch(r"FN\d+", section)
                },
                "sectionNames": [section for section in sections if section],
                "lightingLabels": extract_lighting_labels(args.rk_root, code),
            },
        })

    models.sort(key=lambda model: (str(model["family"]), str(model["name"]), str(model["code"])))
    named_codes = {str(model["code"]).upper() for model in models}
    unregistered_profiles: list[dict[str, object]] = []
    for ini_path in sorted((args.rk_root / "Dev").glob("*/KB.ini")):
        code = ini_path.parent.name.upper()
        if code in named_codes:
            continue
        orphan_sections = parse_sections(read_text(ini_path))
        orphan_options = parse_options(orphan_sections.get("OPT", []))
        profile_field_names.update(orphan_options)
        orphan_keys, width, height = extract_keys(orphan_sections.get("KEY", []))
        orphan_layout = {"width": width, "height": height, "keys": orphan_keys}
        layout_signature = json.dumps(
            orphan_layout, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        layout_id = hashlib.sha256(layout_signature.encode("utf-8")).hexdigest()[:12]
        layouts[layout_id] = orphan_layout
        unregistered_profiles.append({
            "code": code,
            "layoutId": layout_id,
            "profileData": {
                "options": orphan_options,
                "baseMappings": assignments(orphan_sections.get("KEY", [])),
                "fnMappings": {
                    section: assignments(lines)
                    for section, lines in orphan_sections.items()
                    if re.fullmatch(r"FN\d+", section)
                },
                "sectionNames": [section for section in orphan_sections if section],
                "lightingLabels": extract_lighting_labels(args.rk_root, code),
            },
        })
    args.output.parent.mkdir(parents=True, exist_ok=True)
    catalog = {
        "version": 3,
        "source": "RK Keyboard Software 4.06 Cfg.ini and Dev/*/KB.ini",
        "vendorId": "258A",
        "profileFieldNames": sorted(profile_field_names),
        "profileCount": len(list((args.rk_root / "Dev").glob("*/KB.ini"))),
        "unregisteredProfiles": unregistered_profiles,
        "models": models,
        "layouts": layouts,
    }
    args.output.write_text(
        json.dumps(catalog, ensure_ascii=False, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    args.driver_map_output.parent.mkdir(parents=True, exist_ok=True)
    with args.driver_map_output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "profile_code",
                "model_name",
                "usb_vid",
                "usb_pid",
                "direct_profile",
                "fw_raw",
                "static_handler",
                "psd_raw",
                "wireless_vid",
                "wireless_pid",
            ],
        )
        writer.writeheader()
        for model in models:
            options = model["profileData"]["options"]
            fw_raw = str(options.get("Fw", ""))
            fw_value = number(fw_raw, 0)
            writer.writerow({
                "profile_code": model["code"],
                "model_name": model["name"],
                "usb_vid": "258A",
                "usb_pid": model["code"] if model["isDirectPid"] else "",
                "direct_profile": str(bool(model["isDirectPid"])).lower(),
                "fw_raw": fw_raw if fw_raw else "(omitted; loader default 0)",
                "static_handler": "CDevG5KB" if fw_value else "CDevRKKB",
                "psd_raw": options.get("Psd", ""),
                "wireless_vid": model["features"]["wirelessVendorId"] or "",
                "wireless_pid": model["features"]["wirelessProductId"] or "",
            })
    print(f"Wrote {len(models)} model profiles and {len(layouts)} unique layouts to {args.output} from {cfg_path}")
    print(f"Wrote profile-to-handler map to {args.driver_map_output}")


if __name__ == "__main__":
    main()
