#!/usr/bin/env python3
"""Extract public model metadata from RK's Web Driver bundle without saving it."""

from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import urljoin
from urllib.request import Request, urlopen


BASE_URL = "https://drive.rkgaming.com/"
SCRIPT_PATTERN = re.compile(r"[\"'](/assets/[^\"']+\.js(?:\?[^\"']*)?)[\"']")
ENTRY_PATTERN = re.compile(r"<script[^>]+src=[\"']([^\"']+\.js(?:\?[^\"']*)?)[\"']")
DEVICE_PATTERN = re.compile(
    r'\{name:"([^"]+)",image:"([^"]+)",vendorId:(\d+),productId:(\d+),'
    r'usagePage:(\d+),usage:(\d+),connectType:([^,}]+),deviceType:([^,}]+),'
    r'protocolType:([^,}]+),keyText:([^,}]+),keyMatrixLayer:\[([^\]]*)\],'
    r'keyMatrixTable:\[([^\]]*)\],keyLayout:\{(.*?)\},'
    r'lightEffects:([A-Za-z_$][\w$]*),protocol:',
    re.DOTALL,
)
EFFECT_PATTERN = re.compile(
    r"\{effect:pt\.([A-Za-z_$][\w$]*),speed:(![01]),brightness:(![01]),"
    r"color:(void 0|![01]),mixColor:(![01]),sleep:(\d+)\}"
)


def array_assignment_body(script: str, symbol: str) -> str:
    """Read one minified array declaration without evaluating the vendor bundle."""
    match = re.search(rf"(?<![\w$]){re.escape(symbol)}=\[", script)
    if not match:
        return ""
    start = match.end()
    depth = 1
    in_string = ""
    escaped = False
    index = start
    while index < len(script) and depth:
        char = script[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == in_string:
                in_string = ""
        elif char in "\"'`":
            in_string = char
        elif char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
        index += 1
    return script[start:index - 1] if depth == 0 else ""


def js_enum_items(value: str, prefix: str, labels: dict[str, str]) -> list[str]:
    """Map a short enum-reference list to readable labels, preserving unknowns."""
    result: list[str] = []
    for token in value.split(","):
        token = token.strip()
        match = re.fullmatch(rf"{re.escape(prefix)}\.([A-Za-z_$][\w$]*)", token)
        if match:
            name = match.group(1)
            result.append(labels.get(name, name))
    return result


def extract_lighting_effects(array_body: str) -> list[dict[str, object]]:
    effects: list[dict[str, object]] = []
    for match in EFFECT_PATTERN.finditer(array_body):
        name, speed, brightness, color, mix_color, sleep = match.groups()
        effects.append({
            "name": name,
            "speed": speed == "!0",
            "brightness": brightness == "!0",
            "colorValueDefined": color != "void 0",
            "mixColor": mix_color == "!0",
            "sleepValue": int(sleep),
        })
    return effects


def fetch(url: str) -> bytes:
    request = Request(url, headers={"User-Agent": "rk-software-research-catalog/1.0"})
    with urlopen(request, timeout=60) as response:
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status} while fetching {url}")
        return response.read()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def csv_writer(path: Path, fields: list[str], rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def parse_device_records(script: str) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    seen: set[tuple[object, ...]] = set()
    layer_labels = {
        "Nomal": "Normal",
        "FN": "Fn",
        "FN1": "Fn 1",
        "FN2": "Fn 2",
        "Tap": "Tap",
    }
    table_labels = {"WIN": "Windows", "MAC": "macOS"}
    lighting_symbols = {
        match.group(14) for match in DEVICE_PATTERN.finditer(script)
    }
    lighting_profiles = {
        symbol: extract_lighting_effects(array_assignment_body(script, symbol))
        for symbol in lighting_symbols
    }
    for match in DEVICE_PATTERN.finditer(script):
        (
            name, image, vid, pid, usage_page, usage, connect, kind, protocol,
            _key_text, layer_refs, table_refs, layout_body, lighting_symbol,
        ) = match.groups()
        row: dict[str, object] = {
            "name": name,
            "image_asset": image,
            "image_url": urljoin(BASE_URL, f"src/assets/images/{image}"),
            "vendor_id": int(vid),
            "vendor_id_hex": f"0x{int(vid):04X}",
            "product_id": int(pid),
            "product_id_hex": f"0x{int(pid):04X}",
            "usage_page": int(usage_page),
            "usage_page_hex": f"0x{int(usage_page):04X}",
            "usage": int(usage),
            "usage_hex": f"0x{int(usage):04X}",
            "connection": {"Bt.USB": "USB", "Bt.Dongle": "2.4 GHz receiver"}.get(
                connect, connect
            ),
            "device_type": kind.removeprefix("ws."),
            "protocol_type": protocol.removeprefix("bs."),
            "web_configurator": {
                "key_layers": js_enum_items(layer_refs, "It", layer_labels)
                or js_enum_items(layer_refs, "Hn", layer_labels),
                "key_tables": js_enum_items(table_refs, "g", table_labels),
                "layout_group_count": len(re.findall(r"(?:^|,)\d+:\{", layout_body)),
                "lighting_effects": lighting_profiles.get(lighting_symbol, []),
            },
        }
        key = tuple(row[field] for field in (
            "name", "image_asset", "vendor_id", "product_id", "usage_page",
            "usage", "connection", "device_type", "protocol_type"
        ))
        if key not in seen:
            seen.add(key)
            records.append(row)
    return records


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, default=Path("docs"))
    parser.add_argument("--json", type=Path, default=Path("rk-drive-catalog.json"))
    args = parser.parse_args()

    retrieved_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    html_bytes = fetch(BASE_URL)
    html = html_bytes.decode("utf-8", errors="replace")
    entry_matches = ENTRY_PATTERN.findall(html)
    if not entry_matches:
        raise RuntimeError("No JavaScript entry point was found in the official site HTML")
    entry_url = urljoin(BASE_URL, entry_matches[0])

    scripts: dict[str, bytes] = {}
    pending = [entry_url]
    while pending:
        script_url = pending.pop()
        if script_url in scripts:
            continue
        data = fetch(script_url)
        scripts[script_url] = data
        text = data.decode("utf-8", errors="replace")
        for asset_path in SCRIPT_PATTERN.findall(text):
            candidate = urljoin(BASE_URL, asset_path)
            if candidate not in scripts:
                pending.append(candidate)

    entry_script = scripts[entry_url].decode("utf-8", errors="replace")
    records = parse_device_records(entry_script)
    if not records:
        raise RuntimeError("No public model descriptors matched the known bundle schema")

    bundle_hash = sha256(scripts[entry_url])
    for record in records:
        record["source_bundle_url"] = entry_url
        record["source_bundle_sha256"] = bundle_hash
        record["retrieved_at_utc"] = retrieved_at

    manifest_rows = [
        {
            "url": url,
            "bytes": len(data),
            "sha256": sha256(data),
            "entry": url == entry_url,
            "retrieved_at_utc": retrieved_at,
        }
        for url, data in sorted(scripts.items())
    ]
    csv_writer(
        args.out_dir / "rk-drive-js-manifest.csv",
        ["url", "bytes", "sha256", "entry", "retrieved_at_utc"],
        manifest_rows,
    )

    catalog_fields = [
        "name", "image_asset", "image_url", "vendor_id", "vendor_id_hex",
        "product_id", "product_id_hex", "usage_page", "usage_page_hex", "usage",
        "usage_hex", "connection", "device_type", "protocol_type",
        "key_layers", "key_tables", "layout_group_count", "lighting_effect_count",
        "lighting_effects_json",
        "source_bundle_url", "source_bundle_sha256", "retrieved_at_utc",
    ]
    catalog_rows = [
        {
            **row,
            "key_layers": " | ".join(row["web_configurator"]["key_layers"]),
            "key_tables": " | ".join(row["web_configurator"]["key_tables"]),
            "layout_group_count": row["web_configurator"]["layout_group_count"],
            "lighting_effect_count": len(row["web_configurator"]["lighting_effects"]),
            "lighting_effects_json": json.dumps(
                row["web_configurator"]["lighting_effects"],
                ensure_ascii=False,
                separators=(",", ":"),
            ),
        }
        for row in records
    ]
    csv_writer(args.out_dir / "rk-drive-keyboard-catalog.csv", catalog_fields, catalog_rows)

    image_models: dict[str, set[str]] = {}
    for record in records:
        image_models.setdefault(str(record["image_asset"]), set()).add(str(record["name"]))
    photo_rows = [
        {
            "image_asset": image,
            "image_url": urljoin(BASE_URL, f"src/assets/images/{image}"),
            "model_labels": " | ".join(sorted(names)),
            "source_bundle_sha256": bundle_hash,
            "retrieved_at_utc": retrieved_at,
        }
        for image, names in sorted(image_models.items())
    ]
    csv_writer(
        args.out_dir / "rk-drive-image-references.csv",
        ["image_asset", "image_url", "model_labels", "source_bundle_sha256", "retrieved_at_utc"],
        photo_rows,
    )

    output = {
        "source": BASE_URL,
        "retrievedAtUtc": retrieved_at,
        "sourceBundle": {"url": entry_url, "sha256": bundle_hash},
        "descriptorCount": len(records),
        "modelLabelCount": len({str(row["name"]) for row in records}),
        "imageReferenceCount": len(image_models),
        "models": records,
    }
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"Fetched {len(scripts)} JavaScript files; retained no vendor JS bytes.")
    print(f"Wrote {len(records)} device descriptors, {output['modelLabelCount']} labels, "
          f"and {len(image_models)} image references.")
    print(f"Entry bundle SHA-256: {bundle_hash}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
