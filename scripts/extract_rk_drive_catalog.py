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
MOUSE_MARKER = "deviceType:ws.Mouse"


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


def matching_delimiter(text: str, open_index: int) -> int:
    """Return the closing brace/bracket for a minified JS object or array."""
    opening = text[open_index]
    closing = {"{": "}", "[": "]"}.get(opening)
    if not closing:
        return -1
    stack = [closing]
    in_string = ""
    escaped = False
    for index in range(open_index + 1, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == in_string:
                in_string = ""
            continue
        if char in "\"'`":
            in_string = char
        elif char in "{[":
            stack.append("}" if char == "{" else "]")
        elif char in "}]":
            if not stack or char != stack[-1]:
                return -1
            stack.pop()
            if not stack:
                return index
    return -1


def objects_with_marker(script: str, marker: str) -> list[tuple[int, int]]:
    """Find minified object assignments containing a structural property marker."""
    results: list[tuple[int, int]] = []
    seen: set[int] = set()
    for marker_match in re.finditer(re.escape(marker), script):
        start = script.rfind("{", 0, marker_match.start())
        if start < 0 or start in seen:
            continue
        assignment = script[max(0, start - 100):start]
        if not re.search(r"[A-Za-z_$][\w$]*=\s*$", assignment):
            continue
        end = matching_delimiter(script, start)
        if end > marker_match.start():
            seen.add(start)
            results.append((start, end + 1))
    return results


def js_scalar(body: str, key: str) -> str | None:
    """Read a string, number, boolean token, or dotted symbol by object key."""
    match = re.search(rf"(?<![\w$]){re.escape(key)}\s*:", body)
    if not match:
        return None
    index = match.end()
    while index < len(body) and body[index].isspace():
        index += 1
    if index >= len(body):
        return None
    if body[index] in "\"'":
        quote = body[index]
        start = index
        index += 1
        escaped = False
        while index < len(body):
            char = body[index]
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                index += 1
                raw = body[start:index]
                if quote == '"':
                    try:
                        return str(json.loads(raw))
                    except json.JSONDecodeError:
                        return raw[1:-1]
                return raw[1:-1].replace("\\'", "'").replace("\\\\", "\\")
            index += 1
        return None
    token = re.match(r"!?[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*|!?\d+", body[index:])
    return token.group(0) if token else None


def object_property_body(body: str, key: str) -> str:
    match = re.search(rf"(?<![\w$]){re.escape(key)}\s*:\s*\{{", body)
    if not match:
        return ""
    start = body.find("{", match.start())
    end = matching_delimiter(body, start)
    return body[start + 1:end] if end > start else ""


def array_property_items(body: str, key: str) -> list[str]:
    match = re.search(rf"(?<![\w$]){re.escape(key)}\s*:\s*\[", body)
    if not match:
        return []
    start = body.find("[", match.start())
    end = matching_delimiter(body, start)
    if end <= start:
        return []
    array = body[start + 1:end]
    items: list[str] = []
    stack: list[int] = []
    in_string = ""
    escaped = False
    for index, char in enumerate(array):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == in_string:
                in_string = ""
        elif char in "\"'`":
            in_string = char
        elif char == "{":
            if not stack:
                stack.append(index)
            else:
                stack.append(index)
        elif char == "}" and stack:
            item_start = stack.pop()
            if not stack:
                items.append(array[item_start + 1:index])
    return items


def parse_mouse_descriptors(script: str) -> list[dict[str, object]]:
    """Extract mouse descriptors and chooser aliases without retaining vendor JS."""
    parsed: list[dict[str, object]] = []
    for start, end in objects_with_marker(script, MOUSE_MARKER):
        body = script[start + 1:end - 1]
        name = js_scalar(body, "name")
        vid = js_scalar(body, "vendorId")
        pid = js_scalar(body, "productId")
        usage_page = js_scalar(body, "usagePage")
        usage = js_scalar(body, "usage")
        connect = js_scalar(body, "connectType")
        protocol = js_scalar(body, "protocolType")
        if not all((name, vid, pid, usage_page, usage, connect, protocol)):
            continue
        try:
            row: dict[str, object] = {
                "record_type": "legacy_mouse_descriptor",
                "model_label": name,
                "model_id": "",
                "vendor_id": int(vid),
                "vendor_id_hex": f"0x{int(vid):04X}",
                "product_id": int(pid),
                "product_id_hex": f"0x{int(pid):04X}",
                "usage_page": int(usage_page),
                "usage_page_hex": f"0x{int(usage_page):04X}",
                "usage": int(usage),
                "connection": {"Bt.USB": "wired", "Bt.Dongle": "2.4 GHz receiver"}.get(connect, connect),
                "protocol_family": protocol.removeprefix("bs."),
                "layout_symbol": js_scalar(body, "layout") or "",
                "protocol_factory_symbol": js_scalar(body, "protocol") or "",
                "reported_size_bytes": "",
                "hid_report_id": "",
                "declared_feature_flags": "",
                "storage_profile_key": "",
                "image_url": "",
                "chooser_alias_labels": "",
            }
        except ValueError:
            continue
        if not any(
            existing["model_label"] == row["model_label"]
            and existing["vendor_id"] == row["vendor_id"]
            and existing["product_id"] == row["product_id"]
            and existing["usage_page"] == row["usage_page"]
            and existing["usage"] == row["usage"]
            and existing["connection"] == row["connection"]
            and existing["protocol_family"] == row["protocol_family"]
            for existing in parsed
        ):
            parsed.append(row)

    # Drive keeps the lower-case chooser aliases as separate descriptors. Join
    # them to the full model records only when the complete declared HID identity
    # and transport/protocol tuple agree.
    full_records = [row for row in parsed if row["layout_symbol"] and row["protocol_factory_symbol"]]
    alias_records = [row for row in parsed if not (row["layout_symbol"] and row["protocol_factory_symbol"])]
    full_by_identity: dict[tuple[object, ...], list[dict[str, object]]] = {}
    for row in full_records:
        key = (row["vendor_id"], row["product_id"], row["usage_page"], row["usage"], row["connection"], row["protocol_family"])
        full_by_identity.setdefault(key, []).append(row)
    alias_labels: dict[tuple[object, ...], set[str]] = {}
    unmatched_aliases: list[str] = []
    for row in alias_records:
        key = (row["vendor_id"], row["product_id"], row["usage_page"], row["usage"], row["connection"], row["protocol_family"])
        if key in full_by_identity:
            alias_labels.setdefault(key, set()).add(str(row["model_label"]))
        else:
            unmatched_aliases.append(str(row["model_label"]))
    if unmatched_aliases:
        raise RuntimeError("Mouse chooser aliases did not match full descriptors: " + ", ".join(sorted(unmatched_aliases)))
    for key, rows in full_by_identity.items():
        labels = " | ".join(sorted(alias_labels.get(key, set()), key=str.casefold))
        for row in rows:
            row["chooser_alias_labels"] = labels
    if len(full_records) < 20 or len(alias_records) < 20:
        raise RuntimeError(
            f"Mouse schema produced {len(full_records)} full descriptors and "
            f"{len(alias_records)} chooser aliases; review before publishing"
        )
    return full_records


def parse_tlw_mouse_profile(script: str) -> list[dict[str, object]]:
    """Expand CB75-Mouse's public profile into wired/wireless metadata rows."""
    profile_body = ""
    for start, end in objects_with_marker(script, "name:"):
        candidate = script[start + 1:end - 1]
        if js_scalar(candidate, "id") == "cb75":
            profile_body = candidate
            break
    if not profile_body:
        return []
    hid = object_property_body(profile_body, "hid")
    storage = object_property_body(profile_body, "storage")
    features = object_property_body(profile_body, "features")
    profile_id = js_scalar(profile_body, "id") or ""
    model_label = js_scalar(profile_body, "name") or "CB75-Mouse"
    vid = int(js_scalar(profile_body, "vendorId") or "0")
    report_id = js_scalar(hid, "reportId") or ""
    usage_page = int(js_scalar(hid, "usagePage") or "0")
    usage = int(js_scalar(hid, "usage") or "0")
    image = ""
    image_symbol = js_scalar(profile_body, "image")
    if image_symbol:
        image_match = re.search(rf"(?<![\w$]){re.escape(image_symbol)}\s*=\s*\"(/assets/[^\"]+)\"", script)
        if image_match:
            image = urljoin(BASE_URL, image_match.group(1))
    if not image:
        image_match = re.search(r'"(/assets/cb75-mouse-[^"]+)"', script)
        image = urljoin(BASE_URL, image_match.group(1)) if image_match else ""
    declared_flags = {
        key: js_scalar(features, key) == "!0"
        for key in re.findall(r"([A-Za-z_$][\w$]*)\s*:", features)
    }
    storage_profile = js_scalar(storage, "profiles") or ""
    rows: list[dict[str, object]] = []
    for connection in array_property_items(profile_body, "connections"):
        mode = js_scalar(connection, "mode")
        pid = js_scalar(connection, "productId")
        data_size = js_scalar(connection, "dataSize")
        if not all((mode, pid, data_size)):
            continue
        try:
            pid_int = int(pid)
            rows.append({
                "record_type": "TLW_mouse_model_profile",
                "model_label": model_label,
                "model_id": profile_id,
                "vendor_id": vid,
                "vendor_id_hex": f"0x{vid:04X}",
                "product_id": pid_int,
                "product_id_hex": f"0x{pid_int:04X}",
                "usage_page": usage_page,
                "usage_page_hex": f"0x{usage_page:04X}",
                "usage": usage,
                "connection": mode,
                "protocol_family": "TLW",
                "layout_symbol": "",
                "protocol_factory_symbol": "",
                "reported_size_bytes": int(data_size),
                "hid_report_id": report_id,
                "declared_feature_flags": json.dumps(declared_flags, separators=(",", ":")),
                "storage_profile_key": storage_profile,
                "image_url": image,
                "chooser_alias_labels": "",
            })
        except ValueError:
            continue
    return rows


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
    mouse_records = parse_mouse_descriptors(entry_script)
    tlw_mouse_records = parse_tlw_mouse_profile(entry_script)
    if len(mouse_records) < 20:
        raise RuntimeError(
            f"Only {len(mouse_records)} legacy mouse descriptors matched; "
            "review the bundle schema before publishing an incomplete registry"
        )
    if not tlw_mouse_records:
        raise RuntimeError("The CB75-Mouse profile did not produce any connection rows")

    bundle_hash = sha256(scripts[entry_url])
    for record in records:
        record["source_bundle_url"] = entry_url
        record["source_bundle_sha256"] = bundle_hash
        record["retrieved_at_utc"] = retrieved_at
    mouse_rows = mouse_records + tlw_mouse_records
    for record in mouse_rows:
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

    mouse_fields = [
        "record_type", "model_label", "model_id", "vendor_id", "vendor_id_hex",
        "product_id", "product_id_hex", "usage_page", "usage_page_hex", "usage",
        "connection", "protocol_family", "layout_symbol", "protocol_factory_symbol",
        "reported_size_bytes", "hid_report_id", "declared_feature_flags",
        "storage_profile_key", "image_url", "chooser_alias_labels",
        "source_bundle_url", "source_bundle_sha256", "retrieved_at_utc",
    ]
    csv_writer(args.out_dir / "rk-drive-mouse-registry.csv", mouse_fields, mouse_rows)

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
    mouse_images: dict[str, set[str]] = {}
    for record in tlw_mouse_records:
        image_url = str(record["image_url"])
        if image_url:
            mouse_images.setdefault(image_url, set()).add(str(record["model_label"]))
    photo_rows.extend(
        {
            "image_asset": image_url.rsplit("/", 1)[-1],
            "image_url": image_url,
            "model_labels": " | ".join(sorted(names)),
            "source_bundle_sha256": bundle_hash,
            "retrieved_at_utc": retrieved_at,
        }
        for image_url, names in sorted(mouse_images.items())
    )
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
        "keyboardImageReferenceCount": len(image_models),
        "imageReferenceCount": len(photo_rows),
        "models": records,
        "mouseDescriptorCount": len(mouse_records),
        "mouseConnectionProfileCount": len(mouse_rows),
        "mouseModels": mouse_rows,
    }
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"Fetched {len(scripts)} JavaScript files; retained no vendor JS bytes.")
    print(f"Wrote {len(records)} keyboard descriptors, {output['modelLabelCount']} labels, "
          f"{len(image_models)} keyboard images, and {len(mouse_images)} mouse images.")
    print(f"Wrote {len(mouse_records)} legacy mouse descriptors and "
          f"{len(tlw_mouse_records)} CB75-Mouse connection rows.")
    print(f"Entry bundle SHA-256: {bundle_hash}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
