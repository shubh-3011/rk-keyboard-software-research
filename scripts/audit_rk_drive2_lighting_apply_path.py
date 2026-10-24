#!/usr/bin/env python3
"""Verify a bounded, hash-pinned drive2 lighting-to-WebHID source path.

Reads only the already-acquired drive2 JavaScript snapshot and the dated
route-asset ledger. It never executes vendor JavaScript or accesses WebHID.
Offsets in the emitted CSV are zero-based, half-open UTF-8 byte ranges.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ASSET_LEDGER = ROOT / "docs" / "rk-product-driver-route-web-asset-ledger-2026-10-20.csv"
OUTPUT = ROOT / "docs" / "rk-drive2-lighting-apply-path-evidence-2026-10-25.csv"

# Digests are repeated here so this audit cannot silently migrate when the
# route ledger is refreshed. Updating the pin requires a separately dated pass.
PINNED = {
    "index-Cq0ERv1u.js": "26eb7d4cbc70e3d5784ba77e41024d0c6f8b46ee8d022727d619a41217a0e011",
    "DeviceSettingPage-D_XFuI9e.js": "7b20036f4f4390b3559b777f72b3381e513e661929fb097df4378d07e1e6ecfb",
}


def b(text: str) -> bytes:
    return text.encode("utf-8")


# One occurrence per row is required. Long anchors are intentionally narrow:
# they identify particular UI, state, serialization, or transport edges.
ANCHORS = {
    "index-Cq0ERv1u.js": [
        (
            'path:"/device",component:cx',
            "The entry router maps /device to the lazy device-settings component.",
            "direct declaration",
            "A route declaration does not prove a runtime navigation or device identity.",
        ),
        (
            "_x as aS",
            "The entry bundle exports the device-service singleton as export aS, imported by the page chunk as mt.",
            "direct export-table alias",
            "Minified export aliases are build-specific; the relationship is scoped to these pinned assets.",
        ),
        (
            'R2.provide("WebHIDService",_x)',
            "The exported singleton is registered in the app dependency container under WebHIDService.",
            "direct registration",
            "This identifies the service object; it does not imply that a HID device was opened.",
        ),
        (
            "KB2_CMD_PRGB:24",
            "The protocol table assigns command byte 24 (0x18) to KB2_CMD_PRGB.",
            "direct enum value",
            "The enum label does not establish the command's firmware-side meaning or acceptance.",
        ),
        (
            "PRGBPack(e,t,r,a,n,o,s,l,i,u){",
            "The entry bundle defines the PRGB serializer with a 64-byte Uint8Array and ten parameters.",
            "direct serializer declaration",
            "The packet interpretation below is reconstructed from host code, not validated against firmware.",
        ),
        (
            "async writeData(t){if(!this.device)throw new Error(\"No device to write to\");const r=64;",
            "The service writeData method chunks data into reports of at most 64 bytes.",
            "direct method body",
            "A method body is not evidence of invocation in a live session.",
        ),
        (
            "await this.device.sendReport(0,n)",
            "The service's outbound WebHID boundary calls sendReport with report ID 0 and a chunk.",
            "direct API call",
            "No report was sent and no receiver behavior is inferred.",
        ),
    ],
    "DeviceSettingPage-D_XFuI9e.js": [
        (
            '[{icon:"mdi-lightbulb",text:"lightSetting"},{icon:"mdi-align-vertical-bottom",text:"performanceSetting"}',
            "The device page's first menu item is the lighting page.",
            "direct menu declaration",
            "The displayed localization string is not itself a runtime click.",
        ),
        (
            "s=l=>{n.value=l,i.value=0}",
            "Selecting a menu row assigns its index to driveCurrentPage and resets the subpage index.",
            "direct click-handler body",
            "The bound menu handler is static source evidence, not a user interaction observation.",
        ),
        (
            "x(v)==0?(L(),H(L0e,{key:0}))",
            "The device page renders L0e when driveCurrentPage is zero.",
            "direct render condition",
            "No route or page was executed during the audit.",
        ),
        (
            'k(Vt,{value:"lightTabPage-1"',
            "The lighting wrapper defines its first tab as the main-light panel.",
            "direct tab declaration",
            "Tab visibility does not prove physical lighting hardware exists.",
        ),
        (
            "default:Y(()=>[k(A0e)]),_:1}),k(Vt,{value:\"lightTabPage-2\"",
            "The main-light panel A0e is mounted in the first lighting tab.",
            "direct component composition",
            "This is UI composition only.",
        ),
        (
            "changeLightBigMode:f,changeLightLuminance:d,changeDynamicLightMode:v",
            "The main-light component obtains its mode, luminance, and effect handlers from the lighting composable.",
            "direct handler binding",
            "Handler availability does not prove a specific model supports every option.",
        ),
        (
            'k(ml,{modelValue:x(n),"onUpdate:modelValue":[m[0]||(m[0]=_=>Ue(n)?n.value=_:null),x(f)]',
            "The main-light mode selector invokes changeLightBigMode after updating its selected mode.",
            "direct template event binding",
            "The binding does not establish whether a particular keyboard accepts the resulting command.",
        ),
        (
            "await mt.writeData(re.PRGBPack(1,v.value,i.value,c.value,f.value,s.value,o.value,l.value,u.value,d.value)),r.value===3",
            "The mode-change handler passes its updated lighting state to PRGBPack with apply flag 1 and awaits the service write.",
            "direct handler-to-serializer call",
            "The final conditional also starts a per-key color operation for custom mode; this audit does not trace that separate branch.",
        ),
    ],
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv-out", type=Path, default=OUTPUT)
    args = parser.parse_args()

    ledger: dict[str, dict[str, str]] = {}
    with ASSET_LEDGER.open("r", encoding="utf-8-sig", newline="") as stream:
        for row in csv.DictReader(stream):
            if row["route_host"] == "drive2.rkgaming.com" and row["asset_kind"] == "javascript":
                name = Path(row["local_path"].replace("\\", "/")).name
                if name in PINNED:
                    if name in ledger:
                        raise ValueError(f"Duplicate route-ledger entry for {name}")
                    ledger[name] = row

    rows: list[dict[str, str | int]] = []
    for name, expected_hash in PINNED.items():
        row = ledger.get(name)
        if row is None:
            raise ValueError(f"No drive2 JavaScript asset-ledger row for {name}")
        if row["sha256"] != expected_hash:
            raise ValueError(f"Asset-ledger pin changed for {name}: {row['sha256']}")
        path = ROOT / Path(row["local_path"].replace("\\", "/"))
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if digest != expected_hash:
            raise ValueError(f"SHA-256 mismatch for {path}: expected {expected_hash}, got {digest}")
        for needle_text, evidence, classification, limit in ANCHORS[name]:
            needle = b(needle_text)
            start = data.find(needle)
            if start < 0:
                raise ValueError(f"Anchor absent in pinned {name}: {needle_text!r}")
            if data.find(needle, start + 1) >= 0:
                raise ValueError(f"Anchor is not unique in pinned {name}: {needle_text!r}")
            rows.append({
                "file": row["local_path"],
                "sha256": digest,
                "byte_offset_start": start,
                "byte_offset_end": start + len(needle),
                "anchor": needle_text,
                "evidence": evidence,
                "classification": classification,
                "limit": limit,
            })

    # Enforce the specific page-module -> entry-export identity used by the trace.
    page = (ROOT / Path(ledger["DeviceSettingPage-D_XFuI9e.js"]["local_path"].replace("\\", "/"))).read_bytes()
    if b'from"./index-Cq0ERv1u.js"' not in page:
        raise ValueError("Page chunk no longer imports the pinned entry module")
    if b"aS as mt" not in page:
        raise ValueError("Page chunk no longer imports the service export as mt")

    output = args.csv_out if args.csv_out.is_absolute() else ROOT / args.csv_out
    output.parent.mkdir(parents=True, exist_ok=True)
    fields = ["file", "sha256", "byte_offset_start", "byte_offset_end", "anchor", "evidence", "classification", "limit"]
    with output.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    print(f"PASS: {len(rows)} unique anchors verified across {len(PINNED)} hash-pinned drive2 JavaScript assets")
    print(f"Wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
