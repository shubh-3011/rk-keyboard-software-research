#!/usr/bin/env python3
"""Record hash-pinned static connection-path anchors from the drive2 web app.

Reads only the already-acquired HTML/JavaScript asset snapshot and its CSV
hash ledger. It never executes JavaScript or opens a HID device. The emitted
CSV records exact byte offsets for selected route, UI, transport, and packet
builder anchors; lexical matches alone are not treated as proof of reachability.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ASSET_LEDGER = ROOT / "docs" / "rk-product-driver-route-web-asset-ledger-2026-10-20.csv"

ANCHORS: dict[str, list[tuple[bytes, str, str]]] = {
    "index-Cq0ERv1u.js": [
        (b"path:\"/connect\",component:ix", "route table maps /connect to the lazy ConnectDrivePage loader", "static route table; no route execution"),
        (b"path:\"/device\",component:cx", "route table maps /device to the lazy DeviceSettingPage loader", "static route table; no route execution"),
        (b"navigator.hid.requestDevice(", "WebHID chooser API call in the service", "callsite exists; chooser was not invoked"),
        (b"navigator.hid.getDevices()", "WebHID remembered-device enumeration call in reconnect method", "callsite exists; no HID enumeration performed"),
        (b"this.device.open()", "service opens the selected HIDDevice", "callsite exists; device was not opened"),
        (b"this.device.oninputreport=", "service installs an inputreport handler", "static handler; no reports received"),
        (b"this.device.sendReport(0,n)", "service sends report ID 0 through WebHID", "outbound path only; no report sent"),
        (b"localStorage.setItem(\"keyboardInfo\",JSON.stringify(s))", "open path persists keyboardInfo", "stored object contents are recorded separately"),
        (b"ProtocolCMD:{KB2_CMD:0,KB2_CMD_SYNC:1", "packet builder protocol command table", "enum labels do not prove device acceptance"),
        (b"CMDPack(e,t){const r=new Uint8Array(64)", "64-byte command packet builder", "static layout only; no hardware validation"),
        (b"SYNCPack(){const e=new Uint8Array(64)", "64-byte sync packet builder", "static layout only; no hardware validation"),
        (b"ComputeCheckSum(e){let t=53", "packet checksum helper", "static arithmetic only; protocol semantics unresolved"),
        (b"this.device.productName===\"Gaming Keyboard Pro\"", "request path contains product-name exclusions", "not a complete model compatibility map"),
        (b"const s={VID:7247,PID:61064,usagePage:65440,usage:1}", "open path persists a hard-coded keyboardInfo object", "reason and reconnect impact unresolved"),
    ],
    "ConnectDrivePage-ssQP7GIK.js": [
        (b"B=async()=>{try{await a.requestDevice()", "connect-button handler begins with chooser and open sequence", "handler is bound by template to onClick; it was not invoked"),
        (b"await a.writeData(i.SYNCPack())", "connect handler sends sync packet", "no physical report sent"),
        (b"await a.writeData(i.CMDPack(1,null))", "connect initialization requests protocol version", "label derives from packet enum; no response observed"),
        (b"await a.writeData(i.CMDPack(38,null))", "connect initialization issues command 38", "page log labels this as keyboard name; no response observed"),
        (b"await a.writeData(i.CMDPack(37,null))", "connect initialization issues command 37", "page log labels this precision/travel query; no response observed"),
        (b"await a.writeData(i.CMDPack(112,4))", "connect initialization issues command 112 with argument 4", "page log labels this configuration-ID query; no response observed"),
        (b"await a.writeData(i.CMDPack(118,null))", "connect initialization issues command 118", "page log labels this axis-list query; no response observed"),
        (b"await a.writeData(i.CMDPack(80,7))", "connect initialization issues command 80 with argument 7", "page log labels this report-rate query; no response observed"),
        (b"await a.writeData(i.CMDPack(33,null))", "connect initialization issues Windows-mode query command 33", "page log label only; no response observed"),
        (b"await a.writeData(i.CMDPack(34,null))", "connect initialization issues macOS-mode query command 34", "page log label only; no response observed"),
        (b"await a.writeData(i.CMDPack(52,2))", "connect initialization issues command 52 with argument 2", "page log labels this top-dead-zone switch status; no response observed"),
        (b"await a.writeData(i.DBPack(0,0,0,0))", "connect initialization emits a DB packet", "builder name/arguments only; no response observed"),
        (b"await a.writeData(i.CMDArrayPack(68,[255,255,255]))", "connect initialization emits command-array packet 68", "page log labels lighting offset; no response observed"),
        (b"await a.writeData(i.PRGBPack(0,v.value,!1,!1,!1,0,0,0,0))", "connect initialization emits a PRGB packet", "page log calls this a lighting-setting query; semantics unresolved"),
        (b"await a.writeData(i.LOGORGBPack(0,x.value,!1,!1,!1,0,0,0,0,0))", "connect initialization emits a logo-RGB packet", "page log calls this an ambient-light query; semantics unresolved"),
        (b"await a.writeData(i.DEFKEYPack(0,1))", "connect initialization emits three DEFKEY packets", "page log labels this HID-matrix acquisition; semantics unresolved"),
        (b"g.push({path:\"/device\"})", "connect handler navigates to /device after initialization", "static route transition"),
    ],
    "DeviceSettingPage-D_XFuI9e.js": [
        (b"await mt.requestDevice()", "device page has a separate chooser/open action", "callsite exists; no chooser invoked"),
        (b"await t.reConnect(),await t.startEventListen()", "mounted path reconnects and starts HID event listeners when app state is disconnected", "static conditional path; no reconnect executed"),
        (b"await t.writeData(re.LayoutDataPack(", "device page writes layout packets", "feature callers and per-model reachability not closed"),
    ],
}


def occurrences(data: bytes, needle: bytes):
    start = 0
    while True:
        offset = data.find(needle, start)
        if offset < 0:
            return
        yield offset
        start = offset + 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv-out", type=Path, default=ROOT / "docs" / "rk-drive2-connection-path-evidence-2026-10-20.csv")
    args = parser.parse_args()

    expected: dict[str, tuple[str, str]] = {}
    with ASSET_LEDGER.open("r", encoding="utf-8-sig", newline="") as stream:
        for row in csv.DictReader(stream):
            if row["route_host"] == "drive2.rkgaming.com":
                name = Path(row["local_path"].replace("\\", "/")).name
                expected[name] = (row["sha256"], row["local_path"])

    output = args.csv_out if args.csv_out.is_absolute() else ROOT / args.csv_out
    output.parent.mkdir(parents=True, exist_ok=True)
    fields = ["file", "sha256", "byte_offset", "line", "anchor", "static_evidence", "limit"]
    rows: list[dict[str, str | int]] = []
    for name, anchors in ANCHORS.items():
        if name not in expected:
            raise ValueError(f"No hash-pinned route ledger row for {name}")
        digest, relative_path = expected[name]
        path = ROOT / Path(relative_path.replace("\\", "/"))
        data = path.read_bytes()
        actual = hashlib.sha256(data).hexdigest()
        if actual != digest:
            raise ValueError(f"SHA-256 mismatch for {path}: expected {digest}, got {actual}")
        for needle, evidence, limit in anchors:
            offsets = list(occurrences(data, needle))
            if not offsets:
                raise ValueError(f"Anchor not found in hash-pinned {name}: {needle!r}")
            for offset in offsets:
                rows.append({
                    "file": relative_path,
                    "sha256": actual,
                    "byte_offset": offset,
                    "line": data.count(b"\n", 0, offset) + 1,
                    "anchor": needle.decode("ascii"),
                    "static_evidence": evidence,
                    "limit": limit,
                })

    with output.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {len(rows)} hash-verified static anchors to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
