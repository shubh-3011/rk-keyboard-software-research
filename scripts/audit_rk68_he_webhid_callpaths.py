#!/usr/bin/env python3
"""Static, hash-checked call-path evidence for the selector-listed RK68 HE Web app.

This reads only the already acquired same-host HTML/JS/CSS snapshot recorded in
docs/rk-product-driver-route-web-asset-ledger-2026-10-20.csv. It never imports,
evaluates, or launches vendor JavaScript and never accesses a HID device.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "docs" / "rk-product-driver-route-web-asset-ledger-2026-10-20.csv"
OUT = ROOT / "docs" / "rk68-he-static-webhid-callpath-evidence-2026-10-20.csv"
HOST = "rk.hubx.pro"


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_row(
    *,
    category: str,
    statement: str,
    filename: str,
    data: bytes,
    start: int,
    end: int,
    evidence_kind: str,
) -> dict[str, str]:
    left = max(0, start - 110)
    right = min(len(data), max(end, start + 1) + 210)
    return {
        "route_host": HOST,
        "category": category,
        "evidence_kind": evidence_kind,
        "statement": statement,
        "filename": filename,
        "sha256": digest(data),
        "byte_start": str(start),
        "byte_end": str(end),
        "source_excerpt_utf8": data[left:right].decode("utf-8", errors="replace").replace("\r", "\\r").replace("\n", "\\n"),
    }


def find_all(data: bytes, needle: bytes):
    pos = 0
    while True:
        pos = data.find(needle, pos)
        if pos < 0:
            return
        yield pos
        pos += max(1, len(needle))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=OUT)
    args = parser.parse_args()

    listed = [row for row in read_csv(LEDGER) if row.get("route_host") == HOST and row.get("sha256")]
    assets: dict[str, tuple[bytes, str]] = {}
    for row in listed:
        path = ROOT / row["local_path"]
        data = path.read_bytes()
        actual = digest(data)
        if actual != row["sha256"]:
            raise SystemExit(f"hash mismatch: {path} expected {row['sha256']} got {actual}")
        assets[path.name] = (data, actual)

    if "app-BqfTKFxh.js" not in assets or "index.html" not in assets:
        raise SystemExit("hash-pinned HTML entry or main JavaScript bundle is missing")

    rows: list[dict[str, str]] = []

    def add_exact(filename: str, category: str, statement: str, needle: str, evidence_kind: str = "direct-source-syntax") -> None:
        data = assets[filename][0]
        encoded = needle.encode("utf-8")
        locations = list(find_all(data, encoded))
        if not locations:
            raise SystemExit(f"expected static pattern missing from {filename}: {needle}")
        for pos in locations:
            rows.append(make_row(category=category, statement=statement, filename=filename, data=data, start=pos, end=pos + len(encoded), evidence_kind=evidence_kind))

    # Entry and page route inventory. Route chunk associations are static imports;
    # page component names remain descriptive metadata, not runtime reachability.
    html = assets["index.html"][0]
    rows.append(make_row(category="entry", statement="HTML shell loads the main application bundle", filename="index.html", data=html, start=html.find(b"app-BqfTKFxh.js"), end=html.find(b"app-BqfTKFxh.js") + len(b"app-BqfTKFxh.js"), evidence_kind="direct-source-syntax"))
    main = assets["app-BqfTKFxh.js"][0]
    route_text = main.decode("utf-8", errors="replace")
    route_starts = list(re.finditer(r'\{path:"([^"]+)",name:"([^"]*)",components:\{', route_text))
    for index, match in enumerate(route_starts):
        route = match.group(1)
        stop = route_starts[index + 1].start() if index + 1 < len(route_starts) else min(len(route_text), match.start() + 5000)
        body = route_text[match.start():stop]
        component = re.search(r'(?:mainContainer|SiglePage):\(\)=>y1\(\(\)=>import\("\./([^"]+\.js)"\)', body)
        chunk = component.group(1) if component else ""
        module_component = ""
        if chunk and chunk in assets:
            found = re.search(rb'__name:"([^"]+)"', assets[chunk][0])
            if found:
                module_component = found.group(1).decode("ascii", errors="replace")
        pos = len(route_text[:match.start()].encode("utf-8"))
        end = pos + len(match.group(0).encode("utf-8"))
        rows.append(make_row(category="ui-route", statement=f"Route {route!r} ({match.group(2)!r}) statically imports {chunk or 'no detected lazy main component'}{f' ({module_component})' if module_component else ''}", filename="app-BqfTKFxh.js", data=main, start=pos, end=end, evidence_kind="static-route-and-import"))

    # The setup screen's click handler uses an imported binding; the main bundle
    # export table resolves that binding to the new-device HID picker.
    setup = "chunk-D9wJ8Lfy.js"
    if setup not in assets:
        raise SystemExit("setup page chunk missing from the hash-pinned asset ledger")
    add_exact(setup, "ui-to-connect", "Setup page invokes the imported connect/new-device function on its connect action", "async on_new_device(){try{if(this.loading=!0,await w()===null)")
    add_exact(setup, "ui-to-connect", "Setup module imports its local binding w as export c from the main application bundle", "c as w")
    add_exact("app-BqfTKFxh.js", "ui-to-connect", "Main export table binds connect picker $6t as export c", "$6t as c")

    # WebHID picker, compatible-device gates, reattachment and hotplug state.
    add_exact("app-BqfTKFxh.js", "webhid-acquisition", "New-device picker refuses environments without navigator.hid and calls requestDevice with generated filters", "async function $6t(){if(!navigator.hid)")
    add_exact("app-BqfTKFxh.js", "webhid-acquisition", "New-device picker calls navigator.hid.requestDevice({filters:e})", "navigator.hid.requestDevice({filters:e})")
    add_exact("app-BqfTKFxh.js", "model-gate", "Filter list is built from the static i1 product table", "function k6t(){let e=[];for(let t=0;t<i1.length;t++)e.push({vendorId:i1[t].vendor_id,productId:i1[t].product_id});return e}")
    add_exact("app-BqfTKFxh.js", "model-gate", "Candidate match requires exact table vendorId and productId equality", "e[o].vendor_id===t.vendorId&&e[o].product_id===t.productId")
    add_exact("app-BqfTKFxh.js", "model-gate", "Report channel candidates must have compatible input/output/feature report collections", "async function S8(e,t)")
    add_exact("app-BqfTKFxh.js", "model-gate", "Output report ID is checked against the device descriptor", "async function z8(e,t)")
    add_exact("app-BqfTKFxh.js", "model-gate", "Input report ID is checked against the device descriptor", "async function k8(e,t)")
    add_exact("app-BqfTKFxh.js", "model-gate", "New-device parse applies VID/PID, channel, TX ID, RX ID, protocol/controller, and UUID steps in order", "async function H6t(e,t)")
    add_exact("app-BqfTKFxh.js", "model-gate", "V3 wired controller is instantiated only in the kb_by_v3_wired protocol branch and matched against the configured UUID", 'case"kb_by_v3_wired":{t.opened||await t.open();let i=new ll(e[o]);const s=await i.get_uuid()')
    add_exact("app-BqfTKFxh.js", "model-gate", "Existing permission path enumerates navigator.hid.getDevices and matches the saved current device", "async function Su(){if(!navigator.hid)")
    add_exact("app-BqfTKFxh.js", "device-lifecycle", "HID connect/disconnect listeners are registered and connection checks emit online status after a 300 ms delay", "function V6t(){navigator.hid.addEventListener(\"connect\"")
    add_exact("app-BqfTKFxh.js", "device-lifecycle", "Device store is named model_common_device and begins with online/offline/current-device state", 'Ga("model_common_device",{state:()=>({devices:[],online_devices:[],offline_devices:[],current_device:')
    add_exact("app-BqfTKFxh.js", "device-lifecycle", "Device store update_device enumerates authorized HID devices and classifies supported ones", "async update_device(){let e=await navigator.hid.getDevices()")

    # One representative UI -> service -> controller path can be followed
    # without executing code: the lighting route invokes a Pinia action, that
    # action delegates through the controller store, and the V3 implementation
    # reaches the browser HID report API.
    add_exact("chunk-DDGIK9S6.js", "ui-to-protocol", "Lighting page change handler calls the shared store's sync_light_mode action", "e.set_light(this.light_mode_config[this.light_mode_idx].light_mode,this.bright,this.speed,this.color,this.mix_color),await e.sync_light_mode()")
    add_exact("chunk-DDGIK9S6.js", "ui-to-protocol", "Lighting page imports the shared store binding r under its local alias he", "r as he")
    add_exact("app-BqfTKFxh.js", "ui-to-protocol", "Application export table binds the model_kb_by_v3_basic store Li as export r", "Li as r")
    add_exact("app-BqfTKFxh.js", "service-to-controller", "The model_kb_by_v3_basic store's sync_light_mode action delegates to the selected controller with this state", "async sync_light_mode(){try{return await(await Yt().controller).sync_light_mode(this)}catch{return!1}}")
    add_exact("app-BqfTKFxh.js", "service-to-controller", "The controller store getter resolves through its connect action", "getters:{async controller(){return await this.connect()}}")

    # Product profile catalog rows for the routed RK68 HE model.
    for product_label in (b'product_name_text:"RK68 HE"',):
        for pos in find_all(main, product_label):
            excerpt = main[pos:min(len(main), pos + 520)].decode("utf-8", errors="replace")
            match = re.search(r'vendor_id:(\d+),product_id:(\d+),report_id_tx:(\d+),report_id_rx:(\d+),report_id_io_rx:(\d+),send_payload_length:(\d+),type_protocol:"([^"]+)",type_device:"([^"]+)",type_channel:"([^"]+)",type_connection:"([^"]+)",uuid:([0-9a-fx]+)', excerpt)
            if not match:
                raise SystemExit("could not parse static RK68 HE profile tuple")
            statement = (
                f"RK68 HE profile tuple: VID/PID {match.group(1)}/{match.group(2)}, TX/RX/I/O report IDs "
                f"{match.group(3)}/{match.group(4)}/{match.group(5)}, payload {match.group(6)}, "
                f"protocol {match.group(7)}, device {match.group(8)}, channel {match.group(9)}, "
                f"connection {match.group(10)}, UUID {match.group(11)}"
            )
            rows.append(make_row(category="rk68-he-profile", statement=statement, filename="app-BqfTKFxh.js", data=main, start=pos, end=pos + len(product_label), evidence_kind="static-catalog-entry"))

    # Controller surface inventory and lower-level browser report boundary.
    add_exact("app-BqfTKFxh.js", "protocol-controller", "V3 controller class is aliased as ll and receives the descriptor entry", "let ll=Lt;")
    add_exact("app-BqfTKFxh.js", "protocol-controller", "V3 controller stores descriptor IDs and installs an input-report handler for the RX report", "this.report_id_tx=t.report_id_tx,this.report_id_rx=t.report_id_rx")
    add_exact("app-BqfTKFxh.js", "webhid-boundary", "Wired controller output calls browser HIDDevice.sendReport", "return this.device.sendReport(this.report_id_tx,new Uint8Array(t))")
    add_exact("app-BqfTKFxh.js", "webhid-boundary", "Input-report callback validates productId, vendorId and reportId before handling data", "n.productId!==this.product_id||n.vendorId!==this.vendor_id||l!==this.report_id_rx||o(s)")

    # Bound method declarations to the V3 class body. These are controller
    # surface evidence only; they do not prove UI reachability or model support.
    class_start = main.find(b"const Lt=class Lt{")
    alias = main.find(b"let ll=Lt;", class_start)
    if class_start < 0 or alias < 0:
        raise SystemExit("could not locate bounded V3 controller class")
    v3 = main[class_start:alias]
    rows.append(make_row(category="protocol-controller", statement="V3 class source span is bounded from its declaration through the ll alias; no whole-method inventory is inferred by the scanner", filename="app-BqfTKFxh.js", data=main, start=class_start, end=alias + len(b"let ll=Lt;"), evidence_kind="bounded-class-source-span"))
    for method_name in (
        "sync_light_mode",
        "sync_custom_light",
        "sync_rt",
        "sync_advanced_keys",
        "sync_polling_level",
        "_send_macro_to_device",
        "get_battery",
        "fetch_firmware_version",
    ):
        needle = f"async {method_name}(".encode("ascii")
        positions = list(find_all(v3, needle))
        if not positions:
            raise SystemExit(f"expected V3 method declaration missing: {method_name}")
        for offset in positions:
            start = class_start + offset
            rows.append(make_row(category="protocol-method", statement=f"V3 class declares {method_name}; this declaration alone does not establish UI reachability or RK68 HE support", filename="app-BqfTKFxh.js", data=main, start=start, end=start + len(needle), evidence_kind="bounded-class-method-declaration"))

    # For simple methods, capture a single method-local edge to sendReport.
    # This is a source-level call edge, not a claim about runtime success.
    for method_name in ("sync_light_mode", "sync_rt", "sync_polling_level"):
        signature = f"async {method_name}(".encode("ascii")
        offsets = list(find_all(v3, signature))
        if len(offsets) != 1:
            raise SystemExit(f"expected exactly one V3 method declaration for {method_name}")
        method_offset = offsets[0]
        next_method = v3.find(b"async ", method_offset + len(signature))
        if next_method < 0:
            next_method = len(v3)
        send = v3.find(b"await this.sendReport(this.payload)", method_offset, next_method)
        if send < 0:
            raise SystemExit(f"expected direct sendReport call inside V3 {method_name}")
        start = class_start + method_offset
        end = class_start + send + len(b"await this.sendReport(this.payload)")
        rows.append(make_row(category="protocol-operation", statement=f"V3 {method_name} method reaches sendReport within the same bounded method body", filename="app-BqfTKFxh.js", data=main, start=start, end=end, evidence_kind="bounded-method-call-edge"))

    fields = ["route_host", "category", "evidence_kind", "statement", "filename", "sha256", "byte_start", "byte_end", "source_excerpt_utf8"]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    print(f"verified {len(listed)} hash-pinned hubx assets; wrote {len(rows)} evidence rows to {args.output}")
    print(f"main bundle sha256: {assets['app-BqfTKFxh.js'][1]}")
    print(f"bounded V3 class bytes: {alias + len(b'let ll=Lt;') - class_start}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
