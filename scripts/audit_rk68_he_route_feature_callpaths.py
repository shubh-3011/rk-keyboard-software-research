#!/usr/bin/env python3
"""Emit route-scoped static call-path evidence for the RK68 HE selector app.

Reads only hash-pinned local source bytes from the existing route asset ledger.
It does not evaluate JavaScript or access WebHID.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "docs" / "rk-product-driver-route-web-asset-ledger-2026-10-20.csv"
DEFAULT_OUT = ROOT / "docs" / "rk68-he-route-feature-callpaths-2026-10-20.csv"
HOST = "rk.hubx.pro"


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def excerpt(data: bytes, start: int, end: int, *, limit: int = 2500) -> str:
    left = max(0, start - 100)
    right = min(len(data), max(end, start + 1) + 180)
    if right - left > limit:
        right = left + limit
    return data[left:right].decode("utf-8", errors="replace").replace("\r", "\\r").replace("\n", "\\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    listed = [r for r in read_csv(LEDGER) if r.get("route_host") == HOST and r.get("sha256")]
    assets: dict[str, tuple[bytes, str]] = {}
    for row in listed:
        path = ROOT / row["local_path"]
        data = path.read_bytes()
        actual = sha256(data)
        if actual != row["sha256"]:
            raise SystemExit(f"hash mismatch: {path} expected {row['sha256']} got {actual}")
        name = path.name
        if name in assets and assets[name][1] != actual:
            raise SystemExit(f"ambiguous duplicate asset basename in ledger: {name}")
        assets[name] = (data, actual)

    main_name = "app-BqfTKFxh.js"
    if main_name not in assets or "index.html" not in assets:
        raise SystemExit("entry HTML or main bundle missing from hash-pinned snapshot")
    main_data = assets[main_name][0]
    rows: list[dict[str, str]] = []

    def add(
        route: str,
        stage: str,
        status: str,
        filename: str,
        needle: str,
        statement: str,
        evidence_kind: str = "direct-static-source",
    ) -> None:
        if filename not in assets:
            raise SystemExit(f"expected source asset is missing: {filename}")
        data, digest = assets[filename]
        token = needle.encode("utf-8")
        positions: list[int] = []
        position = 0
        while True:
            position = data.find(token, position)
            if position < 0:
                break
            positions.append(position)
            position += max(1, len(token))
        if not positions:
            raise SystemExit(f"expected static pattern missing in {filename}: {needle}")
        for position in positions:
            end = position + len(token)
            rows.append({
                "route": route,
                "stage": stage,
                "edge_status": status,
                "evidence_kind": evidence_kind,
                "statement": statement,
                "filename": filename,
                "sha256": digest,
                "byte_start": str(position),
                "byte_end": str(end),
                "source_excerpt_utf8": excerpt(data, position, end),
            })

    def add_v3_segment(route: str, method: str, target: str, statement: str, stage: str = "controller-call-edge") -> None:
        class_start = main_data.find(b"const Lt=class Lt{")
        alias = main_data.find(b"let ll=Lt;", class_start)
        if class_start < 0 or alias < 0:
            raise SystemExit("could not locate bounded V3 controller class")
        body = main_data[class_start:alias]
        signature = f"async {method}(".encode("ascii")
        starts: list[int] = []
        position = 0
        while True:
            position = body.find(signature, position)
            if position < 0:
                break
            starts.append(position)
            position += len(signature)
        if len(starts) != 1:
            raise SystemExit(f"expected one bounded V3 method {method}, found {len(starts)}")
        start_in_body = starts[0]
        next_method = body.find(b"async ", start_in_body + len(signature))
        if next_method < 0:
            next_method = len(body)
        target_bytes = target.encode("ascii")
        target_start = body.find(target_bytes, start_in_body, next_method)
        if target_start < 0:
            raise SystemExit(f"expected target {target!r} inside V3 method {method}")
        start = class_start + start_in_body
        end = class_start + target_start + len(target_bytes)
        rows.append({
            "route": route,
            "stage": stage,
            "edge_status": "direct-source-edge",
            "evidence_kind": "bounded-v3-method-call-segment",
            "statement": statement,
            "filename": main_name,
            "sha256": assets[main_name][1],
            "byte_start": str(start),
            "byte_end": str(end),
            "source_excerpt_utf8": excerpt(main_data, start, end),
        })

    # Entry route declarations are included so every feature row is anchored
    # to the same static router configuration, not to route-name string hits.
    text_main = main_data.decode("utf-8", errors="replace")
    route_matches = list(re.finditer(r'\{path:"([^"]+)",name:"([^"]*)",components:\{', text_main))
    for index, match in enumerate(route_matches):
        end_route = route_matches[index + 1].start() if index + 1 < len(route_matches) else min(len(text_main), match.start() + 5000)
        body = text_main[match.start():end_route]
        component = re.search(r'(?:mainContainer|SiglePage):\(\)=>y1\(\(\)=>import\("\./([^\"]+\.js)"\)', body)
        chunk = component.group(1) if component else ""
        byte_start = len(text_main[:match.start()].encode("utf-8"))
        byte_end = byte_start + len(match.group(0).encode("utf-8"))
        rows.append({
            "route": match.group(1),
            "stage": "router-entry",
            "edge_status": "direct-static-import" if chunk else "route-only",
            "evidence_kind": "static-router-config",
            "statement": f"Router declares {match.group(1)!r} and imports {chunk or 'no detected main component'}",
            "filename": main_name,
            "sha256": assets[main_name][1],
            "byte_start": str(byte_start),
            "byte_end": str(byte_end),
            "source_excerpt_utf8": excerpt(main_data, byte_start, byte_end),
        })

    # /keyboard: model/protocol switch -> V3 editor -> key-store action.
    add("/keyboard", "model-gate", "direct-source-edge", "chunk-CsbVz4lP.js", 't.type_protocol==="kb_by_v3_wired"?(i(),f(Xe,{key:0}))', "Keyboard component selects the V3 wrapper for kb_by_v3_wired")
    add("/keyboard", "ui-handler", "direct-source-edge", "chunk-CsbVz4lP.js", "async on_drag_end(o,t){const r=v(s(\"sync_failed\"));let e=JSON.parse(o.dataTransfer.getData(\"data\")),a={data:e.data,type:e.type,name:e.name};const n=T();if(n.set_key(this.current_layer,Number(this.keys[t].pos),a),!await n.sync_keys(this.current_layer,[Number(this.keys[t].pos)]))", "Keyboard drop handler stores the key assignment and awaits the shared key-store sync action")
    add("/keyboard", "module-binding", "direct-source-edge", "chunk-CsbVz4lP.js", 'import{m as T}from"./chunk-Dh8PYYis.js"', "Keyboard V3 editor imports the shared V3 key store as T")
    add("/keyboard", "store-definition", "direct-source-edge", "chunk-Dh8PYYis.js", 'const g=_("model_kb_by_v3_keys"', "Shared V3 key store is model_kb_by_v3_keys")
    add("/keyboard", "store-to-controller", "direct-source-edge", "chunk-Dh8PYYis.js", "async sync_keys(t=0,e=[]){try{return await(await l().controller).sync_keys(this,e,t)}catch{return!1}}", "V3 key-store sync_keys delegates to the selected controller")
    add("/keyboard", "controller-store-binding", "direct-source-edge", "chunk-Dh8PYYis.js", 'u as l,Q as k', "V3 key store imports main-bundle export u as l for its controller binding")
    add("/keyboard", "controller-store-binding", "direct-source-edge", main_name, "Yt as u", "Main bundle export u is the controller store Yt")
    add_v3_segment("/keyboard", "sync_keys", "await this._sync_keys(t,s[n],o)", "V3 sync_keys checks for macros then dispatches key packets through _sync_keys")
    add_v3_segment("/keyboard", "_sync_keys", "await this.sendReport(this.payload)", "V3 _sync_keys encodes key/macro assignment data and sends it through sendReport")

    # /macro edits persistent macro definitions; hardware upload occurs when a
    # macro is assigned to a key and the keyboard route syncs that assignment.
    add("/macro", "ui-handler", "direct-source-edge", "chunk-DhL8p3_z.js", 'on_macro_save(){if(this.current_macro_selected===null){re.error(h("not_select_macro"));return}this.macro_config[this.current_macro_selected].macro_data=JSON.parse(JSON.stringify(this.data_macro)),this.macro_config[this.current_macro_selected].macro_type={type:this.macro_current_type,count:this.macro_current_count},this.macro_config[this.current_macro_selected].type="macro",re.success(h("save_success"));const e=ke();e.macro_config=this.macro_config}', "Macro editor save writes its recorded data into the macro-config store")
    add("/macro", "module-binding", "direct-source-edge", "chunk-DhL8p3_z.js", 'import{k as qo}from"./chunk-BsM38hVX.js"', "Macro page imports UI helpers; its macro state comes from the separate macro store")
    add("/macro", "store-binding", "direct-source-edge", "chunk-DhL8p3_z.js", 'import{m as ke}from"./chunk-Cfxa4RfU.js"', "Macro page imports model_macro store as ke")
    add("/macro", "store-definition", "direct-source-edge", "chunk-Cfxa4RfU.js", 'const r=o("model_macro",{state:()=>({macro_config:[]}),persist:!0})', "model_macro persists macro_config; this store itself has no controller action")
    add("/keyboard", "macro-menu-binding", "direct-source-edge", "chunk-CsbVz4lP.js", 'load_macro_config(){const o=Z();this.profile_key_macro=o.macro_config}', "Keyboard V3 macro menu reads macro_config for assignable macros")
    add("/keyboard", "macro-menu-store-binding", "direct-source-edge", "chunk-CsbVz4lP.js", 'import{m as Z}from"./chunk-Cfxa4RfU.js"', "Keyboard V3 macro menu imports the persisted model_macro store")
    add_v3_segment("/keyboard", "sync_keys", "this._check_macro_existed(t,i,o)&&await this._sync_macro(t)", "V3 key sync uploads macro data before key assignment when the changed position is macro-typed")
    add_v3_segment("/keyboard", "_sync_macro", "return await this._send_macro_to_device(a)", "V3 macro sync serializes macro definitions and delegates transfer to _send_macro_to_device")
    add_v3_segment("/keyboard", "_send_macro_to_device", "await this.sendReport(this.payload)", "V3 macro transfer sends each encoded chunk through sendReport")

    # /advanced: saved DKS/MT/TGL/etc structures go through the V3 key store.
    add("/advanced", "ui-handler", "direct-source-edge", "chunk-C1buM9JT.js", "async on_save(o){if(console.log(o),o.type===v.DKS||o.type===v.TGL||o.type===v.MT||o.type===v.MPT||o.type===v.END)", "Advanced-key save handler branches on DKS/TGL/MT/MPT/END and updates the key store")
    add("/advanced", "ui-to-store", "direct-source-edge", "chunk-C1buM9JT.js", "await t.sync_advanced_keys(this.layer,o.pos)", "Advanced-key save invokes sync_advanced_keys for the edited key")
    add("/advanced", "module-binding", "direct-source-edge", "chunk-C1buM9JT.js", 'import{m as H}from"./chunk-Dh8PYYis.js"', "Advanced page imports the V3 key store as H")
    add("/advanced", "store-to-controller", "direct-source-edge", "chunk-Dh8PYYis.js", "async sync_advanced_keys(t=0,e=null,r=null){try{return await(await l().controller).sync_advanced_keys(this,t,e,r)}catch{return!1}}", "V3 key-store advanced-key action delegates to the selected controller")
    add_v3_segment("/advanced", "sync_advanced_keys", "await this._sync_advanced_keys_one(t,a,o,i)", "V3 controller dispatches a single-key advanced configuration to _sync_advanced_keys_one")
    add_v3_segment("/advanced", "_sync_advanced_keys_one", "return await this._sync_advanced_keys_dks(t,a,Number(o),JSON.parse(JSON.stringify(t.keys[s].advanced_key)))", "V3 advanced dispatcher selects the DKS encoder when advanced_key.type is DKS")
    add_v3_segment("/advanced", "_sync_advanced_keys_dks", "await this.sendReport(this.payload)", "V3 DKS encoder packs layer/key/threshold/key-set fields then calls sendReport")

    # /performance: applied key/per-key state goes through the V3 key store.
    add("/performance", "ui-handler", "direct-source-edge", "chunk-CP73SzDP.js", "async on_invoke_single_data(){", "Performance page applies selected per-key settings in on_invoke_single_data")
    add("/performance", "ui-to-store", "direct-source-edge", "chunk-CP73SzDP.js", "await i.sync_key_type(r),await i.sync_distance([0],r),await i.sync_rt([0],r),await i.sync_safe_area([0],r)", "Per-key apply invokes key-type, distance, rapid-trigger, and safe-area store actions")
    add("/performance", "ui-handler", "direct-source-edge", "chunk-CP73SzDP.js", 'async on_invoke_global_data(a){', "Performance page has a separate global-setting apply handler")
    add("/performance", "ui-to-store", "direct-source-edge", "chunk-CP73SzDP.js", 'a==="key_rt"&&await e.sync_rt([0],i)', "Global RT apply dispatches sync_rt for the global-mode key set")
    add("/performance", "module-binding", "direct-source-edge", "chunk-CP73SzDP.js", 'import{m as b}from"./chunk-Dh8PYYis.js"', "Performance page imports the V3 key store as b")
    add("/performance", "store-to-controller", "direct-source-edge", "chunk-Dh8PYYis.js", "async sync_rt(t=[0],e){try{return await(await l().controller).sync_rt(this,t,e)}catch{return!1}}", "V3 key-store sync_rt delegates to the selected controller")
    add_v3_segment("/performance", "sync_rt", "await this.sendReport(this.payload)", "V3 rapid-trigger sync packs per-key RT state into reports and calls sendReport")

    # /features: the router page dispatches by device type and protocol before
    # exposing the V3 keyboard feature panel.
    add("/features", "model-gate", "direct-source-edge", "chunk-3hJ9KbLQ.js", 'l.type_protocol==="kb_by_v3_wired"?(A(),ut(Yo,{key:0}))', "KBFeature selects the V3 feature panel for kb_by_v3_wired")
    add("/features", "ui-handler", "direct-source-edge", "chunk-3hJ9KbLQ.js", "async on_report_rate_change(){this.to_model();let e=qe();e.polling_level=this.polling_level,await e.sync_polling_level()&&await F.sync_to_profile()}", "V3 feature report-rate handler updates the shared store and awaits sync_polling_level")
    add("/features", "store-to-controller", "direct-source-edge", main_name, "async sync_polling_level(){try{return await(await Yt().controller).sync_polling_level(this)}catch{return!1}}", "model_kb_by_v3_basic sync_polling_level delegates to the selected controller")
    add_v3_segment("/features", "sync_polling_level", "await this.sendReport(this.payload)", "V3 polling-level operation calls sendReport with its packed payload")

    # /rhythm invokes an API surface whose implementation is not present in
    # this selector snapshot; preserve it as unresolved rather than inferring.
    add("/rhythm", "unresolved-api-call", "open-static-reference", "chunk-BAldE2tb.js", "await t.changeCurrentRhythm(t.closeEffect,!1,c)", "Rhythm UI calls changeCurrentRhythm, but no implementation is in the acquired JavaScript asset set", "unresolved-property-call")
    add("/rhythm", "unresolved-api-call", "open-static-reference", "chunk-BAldE2tb.js", '(V=t.messageSender)==null?void 0:V.sendChangeMessage(c,m)', "Rhythm parameter updates call messageSender.sendChangeMessage; receiver implementation remains unresolved", "unresolved-property-call")
    add("/rhythm", "store-definition", "direct-source-edge", "chunk-b1jE9zRQ.js", 'c("model_kb_by_v3_rhythm",()=>({isSupport:r(!1),isRunning:r(!1)}))', "Rhythm helper declares only isSupport/isRunning in this snapshot; it does not define the UI-called change/message methods")

    # /custom_keys_layout edits an in-memory layout list and exports JSON text.
    add("/custom_keys_layout", "ui-handler", "direct-source-edge", "chunk-2Gyz-vL_.js", "on_drag_stop(t,e,i){let s=Number(e)-Number(this.keys_local[t].x),l=Number(i)-Number(this.keys_local[t].y)", "Custom layout drag handler mutates keys_local coordinates")
    add("/custom_keys_layout", "ui-handler", "direct-source-edge", "chunk-2Gyz-vL_.js", "on_resize_stop(t,e,i,s,l){this.keys_local[t].x=e,this.keys_local[t].y=i,this.keys_local[t].width=s,this.keys_local[t].height=l}", "Custom layout resize handler mutates only keys_local geometry")
    add("/custom_keys_layout", "local-export", "direct-source-edge", "chunk-2Gyz-vL_.js", "export_layout(){console.log(JSON.stringify(this.keys_local))}", "Custom layout export serializes the in-memory geometry to console text")

    # /settings and /devices routes use the same picker/controller and common
    # authorized-device store paths already present in the main bundle.
    add("/settings", "ui-handler", "direct-source-edge", "chunk-oIAA2p6Q.js", 'async on_reset_factory(){this.factory_reseting=!0,this.percentage=0,setTimeout(async()=>{this.$router.push("/");let e=await P().connect();e!==null&&await e.reset_factory()},2e3)', "Settings confirmation schedules a controller connect then reset_factory")
    add("/settings", "controller-store-binding", "direct-source-edge", "chunk-oIAA2p6Q.js", 'u as P,d as R,_ as z}from"./app-BqfTKFxh.js"', "Settings imports main export u as controller-store binding P")
    add("/settings", "controller-store-binding", "direct-source-edge", main_name, "Yt as u", "Main bundle export u is the controller store Yt")
    add_v3_segment("/settings", "reset_factory", "await this.sendReport(this.payload)", "V3 reset_factory operation emits its protocol payload via sendReport")
    add("/devices", "ui-handler", "direct-source-edge", "chunk-BrDqzObC.js", 'async on_device_add(){try{if(this.device_refresh_dialog=!0,await Z()===null)', "Device add action invokes the imported new-device picker")
    add("/devices", "picker-binding", "direct-source-edge", "chunk-BrDqzObC.js", 'L as N,c as Z,M as j,t as d', "Devices page imports main export c under the picker alias Z")
    add("/devices", "picker-binding", "direct-source-edge", main_name, "$6t as c", "Main bundle export c is new-device picker $6t")
    add("/devices", "ui-handler", "direct-source-edge", "chunk-BrDqzObC.js", "async refresh_device(){const e=N();try{let s=y();await s.update_device(),this.devices=s.online_devices", "Device refresh invokes the common-device store's update_device")
    add("/devices", "selection-navigation", "direct-source-edge", "chunk-BrDqzObC.js", 'async on_device_select(e){let s=y();s.current_device=s.online_devices[e],this.$router.push({path:"/keyboard",params:{}})', "Selecting an online device stores current_device and navigates to /keyboard")
    add("/devices", "common-device-store", "direct-source-edge", main_name, 'J2=Ga("model_common_device"', "Main bundle declares the model_common_device store")
    add("/devices", "common-device-store", "direct-source-edge", main_name, "async update_device(){let e=await navigator.hid.getDevices()", "Common-device update_device enumerates already authorized HID devices")

    for row in rows:
        data, digest = assets[row["filename"]]
        start = int(row["byte_start"])
        end = int(row["byte_end"])
        if row["sha256"] != digest or not (0 <= start < end <= len(data)):
            raise SystemExit(f"invalid generated evidence range/hash: {row['filename']}:{start}-{end}")
        if row["source_excerpt_utf8"] != excerpt(data, start, end):
            raise SystemExit(f"generated excerpt does not match source: {row['filename']}:{start}-{end}")

    fields = ["route", "stage", "edge_status", "evidence_kind", "statement", "filename", "sha256", "byte_start", "byte_end", "source_excerpt_utf8"]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    print(f"verified {len(listed)} hash-pinned hubx assets; wrote {len(rows)} route evidence rows to {args.output}")
    print(f"main bundle sha256: {assets[main_name][1]}")
    print(f"routes represented: {len({row['route'] for row in rows})}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
