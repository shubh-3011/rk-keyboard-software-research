#!/usr/bin/env python3
"""Audit pinned F99 Windows UI IPC and HID path evidence without execution.

The scanner treats JavaScript as bytes. It verifies the saved ASAR and main
bundle hashes, checks a generated hash manifest for the adjacent renderer
snapshot, finds literal renderer IPC calls, and records selected cross-layer
anchors. It never imports or evaluates target code and never accesses HID.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SELECTED = ROOT.parent / ".research" / "F99_3.2.2_static" / "selected"
ASAR = SELECTED / "resources" / "app.asar"
BACKGROUND = SELECTED / "background.js"
RENDERER = SELECTED / "resources" / "app.asar.unpacked"
RENDERER_JS = RENDERER / "js"
HASH_MANIFEST = ROOT / "docs" / "rk-f99-windows-renderer-js-hashes-2026-10-20.csv"
IPC_LEDGER = ROOT / "docs" / "rk-f99-windows-renderer-ipc-ledger-2026-10-20.csv"
PATH_LEDGER = ROOT / "docs" / "rk-f99-windows-ui-to-hid-path-ledger-2026-10-20.csv"

PINNED_SHA256 = {
    "asar": "38ebbf1416050d9ab36eee4910ec86130a0919b69334ec3751378f7f00ff2bdf",
    "background.js": "8db60b45ce93fc20f68950ebb97db0640d6384c3808b06e43c332d8ef4183277",
    "index.html": "b688946c0d06962a2bca85e63d6cb99767f52a9bab789f016b45e80c18aa4a3a",
    "preload.js": "2437e971df0d1a74bca59e3034405768c19a72de84aacd3c333408e48acc303c",
    "app.7057a5da.js": "b1a8ccb44b307a48eb10553d74107675fe2affb4370b3b940ea818e8d5acfacb",
    "8224.10899a1c.js": "cc82f6dadf8a639c2b38c3e9f15d76ca2fe4094f40e763d361f569907fab4408",
}

MODULE_607 = (1_487_507, 2_835_090)
REA_EVIDENCE_ID = "ev_83a56e1c6593964124f97cc1be87f0973e9d8370851c2cd5d02368b1fe6bb2d9"
REA_MI_HID_IMPORT_EDGE = "jag_edge_039776a41a038e64ef992cd15c65415914bfdaa532e3ecd2e180f66fa55239b8"

IPC_RE = re.compile(
    rb"ipcRenderer\.(send|invoke|on|once|sendSync|removeListener|removeAllListeners)"
    rb"\s*\(\s*([\"'])(.{1,160}?)\2"
)
MAIN_IPC_RE = re.compile(rb"ipcMain\.(on|handle)\s*\(\s*([\"'])(.{1,160}?)\2")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_pinned(path: Path, expected: str, label: str) -> bytes:
    data = path.read_bytes()
    actual = sha256(data)
    if actual != expected:
        raise ValueError(f"{label} SHA-256 mismatch: {actual} != {expected}")
    return data


def csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def verify_renderer_manifest() -> dict[str, tuple[int, str]]:
    expected = {
        row["relative_path"]: (int(row["bytes"]), row["sha256"])
        for row in csv_rows(HASH_MANIFEST)
    }
    actual_paths = {
        path.relative_to(RENDERER_JS).as_posix()
        for path in RENDERER_JS.rglob("*.js")
        if path.is_file()
    }
    if expected.keys() != actual_paths:
        missing = sorted(actual_paths - expected.keys())
        stale = sorted(expected.keys() - actual_paths)
        raise ValueError(f"renderer manifest path mismatch; unpinned={missing[:8]}, absent={stale[:8]}")
    for relative, (size, digest) in expected.items():
        path = RENDERER_JS / Path(relative)
        data = path.read_bytes()
        if len(data) != size or sha256(data) != digest:
            raise ValueError(f"renderer manifest mismatch: {relative}")
    return expected


def decode_ascii(data: bytes) -> str:
    return data.decode("utf-8", errors="backslashreplace")


def excerpt(source: bytes, offset: int, width: int = 110) -> str:
    start = max(0, offset - width // 2)
    end = min(len(source), offset + width // 2)
    return decode_ascii(source[start:end]).replace("\r", "\\r").replace("\n", "\\n")


def add_anchor(rows: list[dict[str, str]], source_name: str, source: bytes, digest: str,
               needle: bytes, stage: str, claim: str, *, occurrence: int = 0,
               module_id: str = "", status: str = "proven-static") -> None:
    positions: list[int] = []
    cursor = 0
    while True:
        cursor = source.find(needle, cursor)
        if cursor < 0:
            break
        positions.append(cursor)
        cursor += max(1, len(needle))
    if occurrence >= len(positions):
        raise ValueError(f"anchor not found: {source_name}: {needle!r} occurrence {occurrence}")
    offset = positions[occurrence]
    rows.append({
        "stage": stage,
        "source": source_name,
        "source_sha256": digest,
        "module_id": module_id,
        "byte_offset": str(offset),
        "byte_length": str(len(needle)),
        "anchor_hex": needle.hex(),
        "anchor_ascii": decode_ascii(needle),
        "static_claim": claim,
        "evidence_status": status,
        "context": excerpt(source, offset),
    })


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = list(rows[0]) if rows else []
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stdout-only", action="store_true", help="print summary without rewriting ledgers")
    args = parser.parse_args()

    asar = read_pinned(ASAR, PINNED_SHA256["asar"], "app.asar")
    background = read_pinned(BACKGROUND, PINNED_SHA256["background.js"], "background.js")
    index_html = read_pinned(RENDERER / "index.html", PINNED_SHA256["index.html"], "renderer index.html")
    preload = read_pinned(RENDERER / "preload.js", PINNED_SHA256["preload.js"], "renderer preload.js")
    manifest = verify_renderer_manifest()

    for name in ("app.7057a5da.js", "8224.10899a1c.js"):
        expected = PINNED_SHA256[name]
        if manifest.get(name, (0, ""))[1] != expected:
            raise ValueError(f"renderer manifest does not pin {name}")

    main_channels: dict[str, list[tuple[str, int]]] = {}
    main_rows = []
    for match in MAIN_IPC_RE.finditer(background):
        method = match.group(1).decode("ascii")
        channel = decode_ascii(match.group(3))
        main_channels.setdefault(channel, []).append((method, match.start()))
        main_rows.append((channel, method, match.start()))

    ipc_rows: list[dict[str, str]] = []
    ipc_count = 0
    ipc_channels: set[str] = set()
    for relative, (_, digest) in sorted(manifest.items()):
        source = (RENDERER_JS / Path(relative)).read_bytes()
        for match in IPC_RE.finditer(source):
            ipc_count += 1
            method = match.group(1).decode("ascii")
            channel = decode_ascii(match.group(3))
            ipc_channels.add(channel)
            handlers = main_channels.get(channel, [])
            ipc_rows.append({
                "renderer_source": f"resources/app.asar.unpacked/js/{relative}",
                "renderer_sha256": digest,
                "renderer_byte_offset": str(match.start()),
                "ipc_method": method,
                "channel": channel,
                "main_handler_matches": ";".join(f"ipcMain.{m}@{o}" for m, o in handlers),
                "match_status": "literal-match" if handlers else "no-literal-main-handler-found",
            })
    ipc_rows.sort(key=lambda row: (row["renderer_source"], int(row["renderer_byte_offset"])))

    path_rows: list[dict[str, str]] = []
    bg_name = "background.js"
    bg_hash = PINNED_SHA256[bg_name]
    app_path = "resources/app.asar.unpacked/js/app.7057a5da.js"
    app = (RENDERER_JS / "app.7057a5da.js").read_bytes()
    app_hash = sha256(app)
    fw_path = "resources/app.asar.unpacked/js/8224.10899a1c.js"
    fw_ui = (RENDERER_JS / "8224.10899a1c.js").read_bytes()
    fw_hash = sha256(fw_ui)

    anchors = [
        ("index.html", index_html, sha256(index_html), b'src="./js/app.7057a5da.js"', "renderer-entry-script", "Saved renderer entry page loads the hash-named Vue bundle; this sidecar file is not an indexed member of the pinned ASAR.", 0, ""),
        ("preload.js", preload, sha256(preload), b"ipcRenderer.on('notes2'", "renderer-preload-scope", "Saved preload only registers a notes2 logging listener in the inspected source; no contextBridge API is exposed here.", 0, ""),
        (bg_name, background, bg_hash, b'function(e,t){e.exports=require("mi-hid")', "hid-module-wrapper", "Webpack factory 88 wraps the mi-hid package import.", 0, "88"),
        (app_path, app, app_hash, b"ipcRenderer.send(\"toUpdateFrimware\"", "renderer-ota-action", "Firmware confirmation component sends the device ID and selected firmware install name to the main process.", 0, ""),
        (fw_path, fw_ui, fw_hash, b"ipcRenderer.send(\"fwUpdateCheck\"", "renderer-firmware-query", "Device settings component requests a firmware version check for the selected device.", 0, ""),
        (fw_path, fw_ui, fw_hash, b"ipcRenderer.send(\"radioSelect\"", "renderer-dpi-setting", "Device settings component sends the selected device ID and DPI value.", 0, ""),
        (fw_path, fw_ui, fw_hash, b"ipcRenderer.on(\"sendFirmwareQueryData\"", "renderer-firmware-query-reply", "Renderer receives version-query results, saves them in Vuex, and opens the update dialog.", 0, ""),
        (fw_path, fw_ui, fw_hash, b"ipcRenderer.on(\"sendFwProgress\"", "renderer-ota-progress-reply", "Renderer receives OTA progress and updates the selected device progress display.", 0, ""),
        (bg_name, background, bg_hash, b'ipcMain.on("fwUpdateCheck"', "main-firmware-query-ipc", "Main IPC handler delegates to controller.checkDeviceVersion(deviceID).", 0, "607"),
        (bg_name, background, bg_hash, b'ipcMain.on("radioSelect"', "main-dpi-setting-ipc", "Main IPC handler delegates the selected device ID and DPI value to controller.setDPI.", 0, "607"),
        (bg_name, background, bg_hash, b"setDPI(e,t){pn.setDpi(e,t)}", "controller-dpi-dispatch", "Controller forwards the selected DPI to the HID manager.", 0, "607"),
        (bg_name, background, bg_hash, b"setDpi(e,t){for(const n of this.hidDevices)", "hid-manager-dpi-device-gate", "HID manager routes the DPI update only to a connected, non-free instance matching the device number.", 0, "607"),
        (bg_name, background, bg_hash, b"noticeHid_SetDpi(e){if(0==this.canNoticeHid()", "hid-dpi-report", "Device-series handler gates on report eligibility and firmware-update state before framing the DPI command.", 0, "607"),
        (bg_name, background, bg_hash, b"App_Set_Dpi:6", "hid-dpi-command-id", "Static command table assigns numeric command 6 to App_Set_Dpi.", 0, "607"),
        (bg_name, background, bg_hash, b"noticeHid_HaveData(fe.App_Set_Dpi", "hid-dpi-command-framing", "DPI command and two-byte value enter the shared HID report framer.", 0, "607"),
        (bg_name, background, bg_hash, b"checkDeviceVersion(e){let t=this.devices.get(e)", "controller-firmware-query", "Controller looks up the device record and queries a vendor version endpoint when firmwareName exists.", 0, "607"),
        (bg_name, background, bg_hash, b'url:"http://mic.mimouse.net/dfs/hardware/judge/latest/version?type=mouse&system=mac&deviceType="', "controller-version-endpoint", "Static URL is mouse-specific and includes a macOS system query string in this Windows bundle.", 0, "607"),
        (bg_name, background, bg_hash, b'this.emit("onCallCheckVersion"', "controller-version-result-event", "Controller emits the result of the vendor version query to the main-process event bridge.", 0, "607"),
        (bg_name, background, bg_hash, b'$a.on("onCallCheckVersion"', "main-version-result-bridge", "Main process converts controller result arguments into a firmware-query result object for the renderer.", 0, "607"),
        (bg_name, background, bg_hash, b'webContents.send("sendFirmwareQueryData"', "main-version-result-to-renderer", "Main process forwards the version result to the renderer event consumed by the update dialog.", 0, "607"),
        (bg_name, background, bg_hash, b'ipcMain.on("toUpdateFrimware"', "main-ota-ipc", "Main IPC handler delegates the requested device ID and install name to controller.downloadFrimware.", 0, "607"),
        (bg_name, background, bg_hash, b"downloadFrimware(e,t){if(0!=this.asrMode)", "controller-ota-download", "Controller gates update while ASR is active or another update is underway, downloads a binary blob, then calls the HID manager OTA dispatcher.", 0, "607"),
        (bg_name, background, bg_hash, b"pn.startFwOta(e,0,n,n.length,null,0)", "controller-to-hid-ota", "Downloaded device firmware blob is passed to the HID manager with the selected device number; no runtime call is claimed.", 0, "607"),
        (bg_name, background, bg_hash, b"startFwOta(e,t,n,a,i,o){for(const r of this.hidDevices)", "hid-manager-device-gate", "OTA dispatch searches for a connected, non-free HID instance whose device number matches the request.", 0, "607"),
        (bg_name, background, bg_hash, b"n.usage<1e4||n.usagePage<1e4", "hid-enumeration-usage-gate", "Enumerator filters HID candidates by usage and usage-page thresholds before PID/VID whitelist lookup.", 0, "607"),
        (bg_name, background, bg_hash, b"if(t.vid==n.vendorId&&t.pid==n.productId){a=t;break}", "hid-enumeration-pid-vid-gate", "Enumerator requires an exact vendor/product match in the bundled allowlist before opening a candidate.", 0, "607"),
        (bg_name, background, bg_hash, b'"development"===At.a.env.NODE_ENV?"mi-hid":Dt.a.join', "hid-module-path-selection", "Static path selector uses the package name in development and the packaged resources/node/hid/mi-hid.node path otherwise.", 0, "607"),
        (bg_name, background, bg_hash, b"new ft.a.HID(n.path)", "hid-open", "Allowed candidate path is opened through the mi-hid wrapper in the main process.", 0, "607"),
        (bg_name, background, bg_hash, b"workerData:{hidPath:e.deviceId,hidName:Ut,sharedBuffer:n}", "hid-worker-data", "Separate worker receives the HID path, selected HID module name, and shared stop flag.", 0, "607"),
        (bg_name, background, bg_hash, b"oneOpenDevice = new HID.HID(workerData.hidPath)", "hid-worker-open-read", "Embedded worker source opens the path and uses readTimeout; this worker body has no write call.", 0, "607"),
        (bg_name, background, bg_hash, b"noticeHid_HaveData(e,t,n,a){if(this.hidDevice)", "hid-report-framing", "Controller frames command/data bytes into a report and enqueues it when a HID object exists.", 0, "607"),
        (bg_name, background, bg_hash, b"this.sendDataQueue.push(r)", "hid-report-queue", "Framed HID report enters the send queue.", 0, "607"),
        (bg_name, background, bg_hash, b"this.hidDevice.write(e)", "hid-write-call", "Main-process HID controller writes queued report bytes through the native HID object.", 0, "607"),
        (bg_name, background, bg_hash, b'$a.on("onCallFwProgressShow"', "main-ota-progress-bridge", "Main process subscribes to controller OTA progress events.", 0, "607"),
        (bg_name, background, bg_hash, b'webContents.send("sendFwProgress"', "main-ota-progress-to-renderer", "Main process forwards OTA progress to the renderer event handler.", 0, "607"),
        (bg_name, background, bg_hash, b"noticeHid_OtaOpen(){", "hid-ota-open-command", "OTA implementation builds an OTA-open payload and routes it through the shared HID report framer.", 0, "607"),
        (bg_name, background, bg_hash, b"noticeHid_OtaFwData(e,t,n){", "hid-ota-data-command", "OTA implementation encodes a block index and firmware data before passing it through the HID report framer.", 0, "607"),
        (bg_name, background, bg_hash, b"ipcMain.on(\"changeGeneralSettings\"", "main-app-preference-ipc", "General settings are persisted as app preferences (language, voice, typing and toolbar values); this handler does not call the HID manager.", 0, "607"),
        (bg_name, background, bg_hash, b"noticeHid_SetReport(e){}", "hid-report-set-noop-base", "Base series implementation of report selection is empty; another derived series has a concrete override elsewhere in the same factory.", 0, "607"),
    ]
    for source_name, source, digest, needle, stage, claim, occurrence, module_id in anchors:
        add_anchor(path_rows, source_name, source, digest, needle, stage, claim,
                   occurrence=occurrence, module_id=module_id)

    # Trace the timer and bridge which drive device-list updates to the renderer.
    add_anchor(path_rows, bg_name, background, bg_hash, b"this.timer=setInterval(()=>{this.onDeviceList()},2e3)",
               "controller-device-list-poll", "Controller emits its current device list on a two-second timer after init.", module_id="607")
    add_anchor(path_rows, bg_name, background, bg_hash, b'webContents.send("echo-deviceList",t)',
               "main-device-list-to-renderer", "Main process forwards controller device-list events to the renderer.", module_id="607")
    add_anchor(path_rows, bg_name, background, bg_hash, b"setTimeout(()=>{$a.init()},2e3)",
               "main-controller-start", "Main process schedules controller initialization after two seconds.", module_id="607")
    add_anchor(path_rows, bg_name, background, bg_hash, b"this.deviceManager=pn,this.deviceManager.start()",
               "controller-starts-hid-manager", "Controller init starts the shared HID manager.", module_id="607")
    add_anchor(path_rows, bg_name, background, bg_hash, b"start(){this.detectHidDevice()}",
               "hid-manager-start-method", "HID manager start method begins device detection.", module_id="607")
    add_anchor(path_rows, bg_name, background, bg_hash, b"e.detectDeviceTimer=setInterval(()=>{e.hidDeviceProcess()},2e3)",
               "hid-device-discovery-timer", "HID manager schedules device enumeration every two seconds.", module_id="607")
    add_anchor(path_rows, bg_name, background, bg_hash, b"ft.a.devicesAsync().then(t=>{e.deviceProcess(t)})",
               "hid-device-enumeration-call", "HID manager requests the current HID-device list and passes results into device filtering.", module_id="607")

    summary = {
        "asar_sha256": sha256(asar),
        "background_sha256": sha256(background),
        "renderer_js_files_hash_pinned": len(manifest),
        "renderer_literal_ipc_calls": ipc_count,
        "renderer_literal_ipc_channels": len(ipc_channels),
        "renderer_channels_with_main_literal_match": sum(1 for c in ipc_channels if c in main_channels),
        "main_literal_ipc_handlers": len(main_rows),
        "path_evidence_rows": len(path_rows),
        "rea_evidence_id": REA_EVIDENCE_ID,
        "rea_mi_hid_import_edge": REA_MI_HID_IMPORT_EDGE,
        "module_607_byte_range": f"{MODULE_607[0]}..{MODULE_607[1]}",
        "renderer_hashes": {"index.html": sha256(index_html), "preload.js": sha256(preload),
                             "app.7057a5da.js": app_hash, "8224.10899a1c.js": fw_hash},
        "not_found_in_literal_renderer_channels": [x for x in ("lighting", "keymap", "setReport", "setKeyValue")
                                                     if x not in ipc_channels],
    }
    if not args.stdout_only:
        write_csv(IPC_LEDGER, ipc_rows)
        write_csv(PATH_LEDGER, path_rows)
    import json
    print(json.dumps(summary, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
