# F99 Windows renderer-to-HID static trace

**Scope:** bounded static trace of the saved Windows F99 3.2.2 Electron files. It follows renderer IPC for device DPI and firmware query/update through `background.js`, the HID manager, report construction, and the native HID write call. No application, installer, renderer, updater, or HID interface was opened; no reports or firmware were sent.

## Input identity and source boundary

| Input | Bytes | SHA-256 |
|---|---:|---|
| Windows `resources/app.asar` | 30,252,260 | `38ebbf1416050d9ab36eee4910ec86130a0919b69334ec3751378f7f00ff2bdf` |
| Saved Windows `background.js` | 2,835,093 | `8db60b45ce93fc20f68950ebb97db0640d6384c3808b06e43c332d8ef4183277` |
| Adjacent renderer `index.html` | 498 | `b688946c0d06962a2bca85e63d6cb99767f52a9bab789f016b45e80c18aa4a3a` |
| Adjacent renderer `preload.js` | 382 | `2437e971df0d1a74bca59e3034405768c19a72de84aacd3c333408e48acc303c` |
| Renderer `js/app.7057a5da.js` | 2,043,749 | `b1a8ccb44b307a48eb10553d74107675fe2affb4370b3b940ea818e8d5acfacb` |
| Renderer `js/8224.10899a1c.js` | 10,243 | `cc82f6dadf8a639c2b38c3e9f15d76ca2fe4094f40e763d361f569907fab4408` |

The `background.js` evidence is inside Webpack factory 607, whose byte range is `[1,487,507, 2,835,090)` in the pinned bundle. Factory 338 requires factory 607; factory 607 loads factory 88, whose 42-byte body is `function(e,t){e.exports=require("mi-hid")}`. These module IDs and ranges are also recorded in [the prior F99 cross-platform report](rk-f99-background-js-cross-platform-diff-2026-10-20.md).

REA evidence for the ASAR is `ev_83a56e1c6593964124f97cc1be87f0973e9d8370851c2cd5d02368b1fe6bb2d9`. Its static import relationship is edge `jag_edge_039776a41a038e64ef992cd15c65415914bfdaa532e3ecd2e180f66fa55239b8`, from source node `jag_node_c3053ff8ab225f82a4e942f5f50d57863438d8e488f2c15abaa6a449075e4943` to `jag_node_ed46c733a0bae716c5efe4f25fd9ada6139ec0e3872360d3c024f0a2b8190ef2`; the recorded resolution is `node_modules/mi-hid/nodehid.js` at `background.js` line 2, columns 232,978–232,995. This is static package-resolution evidence, not proof that the import executes.

The renderer files are saved beside `app.asar` under `resources/app.asar.unpacked`, but their paths are not present in the pinned ASAR header. The manifest here pins all 91 adjacent renderer JavaScript files by size and SHA-256; this pins the bytes used by the scan, but does **not** prove that these sidecar files were shipped with the same ASAR. Renderer-to-ASAR provenance remains unresolved. The saved `index.html` loads `js/app.7057a5da.js`; the saved preload only installs a `notes2` logging listener and exposes no `contextBridge` API. The observed renderer IPC calls use direct `ipcRenderer` references.

## Proven static paths

### DPI setting reaches the native HID write call

1. Renderer component `resources/app.asar.unpacked/js/8224.10899a1c.js` sends `radioSelect` with `{deviceID, dpi}` at byte offset 5,738.
2. Factory 607 handles `ipcMain.on("radioSelect", ...)` at offset 2,792,963 and calls `$a.setDPI(deviceID, dpi)`.
3. The controller method at offset 2,778,289 calls `pn.setDpi`. The HID manager method at offset 2,241,267 selects a connected, non-free HID object with the matching device number and calls its `noticeHid_SetDpi` method.
4. The device handler at offset 2,192,667 checks whether HID commands are allowed and whether an update is active. It puts `App_Set_Dpi` (command value 6) and a two-byte DPI value into the shared report builder at offset 2,192,772.
5. The builder frames and queues the report (offsets 2,189,766 and 2,190,403). The main-process send timer drains the queue and calls `this.hidDevice.write(e)` (write call at offset 2,201,988).

This is a complete **static call path** from a renderer event to a native HID write site. The UI names this as DPI selection and the surrounding catalog/version endpoint is mouse-oriented; this trace does not establish that it is a keyboard control or that the path runs successfully on a connected device.

### Firmware query and OTA path

1. The renderer component sends `fwUpdateCheck` with the selected device ID at byte offset 5,516. Factory 607 handles it at offset 2,792,850 and calls `checkDeviceVersion`.
2. The controller looks up that ID in its device map and, when the record has a `firmwareName`, queries the literal URL `http://mic.mimouse.net/dfs/hardware/judge/latest/version?type=mouse&system=mac&deviceType=...` (method starts at offset 2,778,316). This Windows build therefore contains a mouse-specific endpoint and a literal `system=mac` query value.
3. The controller emits a version result; factory 607 bridges it to `sendFirmwareQueryData`, and renderer chunk `8224.10899a1c.js` stores the result and opens its update dialog (renderer listener at offset 3,913; main send at offset 2,833,031).
4. The dialog's `toUpdate` method sends `toUpdateFrimware` with the selected device ID and vendor-provided install name at `app.7057a5da.js` byte offset 27,003. Factory 607 handles it at offset 2,793,352 and calls `downloadFrimware`.
5. The controller rejects this call while its ASR mode is active or another firmware update is underway. Otherwise it downloads the named binary from the same HTTP host. On a 200 response, it calls `pn.startFwOta(deviceID, 0, bytes, byteLength, null, 0)` at offset 2,779,814.
6. The HID manager's OTA dispatcher (offset 2,243,512) only forwards to a connected, non-free HID object with the requested device number. Its OTA implementation stores the firmware data, emits `App_OTA_Open` and firmware-data messages through the shared report builder, then uses the same queued HID write path described above. Progress events are bridged back through `sendFwProgress` to the renderer listener at `8224.10899a1c.js` offset 4,051.

This proves that the saved code contains an OTA-capable path from a UI action to a HID write site. It does not prove version-server availability, downloaded-image validity, cryptographic/signature checks, model compatibility beyond the controller's device-map and `firmwareName` gates, or that any update was attempted. The path was only traced as data; it was never called.

### Device discovery boundary

The controller is initialized from factory 607 after a two-second delay (offset 2,833,494). Its `init()` assigns the shared HID manager and calls `start()` at offset 2,750,588. The manager's `start()` calls device detection; detection schedules enumeration every two seconds and passes the HID list into `deviceProcess` (offsets 2,240,110, 2,243,694, and 2,243,824). The controller also polls its device list every two seconds and forwards list events to the renderer (offsets 2,751,479 and 2,832,431). The manager's `deviceProcess` logic at offset 2,243,874 skips candidates whose usage or usage page is below 10,000, requires a vendor/product pair in its compiled allowlist (comparison at 2,244,131), opens allowed paths with `new ft.a.HID(n.path)` at offset 2,244,432, and selects a handler by HID series type. The associated read worker receives `hidPath`, `hidName`, and a shared stop buffer at offset 2,187,050; its embedded body constructs `HID.HID(workerData.hidPath)` and calls `readTimeout(10)` at offset 2,186,387. That worker body reads only; the main-process HID object is the visible write site.

Static import evidence and the packaged path expression are consistent with the saved Windows `mi-hid.node` (`fe68309021c9640f16a2bbd550738cf8904b3d18a1cc3a4e8b2d22ec2a2d5ee4`). See [the existing native import ledger](rk-f99-native-hid-imports-2026-10-19.csv). These sources prove intended code structure, not native module load success or runtime device discovery.

## Settings, lighting, and keymap boundary

The bounded scan found 95 literal renderer `ipcRenderer` call sites across 91 hash-pinned JavaScript files, covering 32 distinct channel strings. Twenty of those distinct channels have a literal `ipcMain.on`/`handle` match in `background.js`; the row-level list is in [the renderer IPC ledger](rk-f99-windows-renderer-ipc-ledger-2026-10-20.csv).

The main `changeGeneralSettings` handler stores app-level work mode, language, voice, typing, and toolbar preferences. It does not call the HID manager. The `radioSelect` path above is the concrete device-setting path identified in this scan, and it maps to DPI. No literal renderer IPC channel for lighting, keymap, `setReport`, or `setKeyValue` was found. The bundle does contain internal HID manager setters for report/performance/key values, while the base series methods are empty and at least one derived series has overrides; this scan found no renderer-to-main route for those setters. The `keymap` token in another renderer chunk is an editor-library keyboard-shortcut plugin, not evidence of keyboard remapping.

This is a bounded IPC-ledger result, not proof that no such feature exists under a dynamic channel name or in a separate application/package. In particular, the renderer snapshot's packaging relationship to the pinned ASAR is still open.

## Evidence classification and remaining gaps

**Proven from saved bytes:** hash identities; literal renderer IPC calls; matching literal main handlers; source-level method calls, guards, hard-coded HID filters, report framing, queueing, and `hidDevice.write`; and the retained REA `mi-hid` package-resolution relationship.

**Inferred from static structure:** these linked code fragments represent intended UI-to-HID control flow if the saved renderer and main files belong to the same running build and the relevant handlers execute. The sidecar files are not covered by the ASAR digest, and static edges do not establish runtime reachability.

**Unresolved:** renderer/ASAR co-shipping provenance; runtime device/interface selection; whether this F99 3.2.2 package is the same product build relevant to an RK S98 keyboard; the semantic meaning of every supported VID/PID and HID series ID; native addon behavior; endpoint/image authenticity and model checks beyond the visible gates; dynamic renderer channels; and whether other RK software builds implement lighting or keymap controls.

## Reproduction

From the repository root, with the adjacent `.research` snapshot present:

```powershell
python scripts\trace_rk_f99_windows_ui_ipc_hid.py
```

The scanner reads only saved files, verifies the ASAR/background hashes and all renderer JavaScript hashes in [the renderer hash manifest](rk-f99-windows-renderer-js-hashes-2026-10-20.csv), then regenerates the IPC and UI-to-HID ledgers. It prints counts and pins for review. It does not parse/evaluate JavaScript, run REA, or touch a device.
