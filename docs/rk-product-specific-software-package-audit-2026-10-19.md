# Product-specific RK software packages: static audit — 2026-10-19

## Scope and method

This report records four Windows product-specific application packages
selected from RK's current public keyboard catalog, the associated Mac package
for F99 AI, and a separate eight-variant S98 firmware-updater family. The
packages were downloaded to a research-only directory, hashed, and inspected
with archive/PE parsers. Vendor installers, applications, and updaters were
not run. The application package-level hashes, installer families,
signatures, nested binaries, and analysis limits are listed in the accompanying
[`package catalog`](rk-product-specific-software-package-catalog-2026-10-19.csv).
The R99 extracted-file manifest is in
[`rk-r99-package-manifest-2026-10-19.csv`](rk-r99-package-manifest-2026-10-19.csv).

The source packages remain outside this repository; no vendor executables,
assets, or firmware are redistributed here. The public selector snapshot is
described in the [selector API audit](rk-official-selector-api-catalog-audit-2026-10-19.md).

## Findings by software family

### Legacy GamingForceZ application: RK918-labeled and S108 packages

The public RK918 download is a RAR4 archive whose sole member is named
`GamingForceZ RK919 V1.13n.exe`. This mismatch is preserved as observed; the
archive name does not prove the installed product or supported physical model.
The S108 ZIP contains `GamingForceZ GK890 V1.01.000n.exe` and a small
AppleDouble sidecar. Both contained executables are NSIS 2.46.5 Unicode
installers. Their 394-entry payloads share 391 paths, and the root application
EXE plus its principal plugin modules are byte-identical. Three root names
vary by model (`.exe`, `.ini`, `.bat`); model data and a Sonix HID helper DLL
also differ. This is strong static evidence of a shared application family
with SKU-specific data, not proof that either package supports every product
listed in its archive name.

Both package INIs point to `Bin\\Plugin.dll` and `Bin\\Entry.xml`. The latter
declares a `GamingKeyboardMain.dll` plugin and a default
`RecoverSetting\\GK\\GamingKeyboard.gkdb` database. The model-specific
SQLite databases contain profile/key customization, macro, gaming-mode, and
lighting-effect tables; their schemas and defaults are observable, but table
names alone do not prove which records are sent to the keyboard.

The `SonixHidDll.dll` helper exports `FindDeviceWithID`, `HIDReportIn`,
`HIDReportIn2`, and `HIDReportOut`, and imports HID class, SetupAPI, and file
I/O functions. `GamingKeyboardWriter.dll` has strings showing that it loads
this helper and resolves those exports dynamically. This proves a HID
abstraction boundary exists in the package; exact IDs, report shapes,
commands, and call-path semantics remain unresolved. Imports and strings do
not prove that a path executes.

The S108 package inventory contains 26 DLLs, 74 XML files, 281 PNGs, 2 INIs,
2 DBs, 2 other database files, and 3 EXEs, among other resources. Its paired
RK918-labeled package has the same 394 paths. The NSIS overlay and model data
are not byte-identical. A packaged BAT file contains a recursive
`Everyone:F` ACL command, but it was not run; its actual installer reachability
and effects are not established by this static pass.

The `GamingKeyboardWriter.dll` is byte-identical in both packages
(SHA-256 `8b716fa567e84791f77f94582ce8af648e4c3741bf70406b3135eb2129c695d2`).
It dynamically loads `Bin\\GK\\SonixHidDll.dll` and resolves
`FindDeviceWithID`, `HIDReportOut`, `HIDReportIn`, and `HIDReportIn2`. The newer
RK918 package's GK helper enumerates three interface GUIDs; its older GM helper
and both S108 helpers use `HidD_GetHidGuid`. The helper's output routine
constructs feature reports with report ID 0 and Writer callers request 64-byte
reports. Static callers contain words such as `0xE004`, `0xAB04`, `0xF104`,
`0xF004`, `0x0204`, and `0x0504`, but their meanings and product mapping are
unresolved. The detailed evidence is package-build-specific and does not
establish successful device communication.

### R99 RK Driver package

The R99 selector target is an Inno Setup 6.3.0 installer. Its PE version
resource identifies `RK-Driver` 1.0.4.1, while the installer is unsigned. A
portable, source-visible Inno extractor was used to unpack the package; the
installer and extracted EXEs were not run. The extracted tree has 215 files
and is inventoried by path, size, and SHA-1 in the companion manifest.

The main `RK Driver.exe` is a 32-bit GUI application. Its static imports
include SetupAPI enumeration, Raw Input and global-hook APIs, tray notification,
Registry, WinMM, GDI+, and custom exports from `mui.dll`; the package also
contains `CH375DLL.DLL` and `driver\\CH372DRV.EXE`. These imports indicate
available OS integration points, not proven runtime behavior or exact device
operations. The main EXE's direct calls into the helper exports and the
installer's driver-install sequence still need full call-path analysis.

A separate hash-pinned scanner records 2,559 imports and 4,110 direct
imported-call/tail-jump candidates across all seven package PEs. It links nine
CH375 exports called by the main app to 30 `DeviceIoControl` candidates in the
helper, all carrying IOCTL `0x223CDC`; it also maps HID descriptor/capability
calls and SetupAPI enumeration candidates. Candidate-level details and
unresolved function-boundary issues are in the [R99 native API audit](rk-r99-native-api-boundary-audit-2026-10-19.md).

Static resources include 20 layout XMLs covering R87V2, R98, R98GT, R99,
RK99, RKK99, RR99, RR99_UK, T87, and T98, with wired and `_Dongle` variants.
The UI string resources name Remap, Performance, Advanced Keys, Macro, Light,
Config, Aurora Linkage, eight FN layers, DKS, Mod Tap, Toggle Key, macro timing,
lighting profiles, polling rates, Tachyon, Rapid Trigger, firmware update,
and calibration. These are evidence that the package presents those labels;
actual handlers, device-family gates, and hardware behavior are not yet
recovered. Some layout XML files are malformed and are catalogued as such
rather than silently normalized.

### F99 AI RK Setup package

The F99 AI selector target is a signed NSIS 3 Unicode installer for RK Setup
3.2.2. Static extraction reveals an Electron application with 4,569 ASAR
entries, 91 renderer JavaScript chunks, 53 CSS chunks, model imagery, and an
x64 native HID addon. The app loads `mi-hid.node`; static wrapper code exposes
enumeration, open/read/close, and write methods. The application code contains
a 2-second device enumeration loop, VID/PID filtering, 128-byte output report
construction, and a queued writer drained every 30 ms. These are static
implementation paths, not observed I/O.

The package contains 68 VID/PID rows (57 unique pairs) and imports native
Windows APIs including `CreateFileW`, `ReadFile`, `WriteFile`, and
`DeviceIoControl` through the native HID addon. Static JS also names
connectivity/device-info/settings, voice/audio, and OTA functions. The OTA
symbols include start/open/firmware/complete stages and channels 0/1/2; none
were invoked. A focused static pass maps the Electron background entry to
`app://./index.html`; its BrowserWindow enables Node integration and declares
no preload script.

The F99 model gate is a 68-row VID/PID allowlist. The four RK model IDs admitted
under the package's RK build configuration are F99 AI, Air61, i20 AI, and N20
AI, but only F99 has explicit matching PID rows in this table (`248A:8102`,
`248C:8243`, and `248A:8243`). The other three models' precise HID routes are
unresolved. A two-second scan filters HID usage and usage-page values, matches
an allowlisted VID/PID, deduplicates paths, then opens the device through
`mi-hid`. The host sends a random challenge and checks a 32- or 35-byte
response; the heartbeat and verification state must both pass before the app
reports a connected device. F99 maps internally to `RK756` and the
`DEVICE_RK756` keyboard image. The inspected F99 package's model table and
keyboard list contain no S98 entry; that is package-scoped evidence, not proof
of incompatibility with every shared HID path.

The device card receives the main process's device-list event. Its generic DPI
path maps from renderer IPC through the main process and manager to the HID
class, but the F99 keyboard UI hides that control. The firmware-check dialog
maps through IPC to a download and `startFwOta` call; no update was triggered.
The write path allocates a 128-byte scratch buffer but queues reports at the
computed variable length (Darwin/custom build 5 has a 64-byte special case),
then drains the queue every 30 ms through `mi-hid`. These are static paths, not
observed I/O. Exact model data for other rows, complete UI-to-native edges,
protocol fields, and native-addon behavior remain incomplete. No lighting/RGB
command label was found in the inspected F99 enum and UI path; this does not
establish that the addon or other RK software has no lighting support. An F99
Mac DMG was downloaded and hashed, but only its outer container was identified;
its APFS contents were not inspected on this Windows host.

Selected source-byte anchors for this F99 pass:

| Path | Source artifact and SHA-256 | Byte offset(s) and evidence |
| --- | --- | --- |
| Model allowlist and two-second discovery | `selected/background.js`, `8db60b45ce93fc20f68950ebb97db0640d6384c3808b06e43c332d8ef4183277` | Byte offsets `2,236,364` (allowlist loader) and `2,243,880` (discovery/filter/open path) |
| Verify/heartbeat gate | same `background.js` | Byte offsets `2,200,810` (heartbeat setup), `2,203,562` (verification response), and `2,205,791` (serial validation) |
| DPI UI → HID | `resources/app.asar.unpacked/js/8224.10899a1c.js`, `cc82f6dadf8a639c2c38c3e9f15d76ca2fe4094f40e763d361f569907fab4408`; plus `background.js` | Byte offsets: device chunk `5,721`; background IPC `2,792,963`; manager `2,241,267`; command writer `2,192,667` |
| Firmware query/update UI → OTA | device chunk above; `resources/app.asar.unpacked/js/app.7057a5da.js`, `b1a8ccb44b307a48eb10553d74107675fe2affb4370b3b940ea818e8d5acfacb`; plus `background.js` | Byte offsets: device chunk `5,439`; app dialog `27,003`; background query `2,792,850`; background OTA handler `2,793,352` |
| Device-list event and card image selection | `selected/background.js`; device chunk above | Background forwards the device list at byte `2,832,401`; device card selects `DEVICE_RK756` at device chunk byte `9,309` |

Offsets are byte offsets in the named exact files, not runtime addresses. They
are navigation anchors for the static code paths above, not proof those paths
were executed.

REA's CLI JavaScript application analysis completed as local Evidence
`ev_83a56e1c6593964124f97cc1be87f0973e9d8370851c2cd5d02368b1fe6bb2d9`
for the exact ASAR hash in the catalog. Its saved summary reports 3,814
relevant files, 2,971 parsed JavaScript files, 2,738,930 visited AST nodes,
12,483 findings, and three parser failures. The Evidence JSON contains 75,336
`unknown_id` records and 2,111 source-analysis entries marked interrupted due
to result-budget limits. `background.js` is 2,835,093 bytes and marked
`parse_status=partial`; the graph summary also reports incomplete coverage.
The reported zeroes for recognized BrowserWindow/preload/native-addon
relationships are therefore not absence proofs. The full 298 MB Evidence JSON
is retained in `.research` and intentionally is not committed.

### S98 Tri-mode RGB firmware-updater family

The public selector currently returns eight language variants of the S98
Tri-mode RGB updater. All are unsigned PE32 x86 files with a
`requireAdministrator` manifest and an appended `5A A5 SINO` container tied to
VID `0x258A` and language-specific PIDs. Seven builds share executable section
hashes; the Thai variant is a distinct code build. Static disassembly maps the
container parser, a 32-round XTEA-style block transform using a four-byte
trailer key, selected HID feature-report construction/readback paths, and
2,050-byte report buffers with up to 2,048-byte chunks. The transformed
payload format, exact report meanings, full UI-to-transfer graph,
retry/error lifecycle, and device acceptance remain open. No decoded firmware
or updater binary is included. See the
[S98 static audit](rk-s98-firmware-updater-static-audit-2026-10-19.md) and its
linked ledgers.

## Cross-family interpretation

These samples establish at least three distinct product-specific software
families in addition to the separate general Hub Driver and RK Drive web app:

1. `GamingForceZ` NSIS packages with a shared plugin architecture and Sonix
   HID helper;
2. the R99 `RK Driver` Inno Setup application with CH372/CH375 components;
3. the F99 AI Electron application with the `mi-hid` native addon.

Do not merge their API or protocol findings into one universal RK protocol.
Their UI labels, file names, imports, model lists, and implementation
boundaries differ. The packages cover only current selector results acquired
for this audit; they do not represent every current, historic, regional, or
retired RK model/package.

The S98 updater is a separate firmware-tool family with eight regionalized
package variants; it must not be conflated with the application protocols or
treated as evidence that all S98 hardware revisions are supported.

## Remaining work before claiming whole-suite coverage

- Expand the partial F99 analysis with focused, source-path-limited passes on
  the main process entry point, renderer chunks, preload candidates, and the
  native-addon wrapper; map returned paths to exact UI/IPC/native call chains.
  The whole-ASAR pass exhausted its graph-result budget and does not provide a
  complete function map.
- Recover full call graphs and data flow for the three application families,
  especially R99 helper calls, GamingForceZ plugin/DLL calls, and F99
  renderer-to-native-addon calls.
- Map all model/profile/configuration data to product and revision identifiers;
  distinguish labels and selector metadata from verified compatibility.
- Analyze firmware/QMK packages and other current product-specific downloads,
  then expand to historical and regional packages.
- Analyze the F99 Mac payload using a format-capable environment; inspect all
  package assets and runtime owners; complete installer and updater behavior.
- Determine the limits of firmware readback from documented static paths.
  This audit itself did not open a keyboard interface or attempt readback.

## Evidence labels

**Proven statically** means tied to the identified package bytes, PE metadata,
archive members, resources, imports/exports, or source text in the extracted
application. **Inferred** means an architectural interpretation supported by
those observations. **Unresolved** means dynamic reachability, physical model
identity, device acceptance, firmware semantics, or a package class not
examined here. No result in this report is a claim of successful device
communication.
