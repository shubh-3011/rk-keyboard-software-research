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
RK918 package's GK helper (SHA-256
`c7e129af90ef793e362650384088945bcdbff08d6fdf434e0f73990b3922ef87`)
enumerates three interface GUIDs; its older GM helper and both S108 helpers
use `HidD_GetHidGuid` (older helper SHA-256
`eca32342eb27abc8349b8487bdbed679c62b77039e37748a201835047cd83959`). The
helper's output routine
constructs feature reports with report ID 0 and Writer callers request 64-byte
reports. Static callers contain words such as `0xE004`, `0xAB04`, `0xF104`,
`0xF004`, `0x0204`, and `0x0504`, but their meanings and product mapping are
unresolved. The detailed evidence is package-build-specific and does not
establish successful device communication.

The package's `Bin\\GK\\LightingUI.xml` declares a `CWTEventListener`, a
`GK::ID_LIGHT_Switch`, and 16 brightness selectors
(`GK::ID_LIGHT_BrightnessSlider_0` through `_15`; RK file lines 37, 103, 129,
189, and 2460). Its `Entry.xml` configures the Writer plugin with
`MemoryType=1`, `ToolType=1`, `CommandDelayTime=10`, brightness values 1–16,
and lighting modes 1–25 in the RK918-labeled package (lines 189–244) versus
1–19 in S108 (lines 183–232).
`Entry.xml` connects Writer with Profile, Macro, Persister, and UI event
listener components. The two profile databases have matching schemas,
including `KeyLightGeneral` (with `ProfileName`, `LightMode`, `Direction`,
`Frequency`, `Brightness`, `Color1`, `Color2`, and `IsFullColor`), per-effect
`KeyLight*`, `ProfileSummary`, `GamingMode`, and macro tables; each has three
default profiles and 32 `KeyLightGeneral` rows per profile, with stored mode
indexes 9–40. This establishes configuration/UI structure, not the meaning or
serialized device values of each mode or brightness index.

Focused Writer disassembly shows its loader at VA `0x10002E80` constructing and
loading `\\bin\\GK\\SonixHidDll.dll`, then resolving the four helper exports.
The `FindDeviceWithID` path obtains two properties (keys `0x4268` and `0x4269`)
and passes them to a helper that compares them with HID VID/PID attributes;
their numeric values remain unresolved. Writer callsites build 64-byte
requests, including `0x10002759`, `0x10002962`, `0x10002A1F`, `0x10002C4B`, and
`0x10002CBB`. One caller at `0x10002759` sends `0xE004`, reads four response
bytes at `0x100027DC`, and retries up to three times; other callers send
`0xF104` at `0x10002C4B` and `0xF004` at `0x10002CBB`. The helper's output
routine prepends feature report ID zero, while input routines strip the
report-ID byte before copying response data. A helper read call at
`0x10002BD1` requests four bytes with a `0x7D0` (2,000 ms) timeout.

The lighting UI event map is partially traced in the shared
`GamingKeyboardMain.dll` (SHA-256
`d532a10daf97d4748819c2743736a039ae71c2ec668e2e8f0748ec9bd7b346c6`). Two
aligned tables in `.data` (`0x1BC928`–`0x1BCA18` and duplicate
`0x1BD5D8`–`0x1BD6C8`) map all 16 brightness-slider IDs to handler VA
`0x10015610`, with flags `0x111`; the same handler is also assigned to the 16
speed-slider IDs. It queries a widget identifier through `0x1001FC10`, then
dispatches through generic callback helpers `0x10047F7F` / `0x10017FE0`; no
Writer method or Sonix export is directly resolved in that handler. The ID
parser scans for `_` and returns an index-like value, but the framework's
string/result conventions and brightness conversion remain unresolved.

Mode-related event rows also map `GK::ID_LIGHT_ModeList` to `0x10014E50`,
`GK::ID_LIGHT_ModeLabel` to `0x10014C80`, and the light switch to `0x10014FC0`.
The switch calls the mode-list handler, which resolves `GK::ID_LIGHT_ModeIndex`
and updates UI state through indirect widget methods; the handler has no
statically resolved Writer/Sonix call. `LightingUI.xml` declares the CWT UI
listener's collaboration with both Profile and Writer, and its
`CWTChainReactionTextEditOnChange` on `GK::ID_LIGHT_LightModeTrigger` controls
UI visibility. Those links do not prove a commit or device write. Command
meanings, returned status semantics, and brightness/mode serialization remain
unresolved.

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
operations. Some direct CH375, HID, and SetupAPI paths are now mapped below;
full function reachability, helper argument/return semantics, and the complete
installer sequence remain open.

A separate hash-pinned scanner records 2,559 imports and 4,110 direct
imported-call/tail-jump candidates across all seven package PEs. It links nine
CH375 exports called by the main app to 30 `DeviceIoControl` candidates in the
helper, all carrying IOCTL `0x223CDC`; it also maps HID descriptor/capability
calls and SetupAPI enumeration candidates. Candidate-level details and
unresolved function-boundary issues are in the [R99 native API audit](rk-r99-native-api-boundary-audit-2026-10-19.md).

Focused callsite review of `RK Driver.exe` (SHA-256
`61dd118400a4652ba053db6ceb87cdd865e183f59822948ea9018da218aec2e5`)
confirms a CH375 path through its app-shipped 2022 `CH375DLL.DLL` (SHA-256
`a7d5acb61f0d4b0ccbc5b045c1cdf01146cfdaacff23f3931459f17ecd85f571`) and a
separate HID/SetupAPI path. Two CH375 discovery loops enumerate, obtain USB ID
and device name, and close candidates (main EXE VAs `0x41A961`–`0x41A9B8` and
`0x41AE56`–`0x41AEAC`). The ID check compares words `0x4348` and `0x55E0`, which
match the archived INF's USB VID/PID. The selected-path branch sets exclusive
access and timeout, then calls `CH375WriteData` at `0x41AF64`, `0x41B024`, and
`0x41B0D6`; it calls `CH375ReadData` at `0x41AFA1` and `0x41B102`. Two request
builders write 4-byte values `0x281` and `0x283`; another loop processes chunks
up to `0x3C` bytes. These values are request data, not decoded command
semantics or proof of device response.

The app also has a distinct HID/SetupAPI path: a candidate opened with
`CreateFileW` is checked with `HidD_GetAttributes`, preparsed data, and
`HidP_GetCaps` (VAs `0x43E067`–`0x43E0A7`); another path enumerates SetupAPI
interfaces and reads detail/device properties (`0x474ED6`–`0x47521A`). Static
evidence shows both CH375 and HID paths in the same build, but does not show
which branch a given model or runtime connection uses.

A separate static examination of the archived 2023 driver payload resolves
that boundary further. `CH375WDM.sys` dispatches IOCTL `0x223CDC` through its
device-control handler; the handler requires an input buffer of at least eight
bytes, parses an operation and declared length from `IRP.SystemBuffer`, and
sets completion information to the operation's result length plus eight. For
operation 16, jump-table branches for suboperations 3 and 4 call internal
helpers and return 8 and 4 bytes respectively. No `OutputBufferLength` check
was found in this dispatch path; this is a static review item, not a claim of a
runtime vulnerability. A 2023 `CH375DLL.dll` maps `CH375QueryBufUploadEx`,
`CH375ClearBufUpload`, and `CH375SetBufUploadEx` to operation 16 with
suboperations 3, 4, and a set/config path. The DLL shipped beside the main app
is a different version from this archived 2023 helper, so their precise
equivalence remains unresolved.

The pinned files are x86 `CH375WDM.sys` SHA-256
`cd261de65db8f3824495b9466a100b069828c48f92223463cd150b35e067efe4`,
the archive's `WIN 1X\\CH375WDM.sys` SHA-256
`bbe2b9a1a571ccabef21cc1ad082f8c062fe86772900cda52e355d5129a17a79`,
2023 `CH375DLL.dll` SHA-256
`8aadd025422d4634aaaf6ce2de6106ff2915a41c15ede3c1b8118e206e3e997d`,
`SETUP.EXE` SHA-256
`4b58be5dbcfa0a452b7d62fa61ff8a8e5935fc5d524ef086379ec92e11db5519`, and
`CH375WDM.INF` SHA-256
`f41675a827a53d23b59f23677a3d091a8974e251b38ef0c355608f5b47bbb0cf`.
The two `.sys` files have identical PE sections but different whole-file
lengths and signed/overlay bytes, so they are not byte-identical.

Useful x86 file-offset/VA anchors for the 2023 build are:

- `DriverEntry` sets the `IRP_MJ_DEVICE_CONTROL` dispatch slot at `+0x70` to
  handler VA `0x137F0` (file offset `0x37F0`). The handler compares IOCTL
  `0x223CDC` at `0x13864`–`0x13871`, checks `InputBufferLength >= 8` at
  `0x138B4`–`0x138BB`, parses operation/length/body at `0x138C1`–`0x138D2`,
  and sets `IRP.Information = result_length + 8` at `0x14562`–`0x14568`.
- Operation 16 dispatch starts at `0x142F8`; jump table `0x147A8` sends
  suboperation 3 to `0x144F4`, which calls helper `0x10970` with `body+4` and
  returns 8 bytes; suboperation 4 goes to `0x14529`, which calls helper
  `0x118F0` and returns 4 bytes. Operation 18 at `0x146A0` stores its first
  body byte at extension offset `+0x3A5`; no matching named 2023 export was
  found.
- `CH375DriverCommand` in the 2023 DLL at VA `0x4013D3` passes the same buffer
  for input/output and sizes both from `DWORD(buffer+4) + 8`. Its query, clear,
  and set exports build operation-16 requests: query is length 8 with body
  suboperation 3 and endpoint-1; clear is length 8 with body suboperation 4
  and endpoint-1; set is length 12 with option, endpoint-1, and requested
  length fields. These are static buffer mappings; internal driver helper
  behavior is not fully named.

The 2023 `CH375WDM.INF` maps `VID_4348&PID_55E0` and declares a demand-start
`CH375` kernel service. Its `SETUP.EXE` statically calls SetupAPI install
functions, resolves `UpdateDriverForPlugAndPlayDevicesA` dynamically, and
invokes `SetupCopyOEMInfA` / `SetupInstallFilesFromInfSectionA` and
`SetupCommitFileQueueA`. This proves the package contains an installer path;
it does not prove it was run on this PC or that the driver controls a specific
RK model. The INF's `DriverVer` is `10/16/2023,3.4.2023.10`; its service uses
`%10%\\System32\\Drivers\\CH375WDM.SYS` with demand start. The installer calls
`SetupDiCallClassInstaller(DIF_INSTALLDEVICE)` at `0x402F87`, resolves
`UpdateDriverForPlugAndPlayDevicesA` at `0x4032C8`–`0x4032FF`, calls
`SetupCopyOEMInfA` at `0x40354B`, and calls
`SetupInstallFilesFromInfSectionA` / `SetupCommitFileQueueA` at
`0x403F0B`/`0x403F23` and `0x404192`/`0x4041A9`. These static paths do not
establish that installation occurred on this PC.

Static resources include 20 layout XMLs covering R87V2, R98, R98GT, R99,
RK99, RKK99, RR99, RR99_UK, T87, and T98, with wired and `_Dongle` variants.
The UI string resources name Remap, Performance, Advanced Keys, Macro, Light,
Config, Aurora Linkage, eight FN layers, DKS, Mod Tap, Toggle Key, macro timing,
lighting profiles, polling rates, Tachyon, Rapid Trigger, firmware update,
and calibration. These are evidence that the package presents those labels;
some profile, database, and transport-worker paths are now mapped, but action
ownership, device-family gates, exact wire payload mapping, and hardware
behavior remain open. Some layout XML files are malformed and are catalogued
as such rather than silently normalized.

The R99 layout `R99.xml` (SHA-256
`2186ebf64c00f079ec81e57c676f05487c33cf0efc7f972efde417fa11095424`; shared
with `R99_Dongle.xml`) defines a 101-key grid with key codes, names, indices,
light indices, and geometry. `default_light.xml` (SHA-256
`bc079015102b5c5d6341e9f0e925c774353432f027acb3786d021850bd3412b9`) contains
six presets with 105 per-key RGB entries each. The English language file
labels Apply, Light, Light Mode, Brightness, Speed, Direction, and Firmware
Update. The EXE contains SQLite schema/update strings for `t_light_data` at
file offset `0x18D1E0` / VA `0x58E5E0`; fields include brightness, speed,
direction, color, configuration, and status. An update routine at VA
`0x408101` binds record fields before database execution. These prove profile
and local state structure, not which values the keyboard receives.

The CH375 worker at VA `0x41A9D0` opens through helper `0x41AE40`, sets
exclusive access and timeout, then calls the previously mapped read/write
helpers. Generic request routines at `0x41AF40` and `0x41AFE0` send DWORDs
`0x281` and `0x283` with length 4 and read a two-byte response. A transfer
helper at `0x41B040` handles request values `0x80` and `0x82` with an allocated
`0xC8000`-byte buffer; a caller opens and reads a file before sending chunks.
This transfer sequence is not tied to the visible Firmware Update label by a
verified callback xref. No static edge in this pass joins `R99.xml`, the
default RGB presets, or the Apply label to a specific CH375 payload.

The outer `CH372DRV.EXE` (SHA-256
`f3e7b77711fd97024146203c870c668607cad04bbd75d3dacb147ebcd21fd8ef`) is a
WinRAR self-extracting wrapper with a RAR overlay at `0x18200` of length
`273,288`; the actual driver install/API calls reside in the extracted
`SETUP.EXE`, not the outer wrapper.

### F99 AI RK Setup package

The F99 AI selector target is a signed NSIS 3 Unicode installer for RK Setup
3.2.2. Static extraction reveals an Electron application with 4,569 ASAR
entries, 91 renderer JavaScript chunks, 53 CSS chunks, model imagery, and an
x64 native HID addon. The app loads `mi-hid.node`; static wrapper code exposes
enumeration, open/read/close, and write methods. The application code contains
a 2-second device enumeration loop, VID/PID filtering, a 128-byte scratch
buffer, variable-length output-report construction, and a queued writer
drained every 30 ms. These are static implementation paths, not observed I/O.

The package contains 68 VID/PID rows (57 unique pairs) and imports native
Windows APIs including `CreateFileW`, `ReadFile`, `WriteFile`, and
`DeviceIoControl` through the native HID addon. Static JS also names
connectivity/device-info/settings, voice/audio, and OTA functions. The OTA
symbols include start/open/firmware/complete stages and channels 0/1/2; none
were invoked. A focused static pass maps the Electron background entry to
`app://./index.html`; its BrowserWindow enables Node integration and declares
no preload script.

The F99 model gate is a 68-row VID/PID allowlist. Under the package's
`CUSTOM_VALUE=14` RK build configuration, its legal model set is model IDs
6000–6003: F99 AI, Air61, i20 AI, and N20 AI. Only F99 has explicit matching
PID rows in the allowlist (`248A:8102`, `248C:8243`, and `248A:8243`). The
other three models' precise HID routes are unresolved. A two-second scan
filters HID usage and usage-page values, matches an allowlisted VID/PID,
deduplicates paths, then opens the device through `mi-hid`. The host sends a
random challenge and checks a 32- or 35-byte
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
establish that the addon or other RK software has no lighting support. The
official F99 Mac DMG has since received a separate static UDIF/APFS-block,
Mach-O, and ASAR-carve pass. It confirms a universal Electron package with
native HID symbols, but the APFS file paths, asset ownership, and complete
Windows/macOS archive-member delta remain unresolved; see the
[macOS findings report](rk-f99-macos-static-findings-2026-10-20.md).

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

The native `mi-hid.node` addon is an x64 PE, 799,232 bytes, SHA-256
`fe68309021c9640f16a2bbd550738cf8904b3d18a1cc3a4e8b2d22ec2a2d5ee4`. Its PE
has 127 normal imports from `KERNEL32.dll` and 62 delay imports from `node.exe`.
A linear sweep records 447 direct IAT call/tail-jump candidates, including
`CreateFileW`, `WriteFile`, `ReadFile`, `DeviceIoControl`, overlapped I/O, and
handle cleanup in the `hid_*` routines. The callsite ledger is a candidate
list; framework/runtime reachability and all arguments are not fully resolved.

The addon also contains UTF-16 module names `hid.dll` and `cfgmgr32.dll` and
export-name strings for 13 HID APIs (`HidD_*` / `HidP_*`) and six Configuration
Manager APIs (`CM_*`). Direct IAT calls to `LoadLibraryW` at RVA `0x1975B` and
`0x19778`, followed by a sequence of `GetProcAddress` calls from RVA
`0x1979C`, support dynamic resolution; the exact consumer of every resulting
function pointer is not fully mapped. The dynamic-name ledger includes byte
offsets. No decoded `syscall`, `sysenter`, or `int 0x2e` instruction was found
in the executable-section linear sweep. Five raw `0F 05` byte pairs were
recorded separately; none decodes as a syscall instruction. This result is
limited to this addon and scan method, not APIs called inside Windows or other
drivers.

Reproducible native-addon ledgers and scanner:

- [Normal and delay imports](rk-f99-native-hid-imports-2026-10-19.csv)
- [Direct IAT call/tail-jump candidates](rk-f99-native-hid-callsite-candidates-2026-10-19.csv)
- [Dynamic HID and Configuration Manager name strings](rk-f99-native-hid-dynamic-api-symbols-2026-10-19.csv)
- [Decoded syscall instruction candidates](rk-f99-native-hid-syscall-candidates-2026-10-19.csv)
- [Raw `0F 05` byte pairs, separately classified](rk-f99-native-hid-raw-0f05-candidates-2026-10-19.csv)
- [Hash-pinned PE audit script](../scripts/audit_f99_native_hid.py)

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
  native-addon wrapper; extend the now-mapped device, verification, DPI, and
  OTA chains to the remaining UI and native call paths. The whole-ASAR pass
  exhausted its graph-result budget and does not provide a complete function
  map.
- Recover full call graphs and data flow for the three application families,
  including remaining R99 helper operations/return semantics, exact
  GamingForceZ UI-event-to-Writer mappings, and the remaining F99
  renderer-to-native-addon calls.
- Map all model/profile/configuration data to product and revision identifiers;
  distinguish labels and selector metadata from verified compatibility.
- Analyze the remaining firmware/QMK packages beyond the eight S98 regional
  updater variants, plus other current product-specific downloads; then expand
  to historical and regional packages.
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
