# RK Keyboard Software static audit

This document records what can be established from the RK Keyboard Software
installed on the development PC. The work is offline and static: it examines
copies of the application files, profile data, resources, imports, and strings.
It does not execute the RK utility, open a keyboard HID interface, or send
reports to a device.

The audit is broader than the initial catalog pass, but it is not a complete
hardware protocol reverse engineering. The native driver contains several
device-family paths and hardware-write operations. The static profile-to-
handler rules are now documented, but the exact firmware revision for each
model, full command schemas, and a safe active identification request are not
proven. Keydeck therefore remains descriptor-only and does not write settings,
lighting, macros, screen data, or firmware to a keyboard.

This detailed address-level report describes the installed 4.06 package. A
second official Windows Hub Driver package, version 4.6, was acquired and
extracted statically. Its package manifest, profile catalog changes, and
version-specific binary/API differences are kept in the separate
[4.6 snapshot](rk-v4.6-package-snapshot.md),
[catalog delta](rk-profile-catalog-v4.6-delta.md), and
[native binary delta audit](rk-v4.6-native-binary-delta-audit.md). Do not
carry 4.06 addresses or protocol interpretations across versions without
rechecking the changed binary.

The 4.6-labeled package's bundled `Dev/01AF/Update.exe` and `.upf` have exact
SHA-256 matches with the 4.06 updater and update package. Accordingly, the
updater-specific addresses and reports below apply unchanged to those exact
files. The changed `DeviceDriver.exe` remains a separate, incompletely traced
binary. Static V4.6 follow-ups now verify the 265 profile-to-class routes and
map the `CDevG5KB`, `CDev3632`, and 26-slot `CDevRKKB` tables. The RKKB audit
traces its worker dispatch, 24 direct deferred-settings signal callers,
selected `ApplySetting` branches, and 65-byte feature-report writer. The
signal callers still do not identify unique UI controls or prove their
receiver class. Payload schemas, device acceptance, and the full G5 protocol
remain open. See the [4.6 RKKB audit](rk-v4.6-cdevrkbb-settings-and-vtable-audit.md),
[signal caller ledger](rk-v4.6-apply-signal-callers.csv), and
[coverage ledger](../COVERAGE.md).

## Installed suite inventory

The installed `C:\Program Files (x86)\RK Keyboard Software` directory has
about 810 files (about 78 MB). It contains the main native UI/driver, an
installer setup DLL, uninstall components, profile data, skins, fonts,
localization, and a model-specific firmware updater and `.upf` image.

| Component | Static finding |
| --- | --- |
| `Cfg.ini` | App title `RK Keyboard`, version value `0x406`, default VID `0x258A`, supported PID list, languages, and 188 named `DevName` records. |
| `DeviceDriver.exe` | Native 32-bit Windows GUI PE, file/product version `1.0.6.8`, SHA-256 `C03F88BC4E2D78AA4392D7445B0FD62182DC824F97F5D5DB40BD009E547A9AB6`. |
| `Dev/*/KB.ini` | 189 model/profile configurations, including one profile folder (`01C7`) that has no matching `DevName` entry. |
| `Text/en/text.xml` | English UI labels and workflows for key mapping, Fn/tap, macro editing, lighting, sound-reactive effects, keyboard settings, screen animation, software updates, and firmware/reset actions. |
| `Dev/01AF/Update.exe` | Version `1.0.2.2`, metadata identifies Sinowealth Ltd. and “8805PH Update Tool”; a `.upf` update package is next to it. This is evidence that this profile includes a separate update path, not a validated firmware image. |

The package snapshot contains 810 files (78,070,176 bytes). The exact
relative-path, size, and SHA-256 list is in
[`rk-installed-package-manifest.csv`](rk-installed-package-manifest.csv).
The statically imported PE entrypoints for the main UI/driver, updater,
installer helper, and uninstaller are in
[`rk-native-api-imports.md`](rk-native-api-imports.md). The import report
lists declared native APIs; it does not imply that each API executes on every
run or that every runtime call is known. Address-level IAT cross-references
for 1,915 ordinary imports and three delay imports (1,918 rows total) are in
[`rk-native-api-xrefs.csv`](rk-native-api-xrefs.csv). That CSV records direct
x86 `call [IAT]` sites, caller instructions that target import thunks,
import-forwarding `jmp [IAT]` sites, and other absolute IAT references found
in executable sections. Dynamically resolved API names and nearby literal
strings are separately recorded in
[`rk-dynamic-api-targets.csv`](rk-dynamic-api-targets.csv). That inventory has
128 statically identified `LoadLibrary*`/`GetProcAddress` callsites across the
five PEs. These are static byte/address-level references, not a function-level
call graph or a record of executed system calls. The import, IAT-reference,
dynamic-loader, and raw system-call byte-scan inventories are reconciled in the
[system API crosswalk](rk-system-api-crosswalk.md).

The static profile selector for every configured model is captured in
[`rk-profile-driver-family-map.csv`](rk-profile-driver-family-map.csv). It
records profile code/name, USB IDs, raw `Fw` and `Psd` values, wireless IDs,
and the handler selected by the audited binary's `Fw` branch. It is a
software-catalog mapping, not physical-device validation.

The package-wide extension census is 295 PNG, 284 TXT, 190 INI, 22 XML, 4
BMP, 4 TTF, 3 EXE, 2 DLL, 2 GIF, 1 DAT, 1 ICO, and 1 SKN file, plus one UPF
firmware package. Each of the seven UI localization XML files contains 247
intended leaf keys. `Text/Japanese/text.xml` is malformed at `tc_screen1`:
the closing token is `/tc_screen1>` and lacks its opening `<`. An
in-memory-only normalization recovers the same 247-key set; the installed XML
was not modified. Locale values are not identical; exact-string comparisons
and file-by-file findings are in the [resource and localization audit](rk-resource-localization-audit.md).
Static PE dialog-template controls are inventoried separately in the
[dialog-resource audit](rk-dialog-resource-audit.md); those templates do not
expose the full runtime-generated MFC interface.
The manifest covers all remaining assets, but this static pass has not
assigned a semantic meaning to every individual image, animation frame, skin,
or font.

The app's resource paths form this local data graph:

| Resource path or pattern | Role evidenced by code, strings, or profile data |
| --- | --- |
| `Cfg.ini`, `lang.ini` | Global models, defaults, and language selection. |
| `Dev/%04X/KB.ini` | Per-model capability, layout, layer, display, firmware, LED, and wireless fields. |
| `Text/<language>/text.xml` | UI labels and messages; Japanese XML has a malformed `tc_screen1` closing token (missing `<`), while an in-memory normalization recovers the same 247-key set. |
| `Dev/{en,Japanese,Korean,sc,tw}/led.xml`; selected `Dev/<profile>/{en,sc}/led.xml` | Five generic localized LED-name resources have 60 leaf labels each. Ten profile-specific resources exist for `014E`, `015B`, `01C7`, `020B`, and `023D` in English and simplified Chinese; `014E` has three labels per locale and each other profile has 13. These labels correspond to profile LED slot counts, but do not define the meaning of the six values in each `LedOpt*` tuple or its device command. A separate trace confirms dynamic `LedOpt%d` loading and only a partial tuple-to-record/UI bridge; see the [lighting profile-to-record audit](rk-lighting-profile-record-path-audit.md). |
| `keyimg.png`, `kbled.png` | Model UI/keyboard illustration assets. |
| `Dev/%04X/screen.gif`, `%04X/screen_img%d.png`, `gif_delay.gcc` | Per-device screen GIF, decoded PNG frame cache (up to 512 stale frames are purged), and a four-byte playback-delay cache. |
| `Dev/%04X/ET/*`, `Dev/%04X/Cartoon/*`, global `ET/*` / `Cartoon/*` | Effect and animation assets with profile-specific and global fallbacks. |
| `%s\\%s.mck`, `MacroDir`, `MacroHasMsKey`, `%s mac.dct` | Per-macro storage, index/directory metadata, mouse-event marker, and concatenated macro records. Native code reads/writes `0x342`-byte records; `.mck` saves rotate bytes right by two bits and imports rotate them left by two. |
| `audio.dct` | Local `0x24`-byte audio-visualization configuration record; its exact parameter-to-UI mapping is not decoded. |
| `%CSIDL_PERSONAL%\\Log.txt` | Runtime debug log; initialized by `FUN_0040CAA0` and appended by `FUN_0040C9F0`. |
| `%sOther\\%04X_%04X\\start.exe` | A reachable `CreateProcessW` path constructs an optional per-device helper path from profile VID/PID. The external helper binary and its behavior are not in this package snapshot. |
| `Dev/%04X/Update.exe`, `update_version.xml` | Per-profile updater and software-update manifest path. The main app reads optional `UpdateURL` from `Cfg.ini`; otherwise it uses `http://www.rkgaming.com/Work/Update-Single/` or `.../Update-RGB/`, adds `update_version.xml?timestamp=%x`, and calls `URLDownloadToFileW` at thunk callsite `0x403DFB` after clearing the URL cache. Payload URLs depend on runtime XML/config. No download was performed. |

The executable's native imports include SetupDi device enumeration, HID
attributes/capability queries, `HidD_GetFeature`, `HidD_SetFeature`, file read
and write functions, and URL download support. Extracted symbols and strings
include `CDevRKKB`, `CDevG5KB`, and `CDev3632` families; key matrix, macro, LED,
system-parameter, screen-page/frame, and firmware-update routines; and error
messages for feature reports. This establishes that the software has multiple
device implementations and writes to hardware. It does not by itself establish
the meaning or safety of a report.

### Ghidra traces of the native driver

Ghidra 12.1.4 analyzed a byte-identical working copy of `DeviceDriver.exe`.
The driver has imports for HID setup and feature reports. Its enumeration path
gets the HID interface GUID, enumerates device interfaces with SetupAPI, opens
each interface, obtains preparsed HID data and attributes, and reads top-level
capabilities plus button/value capability tables. The default `CreateFileW`
access mask in this path includes read/write access, although this code path
does not itself issue a feature report.

The driver initializes 188 named model rows from the configured PID list.
For each profile code, it opens `Dev/<code>/KB.ini`, reads that profile's VID,
screen flag, firmware/device-type fields, and optional wireless VID/PID, and
falls back to the configured default VID when the profile has no override.
An additional `01C7` profile directory has no configured model row. The
device-change path parses Windows HID interface paths, checks whether a
profile matches, and schedules follow-up scans. The matcher compares USB IDs
and HID usage/report-capability criteria before selecting a driver family:
the 125 `Fw=0` rows route to `CDevRKKB`, and the 63 nonzero-`Fw` rows route to
the G5 wrapper. This is the static selection rule in this installed build;
it does not validate which firmware revision a physical model runs.
The window setup code also registers notifications for the USB-device and HID
interface classes and has arrival/removal timer paths; the register-indirect
calls, GUID bytes, and event-handler limits are documented in the
[HID enumeration and notification audit](rk-device-enumeration-notification-audit.md).

The checked profile-family CSV has 188 rows and marks every named row as a
direct profile. All omit an explicit profile VID and `DevTy`, so the configured
default VID `0x258A` applies. Of the 125 `Fw=0` rows, 124 omit the field and
use its zero default; `015B` explicitly sets zero. The 63 nonzero rows split
into 53 `Fw=1` and ten `Fw=2` profiles. The `Fw=2` profile IDs are `01DE`,
`01D0`, `01CB`, `0215`, `0222`, `020C`, `0210`, `0225`, `01F4`, and `0207`;
their names and raw fields are in the row-by-row map. Separately, the online
wireless/companion path contains a conditional path that can construct
`CDev3632` after descriptor and six-byte checks. The compared bytes' provenance
is unresolved, so this does not prove a successful model-level `Psd` match.
Thus the CSV's `static_handler` is not a complete model of the dynamic
transport path.

`FUN_004155C0` applies different descriptor criteria by profile family. For
`Fw=0`, the inspected branch accepts a vendor-defined usage-page/report
pattern (`FF00`/usage 1 with report marker `0x41`) or a consumer-usage
alternative. For nonzero `Fw`, it accepts the inspected `FF00`/`FF02`
usage/report pattern (`0x208`) or a consumer-usage alternative. Exact matching
still depends on the full descriptor and the branch's other fields; this is
not enough to safely identify every firmware revision.

Wireless IDs have a separate classifier in `FUN_004474D0`. It recognizes
hardcoded pairs `3554:FA09` and `05AC:024F` as class 1, and
`258A:0030`, `258A:0148`, `258A:0150`, and `258A:01BB` as class 2, then checks
the profile table's wireless VID/PID columns for further class-2 matches. A
global-option branch also recognizes `1480:6461` as class 3. For recognized
special IDs, the device-change path skips the ordinary direct-profile ID
loop and gates an online/wireless scan. In the seven catalog profiles with
wireless IDs, the pairs are `258A:0150` (A70), `258A:01BB` (M100 and R98Pro),
`3554:FA09` (M70 DE/FR), and `258A:0233` (X87). The hardcoded M70 pair is
class 1; the other listed profile pairs are class 2. This is evidence of
special matching behavior, not proof that every receiver is an RK keyboard.

`FUN_00415900` (VA `0x00415900`) scans 0x12-byte rows beginning at
`DAT_006102A0`. It requires nonzero VID/PID and nonzero `Fw`, then compares the
incoming six bytes against row offsets `+0x04..+0x09` (instructions
`0x00415995`–`0x004159C9`; the row pointer advances by `0x12` at
`0x00415A4C`) before its conditional `CDev3632` construction path. In the
analyzed binary, `FUN_00447210` (VA `0x00447210`) first clears `0x102C` bytes
at `DAT_006102A0` (callsite `0x0044723F`), then loads VID, PID, `ShowScreen`,
`Fw`, `DevTy`, `VID_Wireless`, and `PID_Wireless` from `KB.ini` at callsites
`0x004472FC`, `0x0044736A`, `0x004473A7`, `0x004473E5`, `0x00447422`, and
`0x00447460`, respectively; it does not load a `Psd` key.
The static xrefs collected for this table show `FUN_00447210` as its initializer
and direct writer, while `FUN_004156E0`, `FUN_00415900`, and `FUN_00447591`
read it. This scan does not exclude writes through aliases or other indirect
paths. Accordingly, the relationship between the compared row bytes and the
`Psd` strings in `KB.ini` is unresolved; the available static evidence does not
show those profile signatures being populated into the compared bytes. The
full online transition sequence and hardware behavior also remain unresolved.

The profile catalog has 63 `Psd` values but only 58 unique normalized
signatures. These are catalog facts, not proof that the binary loads the
strings into the comparison table.
Three signatures are shared across variants: `0A 00 00 00 00 06` (F75 wired
and three-mode), `03 00 00 00 00 6E` (R65 RGB wired and non-wireless), and
`0A 00 00 00 00 22` (four R98Pro regional/variant profiles). If populated as
match keys, those values would not uniquely identify every model. The function
walks rows in configured PID order, but the loader does not establish that
these catalog signatures are the bytes it compares. The eight S98
`Psd` values in the catalog are unique, though the table-loading caveat above
means this does not validate the classifier against a physical keyboard.

The Ghidra listing gives this initial function-level map. The `FUN_` names
are auto-generated names, not original RK symbols:

| Function | Static behavior observed |
| --- | --- |
| `FUN_004164b0` → `FUN_00416570` | Enumerate HID interfaces with SetupAPI, open an interface, collect attributes and report capabilities, then record descriptor metadata. |
| `FUN_00447090` | Clear and repopulate the main device table by invoking HID enumeration. |
| `FUN_00447210` | Zero `0x102C` bytes at `DAT_006102A0`, then load model VID/PID, `ShowScreen`, `Fw`, `DevTy`, and wireless IDs from per-model `KB.ini` files. It does not load `Psd` into this table. |
| `FUN_00447591` | Handle device-change paths, match IDs, and schedule follow-up device detection. |
| `FUN_004155C0` | Match profile VID/PID and HID usage/report capabilities; route `Fw=0` profiles to RKKB and nonzero-`Fw` profiles to G5. |
| `FUN_004474D0` | Classify known wireless IDs and profile wireless VID/PID pairs before the online/wireless scan. |
| `FUN_00415900` | Compare wireless profile VID/PID, nonzero-`Fw`, and row bytes `+0x04..+0x09` before a possible 3632 construction. Their correlation with `KB.ini` `Psd` is unresolved because the table loader does not populate a `Psd` field; indirect writes are not excluded. |
| `FUN_0040f700` | G5 feature-report transport, 520-byte reports and 512-byte payload chunks. A read operation first sends a feature report, then calls `HidD_GetFeature`. |
| `FUN_00412b10` | G5 screen/page transfer path with chunking, acknowledgements, an optional one-byte additive complement, retries, progress, and cancellation. |
| `FUN_0040d7e0` | Separate 3632 transport with 20-byte packets and 14-byte data chunks plus checksum/retry handling. |
| `FUN_00413220` | RKKB 65-byte feature-report writer with up to 62 payload bytes. |
| `FUN_00411b90` | Shared G5/3632 settings orchestrator for matrix layers, macros, lighting, RGB tables, and game/color groups. |
| `FUN_00411260` | Key data mapping across four layers of 132 positions. |
| `FUN_00411700`, `FUN_00411900` | Two settings packers. Embedded logs label debounce, tap, and sleep fields at different indices (`Cfg[2]/[8]/[9]` in one path; `Cfg[3]/[22]/[24]` in another), so record layouts vary by path/version. |
| `FUN_004513B0` | Candidate profile initialization path; reads `DebounceUI`, `MacroBufferNum`, `RGBIndex`, `MusicRGBIndex`, `ShowSleepTime`, LED mask/config options, and dynamically formatted `LedOpt1`–`LedOpt24` keys into runtime state. The `LedOpt` to record/UI path is partial; see the [lighting profile-to-record audit](rk-lighting-profile-record-path-audit.md). |

The main executable's complete PE import table contains 672 imported entries
across 21 DLLs. The updater contains 618 entries across 19 DLLs. The detailed
inventory also includes installer and uninstaller components. Imports show
that the main executable declares `URLDownloadToFileW` and
`DeleteUrlCacheEntryW`, but no WinHTTP or Winsock functions. The updater
declares serial communication APIs (`SetCommMask`, `Get/SetCommState`,
`SetCommTimeouts`, `WaitCommEvent`, `ClearCommError`) as well as HID APIs.
Its generic serial-open routine at `0x00404E60` opens the supplied path with
read/write access and overlapped I/O, then sets a communication mask (`0x81`),
applies a caller-populated DCB, and sets timeouts. `0x00405170` waits for
communication events and performs overlapped reads with error/status checks;
`0x00405370` handles overlapped event completion/cancellation; and
`0x00405430` performs an overlapped read, checks/clears communication errors,
and forwards received bytes to an internal queue/callback. The write worker at
`0x00405640` sends queued bytes through `WriteFile` and checks completion.
The call chain is `FUN_00407E00` state-machine case `0xF` →
`FUN_004091B0` → `FUN_00404E60`. It passes a path and baud rate, with 8 data
bits, no parity, and one stop bit. Embedded class strings identify a UART
update-tool code path. This proves the updater contains a reachable serial
transport setup path, but not that it serves the same keyboard workflow as the
HID path. The exact keyboard mode that enters it and the serial command bytes
are unresolved. See
[`rk-native-api-imports.md`](rk-native-api-imports.md) for every statically
imported entrypoint.

Other updater file-call references were classified where decompilation made
their roles clear. HID interface opens occur in `FUN_00406730`,
`FUN_00406900`, `FUN_00409A50`, and `FUN_0040CFC0`. The `DeleteFileW` sites
`0x00425A8D`/`0x00426163` are MFC autosave cleanup, and `CopyFileW` at
`0x0040EC85` copies an OLE file medium. `SetFilePointerEx` references occur
in CRT seek helpers. The firmware chooser's path reaches CRT file I/O rather
than a direct `ReadFile` import: `FUN_0040C2F0` calls `FUN_0040A940`, which
opens the selected package for binary reading, parses metadata/length/version
fields, seeks through payload sections, and reads them into memory; later
`FUN_0040BB10` copies loaded payload data into the updater's HID transfer
buffer. This is host-to-device update staging evidence, not device-to-host
firmware dumping. The parser's mode branches and partial section mapping are
described below; the bundled file's declared lengths are inconsistent with
its actual size, and no successful parse was observed.

### Installer and uninstaller components

`InitSetup.dll` is an x86 setup helper with one `SetupInit` export (file
version `1.0.0.2`, RVA `0x1080`). It accepts one path. Null returns false;
missing path logs an AppData-path message and returns true; an existing path
calls recursive worker `0x100010F0`. The worker enumerates `path\*.*`,
using `FindFirstFileW` at `0x100011DD` and `FindNextFileW` at `0x1000127F`.
It recurses into child directories at `0x1000124D`, normalizes file attributes
to `0x80` with `SetFileAttributesW` at `0x10001265`, deletes files through a
dynamically resolved `DeleteFileW` pointer at `0x10001273`, normalizes nested
directory attributes at `0x100012D1`, and removes nested directories with
`RemoveDirectoryW` at `0x100012D8`. Recursive errors can be logged, but the
export still returns true for any non-null path. Disassembly of compiled
script records in `unins000.dat` statically links `MyAfterInstall` to this
export with `%LOCALAPPDATA%\RKKB` as its expanded argument. This proves the
script-level call and path, but not that the callback ran or the helper was
loaded. See the [installer/uninstaller script audit](rk-installer-uninstaller-script-audit.md).

`uninstall.dll` has no exports and contains icon/bitmap resources; its imports
are runtime support only, with no network, keyboard, HID, or service behavior
identified. The uninstaller `unins000.exe` is an Inno Setup 5.3.4 engine. The
installed `unins000.dat` log records the Program Files tree,
`%LOCALAPPDATA%\RKKB\lang.ini`, Start Menu and Desktop shortcuts, and
uninstall registry key
`Software\Microsoft\Windows\CurrentVersion\Uninstall\{F5704F18-47C0-41F4-ABF6-0B85B099288E}_is1`.
It names callbacks including `InitializeSetup`, `MyAfterInstall`,
`MyAfterInstall2`, `CurUninstallStepChanged`, and
`InitializeUninstallProgressForm`. Offline disassembly of two compiled script
records shows both call `SetupInit` from `MyAfterInstall` with the expanded
`{localappdata}\RKKB` path. The second script record adds Turkish, Japanese,
and Korean language-index branches. The records establish callback bodies,
not which snapshot the engine selects or whether any callback ran. See the
[dedicated script audit](rk-installer-uninstaller-script-audit.md) for the
disassembly findings and open questions.

`unins000.exe` has no HID, SetupAPI, or Service Control Manager imports. It
dynamically resolves `RegDeleteKeyExW/A` for generic uninstall registry
cleanup (wide resolver at `0x0047F8E0`; name resolution near
`0x0047F93C`/`0x0047F95C`). Its `DeviceIoControl` call at `0x004804B4` uses
`FSCTL_SET_COMPRESSION` on a file handle, not a keyboard handle. A conditional
shutdown path at `0x004AE9CC` calls `ExitWindowsEx` at `0x004AEA38` with
`EWX_REBOOT`; caller `0x004F5BAC` exists, but runtime conditions determine
whether a reboot is requested. The callback bodies are now statically
disassembled, but the exact engine dispatch sequence and runtime effects were
not executed or established.

The address-level IAT cross-reference CSV classifies these import entries and
static executable-section references:

| Binary | Import entries (ordinary + delay) | Direct `call [IAT]` sites | `jmp [IAT]` thunks | Relative calls to thunks | Other absolute references |
| --- | ---: | ---: | ---: | ---: | ---: |
| `DeviceDriver.exe` | 675 (672 ordinary + 3 delay) | 6,353 | 105 | 601 | 853 |
| `Dev/01AF/Update.exe` | 618 | 7,391 | 55 | 53 | 590 |
| `InitSetup.dll` | 76 | 148 | 1 | 2 | 27 |
| `uninstall.dll` | 30 | 21 | 10 | 12 | 6 |
| `unins000.exe` | 519 | 0 | 536 | 2,698 | 0 |

The counts are sums of addresses listed in the CSV, including the delay-import
thunks and callers for the three `OLEACC.dll` entries in `DeviceDriver.exe`.
The CSV preserves each address, including calls to imported file, registry,
UI, HID, audio, graphics, timing, thread, and network APIs. Absolute byte
references can include data or unreachable code; these counts do not equal
unique source-level operations or runtime executions. Windows syscalls made
inside imported APIs and driver stacks are outside this static user-mode PE
scan. Dynamic targets in the updater are mostly compatibility/framework APIs
such as transacted file/registry operations, task dialogs, DWM/theme functions,
and file-system helpers; literal strings are evidence for candidate names,
not proof that the branch executes.

The five analyzed PEs do not import `ntdll.dll`, and no plausible direct
syscall wrapper was identified. A raw opcode scan of executable sections
found these `0F 05`, `0F 34`, and `CD 2E` byte patterns:

| PE | `0F 05` | `0F 34` | `CD 2E` |
| --- | ---: | ---: | ---: |
| `DeviceDriver.exe` | 5 | 4 | 1 |
| `Update.exe` | 4 | 2 | 0 |
| `InitSetup.dll` | 0 | 1 | 0 |
| `uninstall.dll` | 0 | 0 | 0 |
| `unins000.exe` | 1 | 0 | 0 |

The Ghidra listing marks `syscall` mnemonics at `0x464224` and `0x464354` in
`DeviceDriver.exe` as lookup-table data, with no reachable call path recovered.
Those byte addresses are in `.text`, so section permissions alone do not
establish the classification. Other raw matches overlap call displacements,
immediates, or data. No
`sysenter` or `int 0x2e` instruction path was decoded. This is not a runtime
system-call trace and cannot rule out transitions inside imported Windows
libraries, dynamically loaded modules, COM servers, or device drivers. COM
methods reached through interface vtables, unresolved dynamic function
pointers, and kernel-level calls remain outside the import/xref inventory.

The main app also uses classic OLE/COM APIs: `CoInitialize`/`CoInitializeEx`,
`CoCreateInstance`, `CoGetClassObject`, CLSID conversion, clipboard,
drag/drop, storage/stream, menu, and accelerator functions. `CoCreateInstance`
callsites include `0x4049E4`, `0x43C85D`, `0x45B094`, and `0x47BD42`;
`RegisterDragDrop` is called at `0x55C8D8` and `DoDragDrop` at `0x50DC0A`.
COM interface calls then dispatch indirectly, including calls through
`[ecx+0x50]` at `0x4049F8`, `[ecx+0x2C]` at `0x404A05`, and `[ecx+0x0C]` at
`0x4ACA6A`; the target methods are unresolved.

`Update.exe` loads `combase.dll` with `LoadLibraryExW` at `0x53746F` and
resolves `RoInitialize`/`RoUninitialize` at `0x537476`/`0x53754B`. Its wrapper
calls `RoInitialize(1)`, which is WinRT framework initialization evidence,
not a keyboard protocol.

Further resolver call-flow tracing classified these additional targets:

- `DeviceDriver.exe` loads `User32.dll` at `0x450606`, resolves
  `SetProcessDPIAware` at `0x450618`, and calls it at `0x450622` when present.
  It loads `MenuEx.dll` at `0x4332A6` and resolves `SetMenuAlign`,
  `DllPreTranslateMessage`, and `CreateMenuEx` at `0x4332C3`, `0x4332DF`,
  and `0x4332F4`; nearby exports include `DestroyMenuEx` and `SetGdiInit`.
  The GDI compatibility path obtains `GDI32.DLL` at `0x470EE7`, resolves
  `GetLayout` and `SetLayout`, and invokes the resolved pointers on an HDC.
  Registry cleanup resolves `RegDeleteKeyExW` at `0x4A5418` and falls back to
  imported `RegDeleteKeyW`.
- `Update.exe`'s helper at `0x416570` resolves Kernel32 activation-context
  APIs: `CreateActCtxW`, `ActivateActCtx`, `DeactivateActCtx`,
  `FindActCtxSectionStringW`, `QueryActCtxW`, and `GetModuleHandleExW`.
  The activation-context path at `0x4165B6` then loads `Comctl32.dll` at
  `0x416769`, consistent with side-by-side common-controls setup.
- `InitSetup.dll` loads `USER32.DLL` at `0x10009450` and resolves
  `MessageBoxA`, `GetActiveWindow`, `GetLastActivePopup`,
  `GetUserObjectInformationA`, and `GetProcessWindowStation` at
  `0x1000946C`, `0x10009489`, `0x1000949E`, `0x100094B3`, and `0x100094CB`.
  These pointers support modal/error-window handling.
- `unins000.exe` conditionally loads Advapi32 at `0x4B6BDB` and resolves
  `GetNamedSecurityInfoW`, `SetNamedSecurityInfoW`, and `SetEntriesInAclW`
  while preparing ACL updates. Its `LoadLibraryExA` import-thunk call at
  `0x4A1596` is included in the 128-row callsite inventory; no nearby target
  string was recovered for that site.

These are Windows UI, compatibility, registry, and uninstall-permission
flows. Their presence in the PE does not show that each conditional branch
executes in a normal session.

Targeted callsite inspection narrowed several potentially ambiguous imports:
the main app's `SetWindowsHookExW` references use thread-scoped CBT,
MSGFILTER, and mouse hooks; the inspected updater sites likewise use UI-hook
IDs, not `WH_KEYBOARD` or `WH_KEYBOARD_LL`. This does not prove the absence of
all input observation, since key-state APIs are also imported and runtime
branches are unknown. The optional `CreateProcessW` path may launch the
external per-device `Other\\<VID>_<PID>\\start.exe` helper when present.
No Service Control Manager APIs were found. `unins000.exe` imports
`DeviceIoControl`, but its one inspected call passes `FSCTL_SET_COMPRESSION`
(`0x9C040`) with a file-compression input on a file handle; it is not a
keyboard/USB IOCTL. Its `ExitWindowsEx` import has a callsite, but static
analysis does not establish that the uninstall flow invokes that branch.

The `HidD_SetFeature` references found in the selected DeviceDriver analysis
occur at `0x40F14D`, `0x40F87F`, `0x40FBBE`, `0x40FE01`, `0x410062`,
`0x4104EF`, `0x412D3F`, and `0x4132F6`. The corresponding selected
`HidD_GetFeature` references are at `0x40F1A5`, `0x40F8F1`, `0x40FC19`,
`0x40FE5C`, `0x4100C1`, and `0x41054E`. These are static callsite addresses
inside `DeviceDriver.exe`, not verified commands and not safe replay data.
The call pairs at `0x40FE01`/`0x40FE5C` implement the two-byte `GetPower`
response (`0x87`); `0x410062`/`0x4100C1` belong to `GetRealData` (`0x88`),
which reads a caller-requested response length in 512-byte chunks. Both paths
send a feature request before `HidD_GetFeature`.

Additional UI and persistence paths have candidate function starts inferred
from call references, strings, and code boundaries (medium confidence):
`0x403270` update callbacks; `0x403E20` update worker; `0x40DD60`
`WriteMacroData`; `0x42CC80` macro creation and magic validation; `0x42D490`
macro import chooser; `0x42E480` macro record import/validation; `0x42D960`
macro export; `0x42E320` dirty macro flush; and `0x45A310` macro save. Audio visualization configuration
and processing candidates include `0x43BEE0` and `0x438810`; the confirmed
WASAPI capture path is at `0x43C780` (details below). `0x412890` handles
screen GIF parameters, and `0x4663C0` is a
screen burn workflow that passes frame count/timing and supports cancel/retry.
These candidates are not original symbols; the embedded PDB path refers to a
missing PDB, so type and original method names are unavailable.

Further decompilation confirms separate local persistence paths. `FUN_00428600`
reads or writes fixed `0x342`-byte `.rkm` records. `FUN_00459FC0` builds a
record with magic `0xFAFB88A0`, a timestamp, and fields at offsets `0x0c`,
`0x14`, `0x68`, and `0x6a`. `FUN_0045A0A0` copies exactly one record into the
global macro list, and `FUN_0042CC80` validates the magic before inserting or
cloning one. `FUN_0045A310` overwrites `mac.dct` and concatenates eligible raw
records without per-record transform or file header; the node must pass
nonzero-field checks at record offsets `+4` and `+0x6a`.

RTTI ties the 13-entry map at `0x005CD498` to `CMacroDlg`; its vtable is
`0x005CDE3C` and its complete-object locator is `0x005E3FC0`. The constructor
starts at `0x00426140`; the destruction path through `0x004263E0` and
`0x00426400` calls `FUN_0045A310` before teardown at `0x0042643B`. The main
dialog's command `0x6401` sends `WM_CLOSE` to windows named
`OemDrvMacroTopWindow` and `OemDrvMsgTopWindow`, but the static image does not
prove which runtime object owns the named macro window. The destructor-to-file
save route is proven for `CMacroDlg`; connecting it to a particular close
event remains unresolved.

The `.mck` save path (`FUN_0042E320`) rotates each byte in the full record
right by two bits before writing and requires an exact `0x342`-byte write.
The paired import flow (`FUN_0042D490` → `FUN_0042E480`) opens a selected
`.mck`, reads exactly `0x342` bytes, rotates left by two bits, checks the
decoded magic, and applies key compatibility and device-size checks before
adding a copy. `FUN_0042D960` exports by copying the encoded internal file to
the selected destination. The local import/export/persistence routines use
file APIs such as `CreateFileW`, `ReadFile`, `WriteFile`, and `CopyFileW`; the
inspected routines do not call HID. The format's outer size, magic, and
rotation are known, but the complete event encoding is not.

Screen artwork is decoded from each device's `screen.gif` into cached
`screen_img%d.png` frames by `FUN_0046C9F0`; it can delete up to 512 old frame
files before saving the new cache. `FUN_0046D900` regenerates PNG frames.
`FUN_0046ACC0` and `FUN_0046ADC0` read/write `gif_delay.gcc` as four bytes.
These are local file operations. The debug log path is initialized as
`%CSIDL_PERSONAL%/Log.txt` by `FUN_0040CAA0` and appended by `FUN_0040C9F0`.
`FUN_00403270` compares `WM_COMMAND` `lParam` against the language-combo child
and passes its selected index to `FUN_00403170`, which reloads the selected
`Text/<language>/text.xml` and writes `LangIndex` to `lang.ini`; the visible
label-to-control link is still unresolved. See the [resource and localization audit](rk-resource-localization-audit.md).
MFC profile wrappers can write to INI or registry storage depending on the
active profile mode. Audio paths read a text configuration into an in-memory matrix
(`FUN_0043BEE0`), build an audio-visualization structure (`FUN_00438810`), and
read/write the `0x24`-byte `audio.dct`. The loopback acquisition/capture
lifecycle is implemented separately at `FUN_0043C780`, described below; the
exact relationship between these settings and the resulting music packets is
still unresolved.

The decompiled `CDevG5KB::AccessData` path confirms a 520-byte
(`0x208`) feature report. The observed buffer fields are:

| Offset | Static observation |
| --- | --- |
| 0 | report ID supplied by the caller |
| 1 | command value supplied by the caller |
| 2 | caller-supplied option byte |
| 3 | zeroed field in the inspected path |
| 4 | total packet count |
| 5 | packet index |
| 6–7 | current payload length, little-endian |
| 8–519 | payload area, up to 512 bytes |

The inspected function divides transfers into 512-byte pieces. Its operation
value `1` copies caller data into the report before `HidD_SetFeature`; value
`2` also performs `HidD_GetFeature` and copies the response back. The read path
therefore begins by sending a feature report too. It retries failed writes,
waits between attempts, and checks that the response command matches. These
observations explain why the clone must not issue a “harmless read” probe to
identify a model.

Additional named paths in the decompilation include `GetLED` (command `0x84`),
`GetPower` (`0x87`), a password path (`0x82`), and a `GetRealData` path
(`0x88`). A screen-descriptor check also sends report ID `9` with command
`0x82`, then reads and compares six descriptor bytes. A page-transfer helper
named `AccessData_Page` sends command `0x0c` through 520-byte reports, checks
acknowledgments, compares an optional one-byte additive complement, and retries
pages. A separate
`CDevRKKB::WriteDevice` path builds 65-byte (`0x41`) feature reports with
report ID `10`, packet count/index, and up to 62 bytes of payload.

The HID callsite report and targeted decompilation expose several additional
paths. Every path below that calls `HidD_SetFeature` is an active command path;
none was invoked during this audit.

| Routine | Static behavior and evidence | Limits |
| --- | --- | --- |
| `FUN_0040f030` | Scans candidate screen-device descriptors, opens matching handles, sends report ID `9` / command `0x82`, reads six bytes, then compares them with the keyboard profile's six-byte `Psd`. Its log says “Found screen dev, read psd now.” | This is a descriptor-matching transaction, not a passive descriptor read. The data's origin and exact selection path remain open. |
| `FUN_004103e0` | A helper logs `GetPassword failed`, uses command `0x82`, option `1`, and handles a caller-supplied response length in 512-byte chunks; each feature request is sent before response read and command matching. | The caller, exact payload meaning, and reason for the “password” label are not recovered. Keep this separate from screen-profile matching, which uses command `0x82` on report ID `9` to read six `Psd` bytes. |
| `FUN_0040fd10` | `GetPower` command `0x87`; sends a one-report request for two bytes, validates response command `0x87`, then copies the bytes into separate DWORD outputs. | The meaning and units of the two bytes and the caller are unknown. |
| instruction-aligned helper at `0x0040FF60` (older overlapping decompiler label `FUN_00410045`) | `GetRealData` command `0x88`; sends a request and copies caller-requested response bytes from chunks of up to 512 bytes. | The caller and returned-data semantics are unresolved. It is not evidence of firmware-memory access. See the [4.06 G5 vtable audit](rk-406-cdevg5-vtable-audit.md). |
| `FUN_0040fad0` | LED configuration read: G5 command `0x84` requests 128 bytes; 3632 delegates command `0x44`. The G5 path sends a feature report before reading and validates trailing bytes `5A A5`. | This is a read-modify-write step in LED settings apply, not a passive probe. |
| `FUN_0040f600`, `FUN_004131c0` | Connection checks call `HidD_GetAttributes` on an existing handle, or `CreateFileW` and immediately `CloseHandle` on a stored device path. | These checks establish openability/handle state, not the exact keyboard model or its firmware. |
| `FUN_00416740` | Descriptor processing calls `HidP_GetSpecificButtonCaps` and `HidP_GetSpecificValueCaps` for input, output, and feature report types. | It examines HID capabilities; no device feature report is sent in this routine. |

The central settings path exposes the order of several save flows. The
3632-facing `FUN_0040e690` wrapper checks a busy flag, waits 200 ms, then calls
the shared `FUN_00411b90` orchestrator. The orchestrator branches to G5
`FUN_0040f700` or the 3632 routines `FUN_0040d7e0`/`FUN_0040dd60` based on
the device object. Depending on dirty flags, it serializes key matrices and
writes selected layers, serializes macro data, reads then modifies and writes
the lighting configuration, sends a custom LED RGB table, and writes game/color
groups. Its log strings distinguish `SetMatrix`, `SetMacro`, `SetLED`,
`SetLedRgbTab`, and `SetGame` failures. This gives a feature-to-path map, but
the decompiler output does not fully recover the meaning of each matrix byte,
all flag bits, or every caller's UI action.

The UI labels and static call paths support this more specific feature map:

| Feature | Native operation path observed | Limits |
| --- | --- | --- |
| Keymaps and layers | Shared G5/3632 apply uses `FUN_00411260`, then G5 command `3` or 3632 command `1`. RKKB `FUN_00413BF0` invokes `FUN_00413B20` four times to translate four layers of 132 16-byte records into 132-DWORD layers. | The `[KEY]` parser maps cells 1–10 into coordinate arrays and base action records; cell 8 feeds the RKKB 132-slot lookup byte. Construction of the four runtime layers from profile/Fn/UI state, lookup-table contents, picker commit, and the relation of translated buffers to fixed `01 F8`/`10 F8` reports remain unresolved. The separate `04 00` plus `0x780` write is macro-staging context, not a proven complete keymap transfer. See the [keymap translation audit](rk-keymap-translation-audit.md) and [profile-to-UI path audit](rk-keymap-ui-path-audit.md). |
| Macros | Apply-setting associates sequential macro-buffer IDs with mapped keys. `.mck` import/export uses a fixed 834-byte record and reversible byte rotation; profile-local `mac.dct` stores raw concatenated records. Dirty macro data reaches G5 command `5`, the 3632 path `FUN_0040DD60`, or an RKKB three-byte event compactor. | A static follow-up maps CMacroDlg custom-message handlers and dirty flags, but no physical-input producer, event-row constructor, recorder start/stop route, or complete G5/3632/RKKB wire schemas is recovered. See the [macro format and path audit](rk-macro-format-and-path-audit.md) and [macro capture audit](rk-macro-capture-path-audit.md). |
| Lighting and colors | `FUN_0040FAD0` obtains LED/config data; packers `FUN_00411700`/`FUN_00411900` feed G5 command `4` or 3632 command `4`. RGB slot tables use `FUN_004101B0` (G5 command `10`, 3632 command `9`); color groups use G5 command `6` or 3632 command `2`. | The `FUN_0040FAD0` read path sends command `0x84` through `HidD_SetFeature` before `HidD_GetFeature`; this is not a passive probe. RGB values are logged by `FUN_0040CD70`, which is a debug formatter and does not transform the buffer. Slot and tuple semantics remain incomplete. |
| Audio-reactive data | `FUN_0043C780` captures the default render endpoint with WASAPI loopback and computes visualization bands; `FUN_00413340` sends music data through RKKB writer `FUN_00413220`. | A static follow-up maps default-render loopback capture and 24 visualization bands separately from the RKKB music writer; the dataflow between them, UI/settings routes, and output fields remain unresolved. Capture and HID writes were not run; see the [audio-reactive path audit](rk-audio-reactive-path-audit.md). |
| RKKB lighting, key color, and Fn | `FUN_00413BF0` has static bit-`0x02` LED-data, bit-`0x04` per-key-color, and bit-`0x01` translation, macro-staging, matrix, and conditional Fn branches, all using `FUN_00413220`. | Command framing, translation bounds, and several prefixes/lengths are recovered. The `04 00` plus `0x780` block is built from macro staging in the observed caller context; its full schema, field meanings, global flag provenance, and UI/profile gates remain open. See the [keymap translation audit](rk-keymap-translation-audit.md) and [settings serializer audit](rk-setting-serializer-audit.md). |
| Screen and GIFs | G5 screen parameters use command `0x0B`; GIF metadata command `0x0D` serializes flags/index, frame count, and delay into five bytes; command `0x0C` transfers page/frame data in up-to-512-byte subreports with an eight-byte header, optional additive-complement byte, page acknowledgements, retries, and cancellation checks. The UI also decodes `screen.gif` frames into PNG cache files. | The `0x0B` schema and pixel format/layout are unresolved. A follow-up maps GIF-to-PNG caching and a frame-conversion worker, but not the visible import action, the converted-buffer-to-writer edge, delay units, or concrete UI-to-virtual-method route. These command paths write to the keyboard; see the [screen/GIF payload audit](rk-screen-gif-payload-audit.md) and [image-conversion path audit](rk-screen-image-conversion-path-audit.md). |
| Settings and reset | Packets include debounce, tap, and sleep fields. `FUN_004102D0` sends reset command `0x11`; `FUN_00411B90` also has a reset-command branch. | UI warns reset/factory restore clears keyboard data; exact button-to-command dispatch is not mapped. |
| Software and firmware updates | Main UI software update uses `URLDownloadToFileW`; the per-profile `Update.exe` stages `.upf` data for HID transfer and also has an event-driven UART receive/state path. | MFU section-B/C paths perform bounded readback comparisons after writes. UART states 7/11 contain a conditional response-to-file sink, but the file gate, stream setup, and runtime activation are unresolved. See the [updater/readback audit](rk-firmware-readback-audit.md). |

### Lighting payload details

The static `ApplySetting` path begins with a dirty-flag mask. For the
3632-facing wrapper `FUN_0040e690`, the apply operation is gated by the
instance busy flag at offset `+0x260`, waits 200 ms, and enters
`FUN_00411b90`. That common routine chooses a G5 path through `FUN_0040f700`
or 3632 paths through the function pointer at object offset `+0x94` and the
helpers `FUN_0040d7e0`/`FUN_0040dd60`. These are static control-flow facts;
the device was not connected by the analysis.

The lighting configuration read helper `FUN_0040fad0` requests G5 command
`0x84` or 3632 command `0x44`, and reads `0x80` bytes. Its G5 response is
accepted only when the final two bytes are `0x5A, 0xA5`. Applying LED config
uses command `4`, with the packer selected by firmware value: `FUN_00411700`
for firmware value `2`, otherwise `FUN_00411900`. The following source and
output byte offsets were traced statically:

| Packer | Output field | Source/evidence | Confidence and open meaning |
| --- | --- | --- | --- |
| `FUN_00411700` | `+2` | Configuration `+0x3E02`; also logged as debounce | Strong mapping; allowed-value mapping to user-visible timing remains incomplete. |
| `FUN_00411900` | `+3` | Configuration `+0x3E02`; also logged as debounce | Strong mapping; allowed-value mapping to user-visible timing remains incomplete. |
| `FUN_00411700` | `+8` | Configuration `+0x3E08`; logged as tap setting | Strong mapping; exact UI labels and units unresolved. |
| `FUN_00411900` | `+0x16` | Configuration `+0x3E08`; logged as tap setting | Strong mapping; exact UI labels and units unresolved. |
| `FUN_00411700` | `+9` | Configuration `+0x3E14`; logged as sleep setting | Strong mapping; the zeroing condition and units need more caller/UI tracing. |
| `FUN_00411900` | `+0x18` | Configuration `+0x3E14`; logged as sleep setting | Strong mapping; the zeroing condition and units need more caller/UI tracing. |

The packers translate debounce and sleep settings through lookup tables.
`FUN_00411700` zeroes the tap byte when configuration `+0x3E04` is nonzero.
`FUN_00411900` also sets output `+9` from a selected-profile equality test,
`+0xA` from the profile row's first byte except for one special row, `+0xB`
from configuration `+0x25C0 + 0x20`, and `+0x1B` when configuration
`+0x3E20` is zero; `+0x38` and `+0x39` are initialized to `0xFF`. The source
and selection mechanics are known, but labels and behavioral meaning are not.

The two packers encode their mode/item data differently. `FUN_00411900`
iterates runtime rows at configuration `+0x214C + i*0x30`; mode/index is
looked up from `+0x2144`, with nibble inputs at `+0x2140`, `+0x214C`, and
`+0x216C`. `FUN_00411700` uses output `+0x21` for the profile-row byte
(except the special row), `+0x22..+0x24` for selected-mode data, and
`+0x53+2i`/`+0x54+2i` for item pairs. These offsets are a recovered binary
layout, not names for undocumented controls.

### Brightness profile, UI, and serializer path

The profile initializer `FUN_004513B0` at `0x004513B0` formats the active
profile path as `%sDev\\%04X\\%s` with `KB.ini`, then reads `[OPT] LightUI`,
`LightHW`, and `DefBri` through `GetPrivateProfileStringW` and
`GetPrivateProfileIntW`. `LightUI` is parsed by `FUN_0044DC70` into the byte
table at `0x00611854` (parse limit argument `0x14`). If it is absent or does
not parse, initialization falls back to `BriNum`; without a positive
`BriNum`, the code creates five or six sequential values according to the
profile's `Fw` field. With a valid `LightUI`, `LightHW` is parsed into the
separate byte table at `0x00611868`; if that list is absent or invalid, the
initializer copies the UI values into the hardware table. `DefBri` is then
read into global `0x00611850`, defaulting to `4`.

`FUN_0045A430` at `0x0045A430` initializes each 0x30-byte runtime lighting
record with `0x00611850` at record offset `+4` (object offset `+0x2144` for
the first record). The static consumers treat this field as an index: the
RKKB routine `FUN_00413BF0` at `0x00413BF0` uses the record's `+4` value to
index `0x00611868`, then places the translated byte at offset `5` in its
inner LED-data buffer, whose first two bytes are `02 29`. The shared
G5/3632 packer `FUN_00411900` also indexes `0x00611868` from a lighting
record and writes the result into its item-pair output; for the selected
mode it writes a translated brightness byte at output `+0x5E`. This
establishes a profile-table-to-serialized-byte path for these inspected
branches. It does not establish brightness units, a physical luminance
percentage, or a universal payload for every profile and family.

The [lighting profile-to-record trace](rk-lighting-profile-record-path-audit.md)
also resolves the dynamic `LedOpt%d` reader: it visits slots 1–24, and tuple
cell 4 can set runtime-record `+0x08` to 1 or 2. Cells 2–6 feed lighting
dialog state and visibility updates. The full tuple meaning, exact control
labels, and the callback that edits the remaining runtime-record fields are
still unresolved.

There is also a UI-value path: `FUN_00422220` at `0x00422220`, when its
selector argument is `0x95`, formats the value at `0x00611854 + index` for a
runtime control. This supports use of `LightUI` as a displayed value list;
the selector has not been tied to a particular visible widget or command
handler. English `Text/en/text.xml` labels `tc_adv_str1` “Light Brightness”
and `tc_kbin10`, `tc_kbin11`, and `tc_kbin12` are “Brightness +”, “Brightness -”,
and “Brightness Loop”. The XML confirms those localized labels, but the
native control IDs and event handlers for those labels remain unresolved.

### Keymap and macro mapping details

`FUN_00411260` consumes four layers from a runtime map object at `+0x38`.
Each layer contains 132 records with a 16-byte stride (`0x840` bytes per
layer). For each nonempty record (DWORD at `+0` is nonzero), it calls a driver
virtual method at vtable offset `+0x60` to translate the record, then uses a
byte mapping table at `0x616998 + entryOffset` to select an output slot. The
translated DWORD is stored in that slot; return value `-1` and destination
slots above `0x83` are rejected. The table/record relationship and the full
semantic meaning of the translated DWORD remain incomplete. The packed
output has 132 DWORDs (`0x210` bytes) per layer and four layers (`0x840` bytes)
in total for a 132-key profile.

Records with tag byte `+3 == 5` take a macro path: their DWORD at `+8` is
matched to macro nodes, a sequential macro-buffer ID is assigned, and a
serializer is called through vtable offset `+0x64`. The mapped matrix DWORD
contains `(bufferID - 1)` in its high byte. The record contains other fields
used by the virtual translator, but their meanings and all translated DWORD
bits remain unresolved.

The keymap branch in `FUN_00411B90` runs when apply flag bit 0 is set. The
map object's dirty-layer mask at `+0x30` selects layers; its excluded/current
layer index is at `+0x34`. `FUN_00411B50` scans 132 entries for macro tags.
If a dirty layer references macros, the worker can add other macro-containing
layers to the dirty mask, then sends macro data only when at least one macro
is present. It serializes all four layers and calls `FUN_0040F9C0` for each
selected layer.

For G5, `FUN_0040F9C0` passes the mapped matrix length as profile field
`+0xB5 * 4` (528 bytes for 132 keys), report ID from device-object byte
`+0x2D0`, and layer index as the option. `FUN_0040F700` command `3` divides
the payload into 512- and 16-byte chunks, sets packet count 2 and indices 0/1,
and uses a 25 ms inter-report delay. The 3632 path dispatches command `1`.
This establishes the transport length and layer option for the inspected
profile path; it does not define every DWORD field or profile's wiring map.

Macro data assembled for the driver has a `uint16 offset, uint16 length`
pair per unique macro, followed by concatenated serialized event blobs. Each
table offset is based on the end of the `4*n`-byte pair table; the total
payload size is `4*n + sum(blob lengths)`, and macro count is passed
separately. G5 sends command `5` through the generic 520-byte feature helper
with 512-byte payload chunks; 3632 sends command `3` in 20-byte frames with
14-byte payload chunks and response/retry handling. The serializer behind
the model vtable `+0x64` remains unresolved, so this does not decode the
serialized event bytes.

The macro record's event area starts at `+0x6A`; entries are eight bytes
apart and terminate when their 16-bit code is zero. The first row's DWORD is
at `+0x6E`. `FUN_0042DEC0` checks event IDs `0x110`–`0x116` against a
seven-bit capability mask. Those IDs likely correspond to the seven mouse
actions named in the UI, but that association is inferred and the exact
mapping is unknown. `FUN_0042A980` estimates device size from event rows
(`4 + 2` per event, with an additional `4` when the row DWORD exceeds `0x7F`)
and compares it to a global capacity. The UI strings corroborate
unsupported-key and too-large-for-device errors. Other row fields and their
on-wire transformation remain open.

The UI exposes recording, default/fixed delays, keyboard and mouse events,
editing, import/export, and loop-until-count/key-release/key-press options.
The specific input-capture route and event-to-record conversion are not
recovered. Although the executable imports `GetAsyncKeyState` and has
thread-scoped UI/mouse hooks, no inspected call path ties those APIs to the
macro dialog recorder.

### Audio capture path

`FUN_0043C780` statically resolves to a WASAPI loopback capture routine. It
creates an `IMMDeviceEnumerator`, registers endpoint notifications, obtains
the default render/console endpoint, activates an `IAudioClient`, reads the
mix format, and initializes capture with flag `0x20000`
(`AUDCLNT_STREAMFLAGS_LOOPBACK`). It obtains `IAudioCaptureClient`, polls
packet size, reads and releases audio buffers, converts PCM to floating-point
and reduces it to 24 visualization bands, then exits on cancellation/event.
The audio processing path therefore exists in the native software; this does
not show that it was started in this audit or that audio was captured.

The separate `FUN_00413340`/`FUN_00413220` path sends music data through
65-byte RKKB feature reports, using a leading `0` or `[6, 0]` selected by the
RGB flag. It is an active keyboard-write path and was not invoked. The exact
relationship between the generated bands, the `audio.dct` settings, and the
transmitted format remains unresolved.

The catalog has eight S98 profiles, all `Fw=1`, `ShowScreen=1`, `RGBScreen=1`,
320x172, and limited to 60 frames: `0174` RK S98RGB, `0224` RK-S98 DE, `022B`
RK-S98 ES, `022F` RK-S98 default, `0230` RK-S98 RU, `0223` RK-S98 TH,
`01BF` RK-S98RGB ISO Return, and `01AF` RK-S98RGB-New. Their six-byte `Psd`
signatures are unique within this catalog; `0174` ends in `03`, while the
others end in `6E`, `72`, `73`, `74`, `6D`, `2C`, and `23`. They all use
`DataUnitSize=512` and `MusicRGBIndex=1,0,2`. This is catalog evidence, not
hardware validation. None of the eight S98 profile rows lists wireless
VID/PID fields.

A different profile, `020F`, is RK A70 Keyboard; it has wireless VID/PID
`0x258A:0x0150`, `Psd=6,0,0,0,0,56`, and `MusicRGBIndex=1,0,2`, but no screen
fields. Windows' observed USB ID `0x258A:0x0150` therefore matches the A70
receiver profile, not an S98 direct-PID row, and cannot identify the connected
keyboard by itself. All 15 screen profiles are G5 with `RGBScreen=1`. Only
the N99 profile has
`ShowScreen=2`; the other 14 use `1`. `FUN_0040F350` gates the secondary
screen-device/PSD match branch on the value `2`, so that companion-screen
probe is a profile-specific exception, not a universal screen workflow.

Twenty-nine profiles list `MusicRGBIndex`, and every value is `1,0,2`; they
are all nonzero-`Fw` profiles and include all 15 display profiles. This
documents configuration availability, not proof that each model runs audio
capture or the same music-packet path.

### Screen and GIF data paths

The UI-side screen workflow decodes `screen.gif` into cached
`screen_img%d.png` frame images using GDI+. A separate helper reads and writes
`gif_delay.gcc` as a four-byte DWORD; the unit and full range are not
established. The installed package includes screen-frame and playback
settings, but those local files do not show which exact byte values the
device expects.

The native driver sends screen parameters with G5 command `0x0B`, GIF
parameters with command `0x0D`, then transfers pages/frames through
`FUN_00412B10` command `0x0C`. The screen helper passes its caller-supplied
parameter buffer unchanged. The GIF helper builds five bytes: a flags/index
byte (flags in bits 6–7 and GIF index in the low six bits), 16-bit
little-endian frame count, and 16-bit little-endian delay. Delay units and
flag meaning are unresolved.

The page helper carries up to 512 data bytes per 520-byte feature report. Its
header is report ID, command `0x0C`, zero, caller frame value, packet counter,
one-byte checksum, and 16-bit little-endian payload length, followed by
payload. The report ID normally comes from device-object offset `+0x2D0`, with
an alternate report-ID-9 branch. When global `0x611844` is set, checksum byte
5 is `0xFF - (sum(payload) mod 256)`; even/odd accumulators are used to compute
that one value, not two checksum fields or a polynomial CRC. Feature-write
failures retry at most four times with 100 ms delays. The response checks
internal bytes 3 and 4 against a nonzero status and sent packet counter, and
compares byte 5 in checksum mode. Cancellation, progress, and outer page
retry paths are also present; the invalid-page-ACK loop has no visible retry
bound. A call at `0x00466820` starts worker `0x00466450`, which converts frame
images through `0x004661A0`, calls object virtual slots `+0x4C`/`+0x50`, and
supplies progress callback `0x004663C0`. The concrete bridge from those slots
to the driver methods is not recovered. These are screen-write paths and were
not executed.

RGB-table updates use a buffer sized `(profile-count + 1) * 0x15` bytes and
the G5 command `10` or 3632 command `9`. `FUN_0040cd70` is only an optional
debug dumper gated by a logging flag: it formats input bytes but does not
modify the RGB buffer. RGB data is copied from six DWORD color values in
configuration rows beginning at `+0x2150` and selected through channel tables
at `DAT_00612B48`/`DAT_00612B49`/`DAT_00612B4A`; exact color-space/slot meaning
is unresolved. Dirty color-group updates serialize three bytes per group
using profile-row DWORD colors; G5 uses command `6`, while 3632 uses command
`2`. A reset/flag path may call a virtual function at `+0x38`, but its effect
is not resolved.

The SetGame/color-group path has a separate dirty mask at configuration
offset `+0x25C4`. For each dirty group, it reads up to 132 DWORD colors from
the configuration color array (DWORD index `0x972 + group * 0x84`), then
remaps entries through records at `0x6169D1` with 16-byte stride. The remap
record's flag is at `record - 5` and its destination slot is at `record + 0`;
slots beyond the profile key count (`profile + 0xB6`) are clipped. Three
selected channel bytes, using tables at `0x612B50`/`0x612B51`/`0x612B52`, are
serialized per key slot and the group index is passed as the command option.
G5 sends command `6` after 25 ms; the 3632 wrapper sends command `2` after
15 ms. The flag at `0x6117CC` has a special selected-profile path, and flag
`0x10` gates entry to the update; their user-visible meanings and channel
ordering are unresolved.

`FUN_004102D0` is the one-byte reset helper: G5 sends command `0x11`, option
`1`, and passes `0x19` as the transport timing argument; the 3632 path calls
its virtual method at `+0x38`.
Within `FUN_00411B90`, flag `0x10` and global `0x612B8C` gate a logged reset
path that calls the same virtual method and may clear a dirty mask based on
the return value. The LED packers can overlay three `(offset, value)` pairs
from the table at `0x612B84`; the table's relationship to reset is not
established. The SendWeb route scans four layers of 132 key records for tag
`0x0B`, waits 30 ms, then reads a NUL-terminated string from object/config
offset `+0x3E21`. G5 sends it as command `0x12` using the device report ID and
waits 25 ms; the 3632 route sends command `0x12`, option `0`, and waits
15 ms. The string's format and the control that supplies it remain unknown.
These are active write routes and were not invoked. The targeted brightness
trace above maps `LightHW` table selections into family-specific serialized
bytes; their units and physical luminance remain unknown. Debounce, tap, and
sleep fields are also identified, while other LED payload bytes and their UI
bindings remain partly opaque.

The [reset and system-parameter audit](rk-reset-and-system-parameter-path-audit.md)
maps the `CmdReset`-gated virtual route, its family slot targets, and a
periodic profile-configured worker that reads then rewrites lighting state for
G5/3632 objects. It also resolves command `0x6401` as a worker stop-event path.
The visible confirmation prompt still has no proven link to a reset handler;
worker payload meaning and runtime execution remain unresolved.

The [settings serializer audit](rk-setting-serializer-audit.md) maps the
apply-flag branches, family-specific command paths, and the separate screen
writer path. The companion [Apply signaling audit](rk-settings-apply-worker-audit.md)
maps one UI event to the shared worker and the worker's family-specific vtable
targets, while preserving the unresolved receiver and runtime profile. Both
reports record the remaining UI, macro-serializer, and payload gaps.

The [UART chunk-path follow-up](rk-uart-firmware-path-semantics-audit.md)
corrects several little-endian header fields to their transmitted byte order
and separates two closed updater state cycles from proof of a complete
firmware read. Conditional response-to-file sinks exist, but direct state
reachability, stream setup, range/length initialization, and chunk completeness
remain unresolved.

This is a function-level feature map, not a complete MFC button-handler map.
The PE contains ten dialog resources, but the app-looking templates are
generic `Dialog/New` shells (IDs 30721 and 30734) and the other inspected
dialog templates are empty MFC shells. RTTI names show dynamically created
forms/classes including `COemDrvDlg`, `CKeyDlg`, `CKeyFunPickDlg`, `CLedDlg`,
`CMacroDlg`, `CSettingDlg`, `CMenuDlg`, `CMenuSrDlg`, `CBurnScreenDlg`,
`CFrameEditView`, `CFrameView`, `CPickImageDlg`, `CPreviewDlg`, `CScreenDlg`,
`CScreenView`, `CClrPanelDlg`, `CColorBtnDlg`, `CCustomDlg`, `CKBColorDlg`,
`CTipsDlg`, and `CWelcomDlg`. MFC `WM_COMMAND` message-map records are
present—for example IDs `0x420E`–`0x4216` point to handlers at
`0x0049A660`, `0x0049CF85`, `0x00494C21`, `0x0049A475`, `0x00494C6C`,
`0x0049A5F9`, `0x0049A51A`, `0x00494D2E`, and `0x00497F8F`. The generic dialog resources do not
identify every visible control or label. A heuristic scan found 112 candidate
`WM_COMMAND`-shaped rows in 30 blocks (21 multi-entry runs and nine
singletons), based on message code
`0x111`, signature `0x39`, equal ID/range fields, a 24-byte stride, and handler
addresses inside `.text`. The raw `(ID, notification code, target VA, map-row
VA)` list is in [`rk-mfc-command-map-candidates.csv`](rk-mfc-command-map-candidates.csv). All
30 blocks were validated against `WM_COMMAND` entry fields and linked to an
MFC owner through the `AFX_MSGMAP` descriptor, getter, vtable, and RTTI complete
object locator; the descriptor, getter, vtable, COL, RTTI type-descriptor addresses, and
inheritance caveats are in
[`rk-mfc-map-owner-evidence.csv`](rk-mfc-map-owner-evidence.csv). Two blocks
have inherited/shared-getter ambiguity. Class ownership does not reveal every
visible control or establish its effect. One eight-entry run
at `0x005B1630` is attributable to the MFC framework class
`CMFCToolBarButtonCustomizeDialog`: its map descriptor at `0x005B1628`
points to base-map function `0x00479866` and the entries, a getter at
`0x005051BF` returns that descriptor, and the getter is in the RTTI-backed
vtable whose complete-object locator names the class. Its IDs include
`0x4079`–`0x407E`, `0x4091`, and `0x4092`. Those handlers are framework
customization UI and do not identify an RK keyboard feature. A full record
parser now decodes all 26 unique recovered arrays from this owner evidence:
291 entries, including 144 `WM_COMMAND` entries with different signatures and
147 other messages. The earlier 112-row CSV remains the narrower
signature-`0x39`, equal-ID subset. See the [MFC message-map audit](rk-mfc-message-map-audit.md)
and its [normalized full-entry CSV](rk-mfc-message-map-entries.csv).
Additional RTTI-backed app-owned map links are summarized here:

| Owner class | Map entry / command ID | Notification | Handler | Static interpretation and limit |
| --- | --- | --- | --- | --- |
| `CMacroDlg` | `0x005CD558` / `0x0107`; `0x005CD570` / `0x0117` | `WM_COMMAND` code `0x0300` (edit change) | `0x0042B3B0`; `0x0042B530` | The first handler validates a numeric value against a global upper bound and resets invalid input; the second clamps a numeric value to 1–1,048,575. See details below; labels are unresolved. |
| `CScreenDlg` | `0x005DA4D0` / `0x0107` | `WM_COMMAND` code `0x0300` (edit change) | `0x0046C5B0` | Clamps the numeric value to 65,535 and stores it in dialog state at `this+0x114`; the visible control label is unresolved. |
| `COemDrvApp` | `0xE146` | `WM_COMMAND`; notification not recovered | `0x0047EEDF` | Branch target returns zero through a shared epilogue; exact command purpose is unresolved. |
| `COemDrvDlg` | `0x6400`, `0x6401` | `WM_COMMAND`; code `0` | `0x00446770`, `0x00446820` | One handler foregrounds or initializes/shows the dialog; the other closes named helper windows, may persist profile data, and signals the `SendSysParam` worker's event. See the [UI event and worker path audit](rk-ui-event-worker-path-audit.md). |

The full maps also establish the main application's system-message dispatch:

| Owner | Map row | Message | Handler | Static path |
| --- | --- | --- | --- | --- |
| `COemDrvDlg` | `0x005D4C50` | `WM_DEVICECHANGE` (`0x0219`) | `0x00447580`, body at `0x00447591` | Processes arrival/removal branches, parses device paths, and schedules timers `0x844`/`0x845`; the `WM_TIMER` map row at `0x005D4C98` targets `0x00447710`. Runtime event delivery remains unobserved. |
| `CScreenDlg` | `0x005DA4E8` | `WM_TIMER` (`0x0113`) | `0x0046D570` | Timer `0x900` kills its timer, sets `this+0x10C`, and calls UI refresh `0x00475257`; the field's meaning is unknown. |

See the [full MFC message-map audit](rk-mfc-message-map-audit.md) for the
other application-owned non-command entries and all 26 recovered arrays.

Handler-level inspection refined the macro and screen edit behavior. `CMacroDlg`
handler `0x0042B3B0` reads the integer child at `this+0x2FA0`, accepts values
from 1 through global `DAT_611FEC`, resets invalid input to `1` with the
message format `Loop Count = 1 ~ %d`, and sets bit `0x40000000` in state
returned by `FUN_0042CC20`; the owner of that state object is unresolved.
Handler `0x0042B530` reads the child at `this+0x2FA8`, clamps values to
1–1,048,575, and moves the edit caret to the end. The control labels are not
recoverable from the generic dialog resources. `CScreenDlg` handler
`0x0046C5B0` clamps to 65,535 and stores the result at `this+0x114`.

For `COemDrvDlg`, handler `0x00446770` foregrounds the window when visible or
initializes and shows it otherwise. Handler `0x00446820` closes windows named
`OemDrvMacroTopWindow` and `OemDrvMsgTopWindow`; with a profile-state flag set,
it writes active `CDev` object ranges to `pro.dct` files and writes four bytes
to `curid.dct`, then scans profile/PID records and may signal a device object's
event. The event's worker and family-specific timeout operations are traced in
the [UI event and worker path audit](rk-ui-event-worker-path-audit.md). The
on-disk object schema and those four bytes' meaning remain unresolved.

The other recovered arrays belong to MFC framework classes including dialogs,
MDI frames, toolbar customization/property pages, preview/task panes, and
color UI. Their presence in the inventory does not establish an RK hardware
feature. The owner evidence distinguishes framework maps from the four
app-owned dialog/application maps.

A separate `CDev3632::AccessData` helper accepts up to 512 bytes and splits
them into 20-byte packets with 14-byte payload chunks. It queues each frame,
waits for command-matched responses on most commands, and retries timeout or
CRC-class failures up to five times after the initial attempt. The frame
layout recovered from `FUN_0040d7e0` is:

| Byte(s) | 3632 frame field |
| --- | --- |
| 0 | `0x13` marker |
| 1 | command |
| 2 | total packet count |
| 3 | zero-based packet index |
| 4 | caller option in high nibble, payload length in low nibble |
| 5–18 | up to 14 payload bytes, zero padded |
| 19 | low byte of sum of bytes 0–18 |

The response reader `FUN_0040d370` consumes 20-byte records from a queue. It
returns success when response byte 1 matches the requested command and bit 7
of byte 2 is clear; returns `-4` when byte 0 is `0xFF`; returns `-3` when bit
7 of byte 2 is set; returns `-2` when the queue helper reports no data; and
returns `-1` after 20 records with a nonmatching command. The queue helper
`FUN_0043c390` waits up to 4,000 ms when fewer than 20 bytes are queued. The
writer `FUN_0040e0f0` submits each frame with overlapped `WriteFile`, waits up
to 500 ms for pending I/O, and can make up to four write attempts.
`AccessData` retries `-2`/`-3` only when its retry flag is enabled, up to five
retries after the initial attempt. Although logs label `-3` a CRC error, this
receiver path only checks status bit 7; it does not recompute or validate a
response checksum. The meaning of response bytes 0 and 2, any acknowledgment
checksum, and the queue producer remain unresolved. Wrapper/log context labels
these 3632 commands:
SetMatrix `1`, SetGame `2`, SetMacro `3`, SetLED `4`, SetLedRgbTab `9`,
SendWeb `0x12`, and GetLED `0x44`. These labels do not define all payload
fields or prove how every profile maps to the family.

The three observed transport families have different framing:

| Family/helper | Static frame layout and behavior |
| --- | --- |
| G5 `FUN_0040f700` | 520-byte (`0x208`) feature reports: report ID, command, option, zero field, packet count, packet index, little-endian payload length, and up to 512 payload bytes. Its read operation first sends a `HidD_SetFeature` report and then calls `HidD_GetFeature`; retries and command matching are present, with no checksum check in this generic helper. |
| G5 page transfer `FUN_00412b10` | Command `0x0C`, up to 512 payload bytes per report, page ACK, retry, cancellation checks, and optional byte-sum/complement comparison. This is a screen/page transfer path, not a general read protocol. |
| 3632 `FUN_0040d7e0` | 20-byte frames shown above, 14-byte payload, additive checksum, response queue, and optional retries. Macro helper `FUN_0040DD60` first groups data into at most 512-byte chunks, then calls command `3` through the 14-byte transport and waits 100 ms between successful outer chunks; option `6` and trailing argument `0x0F` semantics remain unresolved. |
| RKKB `FUN_00413220` | 65-byte reports: ID `10`, packet count, one-based packet index, and up to 62 payload bytes. The inspected helper uses `HidD_SetFeature`, an 8 ms inter-packet delay, and no ACK/checksum. |

G5 wrapper labels include SetMatrix `3`, SetMacro `5`, SetLED `4`, SetGame
`6`, SetLedRgbTab `10`, SendWeb `0x12`, GetLED `0x84`, GetPower `0x87`, and
GetRealData `0x88`. `GetPower` returns two bytes in the inspected helper. The instruction-aligned GetRealData helper entry is `0x0040FF60`; it uses 520-byte feature reports with up to 512 response bytes per chunk, but the caller, returned-data meaning, and any relationship to firmware memory are unresolved. Each chunk begins with a feature request before the read. Its 27-slot G5 vtable and six nearby UI `+0x68` dispatches resolved to DrawTextW are mapped in the [4.06 G5 vtable audit](rk-406-cdevg5-vtable-audit.md) and [slot ledger](rk-406-cdevg5-vtable-map.csv). RKKB `FUN_00413220` frames up to 62 payload bytes in 65-byte feature reports. Its direct callers include music (`FUN_00413340`) and the separate apply routine's LED, per-key color, key/layer, macro-derived, matrix, and conditional Fn paths. Prefixes and several lengths are recovered in the [serializer audit](rk-setting-serializer-audit.md), but exact payload schemas and model/UI reachability remain incomplete. These are observed code paths, not a guarantee that every catalog profile maps one-to-one to one of these classes.

The labels come from embedded logs and function context. They are useful
protocol leads, not a complete command schema: Ghidra generated addresses for
most functions, virtual calls obscure some callers, and the same utility has
multiple device classes. No buffer was sent to a keyboard to validate these
interpretations.

The separate `Dev/01AF/Update.exe` also imports SetupAPI and HID feature
report functions. `FUN_0040B770` uses a distinct `0x408`-byte
status/control report. Section B is coordinated by `FUN_00402B20` and written
by `FUN_00403290` in `0x802`-byte feature reports carrying up to `0x800` data
bytes (`HidD_SetFeature` callsite `0x00403505`). `FUN_00402FC0` then sends a
`05 52` request, reads `06 72` responses (`HidD_GetFeature` callsite
`0x0040308C`), and compares each response payload with the host buffer at
`0x005C5EFC`, up to its length at `0x005C5F04`. Section C is coordinated by
`FUN_00402CE0`, written by `FUN_00403570` (`HidD_SetFeature` callsite
`0x004036BD`), and verified by `FUN_004037D0`; its `HidD_GetFeature` callsite
is `0x0040389C`, and its host comparison buffer/length are at
`0x005C5EF8`/`0x005C5F00`. Both verifiers compare chunks of up to `0x800`
bytes in RAM. These are readback-verification paths within an update flow,
not an independent full-flash dump or save-to-host workflow. UI strings
include firmware version checks, CRC failures, device-type mismatch, and
USB/BLE update status.

The update stage dispatcher `FUN_00402A40` selects section C (labelled MFU
firmware upgrade) when the global stage is `3` and the main-window flag at
`+0x8E6F` is clear. If that flag is set and `+0x8E6E` is nonzero it returns;
otherwise it labels the operation HID firmware upgrading and enters the
section-B path. The code proves these flag branches, but not which physical
transport or UI action sets the flags.

Both B and C stage helpers check device handles, send a 0x408-byte staging
report filled with `0x45` except the first byte `0x05`, sleep two seconds,
then write a section only when its length is below `0xF001`, rounded up to
0x800-byte boundaries. The write helper is retried up to five times; its
verifier is retried up to ten times. On success the updater sends a 0x408-byte
`0x55` finalization report (first byte `0x05`) followed by a zero-filled
report beginning `05 5A`. The B verification path reads 0x800-byte chunks
from `06 72` responses and compares them with the host staging buffer; C has a
separate verifier and host buffer. Failure returns a nonzero status. These
staging, write, verify, and finalize reports are active device operations;
none was sent during this audit.

The BLE version/status path uses `FUN_00406C20` and `FUN_0040B770`. The UI
labels it “Read BLE Version” or “BLE firmware upgrading” from a window flag.
`FUN_0040B770` calls `FUN_0040BB10` up to three times. That helper polls
report ID `6` using 0x408-byte `HidD_GetFeature` reports, sleeps 100 ms
between up to six reads, checks response prefix `05 01`, and compares version
bytes with `FUN_00404450`. Status strings include CRC failure (`0x0B`),
device-type mismatch (`0x10`), same version (`0x0F`), generic upgrade failure,
and BLE upgrade failure. `FUN_0040B770` then sends its own 0x408-byte
SetFeature control/status report at `0x0040B800`. The exact response fields
and relation between this path and the B/C section dispatcher remain
unresolved.

The updater therefore has a separate firmware-transfer path; its report
fields and full `.upf` format remain only partly decoded. It was not run. The
one installed `.upf` package is 193,652 bytes; its header begins with `5A A5`
followed by the ASCII marker `BLESINO`, and includes VID `258A`, PID `01AF`,
and version text `V1.00`.

The updater's `FUN_0040A940` opens the selected path in binary-read mode and
scans for the byte signature `5A A5 BLESINO`; the supplied file matches at
offset zero. The second signature byte is `A5` (the decompiler displays it as
a signed `char` value of `-0x5b`). On a match the parser reads mode/metadata,
length values, and payload sections. Partial field decoding for this file:

| File offset | Static value | Interpretation and confidence |
| --- | --- | --- |
| `0x09` | `03` | Mode 3; selects the parser branch that stages sections A, B, and C. |
| `0x0A–0x10` | `KB0000\0` | Model/tag string; exact meaning is unknown. |
| `0x11–0x12` | `25 8A` → `0x258A` | VID, strongly supported by filename and decoded global. |
| `0x13–0x14` | `01 AF` → `0x01AF` | PID, strongly supported by filename and decoded global. |
| `0x1A–0x1F` | `V1.00\0` | Version string passed through the updater's string helper. |
| `0x2C–0x2F` | `F0 00 71 6D` → `0xF000716D` | Section A length as decoded by the parser's byte-order logic. |
| `0x30–0x33` | `00 00 A1 87` → `0x0000A187` (41,351) | Section B length. |
| `0x42–0x45` | zero | Section C length. |
| `0x80` | — | Absolute seek position before reading payload data. |

The parser reads these length fields as big-endian. Its mode branches are:
mode 0 reads A+B, mode 1 reads A, mode 2 reads B, and mode 3 reads A+B+C.
For this file, mode 3 is selected. Section B flows into
`FUN_00402b20` → `FUN_00403290`, a HID firmware-upgrade path that writes
chunks with `HidD_SetFeature`. Section C flows into
`FUN_00402ce0` → `FUN_00403570` and a comparison helper at `FUN_004037d0`,
labelled in UI strings as an MFU firmware upgrade. Section A is stored for
the main update object; its use by a BLE upgrade path is a strong data-flow
inference, while its final transport routine is unresolved.

The decoded section A length (`0xF000716D`) is impossible for a 193,652-byte
file (only 193,524 bytes follow offset `0x80`). The static path does not show
an explicit check against the file size before allocation/read. The code
selects the mode-3 branch, but because the updater was not run, we cannot say
whether later reads fail, the file is rejected, or this reflects a format or
version mismatch. Other `5A 5B` byte pairs in the file are not the recognized
signature. Do not treat this `.upf` as a validated or recoverable keyboard
firmware image.

The saved Ghidra analysis of the main driver contains 13,735 procedures and
3,838 defined strings. Existing decompilation reports target HID and SetupAPI
imports, selected device-family strings, and selected data structures; they
do not decompile all procedures. The PE import inventory is complete for the
listed static import tables. Across the five analyzed binaries, the scan found
128 `GetProcAddress`/`LoadLibrary*` callsites in four binaries: 47 in
`DeviceDriver.exe`, 54 in `Update.exe`, four in `InitSetup.dll`, and 23 in
`unins000.exe`. Twenty-two callsites have no nearby literal candidate. Many
recoverable names are Windows/MFC compatibility APIs (for example transacted
file/registry functions, DWM/theme helpers, and task dialogs), but candidate
strings do not prove argument flow or execution. Some targets are not
statically recoverable. COM vtable calls, other indirect calls, and exact
executed paths remain untraced.

The updater's static UI and call traces identify an `.upf` file chooser and
firmware burn flow, plus version/status/acknowledgment handling. Its section-B
and section-C update paths read back bounded chunks and compare them in RAM
with the selected host image after writing. No complete full-flash dump or
save-to-host workflow was recovered. The separate UART state-7/state-11 path
has conditional response-to-file writes, but its file gate is initialized to
zero, and its stream setup and activation are unresolved. The HID
update/verify routines do not establish a firmware-file export, and generic
file API imports alone are not evidence that firmware is copied from a
device.

REA's PE resource inspection of `DeviceDriver.exe` found 61 resources, including
10 dialog resources and 14 string-table resources. The strings and dialogs
corroborate the UI workflows listed below. They do not substitute for
understanding the native event handlers and device transactions.

## Profile database and catalog

The named model catalog has 188 profiles and 90 distinct visual key layouts.
Across those named records, 156 profiles list RGB backlighting and 15 list a
display. The display profiles describe 128×128, 240×135, 240×240, or 320×172
dimensions. The catalog also records one unregistered `01C7` profile separately
so it is available for audit without presenting it as a verified named model.
In 134 named profiles, `LayoutKeyNum` differs from the number of drawable key
rectangles. For example, `022F` declares 104 keys and has 102 drawable
rectangles; its two additional `[KEY]` rows have zero-sized rectangles but
still carry mapping tuples. Schema version 3 retains both counts and every
base mapping row.

There are 88 distinct non-comment `OPT` field names in the installed profile
set. Across all 189 profile files there are 6,506 `OPT` assignments, with no
duplicate option keys inside a profile. The field-by-field profile counts and
static key-literal coverage are in
[`rk-profile-option-field-inventory.csv`](rk-profile-option-field-inventory.csv).
The main binary has individual key-name references for 64 of the 88 fields;
no individual literals were found for `GaoshouKey1`, `GaoshouKey2`,
`ShowAutoDetect`, or `LedOpt1` through `LedOpt21`. The latter are generated by
the dynamic `LedOpt%d` reader in `FUN_004513B0`, which iterates slots 1–24;
see the [lighting profile-to-record audit](rk-lighting-profile-record-path-audit.md).
For the other missing names, a missing literal does not prove a field is
unused because generic/dynamic INI parsing may handle it.
LED slot presence is non-contiguous: 93 profiles have slots 1–21, 53 have
1–17 plus 19–20, 28 have 1–20, 10 have 1–19, four have 1–13, and one has
1–3. Keep the stored slot IDs; neither slot count nor localized labels prove
the tuple-to-command mapping. The profile corpus also contains `[KEY]`,
`[FN1]`, and `[FN2]` sections;
the installed set has 63 `[FN1]` sections and 17 `[FN2]` sections. Most `[KEY]`
rows contain four layout coordinates followed by additional mapping values.
The latter fields and the Fn rows are retained as raw integer tuples because
the mapping semantics have not been decoded. `LayerNum` is not equivalent to
the number of populated Fn sections: for example, profile `022F` declares
`LayerNum=4` but has only an `[FN1]` section.

The regenerated `models.json` uses schema version 3. A static comparison of
the generated JSON against all 189 installed `KB.ini` files found no
mismatches in `OPT` strings, raw `[KEY]`/`[FN1]`/`[FN2]` assignment tuples, or
six-value `LedOpt*` arrays. It retains 15,945 `[KEY]` rows, 2,278 `[FN1]`
rows, 603 `[FN2]` rows, and 3,765 six-value LED-option tuples. The named 188
profiles and the unregistered `01C7` profile are all represented; `01C7` is
under `unregisteredProfiles` and is not selectable as a verified named
model. Seven profiles contain wireless IDs, spanning four VID/PID pairs.
Tuple values are decoded into JSON integer/string arrays, so the data values
are preserved while source whitespace and lexical number formatting are not.
Profile-local English and Simplified Chinese LED labels are also retained in
`profileData.lightingLabels` for the five profiles that ship those files,
including unregistered `01C7`. The five generic locale LED dictionaries are
not assigned to a particular profile in the catalog. These label strings
document UI order; they do not establish the serialized LED command values.
The extractor does not copy the RK executable, firmware, or image assets.

The data in these files describes what the RK utility knows about a device.
It does not prove every value's hardware meaning, and Keydeck does not transmit
these values.

## UI and configuration workflows evidenced in the installed package

The English resource strings and model configuration fields expose these
feature groups. Availability varies by model, and the list describes the RK
utility rather than features already implemented by Keydeck.

The seven locale XMLs have the same 247 intended UI leaf keys after
in-memory-only normalization of the Japanese file's malformed `tc_screen1`
closing token. Their values vary by locale. The key groups include 33 macro labels, 43
advanced-settings/update labels, 29 status/layer/tap/reset messages, 21
screen controls, ten music controls plus ten audio-effect labels, and distinct
shortcut/action groups for media, mouse, browser, system, office, and
keyboard-input choices. Five generic LED locale XMLs have 60 labels each,
with ten additional model-localized LED XML files as described above.
The [resource and localization audit](rk-resource-localization-audit.md)
contains the per-file hashes, exact-string locale comparisons, all 362 UI/LED
key rows, and per-profile illustration/effect-resource coverage.

| RK utility workflow | Evidence in package |
| --- | --- |
| Key remapping | Default/custom functions, key type, Windows shortcuts, key combinations, media, mouse buttons/actions, browser and system shortcuts, disable key, and per-key base/Fn mappings. |
| Layers and tap | Default, `FN1`, `FN2`, and tap labels; profiles may store `LayerNum`, `LayerMask`, and `TapRange`. |
| Macros | Record keyboard and mouse events; configure recording/default/fixed delays; insert events before/after; import/export; and cycle a fixed number of times, until key release, or until key press. Per-model `MacroBufferNum` appears in four profiles. |
| Lighting | 21 localized `tc_led_mode` labels, 20 alternate `tc_led` names, 19 `tc_eft` effect names, brightness/speed/color controls, custom lighting, per-profile `LedOpt*` six-value tuples, color-index arrays, defaults, and hardware/UI lighting options. The profile slot count (3, 13, 19, 20, or 21) does not establish which localized label maps to each slot. |
| Audio-reactive lighting | Music mode, gain, audio device, auto gain, monochrome/colorful choices, and ten effect slots. |
| Keyboard settings | Sleep and wireless sleep, automatic detection, debounce, office and gaming modes, Fn shortcuts, Windows/Mac layout, LED record, reset, and factory restore. |
| Screen / animation editor | Per-model screen dimensions and frame limits; image crop/zoom, layers, frame lists, add/import, apply-to-all, undo, playback interval, and screen preview. The UI says image transfer requires USB rather than wireless. |
| Updates | Software update and firmware detection/download/update prompts. The separate updater and `.upf` file are evidence of an update path; no firmware format or safe update procedure has been reverse engineered here. |

The utility includes destructive flows: its reset strings warn that reset or
factory restore clears keyboard data. Keydeck does not expose or invoke those
flows.

## What the native analysis establishes, and what remains open

The executable is native x86 rather than a .NET application. Its HID imports
and device-family strings indicate that model support is implemented through
multiple native classes. The local profiles provide extensive model-specific
configuration. Together, these establish the app's broad feature surface and
the shape of its data, but not a complete source-level explanation of every
mode or all 188 device paths.

Still unproven:

- The meaning of every field in the 520-byte HID feature reports and the
  request/response state machines.
- Which exact firmware/protocol revision pairs with every named profile.
- A read-only probe that safely distinguishes models when the USB descriptor
  is shared or generic.
- The byte-level encoding for keymaps, macros, lighting, screen transfers,
  gaming/debounce settings, reset, or firmware update.
- Whether a guessed or partially reconstructed write can leave a keyboard in
  a bad state.

The native driver was inspected with Ghidra against a byte-identical working
copy; REA was used for PE resource inspection. Static analysis advanced these
findings without touching hardware. The complete UI event flow, exact
model-to-firmware-revision mapping, and every device-family transaction have
not been reconstructed. No report capture or keyboard write has been
performed for this audit.

## Device identification and safety boundary

The Windows PnP inventory on this PC (2026-10-18 13:24:08 +05:30) includes one
present USB composite device with VID/PID `0x258A:0x0150`, three Bluetooth
nodes named `RK-S98RGB`, seven `HIDClass` children, two `Keyboard` children,
and one `Mouse` child. The HID children include consumer-control,
system-controller, vendor-defined, and USB Input Device entries. The query
also returned no `USBSTOR` nodes and one `DiskDrive` node with an NVMe instance
ID. This was a read-only OS PnP query: no HID interface was opened and no HID
report or GATT data was read. The inventory does not establish that the USB
composite device and the Bluetooth nodes are the same keyboard. The
installed profiles list `0x0150` as a receiver ID for at least one model, and
public S98 inventories also report `0x258A:0x0150`; this ID alone cannot prove
which model is connected. See this
[S98 HID inventory example](https://gist.github.com/andrewbt/10e59b562963200c80017babd2434947).

Keydeck only reads the browser-visible descriptor after device permission. It
does not open the HID device, receive feature reports, send reports, or replay
captured data. Exact product IDs and product names can identify some models;
shared receiver IDs remain ambiguous. Wireless profile matching now compares
both VID and PID when the profile supplies both. No model is guessed from a
feature-report probe.

## Firmware readback assessment

The current Windows PnP inventory includes a `0x258A:0x0150` USB composite
device and three Bluetooth child nodes named `RK-S98RGB`, but does not
establish that they refer to one physical keyboard. Its USB children include
keyboard, mouse, consumer-control, system-controller, and vendor-defined HID
collections. The same PnP query returned no `USBSTOR` nodes and only one
`DiskDrive` node, identified as NVMe. This provides no mass-storage route for
copying firmware; it does not rule out an undocumented software read path.

The only firmware-like update package in the installed RK package is
`Dev/01AF/KB_762_1_v258A_p01AF_F90_8818_V90.0f.1.00.upf` (193,652 bytes,
SHA-256 `e21c11e023247afc7fdbbe27548570240efa5b646147741d5354eecb3041b628`).
Its header identifies VID/PID `258A:01AF`, while Windows currently exposes
`258A:0150`; the receiver ID alone does not establish that the package matches
the firmware in the connected keyboard. The `.upf` is an updater input, not a
dump extracted from keyboard flash. Its header and some section fields are
partially decoded below, but a section length conflicts with the file size and
the package has not been validated.

Static updater paths show firmware selection/burning and short version/status
reads. The section-B and section-C verifiers read bounded update chunks into
RAM and compare them with the selected host image after a write. The installed
`.upf` declares section C as zero length. A separate UART
state-7/state-11 path conditionally passes received chunks to a fwrite-like
wrapper. However, its gate is directly initialized to zero, no nonzero direct
setter or stream-open/file-name path was found, and key stream/buffer globals
are in the zero-filled `.data` tail. The code therefore shows a potential
response-to-file sink, not an activated or complete firmware export workflow.
The generic HID data path inspected for the native driver sends a feature
report before it calls `HidD_GetFeature`, so an attempted “read” is not a
passive USB capture. No keyboard feature report was sent, no updater was
launched, and no bootloader mode was entered. With the evidence available,
there is still no demonstrated way to copy the running firmware while
guaranteeing the keyboard remains unchanged.

The dedicated [updater and firmware readback audit](rk-firmware-readback-audit.md)
records the parser fields, traced HID verification buffers, conditional UART
response-to-file sink, and the limits of this finding.

The [profile catalog and schema audit](rk-profile-schema-audit.md) covers all
189 installed `KB.ini` files, the exact tuple coverage of `models.json`,
profile field omissions, and the unresolved distinction between stored
mapping rows and rendered keys.

## External references

- [REA reverse-engineering project](https://github.com/morluto/rea)
- [Ghidra releases](https://github.com/NationalSecurityAgency/ghidra/releases)
- [RK web configurator](https://drive.rkgaming.com/)
- [RK S98 product specifications](https://rkgamingstore.com/products/s98-wireless-mechanical-keyboard)
- [KludgeKnight](https://github.com/vinc3m1/kludgeknight), an independent
  community implementation. Keydeck does not reuse its source code or write
  its keymap protocol.
