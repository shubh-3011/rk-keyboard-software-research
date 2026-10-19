# RK system API and static call crosswalk

This note reconciles the installed RK package's five PE files with the
ordinary/delay import inventory, IAT-reference CSV, and dynamic loader callsite
CSV. It narrows what those artifacts prove about native API usage and system
calls. It does not claim a runtime call trace.

## Scope and method

The source snapshot was `C:\Program Files (x86)\RK Keyboard Software`.
An `MZ` header scan found five PE files in that tree: `DeviceDriver.exe`,
`Dev/01AF/Update.exe`, `InitSetup.dll`, `uninstall.dll`, and `unins000.exe`.
For each, I read the PE headers and import descriptors with `pefile`, computed
SHA-256, and compared `(DLL name, imported API name, IAT RVA)` against
[`rk-native-api-xrefs.csv`](rk-native-api-xrefs.csv). Every tuple matched;
there were no missing, extra, or mismatched rows. The hashes and byte sizes
also match the records in [`rk-native-api-imports.md`](rk-native-api-imports.md).

For callsite reconciliation, I scanned executable sections for x86
`call [IAT]` (`FF 15`), `jmp [IAT]` (`FF 25`), and relative `call` (`E8`)
byte patterns targeting recorded import thunks, then compared the resulting
addresses with the CSV. The first four PEs match all three address sets
exactly. `unins000.exe` matches the direct-IAT and thunk sets exactly; its raw
byte scan finds three additional `E8` candidates that require instruction
boundary validation and are not counted as calls below. A byte-pattern match
alone is not proof of an instruction or reachable call.

No RK executable was launched. No keyboard interface, serial port, updater,
firmware writer, or bootloader was opened or used.

## Import and component crosswalk

| PE | Imported entries | Transport or OS API evidence | What the imports alone do not prove |
| --- | ---: | --- | --- |
| `DeviceDriver.exe` | 672 ordinary + 3 delay, across 21 ordinary-import DLLs | 4 SetupAPI and 9 HID imports; user-interface/GDI, registry, OLE/COM, performance-counter, and audio APIs. The HID enumeration/open sequence is statically identified in `FUN_004164b0` → `FUN_00416570`; device-family protocol paths are described in the [main report](reverse-engineering.md). | Which branches execute for a connected device, or whether any imported API runs in a particular session. |
| `Dev/01AF/Update.exe` | 618 ordinary, across 19 DLLs | 4 SetupAPI and 7 HID imports; serial communications (`SetCommMask`, `GetCommState`, `SetCommState`, `SetCommTimeouts`, `WaitCommEvent`, `ClearCommError`) plus file I/O. Static traces identify both UART and HID paths; all 15 UART receive-dispatch states are mapped in the [state-machine audit](rk-updater-uart-state-machine.md). | Which transport the user's workflow selects, whether a firmware update succeeds, or whether readback is a standalone firmware backup path. |
| `InitSetup.dll` | 76 ordinary, across `SHLWAPI.dll` and `KERNEL32.dll` | File and directory enumeration, attribute changes, deletion, and 4 dynamic-loader callsites. The `USER32` APIs used for error-window handling are dynamically resolved rather than ordinary imports. | The installed package does not include the installer executable, so the helper's caller and actual arguments are unknown. |
| `uninstall.dll` | 30 ordinary, across `MSVCR90.dll` and `KERNEL32.dll` | Runtime support imports only in the reviewed inventory. | No HID, SetupAPI, service, or network behavior was identified; that does not establish which host process loads the DLL. |
| `unins000.exe` | 519 ordinary, across 23 import descriptors | Inno Setup runtime imports, including registry, file, UI, and `DeviceIoControl` APIs. The inspected `DeviceIoControl` call uses `FSCTL_SET_COMPRESSION` on a file handle. Dynamic loading includes ACL APIs. | It has no HID, SetupAPI, or service-control imports; generic file APIs do not imply keyboard or firmware access. Runtime uninstall branches were not executed. |

The complete names for the 1,915 ordinary imports and 3 delay imports remain in
[`rk-native-api-imports.md`](rk-native-api-imports.md). These are declared PE
imports. Their presence does not establish execution. In particular, the
main executable's URL download imports do not by themselves show a download
occurs, and the updater's serial imports do not identify a selected keyboard
or prove a specific UART workflow.

## IAT-reference reconciliation

The current cross-reference CSV has 1,918 rows, exactly one for each ordinary
or delay import. The counts below are address counts, not source-level API
invocation totals or runtime frequencies.

| PE | Import rows | Direct `call [IAT]` sites | `jmp [IAT]` thunks | Relative calls to thunks | Other absolute IAT references | Imports with direct/thunk calls | Imports without a recorded direct/thunk call |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `DeviceDriver.exe` | 675 | 6,353 | 105 | 601 | 853 | 643 | 32 |
| `Dev/01AF/Update.exe` | 618 | 7,391 | 55 | 53 | 590 | 606 | 12 |
| `InitSetup.dll` | 76 | 148 | 1 | 2 | 27 | 74 | 2 |
| `uninstall.dll` | 30 | 21 | 10 | 12 | 6 | 27 | 3 |
| `unins000.exe` | 519 | 0 | 536 | 2,699 | 0 | 506 | 13 |
| **Total** | **1,918** | **13,913** | **707** | **3,367** | **1,476** | **1,856** | **62** |

The import-entry coverage counts are derived from the per-row address lists:
an entry is in the left call-reference column if the row has at least one
direct IAT call or relative call to an import thunk. Recounting all 1,918 CSV
rows gives 506 entries with such a reference and 13 without for
`unins000.exe`; the totals are 1,856 and 62. These counts match the summary
in `rk-native-api-imports.md`. Imports without these references may be used
through an indirect pointer, callback, or path outside this scan; they are not
proven unused.

The exact 62 rows lacking both a direct IAT call and a relative call to an
import thunk are extracted in
[`rk-native-api-callsite-gaps.csv`](rk-native-api-callsite-gaps.csv). The CSV
retains any other absolute IAT-reference and thunk addresses found for those
entries. The gap means this scan did not recover a direct call instruction; it
does not mean that the API is unused.

Static follow-up resolves several important examples as register-indirect
calls. The main UI loads `SetupDiGetDeviceInterfaceDetailW` into `EBP` and
calls it twice during the HID interface path; it loads
`RegisterDeviceNotificationW` into `EBX` and calls it twice for its USB/HID
filters; cleanup loads `UnregisterDeviceNotification` into `EDI` and calls it
for both saved handles. These transfers are not represented as direct
`call [IAT]` or relative calls to an import thunk, so they remain in the
no-direct-call CSV while their local behavior is documented in the
[HID enumeration and notification audit](rk-device-enumeration-notification-audit.md).

A broader static follow-up mapped indirect calls, callbacks, and one imported
data reference for **52 of those 62 rows**; 10 have no recovered invocation
path. This includes a `DeviceDriver.exe` `PostQuitMessage` wrapper with seven
direct callers and an IAT tail-jump. Four additional imported-API routes are
conditional tail-jumps. A hash-pinned revalidation found three omitted
DeviceDriver call instructions, correcting the register-indirect total from
106 to 109. This does not change the raw scan counts above. Per-API addresses
and the exact unresolved list are in the
[indirect import-call audit](rk-native-api-indirect-call-audit.md).

For `unins000.exe`, the raw executable-section `E8` scan finds candidates at
`0x0044B2BC`, `0x004A9CE7`, and `0x004F4D04` whose computed targets are known
import thunks. The first two byte sequences lie within UTF-16 string data. A
boundary-aware follow-up identifies `0x004F4D04` as a real call to the
`SetLastError` import thunk from an exception action block. A one-record scope
table reaches it through `RtlUnwind` when the matching exception type is
dispatched; the ordinary path skips the block. Runtime occurrence and the
type descriptor's identity remain unresolved. The call was added to the
cross-reference ledger, bringing its recovered relative-call-to-thunk count
to 2,699. See the [uninstaller candidate audit](rk-unins000-third-e8-candidate-audit.md).

## Dynamic loader callsites

[`rk-dynamic-api-targets.csv`](rk-dynamic-api-targets.csv) currently contains
236 rows: the original 128 direct-IAT/import-thunk rows and 108 manually
confirmed register-indirect `GetProcAddress` calls. The latter include seven
calls in the first main-driver block and 101 calls across the 17 other
previously unexpanded IAT-reference blocks in `DeviceDriver.exe`, `Update.exe`,
and `InitSetup.dll`. Recounting by binary and imported loader API gives:

| PE | `GetProcAddress` | `LoadLibraryA` | `LoadLibraryW` | `LoadLibraryExA` | `LoadLibraryExW` | Total rows | Rows with no nearby literal candidate (`[]`) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `DeviceDriver.exe` | 95 | 3 | 6 | 0 | 0 | 104 | 7 |
| `InitSetup.dll` | 14 | 1 | 0 | 0 | 0 | 15 | 0 |
| `Dev/01AF/Update.exe` | 87 | 0 | 2 | 0 | 5 | 94 | 4 |
| `unins000.exe` | 9 | 1 | 9 | 1 | 3 | 23 | 11 |
| `uninstall.dll` | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| **Total** | **205** | **5** | **17** | **1** | **8** | **236** | **22** |

The 22 empty candidate lists count the original direct-IAT/import-thunk
rows; all 108 added register-indirect rows have statically recovered module
and export arguments. Nearby DLL or export strings are candidates only for
the original scan rows: adjacency does not prove call execution. The 17
previously unexpanded `GetProcAddress` IAT-reference blocks are now decoded
into concrete call rows, but this remains a bounded static inventory, not a
complete resolver graph. Several API paths are traced in the main report,
including main-app DPI/menu/GDI compatibility, updater activation-context/WinRT
setup, installer modal-error handling, and uninstaller ACL updates. Caller
reachability, full consumers for all cached pointers, and runtime execution
remain unresolved. Two updater literals are the W-suffixed strings
`GetFileInformationByHandleExW` and `SetFileInformationByHandleW`, while the
canonical export names omit `W`. A current-host `GetProcAddress` probe on
Windows 11 Pro 10.0.26200 build 26200 returned null for the literal requests
and non-null for `GetFileInformationByHandleEx` and
`SetFileInformationByHandle`; see the audit for method and limits. See the
[dynamic API resolution audit](rk-dynamic-api-resolution-audit.md) for
per-call evidence and caveats.
The ten import rows that still lack a recovered invocation path were also
checked for direct relative transfers and exact RVA references; that wider
scan found no additional consumer and does not prove runtime unavailability.
See the [relative-reference follow-up](rk-unresolved-native-api-relative-reference-followup.md).

## Native system-call boundary

All five PEs have zero ordinary or delay imports from `ntdll.dll`, and none
declares an imported API whose name begins with `Nt` or `Zw`. A raw scan of
executable sections reproduced the existing byte-pattern counts:

| PE | `0F 05` (`syscall` byte pattern) | `0F 34` (`sysenter` byte pattern) | `CD 2E` (`int 2e` byte pattern) |
| --- | ---: | ---: | ---: |
| `DeviceDriver.exe` | 5 | 4 | 1 |
| `Dev/01AF/Update.exe` | 4 | 2 | 0 |
| `InitSetup.dll` | 0 | 1 | 0 |
| `uninstall.dll` | 0 | 0 | 0 |
| `unins000.exe` | 1 | 0 | 0 |

These are byte matches, not counts of executed system calls. In the saved
Ghidra analysis, the two `DeviceDriver.exe` `0F 05` locations at `0x00464224`
and `0x00464354` are lookup-table data. For the remaining 16 matches, GNU
`objdump`'s linear decode places the bytes inside instruction operands or
across decoded instruction boundaries; it does not decode them as separate
`syscall`, `sysenter`, or `int 2e` instructions. Linear decoding can be
misleading where code sections contain embedded data, so this is not a full
reachability proof. No reachable direct-system-call wrapper was recovered and
no runtime system-call trace was taken. Calls inside Windows DLLs, kernel
drivers, COM servers, dynamically resolved pointers, and external device
drivers are outside this five-PE import/xref analysis.

Exact candidate addresses, section-relative offsets, and surrounding bytes
are listed in
[`rk-native-syscall-byte-matches.csv`](rk-native-syscall-byte-matches.csv).
Every row is labeled as a raw byte-pattern match; none is promoted to a system
call without instruction-boundary and reachability evidence.
The follow-up [4.06 instruction-boundary audit](rk-406-system-call-byte-audit.md)
classifies all 18 candidates in these five images: two are embedded table
data, and the other 16 lie inside ordinary instruction encodings.

## Evidence status and remaining work

- **Proven statically:** the five installed PE hashes/sizes; complete ordinary
  and delay import descriptor row coverage for these PEs; exact IAT RVA/API
  row matching; the recovered callsite address totals; the listed static
  dynamic-loader callsites; and the absence of declared `ntdll.dll` imports.
- **Inferred from static code:** purpose of API clusters and the UI, HID,
  updater UART, installer, and uninstaller paths documented in the main
  report. These are disassembled paths, not observed runs.
- **Unresolved:** full call graphs for all 13,735 main-app procedures, all
  indirect/COM-vtable and callback targets, remaining caller-fed values and
  argument-to-returned-pointer links across the 236 target-ledger rows,
  complete consumers for every resolved function pointer,
  the matching type and runtime occurrence of the uninstaller `SetLastError`
  exception action, exact runtime branches, and any native system calls occurring
  inside Windows or device drivers. Runtime tracing must remain separate from
  this offline inventory. This report contains no updater launch or keyboard
  write; separately authorized read-only interface observations are recorded
  in the [firmware readback audit](rk-firmware-readback-audit.md).

The feature-read request relationships and file-sink assessment are detailed
in the [HID read/sink audit](rk-hid-read-request-and-firmware-sink-audit.md).
Neither static analysis nor the separately recorded read-only observations
demonstrate a complete firmware export path.
