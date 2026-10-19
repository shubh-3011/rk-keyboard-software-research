# DeviceDriver HID enumeration handle lifecycle: 4.06 and 4.6

## Scope and evidence boundary

This note records only the SetupAPI/HID interface-enumeration path and the
CreateFile/preparsed-data handle lifecycle in two exact `DeviceDriver.exe`
images. It complements
[`rk-device-enumeration-notification-audit.md`](rk-device-enumeration-notification-audit.md)
and the broader [4.6 native API call-path audit](rk-v4.6-native-api-call-path-audit.md).
Both binaries were examined offline using PE metadata, disassembly, and static
cross-references; neither executable was launched, and no keyboard or HID
interface was opened. Addresses below are image virtual addresses.

| Version | Evidence file | SHA-256 | Size |
| --- | --- | --- | ---: |
| Installed 4.06 | `C:\Program Files (x86)\RK Keyboard Software\DeviceDriver.exe` | `c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6` | 2,326,528 |
| Extracted 4.6 package | `.research/rk4_6_official_extract_20261015/app/DeviceDriver.exe` | `8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9` | 2,418,176 |

The 4.06 hash is also recorded in
[`rk-native-api-imports.md`](rk-native-api-imports.md); the 4.6 package identity
is recorded in [`rk-v4.6-package-snapshot.md`](rk-v4.6-package-snapshot.md).
“Proven” below means a static instruction/dataflow fact for those exact files,
not observed runtime behavior.

## Enumeration path correspondence

| Path | Installed 4.06 | Package 4.6 | Static evidence |
| --- | --- | --- | --- |
| Outer enumerator | `FUN_004164B0`, `0x004164B0–0x0041655D` | `FUN_00417330`, `0x00417330–0x004173DD` | Gets HID class GUID; calls `SetupDiGetClassDevsW` with flags `0x12`; loops `SetupDiEnumDeviceInterfaces`; calls per-interface helper; destroys the device-info set on the observed exits. |
| Per-interface helper | `FUN_00416570`, relevant range `0x00416570–0x0041673A` | `FUN_004173F0`, relevant range `0x004173F0–0x004175BD` | Calls `SetupDiGetDeviceInterfaceDetailW` through a loaded IAT pointer twice (size query, then path retrieval); attempts `CreateFileW`; queries HID attributes and preparsed capabilities; records selected metadata; closes a valid file handle. |
| Slot lookup | `FUN_00416480`, `0x00416480–0x004164AF` | `FUN_00417300`, `0x00417300–0x0041732F` | Searches an 80-entry table at stride `0x22C` for a row whose first word is zero. |
| Capability selector | `FUN_00416740` | `FUN_004175C0` | Queries specific button/value capability data and returns a selector in `AX`; the caller stores it and selected `HIDP_CAPS` words in the row. |

The outer enumerators use `HidD_GetHidGuid`, `SetupDiGetClassDevsW`,
`SetupDiEnumDeviceInterfaces`, and `SetupDiDestroyDeviceInfoList`. The detail
API is a register-indirect call: 4.06 loads the IAT pointer at `0x00416580`
and calls it at `0x004165A1` and `0x004165EF`; 4.6 loads it at `0x00417400`
and calls it at `0x00417421` and `0x0041746F`. These are concrete callsites,
not an inference from import presence.

## Handle and access-mask flow

The helpers pass the resolved interface path to `CreateFileW` with share mode
`3`, null security attributes, creation disposition `3` (`OPEN_EXISTING`),
and zero flags/template. The requested access comes from a branch on a
zero-initialized trailing pool DWORD:

| Version | `CreateFileW` call alternatives | Access selector DWORD | Table allocation |
| --- | --- | --- | --- |
| 4.06 | `0x00416621` or `0x00416632`, IAT `0x0059E470` | `0x0062AC50` | zeroes `0xADC0` bytes at `0x0061FE90` (`80 × 0x22C`) in `FUN_00447090`; first metadata row is `base + 0x208` |
| 4.6 | `0x004174A1` or `0x004174B2`, IAT `0x005A6474` | `0x00646BF0` | zeroes `0xADC0` bytes at `0x0063BE30` (`80 × 0x22C`) in `FUN_004497C0`; first metadata row is `base + 0x208` |

For both versions, the static branch requests desired access `0x0012019F`
when the selector DWORD equals zero, and zero otherwise. PE section metadata
places each selector DWORD in the zero-initialized virtual tail of `.data`;
the inspected image has no direct `.text` store to either exact address.
Therefore `0x0012019F` is the default implied by the file image. This does not
prove the value stays zero at runtime: external or indirect writes are outside
this static conclusion. The reason for the alternate zero-access branch is
unresolved.

After the `CreateFileW` result is checked against `INVALID_HANDLE_VALUE`, a
valid handle is passed to `HidD_GetPreparsedData`, `HidD_GetAttributes`, and
`HidP_GetCaps` in that order. On successful capability extraction, the helper
uses the selector and copies selected capability fields into the matching
pool row, then closes the file handle with `CloseHandle` (`0x00416717` in
4.06; `0x00417597` in 4.6). The row stores selector at `+0x208` and copied
capability words at `+0x20C` through `+0x224`. The table does not visibly
retain the opened file handle. This enumeration helper contains no feature
report call; feature-report transport is handled at separate callsites
cataloged in the native API audits.

## Preparsed-data release candidate

The one direct `HidD_FreePreparsedData` callsite in each image is reached only
when `HidP_GetCaps` fails after preparsed data has been acquired:

| Version | Acquire preparsed data | Attributes | Capabilities | Free callsite | Handle close |
| --- | --- | --- | --- | --- | --- |
| 4.06 | `HidD_GetPreparsedData`, `0x0041664D` | `HidD_GetAttributes`, `0x0041665C` | `HidP_GetCaps`, `0x0041666B` | `0x00416679` (GetCaps failure edge) | `0x00416717` |
| 4.6 | `HidD_GetPreparsedData`, `0x004174CD` | `HidD_GetAttributes`, `0x004174DC` | `HidP_GetCaps`, `0x004174EB` | `0x004174F9` (GetCaps failure edge) | `0x00417597` |

In both helper ranges, an attributes-query failure after preparsed-data
acquisition branches to handle cleanup without a direct free call. The
successful `HidP_GetCaps` path proceeds through specific-capability queries,
row recording, and handle close, with no further direct
`HidD_FreePreparsedData` call. Static cross-reference inventory finds no
other direct free call in either image. These branches make an unreleased
preparsed-data allocation a **static leak candidate** on the attributes-fail
and success paths. This is not a runtime leak measurement: indirect cleanup,
callee behavior, exceptional exits, or ownership conventions were not
established here.

## Findings and unresolved items

- **Proven statically:** both binaries use the same broad HID enumeration
  shape, 80 slots, `0x22C`-byte rows, HID preparsed/capability queries, and
  per-device `CreateFileW`/`CloseHandle` lifecycle.
- **Proven statically:** the helpers make no feature-report request in their
  analyzed ranges; the recorded table row contains selector/capability
  metadata, not the opened handle.
- **Static leak candidate:** `HidD_FreePreparsedData` appears once per image
  and its direct callsite is restricted to the `HidP_GetCaps` failure edge;
  no direct release is present on the visible attributes-failure or success
  edges.
- **Unresolved:** what sets the access-selector DWORD away from its initial
  zero; why the alternate branch requests access zero; the semantic meaning
  of the selector/capability row for each profile; whether cleanup is
  performed indirectly or by an ownership convention; and runtime behavior
  on real devices.

This is a static code-path note and does not describe the separate live
read-only HID probe recorded in the
[firmware readback audit](rk-firmware-readback-audit.md). No device API was
called while producing this static analysis.
