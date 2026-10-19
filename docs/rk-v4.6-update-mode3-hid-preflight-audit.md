# RK 4.6 updater mode-3 HID preflight and fallback path

## Scope and evidence

This focused addendum checks the V4.6 package's model updater command `0x0419`
against the exact packaged binary and follows the mode-3 HID selection path
through its preflight, status probe, and fallback transfer-thread creation. It
does not re-map the updater's full firmware transfer routine or UART state
table; those remain in the [command trace](rk-updater-command-0419-static-path-audit.md),
[firmware audit](rk-firmware-readback-audit.md), and
[UART state-machine report](rk-updater-uart-state-machine.md).

The evidence is static x86 disassembly and existing resource/parser findings.
No RK binary was launched, no HID or serial interface was opened, and no
device report or command was sent.

- **Direct** means the bytes, branch, API call, or memory access are present
  in the identified image.
- **Inferred** means the interpretation follows from direct data flow but was
  not observed at runtime.
- **Unresolved** means static evidence does not establish the result.

## Exact package inputs

The V4.6 manifest records `app/Dev/01AF/Update.exe` as 2,109,952 bytes with
SHA-256
`27894463b0dfe5bc3f5dc19d4d3351d9dfb692c402bf277bde3889d37e4a206c`.
The installed 4.06 `Dev/01AF/Update.exe` has the same size and hash, so this
4.6-labeled package uses the same updater image for this path. All addresses
below are virtual addresses for that PE image, whose base is `0x00400000`.

The packaged sample
`app/Dev/01AF/KB_762_1_v258A_p01AF_F90_8818_V90.0f.1.00.upf` is 193,652
bytes, SHA-256
`e21c11e023247afc7fdbbe27548570240efa5b646147741d5354eecb3041b628`.
Its header declares mode byte `03`, VID bytes `25 8A` (parser value
`0x258A`), and PID bytes `01 AF` (parser value `0x01AF`). The existing parser
audit records an A-section length of `0xF000716D`, which exceeds the file
size. Therefore the mode-3 behavior below describes a conditional code path;
the static evidence does not show that this packaged sample is accepted or
that the mode-3 path runs with it.

## `0x0419` to the mode-3 worker

The command-map entry routes `0x0419` to `FUN_00409DC0`. After the selected
file parser returns something other than `0xFF`, the handler reads edit
controls `0x0424` and `0x0425`, stores converted values in globals
`0x005C6F78` and `0x005C6F74`, and creates a thread starting at
`FUN_00406AE0` (`CreateThread` call at `0x0040A0AD`). The handler clears
`this+0x8E6C` at `0x00409DEA`.

**Direct correction to the general command summary:** when
`0x005C5F0C == 3`, `FUN_00406AE0` does not pass the text-field VID/PID to its
first HID searches. It loads `ECX=0x0603` and `EDX=0x1021` before each helper
call (`0x00406B4D`–`0x00406B73`):

1. `FUN_00406730(0x408)` at `0x00406B5C` returns a long-feature HID handle
   into `0x005C5F14`.
2. `FUN_00406900` at `0x00406B73` returns a second handle into
   `0x005C5F18`.
3. Only if both results differ from `-1` does the worker set
   `this+0x8E6E=0x100` and call `FUN_0040A0F0` (`0x00406B7D`–`0x00406B9D`).
   If either search fails, it clears the field and calls `FUN_0040A580`
   (`0x00406BAB`–`0x00406BBD`).

The `ECX` and `EDX` values are the helper's vendor and product comparison
inputs, respectively: each helper saves them and compares them with the
`VendorID` and `ProductID` members returned by `HidD_GetAttributes`. The
selectors on this direct mode-3 branch are therefore VID `0x0603`, PID
`0x1021`; their relationship to the `.upf` header's `258A:01AF` is
**unresolved**. The code does not establish that either pair is a bootloader
identity.

## What the two HID helpers select

Both helpers enumerate HID device interfaces via SetupAPI, obtain interface
paths, and call `CreateFileW` with `GENERIC_READ | GENERIC_WRITE`, share mode
`3`, `OPEN_EXISTING`, and `FILE_FLAG_OVERLAPPED`. They then use
`HidD_GetAttributes`, `HidD_GetPreparsedData`, and `HidP_GetCaps`, closing
nonmatching handles. This records the binary's static open/write capability;
none of these paths was executed for this audit.

`FUN_00406730` (`0x00406730`) accepts the caller's feature-length value and
returns a handle only when all these comparisons match:

- `HIDD_ATTRIBUTES.VendorID` and `ProductID` equal its `ECX` and `EDX`
  inputs;
- `HIDP_CAPS.UsagePage` equals `0xFF00`;
- `HIDP_CAPS.FeatureReportByteLength` equals the stack argument exactly.

The mode-3 call's `0x408` is decimal 1,032 bytes. The field offsets used by
the code match the documented `HIDP_CAPS` layout, where `UsagePage` and
`FeatureReportByteLength` are members of the structure ([Microsoft
documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/hidpi/ns-hidpi-_hidp_caps)).

`FUN_00406900` applies the same VID/PID and `UsagePage == 0xFF00` checks, but
accepts a nonzero `FeatureReportByteLength` no greater than 8. On a match it
also stores `HIDD_ATTRIBUTES.VersionNumber` in `0x005C6FD8` and the feature
length in `0x005C5F1C`. Mode 3 therefore requires a matched 1,032-byte
feature collection and a matched short-feature collection for the same
selector pair; the runtime interface paths and actual lengths are unknown.

The direct imported API call sites in the two helpers are:

| Operation | `FUN_00406730` | `FUN_00406900` |
| --- | ---: | ---: |
| `SetupDiGetClassDevsW` | `0x0040676F` | `0x0040693F` |
| `SetupDiEnumDeviceInterfaces` | `0x0040678D` | `0x0040695D` |
| `SetupDiGetDeviceInterfaceDetailW` | `0x004067B6`, `0x004067E7` | `0x00406983`, `0x004069AE` |
| `CreateFileW` | `0x00406803` | `0x004069CA` |
| `HidD_GetAttributes` | `0x00406822` | `0x004069E9` |
| `HidD_GetPreparsedData` | `0x0040682D` | `0x004069F4` |
| `HidP_GetCaps` | `0x0040683E` | `0x00406A05` |

## Retry, status probe, and transfer entry

The `0x0419` handler's cleared `this+0x8E6C` flag sends the mode-3 worker
through the main search loop in `FUN_0040A0F0` (branch at `0x0040A17D`–
`0x0040A1A1`). Its counter starts at 7 (`0x0040A1A7`). Although the preflight
has already stored both handles, `FUN_0040A0F0` enumerates `0603:1021` again
and overwrites those globals. Each mode-3 pass searches that selector with
the same pair of helper criteria. If that pair
does not produce two handles, it updates the search status, sleeps 2,000 ms,
then tries `VID=0603`, `PID=1020`: `FUN_00406730(0x802)` at `0x0040A291`
and `FUN_00406900` at `0x0040A2A8`. Here `0x802` is decimal 2,050, so the
long-feature helper requires a 2,050-byte `FeatureReportByteLength`; the
short-feature helper still requires a nonzero length of at most 8. The
counter gates retries after fallback failures.

If the `0603:1020` pair succeeds, `FUN_0040A0F0` directly creates a thread
whose start routine is `FUN_00406BD0` (`CreateThread` call at
`0x0040A3B4`). That worker calls `FUN_0040C090` at `0x00406C10`, which calls
section dispatcher `FUN_00402A40` at `0x0040C099`. The dispatcher is the
existing mode-selected HID transfer path; its report writes and verification
reads are documented in the firmware audit.

The first `0603:1021` pair has a different next edge. Once both handles are
found, `FUN_0040A0F0` sets status and calls `FUN_00409760` at `0x0040A35A`;
there is no direct `FUN_00406BD0` thread creation on that branch. The helper
builds a feature report beginning `05 C9 60`, sends it with
`HidD_SetFeature` at `0x004097A8`, then polls with `HidD_GetFeature` at
`0x0040980D` (up to six one-second intervals). It checks for a `60` response
prefix and updates the gate `0x005C5F08` from the response byte. If this poll
returns zero in mode 3, `FUN_0040A0F0` calls `FUN_0040A580` at
`0x0040A389`; otherwise the caller returns while the probe helper has started
the separate `FUN_00406C20` worker. A follow-up traces that worker through
`FUN_0040B770` into a conditional `FUN_0040A580` call and then the fallback
`0603:1020` pair that can create `FUN_00406BD0`; see the
[status-to-transfer follow-up](rk-v4.6-mode3-status-to-transfer-worker-followup.md).
The branch predicates and device responses remain unobserved. The separate
timer-3 handler can also create `FUN_00406BD0`, but the timer's origin remains
unresolved in the existing timer audit.

## Mode-switch fallback path

The mode-3 preflight failure edge from `FUN_00406AE0` and the status-poll
failure edge above call `FUN_0040A580`. This function allocates a six-byte
buffer, zeroes it, and sets the first bytes to `05 75` (`0x0040A603`–
`0x0040A648`). On its `this+0x8E6C == 0` path, the short-interface selector
is conditional: only mode 3 with `this+0x8E6F == 1` uses hard-coded
`0603:1021` (`0x0040A662`–`0x0040A684`); otherwise it uses the values copied
from the UI fields (`0x0040A69F`–`0x0040A6AB`). The `0x0419` chain does not
write `this+0x8E6F`, while dialog initialization clears it; whether another
untraced action changes it before this helper runs is unresolved.

If the short-interface helper returns a handle, the function calls
`HidD_SetFeature` at `0x0040A75A`, passing that six-byte buffer and length
`0x005C5F1C` (the selected collection's feature length). It then sleeps
3,000 ms and searches the fallback pair `0603:1020` again with
`FUN_00406730(0x802)` (`0x0040A77A`) plus `FUN_00406900`
(`0x0040A791`). When both handles are found it creates
`FUN_00406BD0` (`CreateThread` at `0x0040A841`). The function repeats this
search sequence under a local retry counter; the number of retries and any
success on an actual device were not observed.

The exact buffer allocation and call length also reveal a **potential static
size mismatch**: the report buffer allocation is six bytes, while the matched
short collection may advertise any feature length from 1 through 8. The
`HidD_SetFeature` call passes the advertised value. If a matching collection
reports more than six bytes, the call's requested length exceeds the visible
allocation. This is a static risk only; the actual selected length and API
behavior were not tested.

## UART boundary and conclusions

The newly traced mode-3 selectors and downstream calls are on the HID path.
In the direct call edges mapped here, there is no call to serial-open routine
`FUN_00404E60` or direct store to UART dispatch state `0x005C5F58`. The updater's `0x0401`
serial receive handler and 15-state table remain separately mapped in the
[UART report](rk-updater-uart-state-machine.md). This does not rule out an
indirect or externally triggered relationship; no such edge is established
here.

- **Proven statically:** accepted mode 3 enters a `0603:1021` preflight using
  1,032-byte and 1–8-byte feature collections; the direct retry path checks
  `0603:1020` using a 2,050-byte collection and a 1–8-byte collection.
- **Proven statically:** fallback-pair success creates the section-transfer
  worker; status-probe or preflight failure can enter a `05 75` feature-write
  path before retrying the `1020` pair.
- **Inferred:** these fixed ID pairs select different updater device modes.
  Their hardware or bootloader meaning is not established.
- **Unresolved:** whether the malformed packaged `.upf` is accepted, which
  interface paths are chosen at runtime, whether the 1,032/2,050-byte
  collections exist for those IDs, the `+0x8E6F` value at mode-switch time,
  whether the successful `1021` status response and secondary-worker branch
  predicates are satisfied at runtime, and the origin of timer 3.
- **Unresolved:** any direct or indirect link between this HID path and the
  UART response/file sinks.

## Static reproduction

With GNU `objdump` and the manifest-listed image, these commands reproduce the
key disassembly ranges without executing the updater:

```powershell
objdump -d -M intel --start-address=0x00406AE0 --stop-address=0x00406BE0 Update.exe
objdump -d -M intel --start-address=0x00406730 --stop-address=0x00406AE0 Update.exe
objdump -d -M intel --start-address=0x00406900 --stop-address=0x00406AE0 Update.exe
objdump -d -M intel --start-address=0x0040A0F0 --stop-address=0x0040A3D0 Update.exe
objdump -d -M intel --start-address=0x00409760 --stop-address=0x00409880 Update.exe
objdump -d -M intel --start-address=0x0040A580 --stop-address=0x0040A8C0 Update.exe
```
