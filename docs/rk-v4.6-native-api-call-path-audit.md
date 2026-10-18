# RK DeviceDriver.exe 4.6 native API call-path audit

## Scope and safety

This audit examines only the `DeviceDriver.exe` extracted from the 4.6-labeled
package. Its SHA-256 is
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`
(2,418,176 bytes). It is not evidence about the separate 4.6 updater, other
RK drivers, other builds, or runtime behavior. The executable was not run; no
keyboard interface was opened and no device data was sent or changed.

The machine-readable inventory is
[`rk-v4.6-native-api-call-sites.csv`](rk-v4.6-native-api-call-sites.csv). It
contains each ordinary and delay import with its IAT RVA and VA, plus the
decoded direct IAT calls, direct IAT jumps, and relative calls to discovered
IAT-jump thunks. `call_iat_register` rows are a supplemental conservative
same-straight-line-block heuristic for `mov reg,[IAT]` followed by `call reg`;
they are not a complete register data-flow analysis.

## Method and evidence labels

[`audit_rk46_import_call_sites.py`](../scripts/audit_rk46_import_call_sites.py)
pins the input SHA-256, reads ordinary/delay import descriptors using pefile,
and parses GNU `objdump -d` output. It accepts direct calls/jumps only when
the decoded instruction bytes are `FF 15 <IAT VA>` / `FF 25 <IAT VA>` and the
IAT VA matches an import-table entry. It identifies import thunks as decoded
`FF 25 <IAT VA>` jumps, then records an `E8 rel32` call only when the decoded
target equals one of those thunk addresses. VAs are for the PE's preferred
image base `0x00400000`.

**Proven statically** below means supported by this exact PE's import table,
bytes, strings, or decoded instructions. **Inferred** means the likely purpose
suggested by those static artifacts. **Unresolved** means the call graph,
branch reachability, caller arguments, device result, or firmware behavior was
not established by this pass.

The decoder starts a linear sweep over executable code. An instruction address
and exact encoding are validated as GNU objdump's decoded instruction, but
this is not a control-flow graph: embedded data can be decoded as instructions,
and a listed callsite is not proof that the function is reachable or executes.
The register-call heuristic is even narrower: it requires a recognized
absolute IAT load and call through the same register without a branch,
intervening call, or explicit write. The CSV does not include every possible
callback, vtable, dynamically resolved API, or register-indirect transfer.

## Inventory coverage

The pinned image has 675 ordinary and 3 delay imports. The decoded sweep
yielded 570,387 instruction lines and 106 distinct IAT-jump thunk slots. The
CSV contains:

| Static transfer class | Rows |
| --- | ---: |
| Direct `call [IAT]` | 6,451 |
| Direct `jmp [IAT]` (including import thunk stubs) | 107 |
| Relative `call` to an identified import thunk | 633 |
| Supplemental same-block register-indirect calls | 855 |
| Import entries with no recognized transfer in these scans | 16 |

These are decoded instruction-site counts, not runtime call counts. In
particular, the 6,451 direct calls include normal UI/framework APIs and do not
mean the device protocol executes that many times. The 16 imports with no
recognized transfer are unresolved, not proven unused. Register-flow routes
that cross a conditional branch require manual or CFG analysis; examples are
called out below and may be absent from the supplemental CSV rows.

## Added imports versus the installed 4.06 baseline

The previous binary delta audit identified four added imports. Their 4.6
instruction paths are now statically mapped:

| API | IAT VA | Decoded callsite evidence | What it supports |
| --- | ---: | --- | --- |
| `KERNEL32!GetPrivateProfileStringA` | `0x005A63C8` | Direct call `0x00456748` | Reads local section `OPT`, key `TouchWeb`, into a 50-byte buffer; empty value takes an RK Drive URL fallback. Final consumer action remains unresolved. |
| `USER32!SendInput` | `0x005A66DC` | Direct call `0x0045877A` | Helper emits 28-byte Unicode keyboard down/up record pairs in batches of at most 64 code units. A caller at `0x0044B1BF` is gated by numeric fields and selects text from a fixed table; its visible feature name/reachability remain inferred or unresolved. |
| `gdiplus!GdipGetPropertyItemSize` | `0x005A696C` | Thunk `0x00590914` jumps to the IAT; relative caller `0x0046F34C` | Reads property identifier `0x5100` in a multi-frame image timing path; frame selection and timer are mapped, while the asset/feature tie remains unresolved. |
| `gdiplus!GdipGetPropertyItem` | `0x005A6968` | Thunk `0x0059091A` jumps to the IAT; relative caller `0x0046F376` | Reads the item used by the same image-frame timing path. See the dedicated follow-up for the interval and fallback evidence. |

The argument, caller and local-UI traces for these additions are collected in
the [native API feature follow-up](rk-v4.6-native-api-feature-follow-up.md).

The two GDI+ callers pass property identifier `0x5100` in the shown code. This
is static argument evidence only; this report does not assign a semantic name
to that property or tie it to the Side LED feature. The removed
`gdi32!AddFontResourceW` has no 4.6 IAT entry to cross-reference.

## HID discovery, handle open, and report capability checks

The following paths are decoded in the 4.6 image itself; their addresses are
not copied from the 4.06 build:

1. `HID!HidD_GetHidGuid` has IAT VA `0x005A61E4`, with a thunk at
   `0x00590A14` and relative call `0x0041734C`.
2. `SetupDiGetClassDevsW` (`0x005A6514`) is called directly at `0x0041735C`.
   `SetupDiEnumDeviceInterfaces` (`0x005A6518`) is called at `0x00417380` and
   `0x004173AF`; `SetupDiDestroyDeviceInfoList` (`0x005A651C`) is called at
   `0x004173BA` and `0x004173D5`. The instruction sequence initializes an
   enumeration index, repeats the interface-enumeration call, and destroys
   the device-info list on exit paths.
3. `SetupDiGetDeviceInterfaceDetailW` has IAT VA `0x005A6510`, loaded into
   `EBP` at `0x00417400`. The same function body calls through `EBP` at
   `0x00417421` and, after a conditional branch and buffer setup, at
   `0x0041746F`. The first call passes a null detail buffer and a required-size
   pointer, consistent with the documented size-query pattern (**inferred**);
   the second supplies the prepared buffer. The branch-spanning second call
   is not recovered by the CSV's straight-line register heuristic.
4. `CreateFileW` is called at `0x004174A1` and `0x004174B2` after the detail
   query and uses the resulting path buffer. This supports a device-interface
   open path in the code, but the static report does not prove the path resolves
   to the connected S98 or that either branch succeeds.
5. The resulting handle is passed to `HidD_GetAttributes` at
   `0x004174DC`, then through `HidD_GetPreparsedData` (`0x004174CD`),
   `HidP_GetCaps` (`0x004174EB`), and HID button/value-capability queries at
   `0x00417673` and `0x004176A5`. A failure path frees preparsed data at
   `0x004174F9`. Other `HidD_GetAttributes` callers are at `0x0040DEF8`,
   `0x0040FF35`, and `0x00417732`.

Device-change notification imports are also used through register copies:
`RegisterDeviceNotificationW` IAT VA `0x005A6708` is loaded at `0x00449720`
and called through `EBX` at `0x00449753` and `0x0044979A`.
`UnregisterDeviceNotification` IAT VA `0x005A6720` is loaded at
`0x004487C0` and called through `EDI` at `0x004487C7` and `0x004487D0`.
These support host-side arrival/removal notification handling; they do not
show a keyboard write.

## HID feature-report calls

`HidD_SetFeature` is imported at IAT VA `0x005A61E0`, with thunk
`0x00590A08`; relative callsites are `0x0040F91D`, `0x0041014F`,
`0x004104EF`, `0x00410731`, `0x00410992`, `0x00410E1F`, `0x00413ACF`, and
`0x00414036`. Seven shown callers pass a length of `0x208` bytes; the final
caller passes `0x41` bytes. `HidD_GetFeature` is imported at IAT VA
`0x005A6200`, with thunk `0x00590A0E`; relative callsites are `0x0040F975`,
`0x004101C1`, `0x0041054E`, `0x0041078C`, `0x004109F1`, and `0x00410E7E`.

This proves that the executable contains code that calls Windows HID feature
report APIs with those buffer lengths. The functions consume a handle and
buffer, and nearby code checks return values. This pass does **not** recover
all report bytes, report IDs, command meanings, model gates, complete caller
function boundaries, or which calls run for the attached S98. The existence of
these calls is not evidence that firmware can be read or copied without
writing; see the separate
[`rk-firmware-readback-audit.md`](rk-firmware-readback-audit.md) and the
updater/UART reports for the unresolved firmware question.

The imports `CreateFileW` (IAT `0x005A6474`), `ReadFile` (`0x005A6470`),
`WriteFile` (`0x005A646C`), `GetOverlappedResult` (`0x005A6450`), and
`CancelIo` (`0x005A6454`) have additional callsites. Their many handles are
not all traced back to a device open in this audit; those file APIs must not be
treated wholesale as HID or firmware traffic.

## Deferred settings worker signal

The native API ledger lists `CreateSemaphoreW`, `ReleaseSemaphore`, and
`WaitForMultipleObjects` callsites, but its IAT inventory alone does not group
them into a device-settings route. The hash-pinned
[`CDevRKKB` and signal-path audit](rk-v4.6-cdevrkbb-settings-and-vtable-audit.md)
links the worker semaphore at `0x006356C4` to its queue, active-device
dispatch, and `ApplySetting` vtable slot. A separate
[24-caller ledger](rk-v4.6-apply-signal-callers.csv) identifies all decoded
direct callers of `0x00401100`; it keeps the caller class and UI-control
mapping unresolved. Other `ReleaseSemaphore` sites use a different global
handle and are not assumed to wake this worker. No worker was run.

## Side LED and text-macro references

### Proven static references

The 4.6 image contains and references configuration literals for `ShowLED`,
`ShowTextMacro`, `ShowSideLED`, `DefSideLedIndex`, `SideLedOpt%d`, and
`tc_side_led%d`. The `ShowLED` and `ShowTextMacro` addresses are pushed in
code at `0x004549B8` and `0x00454A06`; `ShowSideLED` and `DefSideLedIndex`
are referenced at `0x00455D38` and `0x00455D5A`; `SideLedOpt%d` is referenced
at `0x00455DF7`; and `tc_side_led%d` at `0x0045E197`. These references sit in
profile/configuration handling code that also passes string keys and buffers
to internal helpers and `GetPrivateProfileStringW`. This supports that the
binary reads local feature/configuration state; it does not by itself prove a
reachable dialog or a device command.

The binary contains `sideled_nr.png` and `sideled_ov.png`, referenced from
code at `0x0045BBD3` and `0x0045C3B1`/`0x0045C3C8`. The format string
`%sDev\\%04X\\sideled.png` is referenced at `0x0045E6BD`; a separate
`%sDev\\%04X\\SideLed\\%s\\led.xml` literal exists in the image, but a
direct code reference to that exact string was not recovered by the raw
address search. These are asset/path references only; the helper routines and
per-model directory contents are not resolved here.

The `CSideLedDlg` RTTI name and Side LED strings are evidence of compiled
feature-related code. The corresponding feature's reachability, actual visual
layout, supported-model gates, and relationship to the 4.6 profile catalog
remain unresolved.

### Local text-macro file path

The `textmacro.dct` string is referenced at `0x0041F55C` and `0x004597FC`.
At the first site, code builds a path, calls `CreateFileW` at `0x0041F59A`
with desired access `0xC0000000` (read/write bits), writes `0xC8C8` bytes via
`WriteFile` at `0x0041F5C1`, then closes the handle at `0x0041F5C8`. At the
second site, code opens with desired access `0x80000000` (read), reads
`0xC8C8` bytes via `ReadFile` at `0x00459861`, then closes at `0x00459868`.
This is strong static evidence for host-side local macro-file persistence.
The file format and exact UI-to-serialization call graph are unresolved. These
file operations do not identify firmware storage or a keyboard readback path.

The `SendInput` call at `0x0045877A` is host input injection. A gated caller
at `0x0044B1BF` looks up a text record in the same `0x0060D3C4` table and
passes the UTF-16 record text to the helper; the table is also the buffer
read/written by the `textmacro.dct` helpers. This supports an inferred
text-macro playback route. The numeric gate meanings, visible trigger, and
full UI-to-playback path remain unresolved; see the
[native API feature follow-up](rk-v4.6-native-api-feature-follow-up.md).

## Conclusions and remaining limits

**Proven statically:** this hash imports the listed Windows APIs; the CSV maps
decoded direct IAT calls, IAT jumps, and relative calls to detected import
thunks. Independent 4.6 code also contains a SetupAPI/HID discovery/open path,
feature-report callsites, local profile keys and Side LED assets, and local
`textmacro.dct` read/write paths.

**Inferred:** the setup path is intended to enumerate HID interfaces and
inspect report capabilities; Side LED keys/assets support a Side LED UI or
preview; the `SendInput` path likely implements text-macro playback; and the
GDI+ property path likely controls animation timing.

**Unresolved:** full CFG reachability, dynamic API/COM targets, all register
and callback data-flow, complete UI control-to-handler links, all feature
report payload semantics, per-model behavior, live S98 identity, runtime
success, and whether firmware can be copied safely. This audit does not close
the broader reverse-engineering goal and makes no firmware-readback claim.
