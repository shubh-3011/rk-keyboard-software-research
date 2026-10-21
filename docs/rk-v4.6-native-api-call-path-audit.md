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

The original CSV above is preserved as the raw conservative scan. A separate
[reconciled companion CSV](rk-v4.6-native-api-call-sites-reconciled.csv)
adds the manually reviewed calls from the hash-pinned
[unresolved-reference follow-up](rk-v4.6-unresolved-api-reference-audit.md).
That follow-up resolves the raw scan's 16 `none_decoded` import rows to 31
static `call reg` instruction sites, including both `PlaySoundW` calls in its
worker. The companion has 8,077 rows, 886 register-indirect call rows, and no
remaining `none_decoded` rows. This merged view improves API-site accounting;
it still does not establish a complete CFG, caller reachability, or runtime
execution. Regenerate it with
[`reconcile_rk46_api_call_sites.py`](../scripts/reconcile_rk46_api_call_sites.py).

## Added imports versus the installed 4.06 baseline

The previous binary delta audit identified four added imports. Their 4.6
instruction paths are now statically mapped:

| API | IAT VA | Decoded callsite evidence | What it supports |
| --- | ---: | --- | --- |
| `KERNEL32!GetPrivateProfileStringA` | `0x005A63C8` | Direct call `0x00456748` | Reads local section `OPT`, key `TouchWeb`, into a 50-byte buffer; empty value takes an RK Drive URL fallback. The value reaches selector-`0x12` RK action/command helpers; browser launch and device outcome are not established. |
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
   `0x0041746F`. A branch-aware reaching-definition and stack-argument review
   confirms both calls use that IAT target: the first passes null detail data,
   size zero, a valid `RequiredSize` pointer, and null `DeviceInfoData`; the
   second passes the returned size and allocated detail buffer, reuses the
   required-size pointer, and also passes null `DeviceInfoData`. The first
   Boolean result is ignored; the second is tested. This matches the documented
   two-call size-query/retrieval pattern. The second call remains absent from
   the CSV's straight-line register heuristic because it is branch-spanning;
   see the detailed [root-CFG follow-up](rk-v4.6-rooted-cfg-callgraph-audit.md#per-interface-setupapi-detail-calls).
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

A stack-argument follow-up maps each GetFeature call to its paired SetFeature
call and confirms that all six pass the same handle. In the G5 `+0x34` and
`+0x70` helpers, the apparent `+0x2DC` handle mismatch disappears when the
pending delay argument is included in the stack calculation; that byte is
copied separately into the report. This is static argument evidence only; no
hardware response was observed. See the
[six-call handle audit](rk-v4.6-hid-getfeature-argument-audit.md).

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

## Host-local language preference write

For `DeviceDriver.exe` SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`, the
reconciled callsite ledger has a direct `KERNEL32!WritePrivateProfileStringW`
call at `0x00403643` (`FF 15 84 64 5A 00`, IAT VA `0x005A6484`). In the
surrounding code, the message handler at `0x00403670` compares its `lParam`
with the child window handle read through `this+0x8C/+0x20`; on a match, it
reads the selected integer from `this+0x11C` and passes it to `0x00403570`.
That routine uses the index to select a 120-byte locale-table record, formats
a `Text\\<locale>\\text.xml` path, and calls the internal locale loader at
`0x00444320`.

At `0x00403570`, the selected integer is also saved at global `0x0062BD64`.
The routine formats a local path buffer from the global prefix at
`0x006352B0` plus the literal `lang.ini`, and formats the integer as decimal
text with `%d`. The four `WritePrivateProfileStringW` arguments at
`0x00403643`, in API order, are:

| Argument | Value/source | Evidence |
| --- | --- | --- |
| `lpAppName` | `L"OPT"` | Literal at `0x005D0044`, pushed immediately before the call. |
| `lpKeyName` | `L"LangIndex"` | Literal at `0x005D0030`. |
| `lpString` | A stack buffer formatted as decimal `%d` from `0x0062BD64` | The selected index is copied to that global; the buffer address is pushed as the value argument. |
| `lpFileName` | A stack path buffer formatted as `"%slang.ini"`, using global prefix `0x006352B0` | Static startup path setup derives this prefix from `CSIDL_LOCAL_APPDATA` and configured `appdir`; the package `app/Cfg.ini` has `appdir=RKKB`; if that value is read, the intended path shape is `%LOCALAPPDATA%\RKKB\lang.ini`. The absolute `cfg.ini` source path is not established. Runtime execution and write success are not observed; see the Config-derived local-appdata root section below and the [installer callback recovery](rk-v4.6-inno-installer-callback-recovery-2026-10-20.md). |

This is a host-side locale preference sink. The API return value is not tested
in the shown path, so a successful write is not established. The binary's
direct call and the selected-index flow are statically visible, but whether
Windows/MFC dispatch reaches `0x00403670`, and the state effects of the
function-pointer call through global `0x00646C1C` earlier in that handler, are
not resolved here. Static setup code conditionally derives this location, and the 4.6 installer
names the same intended destination; neither establishes that the runtime
branch executes or that Windows creates or writes the file. This slice contains
no keyboard report or device-I/O operation.

### Config-derived local-appdata root

The 4.6 package manifest identifies `app/Cfg.ini` with SHA-256
`AB9C84BB951BCFEC99E18E0C6A77ECE913E14376265C33276E3B176C030B6CC5`. Its
`[OPT]` section sets `appdir=RKKB`. In `DeviceDriver.exe`,
`0x00456520` builds a `cfg.ini` path from global prefix `0x006354B8` and the
UTF-16 `cfg.ini` literal; the prefix's runtime contents are not recovered.
It calls `GetPrivateProfileStringW` at `0x0045693D` (IAT
`0x005A63D8`) for `[OPT] appdir`. The default is empty; the destination is
global wide buffer `0x00629F64` with size `0x1E`. The package entry contains
`appdir=RKKB`, but the evidence does not establish that `0x006354B8` resolves
to the package `app/` directory at runtime.

The initialization path in `0x00448030` calls `0x00456520` and, when its
return is nonzero, calls `0x00453220`. That path calls
`SHGetSpecialFolderPathW` at `0x0045323F` (IAT `0x005A6534`) with
`hWnd=null`, `CSIDL_LOCAL_APPDATA` (`0x1C`), `fCreate=0`, and a stack output
buffer. It formats `"%s\\%s\\"` from that buffer and `0x00629F64` into global
`0x006352B0`, then checks the result with `PathFileExistsW` (IAT
`0x005A6558`) and calls `CreateDirectoryW` (IAT `0x005A640C`) if it does not
exist.

If the runtime reader selects package `app/Cfg.ini`, these code paths imply
the intended prefix `%LOCALAPPDATA%\RKKB\`. The absolute config path remains
unknown. The `SHGetSpecialFolderPathW` return value is unchecked; runtime API
results and branch execution were not observed, and no user-local configuration
was read. This conditional path derivation does not prove a directory was
created. It explains how `0x006352B0` is populated; its concrete runtime value
depends on the selected config and API success. This prefix is used in the
downstream language and text-macro paths below.

## Host temporary-file factory

The same hash-pinned image has a temporary-file factory at `0x004DC2CC`,
called directly from multiple later code locations. Its path construction and
file open are explicit in this routine:

1. `GetTempPathW` is called at `0x004DC32D` (IAT `0x005A62E0`) with a
   `0x104`-character stack buffer returned by the string helper and a
   `0x104` length. The API return value is not tested in the recovered
   sequence.
2. `GetTempFileNameW` is called at `0x004DC35E` (IAT `0x005A62E4`) with that
   temporary-directory string, the `L"AFX"` prefix at `0x005B2FF0`, unique
   value zero, and a second `0x104`-character stack buffer. Its API return is
   not tested before the output string is passed onward.
3. `CreateFileW` is called at `0x004DC380` (IAT `0x005A6474`) for that
   generated path with desired access `0xC0000000` (read/write), share mode
   zero, null security attributes, `CREATE_ALWAYS` (`2`), flags
   `0x04000100` (`FILE_ATTRIBUTE_TEMPORARY` plus
   `FILE_FLAG_DELETE_ON_CLOSE`), and a null template handle. This return is
   checked against `INVALID_HANDLE_VALUE`; failure clears the temporary
   string state and returns zero.

On the successful open path, the handle is wrapped at `0x004847D6`; a
`0x1000`-byte buffer and an internal stream-like object are then prepared.
The routine invokes a virtual method at offset `+0x08` on the caller-supplied
object with the stream-like pointer as its argument, releases the temporary
wrapper objects, and stores the raw handle into caller-owned state through
`0x004A232E`. Exception-unwind cleanup blocks at `0x004DC42B`, `0x004DC449`,
and `0x004DC467` call `CloseHandle` (IAT `0x005A64B8`) on the opened handle
and clear the associated state. On the normal return path the handle is
transferred to caller-owned state; its later close site and the actual
serialized content were not traced in this slice.

This is proven host-side temporary-file behavior with an `AFX` filename
prefix. The API bytes do not identify a keyboard settings file or firmware
readback path. The runtime directory and successful API execution remain
unresolved. The `GetTempPathW` and `GetTempFileNameW` API results are not
explicitly checked in the shown sequence; only the `CreateFileW`
invalid-handle result is tested.

### Recovered caller and stream path

The direct caller edges in `rk-v4.6-rooted-cfg-edges.csv` identify these
callsites into `0x004DC2CC`:

- `0x00551405` is in `0x00551398` (`WM_DESTROY`) and `0x00551C13` is in
  `0x00551BD3` (`WM_COMMAND`, ID `0x40ED`). At each site `ECX` is
  `0x0061DD54`, the first stack argument is the page's `[this+0x3F4]`, and
  the second is `[this+0x3E4]`. The factory's virtual call at `+0x08`
  therefore receives the archive-like stream through the object at
  `[this+0x3E4]`.
- `0x0055193D` and `0x005519F9` are in `0x0055181F` (`WM_COMMAND`, ID
  `0x40F0`). `ECX` is again `0x0061DD54`; the first stack arguments are
  `[EDI+0x68]` and `EDI`, respectively, while the second argument is
  `[this+0x3E4]` at both sites. The stream is passed to that same page-owned
  object.
- `0x00551390` is in helper `0x0055133E`. Its first argument is
  `[[this+0x3E8]+0xDBC]`; its second is the return value of virtual method
  `+0x19C` on the object at `[this+0x3E8]`. The helper is reached from
  `0x00551398` (`WM_DESTROY`, call at `0x00551431`), `0x0055145A`
  (`WM_COMMAND`, ID `0x40EE`, call at `0x00551497`), and callback-like
  function `0x00551597` (call at `0x005515B6`). The latter is reached from
  `0x004E61A2` at `0x004E635A` when its `[ESI+0x11C]` field is nonzero; its
  precise higher-level trigger is not mapped here.

The MFC message map names the owner for the mapped entries as
`.?AVCMFCToolBarsMenuPropertyPage@@` (`rk-v4.6-mfc-message-map-entries.csv`).
Together with the toolbar-customization resource strings in this image, this
places the traced callers in MFC toolbar/property-page UI code. It supports a
host UI customization context; it does not establish which command state is
serialized or that this is a keyboard profile/configuration path.

The factory constructs the CArchive-like object at `0x004DC3B6` with the CFile
wrapper, mode argument `0`, buffer size `0x1000`, and null caller buffer, then
calls the second argument object's vtable entry `+0x08` at `0x004DC3D1`. The
concrete target is now resolved for both caller forms described above:

- For the page-owned object at `[this+0x3E4]`, initialization at
  `0x00551E2B` passes runtime-class record `0x006095AC` to the class-check
  helper at `0x0048BFBB`. The record names `CMFCMenuBar` and gives object size
  `0xC54`; its TypeDescriptor is at `0x006095D4` (`.?AVCMFCMenuBar@@`), with
  Complete Object Locator `0x005E863C` and vtable `0x005B64DC`. Vtable entry
  `+0x08` is `0x004A49B9`.
- For the cleanup form, the object at `[this+0x3E8]` is initialized as
  `CMFCPopupMenu` (vtable `0x005B3C64`, RTTI COL `0x005E7D34`). Its vtable
  entry `+0x19C` is `0x004E75E8`, which directly returns its embedded object
  at `this+0x124`. That embedded object is initialized with vtable
  `0x005B4384`, whose RTTI identifies `CMFCPopupMenuBar` (COL
  `0x005E7F20`). Its `+0x08` entry also targets `0x004A49B9`.

The serializer at `0x004A49B9` is therefore the concrete shared target for
these dispatches. The archive constructor at `0x0048D49C` stores the supplied
mode at archive `+0x18`; here that value is zero. In this target, the zero-mode
branch at `0x004A4B50` takes the store path: it calls archive helpers that
write values into the archive buffer. The earlier statement that mode `0`
implied load mode was incorrect and is superseded by this branch and helper
trace.

### Serializer data path and known payload

The following byte-content facts are direct consequences of the target's
decoded calls and the archive helpers; runtime values and collection contents
are still unknown:

1. `0x004A49B9` first delegates to `0x0050B07F`. In the zero-mode path,
   `0x0050B07F` writes two 32-bit values through `0x0048CFD0`: the current
   object's `[this+0x70] & 0xF000`, then the return value of that object's
   vtable entry `+0x154`. The meaning of the second value is unresolved.
2. It serializes the embedded list at `[this+0xB04]` through virtual `+0x08`
   (`0x004A4A3F`). The list helper at `0x004E88A5` writes the list count, then
   iterates its linked entries and invokes the MFC object-serialization helper
   at `0x004E266C` for each object. The helper writes null/object identity and
   runtime-class metadata as applicable, then dispatches each non-null
   object's own `Serialize` entry at `+0x08`. Thus the list's exact records
   depend on its runtime contents and each dynamic object's serializer.
3. It writes `[this+0xA54]` as a 32-bit value via `0x0048CFD0`.
4. It obtains a Unicode window caption from `[this+0x20]` through the
   `GetWindowTextLengthW` / `GetWindowTextW` imports when no cached string is
   present, then serializes that CString via `0x00477F69`. That helper writes
   the wide-string marker (`0xFF`, then `0xFFFE`), a CArchive count encoding
   for the character length, and `2 * length` bytes of UTF-16 text. The actual
   caption and length depend on runtime window state.
5. It writes `[this+0x10C]` as a 32-bit value via `0x0048CFD0`.

After the virtual call, the factory calls `0x0048CDAB` to flush the archive
buffer. Its zero-mode path passes the buffered data and byte count through the
wrapped CFile's virtual file operations. This establishes that the serializer
populates and flushes bytes to the temporary file on this path; it does not
establish the exact complete byte stream because the list objects, virtual
return value, fields, and caption are state-dependent. The file is host-side
MFC toolbar/menu state in the traced path. No evidence in this call chain links
it to keyboard reports or firmware.

On the successful normal path, the temporary CFile wrapper is constructed
with its close-on-destruction field cleared at `0x004847D6`; its destructor
path does not close the raw handle. The factory associates that handle with
the first argument in the `0x0061DD54` object's registry via `0x004A232E` and
returns success. A later factory call for the same key retrieves and closes
the prior handle at `0x004DC30C` before replacement. The file's
`FILE_FLAG_DELETE_ON_CLOSE` means it is removed when its raw handle is closed.
Factory exception-unwind paths also close the open handle at `0x004DC436`,
`0x004DC454`, and `0x004DC472`. The eventual normal-path registry cleanup or
close site was not traced, so persistence beyond those observed paths is
unknown.

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
thunks. Given the package `appdir` value, native setup code implies this
intended `0x006352B0` prefix is `%LOCALAPPDATA%\RKKB\` if that package config
is selected. The toolbar temporary-file path reaches the concrete MFC
serializer `0x004A49B9`, and its archive
buffer is flushed through the wrapped CFile. Independent 4.6 code contains a
SetupAPI/HID discovery/open path, feature-report callsites, local profile keys
and Side LED assets, and local `textmacro.dct` read/write paths.

**Inferred:** the setup path is intended to enumerate HID interfaces and
inspect report capabilities; Side LED keys/assets support a Side LED UI or
preview; the `SendInput` path likely implements text-macro playback; and the
GDI+ property path likely controls animation timing.

**Unresolved:** full CFG reachability, dynamic API/COM targets, all register
and callback data-flow, complete UI control-to-handler links, all feature
report payload semantics, per-model behavior, live S98 identity, runtime
success, and whether firmware can be copied safely. This audit does not close
the broader reverse-engineering goal and makes no firmware-readback claim.
