# RK updater and firmware readback audit

This note compares the installed 4.06 model-specific updater with the
corresponding files in the separately extracted official 4.6-labeled Windows
Hub Driver package. It answers a narrow question: do the examined RK software
files expose a demonstrated way to copy the firmware currently running in the
connected RK S98 to a host file while leaving the keyboard unchanged? This is
a static assessment of these two package snapshots, not a claim about every RK
software or firmware revision.

The binary findings here are static. A separately dated live check opened
selected HID collections, queried descriptor metadata, and made three direct
`HidD_GetFeature` requests. It sent no output report or `HidD_SetFeature`
payload and read no input report. No RK executable or updater was launched,
no serial command was sent, and no bootloader mode was entered. Findings are
marked **proven** when
the binary or installed files directly establish them, **inferred** when they
follow from a traced data flow but are
not validated at runtime, and **unresolved** where static evidence is
incomplete.

## Examined package

The 4.6-labeled package contains byte-identical copies of the 4.06
`Dev/01AF/Update.exe` and its `.upf`; their SHA-256 values are recorded in the
[4.6 package manifest](rk-4.6-package-manifest.csv) and cross-version file
comparison. Thus the updater analysis below applies to those exact updater
files in both snapshots. The installed 4.06 `DeviceDriver.exe` has SHA-256
`c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6`; the
4.6 `DeviceDriver.exe` is a different binary (2,418,176 bytes; SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`); its
two G5 feature-read paths discussed below were audited separately. This
limited cross-version check does not establish that every path in that driver
has been analyzed.

The installed updater is
`C:\Program Files (x86)\RK Keyboard Software\Dev\01AF\Update.exe`, x86,
file version `1.0.2.2`, SHA-256
`27894463b0dfe5bc3f5dc19d4d3351d9dfb692c402bf277bde3889d37e4a206c`.
Its embedded PDB path names `UartUpdateTool`, and RTTI strings name
`CSerial`, `CUartUpdateToolApp`, and `CUartUpdateToolDlg`. The UI contains
strings for `Read Version`, `Force upgrade`, `Start Burn`, and an `.upf`
file-picker filter. These prove the executable combines a firmware UI, an
HID update path, and a UART-related component; they do not prove that the
serial and HID paths target the same hardware or package.

The only `.upf` in the installed package is
`Dev/01AF/KB_762_1_v258A_p01AF_F90_8818_V90.0f.1.00.upf`, 193,652 bytes,
SHA-256
`e21c11e023247afc7fdbbe27548570240efa5b646147741d5354eecb3041b628`.
The file begins with `5A A5 BLESINO`; its header includes VID/PID `258A:01AF`
and version text `V1.00`. The local `Dev/01AF/KB.ini` has `Fw=1`,
`VerNeedToUpdate=0x2108`, and `NoUpdate=1`. A USB composite device observed in
PnP has VID/PID `258A:0150`, which is not the package PID. That generic PnP
identity does not establish that this `.upf` belongs to the S98 or its
receiver. The `.upf` is a host-side updater input, not evidence of firmware
read from a keyboard.

**Current Windows PnP snapshot (2026-10-18 13:24:08 +05:30):** read-only
`Get-PnpDevice -PresentOnly` enumeration returned one present USB composite
device with VID/PID `258A:0150`, three present Bluetooth nodes named
`RK-S98RGB`, seven `HIDClass` children, two `Keyboard` children, and one
`Mouse` child. The HID children include consumer-control, system-controller,
vendor-defined, and USB Input Device entries. The same PnP query returned no
`USBSTOR` nodes and one `DiskDrive` node with an NVMe instance ID; this does
not identify an external or keyboard firmware volume. No HID interface was
opened and no HID report or GATT data was read. The friendly names, generic
composite record, and child collections do not identify the USB device as the
S98 or identify firmware revision; they also do not prove that a control
channel is available. In the installed
profile crosswalk, `0150` is recorded as the wireless PID for an RK A70
profile, while the eight S98 profile rows have direct PIDs `0174`, `01AF`,
`01BF`, `0223`, `0224`, `022B`, `022F`, and `0230` and no installed
`PID_Wireless` value. The USB `258A:0150` node therefore remains ambiguous and
cannot be confidently assigned to the S98 or its Bluetooth LE nodes.

**Current descriptor-only HID snapshot (2026-10-19):** after explicit user
authorization to open the HID interface, a read-access handle was used only
for `HidD_GetAttributes`, `HidD_GetManufacturerString`,
`HidD_GetProductString`, `HidD_GetSerialNumberString`,
`HidD_GetPreparsedData`, and `HidP_GetCaps` on the present `258A:0150`
collections. During this metadata pass, no input report was read and no output
report or `HidD_SetFeature` payload was sent; the separate direct feature-read
results are listed below. Seven of ten enumerated collections could be opened;
Windows returned access denied for MI_00, MI_01/COL_05, and MI_01/COL_09. The
accessible descriptor results were:

The metadata pass was repeated with the repository's
[read-only HID metadata probe](../scripts/probe_rk_hid_metadata.ps1). It
requests `GENERIC_READ` only, and imports no report-read, report-write, or
device-control API. The rerun reproduced the same seven successful
collections, three Win32 access-denied results, VID/PID/revision, manufacturer
string, and report lengths shown here. The additional serial-string call
failed with Win32 87 on every accessible collection; that leaves a serial
number unavailable and does not establish that the receiver has no serial
number. The probe's C# `Marshal.WriteInt32` and `Marshal.WriteInt16` calls
initialize local SetupAPI/string buffers; they do not write to the keyboard.

| Interface collection | Usage page:usage | Input bytes | Output bytes | Feature bytes | Feature report IDs |
| --- | --- | ---: | ---: | ---: | --- |
| MI_01/COL_01 | `FF02:0002` | 20 | 20 | 0 | — |
| MI_01/COL_02 | `0001:0080` | 2 | 0 | 0 | — |
| MI_01/COL_03 | `000C:0001` | 3 | 0 | 0 | — |
| MI_01/COL_04 | `FF02:0001` | 4 | 0 | 0 | — |
| MI_01/COL_06 | `FF00:0001` | 0 | 0 | 6 | `05` |
| MI_01/COL_07 | `FF00:0001` | 0 | 0 | 1032 | `06` |
| MI_01/COL_08 | `FF01:0001` | 0 | 0 | 8 | `0A` |

The opened device attributes report VID/PID `258A:0150` and version `0206`.
`HidD_GetManufacturerString` returns `SINOWEALTH` on each accessible
collection. `HidD_GetProductString` decodes to garbled text (`慇業杮䬠`), so
that value is not used as identity evidence. The 4.6 public registry has 46 receiver profiles
with this same VID/PID and `FF02:0002` usage, spanning S98 and other models;
the connected hardware therefore still cannot be identified as S98 from this
descriptor or VID/PID alone. This is a live interface/descriptor observation,
not a report-level protocol trace. The Bluetooth PnP nodes named `RK-S98RGB`
remain generic BLE records without a proven association to the USB receiver.

**Cached BLE HID metadata (2026-10-19):** Windows has three present Bluetooth
roots named `RK-S98RGB`; their BLE HID service children share their respective
root containers. All three report `ConnectionStatus=Disconnected`. The USB
`258A:0150` composite device is in a different PnP container, and Windows
exposes no common parent/container linking it to any BLE root. This leaves
the BLE names as model labels, not proof that a BLE entry and the USB receiver
are the same physical unit.

The BLE HID service instance ID contains
`VID&02046D_PID&B35A_REV&0011`, which encodes a vendor-ID source, VID, PID, and
revision. The Bluetooth Device Information Service defines source `0x02` as
USB-IF and specifies little-endian VID/PID/version fields; interpreted by
that layout, the ID indicates source `0x02`, VID `0x046D`, PID `0xB35A`, and
revision `0x0011` ([Bluetooth SIG PnP_ID specification](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/DIS_v1.2/out/en/index-en.html)).
This does not match the USB receiver's `258A:0150` identity. It is Windows
PnP metadata; the cached characteristic values themselves were not read.

Cached GATT service discovery (Windows `BluetoothCacheMode.Cached`) returned
services `1800`, `1812`, `180F`, `180A`, and `F200` for each BLE root. Cached
characteristic enumeration for HID service `1812` returned `AccessDenied` on
all three, so no report map or HID caps were obtained. The additional `F200`
service exposes characteristic `F202` with Read, Write, and
WriteWithoutResponse properties; no characteristic value was read and no
write was issued. SetupAPI HID-interface enumeration found no corresponding
BLE interface path for either candidate VID/PID, so no BLE HID handle was
opened. These are cached Windows observations, not a live GATT session or
proof of a firmware-read path.

**Direct feature-read attempt (2026-10-19):** using only the descriptor's
feature report IDs and lengths, `HidD_GetFeature` was called once per
accessible feature collection, with no preceding `HidD_SetFeature` request:

| Interface collection | Requested report | Result | Returned bytes or error | SHA-256 of returned report |
| --- | --- | --- | --- | --- |
| MI_01/COL_06 | ID `05`, 6 bytes | Success | `06 A0 02 86 28 CB` | `0942459c22f269a1c5126070bbede7a6fb01bcdd2bf47f54e11e95346c1b2763` |
| MI_01/COL_07 | ID `06`, 1032 bytes | Failure | Win32 error 31 (`ERROR_GEN_FAILURE`) | — |
| MI_01/COL_08 | ID `0A`, 8 bytes | Success | `06 A0 02 86 28 CB 24 67` | `cda6d71acf4f56682512674c8846aa7786ab6d8b81181537f529f0f831182168` |

The successful short responses share the same first six bytes even though
their collections and requested report IDs differ. In both responses, byte 0
is `06`, not the requested ID (`05` or `0A`); this mismatch is unresolved.
The bytes' meaning and whether the values represent current device state, a
generic response, or stale report data are also unresolved. The 1032-byte
report that could be relevant to updater traffic did not return data on this
direct request. This does not establish a firmware read or a complete
firmware-copy path; each official software read
path located so far first sends a feature request/write.

## `.upf` parser and host-to-device flow

**Proven from the static code path:** the firmware chooser reaches
`FUN_0040A940` (VA `0x0040A940`). It opens the selected path through the
updater's C++ stream/runtime helpers, checks the `5A A5 BLESINO` signature,
reads metadata and section lengths, seeks to the payload area, and reads
section data into host memory. The parser does not call a keyboard read API.
Its mode dispatch is mode 0 = A+B, mode 1 = A, mode 2 = B, and mode 3 = A+B+C.
The inspected file declares mode 3. The payload seek is to file offset
`0x80`.

The parser decodes these fields from the inspected file:

| File offset | Bytes/value | Static interpretation |
| --- | --- | --- |
| `0x00–0x08` | `5A A5 BLESINO` | Signature checked by the parser. |
| `0x09` | `03` | Mode selector; parser follows the A+B+C branch. |
| `0x0A–0x10` | `KB0000\0` | Tag string; meaning unresolved. |
| `0x11–0x12` | `25 8A` | VID `0x258A`. |
| `0x13–0x14` | `01 AF` | PID `0x01AF`. |
| `0x1A–0x1F` | `V1.00\0` | Version string. |
| `0x2C–0x2F` | `F0 00 71 6D` | Big-endian A length `0xF000716D`. |
| `0x30–0x33` | `00 00 A1 87` | Big-endian B length `0xA187` (41,351). |
| `0x42–0x45` | `00 00 00 00` | C length zero. |
| `0x80` | — | Payload seek position. |

**Unresolved package validity:** only 193,524 bytes follow offset `0x80`,
while the parsed A length is `0xF000716D`, far larger than the available file.
The function-level trace does not establish a successful parse or explain
this mismatch. The package must not be treated as a validated firmware image
or as a recoverable backup. No attempt was made to run the parser against it.

### Independent REA/Ghidra parser cross-check

A read-only REA overview and function dossier were generated from an offline
copy with the same SHA-256. The dossier independently identifies
`FUN_0040A940` as a path-based binary reader, shows the `5A A5 BLESINO`
signature check, and traces the selected file into host-side parsing. REA's
decompiler output is supporting evidence, not source: six indirect calls were
unresolved and some high-p-code output was truncated. A focused query for
verifier `FUN_00402FC0` ran for about six minutes without producing a dossier
and was cancelled; the verifier conclusions below rely on the existing
instruction/callsite analysis, not that incomplete query.

| Artifact | Identity | Use and limitation |
| --- | --- | --- |
| REA updater overview | Evidence ID `ev_f0da86b00564426d140556cc3cc4e5d425052a7b9656c90302e46b12829c1ec3`; SHA-256 `27894463b0dfe5bc3f5dc19d4d3351d9dfb692c402bf277bde3889d37e4a206c` | Static inventory for the exact updater image documented above. |
| REA parser dossier for `FUN_0040A940` | Evidence ID `ev_bc583b23d58a728a1441cd7ea30948cfeda53a6c41f65861c4980c47a9c3e4bf` | Function-level corroboration of local `.upf` parsing; not proof that this malformed sample parses successfully or that the parser reaches a keyboard. |

The REA artifacts are retained in the local analysis workspace rather than
the public source tree. The evidence IDs are recorded here to tie the
cross-check to the exact package hash without publishing an unreviewed
decompiler snapshot as source.

The static transfer data flow is:

| Stage | Code and evidence | Direction and limit |
| --- | --- | --- |
| B update | `FUN_00402B20` → `FUN_00403290`; `HidD_SetFeature` callsite `0x00403505`. The updater stages the host section buffer at `0x005C5EFC`, length `0x005C5F04`, into reports carrying up to `0x800` payload bytes. | Host buffer to device. |
| B verify | `FUN_00402FC0`, `HidD_GetFeature` at `0x0040308C`; request bytes include `05 52`, response prefix is `06 72`. The returned chunks are compared in RAM against the section-B buffer at `0x005C5EFC`. | Device response to RAM, used for equality/retry verification. No file output is identified in this traced routine. |
| C update | `FUN_00402CE0` → `FUN_00403570`; `HidD_SetFeature` at `0x004036BD`. The C source buffer is `0x005C5EF8`, length `0x005C5F00`. | Host buffer to device. |
| C verify | `FUN_004037D0`, `HidD_GetFeature` at `0x0040389C`; returned chunks are compared in RAM against the C source buffer at `0x005C5EF8`. | Device response to RAM, used for equality/retry verification. No file output is identified in this traced routine. |
| Stage control | `FUN_00402B20` and `FUN_00402CE0` send 0x408-byte start/finalize reports. The final sequence includes a report beginning `05 55` followed by one beginning `05 5A`. | Active device writes; not reads or backup operations. |
| A / BLE version | `FUN_0040BB10` and its caller `FUN_0040B770` poll report ID 6, validate a short `05 01` response and compare version bytes. The helper then emits a separate 0x408-byte control/status report. | Short status/version exchange plus a control write; not a flash read. Exact relation between A and the BLE path is inferred and partly unresolved. |

Section B/C verification is readback from the update target after the updater
has sent a write. Its returned bytes are used as a bounded in-memory
comparison with the chosen host image; this is not a copy operation into a
host firmware file. The section dispatcher at `FUN_00402A40` chooses the C
path for one value of global state and otherwise the B/HID path. The UI labels
these branches “MFU firmware upgrading” and “HID firmware upgrading.” Their
runtime flag sources and physical transport mapping are not fully established.

## Other updater reads and file I/O

The import cross-reference inventory lists nine direct-call
`HidD_GetFeature` sites in `Update.exe`: `0x004023CF`, `0x0040269B`,
`0x0040289C`, `0x00402985`, `0x0040308C`, `0x0040389C`, `0x0040980D`,
`0x0040BC16`, and `0x0040BF57`. Rechecking the static HID-caller export and
the binary also found two register-indirect calls through the import address:
`0x00402ED3` and `0x00402EFB` in `FUN_00402E80`. The direct-IAT xref table
records the IAT operand load at `0x00402ECE` as a non-call reference, so a
direct-call-only read of that table misses these two invocations.

`FUN_00402B20` calls `FUN_00402E80` at `0x00402C73` after its section-B
transfer/verification loop succeeds. The helper allocates a six-byte buffer,
sends a feature report through `HidD_SetFeature` at `0x00402EBA`, writes
report bytes beginning `05 72` at `0x00402EC7`, then calls
`HidD_GetFeature` with length 6 at `0x00402ED3`. It extracts bytes 2–5 and
performs a second six-byte `HidD_GetFeature` call at `0x00402EFB`; the helper
then continues with short feature writes. This is additional updater protocol
traffic, not evidence of a complete firmware read: the two reads in this
helper use six-byte buffers and are nested in the section-B update path. The
meaning of the exchanged values remains unresolved. The other traced feature
reads divide into section-B/C verification, BLE/version/status handling, and
an updater mode/connection helper. The `0x0040980D` routine also has a nearby
`HidD_SetFeature` at `0x004097A8`; therefore it is not evidence of passive
capture. No inspected feature-read path streams a full firmware image to a
host file. A separate conditional UART response-to-file path is present and
described below.

### V4.6 main-driver G5 reads

The separate, hash-pinned V4.6 `DeviceDriver.exe` has G5 vtable `+0x70`
wrapper `0x00411030`, which calls helper `0x00410890` unless object busy flag
`+0x238` is set. The helper builds `0x208`-byte feature reports with command
`0x88` at byte 1, uses chunks capped at `0x200`, and contains a conditional
copy from response offset 8 to caller memory until the caller-supplied length
is covered. It contains no file sink. `HidD_SetFeature` at `0x00410992` and
`HidD_GetFeature` at `0x004109F1` use the same saved `[this+0x04]` handle.
Correct stack accounting at the GetFeature call shows that the pending delay
argument makes `[esp+0x14]` refer to that saved handle; `[esp+0x18]` is the
separately stored byte at `[this+0x2DC]`, which is copied into the report.
The conditional copy is reached only if the read call reports success and the
response command matches. This confirms a conditional code-level response
read/copy path, not an observed device read.

A scan of 77 decoded indirect `call *+0x70` sites did not identify a caller
attributable to this G5 method. A superficially plausible two-argument call
at `0x004899D9` is inside a Windows hook-callback path that also calls
`CallNextHookEx`; its first argument is validated as `nCode`, which is
incompatible with the G5 method's writable output-buffer argument. The actual
caller, requested length, data meaning, firmware address/range, full-image
behavior, and downstream persistence remain unresolved.
The broader candidate screening also excludes signature-shaped point/layout
methods where the same receiver is used at vtable slots beyond the G5 table;
see the [focused `+0x70` caller audit](rk-v4.6-cdevg5-realdata-caller-audit.md).

The nearby G5 `+0x34` password-query method follows the same broad pattern for
command `0x82`. Stack accounting at `0x00410E7E` likewise resolves its
`HidD_GetFeature` handle to the saved `[this+0x04]` handle used by
`HidD_SetFeature`; the `+0x2DC` byte is a separate report field. Both methods
contain conditional response-copy code, but no successful hardware response
was observed. Neither method establishes that returned data is firmware or
that a full image is exported. Their requests include feature writes, so they
are not passive reads. See the
[V4.6 G5 password-query audit](rk-v4.6-cdevg5-password-query-audit.md),
[vtable/settings audit](rk-v4.6-cdevg5-settings-and-vtable-audit.md),
[six-call handle-argument audit](rk-v4.6-hid-getfeature-argument-audit.md), and
[vtable evidence map](rk-v4.6-cdevg5-vtable-map.csv). This V4.6 driver is a
different binary from the installed 4.06 updater and its findings do not
resolve the updater's UART file-sink path.

The updater also contains a separate serial transport and event-driven
dispatcher. `FUN_00404E60` calls `CreateFileW` at `0x00404F09` with
`GENERIC_READ | GENERIC_WRITE`, `OPEN_EXISTING`, and overlapped I/O, then sets
the communication mask, DCB, and timeouts. It stores the notification window
and message ID `0x401` in globals `0x005BB4F4`/`0x005BB4F8` and starts four
worker threads. The configured baud value is held in object state and has not
been decoded.

Receive worker `FUN_00405430` calls `ReadFile` at `0x00405535` and may finish
pending reads with `GetOverlappedResult` at `0x00405584`. It queues received
chunks capped at `0x1FFF` bytes under global queue state around `0x005BB500`,
then posts message `0x401` at `0x004055E6`. The consumer `FUN_00407E00` calls
queue helper `FUN_00405920` at `0x00407E36`, reads state `0x005C5F58`, and
dispatches states 1–15 through the jump table at `0x00408044`. State 15
reaches serial setup `FUN_004091B0` at `0x00408034`, which calls
`FUN_00404E60` at `0x004091F9`. The message-map row at `.rdata` address
`0x005943D0` maps message `0x401` to `FUN_00407E00`; this verifies the row,
although its owning MFC class is not independently confirmed. The handler
drains queued bytes into `0x005C5F60`.

### Conditional UART response-to-file path

The UART dispatcher contains a conditional stream-write sink. This qualifies
the earlier negative result: a response-to-file path exists in the binary,
but static evidence does not establish that it can be enabled or that it
exports a complete firmware image.

| State/path | Static flow | Evidence and limit |
| --- | --- | --- |
| State 7 | Handler `FUN_00408710` conditionally calls the fwrite-like wrapper `FUN_00535EAC` with buffer `0x005C5F60`, element size 1, selected chunk count, and stream global `0x005C5F30` (`0x00408761` or `0x00408798`). It also copies a 0x1000-byte block into `0x005C6F80 + blockIndex*0x1000` (`memcpy` at `0x004087C2`) and compares the assembled data with the reference buffer at `0x005C6F8C`. | Conditional response-to-file and response-to-RAM comparison paths are present. The intended image and runtime use remain unresolved. |
| State 10 → 11 | `FUN_00408F20` recognizes response prefix `C0 3F` at `0x00408F30`/`0x00408F39`, sets state 11, and queues `5A 69 3C 0F 13 EC`. | Command and response meanings are not identified. |
| State 11 | Handler `FUN_00408FC0` conditionally writes queued bytes from `0x005C5F60` to the same stream through `FUN_00535EAC` at `0x0040903D`. It chooses a partial, 0x1000-byte, or total-length count. | A second response-to-file path is present. State 11 does not copy data into `0x005C6F80`. |
| Next block | `FUN_00408BA0`, reached from state 11, sets state 10, builds a 13-byte request, and advances offset `0x005C5F2C` by `0x1000` at `0x00408D50`. | This resembles a chunked read loop; command meaning and entry conditions are unresolved. |

The file gate `DAT_005C5F12` has a direct store of zero at `0x004071BB`;
no nonzero direct store was found in the updater's disassembled `.text`. The
stream pointer at `0x005C5F30` is used as the `fwrite`/close argument, but no
direct initializer, open/create call, or file-name flow to it was recovered.
The PE `.data` section has VA base `0x005B3000`, virtual size `0x15200`, and
raw size `0xCA00`; the stream and buffer globals used by this path fall in its
zero-filled virtual tail.
`FUN_00535F9A` is a close-like wrapper called on selected completion paths
when the gate is set. The sink's activation is therefore unresolved and
likely dormant or unfinished in this build; indirect initialization or
untraced paths cannot be ruled out.

A fresh direct-reference scan of the hash-verified updater also found that
the state-10/11 handlers form a closed direct transition cycle: the only
direct store to state 10 is inside a helper called from state 11, and the
only direct store to state 11 is inside the state-10 handler. Serial
initialization sets the state global to 0, and no direct transition from that
initialization or states 0–9/12–15 enters 10/11. See the full address map in
[`rk-updater-uart-state-machine.md`](rk-updater-uart-state-machine.md). An
indirect store, external call, or other untraced path remains possible, so
this is not proof that the code can never execute.

This establishes potential chunked UART response-to-file code, not a
demonstrated way to copy the connected keyboard's firmware while leaving it
unchanged. The physical device/mode, complete protocol, file creation path,
and runtime reachability are not established. The separate HID `.upf` path
remains host-file-to-memory staging.

The API inventory also records file `ReadFile`/`WriteFile` references in the
updater. At `0x00405250` and `0x00405535`, `ReadFile` operates on the serial
object's handle; `WriteFile` at `0x0040572A` is in its corresponding serial
worker. The `0x00431E27` read and `0x00431F9C` write are generic file-wrapper
methods, while the remaining references are in runtime/library code. The
`.upf` parser's direct path is via C++ stream/runtime helpers and allocates
section buffers before the HID transfer; the traced HID verifier buffers are
compared in memory. Separately, the UART state 7/11 handlers conditionally
pass received chunks to a stream-write wrapper. Its gate, file pointer setup,
file name, and activation remain unresolved; this supersedes the earlier
negative finding that no UART queue-to-file sink had been identified.

### Updater temporary-file serializer follow-up

The updater's `CreateFileW` call at `0x00480B1D` creates an `AFX`-prefixed
temporary file with `CREATE_ALWAYS` and flags
`FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE`. The handle is wrapped
in an MFC `CFile`-like object and a `CArchive`-like serializer; the serializer
then calls a supplied object's virtual method. Eighteen direct callers of
this helper are in the OLE/document-object region (`0x004CF550` through
`0x004D23A9`). No direct caller from the UART or HID receive handlers was
found. This is evidence for generic object serialization into an ephemeral
file, not a persistent firmware export path. Indirect COM/runtime behavior
remains unresolved.

## Can the connected S98 firmware be copied without changing it?

**Conclusion across the examined snapshots:** no complete, read-only S98
firmware export is demonstrated. The 4.06 updater findings also apply to the
identical updater shipped in the 4.6-labeled package. The changed 4.6 main
driver has separate command-`0x88` and command-`0x82` G5 paths that issue
feature writes and contain conditional response-copy code. The six V4.6
`HidD_GetFeature` callsites were stack-audited and each uses the same handle
as its paired `HidD_SetFeature`; the `+0x2DC` byte is a separate report field.
Static code does not establish an observed device response, a caller for the
G5 `+0x70` path, or a full-image/file export.

**Proven:** Windows has not exposed this keyboard as a mass-storage volume
from which firmware could simply be copied. The bundled `.upf` is a
host-side package with a VID/PID that differs from the observed USB unit. The
HID updater writes section data and then reads back bounded chunks to verify
those writes. The UART state machine also contains a conditional
response-to-file sink, but its stream setup and enabling condition are not
recovered.

**Inferred from the analyzed paths:** the validated HID update flow is
host-to-device; its verification reads follow write operations, and the
generic HID read helper has request writes associated with the read. The
UART code suggests a possible chunked response export, but the file gate is
directly initialized to zero, no nonzero direct setter was found, and no
stream-open/file-name path was recovered. In the direct UART state graph,
the state-7 sink belongs to a state-3/4/6/7 subgraph with no direct entry
from initialized state 0, and the state-10/11 chunk loop likewise has no
direct incoming transition from state 0. Neither path is evidence of a
reachable, working passive firmware backup feature.

**Unresolved:** UART command/response semantics, any indirect or external
transition into the state-7 or state-10/11 file paths, stream-pointer and
file-name setup, all indirect writes to the file gate, undocumented
bootloader commands, and the exact protocol revision of the connected S98
are not reconstructed. Static analysis cannot prove extraction is
impossible, but it does not demonstrate a complete read-only backup workflow.
The live metadata and direct feature reads documented above have not resolved
this question: the only successful reads were eight bytes and six bytes, and
the 1032-byte feature read failed. The official software's candidate
firmware-relevant paths pair `HidD_GetFeature` with request writes through
`HidD_SetFeature`; their command semantics and response data remain
unvalidated on this receiver. No output report or `HidD_SetFeature` payload
was sent, and no updater or bootloader operation is documented here.

## Evidence files

- Installed package manifest: [`rk-installed-package-manifest.csv`](rk-installed-package-manifest.csv)
- Native API addresses: [`rk-native-api-xrefs.csv`](rk-native-api-xrefs.csv)
- Native import list and binary hashes: [`rk-native-api-imports.md`](rk-native-api-imports.md)
- Full 15-state UART receive map: [`rk-updater-uart-state-machine.md`](rk-updater-uart-state-machine.md)
- UART chunk-path byte-order and reachability follow-up: [`rk-uart-firmware-path-semantics-audit.md`](rk-uart-firmware-path-semantics-audit.md)
- Static dialog/control inventory and selected updater UI-handler links: [`rk-dialog-resource-audit.md`](rk-dialog-resource-audit.md)
- Broader audit context: [`reverse-engineering.md`](reverse-engineering.md)
