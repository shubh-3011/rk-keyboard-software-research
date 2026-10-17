# RK updater and firmware readback audit

This note examines the installed model-specific updater and its bundled
firmware-like package. It answers a narrow question: does the inspected RK
software expose a demonstrated way to copy the firmware currently running in
the connected RK S98 to a host file while leaving the keyboard unchanged?

The evidence here is static. No RK executable or updater was launched, no
keyboard HID interface was opened, no keyboard report or serial command was
sent, and no bootloader mode was entered. Findings are marked **proven** when
the binary or installed files directly establish them, **inferred** when they
follow from a traced data flow but are not validated at runtime, and
**unresolved** where static evidence is incomplete.

## Examined package

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
`VerNeedToUpdate=0x2108`, and `NoUpdate=1`. Windows previously enumerated the
connected unit as `258A:0150`, which is not the package PID. That descriptor
does not establish that this `.upf` belongs to the connected S98 or its
receiver. The `.upf` is a host-side updater input, not evidence of firmware
read from a keyboard.

**Current Windows descriptor snapshot (2026-10-18):** a read-only
Plug-and-Play enumeration returned three present Bluetooth LE child nodes
named `RK-S98RGB` and no present USB device node with VID `258A`. No HID
interface was opened and no report or GATT data was read. These friendly names
and PnP child records do not identify the keyboard's firmware revision or
prove a control channel is available. A prior USB descriptor observation
reported `258A:0150`; in the installed profile crosswalk, `0150` is recorded
as the wireless PID for an RK A70 profile, while the eight S98 profile rows
have direct PIDs `0174`, `01AF`, `01BF`, `0223`, `0224`, `022B`, `022F`, and
`0230` and no installed `PID_Wireless` value. The historical `0150` node
therefore cannot be confidently assigned to the S98 or its current Bluetooth
LE nodes.

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

## Can the connected S98 firmware be copied without changing it?

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
The hardware constraint remains in force: do not test this uncertainty by
opening HID, sending a report, running the updater, or entering a bootloader.

## Evidence files

- Installed package manifest: [`rk-installed-package-manifest.csv`](rk-installed-package-manifest.csv)
- Native API addresses: [`rk-native-api-xrefs.csv`](rk-native-api-xrefs.csv)
- Native import list and binary hashes: [`rk-native-api-imports.md`](rk-native-api-imports.md)
- Full 15-state UART receive map: [`rk-updater-uart-state-machine.md`](rk-updater-uart-state-machine.md)
- UART chunk-path byte-order and reachability follow-up: [`rk-uart-firmware-path-semantics-audit.md`](rk-uart-firmware-path-semantics-audit.md)
- Static dialog/control inventory and selected updater UI-handler links: [`rk-dialog-resource-audit.md`](rk-dialog-resource-audit.md)
- Broader audit context: [`reverse-engineering.md`](reverse-engineering.md)
