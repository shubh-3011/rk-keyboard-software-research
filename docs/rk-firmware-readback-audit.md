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

The ordinary import cross-reference inventory lists nine `HidD_GetFeature`
call instructions in `Update.exe`: `0x004023CF`, `0x0040269B`, `0x0040289C`,
`0x00402985`, `0x0040308C`, `0x0040389C`, `0x0040980D`, `0x0040BC16`, and
`0x0040BF57`. The traced ones divide into section-B/C verification,
BLE/version/status handling, and an updater mode/connection helper. The
`0x0040980D` routine also has a nearby `HidD_SetFeature` at `0x004097A8`;
therefore this is not evidence of passive capture. No inspected feature-read
path streams a full firmware image to a host file.

The updater also contains a separate, generic serial transport. The open
routine at `0x00404E60` calls `CreateFileW` at `0x00404F09` with
`GENERIC_READ | GENERIC_WRITE`, `OPEN_EXISTING`, and overlapped I/O, then sets
the communication mask, DCB, and timeouts. The surrounding serial workers
perform overlapped `ReadFile`/`WriteFile` operations and queue received bytes
for an internal callback. A documented static call chain enters this setup
from an updater state-machine path, but the precise device mode and the
relationship to the HID `.upf` path remain unresolved. A generic serial read
can return bytes to RAM; that fact alone does not identify a firmware dump
command or a save-to-file workflow.

The API inventory also records file `ReadFile`/`WriteFile` references in the
updater. At `0x00405250` and `0x00405535`, `ReadFile` operates on the serial
object's handle; `WriteFile` at `0x0040572A` is in its corresponding serial
worker. The `0x00431E27` read and `0x00431F9C` write are generic file-wrapper
methods, while the remaining references are in runtime/library code. The
`.upf` parser's direct path is via C++ stream/runtime helpers and allocates
section buffers before the HID transfer; the traced HID verifier buffers are
compared in memory. **No data flow from a firmware response buffer to a host
file write was found in these traced update/verify routines.** This is a
negative result over the inspected paths, not proof that no untraced,
indirect, or undocumented path exists anywhere in the updater or bootloader.

## Can the connected S98 firmware be copied without changing it?

**Proven:** Windows has not exposed this keyboard as a mass-storage volume
from which firmware could simply be copied. The bundled `.upf` is a
host-side package with a VID/PID that differs from the observed USB unit. The
traced HID updater writes section data and then reads back bounded chunks to
verify those writes. Its BLE path reads version/status data. No traced path
copies a full device firmware image to a host file.

**Inferred from the analyzed paths:** the installed RK package offers a
host-to-device update flow, not a demonstrated read-only firmware backup
workflow. In particular, an updater “read” is not automatically passive: the
section-verification paths follow explicit stage/write operations, and the
generic HID read helper has request writes associated with the read.

**Unresolved:** the full UART state machine, every indirect call, undocumented
bootloader commands, and the exact protocol revision of the currently
connected S98 are not reconstructed. Therefore static analysis cannot prove
that extracting firmware is technically impossible. It does establish that
there is currently no demonstrated way in the inspected software to copy the
running firmware while guaranteeing the keyboard remains unchanged. The
explicit hardware constraint remains in force: do not test that uncertainty
by opening HID, sending a report, running the updater, or entering a
bootloader.

## Evidence files

- Installed package manifest: [`rk-installed-package-manifest.csv`](rk-installed-package-manifest.csv)
- Native API addresses: [`rk-native-api-xrefs.csv`](rk-native-api-xrefs.csv)
- Native import list and binary hashes: [`rk-native-api-imports.md`](rk-native-api-imports.md)
- Broader audit context: [`reverse-engineering.md`](reverse-engineering.md)
