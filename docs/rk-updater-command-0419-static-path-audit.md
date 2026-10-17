# RK updater command `0x0419`: static UI-to-worker trace

## Scope and evidence labels

This report traces the one-click-upgrade command in the installed
`Dev/01AF/Update.exe` x86 image, SHA-256
`27894463b0dfe5bc3f5dc19d4d3351d9dfb692c402bf277bde3889d37e4a206c`.
The installed executable and the preserved static-analysis input have the
same hash. Addresses are image VAs for that exact file.

The trace uses PE resources, the recovered MFC command map, existing Ghidra
function exports, and GNU objdump disassembly. The updater was not launched;
no interface was opened, no report or serial command was sent, and no
bootloader was entered.

- **Direct**: the resource, call, branch, memory access, or API reference is
  present in the image.
- **Inferred**: caller/callee data flow supports the interpretation, but the
  runtime result was not observed.
- **Unresolved**: the static evidence does not establish the path or meaning.

## Entry command and resource controls

**Direct:** updater resource 102 (language 1028) declares control `0x0419`
with caption `一键升级` (“one-click upgrade”). The recovered MFC message-map
entry at `.rdata` `0x005943F0` routes command `0x0419` to
`FUN_00409DC0`. The resource inventory identifies the companion controls:

| Control | Resource role | Static touchpoints in this trace |
| --- | --- | --- |
| `0x0419` | One-click-upgrade button | Handler entry; disabled before worker activity; re-enabled on some failure/completion paths. |
| `0x03E8` | Firmware path edit | Its value is consumed by the selected-file parser path. |
| `0x03E9` | Browse button | File-picker handler is `0x0040B0A0`; disabled during portions of upgrade work. |
| `0x041C` | Status text | Set to messages including “Please load firmware!”, firmware error, HID search, and upgrade-mode status. |
| `0x0413`, `0x041B` | Progress controls | Present in the dialog resource. A complete posted-progress-message-to-control mapping is unresolved. |
| `0x041E`, `0x041F`, `0x0421` | Version/device information fields | Parser and device-selection branches write display values; exact field semantics are only partly recovered. |
| `0x0424`, `0x0425` | VID and PID edit fields | Read by the click handler and converted to target values when the parsed file is accepted. |

Control `0x0423` (“specify”) enables or disables `0x0424` and `0x0425` through
handler `0x0040C6D0`. This establishes the UI relationship, but not that the
entered VID/PID identifies a compatible physical device.

## Click handler `0x00409DC0`

### File checks and parse result

**Direct:** at `0x00409DEA`, the handler clears dialog flag `this+0x8E6C`.
It compares the wide string at global `0x005C6FF8` against the empty-string
constant at `0x00593CB4` (`0x00409DF1`–`0x00409E32`). If equal, it updates
status control `0x041C` with the localized “Please load firmware!” string
and returns (`0x00409E34`–`0x00409E92`). The global's producer is the separate
file-selection path; the comparison is consistent with an empty selected
firmware path.

When the value is nonempty, the handler calls `FUN_0040C2F0`
(`0x00409EA9`). That wrapper calls the file parser `FUN_0040A940`
(`0x0040C338`) and stores its return value in `0x005C5F5C`
(`0x0040C33D`). The parser checks the `.upf` signature and reads its header
and section data into host memory; it does not read firmware from the
keyboard. See the existing [firmware readback audit](rk-firmware-readback-audit.md)
for the file format and host-to-device section paths.

**Direct:** if the parser result is `0xFF`, the click handler sets the status
control to “Firmware error, can't upgrade!” and returns
(`0x00409EAE`–`0x00409F18`). If it is not `0xFF`, execution proceeds to
device-selection and worker setup.

### Target fields and worker creation

**Direct:** after an accepted parse result, the handler reads text from edit
controls `0x0424` and `0x0425` using the dialog's `GetDlgItem` path
(`0x00409F53`–`0x0040A09C`). It converts the values and stores them in
globals `0x005C6F78` and `0x005C6F74` (`0x00409FF3`–`0x0040A097`). These
globals are copied into dialog fields later used by the HID/device-selection
branches. This is a static data-flow link; the meaning of every format and
validation edge is not reconstructed.

The handler then calls `CreateThread` at `0x0040A0AD`, with start routine
`FUN_00406AE0` and the dialog pointer as its context. It does not itself call
`HidD_SetFeature`, `HidD_GetFeature`, `ReadFile`, or a serial write API.

## Mode-dependent worker and HID-selection flow

`FUN_0040A940` stores the `.upf` mode byte in global `0x005C5F0C`
(`0x0040AAA2`). The parser's decoded mode dispatch is documented as
0 = A+B, 1 = A, 2 = B, and 3 = A+B+C. **Direct:** `FUN_00406AE0` first
disables `0x0419`, sets `this+0x8F60`, then branches on that mode
(`0x00406AE0`–`0x00406BC8`):

| Parsed mode | Direct worker branch | Limit |
| ---: | --- | --- |
| 0 | Calls `FUN_0040A0F0`. | The later device state and result depend on interface enumeration and additional flags. |
| 1 | Returns after the button-disable step. | No further work is visible in this worker branch; later effects are unresolved. |
| 2 | Clears `this+0x8E6E`, then calls `FUN_0040A580`. | This helper contains a direct HID write call, described below. |
| 3 | Enumerates an HID interface using the selected VID/PID; on success sets `this+0x8E6E=0x100` and calls `FUN_0040A0F0`; on failure clears the field and calls `FUN_0040A580`. | VID/PID compatibility and runtime discovery were not tested. |

`FUN_0040A0F0` retries HID interface enumeration. Its direct calls include
`FUN_00406730(0x408)` / `FUN_00406900`; for modes 0 and 3, a failed first
search updates status `0x041C` to “Searching HID Device...”, sleeps two
seconds, and tries an alternate interface selector `0x802`. If that search
succeeds it creates worker `FUN_00406BD0`; if retries end, it sets an error
status and changes the button state. When a device is found, the function
updates status to “Waiting into upgrade mode...” and calls the status/poll
helper `FUN_00409760` on the mode-dependent path. The direct calls and UI
strings are visible; discovery success and exact meaning of each interface
selector are runtime-unobserved.

`FUN_0040A580` is a mode/upgrade-transition helper. It builds a six-byte
feature-report buffer beginning `05 75`, enumerates a HID handle, and calls
`HidD_SetFeature` at `0x0040A75A`; the helper then waits and searches another
interface, and may create worker `FUN_00406BD0`. This is a **direct write
capability in the static code path**, not an observation that it ran on the
attached keyboard.

## Follow-on worker and section transfer dispatch

`FUN_00406BD0` disables controls `0x0419` and `0x03E9`, resets a dialog event,
then calls `FUN_0040C090`. `FUN_0040C090` directly calls the section dispatcher
`FUN_00402A40` with the firmware/update object at `this+0x160`
(`0x0040C093`–`0x0040C099`). The existing static transfer audit maps that
dispatcher to the mode-selected B/C transfer routines, which contain direct
`HidD_SetFeature` operations and bounded verification reads. The direction
and limits of those paths are described in
[`rk-firmware-readback-audit.md`](rk-firmware-readback-audit.md).

`FUN_0040C090` then branches on the dispatcher result and mode, updates
`this+0x8E6D`/`this+0x8E6E`/`this+0x8E6F`, changes status and button enablement,
and posts message `0x0402` to a dialog-owned window at `0x0040C28E`–
`0x0040C2A3`. The `0x0402` receiver and full mapping from progress values to
controls `0x0413`/`0x041B` are not present in the recovered updater message
map, so that UI edge remains unresolved.

## Timer message path

The recovered dialog `WM_TIMER` handler is `FUN_00409950`. It has three
branches based on `wParam`:

| Timer ID | Direct behavior in `0x00409950` | Relation to command `0x0419` |
| ---: | --- | --- |
| 2 | If gate `0x005C5F08` is 1, kills timer 2; otherwise calls `FUN_00409760`. That helper contains direct HID feature-report calls. | No direct `SetTimer` edge from `0x00409DC0` or `0x00406AE0` to timer 2 was recovered. |
| 3 | Calls status helper `FUN_00409A50`; on nonzero return, updates `0x041C`, disables `0x0419` and `0x03E9`, kills timer 3, sleeps one second, and creates `FUN_00406BD0`. | This supplies another static entry to the follow-on section worker. The timer's creation and runtime trigger are unresolved. |
| 4 | Calls `FUN_0040A580`, which contains the `HidD_SetFeature` site above. | No direct timer-4 creation edge from the click handler was recovered. |

The audited code and API cross-reference inventory do not establish where
these timer IDs are first scheduled for this dialog or whether the timer-3
path is reached after a particular `0x0419` click. Do not infer a runtime
sequence from the presence of a `WM_TIMER` branch alone.

## Separate UART receive state machine

The updater also maps custom message `0x0401` to `FUN_00407E00` at `.rdata`
`0x005943D0`. Its serial receive worker posts `0x0401`; the handler drains
the queue and dispatches global state `0x005C5F58` through the 15-entry table
at `0x00408044`. Initialization writes state 0 at `0x00407231`, and the
direct transition map is in
[`rk-updater-uart-state-machine.md`](rk-updater-uart-state-machine.md).

**Direct:** the `0x0419` handler and its immediate worker do not directly
store `0x005C5F58`. The existing state-store scan places the recovered UART
state transitions in other functions. **Unresolved:** whether an indirect,
external, or untraced path couples a particular button workflow to the UART
state machine. Keep the UART response-to-file sinks and their reachability
limits separate from the `.upf` HID section-transfer path.

## Findings and limits

- **Proven statically:** command `0x0419` routes to `0x00409DC0`; the handler
  checks for a selected path, parses the `.upf`, reads target VID/PID fields,
  and creates a worker. The worker is mode-dependent and has paths into HID
  interface discovery and section dispatch.
- **Proven statically:** the same reachable call graph contains HID
  `SetFeature` sites in `0x0040A580` and the section update routines. Those
  routines can modify device state if executed with a compatible device.
- **Inferred:** the user-visible “one-click upgrade” command is a host-file
  to device upgrade workflow with HID mode-switch and transfer stages.
- **Unresolved:** actual runtime selection, device/interface chosen, branch
  results, message `0x0402` consumer, timer origins, final progress-control
  updates, and any coupling to the UART state table.
- **Not established:** a full device-neutral model of updater behavior or a
  safe passive firmware-copy path. No runtime test is justified by this
  static trace.

## Evidence cross-references

- [`rk-dialog-resource-audit.md`](rk-dialog-resource-audit.md): resource
  controls and message-map summary.
- [`rk-firmware-readback-audit.md`](rk-firmware-readback-audit.md): `.upf`
  parser and HID update/verification paths.
- [`rk-updater-uart-state-machine.md`](rk-updater-uart-state-machine.md):
  15-state UART response dispatcher.
- [`rk-uart-firmware-path-semantics-audit.md`](rk-uart-firmware-path-semantics-audit.md):
  response-to-stream sinks and their unresolved reachability.
