# RK updater UART receive state machine

This note maps the serial receive dispatcher in the installed
`Dev/01AF/Update.exe` (SHA-256
`27894463b0dfe5bc3f5dc19d4d3351d9dfb692c402bf277bde3889d37e4a206c`). It is
based on static x86 disassembly only. The updater was not run, and no serial
port, keyboard, or bootloader was accessed. Address-level reproduction
requires the same RK package; vendor binaries are not included in this repo.

The message-map row at `.rdata` `0x005943D0` maps message `0x401` to
`FUN_00407E00`. The serial receive worker posts that message at `0x004055E6`
with `wParam=0` and `lParam=0`. The handler drains the queue through
`FUN_00405920` at `0x00407E36` into `0x005C5F60`, then indexes the 15-entry
state table at `0x00408044` using `DAT_005C5F58`. The message row is identified;
its owning MFC class has not been independently recovered.

`FUN_00404220` is a gated diagnostic formatter whose strings identify send
and receive logging; it is not the byte queue. `FUN_004059B0` and custom
builders enqueue bytes and signal the worker. States 7 and 11 process queued
data without the wrapper's two-byte receive log.

## State map

| State | Table slot → dispatch target → body | Response check, transition, queue/request | File or memory effect; unresolved meaning |
| ---: | --- | --- | --- |
| 1 | `0x408044 → 0x407E51 → 0x408080` | Checks `C2 3D` (`0x408089–0x40808D`) or `C3 3C` (`0x4080D0–0x4080D4`). A match sets `0x5C5F2A=1` and state 0 (`0x4080DD–0x4080E4`). Otherwise sets state 2 (`0x40809D`); if `0x5C5F2B!=0`, queues byte `55` at `0x4080B3`. | No image-buffer/file operation. Pair meaning and gate purpose unresolved. |
| 2 | `0x408048 → 0x407E70 → 0x408100` | `AA` selects byte `66`; `99` sets `0x5C5F2A=1` and state 0 (`0x408117–0x40811E`). Other input selects `55`. For `AA` or other input, `0x5C5F2B` gates queueing at `0x408141`. | No image-buffer/file operation. Status meanings unresolved. |
| 3 | `0x40804C → 0x407E8F → 0x408160` | Requires `C0 3F` (`0x408192–0x40819F`). Queues a `0x1006`-byte frame at `0x408263` or `0x408308`, containing `5A 69 3C 0F FD 02` plus source data; then queues a 15-byte control frame at `0x4083C6`. Sets state 4 at `0x4083BC`. | Copies chunks from `0x5C6F8C` using the block index/length and queues them. A nonmatching response reports an error at `0x408400`. Wire-level command meaning unresolved. |
| 4 | `0x408050 → 0x407EB0 → 0x408420` | Requires `C0 3F` (`0x408430–0x408442`); updates block index and offset (`0x5C5F48`, `0x5C5F50`) at `0x40844F–0x408460`, reports progress via `0x402` at `0x40849E`. If more data remains, builds and queues an 11-byte `FE 01` frame at `0x408580` and sets state 3 at `0x408576`. Completion calls `FUN_004089D0` at `0x4084EE`. | The helper sets state 6 and queues a 13-byte request. Its relation to the final update/readback transition is inferred from dataflow; command meaning unresolved. |
| 5 | `0x408054 → 0x407ED1 → 0x408610` | Checks `C0 3F` (`0x408610–0x408619`) and `C1 3E` (`0x408636–0x40863A`); otherwise reports a generic error status. | No state transition, queue, or image-buffer/file operation in this handler. UI status meaning unresolved. |
| 6 | `0x408058 → 0x407EF2 → 0x408670` | Requires `C0 3F` (`0x408680–0x408689`); sets state 7 (`0x408694`) and queues `5A 69 3C 0F 13 EC` at `0x4086BA`. | Starts the state 7 data-processing path; request meaning unresolved. |
| 7 | `0x40805C → 0x407F13 → 0x408710` | Does not check a response signature. If more chunks remain, calls `FUN_004089D0` at `0x4088F0`, which sets state 6 and queues the next 13-byte request. | Optionally calls fwrite-like `FUN_00535EAC` at `0x408761` or `0x408798`; always copies `0x1000` bytes to `0x5C6F80 + blockIndex*0x1000` (`0x4087C2`). At completion it compares assembled data with `0x5C6F8C` (`0x408860–0x408951`) and reports success/error. File-path activation unresolved. |
| 8 | `0x408060 → 0x407F24 → 0x408D70` | Requires `C0 3F` (`0x408D8A–0x408D97`); queues `0x1006` bytes at `0x408DF5`: `5A 69 3C 0F FD 02` plus `0x1000` bytes from `0x5C6F8C`; reports progress. | No state write found in this handler. Purpose, source-buffer setup, and next state unresolved. |
| 9 | `0x408064 → 0x407F45 → 0x408EC0` | Checks `C0 3F` (`0x408EC0–0x408EC9`) and `C1 3E` (`0x408EE6–0x408EEA`); otherwise reports a generic error. | No state transition, queue, or image-buffer/file operation. Meaning unresolved. |
| 10 | `0x408068 → 0x407F66 → 0x408F20` | Requires `C0 3F` (`0x408F30–0x408F39`); sets state 11 (`0x408F44`) and queues `5A 69 3C 0F 13 EC` at `0x408F6A`. | No local image-buffer copy. How this state is initially entered is unresolved. |
| 11 | `0x40806C → 0x407F87 → 0x408FC0` | Does not check a response signature. Processes a chunk and updates progress/index. If more remains, calls `FUN_00408BA0` at `0x4090D1`; that helper sets state 10 (`0x408C43`), queues a 13-byte request, and advances offset `0x5C5F2C` by `0x1000` (`0x408D50`). | Conditionally calls `FUN_00535EAC` with queued bytes and `0x5C5F30` at `0x40903D`; conditionally closes that stream at `0x4090F9`. It does not copy to `0x5C6F80`. File activation unresolved. |
| 12 | `0x408070 → 0x407F98 → 0x408E60` | Checks `C0 3F` (`0x408E60–0x408E69`) and `C1 3E` (`0x408E86–0x408E8A`); otherwise reports a generic error. | No state transition, queue, or image-buffer/file operation. Meaning unresolved. |
| 13 | `0x408074 → 0x407FB9 → 0x409120` | Checks `C2 3D` (`0x409120–0x409129`) and `C3 3C` (`0x409146–0x40914A`); otherwise reports a generic error. | No state transition, queue, or image-buffer/file operation. Meaning unresolved. |
| 14 | `0x408078 → 0x407FDA` (inline), then `0x409180` | Requires first byte `D0` (`0x407FEE`); otherwise reports an error status. | Reads bytes 1–2 as a little-endian word, sets `0x5C5F28=1`, and passes the value to `FUN_00404940` (`0x409180–0x4091A5`). No queue or state write. Displayed value meaning unresolved. |
| 15 | `0x40807C → 0x408021` (inline), then `0x4091B0` | No response-prefix branch. | Configures serial parameters and calls `FUN_00404E60` to open the configured port at `0x4091F9`; that function calls `CreateFileW` at `0x404F09`. No queue or state write in this handler. Serial mode/target unresolved. |

## Conditional file sink and limits

States 7 and 11 contain conditional response-to-file writes through the
fwrite-like wrapper `FUN_00535EAC`. The gate `0x005C5F12` has a direct store of
zero at `0x004071BB`; no nonzero direct store was found in disassembled
`.text`. A fresh full disassembly scan of the installed `Update.exe`
(SHA-256 `27894463B0DFE5BC3F5DC19D4D3351D9DFB692C402BF277BDE3889D37E4A206C`)
found only a comparison at `0x0040424D` and branch checks in the state-7/11
handlers in addition to that zero store.

The stream pointer `0x005C5F30` is only passed to the write/close wrappers at
`0x00408753`, `0x00408786`, `0x004088C0`, `0x0040895C`, `0x004089A1`,
`0x00409007`, `0x00409019`, `0x0040902F`, and `0x004090F3`. No direct
initializer, file-open call, or filename flow to that global was recovered.
The stream and related buffers are in the PE's zero-filled `.data` virtual
tail.

### State 7 entry analysis

State 7 is the other state with a response-to-file sink. The direct state-store
map above places its transition in a closed subgraph: state 7 is set only by
the state-6 handler at `0x00408694`; state 6 is set by `FUN_004089D0` at
`0x00408A73`; that helper is called from the state-7 follow-up at
`0x004088F0` and state-4 completion at `0x004084EE`; state 4 is set from
state 3 at `0x004083BC`; and state 3 is set from state 4 at `0x00408576`.
Initialization sets the state global to zero at `0x00407231`. No direct
state-store edge from initialization or another listed state enters the
state-3/4/6/7 subgraph. Consequently, the direct global-store graph does not
establish a path from initialized state 0 to the state-7 file sink. This does
not exclude an indirect/computed store, an external invocation, or a missed
control path.

### State 10/11 entry analysis

The dispatcher reads state global `0x005C5F58` at `0x00407E3B`. Direct stores
found across the entire disassembly are:

| Store address | Value | Role in the state table |
| --- | ---: | --- |
| `0x00407231` | 0 | Initialization/reset path before serial dispatch. |
| `0x0040809D` | 2 | State 1 transition. |
| `0x004080E4`, `0x0040811E` | 0 | State 1/2 completion paths. |
| `0x004083BC` | 4 | State 3 transition. |
| `0x00408576` | 3 | State 4 loop transition. |
| `0x00408694` | 7 | State 6 transition. |
| `0x00408A73` | 6 | State 7 follow-up transition. |
| `0x00408C43` | 10 | Helper `0x00408BA0`, called from state 11 at `0x004090D1`. |
| `0x00408F44` | 11 | State 10 handler `0x00408F20`. |

The only direct call to helper `0x00408BA0` is at `0x004090D1` inside the
state-11 handler. The state-10 handler is dispatched from slot 10 at
`0x00407F79`; it sets state 11. The state-11 handler is dispatched from slot
11 at `0x00407F8A`; it may call the helper that sets state 10. Thus the
observed state-10/11 transitions form a closed cycle with no direct incoming
transition from the initialization path or states 0–9 and 12–15. In the
statically recovered direct state graph, this response-to-file loop is
unreachable from the initialized state 0. An indirect store, externally
supplied invocation, or other untraced control path cannot be ruled out.

This strengthens the conclusion that these are conditional sink routines,
not evidence of an enabled or reachable firmware-export feature. The active
file feature, any indirect state/gate initialization, and a complete firmware
export remain unproven.

Confidence is high for the table slots, response-byte checks, transitions,
queue calls, and buffer paths visible in the disassembly. The protocol
meanings, initial selection of state 10/11, target device, and file feature
activation remain unresolved. Do not treat this map as permission to replay
commands or as a safe firmware-read procedure.
