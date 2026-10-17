# RK updater UART chunk-path semantics and reachability audit

## Scope and method

This report narrows in on UART receive states 3/4/6/7 and 10/11 in the
installed x86 `Dev/01AF/Update.exe`, SHA-256
`27894463b0dfe5bc3f5dc19d4d3351d9dfb692c402bf277bde3889d37e4a206c`
(2,109,952 bytes). Addresses are virtual addresses in that exact executable.
The analysis uses its disassembly and the existing state/firmware audit notes;
the updater was not run, and no serial, HID, GATT, keyboard, or bootloader I/O
was attempted.

**Proven** means directly visible in the binary's code or PE layout.
**Inferred** means supported by a static producer/consumer or control/data
flow but not checked at runtime. **Unresolved** means the binary does not
establish the interpretation. Hex byte sequences below are in memory/send
order; immediate WORD values are little-endian when written to buffers.

## Receive buffer passed to the state handlers

**Proven:** the receive worker reads serial data with `ReadFile` at
`0x00405535`, packages each read into a queue node, and caps a node's recorded
length at `0x1FFF` (`0x004055B2`–`0x004055D3`). The worker posts message
`0x401` at `0x004055E6`. `FUN_00407E00` drains one node through
`FUN_00405920` at `0x00407E36` before dispatching state global
`0x005C5F58` through the table at `0x00408044`.

`FUN_00407E00` first zeroes a `0x1000`-byte scratch region at
`0x005C5F60`. `FUN_00405920` copies at most `0x1000` bytes from one queued
node, stores the copied count in a local output variable, and appends a NUL
byte (`0x00405969`–`0x00405997`). **Proven:** state 7 and state 11 do not
validate a response prefix or checksum before processing this scratch buffer.
No dataflow from the drain helper's local copied-count output into either
handler was recovered. State 7 always copies `0x1000` bytes from the scratch
buffer; state 11 selects its write count from total length and block index.
Consequently, the code examined here does not establish that each consumed
chunk contains the number of nonzero bytes the handlers assume.

This variable-length UART queue is distinct from the DeviceDriver 3632
transport's fixed 20-byte records in
[`rk-3632-response-semantics-audit.md`](rk-3632-response-semantics-audit.md).
The 3632 response rules cannot be imported into this UART dispatcher.

## States 3 and 4: source-buffer transfer loop

### State 3 builder and response gate

**Proven:** state 3 is dispatched at `0x00407E8F` to
`FUN_00408160`. It accepts only the first two scratch bytes `C0 3F`
(`0x00408192`–`0x004081A6`). On a match, it constructs and queues a data
frame through `FUN_004059B0` at `0x00408263` or `0x00408308`.

The data-frame prefix is `5A 69 3C 0F 02 FD` in transmitted byte order. The
last pair comes from storing WORD `0xFD02` at buffer offset 4, so the bytes
are `02 FD`, not `FD 02`. The frame contains up to `0x1000` bytes following
the six-byte prefix. Its source pointer is `0x005C6F8C + blockIndex*0x1000`;
the copy count is bounded using `0x005C6F88`. The queued length is either
`0x1006` or the final remainder plus six, selected using total-length global
`0x005C5F54` and block index `0x005C5F48` (`0x004081AC`–`0x00408263`,
`0x00408288`–`0x00408308`). A per-frame 0x1000-byte local staging buffer is
zeroed before the source copy.

After this data frame, the same state constructs a 15-byte control frame at
`0x005C5F34` and queues it at `0x004083C6`. Its known fixed bytes are
`5A 69 3C 0F 03 FC`: WORD `0xFC03` occupies offsets 4–5, yielding `03 FC`.
Other fields are assembled from globals `0x005C5F52`, `0x005C5F50`, and
`0x005C5F4C`; byte 14 is produced by an inverted byte-addition sequence.
The roles and units of those fields are unresolved, and the final byte is
not identified here as a standard checksum.

### State 4 loop / completion

**Proven:** state 4 is dispatched at `0x00407EB0` to `FUN_00408420` and
also requires `C0 3F` (`0x00408430`–`0x00408449`). It increments block index
`0x005C5F48` and adds `0x1000` to offset-like global `0x005C5F50`
(`0x0040844F`–`0x00408460`). It computes progress and reports it through
message `0x402`.

When another block remains, it builds an 11-byte frame at
`0x00408520`–`0x00408580` and stores state 3 (`0x00408576`). Its bytes are
`5A 69 3C 0F 01 FE`, followed by the high and low bytes of
`0x005C5F4C`, then the high and low bytes of the selected length, then a
final inverted byte sum. WORD `0xFE01` gives the on-buffer bytes `01 FE`.
The earlier state-machine draft's shorthand “`FE 01` frame” reversed these
two wire bytes.
The framing and loop are proven; the command meaning and the meaning of the
offset/length fields are unresolved.

At completion, state 4 clears the block index and calls
`FUN_004089D0` (`0x004084EE`). That helper sets state 6 (`0x00408A73`),
enqueues a 13-byte record on the updater's serial transmit queue, then
signals the queue event at `0x005BB4F0` via `SetEvent` at
`0x00408B65`. Its leading bytes are `5A 69 3C 0F 12 ED`;
the remaining fields are taken from globals at `0x005C5F2C`,
`0x005C5F2E`, and `0x005C5F54`, followed by a calculated final byte.
The meanings of these fields and this request are unresolved.

### States 6 and 7 after the transfer

**Proven:** state 6 accepts only `C0 3F` (`0x00408680`–`0x00408690`),
sets state 7 (`0x00408694`), and queues exactly six bytes
`5A 69 3C 0F 13 EC` (`0x0040869E`–`0x004086BA`). State 7 is dispatched to
`FUN_00408710` and does not check a response signature. It writes received
scratch bytes conditionally to the stream at `0x005C5F30` when gate
`0x005C5F12` is nonzero. It also copies `0x1000` bytes from
`0x005C5F60` into `0x005C6F80 + blockIndex*0x1000`
(`0x004087B1`–`0x004087C2`). At its completion branch it compares the
assembled region at `0x005C6F80` against `0x005C6F8C` for a length derived
from `0x005C5F54` (`0x0040884D`–`0x00408998`). A matching comparison reports
one result; a mismatch reports another.

**Inferred:** because this path follows the state-3 source-buffer transfer
and compares a post-transfer buffer with a separate reference pointer, it
resembles a transfer verification/readback phase. It is not evidence of a
passive, read-only firmware-copy feature: preceding states queue source data
and control frames, and the state-7 path is reached only within that transfer
subgraph in the directly recovered state graph.

**Unresolved:** no direct `.text` write to `0x005C6F80`, `0x005C6F88`, or
`0x005C6F8C` was found; these addresses lie in the PE `.data` zero-filled
virtual tail. In the examined code, `0x005C6F80` and `0x005C6F8C` are read as
buffer pointers, and `0x005C6F88` is read as a length. A nonlocal/indirect
initializer or omitted path cannot be excluded, but the complete pointer and
source setup needed to substantiate this comparison is absent from the
recovered direct references.

## States 10 and 11: separate offset/chunk loop

### State 10 request gate and state 11 acknowledgement

**Proven:** state 10 is dispatched at `0x00407F79` to `FUN_00408F20`. It
accepts scratch prefix `C0 3F` (`0x00408F30`–`0x00408F40`), sets state 11
(`0x00408F44`), and queues the six-byte sequence `5A 69 3C 0F 13 EC`
(`0x00408F4E`–`0x00408F6A`). State 11 is dispatched at `0x00407F8A` to
`FUN_00408FC0`; it has no response-prefix check before its chunk handling.

`FUN_00408FC0` reads the nominal total length from `0x005C5F54` and block
index from `0x005C5F48`. When gate `0x005C5F12` is nonzero, it calls the
fwrite-like wrapper `FUN_00535EAC` with scratch buffer `0x005C5F60` and a
count selected as a remainder, `0x1000`, or the total length, depending on
the index/length branch (`0x00408FC1`–`0x00409048`). It updates progress and
the block index. If another block is due, it calls `FUN_00408BA0` at
`0x004090D1`; on the completion path it conditionally closes the stream
through `FUN_00535F9A` at `0x004090F9` and displays a completion status.

### 13-byte next-block builder

`FUN_00408BA0` is the only direct caller target that sets state 10; its only
direct caller is the state-11 handler at `0x004090D1`. The helper sets state
10 at `0x00408C43`, enqueues a 13-byte record, signals the queue event, and
increments `0x005C5F2C` by `0x1000` (`0x00408C37`–`0x00408D50`). The byte
layout established by stores is:

| Byte offsets | Proven construction |
| --- | --- |
| 0–3 | `5A 69 3C 0F` |
| 4–5 | `12 ED` (WORD `0xED12` in memory order) |
| 6–7 | High byte, low byte of WORD global `0x005C5F2E` |
| 8–9 | High byte, low byte of global `0x005C5F2C` |
| 10–11 | High byte, low byte of selected block length (`0x1000` for the full block, otherwise the computed remainder) |
| 12 | Complemented byte sum formed from the offset, length, and `0x005C5F2E` bytes; no standard checksum name is established |

The builder gives a bounded basis for describing request framing and
0x1000-step offsets. The 13-byte shape, repeated offset increment, and
state-11 response processing are **consistent with** a chunk request followed
by a chunk response, but do not identify the command as firmware read or
establish which memory region the offset addresses. The first transition
into state 10 is not recovered; this helper only shows the repeat request
after state 11 has processed a chunk.

## Initialization, direct transition graph, and dormant sinks

The dispatcher reads `0x005C5F58` at `0x00407E3B`; initialization writes
state 0 at `0x00407231`. A full disassembly reference scan found these direct
state stores:

| Address | Value | Direct path |
| --- | ---: | --- |
| `0x00407231` | 0 | Initialization/reset |
| `0x0040809D` | 2 | State 1 |
| `0x004080E4`, `0x0040811E` | 0 | State 1/2 completion |
| `0x004083BC` | 4 | State 3 |
| `0x00408576` | 3 | State 4 loop |
| `0x00408694` | 7 | State 6 |
| `0x00408A73` | 6 | `FUN_004089D0`, called by state-4 completion and state-7 continuation |
| `0x00408C43` | 10 | `FUN_00408BA0`, called from state 11 |
| `0x00408F44` | 11 | State 10 |

**Inferred from direct stores/calls:** states 3/4/6/7 form a closed direct
subgraph that can cycle through a source-buffer transfer and comparison.
States 10/11 form another closed direct cycle: state 10 enters 11, and only
state 11 calls the helper that returns to 10. Neither subgraph has a direct
state-store edge from initialized state 0 or from states 1/2. An indirect
alias write, external invocation, or missed path is not excluded, so this is
not proof that either routine can never execute.

**Proven:** `0x005C5F12` is assigned zero at `0x004071BB`; no nonzero direct
store to it was found. No file-open call, filename flow, or direct
initializer for stream pointer `0x005C5F30` was recovered. The stream pointer
is used only at the conditional write/close callsites in states 7/11. These
sink routines therefore do not by themselves establish an active file export
path.

The key loop inputs are also incomplete in direct references: `0x005C5F54`
is read as a total length but has no recovered direct `.text` store;
`0x005C5F2E` is read but has no recovered direct store; `0x005C5F2C` starts
in the zero-filled data tail and is only advanced by `0x1000` in the
state-10 helper. The zero-filled initial value of a global does not prove
what an untraced runtime alias might later write, but the inspected binary
does not show an ordinary initialization of the range or length for a full
export.

## Finding on a complete firmware read

**Proven:** `Update.exe` contains conditional UART response-to-stream writes
and two chunk-shaped control paths. The state-10/11 helper builds requests
with an offset-like field, a block length, and a 0x1000 offset advance. State
7 also copies incoming scratch bytes to a buffer and compares that buffer to
a reference pointer. The ordinary receive path does not validate a body
signature or response checksum for states 7/11.

**Inferred:** the 10/11 loop could be a chunk collection path when reached
with suitable globals and an enabled file stream. The 3/4/6/7 chain could be
a post-transfer verification/readback sequence. Neither inference identifies
the returned bytes as the connected S98's firmware.

**Unresolved:** no direct entry into states 3/4/6/7 or 10/11 from state 0 was
found; the file gate is directly initialized false; the stream pointer,
filename, total length, and address/range setup are absent from the recovered
direct flow; model/protocol identity is unknown; and the receiver does not
prove chunk completeness before state 7/11 consumes the scratch buffer.
Therefore the binary does **not demonstrate a reachable, complete firmware
read or a safe read-only firmware backup of the connected RK S98**. Static
analysis cannot prove that no omitted indirect path exists, and this report
does not claim extraction is impossible.

## Corrections found in the earlier state-machine draft

Before the root report was patched, its table rows at lines 28, 29, and 33
had three stale byte-order renderings. The current working copy of
`docs/rk-updater-uart-state-machine.md` has been corrected. The exact
corrections are:

| Earlier row/location | WORD stored by the binary | Correct bytes in memory/send order |
| --- | --- | --- |
| Line 28, state 3 data-frame prefix | `0xFD02` | `02 FD` (full prefix `5A 69 3C 0F 02 FD`), not `FD 02` |
| Line 28, state 3 15-byte control frame | `0xFC03` | `03 FC` (full known prefix `5A 69 3C 0F 03 FC`) |
| Line 29, state 4 11-byte frame | `0xFE01` | `01 FE` (full known prefix `5A 69 3C 0F 01 FE`), not `FE 01` |
| Line 33, state 8 frame | `0xFD02` | `02 FD` (full prefix `5A 69 3C 0F 02 FD`), not `FD 02` |

These are byte-order corrections only. They identify literal bytes written
into the frames; they do not establish command names or protocol semantics.
The complete 15-state path and firmware-package audit are in
[`rk-updater-uart-state-machine.md`](rk-updater-uart-state-machine.md) and
[`rk-firmware-readback-audit.md`](rk-firmware-readback-audit.md).
