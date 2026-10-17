# RK V4.6 `CDev3632` frame and selector audit

## Scope and provenance

Offline static analysis of the extracted V4.6-labeled `DeviceDriver.exe` only:

- SHA-256: `8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`
- Size: 2,418,176 bytes; PE image base: `0x00400000`
- Source: `.research/rk4_6_official_extract_20261015/app/DeviceDriver.exe`
- Disassembly snapshot: `.research/rk4_6_objdump_disasm.txt`

The hash was recomputed against the extracted input. Evidence below is limited to
static bytes and control flow in this exact binary. The device was not opened,
and no report, command, or updater was run. “Selector” is used as a neutral name
for the literal byte passed by the caller; end-user meanings are not established
unless explicitly described as inferred.

## 20-byte frame layout

The receive worker at `0x0040D7D0` calls `ReadFile` for exactly `0x14` bytes,
then passes successful reads to `0x0040D990`. Request builders at
`0x0040DF10`, `0x0040E200`, and `0x0040E9C0` also construct and write 20-byte
records. For the chunked builder (`0x0040DF10`), the statically decoded offsets
are:

| Offset | Evidence-backed construction/use | Boundary |
| ---: | --- | --- |
| `0` | Set to `0x13` in request builders. | Marker/format byte is a descriptive name, not a recovered protocol name. |
| `1` | Caller selector; response matcher compares received byte 1 with the requested selector. | Exact selector semantics vary by callsite and remain unknown. |
| `2` | Request builder writes total chunk count. The response matcher treats bit 7 as an error indicator. | Role differs between request and response paths; do not treat it as one fixed field meaning. |
| `3` | Request chunk index, initialized at zero and incremented for each packet. | Response assembly also uses sequence/count-related header fields; not every variant has been mapped to a single schema. |
| `4` | Chunked writer packs `(context_word & 0x0F) << 4` with the chunk payload length in the low nibble. `0x40E200`/`0x40E9C0` use this position differently for their one-frame query builders. | The high nibble is an opaque context/tag value here; its semantic name is unknown. Do not apply the chunk encoding to all selectors. |
| `5..18` | Up to 14 data bytes in the chunked writer; bytes beyond the last chunk’s payload are zero-filled. | For one-frame query builders these bytes are initialized to zero before receive/assembly. |
| `19` | Request builder writes an 8-bit sum after initializing the packet to zero. | The receiver path reviewed here does not recompute this sum. |

For `0x0040DF10`, the number of chunks is `ceil(length / 14)`, with a maximum
accepted payload length of `0x1FF` (511 bytes); the high and low parts of byte 4
are constructed at `0x0040DF91–0x0040DFE0`, payload bytes are copied beginning at
offset 5 (`0x0040E081–0x0040E093`), and the final byte is assigned at
`0x0040E0CC–0x0040E0D7`. The other query builders initialize a 20-byte packet,
set byte 0 to `0x13`, byte 1 to their selector, byte 2 to `1`, byte 3 to `0`,
then use the same byte-sum pattern (`0x0040E200–0x0040E2E0` and
`0x0040E9C0–0x0040EA89`).

### Checksum and error handling

All three request construction paths sum the 20 byte positions modulo 256 while
the final checksum position is still zero, then store the resulting low byte at
offset 19. Thus the proven request checksum is an additive byte sum of offsets
0 through 18. No stronger checksum name or polynomial is supported by these
instructions.

The receive worker and parser route non-`0x0A` records into a 20-byte ring
buffer (`0x0040D990`, `0x0043E4B0`). The response matcher at `0x0040DA50`
dequeues records and checks for byte 0 equal to `0xFF`, byte 2 bit 7 set, or
byte 1 matching the requested selector. The `byte2 & 0x80` case returns internal
status `-3`; the caller’s error log labels that status `crc`. This is evidence
for an error-status bit and the software’s `crc` label, not evidence of
recomputed CRC/checksum validation. In the receive/parser/queue/matcher paths
examined, no code sums received offsets 0–18 or compares a computed value with
offset 19. Whether another layer or the device validates incoming checksum
bytes is unknown.

## Receive queue and matching behavior

- Worker `0x0040D7D0` issues an overlapped 20-byte `ReadFile`, and dispatches a
  completed record to `0x0040D990`.
- Parser `0x0040D990` special-cases byte 1 equal to `0x0A`: it may update a
  cached Boolean from byte 6 when byte 5 equals 2, and posts message `0x7EB`
  with bytes 5–7 packed into the message parameter. This is a statically
  observed asynchronous path; its user-facing meaning is unknown.
- Other records are placed in the ring at object offset `+0x294`. The ring
  writer `0x0043E4B0` appends a 20-byte record and signals its event; reader
  `0x0043E580` waits for enough queued bytes and removes a 20-byte record.
- Matcher `0x0040DA50` reads up to 20 queued records, discarding records whose
  byte 1 differs from the requested selector. It returns zero on an exact byte
  1 match, `-2` for a queue timeout, `-3` when response byte 2 has bit 7 set,
  `-4` when byte 0 is `0xFF`, and `-1` after exhausting the mismatch scan.
- The direct query helper `0x0040E200` waits using a 3000 ms timeout and skips
  response matching for selector `0x06`. The chunked writer `0x0040DF10` skips
  it for selector `0x06` and for negative signed-byte selectors such as
  `0x88`; otherwise it requests a selector-matched response. Its caller can
  permit retry on `-2`/`-3`, with the loop bounded to five retries.

This is a software-side queue and selector matcher. It does not show that any
specific model accepts or answers these requests.

## What the selector callsites support

| Selector | Proven call path and behavior | Safe semantic description | Unknowns |
| ---: | --- | --- | --- |
| `0x05` | Vtable slot 13 wrapper `0x0040E6B0` calls `0x0040E9C0` with caller-provided values/buffers and a constant `2`; helper builds a one-frame request and receives/assembles response chunks. | Parameterized query/read path with caller buffer handling. | Field meanings, data object, and feature name. |
| `0x06` | Vtable slot 14 wrapper `0x0040E680` calls `0x0040E200`; the helper explicitly returns without waiting for a response for selector 6. | One-way command path in this helper. | Command action and whether the device emits any unsolicited reply. |
| `0x07` | Vtable slot 11 wrapper `0x0040E6E0` calls `0x0040E200` requesting one response byte; on success it caches `response[0] == 0` as a Boolean in `[this+0x264]`. | One-byte status query feeding a cached Boolean. | What the Boolean represents. |
| `0x44` | Vtable slot 15 wrapper `0x0040E5D0` calls `0x0040E200` with caller-supplied arguments. Slot 19 calls slot 15 asking for `0x80` bytes, then passes that buffer to selector `0x04`. | Parameterized query/read path; one internal caller requests a 128-byte result. | Meaning of the returned bytes and end-user setting. |
| `0x4A` | Vtable slot 12 wrapper `0x0040E600` calls `0x0040E200` for two response bytes and copies them to optional output pointers. | Two-byte status/query response. | Meaning/encoding of either byte. |
| `0x88` | Vtable slot 18 wrapper `0x0040ED20` calls chunked helper `0x0040DF10` with caller data/length; it is gated by object field `[this+0x238]`. The helper’s signed-byte branch skips selector-response matching for `0x88`. | Chunked send path with no synchronous matched response in this helper. | Data format, purpose, receiver ACK behavior outside this path. |
| `0x04` | Slot 19 passes the 128-byte result from selector `0x44` to `0x0040DF10` using selector `0x04`, with retry enabled. | Chunked 128-byte follow-on transfer in that callsite; helper expects a matching response. | Whether this is save/apply/profile state, and the payload schema. |
| `0x0B` | Vtable slot 20 wrapper `0x0040E640` invokes `0x0040DF10` with selector `0x0B` and fixed length `0x0F` (15); the wrapper reduces the result to success/failure. | 15-byte chunked transfer with selector-matched response handling. | The 15-byte structure and operation name. |

These are callsite-level roles only. Names such as “brightness,” “lighting,”
“keymap,” or “firmware” are not assigned to these selectors by this report.

## Limits

The `0x0A` asynchronous dispatch is not the same as a matched query response.
The selector matcher is not a full protocol parser: it matches byte 1 and
interprets a few status bytes, while chunk assembly is performed by higher
helpers. Some helper call argument roles and the upper nibble used by the
chunked writer remain unnamed. No runtime branches, device responses, model
revision compatibility, or physical device semantics were verified.
