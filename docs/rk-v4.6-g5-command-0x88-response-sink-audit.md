# V4.6 G5 command `0x88` response and sink audit

## Scope and boundary

This is a static follow-up for the V4.6 `DeviceDriver.exe` command-`0x88`
response path, focused on the `HidD_GetFeature` call at `0x004109F1`, its
caller candidates, and any downstream file sink. The hash-pinned image is
2,418,176 bytes with SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9` at
`C:\Users\shubh\Downloads\sshorcale\.research\rk4_6_official_extract_20261015\app\DeviceDriver.exe`.
Disassembly was read from disk; the PE was not executed. No HID
interface was opened and no device report was sent or read.

The conclusions below distinguish the presence of a conditional code path
from evidence that a caller invokes it or that the returned bytes are firmware.

## Static method and response flow

`CDevG5KB`'s V4.6 vtable address point is `0x005D3D0C`; its `+0x70` slot at
`0x005D3D7C` points to wrapper `0x00411030`. The wrapper checks object field
`+0x238` and returns zero if it is set. Otherwise it passes the caller's
output pointer and requested byte length to helper `0x00410890`.

In the wrapper/helper ABI, the output pointer reaches the helper in `ECX`, the
G5 object is passed as a stack argument, and the requested length is the other
stack argument. The helper reads the HID handle from object `+0x04` and report
identifier from `+0x2DC`; it rejects a null handle or a nonpositive length.
It limits each iteration to `0x200` bytes and builds a `0x208`-byte feature
buffer. The constructed request has command byte `0x88` at offset 1 and
includes the chunk length and offset-related fields. The precise protocol
meaning of those other bytes is not established here.

For each chunk, the helper calls `HidD_SetFeature` at `0x00410992`, then
`HidD_GetFeature` at `0x004109F1`, each with the same object handle and
`0x208`-byte buffer. If the read succeeds, it verifies response byte 1 is
still `0x88`. Only then does it call the internal copy routine at
`0x0057BA90` with destination `output + offset`, source `response + 8`, and
length `chunkLength`. The copy routine's arguments and body match a local
`memcpy` implementation. The loop advances by the copied chunk and continues
until the requested length is reached. Error, handle, and response-command
checks can stop the operation; the wrapper itself also has the busy-state
gate.

This establishes a request-write followed by a conditional response-read and
memory copy in this exact image. It does not establish that command `0x88`
selects firmware, that the device accepts the request, or that any particular
caller requests a full image range.

## Caller and output-buffer attribution

The existing hash-pinned V4.6 caller scan was rechecked against this helper
and wrapper. It reports:

| Scan result | Evidence and limit |
| --- | --- |
| Direct calls to wrapper `0x00411030` | None in the decoded `.text`; the only raw occurrence of that pointer is the `+0x70` vtable entry. This does not rule out computed or external dispatch. |
| Direct calls to helper `0x00410890` | Only the wrapper call at `0x00411048`. |
| Decoded virtual `call [reg+0x70]` sites | 77 screened; none attributed to the `CDevG5KB` receiver or to this wrapper. |
| Tail relays through slot `+0x70` | Three generic candidates at `0x0047FFA0`, `0x004EDD9E`, and `0x0051B04E`; none has a statically proven G5 receiver, request length, or output-buffer consumer. They remain unresolved, not excluded. |

The detailed site and method-pointer search results are in the
[V4.6 command-`0x88` callsite completeness follow-up](rk-v4.6-g5-command88-callsite-completeness-follow-up.md)
and the [G5 `+0x70` caller attribution audit](rk-v4.6-cdevg5-realdata-caller-audit.md).
Because no caller is attributable to this G5 method, there is no recovered
caller buffer whose length, requested range, or downstream use can be followed
to a persistent sink. The helper itself has no `CreateFile*`, `WriteFile`,
configuration-file, or stream call; its visible data sink is the caller-owned
memory buffer.

## Evidence status

| Question | Static status |
| --- | --- |
| Does this image contain a `0x88` request/read/chunk-copy routine? | **Proven.** The G5 `+0x70` wrapper reaches the helper; the helper issues a request write and conditional feature read, checks the response command, and copies chunks to its output buffer. |
| Is the transaction passive/read-only? | **No.** The statically recovered helper sends `HidD_SetFeature` before `HidD_GetFeature` in each chunk transaction. No device behavior was observed. |
| Is the response identified as firmware bytes? | **Unresolved.** Command value and byte-copy mechanics do not identify the data's meaning. |
| Is a caller, full requested range, or output-buffer consumer established? | **No.** The 77-call scan and three tail relays produce no attributable G5 caller. |
| Is a complete firmware-file export path established? | **No.** There is no traced G5 caller-to-full-range-to-file path. Static analysis cannot prove that an indirect, external, or unrecognized path is impossible. |

## Remaining work

To demonstrate a firmware export path statically, the unresolved receiver
would first need to be attributed to this exact G5 vtable, then its actual
output pointer and requested length traced to the consumer and any file sink.
The requested range would have to cover a complete image, and the response
format would need a defensible firmware interpretation. These facts are not
available from the current static evidence. No live keyboard access is part
of this audit.
