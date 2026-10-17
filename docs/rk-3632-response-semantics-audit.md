# RK 3632 response and status-event audit

This audit examines the 3632 transport paths in the installed `DeviceDriver.exe`
4.06 PE, SHA-256
`C03F88BC4E2D78AA4392D7445B0FD62182DC824F97F5D5DB40BD009E547A9AB6`.
Addresses below are virtual addresses for that exact binary. The work is static
analysis of the existing binary snapshot and read-only Ghidra project; no RK
application, updater, keyboard interface, or report was run.

## Findings

### Request framing and checksum

`FUN_0040D7E0` constructs a zero-filled 20-byte request frame in its local
buffer at `0x0040D8B8`–`0x0040D8EA`, then sends it through
`FUN_0040E0F0` at `0x0040D95C`.

| Offset | Static construction | Interpretation limit |
| --- | --- | --- |
| `0` | Constant `0x13` (`0x0040D8DD`) | Meaning of the marker is unknown. |
| `1` | Command byte (`0x0040D8E2`) | Command meanings vary by caller and remain incomplete. |
| `2` | Total number of 14-byte chunks (`0x0040D8CC`–`0x0040D8D0`) | This is the count calculated for the whole request. |
| `3` | Zero-based packet index (`0x0040D8D4`–`0x0040D8D8`) | Incremented once while building each frame. |
| `4` | `(option << 4) | payload_length`, with at most 14 payload bytes (`0x0040D865`–`0x0040D89D`, `0x0040D8EA`) | The option field’s meaning is unresolved. |
| `5`–`18` | Up to 14 payload bytes copied at `0x0040D8F2`–`0x0040D904`; unused bytes stay zero | No independent payload schema is established here. |
| `19` | Low 8 bits of the additive sum (`0x0040D920`–`0x0040D958`) | This is a request-side checksum calculation only. |

The checksum loop adds the 20 frame bytes while offset 19 is still zero, then
stores the wrapped byte sum at offset 19. It is equivalent to the low byte of
the sum of offsets 0–18. The receive path below does **not** calculate or
compare this checksum on returned records.

### Reader and dispatch block

The reader begins at `0x0040D120`; Ghidra has instructions there but no
recovered function boundary or function name. The following is therefore a
bounded basic-block/control-flow description, not a recovered C function.

- It checks a word-sized stop/active field at object offset `+0x24A`
  (`0x0040D13D`–`0x0040D144`). If that field is zero, it reaches the return
  path at `0x0040D2BB`–`0x0040D2CF`.
- It obtains the device handle from object offset `+0x04` (`0x0040D195`). If
  null, it sleeps 200 ms and checks again (`0x0040D19C`–`0x0040D1A7`).
- It initializes a 64-byte local area (`0x0040D1A9`–`0x0040D1B7`) and calls the
  `ReadFile` import indirectly through the pointer loaded at `0x0040D15E`,
  requesting 20 bytes with an overlapped structure (`0x0040D1BA`–`0x0040D1D1`).
- A successful immediate read dispatches the local buffer to
  `FUN_0040D2E0` at `0x0040D1DB`, then loops to read again (`0x0040D1D7`–
  `0x0040D1E0`).
- `ERROR_IO_PENDING` (`0x3E5`) leads to `WaitForMultipleObjects` with two
  handles and an infinite timeout (`0x0040D1E2`–`0x0040D1FD`). Return value zero
  dispatches the buffer and repeats (`0x0040D1FF`–`0x0040D20C`). Return value
  one reaches the cancellation/cleanup path at `0x0040D287`–`0x0040D2B9`, which
  calls `CancelIo` and then `GetOverlappedResult` with its wait argument set.
- Other wait results return to the read loop. For read errors `0x048F` or
  `0x0006`, the code sets the buffer's first byte to `0xFF`, dispatches that
  record, logs, and exits (`0x0040D234`–`0x0040D284`). Other non-pending read
  errors are logged and retried through the loop (`0x0040D234`–`0x0040D24E`).

The reader passes the 20-byte buffer to the dispatcher without an evident
comparison of the `ReadFile` byte-count output to 20. Thus the static path
shows a 20-byte request and a fixed 20-byte dispatch, but does not establish
that every successful completion supplied exactly 20 bytes.

### `0x0A` status/event route versus ordinary records

`FUN_0040D2E0` first tests record byte 1 (`0x0040D2E0`–`0x0040D2E4`).

- If byte 1 is `0x0A`, the record takes a status/event path. When byte 5 equals
  `0x02`, byte 6 is compared with zero and the result is written as a DWORD to
  object offset `+0x260` (`0x0040D301`–`0x0040D30F`). If the associated child
  window exists and is valid, the code posts message `0x07EB`; its `wParam` is
  assembled from bytes 5, 6, and 7 in little-endian order
  (`0x0040D315`–`0x0040D35B`). If there is no valid window, the status record is
  not queued.
- For any other byte-1 value, it calls `FUN_0043C2C0` with the full 20-byte
  record and queue object at device offset `+0x288` (`0x0040D35C`–
  `0x0040D365`).

This proves a distinct handling branch and that `0x0A` records do not enter the
ordinary response queue. It does not establish the meanings of status bytes,
the posted UI event, or whether `0x0A` is also used as a command identifier.

### Ordinary response queue and matching

`FUN_0043C2C0` appends records to the ring buffer, updates its write position
and queued-byte count, signals the event at queue offset `+0x18` when present,
and invokes a virtual callback (`0x0043C2C0`–`0x0043C384`). The reader
`FUN_0043C390` removes the requested number of bytes, handles ring wraparound,
and waits on that event when insufficient bytes are queued. It resets the event
before waiting and uses `WaitForSingleObject` with the caller-supplied timeout
(`0x0043C390`–`0x0043C4C7`).

`FUN_0040D370` requests 20-byte records from the queue at device offset
`+0x288`. The writer path sets its queue wait to `0xFA0` milliseconds
(`0x0040D979`–`0x0040D985`), so a single missing record can wait up to 4
seconds before the reader returns. It then examines the record in this order:

1. No data or a queue wait result `<= 0` returns `-2` (`0x0040D384`–
   `0x0040D3BE`), which the caller logs as `timeout`.
2. Byte 0 equal to `0xFF` returns `-4` (`0x0040D390`–`0x0040D3C8`). This is
   the reader's synthesized disconnect/invalid-handle marker as well as a
   reserved first-byte condition; the caller reports it as a generic read
   error.
3. Bit 7 set in byte 2 returns `-3` (`0x0040D395`–`0x0040D3D2`). The caller's
   error log labels this case `crc`, but the receive code only tests this bit;
   it does not calculate a checksum.
4. Otherwise byte 1 is compared with the requested command (`0x0040D39B`–
   `0x0040D3A2`). A match returns zero. A mismatch consumes another 20-byte
   record and tries again, up to 20 records; exhaustion returns `-1`
   (`0x0040D3A4`–`0x0040D3E1`).

The queue read is called again for each unmatched record with the same 4-second
timeout. In the static worst case, scanning 20 unmatched records could incur
up to twenty such waits; normal matching or the first timeout returns sooner.
No response checksum byte is checked, and no response checksum algorithm is
recovered.

### Send timeout and command retry behavior

`FUN_0040E0F0` sends exactly 20 bytes with overlapped `WriteFile`
(`0x0040E134`), waits up to 500 ms for completion (`0x0040E153`–
`0x0040E163`), cancels a timed-out write, waits for its overlapped completion,
logs `SendData_3632 TimeOut`, sleeps 10 ms, and retries
(`0x0040E16A`–`0x0040E1C0`). Starting from the initial send, the loop permits
up to three timed-out retries; a fourth timeout returns failure
(`0x0040E196`–`0x0040E1E4`). Non-pending write errors return failure without
this retry loop (`0x0040E142`–`0x0040E14D`, `0x0040E1FD`–`0x0040E20C`).

At the higher `FUN_0040D7E0` layer, a response timeout (`-2`) or byte-2 error
flag (`-3`) can trigger a resend if its retry input is nonzero. The retry
counter starts at zero; it resends while the previous count is at most four,
then stops on the next such failure (`0x0040D998`–`0x0040D9C3`,
`0x0040DA2E`–`0x0040DA57`). This is up to five command-level retries after the
initial send. Before retrying it decrements the packet index so the resent
frame uses the same packet index. Other response errors, including the
`0xFF` record and exhausted command-mismatch scan, terminate the command path
without that retry branch (`0x0040D98E`–`0x0040D998`,
`0x0040DA12`–`0x0040DA2C`).

The command-level resend is distinct from `FUN_0040E0F0`'s write-completion
retry: a single command attempt can therefore include up to four transport
write attempts, and the caller may then repeat the command after a response
timeout or error-bit record. Static code does not reveal device-side
deduplication or whether repeated frames have idempotent effects.

## Evidence classification

### Confirmed from the binary

- Fixed 20-byte read and write requests, up to 14 payload bytes, request frame
  fields, and additive request checksum locations are directly constructed in
  code.
- Reader block `0x0040D120` dispatches completed frames to `FUN_0040D2E0`.
- `FUN_0040D2E0` diverts byte-1 `0x0A` records into a status/window-message
  path and sends other 20-byte records to the queue at device offset `+0x288`.
- The ordinary response consumer filters by byte 1, special-cases byte 0
  `0xFF`, checks only bit 7 of byte 2, and does not recompute a response
  checksum.
- The send helper has a 500 ms overlapped-write wait and up to three retries;
  the command layer retries timeout/error-bit responses up to five times when
  its retry input is enabled.

### Inferred from static agreement

- The receive dispatcher and the command response consumer share the ordinary
  queue: the producer enqueues at `device + 0x288`, and the consumer reads from
  the same offset in a matching 20-byte record size. This is a strong static
  producer/consumer association, not runtime proof that a particular thread
  instance feeds a particular command.
- The log label `crc` probably describes an error condition represented by
  byte 2 bit 7. The code proves only the bit test and log text, not that a CRC
  calculation exists on the receive path.

### Unresolved

- The semantic names and wire meanings of status bytes 5–7, message `0x07EB`,
  byte 0 marker `0x13`, byte 2, and byte 4 option bits are not established.
- Whether ordinary responses have a checksum, where it resides, or who checks
  it is unresolved. No receive-side checksum computation appears in the traced
  path.
- The reader has no recovered Ghidra function boundary at `0x0040D120`; its
  control flow is documented from the decoded instruction region only.
- The two wait handles' exact ownership and lifecycle relationship, short-read
  behavior, queue capacity under load, protocol-version differences, and
  physical model coverage remain open.
- No runtime trace was collected. Nothing here establishes that any keyboard
  emitted these records or confirms the behavior on a specific 3632 revision.

For the broader 3632 serializer and apply paths, see
[`rk-setting-serializer-audit.md`](rk-setting-serializer-audit.md).
