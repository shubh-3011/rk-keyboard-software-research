# Installed 4.06: offline 3632 framing implementation

`rebuild/windows/ProtocolFrames.cs` contains independently authored pure C#
request framing and recorded-response classification. It has no transport,
device handle, firmware update or command execution interface. It is compiled
into the app but not wired to device I/O.

## Evidence boundary

This implements the framing described in the
[3632 response audit](rk-3632-response-semantics-audit.md), pinned to installed
`DeviceDriver.exe` SHA-256
`c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6`.
The request builder `0x0040D7E0` was rechecked through instruction-aligned
Capstone disassembly at its entry. Static framing compatibility is not
physical-device compatibility, and a command match is not firmware acceptance.

## Request construction

- Require 1–512 payload bytes, as checked at `0x0040D80D`–`0x0040D816`.
- Split into chunks of at most 14 bytes; maximum 37 frames.
- Each frame is 20 bytes: marker `0x13`, command byte, total frame count,
  zero-based frame index, packed option/length byte, 14-byte payload area,
  additive checksum.
- Upper nibble of byte 4 is the caller's explicit option; lower nibble is
  this frame's payload length. The helper rejects options outside 0–15
  instead of silently truncating them.
- The unused payload area remains zero. Byte 19 is the low byte of the sum
  of bytes 0–18. This checksum is not a security mechanism.
- High-bit commands and command 6 bypass the native ordinary-response wait
  (`0x0040D970`–`0x0040D977`). No waiting or retries are implemented here.

## Recorded-response classification

The helper requires exactly 20 recorded bytes and preserves all other bytes
in the caller's original buffer. Command `0x0A` represents a status event
diverted by the dispatcher before the ordinary queue. Status data combines
bytes 5–7 into a little-endian 24-bit message value.

For ordinary records, it checks byte 0 equal to `0xFF`, then byte 2's high
error bit, then command equality, matching the bounded consumer audit. It
does **not** invent response checksum, marker, index or length checks that
were not observed in that consumer. Callers must not treat this limited
classification as proof that a packet is authentic, complete or safe to act on.

## Verification

`rebuild/windows/tests/ProtocolFramesTests.cs` includes hand-computed
single/split request fixtures, every payload size from 1 through 512,
reassembly, headers, modulo checksums, zero padding, invalid bounds, all 256
response-wait predicates and response precedence. **30,159 checks passed.**

```powershell
cd rebuild/windows
./test.ps1
```

These are synthetic tests, not captured hardware fixtures. No device was
opened or changed during implementation or verification.
