# V4.6 G5 password-query attempted read/copy path

## Evidence boundary

This static note follows the V4.6 `CDevG5KB` vtable entry at `+0x34` in the
manifest-pinned 2,418,176-byte `app/DeviceDriver.exe` (SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`). The
binary was disassembled from disk; the driver was not launched and no keyboard
interface or report was opened or used.

## Observed route

The verified G5 vtable map places `0x00410D10` at entry `0x005D3D40`, offset
`+0x34`. The function reads a byte from object offset `+0x2DC` and the device
handle from `+0x04`, then processes the caller-requested length in chunks
capped at `0x200` bytes. The meaning of the byte at `+0x2DC` is not identified.

For each chunk, the function zeroes a `0x208`-byte report, writes command
`0x82` at report byte 1, fills request chunk metadata, and calls
`HidD_SetFeature` with `0x208` bytes using the handle at object `+0x04`. The
routine retries this set stage up to three times and calls a short delay
helper between attempts. It then calls `HidD_GetFeature` through thunk
`0x00590A0E` at `0x00410E7E`, but the first argument is a zero-extended byte
from object `+0x2DC`, not the `+0x04` handle passed to `HidD_SetFeature`.
Only if that call reports success and response byte 1 is `0x82` does the code
copy up to `0x200` bytes from response offset 8 into the caller buffer. A
diagnostic at `0x005D2E84` is `GetPassword failed`.

## Interpretation and limits

The vtable placement, command bytes, request chunking, and conditional copy
instructions are directly visible in this exact binary. The diagnostic
supports calling this a password-query method, but the password representation
and purpose of returned bytes are not decoded. Because the `HidD_GetFeature`
first argument is the byte field at `+0x2DC`, not the `+0x04` handle used by
the preceding write, successful device readback is not established. This is
a suspicious handle-argument mismatch and may prevent a valid feature read.
A report write is part of the attempted query; this is not a passive HID read.

The G5-specific caller, model/revision guard, user-interface route, downstream
consumer, and any file/configuration persistence are unresolved. No file sink
is present in the method body. These instructions do not establish firmware
access, firmware bytes, or a keyboard-compatible operation. The separate
`+0x70` `GetRealData` method is a distinct command-`0x88` attempted
read/copy path with the same `+0x2DC` versus `+0x04` handle mismatch; its
caller and returned-data meaning are also unresolved. See the
[G5 vtable map](rk-v4.6-cdevg5-vtable-map.csv) and
[firmware readback audit](rk-firmware-readback-audit.md).
