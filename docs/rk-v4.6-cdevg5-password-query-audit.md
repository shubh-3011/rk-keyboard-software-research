# V4.6 G5 password-query read path

## Evidence boundary

This static note follows the V4.6 `CDevG5KB` vtable entry at `+0x34` in the
manifest-pinned 2,418,176-byte `app/DeviceDriver.exe` (SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`). The
binary was disassembled from disk; the driver was not launched and no keyboard
interface or report was opened or used.

## Observed route

The verified G5 vtable map places `0x00410D10` at entry `0x005D3D40`, offset
`+0x34`. The function reads its report ID from object offset `+0x2DC` and the
device handle from `+0x04`, then processes the caller-requested length in
chunks capped at `0x200` bytes.

For each chunk, the function zeroes a `0x208`-byte report, writes command
`0x82` at report byte 1, fills the request's chunk metadata, and calls
`HidD_SetFeature` with `0x208` bytes. On a successful write, it calls
`HidD_GetFeature` with the same report length, checks that response byte 1 is
`0x82`, and copies up to `0x200` bytes from response offset 8 into the caller's
buffer. The routine retries the set operation up to three times and calls a
short delay helper between attempts. A diagnostic at `0x005D2E84` is
`GetPassword failed`.

## Interpretation and limits

The vtable placement, request/response command, chunk cap, and copy into caller
memory are directly visible in this exact binary. The diagnostic supports
calling this a password-query method, but the password representation and
purpose of the returned bytes are not decoded. A report write is part of the
query protocol; this routine is not a passive HID read.

The G5-specific caller, model/revision guard, user-interface route, downstream
consumer, and any file/configuration persistence are unresolved. No file sink
is present in the method body. These instructions do not establish firmware
access, firmware bytes, or a keyboard-compatible operation. The separate
`+0x70` `GetRealData` method is a distinct command-`0x88` request/response path;
its caller and returned-data meaning are also unresolved. See the
[G5 vtable map](rk-v4.6-cdevg5-vtable-map.csv) and
[firmware readback audit](rk-firmware-readback-audit.md).
