# 4.06 wireless profile `Psd` comparison dataflow

## Scope and evidence boundary

This report follows the six-byte comparison used by the conditional wireless/
companion-device path in the installed RK Keyboard Software 4.06
`DeviceDriver.exe` (SHA-256
`c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6`,
2,326,528 bytes). The analysis is static. It did not run the RK application,
issue a HID request, update firmware, or change keyboard state. Function names
are analysis labels, not RK symbols.

## Profile-table layout

The candidate table begins at `0x006102A0`, occupies `0x102C` bytes, and has
228 rows of `0x12` bytes each. `FUN_00447210` clears the table at
`0x00447236`–`0x0044723F`, then fills rows from the per-profile `Dev\\%04X\\KB.ini`
files.

| Row offset | Field | Static source/use |
| ---: | --- | --- |
| `+0x00` | VID | Loaded profile value |
| `+0x02` | PID | Loaded profile code/value |
| `+0x04..+0x09` | Six-byte `Psd` | Parsed from `[OPT] Psd`; compared by `FUN_00415900` |
| `+0x0A` | `Fw` | Loaded profile value; comparison requires it to be nonzero |
| `+0x0B` | `DevTy` | Loaded profile value |
| `+0x0C` | `ShowScreen` | Loaded profile value |
| `+0x0E` | `VID_Wireless` | Loaded profile value |
| `+0x10` | `PID_Wireless` | Loaded profile value |

## Profile-side `Psd` load

For each row, `FUN_00447210` sets `EDI` to row offset `+0x04`
(`0x00447473`) and calls `FUN_00447110` with the profile PID
(`0x00447477`). The helper:

1. Reads key `Psd` (`0x005D4FC8`) from section `OPT` (`0x005C7FC0`) in that
   profile's `KB.ini` using `GetPrivateProfileStringW`, IAT
   `0x0059E3D8`, callsite `0x0044716F`.
2. Caps the requested parse at six values (`0x004471A0`) and calls
   `FUN_0044DC70` with radix `0x10` (`0x004471A8`).
3. Relies on the parser's inherited `EDI` output pointer: the parser stores
   each parsed byte at `[EDI + ESI]` (`0x0044DD06`). The bytes therefore land
   at row offsets `+0x04..+0x09`.
4. Returns the parsed count; the caller checks for six (`0x0044747F`).

This closes the static source of the compared table bytes. A direct-call scan
found `FUN_00447210` as the sole caller of `FUN_00447110`. A bounded raw
`.text` scan for addresses in the table range found 16 four-byte immediate
hits: 15 table references and one false positive at the end boundary, where a
separate buffer ends at `0x006102A0`. No pointer values into the table range
were found in `.data`, `.rdata`, `.rsrc`, or `.reloc`. This bounds the search;
it is not a universal proof that no computed alias exists.

## Response-side query and comparison

`FUN_00415D20` initializes a six-byte local response buffer and calls
`FUN_0040E210` with arguments `(5, 6, buffer, 6, 2)` at
`0x00415E4E`–`0x00415E71`. This is an active transaction: the helper builds a
20-byte request packet with byte `0x13` at its leading command/header position,
submits the packet through `WriteFile` (IAT `0x0059E468`) in
`FUN_0040E0F0`, then receives a 20-byte response through `ReadFile` (IAT
`0x0059E46C`) in `FUN_0040DF80`, including overlapped-I/O completion handling.
It is not a `HidD_GetFeature`/`HidD_SetFeature` call in the traced helper path.
The call is gated on success at `0x00415ECC`; the same six-byte buffer is then
passed to `FUN_00415900` at `0x00415EE5`. The adjacent log string at
`0x005CC3B4` is `GetPSD = %d`.

`FUN_00415900` starts its row scan at `0x006102A4` (`0x00415966`). For each
row it checks VID/PID and requires nonzero `Fw`, then compares the six
response bytes with row offsets `+0x04..+0x09` (`0x00415995`–`0x004159C9`).
The row pointer advances by `0x12` at `0x00415A4C`; a matching row reaches a
conditional `CDev3632` construction path.

The static path therefore compares a response returned by an active 20-byte
write/read transaction against the profile's `[OPT] Psd` bytes. Static
analysis does not define the request's hardware effect or what `Psd` means,
whether the six bytes are a serial, pairing token, or other signature, or
whether a particular physical receiver returns one of the configured values.

## Wireless profile candidates and collisions

The installed 4.06 catalog has seven nonempty wireless VID/PID rows. Their
source `Psd` tokens are shown below as six hexadecimal bytes, preserving the
profile values:

| Profile | Name | Wireless VID:PID | `Psd` bytes |
| --- | --- | --- | --- |
| `020F` | RK A70 Keyboard | `258A:0150` | `06 00 00 00 00 56` |
| `0211` | RK M100 Keyboard | `258A:01BB` | `06 00 00 00 00 60` |
| `0228` | RK M70 DE Keyboard | `3554:FA09` | `03 00 00 00 03 53` |
| `0227` | RK M70 FR Keyboard | `3554:FA09` | `03 00 00 00 03 52` |
| `020C` | R98Pro Keyboard | `258A:01BB` | `0A 00 00 00 00 22` |
| `0210` | R98Pro Keyboard | `258A:01BB` | `0A 00 00 00 00 20` |
| `0207` | X87 Keyboard | `258A:0233` | `0A 00 00 00 00 21` |

Across the 63 catalog profiles with `Psd`, there are 58 distinct values.
Three values are shared across variants: `0A 00 00 00 00 06` (two F75
profiles), `03 00 00 00 00 6E` (two R65 profiles), and `0A 00 00 00 00 22`
(four R98Pro profiles). A six-byte match is consequently not a unique model
identifier for the entire catalog. The eight S98 catalog `Psd` values are
distinct within this dataset, but that does not establish a physical S98
match.

## Separate secondary-screen comparison

Do not conflate the wireless `FUN_00415D20` comparison above with the
secondary-screen path. For profile `01B8`, when `ShowScreen==2`,
`FUN_0040F350` zeroes a six-byte buffer and calls the active keyboard object's
G5 vtable slot `+0x34`; the 4.06 G5 slot resolves to `FUN_004103E0`. It passes
that returned keyboard response to `FUN_0040F030`, which scans candidate
screen HID descriptors, opens a candidate, sends report ID `9` / command
`0x82`, reads six bytes, and compares them with the prior keyboard response.
The code's “PSD match” log text does not show this screen comparison using
`KB.ini` `Psd`.

## What remains unverified

- Whether `FUN_0040E210` succeeds on a connected keyboard and which interface
  it uses at runtime.
- Whether the `258A:0150` device observed on this PC matches profile `020F`
  or any other candidate row; its shared receiver VID/PID is not a model ID.
- Whether a matching row reaches and completes `CDev3632` construction in a
  live session.
- The meaning and provenance outside this software of the `Psd` bytes.
- Whether the separate secondary-screen HID path succeeds on any connected
  display.

The direct read-only feature probes documented in
[`rk-live-hid-selector-crosscheck-2026-10-19.md`](rk-live-hid-selector-crosscheck-2026-10-19.md)
used report IDs `05` and `0A`; their responses are not evidence of the
`FUN_0040E210` call or of a wireless-profile match. The wireless transaction
above was not executed because it actively submits a packet. The separate
screen path contains its own report transaction and was not executed.
