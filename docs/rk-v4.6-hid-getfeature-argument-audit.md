# RK V4.6 HID GetFeature argument audit

## Scope and evidence boundary

This audit checks all six decoded `HidD_GetFeature` callsites in the
4.6-labeled `DeviceDriver.exe`, SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`.
It traces the handle argument at each call against its nearby
`HidD_SetFeature` call and checks the report-byte construction. The executable
was disassembled from disk only. It was not run; no HID interface was opened
and no report or command was sent.

## Results

| `GetFeature` call | Paired `SetFeature` call | Handle argument evidence | Nearby operation |
| --- | --- | --- | --- |
| `0x0040F975` | `0x0040F91D` | Both pass `EDI`, the `CreateFileW` result from the profile/Psd matching path. | Report field `0x09`, request byte `0x82`; conditional response handling uses the six-byte profile/Psd path. |
| `0x004101C1` | `0x0041014F` | Generic helper `0x0040FFD0` receives a handle argument and saves it at local `S+0`. At `0x004101A4` the delay argument is still pushed, so `[esp+0x14]` resolves to `S+0`; the same local is used by SetFeature. | Generic command/report helper; the response branch is operation `2`. Caller `0x0041030B` passes `[this+4]` as the first explicit argument, but runtime reachability is not established. |
| `0x0041054E` | `0x004104EF` | Helper `0x004103C0` saves `[this+4]` at local `S+0` and byte `[this+0x2DC]` at `S+4`. With the delay argument pending, `[esp+0x14]` resolves to `S+0`, the handle; `[esp+0x18]` resolves to `S+4`, the separate byte. | Command `0x84`; the `+0x2DC` byte is copied into the report. |
| `0x0041078C` | `0x00410731` | `EDI` is loaded from `[this+4]` at `0x00410667` and passed to both calls. | Power-query command `0x87`; response handling copies two bytes to separate outputs. The byte from `+0x2DC` is report state, not the handle. |
| `0x004109F1` | `0x00410992` | Helper `0x00410890` saves `[this+4]` at local `S+0` and byte `[this+0x2DC]` at `S+4`. With the delay argument pending at `0x004109D2`, `[esp+0x14]` resolves to `S+0`; `[esp+0x18]` resolves to `S+4`. | Command `0x88`; conditional response copy starts at report offset 8 and is chunked up to `0x200` bytes. |
| `0x00410E7E` | `0x00410E1F` | Helper `0x00410D10` uses the same `S+0` handle and `S+4` byte layout. With the delay argument pending at `0x00410E5F`, `[esp+0x14]` resolves to `S+0`; `[esp+0x18]` resolves to `S+4`. | Command `0x82`; conditional response copy is chunked up to `0x200` bytes. The method logs `GetPassword failed` on its failure path. |

The apparent `+0x2DC`-as-handle mismatch in the two chunked G5 methods came
from reading stack-relative offsets after the delay argument had already been
pushed. Accounting for that pending four-byte argument resolves the
`GetFeature` handle to the previously saved `[this+4]` handle. The `+0x2DC`
byte is a separate report-field value.

## Limits

The binary contains conditional code that reads a feature report using the
same handle as the paired feature write and, in selected paths, copies
matching response bytes into process memory. This corrects the earlier
argument-mismatch interpretation. It does not prove that a particular call
runs, that Windows returns a report for the physical S98, or that the returned
data is firmware. Each of the six paths includes a feature write; none of
these observations is a passive capture. The `+0x70` caller, requested
firmware range, full-image assembly, and file export remain unresolved.

The analogous installed 4.06 G5 `+0x68` GetRealData path uses its saved
`[this+4]` handle at `0x004100C1`; the separate byte from `+0x2D0` is report
state. This is static argument evidence only and does not establish runtime
readback.
