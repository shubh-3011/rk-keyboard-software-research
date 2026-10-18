# V4.6 G5 `+0x70` caller attribution audit

## Scope and method

This static follow-up checks potential callers of `CDevG5KB` vtable slot
`+0x70` in the hash-pinned V4.6 `DeviceDriver.exe`, SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`.
The target slot is wrapper `0x00411030`, which reaches command-`0x88` helper
`0x00410890` when the busy flag permits. The helper's output argument is a
byte buffer and its requested length is processed in chunks up to `0x200`.
The executable was disassembled from disk only; no driver or device API was
run.

The existing scan identified 77 decoded virtual calls using slot offset
`+0x70`. Candidate receivers were checked against surrounding virtual calls,
runtime-class strings, and the shape and later use of their arguments.

## Findings

No caller in the checked 77-site set could be attributed to `CDevG5KB`.
Several signature-shaped sites are excluded by same-receiver dispatches to
slots beyond the 29-entry G5 table:

| Candidate site | Static evidence that the receiver is another interface |
| --- | --- |
| `0x004CD5F5` | The same receiver is dispatched at `+0x228` at `0x004CD5C5`. |
| `0x004EC566` | The receiver is a factory-created UI object; the same object is dispatched at `+0xB8` at `0x004EC603`. |
| `0x004F0CF9` | The same receiver is called at `+0x74` at `0x004F0D08`. |
| `0x00527CDB` | Passes `(&local, 1)`; the same receiver is called at `+0x198` and `+0x18C` at `0x00527CE2` and `0x00527D00`. Related `0x00527F08` is followed by same-receiver slot `+0x1C0`. |
| `0x005299BA` / `0x005299CA` | The same receiver is called at `+0x198` at `0x005299DB`; `0x00529A7E` is in this larger-interface routine. |
| `0x0052BBE5` | Passes `(&POINT, 1)`; the same receiver later calls `+0x1A8` at `0x0052BCEB`. |
| `0x0052B9D2` | Passes a point-sized output with a small flag; the returned coordinates feed later layout arithmetic, and nearby member path `0x0052BA55` dispatches at `+0x1D0`. |
| `0x00554DF9` | Passes `(&POINT, 1)`, then uses the same receiver at `+0xD8` at `0x00554E15`. |

Other near-matches are inconsistent with the G5 method's buffer-and-byte-
length contract: point-query sites at `0x0052970A`, `0x0052B9D2`,
`0x0052BBE5`, and `0x00554DF9` pass an eight-byte point output with flags
`0`, `1`, or `-1`, then compare or consume both coordinates. `0x004899D9`
passes a hook callback's validated `nCode`; `0x004B294A` passes `(arg, &arg)`.
`0x00527111` resolves a `CMFC RibbonButton` using runtime-class record
`0x005BC940` and string `0x005BC92C`. Additional same-receiver calls at
`+0x228`, `+0xB8`, `+0x74`, `+0x198`, `+0x1A8`, `+0x1C0`, and `+0xD8` rule
out these receivers as objects with the verified 29-entry G5 vtable.
Candidates `0x004940BA` and `0x004954E6` use receivers later dispatched at
`+0x1A0` and `+0x200`; candidates `0x004E1169` and `0x004E11B3` use a
receiver dispatched at `+0x1B0`. These are larger interfaces as well.

The vptr installation sites for `CDevG5KB` are `0x0040F4C3` and
`0x0040F5E9`; direct constructor callsites include `0x0040EEEF`,
`0x004166A0`, `0x0041692D`, and `0x00448CD0`. The active-object global at
`0x00647320` has no direct disassembly references after `0x004748FE` in the
scanned image. These references do not rule out indirect aliases or runtime
dispatch.

## Conclusion and limits

The 77-site scan and the reviewed signature-shaped candidates provide no
attributable caller for the G5 `+0x70` wrapper. This is not proof against an
untraced vtable alias, computed target, different dispatch encoding, or
runtime-generated call. The caller, requested data range, meaning of
command `0x88`, and any firmware interpretation remain unresolved. The
separate [GetFeature argument audit](rk-v4.6-hid-getfeature-argument-audit.md)
shows that the conditional `HidD_GetFeature` path uses the paired
`HidD_SetFeature` handle; no hardware response was observed, and this caller
scan does not identify a full-image or file export.
