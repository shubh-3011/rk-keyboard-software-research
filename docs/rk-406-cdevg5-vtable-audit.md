# 4.06 `CDevG5KB` vtable audit

## Scope and evidence boundary

This audit maps the 4.06 `CDevG5KB` vtable and follows its command-`0x88`
GetRealData path. The exact x86 PE examined is
`C:\Users\shubh\Downloads\sshorcale\_rk_analysis\inputs\DeviceDriver.exe`,
SHA-256
`C03F88BC4E2D78AA4392D7445B0FD62182DC824F97F5D5DB40BD009E547A9AB6`.
Addresses below are virtual addresses in that image. The binary itself is not
included in this repository.

The findings are from static PE bytes, disassembly, and saved Ghidra reports.
Neither the RK application nor an updater was launched; no HID/device interface
was opened; no report was captured or sent; and no keyboard state was changed.
“Proven” means that the bytes or static control/data flow establish the stated
fact in this exact PE. It does not establish runtime reachability, device
acceptance, or the physical effect of a command.

The independent evidence inputs are the constructor and vtable bytes in the
PE, `objdump` disassembly around each mapped target, and the saved static
exports `device-string-xrefs.txt`, `device-targeted-functions.txt`, and
`DeviceDriver-hid-callers.txt` under `_rk_analysis/reports`. No report in this
audit is based on a live device trace.

## Class and table boundary

The constructor at `0x0040ECB0` writes the vtable address point
`0x005CBA2C` at `0x0040ECE3`; the instruction bytes are
`C7 06 2C BA 5C 00`. The COL pointer immediately preceding the address point
is stored at `0x005CBA28` as `10 3C 5E 00`, or `0x005E3C10`. The RTTI-backed
class is `CDevG5KB` derived from `CHidDev` in the saved analysis.

The address point contains 27 consecutive little-endian pointers, occupying
`0x005CBA2C` through `0x005CBA97` (entry addresses `0x005CBA2C` through
`0x005CBA94`). The bytes at `0x005CBA98` begin UTF-16 `CDev`, an independent
boundary check. The complete slot ledger, including the raw pointer bytes and
evidence scope for every row, is in
[`rk-406-cdevg5-vtable-map.csv`](rk-406-cdevg5-vtable-map.csv).

Do not transfer these slot indices to the V4.6 build. The separate
[V4.6 G5 audit](rk-v4.6-cdevg5-settings-and-vtable-audit.md) uses a different
PE, vtable address point, table length, and method layout.

## Command `0x88`: GetRealData request and response

Slot `+0x68` at `0x005CBA94` points to `0x00410700`. Its entry bytes are
`83 B9 38 02 00 00 00 74 05 33 C0 C2 08 00`: the method returns zero while
the busy field at `this+0x238` is set. Otherwise it calls
`0x0040FF60` at `0x00410718` and returns with `ret 8`.

The helper's static path is:

1. It checks the primary handle at `this+0x04` and a positive caller length.
2. It builds a `0x208`-byte feature report for each chunk, with at most
   `0x200` (512) data bytes per chunk. It inserts the object's report ID from
   `this+0x2D0` and sets command byte `0x88` at `0x0041002F`.
3. It calls `HidD_SetFeature` at `0x00410062`, waits, then calls
   `HidD_GetFeature` at `0x004100C1`.
4. It checks that the returned command byte is still `0x88` at
   `0x004100CE`, then copies up to 512 response bytes to the caller's buffer
   at `0x004100E4`. It repeats until the requested length is copied or an
   error path logs `GetRealData failed`.

Therefore this is a **request write followed by a response read**, not a
passive read operation. The bytes do not establish what the request selects,
what the returned data represents, or that the operation reads firmware.
The helper copies data into caller memory and contains no file-open or file-
write sink. The caller's later use of the returned bytes remains unresolved.

### Candidate `+0x68` virtual callers

Static disassembly shows six `+0x68` vtable dispatches in the function body
beginning at `0x00401BD0`:

| Call instruction | Nearby buffer-size setup | Status |
| --- | --- | --- |
| `0x00401E92` | `0x8134` | Receiver vptr/type unresolved; candidate only. |
| `0x00401F1E` | `0x8134` | Receiver vptr/type unresolved; candidate only. |
| `0x00401FB5` | `0x8134` | Receiver vptr/type unresolved; candidate only. |
| `0x00402059` | `0x8134` | Receiver vptr/type unresolved; candidate only. |
| `0x004020FD` | `0x8134` | Receiver vptr/type unresolved; candidate only. |
| `0x0040217A` | `0x8135` | Receiver vptr/type unresolved; candidate only. |

These instructions prove dispatch through a method offset of `+0x68` on their
respective objects. They do **not** prove that those objects use the
`CDevG5KB` vtable or reach `0x00410700`; the objects' vptrs have not been
resolved. There are other generic `+0x68` virtual calls elsewhere in the PE,
so this six-call list is scoped to the one recovered function and its
`0x8134`/`0x8135` buffer setup. The direct helper call found in the recovered
G5 wrapper is `0x00410718 -> 0x0040FF60`; a direct call to wrapper address
`0x00410700` was not found.

The six candidate sites are not connected by recovered data flow to a file
sink. The saved native API xref inventory lists `DeviceDriver.exe`
`WriteFile` callsites at other addresses, with none at these six sites, and
the command-`0x88` helper itself has no file API call. This does not rule out
an indirect or later consumer; tracing object identity, buffer ownership, and
all downstream sinks is still open.

## Remaining gaps and related evidence

- Resolve the six candidate receiver types and determine whether any dispatch
  reaches the G5 `+0x68` target.
- Trace any confirmed GetRealData caller's output buffer through its complete
  downstream data flow, including possible file or configuration sinks.
- Identify the command-`0x88` selector/request fields and response schema.
- Recover the action taxonomy used by slot `+0x60` and the event-record schema
  used by slot `+0x64`; those roles are inferred from their control flow.
- Establish model/firmware availability and UI origin without treating static
  profile routing as hardware validation.

Related 4.06 evidence is in the [settings serializer audit](rk-setting-serializer-audit.md),
[screen/GIF audit](rk-screen-gif-payload-audit.md),
[reset and system-parameter audit](rk-reset-and-system-parameter-path-audit.md),
[settings worker audit](rk-settings-apply-worker-audit.md),
[UI event-worker audit](rk-ui-event-worker-path-audit.md), and the
[main reverse-engineering report](reverse-engineering.md). That report has an
older Ghidra function label `FUN_00410045` for the overlapping decode around
the GetRealData helper; the instruction-aligned helper entry established here
is `0x0040FF60`. The updater firmware-readback audit concerns separate updater
paths and does not turn command `0x88` into a demonstrated firmware backup.

The method map does not claim complete reverse engineering of the whole RK
application, every system call, or every model-specific protocol. Static
method presence is not proof a branch ran, and no physical keyboard behavior
was tested.
