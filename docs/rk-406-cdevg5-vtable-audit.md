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

### `+0x68` dispatches in the nearby UI function

Static disassembly shows six `+0x68` vtable dispatches in the function body
beginning at `0x00401BD0`. These resolve to a local GDI text adapter, not to
the G5 class:

| Call instruction | Text pointer | DrawTextW flags | Resolution |
| --- | --- | --- |
| `0x00401E92` | `[0x0062B760]` | `0x8134` | vtable `0x0059F314`, slot `+0x68` -> `0x0047111A` |
| `0x00401F1E` | `[0x0062B75C]` | `0x8134` | same `USER32!DrawTextW` adapter |
| `0x00401FB5` | `[0x0062B7A8]` | `0x8134` | same `USER32!DrawTextW` adapter |
| `0x00402059` | `[0x0062B62C]` | `0x8134` | same `USER32!DrawTextW` adapter |
| `0x004020FD` | `[0x0062B7B8]` | `0x8134` | same `USER32!DrawTextW` adapter |
| `0x0040217A` | `[0x0062B7BC]` | `0x8135` | same `USER32!DrawTextW` adapter |

At `0x00401C37`, the caller constructs a local object at `[esp+0x38]` through
constructor `0x0047105C`. That constructor writes vtable pointer `0x0059F314`
and zeroes the three following DWORD fields. At each listed call, after four
arguments have been pushed, the caller loads the local object's vptr from
`[esp+0x48]`, reads slot `[eax+0x68]`, sets `ecx` to that object, and calls the
slot. Vtable entry `0x0059F37C` contains target `0x0047111A`.

Wrapper `0x0047111A` forwards the object's `this+4` field and four caller
arguments through IAT VA `0x0059E6B8`; the PE import table maps that thunk to
`USER32.dll!DrawTextW`. It returns with `ret 0x10`, matching cleanup for the
four stack arguments. The arguments are the global text pointer, the DWORD at
text pointer minus `0xC` used as the character count, a local rectangle
pointer, and format flags. Treating that preceding DWORD as a string length
is strongly inferred from its use as `cch`; the actual text and buffer
initializers remain unresolved.

The flags resolve to standard Windows text-layout values: `0x8134` is
`DT_VCENTER | DT_WORDBREAK | DT_SINGLELINE | DT_NOCLIP | DT_END_ELLIPSIS`,
and `0x8135` adds `DT_CENTER`. Their 62 and 13 occurrences in the disassembly
do not identify a device selector or buffer size. The six sites are excluded
as direct calls to the G5 `+0x68` method: they use a different vtable receiver
and the four-argument `DrawTextW` ABI, while the concrete G5 wrapper at
`0x00410700` returns with `ret 8` and calls helper `0x0040FF60` at
`0x00410718`. A caller of the G5 method remains unresolved.

The row-level evidence is in the
[`six-call resolution ledger`](rk-406-vtable-68-resolution.csv).
The hash-pinned static checker is
[`audit_rk406_g5_vcall_resolution.py`](../scripts/audit_rk406_g5_vcall_resolution.py);
run it against the same `DeviceDriver.exe` to verify the constructor, vtable
slot, import mapping, wrapper cleanup, call shapes, and literal counts. It
invokes `objdump` only and never executes the PE.

The resolved UI text-drawing sites are not G5 data-read callers. The command-
`0x88` helper itself still has no file API call, and its actual caller and any
downstream consumer remain unresolved.

## Remaining gaps and related evidence

- Find a real caller of the concrete G5 `+0x68` method at `0x00410700`.
- Trace that caller's command-`0x88` output buffer through its complete
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
