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

An independent RTTI read identifies the type descriptor at `0x006037A8` by
its decorated name `.?AVCDevG5KB@@`. Two constructor paths, `0x0040ECB0` and
`0x0040EDE0`, install the same vtable address point; the first initializes
object fields through `this+0x2DC`. Direct callers of the first constructor
are `0x0040E754`, `0x00415830`, `0x00415ABE`, and `0x0044665E`. Those
constructor callers establish object creation sites, not a call to the
GetRealData slot.

The address point contains 27 consecutive little-endian pointers, occupying
`0x005CBA2C` through `0x005CBA97` (entry addresses `0x005CBA2C` through
`0x005CBA94`). The bytes at `0x005CBA98` begin UTF-16 `CDev`, an independent
boundary check. The complete slot ledger, including the raw pointer bytes and
evidence scope for every row, is in
[`rk-406-cdevg5-vtable-map.csv`](rk-406-cdevg5-vtable-map.csv).

The version boundary matters for the read-copy method: installed 4.06 has
`GetRealData` at `CDevG5KB +0x68` (`0x00410700`), while the separate V4.6
build has it at `+0x70` (`0x00411030`). The V4.6 audit uses a different PE,
vtable address point, table length, and method layout; do not transfer its
slot indices or caller scan to this installed 4.06 image.

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

### Static caller-attribution follow-up

A hash-pinned scan of decoded application code found no direct call to
`0x00410700`; the only direct call to helper `0x0040FF60` is the wrapper at
`0x00410718`. The six nearby UI sites above have four pushed arguments and no
statically established `CDevG5KB` receiver. Another `+0x68` dispatch at
`0x004051AC` uses a different vtable. Code at `0x0043BA84` accesses a
`CDevG5KB` field but dispatches slot `+0x28`, not `+0x68`. No scanned virtual
call could be tied statically to the `CDevG5KB` vtable at `0x005CBA2C`.

This leaves the command-`0x88` caller unresolved. It does not prove the method
is never invoked: a runtime-polymorphic call through an escaped device pointer
remains possible. The helper's returned bytes, selector fields, downstream
consumer, and any firmware-file relationship are still unknown.

### Expanded decoded-callsite sweep

I repeated the caller scan against the installed
`C:\Program Files (x86)\RK Keyboard Software\DeviceDriver.exe` on disk. Its
SHA-256 is
`C03F88BC4E2D78AA4392D7445B0FD62182DC824F97F5D5DB40BD009E547A9AB6`, matching
the image hash recorded above. This was a read-only GNU `objdump -d -Mintel`
scan; the executable was not run.

The vtable bytes at `0x005CBA2C` contain 27 entries, ending at slot `+0x68`.
The next slot, `+0x70`, is outside this table. In the decoded `.text`, there
are no direct calls to wrapper `0x00410700`; helper `0x0040FF60` has one
direct call, from `0x00410718`. A raw-pointer occurrence scan finds the
wrapper address at its vtable entry `0x005CBA94`; the two code references to
vtable address `0x005CBA2C` are the constructor stores at `0x0040ECE3` and
`0x0040EE09`.

The broad operand sweep found 60 decoded `call [register+0x68]` instructions
and two `jmp [register+0x68]` tail dispatches. A separate loose pattern pass
found 83 cases where code loads `[register+0x68]` into a register and calls
that register within the next three decoded instructions. These counts are
candidate dispatch shapes, not a count of proven `CDevG5KB` calls: `+0x68` is
common across unrelated interfaces, and the register-mediated pattern also
admits ordinary data/function-pointer loads. The six calls at `0x00401E92` through
`0x0040217A` and the adapter call at `0x004051AC` are separately resolved
above; none uses the G5 vtable.

Four two-argument sites looked superficially compatible with a buffer and
length. Each passes a pointer to a 16-byte rectangle and zero as the second
argument:

| Call instruction | Static argument and subsequent-use evidence |
| --- | --- |
| `0x00475808` | Passes `&RECT` at `[ebp-0x20]` and `edi=0`; the return feeds the geometry helper at `0x00473357`. |
| `0x0048CD57` | Passes `&RECT` at `[ebp-0x14]` and zero; the routine continues with window/rectangle geometry calculations. |
| `0x0048EA3D` | Passes `&RECT` at `[ebp-0x10]` and zero to an object stored at parent offset `+0x418`; the rectangle is derived from parent/child layout offsets. |
| `0x0049292A` | Loads the receiver from `[ebx+0xB0]`, passes `&[ebp-0x60]` and `edi=0`; after the call, the four rectangle fields feed geometry calculations and a positioning helper. |

At these sites the second stack argument is zero, matching a zero requested
length if interpreted using the G5 wrapper ABI. The G5 helper rejects
non-positive lengths before constructing its command-`0x88` request, so these
calls cannot establish a byte read even under that hypothetical dispatch.
For `0x0049292A`, the function zeroes `EDI` at `0x004927FE`; the receiver is the
object pointer stored at `[ebx+0xB0]`. The 16-byte local at `[ebp-0x60]` is
copied from four existing coordinates at `[ebp-0x1C..-0x10]` before the
virtual call. After it returns, the same `[ebx+0xB0]` object is queried through
direct helper `0x0047882E` for style bits; the code adjusts the rectangle's
edges, derives width/height, and passes the resulting coordinates to helper
`0x00478BDE`. This static producer/use chain identifies this candidate as a
window-geometry path. It does not recover the receiver's concrete runtime
class, and it does not prove that every other `+0x68` receiver is unrelated to
G5. The other three sites also have rectangle/layout data flow, and their
receivers are not statically identified as `CDevG5KB`.
Other scanned `+0x68` sites have different observed argument shapes or
status/UI behavior, and none could be tied to the G5 vptr at `0x005CBA2C`.

The helper's scoped persistence result is unchanged: it copies conditional
response bytes into caller memory, and its body has no file-open or file-write
sink. Because no caller is attributable to this method, the scan cannot trace
its buffer to any downstream file API. Thus a full firmware export is not
statically established. An untraced runtime alias or dynamically selected
receiver remains possible, so this negative result is limited to the decoded
static evidence above.

For the distinct V4.6 `+0x70` path and its separate caller search, see the
[V4.6 G5 caller audit](rk-v4.6-cdevg5-realdata-caller-audit.md) and
[V4.6 G5 vtable audit](rk-v4.6-cdevg5-settings-and-vtable-audit.md).

## Remaining gaps and related evidence

- Find a statically attributable caller of the concrete G5 `+0x68` method at
  `0x00410700`; direct-call and decoded virtual-call scans have not found one.
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
