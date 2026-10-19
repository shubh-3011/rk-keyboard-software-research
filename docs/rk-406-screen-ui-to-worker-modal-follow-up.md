# RK 4.06 screen UI to worker modal follow-up

## Scope and evidence

This follow-up traces the installed RK Keyboard Software 4.06
`DeviceDriver.exe` screen-editor dispatch toward its screen-transfer dialog,
frame-list preparation, and the separately recovered transfer worker. The
binary is PE32 x86, image base `0x00400000`, SHA-256
`C03F88BC4E2D78AA4392D7445B0FD62182DC824F97F5D5DB40BD009E547A9AB6`.
The installed image at
`C:\Program Files (x86)\RK Keyboard Software\DeviceDriver.exe` and the
workspace analysis copy `_rk_analysis/inputs/DeviceDriver.exe` both have that
hash.

The analysis is static. The RK application and updater were not run; no HID
interface was opened and no report or command was sent.

Evidence labels:

- **Confirmed statically**: directly supported by instructions, data, or a
  recovered call/message path in this exact image.
- **Inferred**: the static pieces fit the interpretation, but an edge or
  semantic label is missing.
- **Unresolved**: the available static path does not establish the claim.

## Screen-editor transfer action

**Confirmed statically.** In the `CScreenDlg` dispatch routine at
`0x0046D300`–`0x0046D4FC`, the child window handle at `this+0x1408` is compared
with the incoming control handle (`0x0046D399`–`0x0046D3A8`). On a match, the
routine obtains the device object through global `0x0062B380` and invokes its
virtual slot `+0x28` (`0x0046D3AE`–`0x0046D3C0`). A true return proceeds; a false
return takes the alternate message path. The meaning of slot `+0x28` is not
recovered here, so it is only a device-object gate, not a proven `ShowScreen`
profile check.

After that gate, the dispatcher requires the count field at `this+0xEC` to be
positive (`0x0046D3DE`–`0x0046D3E5`). It appears to be the screen frame count,
but that semantic label is inferred from context. It then:

1. Initializes a stack object with `0x00465EA0` (`0x0046D3EB`–`0x0046D3F0`).
   The constructor writes vtable pointer `0x005D9A4C`, initializes the
   pointer-array area at object offset `+0x3A4` for `0x800` bytes, and clears
   fields at `+0x390` and `+0x394`.
2. Traverses a linked list rooted at `this+0xF4`, copies each node's first
   pointer into that object's array, and stops at 512 entries
   (`0x0046D400`–`0x0046D429`). The resulting count is stored immediately
   before that array. This is the strongest UI-to-dialog evidence for the
   screen frame/image object list.
3. Copies the numeric field from `this+0x114` into the object at offset
   `+0xBA4` (`0x0046D429`–`0x0046D43A`). Its UI meaning remains unknown.
4. Calls `0x00479A27` with the initialized object (`0x0046D43A`–`0x0046D441`),
   then destroys the object with `0x00465F50` (`0x0046D44A`–`0x0046D455`).

**Confirmed statically.** The vtable installed by the constructor contains
`0x00479A27` at offset `+0x14C` and `0x00466820` at offset `+0x150`
(`0x005D9B98` and `0x005D9B9C` respectively). The former is the method called
by the screen-editor dispatcher; the latter is the worker setup routine that
starts callback `0x00466450`. Thus the modal object class exposes the worker
setup method in its vtable. The related code logs `CBurnScreenDlg: user
cancel` (`0x005D9A00`), which supports—but does not alone prove—the class-name
association.

**Inferred.** The stack object and call to `0x00479A27` form the screen burn
progress/modal path: the object contains the copied frame pointer array and
progress-related state. The visible label and exact dialog resource/control
identity are not established by this trace.

## Candidate image and GIF preparation route

**Confirmed statically.** A separate `CScreenDlg` dispatch branch compares the
incoming child handle with the child object at `this+0xC74` and directly calls
`0x0046F610` (`0x0046D45C`–`0x0046D478`). That routine reads an item count at
object offset `+0x64` and traverses a linked list at `+0x6C`.

- For a count of one, the routine selects a `.png` filter and the embedded
  UTF-16 title `NewPNG` (`0x0046F659`–`0x0046F6B0`; strings at
  `0x005DA900`–`0x005DA934`) and processes the single listed image object.
- For other positive counts, it selects a `.gif` filter and embedded title
  `NewGIF` (`0x0046F718`–`0x0046F779`; strings at
  `0x005DA940`–`0x005DA974`), then iterates the image-object list. Each item
  is passed through frame-processing helper `0x00467E50`; the routine calls
  finalizers `0x00467F90` and `0x00467D40` (`0x0046F7D5`–`0x0046F884`).

This proves a screen-editor child route that prepares PNG/GIF image objects.
It does not prove that these objects are the same pointers later copied from
`CScreenDlg+0xF4`, nor that the generated objects become the raw bytes sent to
the keyboard. The 4.06 profile GIF-to-PNG cache path documented in
[`rk-screen-image-conversion-path-audit.md`](rk-screen-image-conversion-path-audit.md)
also remains a separate local-file path in the evidence available here.

## Boundary to the established transfer worker and writers

**Confirmed statically.** A separate setup routine `0x00466820` starts worker
`0x00466450` through thread helper `0x0056DC08`. The worker invokes virtual
slots `+0x58`, `+0x50`, and `+0x4C`; it converts frame image objects through
`0x004661A0`, passes the conversion buffer and length to `+0x4C`, and invokes
`+0x50` with frame/length-related values. This is the worker described in the
[screen image-conversion audit](rk-screen-image-conversion-path-audit.md).
The G5 screen serializers are separately established in the
[screen/GIF payload audit](rk-screen-gif-payload-audit.md): command `0x0B`
parameter writer, command `0x0D` GIF metadata writer, and command `0x0C` page
writer. The page serializer accepts a caller buffer and splits it into
up-to-512-byte subreports; the screen-capable profiles in this package set
`DataUnitSize=512`.

**Unresolved.** This follow-up does not recover a call or message-map dispatch
from the `0x00479A27` modal path to vtable slot `+0x150` (`0x00466820`). The
vtable membership establishes that the modal class has the worker-start
method, but does not prove that this UI action invokes it. Nor does the
available edge establish that the copied list is the worker's `+0x3A8` frame
array, or that `0x004661A0` output reaches
`FUN_00412F20`/`FUN_00412B10`. The concrete
targets of worker slots `+0x4C`, `+0x50`, and `+0x58` are not established by
this UI trace. No UI click path is established here for the `0x0B` or `0x0D`
serializers.

The available click-handler block reads no `ShowScreen` field directly. It
has a positive frame-count condition and calls the device object's virtual
`+0x28` gate; whether that gate implements profile eligibility, connection
readiness, or both is unresolved. Existing profile parsing proves that
`ShowScreen` gates loading screen-related profile settings, but not that this
specific UI action uses that field as its gate.

## Bounded conclusion

The 4.06 screen editor has a concrete child-window route that prepares PNG/GIF
objects and another route that, after a device-object gate and nonempty-frame
check, copies up to 512 frame-related pointers plus a numeric value into a
screen modal object. A separate worker converts image objects and calls
virtual methods, while separate G5 command writers serialize screen data.
Static evidence stops at the modal-to-worker and worker-slot-to-G5-writer
edges. Thus the UI path is mapped to a candidate transfer dialog, but an
end-to-end GIF-to-device write is not established.
