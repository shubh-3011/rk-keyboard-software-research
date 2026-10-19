# RK DeviceDriver 4.6 screen-dialog event to frame worker

## Scope and evidence identity

This offline static follow-up inspects only the extracted 4.6-labeled
`DeviceDriver.exe`, SHA-256
`8D8538DE3ADA5FCF80E00C13B364B17ACEFA708480E102EC1E6A0B1309639AE9`
(2,418,176 bytes, PE32, preferred image base `0x00400000`). The hash matches
`app/DeviceDriver.exe` in the package manifest. Disassembly and PE data were
read statically. The vendor program was not launched, and no HID interface,
updater, bootloader, or keyboard command was accessed.

The existing [screen/GIF transport audit](rk-v4.6-screen-gif-ui-transport-audit.md)
traces the selected image list through a 512-entry snapshot and worker thread
to the G5 screen-transfer methods. This note closes a narrower gap: one
`CScreenDlg` child-window event branch that supplies dialog state to that
worker-launch path.

## Class and message-map evidence

The RTTI type descriptor at `0x0061A654` names `.?AVCScreenDlg@@`. The
complete-object-locator pointer immediately before vtable `0x005E394C`
references that descriptor. Constructor `0x00471D00` installs this vtable at
`0x00471D3D`; its `+0xF0` slot at `0x005E3A3C` contains handler
`0x004740E0`. These references identify `0x004740E0` as a virtual method of
the `CScreenDlg` object layout.

The message-map table at `0x005E36B8` includes this command entry. Its
attribution to `CScreenDlg` remains a static candidate, consistent with the
existing screen/GIF audit. Setup code at `0x00473004` supplies control ID
`0x0107` and stores the created control wrapper at `this+0x2180`; handler
`0x00473810` reads from that same member. This ties the row and the dialog's
control layout together, though no live MFC dispatch was observed.

| Entry VA | Message | Code | Control ID | Handler | Static result |
| --- | --- | ---: | ---: | --- | --- |
| `0x005E3748` | `WM_COMMAND` (`0x0111`) | `0x0300` (`EN_CHANGE`) | `0x0107` | `0x00473810` | Reads the edit text, parses an integer, caps it at `0xFFFF`, then stores it in `this+0x114` (`0x0047394D`). |

The dialog constructor initializes a separate child wrapper at
`this+0x1408`, and the
dialog setup path passes that wrapper to control-construction helper
`0x004521D0` at `0x004733F5`. The two wrappers must not be conflated: the
static map identifies edit control ID `0x107`, while the later worker-trigger
branch is keyed by the HWND in the `+0x1408` wrapper. Its visible caption,
control ID, and exact notification type are not recovered here.

## Child event to worker snapshot

`0x004740E0` receives two stack arguments and compares its second argument
with HWNDs held by several child wrappers. In the branch for
`this+0x1408`, instructions at `0x0047483D`–`0x0047485F` perform the following
data flow:

1. Read the child HWND from `[this+0x1408]+0x20` and compare it with the
incoming second argument.
2. On equality, load `[this+0x114]` and pass it as the explicit argument to
`0x004748A0`; pass `this+0xE0` in `EDI` as the frame-list context.
3. `0x004748A0` skips the snapshot if the active-device pointer at
`0x00647320` has a nonzero result from virtual slot `+0x28`. Otherwise, when
the list count at `this+0xEC` is positive, it copies pointers from the list
head at `this+0xF4` into a temporary array at `+0x3A8`, capped at 512 entries,
and stores the count at `+0x3A4`.
4. The incoming integer is written to that temporary object at `+0xBA4`
(`0x00474969`–`0x00474982`), then `0x004811E6` is called with the temporary
object. The object is destroyed after that call.

The `0x004811E6` setup path is traced in the existing screen/GIF audit:
it creates the worker dialog; its initialization invokes the temporary
object's `+0x150` virtual slot, resolving to `0x0046CE50`. That routine passes
worker callback `0x0046CA80` to the thread helper, which reaches
`CreateThread`. In the worker, `0x0046CC15` reads the copied `+0xBA4` value,
subtracts the current frame index, clamps a negative result to zero, and
passes it to the current device's virtual slot `+0x58` at `0x0046CC22` before
the frame loop. For the statically recovered G5 vtable, `+0x58` resolves to
`0x00413620`, the GIF-parameter method. The frame loop then calls `+0x54` at
`0x0046CCFC`, which is the previously traced frame-page transfer route.

This is a static dialog-child-HWND → shared numeric state → worker snapshot →
frame worker edge. The edit callback at control ID `0x107` updates the same
`this+0x114` field consumed by the trigger branch; the evidence does not show
that editing alone launches the worker. The triggering child HWND is a
separate event source.

## Interpretation and limits

**Proven statically:** the edit-change handler stores a parsed/clamped number
at `this+0x114`; the `+0x1408` child-HWND branch supplies that field to the
worker snapshot; the worker consumes the copied value before invoking device
slot `+0x58`; and the existing G5 vtable resolves that slot to the GIF
parameter method. The worker launch and subsequent transfer are conditional
on the static branches described above.

**Inferred:** the numeric field is likely a GIF delay value. The binary has a
profile-specific `%s%04X\\gif_delay.gcc` path and a `load_gif_delay failed`
diagnostic; separate helpers read/write a four-byte value at that path. The
worker's per-frame subtraction and the G5 method's GIF parameter payload are
consistent with a delay setting, but the exact units and field semantics are
not named in the code.

**Unresolved:** the visible label and control ID for the `+0x1408` child, the
exact Win32 event/notification that reaches `0x004740E0`, the meaning of the
active-device `+0x28` guard, which family vtable is active at runtime, and
whether a keyboard accepts any resulting report. No runtime or hardware
behavior is claimed.

For the broader selected-file, frame conversion, report, and G5 transfer
evidence, see the [screen/GIF transport audit](rk-v4.6-screen-gif-ui-transport-audit.md).
