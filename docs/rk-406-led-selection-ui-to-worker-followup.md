# RK 4.06 LED selection UI-to-worker boundary follow-up

## Scope and exact image

This static follow-up traces one candidate LED-dialog selection route from a
mouse-message producer through the `CLedDlg` message map and selection handler,
then to the Apply worker and its conditional G5 LED serializer. It is limited
to the installed x86 `DeviceDriver.exe` 4.06 image with SHA-256
`C03F88BC4E2D78AA4392D7445B0FD62182DC824F97F5D5DB40BD009E547A9AB6`.
All addresses below are image virtual addresses for that exact hash. The
binary was inspected statically; RK software was not run and no keyboard or
HID interface was opened or contacted.

Evidence terms: **proven statically** means the bytes, decoded instructions,
or table data directly show the operation. **Conditional/inferred** marks a
link that depends on the runtime window, profile, selected row, or active
device object. **Unknown** marks a mapping or behavior not established by this
binary evidence.

## Message entry and candidate producer

The recovered `CLedDlg` MFC message-map row is at `0x005CD0A8` in the map
array at `0x005CD150` (base `0x005CCFE8`, row 8). It maps private Windows
message `0x0594` to handler `FUN_00422430` at `0x00422430`, with signature
`0x0E`. This is a software window message, not a keyboard protocol command.
The entry is recorded in
[`rk-mfc-message-map-entries.csv`](rk-mfc-message-map-entries.csv) and
discussed in the [MFC map audit](rk-mfc-message-map-audit.md).

A candidate producer appears in the control event dispatch around
`0x0045D4B8`–`0x0045D5E9`:

1. At `0x0045D4B8`, the dispatch checks for `WM_LBUTTONDOWN` (`0x0201`).
2. At `0x0045D535`, it resolves the source control's parent through
   `FUN_004050E0`; that helper calls `USER32!GetParent` through IAT slot
   `0x0059E82C` and uses wrapper `0x004752FD`. The parent wrapper's HWND at
   `+0x20` becomes the message target at `0x0045D555` (or the target is null
   if the wrapper lookup fails).
3. The source control ID is obtained through `FUN_00478901` at `0x00478901`.
   Its fallback calls `USER32!GetDlgCtrlID` through IAT slot `0x0059E684`;
   a wrapper virtual slot `+0x90` can also supply the value.
4. At `0x0045D5D8`–`0x0045D5D9`, the call pushes `EBX` as `lParam`, the
   returned control ID as `wParam`, literal `0x0594` as `message`, and the
   parent HWND, then calls `PostMessageW` through IAT slot `0x0059E738`.

The literal message, argument order, parent lookup, and API call are static
facts. **Inferred:** this producer targets the `CLedDlg` instance owning the
map row because the code posts `0x0594` to the resolved parent and the image
maps `0x0594` to that handler. No runtime HWND trace proves the owner, and the
source control's dynamic ID and `EBX` value are not mapped to a visible LED
control or option.

## Handler state and refresh path

`FUN_00422430` queries a child at `this+0xAC` with `SendMessageW` arguments
`0x110A, 9, 0` at `0x0042247C` (IAT slot `0x0059E834`). It compares the result
against entries in a linked structure rooted at `this+0x1B0` (`0x00422488`–
`0x0042249B`). On a match, it takes the node's `+0x10` value and stores the
selected row/index through the pointer at global `0x0062B388`, field offset
`+0x213C`, at `0x004224AD`. The binary proves the field write and subsequent
use as an index; it does not identify the visible label or define the row as
a hardware effect/mode ID.

At `0x004224B3`, the handler calls `FUN_00424B10(row, 0)` to refresh the
dialog page. That routine reads selected-row values from the `0x3C`-stride
profile table at `0x00611A10` and updates dialog state/visibility, as detailed
in the [lighting profile-record audit](rk-lighting-profile-record-path-audit.md).
This is consistent with refreshing profile-dependent LED controls, but does
not map the source control ID to one specific `LedOptN` field.

The handler then branches on the selected row. Row `0x1E` skips the ordinary
Apply-signal path. Otherwise, the normal mask is `0x02`; when the row equals
global `0x006117CC`, it uses mask `0x06` and sets a dirty field at the active
configuration base `+0x25C4` (`0x004224C2`–`0x004224DC`). After a 100 ms wait,
if guard global `0x00611794` is nonzero, it calls `FUN_00401080(mask)` at
`0x004224F5`; it then calls `FUN_0045ABF0` with global `0x0061175C` to save
profile state. These are static branches. The meaning of row `0x1E`,
`0x006117CC`, the mask values as user-facing operations, and the saved
profile's runtime identity remain unresolved.

## Worker and conditional G5 serializer

`FUN_00401080` stores the masked operation value in shared field
`0x0061972C` and releases semaphore `0x00619724`; the worker at
`FUN_00401170` wakes and calls the active root object's virtual slot `+0x3C`
at `0x004012A0`. The worker route and possible class targets are described in
the [Apply worker audit](rk-settings-apply-worker-audit.md).

The active receiver is runtime-dependent. The
[active-profile dispatch follow-up](rk-406-active-profile-apply-dispatch-follow-up.md)
maps eight S98-labeled profile rows (`0174`, `01AF`, `01BF`, `0223`, `0224`,
`022B`, `022F`, `0230`) to the static G5 class route. **Conditional:** if one
of those profile-selected G5 objects is the active worker receiver, slot
`+0x3C` resolves to `FUN_00411B90`. This is not proof that the connected
keyboard or object was an S98/G5 instance during an event.

Inside `FUN_00411B90`, mask bit `0x02` enters the LED configuration
read/modify/write branch: `FUN_0040FAD0` reads 128 bytes (G5 command `0x84`),
then `FUN_00411700` or `FUN_00411900` packs the setting and the orchestrator
emits command `4`. For the G5/Fw=1 S98 profile path, `FUN_00411900` reads the
selected-row byte from `[EBX+0x213C]` at `0x00411939`, scales it by a
15-DWORD/`0x3C`-byte table stride at `0x00411940`–`0x00411953`, and selects
from the table beginning at `0x00611A10`. The command and packer boundary are
documented in the [settings serializer audit](rk-setting-serializer-audit.md);
record fields and the serializer's profile data are covered by the
[lighting profile-record audit](rk-lighting-profile-record-path-audit.md).

The handler's field and packer's field share offset `+0x213C`, and both are
used as row/index state. **Conditional/inferred:** the static evidence here
does not establish that the object reached through global `0x0062B388` is
identical to the `EBX` configuration object supplied to `FUN_00411900`, nor
that the active G5 profile is one of the S98 rows. Therefore the full
selection-handler-to-command-4 edge is a plausible static route, not a proven
runtime dispatch. Even if this branch runs, no evidence here confirms that a
physical keyboard accepts the payload or changes its LEDs.

## What remains unknown

- The exact control ID-to-row mapping and which visible child emits this
  `0x0594` message.
- Whether runtime MFC dispatch delivers this posted message to this
  `CLedDlg` instance, and whether the sender's `EBX`/control-ID values have
  the expected runtime values.
- The user-facing meaning of the selected row, mode/effect, and fields; the
  LED candidate labels are not proven firmware mode IDs. See
  [4.06 LED label/control candidates](rk-led-control-candidates-4.06.md).
- Which runtime profile and device object are active at the worker call, and
  whether global `0x0062B388` and the serializer's configuration pointer are
  the same object.
- Whether a physical device accepts the operation or what visible/color
  effect results.

## Related source documents

- [Recovered MFC message-map entries](rk-mfc-message-map-entries.csv) and
  [map audit](rk-mfc-message-map-audit.md)
- [Selector message sender follow-up](rk-led-selector-message-sender-followup.md)
- [Settings Apply worker and family dispatch](rk-settings-apply-worker-audit.md)
- [Active-profile Apply dispatch follow-up](rk-406-active-profile-apply-dispatch-follow-up.md)
- [Lighting profile records and packer fields](rk-lighting-profile-record-path-audit.md)
- [Settings serializer and command paths](rk-setting-serializer-audit.md)
- [LED label/control candidates](rk-led-control-candidates-4.06.md)
