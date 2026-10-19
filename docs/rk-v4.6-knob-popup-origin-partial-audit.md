# V4.6 knob-option popup origin: partial static trace

## Scope and evidence boundary

This follow-up examines the UI origin of the `CKeyDlg` private messages
`0x0483` and `0x0477` in the 4.6-labeled `DeviceDriver.exe`. The input is the
2,418,176-byte x86 PE with SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`;
addresses below are preferred-image-base VAs for that file. The observations
come from PE bytes, MFC message-map data, RTTI, and static disassembly. No RK
binary was run and no keyboard interface was opened.

## Selection control to `CKeyDlg` popup

The RTTI-backed message map for `CKBColorDlg` has descriptor `0x005D49E8`
and entries at `0x005D4910`. Its Complete Object Locator at `0x005ECF70`
points to type descriptor `0x0061A13C`, whose decorated name is
`.?AVCKBColorDlg@@`. The map row at `0x005D49B8` maps message `0x0205`
(`WM_RBUTTONUP`) to handler `0x00418BA0`.

In that handler, the selected row/index is computed through helper
`0x00418E20`, stored at `this+0x80`, and posted to the parent chain as private
message `0x0483`: callsite `0x00418C09` pushes message `0x0483`, `wParam`
`[this+0x80]`, and `lParam=0`, then calls `PostMessageW` through IAT slot
`0x005A673C`.

The `CKeyDlg` map descriptor at `0x005D4CA0` points to entries at
`0x005D4B80`; its row at `0x005D4C28` maps `0x0483` to handler
`0x0041CB00`. When the handler's profile and UI-state gates pass, it stores the
index in `this+0x2184`, calculates a popup position, and calls helper
`0x0041CBA0`.

Helper `0x0041CBA0` reads the four option-array globals beginning at
`0x006478F4`, `0x006478F8`, `0x006478FC`, and `0x00647900`. The UI builder at
`0x00447F20` populates this array family from `tc_knob1` through `tc_knob4`
(localized as Volume, Keyboard brightness, Mouse wheel, and Arrow keys in the
English catalog). The helper then calls `0x00435720` at `0x0041CEF0`, passing
the `CKeyDlg` object and the popup data. This connects the `0x0483` selection
route to a dynamically created popup containing the localized knob options.

## Popup selection to `CKeyDlg` `0x0477`

The popup created on this route is `CMenuDlg`: its constructor writes vtable
`0x005DA5AC`, whose preceding Complete Object Locator at `0x005ED328` points
to decorated type `.?AVCMenuDlg@@`. Its MFC map at `0x005DA510` maps `WM_LBUTTONUP`
(`0x0202`) to `0x00435A00`.

The creator `0x00435720` obtains the parent HWND from the passed `CKeyDlg`
object (`[arg1+0x20]`) and initializes `CMenuDlg`'s owner-window field at
`this+0x74`. On a selected popup row, handler `0x00435A00` posts private
message `0x0477` to that owner at `0x00435A23`; `wParam` is the selected
`0x58`-byte row's first DWORD, and `lParam` comes from `CMenuDlg+0x14D8`.

For the knob-option popup creation call at `0x0041CEF0`, stack argument five
is zero. `0x00435720` stores that argument in `CMenuDlg+0x14D8` at
`0x00435800`, so this particular popup posts `0x0477` with `lParam=0`. The
separate `CKeyDlg` handler `0x0041CF20` only enters its signal-2 branch when
the second message argument equals `2` (`0x0041CFEA`–`0x0041CFFF`). Therefore
the newly traced localized-option popup does **not** establish the
`lParam=2` command-4 route documented in the command-4 follow-up.

## What this closes and what remains open

**Proven statically:** a `CKBColorDlg` right-button-up selection can post
`0x0483` with a selected row to `CKeyDlg`; the guarded `CKeyDlg` handler
builds a popup from the four localized knob-option arrays; the `CMenuDlg`
created on that path can post `0x0477` back to `CKeyDlg` with `lParam=0`.
The parsed standard `RT_DIALOG` inventory contains no identified
knob-specific control; the popup on this path is created dynamically.

**Still unresolved:** which exact visible widget or key row exposes the
`CKBColorDlg` selection, any control/resource ID for it, why the separate
`lParam=2` branch exists, whether the second sender (`CMenuSrDlg` handler
`0x00436660`) has a knob-related caller, and which physical model/revision
uses these fields. Profile `KnobIndex`/`KnobDef` rows remain package
configuration evidence, not proof of a selected or connected device.
Neither the profile match nor device acceptance is runtime-validated.

## Related evidence

- [Knob labels and profile state](rk-v4.6-ui-knob-localization-path-audit.md)
- [Signal-2 and G5 command-4 path](rk-v4.6-knob-signal-to-g5-command04-follow-up.md)
- [4.6 dialog-resource inventory](rk-v4.6-dialog-resource-audit.md)
