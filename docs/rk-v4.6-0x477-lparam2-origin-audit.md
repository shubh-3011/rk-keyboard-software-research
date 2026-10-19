# V4.6 `0x0477` `lParam=2` origin audit

## Scope and evidence

This static follow-up checks the known `0x0477` UI routes for a source of the
`CKeyDlg` handler's `lParam=2` branch. The target is the 2,418,176-byte x86
`DeviceDriver.exe`, SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`.
Addresses are preferred-image-base VAs. Evidence is from PE metadata and
static disassembly only; the vendor program was not run and no device
interface was opened.

## Required `CKeyDlg` message arguments

The `CKeyDlg` map entry at `0x005D4BC8` routes private message `0x0477` to
`0x0041CF20`. That handler enters the signal-2 branch only when `lParam == 2`
and `wParam & 0xFF00` is nonzero (`0x0041CFEA`–`0x0041CFFF`). The queue and
G5 command-4 consequences of this conditional branch are documented in the
[signal-2 follow-up](rk-v4.6-knob-signal-to-g5-command04-follow-up.md).

## Known senders do not establish this argument

The `CMenuDlg` sender at `0x00435A23` posts `0x0477` with `lParam` copied from
`CMenuDlg+0x14D8`. Its creator `0x00435720` stores caller argument five in
that field (`0x00435800`). The localized knob-option popup creation from
`CKeyDlg` at `0x0041CEF0` supplies zero for argument five. That route therefore
posts `lParam=0`; see the [popup-origin audit](rk-v4.6-knob-popup-origin-partial-audit.md).

A separate `CMenuDlg` caller at `0x00408593` is inside the RTTI-identified
`CComboBtn` subsystem (`.?AVCComboBtn@@`; map descriptor `0x005D0FC0`). It
passes `[CComboBtn+0x638]` as argument five. The constructor at `0x00408040`
initializes that field to zero at `0x00408093`. The resulting popup targets
the `CComboBtn` window (`[arg1+0x20]` in the shared creator), whose own map
routes `0x0477` to `0x004085B0` (map row `0x005D0F90`). This is a combo-button
selection route, not evidence of a message sent to `CKeyDlg`; its statically
observed payload source is initialized to zero.

The other known sender, `CMenuSrDlg::OnLButtonUp`, posts `0x0477` at
`0x00436686`, taking `lParam` from `CMenuSrDlg+0x1328`. The map identifies the
sender as `.?AVCMenuSrDlg@@` and maps `WM_LBUTTONUP` to `0x00436660`. Its
creation sequence around `0x00436100`–`0x0043622D` writes zero to `+0x1328`
at `0x004361EB`. The constructor at `0x00436240` does not touch that field in
its observed body. In the image's direct references to this field, the only
identified write is the creator's zero-initialization; the sender reads it at
`0x0043666E`. The creator's target window/control and any alternate nonzero
initialization remain unproven.

The remaining direct `CMenuDlg` creator at `0x004752A7` also passes zero as
argument five. Thus, the statically identified menu paths explain
`lParam=0` or target a `CComboBtn` receiver; none proves delivery to
`CKeyDlg` with `lParam=2`.

## Localized control relationship

The existing localization audit shows that `tc_knob1`–`tc_knob4` are consumed
by a UI builder and that the `CKeyDlg` `0x0483` selection path creates the
localized knob-option popup. That popup is the `CMenuDlg` path with
`lParam=0`. The localized labels do not identify a control that supplies
`lParam=2`. Neither `CComboBtn` nor `CMenuSrDlg` has been statically linked to
those knob labels or to a specific visible control/resource ID.

## Conclusion

**Unresolved:** the sender and visible control that deliver
`CKeyDlg::OnMessage(0x0477)` with `lParam=2`. The known `CMenuDlg` knob popup
does not meet the argument condition; the generic `CComboBtn` popup is routed
to its own handler and has a zero-initialized payload source; the known
`CMenuSrDlg` payload is likewise initialized to zero. These static findings
do not rule out another runtime path or indirect field assignment, but no such
path is established by this audit. No physical keyboard model or device-side
behavior is inferred.

## Related evidence

- [Knob labels and profile flow](rk-v4.6-ui-knob-localization-path-audit.md)
- [Popup origin and localized option route](rk-v4.6-knob-popup-origin-partial-audit.md)
- [Signal-2 to G5 command-4 route](rk-v4.6-knob-signal-to-g5-command04-follow-up.md)
- [V4.6 MFC message-map entries](rk-v4.6-mfc-message-map-entries.csv)
