# RK 4.06 `CLedDlg` selector-message sender follow-up

## Scope and evidence

This offline follow-up traces literal message senders for the two
`CLedDlg`-mapped private messages `0x0800` and `0x0801` in the installed
4.06 `DeviceDriver.exe`, SHA-256
`c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6`.
Addresses are image virtual addresses. It uses a full GNU `objdump -d -M
intel` disassembly, the native API IAT ledger, and the RTTI-backed MFC map.
The executable was not run and no HID report or command was sent.

**Proven statically** means the instruction or data-flow edge appears in the
hash-pinned image. **Inferred** marks a likely window relationship not
observed at runtime. **Unresolved** marks a field value, user control, or
device effect not established by this image.

## Literal `PostMessageW` send sites

The `PostMessageW` IAT slot is `0x0059E738`. A full-image search for literal
message pushes followed by calls through that slot found these callsites:

| Message | Callsite | `wParam` source | `lParam` source | Parent-window lookup |
| --- | ---: | --- | --- | --- |
| `0x0801` | `0x0043693D` | `[ESI+EDI*4+0x298]` | `[ESI+0x54]` | `GetParent` at `0x00436918`; wrapper `0x004752FD`. |
| `0x0801` | `0x004372D9` | caller stack argument | `[ESI+0x54]` | `GetParent` at `0x00437277`; wrapper `0x004752FD`. |
| `0x0801` | `0x0044C204` | `EBX` selected value | `[ESI+0x930]` | `GetParent` at `0x0044C1E3`; wrapper `0x004752FD`. |
| `0x0801` | `0x0044DAEC` | caller stack argument | `[ESI+0x9E0]` | `GetParent` at `0x0044DAC7`; wrapper `0x004752FD`. |
| `0x0800` | `0x00436A45` | `[ESI+EDI*4+0x298]` | `[ESI+0x54]` | `GetParent` at `0x00436A20`; wrapper `0x004752FD`. |
| `0x0800` | `0x00437299` | caller stack argument | `[ESI+0x54]` | `GetParent` at `0x00437239`; wrapper `0x004752FD`. |
| `0x0800` | `0x0044C80C` | `EDI` selected value | `[ESI+0x930]` | `GetParent` at `0x0044C7EB`; wrapper `0x004752FD`. |
| `0x0800` | `0x0044D299` | `EDI` selected value | `[EBX+0x9E0]` | `GetParent` at `0x0044D278`; wrapper `0x004752FD`. |
| `0x0800` | `0x0044DAAC` | caller stack argument | `[ESI+0x9E0]` | `GetParent` at `0x0044DA87`; wrapper `0x004752FD`. |

At each site the HWND argument comes from the wrapper's `+0x20` field after
the parent lookup. These are direct message-posting callsites, not
`SendMessageW` calls. **Inferred:** the parent window is the `CLedDlg` that
owns the matching MFC map. The runtime HWND identity is not observed.

## Handler argument meaning

The MFC map sends `0x0800` to `0x00422190` and `0x0801` to `0x00422220`.
Handler `0x00422220` compares its `lParam` with `0x94` and `0x95`. For
selector `0x95`, its `wParam` indexes the `LightUI` byte table at
`0x00611854`, then the value is formatted for display. Handler `0x00422190`
forwards the message arguments to `0x00422220`, copies page state, and can
signal Apply mode `2` under its guards.

This ties the `0x0801` sender families to the selector-message route, but the
sender's `lParam` values are loaded from child-object fields `+0x54`,
`+0x930`, and `+0x9E0`. A constructor path now proves that `+0x9E0` is
initialized to selector `0x95` for one LightUI-based control construction:

- At `0x00423630`, code scans the `LightUI` byte table at `0x00611854` and
  retains a selected index in `EBX`.
- The call at `0x004236D9` passes object pointer `EDI+0x1A6C` as argument 3,
  the selected index as argument 5, literal `0x95` as argument 6, and the
  `bar_nr.png` string as argument 7 to helper `0x00450140`.
- Helper `0x00450140` loads argument 3 into `ESI` at `0x0045018B` and argument
  6 into `EDX` at `0x004503EB`, then stores `EDX` to `[ESI+0x9E0]` at
  `0x0045040B`.
- Sender functions `0x0044DA80` and `0x0044DAC0` load their own `[this+0x9E0]`
  field into `lParam` before posting `0x0800` and `0x0801`, respectively.

This proves the selector assignment to field `+0x9E0` on that construction
path and the matching sender-field offset. In isolation, this data-flow did
not prove that one of those sender methods is invoked on that constructed
instance at runtime; the message-map bridge below adds the static class-level
association. The `wParam` values remain dynamic or caller arguments, and a
specific widget-to-index mapping is unresolved.

## RTTI-backed child-class and message-map bridge

The constructor and MFC metadata statically identify the object used by that
selector initializer:

- `CLedDlg` constructor `0x004210C0` calls `0x0044CBE0` with `this+0x1A6C`
  (`0x00421177`). The same constructor calls it for other offsets, but this
  selector path specifically passes `this+0x1A6C`.
- Constructor `0x0044CBE0` writes vptr address point `0x005D5EF4`. Its RTTI
  Complete Object Locator at `0x005E4664` references TypeDescriptor
  `0x00603B54`, whose name is `.?AVCPngSliderBar@@`.
- The `CPngSliderBar` vtable's `GetMessageMap` slot calls `0x0044CDD0`, which
  returns map descriptor `0x005D5EA8`; that descriptor points to entries at
  `0x005D5DD0`. The entries bind private message `0x0800` to `0x0044DA80`
  and `0x0801` to `0x0044DAC0` (both signature `0x0E`).
- Those two methods load `[this+0x9E0]` into `lParam`, call `GetParent`, then
  post their corresponding private message through `PostMessageW`. The
  selector initialization above stores `0x95` at this same field on the
  `CLedDlg+0x1A6C` child object.
- The `CLedDlg` MFC map separately binds `0x0800` to `0x00422190` and `0x0801`
  to `0x00422220`. The latter handles `lParam == 0x95` through the `LightUI`
  table path described above.

Together, this establishes a static object/type/map/data-flow bridge:
`CLedDlg+0x1A6C` is constructed as `CPngSliderBar`; that class's message map
associates the two private IDs with methods that post the same IDs and the
stored selector to the parent; and `CLedDlg` has matching parent handlers.
This supports a child-to-parent message route for selector `0x95`, but does
not establish that Windows dispatches either callback for this instance in a
particular run or identify the user-visible label/behavior of the control.

## Limits

- The literal `PostMessageW` callsites and arguments are proven, while
  computed-message sends or alternate API wrappers are outside this literal
  search.
- The parent HWND identity is not observed at runtime; its association with
  `CLedDlg` is supported statically by the child being constructed at
  `CLedDlg+0x1A6C` and by the matching parent-map IDs.
- Whether the initialized `+0x9E0` value is later overwritten, what action
  delivers the private messages to the child handlers, and what visible label
  or behavior the control represents remain unresolved.
- The later [record-base correction](rk-406-brightness-record-base-correction-2026-10-26.md)
  verifies the slider mouse-up → selection-state → parent-handler path and
  brightness-field write. This supersedes the missing-setter inference;
  runtime delivery, family-specific execution and physical effects remain unproven.

## Related evidence

- [Brightness UI handler audit](rk-lighting-brightness-ui-handler-audit.md)
- [Recovered MFC message-map arrays](rk-mfc-message-map-audit.md)
- [UI control-to-command crosswalk](rk-ui-control-command-crosswalk.md)
- [Apply worker and signal paths](rk-settings-apply-worker-audit.md)
