# RK 4.06 LED `0x0594` parameters and generated-row audit

## Scope and image identity

This static follow-up checks whether the control ID posted as `wParam` for
`CLedDlg` message `0x0594` identifies one generated LED label, a resource
control, or a profile row. The input is the installed x86
`DeviceDriver.exe`, SHA-256
`C03F88BC4E2D78AA4392D7445B0FD62182DC824F97F5D5DB40BD009E547A9AB6`.
Addresses are image virtual addresses for that file. The application was not
run, and no keyboard or HID interface was opened or contacted.

## The posted parameters are not used by the handler

The `CLedDlg` message map associates `0x0594` with `FUN_00422430` at
`0x00422430` (map row `0x005CD0A8`; descriptor `0x005CD150`). The candidate
producer is in the `WM_LBUTTONDOWN` path at `0x0045D4B8`–`0x0045D5E9`:

- At `0x0045D535`, it resolves a parent; at `0x0045D555` it obtains the
  parent wrapper's window handle.
- At `0x0045D55B` (or fallback `0x0045D543`), it calls `FUN_00478901` for the
  source control's ID. That helper has a `GetDlgCtrlID` fallback.
- At `0x0045D558`–`0x0045D5D9`, it passes `EBX` as `lParam`, the helper result
  as `wParam`, message `0x0594`, and the parent HWND to `PostMessageW`.

In `FUN_00422430`, `ECX` is saved as `this` at `0x00422431`. The handler does
not load either message parameter from its entry stack frame. Instead, at
`0x0042246C`–`0x0042247C` it calls `SendMessageW` on `[this+0xAC]` with
message `0x110A`, `wParam=9`, and `lParam=0`. The return value in `EAX` is
compared with each generated-list payload's first DWORD at
`0x00422490`–`0x00422494`.

The linked collection is reached through `[this+0x1B0]` at `0x00422482`–
`0x00422488`. On a token match, the handler loads the payload's `+0x10`
ordinal into `ESI` at `0x00422513`, then stores it in the active configuration
field `+0x213C` at `0x004224AD`. If there is no match, it uses `-1` as the
ordinal. Thus the handler resolves the current selection through the child
query and generated list; it does not resolve `wParam` or `lParam` to a row.

## Generated candidate list and constructor context

`FUN_00422AF0` builds an ordered vector of 24 localized LED-label candidates
at `0x0062B690`–`0x0062B6EF`, using one of the `tc_eft%d`, `tc_led_mode%d`,
or `tc_led%d` key families. `FUN_00422DA0` calls that builder at
`0x00422DC7`, then walks the vector. The loop counter starts at zero
(`0x00422E31`) and advances once per candidate (`0x00422F81`). For each
candidate not skipped by the `LedMask` test at `0x00422E4D`–`0x00422E57`,
the builder requests an entry from the child control at `0x00422F04`–
`0x00422F09`, allocates a payload, stores the returned selection token at
payload `+0` (`0x00422F22`–`0x00422F29`), and stores the zero-based candidate
ordinal at payload `+0x10` (`0x00422F22`–`0x00422F37`). It appends the payload
to the collection at `this+0x1A0` through `FUN_0043E7B0` at `0x00422F4D`;
that collection's head is at `this+0x1B0`.

The constructor at `0x004210C0` initializes a member object at `this+0x8C`;
it writes vtable pointer `0x005D9094` at `0x0042110A`. The existing RTTI/vtable
audit identifies `0x005D9094` as `CTreeCtrlExRk`. Its HWND field at child
offset `+0x20` is `this+0xAC`, the same child queried by the `0x0594`
handler. This is constructor/type context for the selection container. It
does not provide a numeric control ID or a per-label control-ID assignment.

The static source-control and creation-ID path is resolved separately in the
[tree-control/row-token follow-up](rk-406-led-0594-tree-control-row-token-followup.md): the child is a `SysTreeView32` control created with ID `0x0105`, and localized choices are `HTREEITEM` rows. That identifies the source widget, but does not turn the window ID into a row or effect identifier.

The candidate ordinal is a position in the generated label vector, not proof
that a localized string was rendered visibly: the code can skip entries by
`LedMask`, and runtime window state is not observed here. No static edge ties
the producer's `GetDlgCtrlID` result to a payload token, ordinal, individual
label, resource ID, or `LedOptN` key. The resource inventory also does not
provide a per-row control-ID crosswalk for these runtime-generated entries.

## Evidence limits and related audits

The producer and handler instructions establish a static code path and the
handler's data flow. They do not prove which runtime window instance posts the
message, the numeric control ID returned on a running system, that a click is
delivered, or any device-side result.

- [4.06 LED selection UI-to-worker boundary](rk-406-led-selection-ui-to-worker-followup.md)
- [4.06 LED label/control candidates](rk-led-control-candidates-4.06.md)
- [MFC tree-control message producer and RTTI evidence](rk-macro-capture-path-audit.md)
- [Dialog-resource inventory and limits](rk-dialog-resource-audit.md)
- [Lighting profile records and `LedOptN` loader](rk-lighting-profile-record-path-audit.md)
