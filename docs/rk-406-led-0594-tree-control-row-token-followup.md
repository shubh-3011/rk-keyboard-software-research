# RK 4.06 LED `0x0594` source tree-control crosswalk

## Scope and exact image

This static follow-up resolves the source control behind the candidate
`WM_LBUTTONDOWN` producer for `CLedDlg` message `0x0594`, and distinguishes
the control ID from the generated LED rows. The image is the installed x86
`DeviceDriver.exe`, SHA-256
`C03F88BC4E2D78AA4392D7445B0FD62182DC824F97F5D5DB40BD009E547A9AB6`.
Addresses below are image virtual addresses for that hash. No RK software was
run, and no keyboard, HID, or other device interface was opened or contacted.

## The producer's source is the `CLedDlg` tree control

The `CLedDlg` constructor at `0x004210C0` initializes the member at
`this+0x8C` through `FUN_0045B9C0` (`0x004210FF`), then writes vtable
`0x005D9094` at `0x0042110A`. The existing vtable/RTTI audit identifies this
as `CTreeCtrlExRk`; its HWND field at `+0x20` is the parent dialog's
`this+0xAC` field queried by the `0x0594` handler.

The corresponding initialization routine begins at `0x00423110`; it saves
its incoming `ECX` (`this`) in `EDI` at `0x00423142`. It constructs the tree
member as one child window:

1. At `0x0042335D`, `ESI` becomes `EDI+0x8C`. The code then sets `ECX=0x105`
   at `0x00423366`, `EAX=ESI`, `EDX=EDI`, and calls `FUN_0045D2D0` at
   `0x0042336F`. The offsets match the constructor's tree member and the
   parent dialog object.
2. `FUN_0045D2D0` saves the supplied ID and parent, then dispatches the child
   vtable slot `+0x13C` with style `0x50000027`, a geometry pointer, parent,
   and ID. For vtable `0x005D9094`, slot `+0x13C` is `FUN_0045E010`.
3. `FUN_0045E010` forwards the style, geometry, parent, and ID to
   `FUN_0047D8B1` at `0x0045E179`–`0x0045E19A`. The latter supplies class
   string `0x005A1794`, whose UTF-16 value is `SysTreeView32`, and forwards
   the parent and ID to the child window-creation wrapper at vtable slot
   `+0x54`. Its `0x00473D5F` target consumes the ID argument and passes it
   through the next creation wrapper.

Therefore the statically recovered source is one dynamically created
`SysTreeView32` child owned by `CLedDlg`, with `0x0105` supplied as its
creation control ID. It is not one window per LED effect. The call at
`0x0045D340` is the `CTreeCtrlExRk` `PreTranslateMessage` override (vtable
slot `+0x108`); for its `WM_LBUTTONDOWN` branch (`0x0045D4B8` onward),
`FUN_00478901` supplies the source control ID and the producer posts message
`0x0594` to the resolved parent at `0x0045D555`–`0x0045D5D9`.

`FUN_00478901` calls `GetDlgCtrlID` on the source HWND when its wrapper field
`this+0x50` is null; if non-null, it delegates to that wrapper's virtual slot
`+0x90`. The creation path statically supplies ID `0x0105`, but this audit
does not observe a live window or the producer's runtime `wParam`; the
alternate wrapper return path is retained as a runtime/value limit.

## Generated LED labels are tree items, not child controls

`FUN_00422AF0` builds the ordered 24-candidate localized label vector at
`0x0062B690`–`0x0062B6EF`. `FUN_00422DA0` iterates that vector and tracks a
zero-based candidate ordinal. At `0x00422EF1`–`0x00422F09`, it calls
`FUN_0047D9F2` on the tree control for the current candidate entry.
`FUN_0047D9F2` builds the item structure and sends message `0x1132` to the
tree HWND at `0x0047DA30`–`0x0047DA6A` (`TVM_INSERTITEMW`). The returned tree
item handle (`HTREEITEM`) is stored as the generated-row payload's first DWORD
at `0x00422F29`; its candidate ordinal is stored at payload `+0x10` at
`0x00422F37`. Candidates skipped by the `LedMask` branch do not take this
row-construction path.

The `0x0594` handler at `0x00422430` ignores its entry `wParam` and `lParam`.
It queries the tree with `SendMessageW(0x110A, 9, 0)` at
`0x0042246C`–`0x0042247C` (`TVM_GETNEXTITEM` with `TVGN_CARET`), compares the
selected `HTREEITEM` against payload first DWORDs, and takes the matched
payload's `+0x10` ordinal at `0x00422513`. The ordinal is then stored in the
configuration field at `+0x213C` (`0x004224AD`). The selection identity is
thus the item handle and its associated ordinal; the window's control ID
identifies the tree containing those items.

## Resource and profile mapping limits

The resource inventory lists `DeviceDriver.exe` resource ID `105`, language
`2052`, as an empty dialog template with zero declared controls. That is a
numeric collision with the dynamically assigned child control ID, not a
resource-template declaration of this tree or of any LED row.

This trace binds the producer to the tree control and the generated row
payload to an `HTREEITEM` plus candidate ordinal. The vector's candidate slot
and the loop ordinal advance together, but the source control ID does **not**
identify an individual label, row, or `LedOptN` entry. The separate
profile-table path indexes `LedOpt` data using the selected ordinal; it does
not make the tree's control ID an option index. This report does not identify
an ordinal as a firmware effect ID or prove that a particular label is
visible at runtime.

## Evidence limits and related audits

These are static instruction and resource observations for the pinned image.
They establish a candidate code path, not a runtime click, message delivery,
actual `wParam` value, UI appearance, profile selection, or device-side
effect.

- [4.06 LED `0x0594` parameter and generated-row audit](rk-406-led-0594-parameter-and-generated-row-audit.md)
- [4.06 LED selection UI-to-worker boundary](rk-406-led-selection-ui-to-worker-followup.md)
- [4.06 LED label/control candidates](rk-led-control-candidates-4.06.md)
- [Lighting profile records and `LedOptN` loader](rk-lighting-profile-record-path-audit.md)
- [Dialog-resource inventory and limits](rk-dialog-resource-audit.md)
- [MFC tree-control message producer and RTTI evidence](rk-macro-capture-path-audit.md)
