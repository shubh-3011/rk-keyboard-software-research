# RK 4.6 `CLedDlg` message map and selection-to-worker path

## Scope and evidence boundary

This static follow-up examines the `CLedDlg` MFC message map and the
position-selection messages that reach the settings worker in the 4.6-labeled
`DeviceDriver.exe`. The input is the 2,418,176-byte x86 PE with SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`.
Addresses are preferred-image-base VAs for that exact file.

The executable was read as PE bytes and disassembly. RK software was not
launched, no HID/device interface was opened, and no report or command was
sent. A mapped message and call path prove the static code/data relationship;
they do not prove that MFC dispatches it at runtime or that a keyboard accepts
any resulting payload.

The hash-pinned decoder is
[`audit_rk46_cleddlg_message_map.py`](../scripts/audit_rk46_cleddlg_message_map.py),
and its 15-row output is
[`rk-v4.6-cleddlg-message-map.csv`](rk-v4.6-cleddlg-message-map.csv).

## Message-map owner and structure

The accessor at `0x004234D0` returns descriptor `0x005D5640`. That descriptor
contains base-map getter `0x00481025` and entry-array pointer `0x005D54C0`; the
base getter returns `0x005A8224`. The entry array consists of 15 six-DWORD,
24-byte MFC-shaped rows and an all-zero terminator at `0x005D5628`.

The RTTI Complete Object Locator at `0x005ED0C0`, reached from the vtable
preceding the `GetMessageMap` slot, points to type descriptor `0x0061A1B0`.
Its decorated name is `.?AVCLedDlg@@`. This ties the recovered map to
`CLedDlg` in this PE rather than inferring the owner from nearby strings.

| Message | Handler | Static identification |
| --- | ---: | --- |
| `WM_ERASEBKGND` (`0x0014`) | `0x0044B310` | Background handler |
| `WM_PAINT` (`0x000F`) | `0x00423550` | Paint handler |
| Private `0x0477` | `0x004276A0` | Message purpose unresolved |
| Private `0x0800` | `0x004240A0` | Row-update/refresh route, also covered by the brightness follow-up |
| Private `0x0801` | `0x00424130` | Selector/display route, also covered by the brightness follow-up |
| Private `0x0481` | `0x00424660` | Per-position mapping toggle |
| Private `0x0482` | `0x00424570` | Apply current mapping to selected positions |
| Private `0x05C7` | `0x004244A0` | Shared handler; exact purpose unresolved |
| Private `0x0594` | `0x00424340` | Mode-selection handler, also covered by the brightness follow-up |
| Private `0x08B3` | `0x00427220` | Message purpose unresolved |
| Private `0x043E` | `0x004244A0` | Shared handler |
| Private `0x0461` | `0x004244B0` | Shared handler with `0x05D1` |
| Private `0x05D1` | `0x004244B0` | Shared handler |
| `WM_LBUTTONDOWN` (`0x0201`) | `0x0045F7D0` | Mouse handler |
| `WM_TIMER` (`0x0113`) | `0x00427380` | Handles timer `0x0882` |

The 4.06 `CLedDlg` map has 14 recovered entries; this 4.6 table adds a
`WM_TIMER` entry. That is a static map difference, not evidence that the timer
is installed during an ordinary user session.

## Position-selection message producers

Two `PostMessageW` callsites carry the private messages into the parent-window
path:

| Callsite | Message | `wParam` | `lParam` | Evidence |
| --- | --- | --- | --- | --- |
| `0x00418ACB` | `0x0482` | `0` | `0` | `GetParent` at `0x00418AAE`; the returned wrapper's `+0x20` value is passed as `HWND`. |
| `0x00418B5A` | `0x0481` | `[ESI+0x80]` | `0` | Same parent/wrapper path; the code then invalidates the child window stored at `ESI+0x20`. |

These callsites and the `CLedDlg` map support a parent-notification path from a
position-selection control. The runtime identity of the parent `HWND`, the
child resource ID, and the exact user action are not recovered. A separate
`push 0x0481` at `0x0057251F` is the flags argument to `RedrawWindow`, not a
message send; the IAT resolves that call to `USER32!RedrawWindow`.

## Handler state changes and deferred apply

Handler `0x00424660` for message `0x0481` uses the supplied position/mapping
value to select a row in the 132-position structure. It toggles the value in
the row field at `+0xA4`, refreshes the page through `0x00427530`, updates a
dirty-bit mask at object offsets `+0x45A0/+0x45A4`, and calls the settings
queue helper `0x00401100` with value `4` when global `0x0062A234` permits it.
It then calls `0x00460DA0` with the configured path value. The latter helper
persists profile data to a local `pro.dct` file; that host-file write is not a
keyboard write.

Handler `0x00424570` for message `0x0482` walks the current selected-position
list, resolves eligible rows within the 132-position bound, and writes the
current mapping value into each row's `+0xA4` field. It refreshes the view,
sets the same dirty-bit family, and conditionally queues value `4` at
`0x00424637`, then reaches the same `pro.dct` persistence helper. The direct
`0x0481` queue call is at `0x00424786`. The UI-to-worker edge is therefore
proven statically for both handlers, subject to the `ApplyNow` gate and normal
MFC reachability.

The shared worker at `0x00401290` dispatches the queued value through the
active device object's vtable slot `+0x44`. For a `CDevG5KB` instance, value
`4` reaches the flag-`0x04` route, which can serialize group/key RGB records
through operation `1`, command `6`, when its selected-profile guard passes.
The nested `CDev3632` route uses selector `2`. In `CDevRKKB`, queued value `4`
also satisfies the `mask & 0x14` matrix-information branch, which constructs a
buffer beginning `03 7E` and chooses length `0x81` or `0x17D` before the
family writer. The active family and branch guards at runtime are unknown, and
the three family paths do not establish the same protocol semantics or
hardware effect.

## Timer `0x0882`

The added `WM_TIMER` entry targets `0x00427380`. That handler compares the
timer ID with `0x0882`, kills that timer on the window at `this+0x20`, sends
message `0x110A` with `wParam=9` to the window at `this+0xAC`, and searches a
linked collection before optionally invoking helpers `0x00462DA0` and
`0x00426B30`. A static setter at `0x004274A0` creates timer `0x0882` with
interval `0x0BB8` (3,000 ms) behind several global state checks. This recovers
the timer ID, interval, and handler route; the timer's user-visible purpose
and runtime activation are unresolved.

## Remaining limits

- The MFC message signature values are recorded as compiled; their symbolic
  MFC enum names are not established.
- No resource ID or localized label has been tied to the position-selection
  child that sends `0x0481`/`0x0482`.
- The meaning of row field `+0xA4` and each mapping value remains unresolved.
- A static mode-4 route does not demonstrate worker scheduling, active-family
  selection, transport success, or keyboard acceptance.
- This closes one 4.6 UI-to-worker path and adds a message-map delta. It does
  not complete all UI handlers, APIs, package versions, model/revision
  mappings, protocols, or the full RK software suite.
