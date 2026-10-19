# RK 4.6 private message `0x0477` popup fanout

## Scope and evidence

This static follow-up joins the shared popup click handlers to the application
message-map rows for private message `0x0477` in the exact 4.6
`DeviceDriver.exe` (SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`). The
map rows are from the [hash-pinned MFC inventory](rk-v4.6-mfc-message-map-inventory.md);
sender parameters were checked against x86 disassembly and the `PostMessageW`
call at IAT VA `0x005A673C`.

No RK executable was launched and no device interface was opened. A message
map and static call edge establish code relationships, not runtime delivery
or the visible menu state.

## Shared popup senders

Two application-code sites contain the direct literal `PostMessageW`
sequence for `0x0477`:

| Popup class and click handler | Post site | Target HWND | `wParam` | `lParam` |
|---|---:|---|---|---|
| `CMenuDlg`, `WM_LBUTTONUP` handler `0x00435A00` | `0x00435A29` | `this+0x74` | First DWORD of selected `0x58`-byte row at `this+0x88+index*0x58` | `this+0x14D8` |
| `CMenuSrDlg`, `WM_LBUTTONUP` handler `0x00436660` | `0x0043668C` | `this+0x1E8` | First DWORD of selected `0x58`-byte row at `this+0x1F8+index*0x58` | `this+0x1328` |

Both handlers first reject the `index == -1` state. After posting, they call
the same popup/window cleanup helper `0x0047CA03`. The menu rows carry the
selected value in their first DWORD; this inventory does not identify every
row's user-visible label.

One direct relative-call edge creates a `CMenuSrDlg` through helper
`0x004360A0` at `0x00421EFB`. That creator writes zero to the new object's
`+0x1328` field before completing its window setup (`0x004361EB`); a later
click on that instance therefore posts `lParam=0`. The exact visible feature
represented by this instance and any alternate or indirect creation paths
remain unresolved. Separately, the known knob-option `CMenuDlg` creation at
`0x0041CEF0` supplies zero for `+0x14D8`; it also posts `lParam=0`.

## Receiver map and recovered behavior

The RTTI-attributed message-map inventory contains these `0x0477` receivers:

| RTTI-attributed page | Handler | Static behavior recovered |
|---|---:|---|
| `CKeyDlg` | `0x0041CF20` | Uses the selected value and has a distinct branch when the second message argument equals `2`. The known knob popup above sends zero, so it does not reach that branch. Other callers that produce `lParam=2` are not identified here. |
| `CLedDlg` | `0x004276A0` | If a shared popup object is active and the cleanup gate permits it, calls its virtual cleanup slots, clears the shared pointer, and returns handled. The body does not inspect the message arguments. |
| `CMacroDlg` | `0x0042DF90` | Enters a large private-message dispatcher. The exact menu selection action and the route from a popup row to a macro state change are not fully resolved. |
| `CScreenDlg` | `0x004752D0` | Branches on the first message argument: values zero and one call helper `0x00474C90` with the same value and page object. The helper's full relationship to every menu row is not established by this follow-up. |
| `CWelcomDlg` | `0x0046C400` | Stores the first message argument in global `0x00647320`, obtains the parent of its window, and passes that result to helper `0x0047CAA9` and routine `0x004495E0`. The resulting UI action remains unidentified. |

The map rows prove that these handlers are registered in the static MFC maps
associated with their RTTI/vtables. They do not prove that every popup
creation path targets each page. Existing screen/GIF and knob reports provide
additional feature-specific context; this report does not replace them.

## Findings and remaining gap

**Proven statically:** two shared popup click handlers post message `0x0477`
using the selected row value as `wParam` and an object-stored context as
`lParam`. The traced knob popup path stores context zero. `CScreenDlg` and
`CKeyDlg` have receiver branches with different parameter behavior, while the
`CLedDlg` handler performs popup cleanup.

**Unresolved:** the full set of indirect/dynamic popup creation paths, the
localized label and semantic meaning of every row, the complete `CMacroDlg`
and `CWelcomDlg` selection workflows, runtime owner-window relationships,
and the source of `CKeyDlg`'s `lParam=2` branch. The inventory is not proof
that message `0x0477` has only two senders under every encoding or wrapper.

## Reproduction ranges

For the pinned PE, inspect `0x00435A00`–`0x00435A36`,
`0x00436660`–`0x0043669A`, `0x004360A0`–`0x00436230`,
`0x0041CF20`–`0x0041D080`, `0x004276A0`–`0x004276DC`,
`0x0042DF90`, `0x004752D0`–`0x00475340`, and
`0x0046C400`–`0x0046C464`.
