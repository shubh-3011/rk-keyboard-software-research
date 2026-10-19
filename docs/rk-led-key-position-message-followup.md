# RK 4.06 key-position mapping message follow-up

## Scope and evidence

This offline static follow-up traces two private messages in the
RTTI-attributed `CLedDlg` message map of the installed 4.06
`DeviceDriver.exe`, SHA-256
`c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6`.
Addresses are image virtual addresses for that exact x86 executable. Evidence
comes from GNU `objdump -d -M intel`, the checked-in native API cross-reference,
the decoded MFC map ledger, and the apply-signal caller ledger. No RK software
was launched and no HID report or command was sent.

**Proven statically** means the instruction, table field, or direct data-flow
edge is present. **Inferred** means the interpretation depends on an indirect
window or object relationship. **Unresolved** means the available static
evidence does not establish the result.

## Message producers

The `CLedDlg` MFC map routes private message `0x0481` to `0x00422780` and
`0x0482` to `0x00422640` (map rows `0x005CD060` and `0x005CD078`, signature
`0x0E`). A full `.text` disassembly search found these immediate values in
two `PostMessageW` calls:

| Callsite | Posted message | `wParam` | `lParam` | Target setup |
| --- | --- | --- | --- | --- |
| `0x00417D3C` | `0x0481` | `[ESI+0x80]` | `0` | `GetParent` at `0x00417D1A`, then wrapper `0x004752FD` and its `+0x20` HWND field. |
| `0x00417CA7` | `0x0482` | `0` | `0` | `GetParent` at `0x00417C8A`, then wrapper `0x004752FD` and its `+0x20` HWND field. |

The source code around these calls maintains drag/selection state, enumerates
up to `0x84` position slots, and invalidates the child window. The target
comes from the parent-window lookup and a CWnd-like wrapper. **Inferred:**
these are notifications from a key-position selection control to a parent that
can dispatch the `CLedDlg` map. The precise child control, its resource ID,
and the runtime identity of the parent HWND are not recovered.

The other apparent `push 0x481` at `0x0056ADEA` is not a message producer.
It is the flags argument to `RedrawWindow`; the corresponding import is
identified in [`rk-native-api-xrefs.csv`](rk-native-api-xrefs.csv). This
distinguishes a numeric flag match from a Windows-message callsite.

## Handler effects

### Message `0x0481`

Handler `0x00422780` consumes the posted `wParam` as a position/mapping value
and checks it against the configured position limit at `0x006114D8`. It then
updates a record in the 132-entry structure rooted at the current page's
`+0x2C74` field. At record offset `+0x9C`, the value is toggled between zero
and the selected mapping value (loaded from the page state or global
`0x00612AF0`, depending on a guard). The handler refreshes page state through
`0x00425440`, marks a dirty bit using the page field at `+0x25C0`, sets the
Apply signal mode to `4` at `0x0061972C`, and releases semaphore
`0x00619724` at `0x004228AF`.

### Message `0x0482`

Handler `0x00422640` walks the current position list at
`current-page+0x2C74`, bounded by the configured count at `0x006114D4`. For
eligible list entries within the 132-position table, it writes the current
selected mapping value into each record's `+0x9C` field. It then refreshes
page state, marks the corresponding dirty bit, sets Apply signal mode `4`,
and releases the same semaphore at `0x00422710`.

**Proven statically:** both handlers mutate host-side page/mapping records and
signal the settings worker with mode `4`. This is a message-to-state-to-worker
route. It does not identify a protocol command, establish a color/lighting
meaning for record offset `+0x9C`, or prove that the worker selects a device
family writer for a specific profile.

## Remaining limits

- The static sender path reaches the parent HWND through `GetParent` and a
  wrapper, but the runtime HWND-to-`CLedDlg` relationship is not observed.
- The visible label, child control ID, mapping-value names, and precise user
  interaction that schedules each posted message remain unresolved.
- The relation between the `+0x9C` record field, visible LED controls, and
  family-specific HID serializers remains unresolved. This does not close the
  separate `LightUI` selector `0x95` or brightness control-to-writer gap.
- No UI behavior, worker execution, device response, or physical keyboard
  effect was observed.

## Related evidence

- [Recovered MFC message-map arrays](rk-mfc-message-map-audit.md)
- [UI control-to-command crosswalk](rk-ui-control-command-crosswalk.md)
- [Apply signal callers](rk-apply-signal-callers.csv)
- [Brightness UI handler audit](rk-lighting-brightness-ui-handler-audit.md)
- [Settings Apply worker](rk-settings-apply-worker-audit.md)
