# RK updater timer-origin static audit

## Scope and method

This audit checks timer creation references in the pinned `Dev/01AF/Update.exe`
x86 image, SHA-256
`27894463b0dfe5bc3f5dc19d4d3351d9dfb692c402bf277bde3889d37e4a206c`.
The file analyzed was the preserved static input at
`../_rk_analysis/inputs/Update.exe`; its hash matches the pinned installed
image. Evidence comes from `objdump` disassembly and the
[`rk-native-api-xrefs.csv`](rk-native-api-xrefs.csv) import-reference ledger.
The executable was not launched. No HID or serial interface was opened and no
device command was sent.

Labels used below:

- **Direct** means the instruction, operand, or branch is present in the
  binary.
- **Inferred** means the interpretation follows from call arguments or local
  data flow but was not observed at runtime.
- **Unresolved** means this static evidence does not establish the fact.

## The dialog timer consumer

**Direct:** the updater dialog's recovered `WM_TIMER` handler is
`0x00409950`. Its `wParam` branches handle timer IDs 2, 3, and 4. ID 2 can
kill timer 2 at `0x0040996B` or call `0x00409760`; ID 3 can kill timer 3 at
`0x00409A15` before creating worker `0x00406BD0`; ID 4 calls
`0x0040A580`. The handler and its update consequences are mapped in the
[command `0x0419` audit](rk-updater-command-0419-static-path-audit.md).

The command handler `0x00409DC0`, its first worker `0x00406AE0`, the
follow-on worker `0x00406BD0`, and dialog initialization `0x00407020` have no
direct `SetTimer` call. The full import-reference scan below finds no
window timer with a statically resolved ID of 2, 3, or 4. The two null-HWND
callback timers have dynamic `nIDEvent` values but their callback path is
distinct from the dialog handler. Therefore, the static evidence does not
show how the handler's low-numbered IDs are scheduled.

## SetTimer import-reference inventory

The import ledger records 29 executable references to `USER32!SetTimer`:
28 direct calls through the IAT at `0x00560610`, plus one non-call operand
reference. That additional reference is the instruction at `0x004B8493`
loading the IAT pointer into ESI; its operand begins at `0x004B8495`. The
cached pointer is called at `0x004B84CA` with timer ID `0xEC14` and at
`0x004B8549` with timer ID `0xEC13`.

The 28 direct-call sites from the ledger were inspected. Two are callback
timers with a null HWND and callback address `0x00425CD8`:

| Call site | Timer arguments visible in the call setup | Assessment |
| --- | --- | --- |
| `0x00426729` | HWND is EBX, initialized to zero at `0x004266B0`; nID is `[esi+0xC8]`; callback is `0x00425CD8`. | **Inferred:** a thread callback timer, not a window `WM_TIMER` route to the updater dialog. |
| `0x00427A5B` | HWND is literal zero; nID is `[esi+0xC8]`; callback is `0x00425CD8`. | **Inferred:** a thread callback timer, not a window `WM_TIMER` route to the updater dialog. |

The callback routine at `0x00425CD8` ends with `ret 0x10` at `0x00425CF9`,
consistent with a four-argument timer callback.

The other 26 direct calls pass window-like HWND members and timer IDs in the
`0xEC00`–`0xEC1D` family. This includes the cases requiring data-flow
resolution:

- `0x0047EE79` takes its ID from `[ebp+8]`. Its three in-image callers pass
  `0xEC0A` (`0x0047ECB3` and `0x0047EF13`) or `0xEC09` (`0x0047ED0E`).
- `0x004BFE5E` passes EBX, initialized to `0xEC17` in that routine.
- `0x004CFEE7` passes EBX, initialized to `0xEC12` in that routine.
- `0x004FF391` passes EDI. The only branch reaching this call first sets
  EDI to `0xEC1B` at `0x004FF2C2`; the intervening code does not overwrite it.
- `0x005062AF` computes the ID as `0xEC01` plus a Boolean value, so the two
  statically possible values are `0xEC01` and `0xEC02`.
- Other direct calls use immediate IDs from the same `0xECxx` range, including
  `0xEC00`, `0xEC03`–`0xEC0D`, `0xEC11`–`0xEC1A`, and `0xEC1C`–`0xEC1D`.

**Finding:** among all references to the imported `SetTimer` in this image,
none schedules a window timer with ID 2, 3, or 4. The two calls with dynamic
IDs use a nonzero timer callback and null HWND; the window-associated dynamic
IDs resolve to the `0xECxx` family. This narrows the timer-origin gap in the
command and progress-control audits.

## Limits

- **Proven statically:** this image's imported `SetTimer` references contain
  no identified window-timer creation for IDs 2, 3, or 4; the 28 direct-call
  sites and the one cached-pointer reference are accounted for above.
- **Inferred:** the two null-HWND calls use callback-based thread timers and
  therefore do not dispatch their expirations as the dialog's `WM_TIMER`
  handler.
- **Unresolved:** who schedules or delivers IDs 2, 3, and 4 to
  `0x00409950`, whether an indirect mechanism outside the imported
  `SetTimer` references is involved, which object owns the other window timer
  IDs, and which timer branches occur at runtime.

This is a static code-coverage result, not evidence that any timer was armed
or that a keyboard was contacted.

## Related audits

- [Updater command `0x0419` UI-to-worker trace](rk-updater-command-0419-static-path-audit.md)
- [Updater progress-control audit](rk-updater-progress-control-audit.md)
- [Updater dialog resources and selected handlers](rk-dialog-resource-audit.md)
- [Native API import and reference ledger](rk-native-api-xrefs.csv)
