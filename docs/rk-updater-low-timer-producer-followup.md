# RK updater low `WM_TIMER` producer follow-up

## Scope and evidence

This offline follow-up searches for a static producer of `WM_TIMER` (`0x0113`)
with `wParam` 2, 3, or 4 for the updater dialog handler at `0x00409950`. The
target is the hash-pinned x86 `Dev/01AF/Update.exe`, SHA-256
`27894463b0dfe5bc3f5dc19d4d3351d9dfb692c402bf277bde3889d37e4a206c`.
The preserved input at `../_rk_analysis/inputs/Update.exe` has that hash.
Evidence is from GNU `objdump -d -M intel`, the checked-in API import/xref
ledger, the dialog message-map/resource analysis, and local read-only PE byte
searches. The updater was not launched. No window was created, no hardware
interface or serial port was opened, and no command was sent.

**Proven** means the instruction, argument, or data reference is present in
the pinned file. **Inferred** means the stated relationship follows from
static argument/data flow but was not observed at runtime. **Unresolved**
means this static evidence does not establish the route.

## Dialog consumer

**Proven:** the updater message map contains the `WM_TIMER` row for handler
`0x00409950`; the handler branches on IDs 2, 3, and 4. Its map is described in
the [dialog resource audit](rk-dialog-resource-audit.md), and its `SetTimer`
inventory is in the [timer-origin audit](rk-updater-timer-origin-static-audit.md).
The absolute little-endian pointer `0x00409950` occurs once in the pinned PE,
at `.rdata` VA `0x0059439C`, in that map. No direct code instruction was found
that calls the handler or loads it as a timer callback.

## Message-posting and send paths

**Proven:** the API ledger records 55 direct `PostMessageW` callsites and 623
direct `SendMessageW` callsites. I inspected the message argument setup around
those direct calls for an immediate `0x0113`; none pushes that message ID.
The updater's resolved direct `SendMessageW` calls in the `0x0040xxxx`
workflow send `PBM_SETPOS` (`0x0402`), button/checkbox messages such as
`0x00F0`, and other control messages, not `WM_TIMER`. The cached-IAT
`SendMessageW` call at `0x004084EA` also sends `0x0402` to the progress
control. These are static call arguments, not a claim that all dynamic
message values in the full UI framework have been resolved.

The two `PostThreadMessageW` callsites, `0x00428655` and `0x00517EA3`, post
message `0x036A` to the current thread. A thread message has no dialog HWND,
and the static message value is not `WM_TIMER`.

### Dialog-HWND serial notifier

This is the one updater-dialog posting route resolved through the serial
receive queue:

1. At `0x004091F6`–`0x004091F9`, setup routine `0x004091B0` passes the dialog
   HWND at `this+0x20` to helper `0x00404E60`.
2. Helper `0x00404E60` stores its HWND argument in global `0x005BB4F4` at
   `0x00404ECE` and stores message `0x0401` in `0x005BB4F8` at `0x00404ED9`.
3. Serial worker `0x00405430` posts using those fields at `0x004055E6` with
   `wParam=0`, `lParam=0`; worker `0x00405640` posts using them at
   `0x004057C6` with `wParam=1`.
4. The dialog map routes message `0x0401` to `0x00407E00`, the serial-queue
   handler. It is a distinct custom-message route from the `0x0113` row at
   `0x00409950`.

This proves that the dialog HWND is exposed to the serial notifier, but the
notifier's stored message is `0x0401`. It does not explain delivery of timer
IDs 2, 3, or 4.

## Timer callbacks and window-procedure forwarding

The `SetTimer` census accounts for 29 import references: 28 direct calls and
one cached-IAT operand. As detailed in the [timer-origin audit](rk-updater-timer-origin-static-audit.md),
the window-associated calls resolve to the `0xECxx` family; none is statically
shown creating window timer 2, 3, or 4. The two callback-style calls at
`0x00426729` and `0x00427A5B` pass a null HWND and callback `0x00425CD8`.
That callback ends with `ret 0x10`, has no direct `PostMessageW`,
`SendMessageW`, or `0x00409950` reference, and makes two virtual calls through
an object returned by `0x0040F1FB`. The virtual targets are not resolved here.
**Inferred:** these null-HWND callback timers do not themselves enqueue the
dialog's ordinary window `WM_TIMER` message. **Unresolved:** whether their
virtual-call side effects can indirectly reach another message producer.

`CallWindowProcW` has three direct sites. The calls at `0x0041DB15` and
`0x0041DBAA` are in window-procedure forwarding code; one passes
`WM_INITDIALOG` (`0x0110`), while the other forwards a caller-supplied message
parameter. The general forwarder at `0x0041AABB` also receives its message as
a parameter. These are dispatch/forwarding paths rather than timer-creation
calls. No callsite supplies literal `0x0113`; arbitrary caller-supplied
messages remain a static gap.

The `SetWindowLongW` GWL_WNDPROC sites install or restore window procedures,
including static targets `0x00419CA7` and `0x0041DA93`; none names
`0x00409950`. They may forward incoming messages, but their presence does not
establish a producer for timer IDs 2, 3, or 4.

## Result and limits

- **Proven:** no inspected direct `PostMessageW` or `SendMessageW` argument
  setup contains an immediate `WM_TIMER` message ID. The resolved
  dialog-targeted serial posts use message `0x0401`. `PostThreadMessageW`
  uses `0x036A`. The pinned image's imported `SetTimer` references have no
  identified window-timer creation for IDs 2, 3, or 4.
- **Inferred:** the known serial-post path and null-HWND timer callback path
  do not directly deliver the dialog's `WM_TIMER` handler.
- **Unresolved:** generic `SendMessageW`/window-procedure forwarding paths
  accept dynamic message values, some indirect IAT references have not been
  reduced to complete caller arguments, and the timer callback's virtual
  targets are unresolved. This pass therefore finds no provable producer,
  but does not prove that no dynamic, framework, or external producer can
  deliver those messages at runtime.

This finding narrows the gap; it does not identify when the three timer
branches execute. No runtime behavior or keyboard activity was tested.

## Related evidence

- [Updater timer-origin inventory](rk-updater-timer-origin-static-audit.md)
- [Updater command `0x0419` trace](rk-updater-command-0419-static-path-audit.md)
- [Updater UART receive state machine](rk-updater-uart-state-machine.md)
- [Updater dialog resource and message map](rk-dialog-resource-audit.md)
- [Native API import and xref ledger](rk-native-api-xrefs.csv)
