# RK DeviceDriver 4.6 Side LED message-map follow-up

## Scope and safety

This is an offline static follow-up to
[`rk-v4.6-side-led-static-audit.md`](rk-v4.6-side-led-static-audit.md).
It inspects only the hash-pinned 4.6 `DeviceDriver.exe`
(`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`)
with PE section data and disassembly. The application was not launched, and no
HID, serial, updater, bootloader, or other device interface was opened. This
note contains no vendor artwork or copied binary code.

Addresses are preferred-base VAs (`ImageBase = 0x00400000`). `Proven` below
means supported by static bytes and control/data references; it does not mean
the path ran or that firmware accepted a report.

## Message-map descriptor and candidate records

`0x0045D4C0` is a two-instruction accessor: it loads `0x005E1138` into `EAX`
and returns. The two DWORDs at `0x005E1138` are `0x00481025` and
`0x005E1030`. The function at `0x00481025` returns `0x005A8224`, consistent
with the base-map getter shape used by the neighboring MFC message maps.

The pointed-to block at `0x005E1030` is a conventional array of ten
six-DWORD (`0x18`-byte) `AFX_MSGMAP_ENTRY` records, followed by an all-zero
terminator at `0x005E1120`. The fields decode in MFC order as
`nMessage, nCode, nID, nLastID, nSig, pfn`:

| Entry VA | `nMessage` | `nCode` | `nID`–`nLastID` | `nSig` | Handler (`pfn`) | Static observation at handler |
| --- | ---: | ---: | --- | ---: | --- | --- |
| `0x005E1030` | `0x0014` (`WM_ERASEBKGND`) | `0` | `0`–`0` | `0x0001` | `0x0044B310` | Returns `1`, the handled-background result. |
| `0x005E1048` | `0x000F` (`WM_PAINT`) | `0` | `0`–`0` | `0x0013` | `0x0045D4F0` | Uses drawing/geometry helpers; consistent with a custom paint path, but no visual runtime was inspected. |
| `0x005E1060` | `0x0800` (`WM_USER+0x0400`) | `0` | `0`–`0` | `0x000E` | `0x0045DC40` | Calls `0x0045DC90`, then `0x0045F660`; may persist state through `0x00460DA0`. |
| `0x005E1078` | `0x0801` (`WM_USER+0x0401`) | `0` | `0`–`0` | `0x000E` | `0x0045DC90` | Processes message parameters and branches on `0x97`/`0x98`; then invokes control helpers. |
| `0x005E1090` | `0x05C7` (`WM_USER+0x01C7`) | `0` | `0`–`0` | `0x000E` | `0x004244A0` | Returns `1` immediately. |
| `0x005E10A8` | `0x0594` (`WM_USER+0x0194`) | `0` | `0`–`0` | `0x000E` | `0x0045DDC0` | Updates global/control state, calls `0x0045F350`, and then `0x00460DA0`. |
| `0x005E10C0` | `0x043E` (`WM_USER+0x003E`) | `0` | `0`–`0` | `0x000E` | `0x0045DE80` | Iterates seven child controls, updates selection state, then calls `0x0045F660`. |
| `0x005E10D8` | `0x0461` (`WM_USER+0x0061`) | `0` | `0`–`0` | `0x000E` | `0x0045DFA0` | Stores a passed value to a child-control field, updates state, and calls `0x0045F660`. |
| `0x005E10F0` | `0x05D1` (`WM_USER+0x01D1`) | `0` | `0`–`0` | `0x000E` | `0x0045DFA0` | Same handler as the preceding entry. |
| `0x005E1108` | `0x0201` (`WM_LBUTTONDOWN`) | `0` | `0`–`0` | `0x0035` | `0x0045F7D0` | Updates control/global state and forwards a synthesized message through a window procedure. |

The table's record boundaries, standard field layout, executable handler
pointers, and all-zero terminator are directly visible in the PE. The numeric
`nSig` values are recorded as compiled; handler stack cleanup is consistent
with their expected call shapes (for example, `0x0044B310` cleans up one
4-byte argument, the `0x000E` handlers generally clean up two, and
`0x0045F7D0` cleans up three). The exact MFC signature enum names are not
recovered here. Message values in the `WM_USER` range are application-defined;
their symbolic meanings are not present in the recovered evidence.

## Selection state to report-builder data

There is a static data path from the selection-like callback routines to the
record shape consumed by the Side LED report builder:

1. Candidate callbacks `0x0045DC40`, `0x0045DE80`, and `0x0045DFA0` call
   `0x0045F660`. `0x0045DDC0` reaches the same UI state area through
   `0x0045F350` and then saves profile state.
2. `0x0045F660` reads child controls rooted at `this + 0x1D80`, resolves the
   active device object through global pointer `0x00647328`, and addresses a
   36-byte-stride record array rooted at device-object offset `+0x5D90`. It
   writes control-derived bytes into that record family (including offsets
   `+0x04` through `+0x08`). This supports selection-to-in-memory-state flow;
   it does not identify the semantic names of each byte.
3. `0x00412060` uses the same device-object `+0x5D90` record family while
   building a report. At `0x004122D7` it checks the parsed `ShowSideLED` byte at
   `0x0062A2C8`. With the feature enabled, it reads the selected option data
   and copies bytes into report-buffer offsets `+0x28` through `+0x2B` at
   `0x00412300`–`0x00412329`. The selection routine and report builder therefore
   meet at the same object-relative record array, although an exact selected
   index-to-option relationship and each byte's meaning are still unresolved.
4. The report-builder caller at `0x00412D0D` then iterates report records and
   calls `0x00410290`; the existing Side LED audit traces that path through
   `0x0040FFD0` to the `HidD_SetFeature` import. This is a generic feature
   report path, not proof of a Side-LED-specific report ID or device response.

Several candidate callback bodies also call `0x00460DA0`. Its static path
formats a local path with `%s%04X\\pro.dct` using the literal at
`0x005E1814` and opens it through `KERNEL32!CreateFileW` at `0x00460E25` with
`GENERIC_READ | GENERIC_WRITE`, share mode `3`, `CREATE_ALWAYS`, and normal
file attributes. If its initial scan of the list at global `0x00619DCC` finds
at least one eligible object, it traverses the list and writes `0x5F14` bytes
from each eligible object pointer through `KERNEL32!WriteFile` at
`0x00460EA8`. Before that write, when object field `+0x423C` equals `0x1E`,
it replaces that DWORD with the zero-extended byte at global `0x0062B811`. It
closes the file handle after processing the list. This is host-local
profile-state persistence; the runtime base path and the file-record schema
are unresolved.

## Message-map handlers to the deferred settings worker

The message-map table also closes part of the UI-callback-to-worker gap. Four
handler paths, across five message-map entries, converge on settings request
value `2` after updating Side LED dialog or shared selection state:

| Handler | Message-map entry | State work before enqueue | Request route |
| --- | --- | --- | --- |
| `0x0045DC40` | `WM_USER+0x0400` (`0x0800`) | Calls `0x0045DC90` with message parameters, then `0x0045F660` to rebuild shared state from the controls. | If `[OPT] ApplyNow` is nonzero, pushes `2` to `0x00401100` at `0x0045DC67`; then calls `0x00460DA0`. |
| `0x0045DDC0` | `WM_USER+0x0194` (`0x0594`) | Updates global/control state, sends message `0x110A` with `wParam=9`, resolves the result against the dialog list, stores the resulting value at candidate device offset `+0x5D90`, and calls `0x0045F350`. | If `[OPT] ApplyNow` is nonzero, pushes `2` to `0x00401100` at `0x0045DE57`; then calls `0x00460DA0`. |
| `0x0045DE80` | `WM_USER+0x003E` (`0x043E`) | Iterates seven child controls and updates their selection state, processes a pending child value when present, resolves message `0x110A`, then calls `0x0045F660`. | Inserts value `2` directly through `0x0043E6C0` at `0x0045DF36`, then releases the worker semaphore at `0x0045DF45`. This is an inline producer, not one of the 24 direct calls to `0x00401100`. |
| `0x0045DFA0` | `WM_USER+0x0061` (`0x0461`) and `WM_USER+0x01D1` (`0x05D1`) | Stores the passed value in the first child control, invalidates that control, resolves message `0x110A`, then calls `0x0045F660`. | If `[OPT] ApplyNow` is nonzero, pushes `2` to `0x00401100` at `0x0045E000`; then calls `0x00460DA0`. |

The inline route uses the same queue global `0x006356D8`, queue insertion
helper `0x0043E6C0`, and semaphore global `0x006356C4` as the `0x00401100`
wrapper. After signaling, that handler checks active-device global
`0x00647320` and follows a separate virtual slot `+0x28` path. This does not
identify that slot's semantic name or prove it is the same device object as
the `+0x5D90` object used by the dialog's selection update.

The worker at `0x00401290` drains the queued DWORD and, for an active device
that passes its connection checks, dispatches the request through virtual
slot `+0x44`. The verified G5 table resolves that slot to
`CDevG5KB::ApplySetting` at `0x004127B0`; its `nFlag & 0x02` branch reads and
transforms a 128-byte LED/profile block before a command-4 writer call (see
the [G5 settings audit](rk-v4.6-cdevg5-settings-and-vtable-audit.md)). This
establishes a static Side LED-dialog-message → request value `2` → family-
virtual-apply path, conditional on the option and worker checks. It does not
prove the runtime active family, that `nFlag=2` means Side LED on every family,
that report builder `0x00412060` is invoked by these handlers, or that a
keyboard receives or accepts the resulting report. The dialog-state pointer
`0x00647328` and worker active-device pointer `0x00647320` remain distinct.

No direct call from the candidate Side LED callbacks to `0x00412060` was
found in the inspected call bodies. The report-builder route is consequently
a data-flow connection through shared device-object state; whether a UI
change triggers that builder immediately, on a timer, or through another
callback remains unresolved.

## Findings and remaining uncertainty

### Proven statically

- `CSideLedDlg` returns a descriptor at `0x005E1138`; its entries pointer is
  `0x005E1030`.
- The entry block decodes as ten standard 24-byte message-map entries and an
  all-zero terminator, with message values, signature codes, and handler
  addresses listed above.
- Multiple executable targets update the Side LED dialog's control-derived
  state and converge on `0x0045F660`.
- The four handler paths listed above (five message-map entries, because
  `0x0045DFA0` handles two) request deferred settings value `2` through the
  shared worker queue (three through `0x00401100`, one through the
  queue-insert/semaphore sequence inline).
- The UI state record family rooted at device-object offset `+0x5D90` is also
  consumed by report builder `0x00412060` when `ShowSideLED` is enabled.
- Candidate callbacks that invoke `0x00460DA0` also persist a local
  `pro.dct` file. That call alone is not evidence of a keyboard write.

### Not established

- The exact MFC signature enum names for `nSig` values `0x01`, `0x13`, `0x0E`,
  and `0x35`.
- Which application-defined message value corresponds to a Side LED selector
  action, brightness or speed change, apply/save button, or another UI event.
- Whether the UI callback path immediately schedules or invokes the generic
  report-builder caller at `0x00412D0D`; no direct static call edge from the
  candidate callback bodies to that caller was recovered.
- The semantics of each state byte, the final on-wire report layout, and any
  physical keyboard response.

## Evidence source

The source PE is the local 4.6 package extraction at
`.research/rk4_6_official_extract_20261015/app/DeviceDriver.exe`; SHA-256 is
recorded above. Relevant static ranges are `0x0045D4C0`, `0x0045DC40`–
`0x0045DFA0`, `0x0045F660`, `0x00460DA0`, `0x00412060`–`0x00412359`,
`0x00412D0D`–`0x00412D54`, and `.rdata` at `0x005E1030`–`0x005E113F`.
