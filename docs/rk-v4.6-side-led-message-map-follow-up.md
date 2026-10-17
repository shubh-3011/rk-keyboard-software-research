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
formats a local path using the `pro.dct` literal at `0x005E1814`, opens the
result with a file API, and performs a write through an indirect API call.
This supports local profile persistence. No direct call from the candidate
Side LED callbacks to `0x00412060` was found in the inspected call bodies.
The report-builder route is consequently a data-flow connection through
shared device-object state; whether a UI change triggers that builder
immediately, on a timer, or through another callback remains unresolved.

## Findings and remaining uncertainty

### Proven statically

- `CSideLedDlg` returns a descriptor at `0x005E1138`; its entries pointer is
  `0x005E1030`.
- The entry block decodes as ten standard 24-byte message-map entries and an
  all-zero terminator, with message values, signature codes, and handler
  addresses listed above.
- Multiple executable targets update the Side LED dialog's control-derived
  state and converge on `0x0045F660`.
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
