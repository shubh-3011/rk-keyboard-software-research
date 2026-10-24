# S98 01BF updater: All Start to worker reachability

## Scope and artifact

This is a bounded static trace for the English-UK S98 Tri-mode RGB package
`S98-Tri-RGB-01BF-L10-20260527170338_1467.exe`. The package is 2,140,176 bytes;
its SHA-256 is
`475e8d7b97adfbd861c3b7b16721ad598df04095b81228e381319b6be23129e6`. Its
`.text` section SHA-256 is
`3643f4d710a296b62598d3d8b71c7dd9dcab049ebbb540588b11757ccd5f03ed`.

The updater was not launched. No HID interface was opened, no report was sent,
and no bootloader or firmware-write operation was performed. The conclusions
below describe static bytes and call/data flow only.

## UI resource and MFC mapping

PE resource `RT_DIALOG #102`, language 1028, is at RVA `0x001E62E8` (file
offset `0x001D8AE8`), size 1,672 bytes, SHA-256
`b6ced0626e42b9a5346c01e1e1fe2b00a97b5e8f23a5c20f4dad7d7ff0779c7b`. It is
an extended dialog titled `Update Tool` with 40 controls. Control ID 1 is the
button captioned `全部開始` (“All Start”).

The dialog's `GetMessageMap` routine at `0x00407350` returns map descriptor
`0x0058DC1C`. The descriptor names base map `0x00415EB6` and entry array
`0x0058DC28`. The row at `0x0058DC88` is the fifth 24-byte
`AFX_MSGMAP_ENTRY`:

```text
{ message=0x0111 (WM_COMMAND), code=0, id=1..1, signature=0x3A,
  handler=0x004096A0 }
```

This binds the resource button's command ID to handler `0x004096A0` in the
static MFC message map.

## Bounded static chain

1. Dialog initialization calls `0x00409DE0` at `0x00407C4F`. That routine
   initializes 16 per-slot records with stride `0x41C`, creates one event per
   slot using `CreateEventW` (IAT `0x0055A28C`), and passes worker callback
   `0x00409E50` plus a slot-record pointer into the thread factory at
   `0x0040C235`.
2. The All Start handler `0x004096A0` iterates over the 16 slots. Its branch
   checks the per-slot connection/status byte and status DWORD; eligible slots
   with zero status and an available dialog counter call setup routine
   `0x00409730` at `0x004096E1`.
3. `0x00409730` sets the per-slot state, prepares the per-slot object, loads
   its event handle at slot record `+0x418`, and calls `SetEvent` through IAT
   `0x0055A29C` at `0x004097DC`.
4. The thread factory constructs an MFC `CWinThread` wrapper. Its constructor
   stores the callback at object `+0x38` and callback parameter at `+0x34`.
   The start path passes wrapper entry `0x0040CB26` to the MFC
   `AfxBeginThread` helper at `0x00532290`; that helper calls imported
   `CreateThread` through IAT `0x0055A2F4`.
5. The MFC wrapper loads its saved callback and parameter from `+0x38` and
   `+0x34`, then invokes that callback indirectly at `0x0040CC23`. The stored
   app callback is `0x00409E50` with the per-slot record as its parameter.
6. `0x00409E50` waits indefinitely on the event handle at slot `+0x418` using
   `WaitForSingleObject` (IAT `0x0055A288`) at `0x00409ED9`. After the wait,
   the path calls `0x00401B30` at `0x00409F60`, which calls `0x00402010` at
   `0x00401C3E`.
7. `0x00402010` calls helper `0x00402880` at `0x004026FD`. The helper loads
   `HidD_GetFeature` from IAT `0x0055A1C8`, initializes a six-byte buffer with
   prefix `05 72`, and calls the API at `0x004028CD` and `0x004028F5`. The
   helper later builds a `05 77` report and calls `HidD_SetFeature` at
   `0x0040295A` through the loaded setter pointer.

**Reachability result:** yes. In this bounded static call/data-flow chain, the
newly mapped `HidD_GetFeature` helper at `0x00402880` is reachable from the
All Start command through slot setup, event signaling, and the event-waiting
worker callback. This is conditional static reachability, not evidence the
handler or worker actually ran.

## Reproduction

From the repository root, regenerate and verify the evidence ledger with:

```powershell
python scripts/audit_s98_01bf_start_worker_reachability.py `
  --binary ..\.research\rk-selector-software-2026-10-19\S98-firmware-packages\S98-Tri-RGB-01BF-L10-20260527170338_1467.exe `
  --out docs/rk-s98-01bf-start-worker-reachability-evidence-2026-10-24.csv
```

The verifier checks the whole-file and `.text` hashes, resource RVA/raw offset,
size and hash, dialog title/control, MFC map descriptor and row, 37 exact
instruction byte facts, nine direct call targets, and six IAT mappings. The
resulting [evidence CSV](rk-s98-01bf-start-worker-reachability-evidence-2026-10-24.csv)
contains 48 rows. The [verifier](../scripts/audit_s98_01bf_start_worker_reachability.py)
only reads the PE and writes the CSV.

## Runtime limits and unresolved points

Static analysis cannot establish that a device was present, the handler's
gates passed, event creation/signaling or thread creation succeeded, the worker
was scheduled, any HID call succeeded, or the device accepted or acted on the
reports. The meaning of the `05 72` read and `05 77` command fields remains
unresolved. This trace does not establish the full updater lifecycle, firmware
write behavior, all UI routes, or equivalence across the other S98 packages or
RK software families.
