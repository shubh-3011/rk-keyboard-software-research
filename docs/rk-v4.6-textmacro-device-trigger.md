# RK 4.6 text-macro device-report trigger path

## Scope and result

This static follow-up connects two `DeviceDriver.exe` device-read worker paths
to the previously identified host text-macro `SendInput` call. The examined
`CDev3632` and `CDevG5KB` workers parse selected reports and post private
message `0x07EB` to a window. The `COemDrvDlg` message-map handler decodes the
packed `WPARAM`, resolves a selected mapping cell tagged `0x0A00005B`, looks up
its macro record without allocating, and passes the record text to the host
input helper.

The input image is the 2,418,176-byte RK 4.6-labeled `DeviceDriver.exe`,
SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`.
The binary was read and disassembled only. The worker threads were not run;
no HID handle was opened, no message was delivered, and no OS input was sent.

The [81-instruction verifier](../scripts/audit_rk46_textmacro_device_trigger.py)
and [evidence ledger](rk-v4.6-textmacro-device-trigger.csv) pin the selected
instructions, imports, vtable entries, and raw MFC message-map row. The class
identity for each worker-start slot is linked to the existing
[CDev3632 vtable map](rk-v4.6-cdev3632-vtable-map.csv) and
[CDevG5KB vtable map](rk-v4.6-cdevg5-vtable-map.csv); the dialog message-map
owner comes from the existing
[MFC message-map ledger](rk-v4.6-mfc-message-map-entries.csv).

## Device-read workers and report decoders

### `CDev3632`

The `CDev3632` vtable slot `+0x0C` points to worker-resource setup
`0x0040DC60`. That routine passes `0x0040D7D0` to `CreateThread`. The worker
loads the `ReadFile` and `WaitForMultipleObjects` imports, requests a
20-byte report through the object handle at `+4`, and calls decoder
`0x0040D990` on the successful-result branch. The callsite does not validate
the returned byte count.

Decoder `0x0040D990` checks report byte `+1` for `0x0A`. In the selected
branch it checks report byte `+5` for `8`, verifies the stored nested HWND
with `IsWindow`, then packs `WPARAM` from report bytes `+6` through `+9`:

```text
WPARAM = (byte[+8] << 24)
       | ((((byte[+9] << 4) & 0xFF) | byte[+7]) << 16)
       | (byte[+6] << 8)
       | 0x08
```

The shift and byte-sized operations are the compiled behavior; the field
names and physical key meaning are unknown.

### `CDevG5KB`

The `CDevG5KB` vtable slot `+0x0C` points to setup `0x0040F670`, which passes
worker entry `0x0040F140` to `CreateThread`. This worker requests an
8-byte report through the object handle at `+4` and calls decoder
`0x0040F320` on the successful-result branch. The callsite does not validate
the returned byte count.

Decoder `0x0040F320` checks report byte `+1` for `0x0A`. A type-`6` branch
takes a separate path; the selected type-`8` branch checks byte `+2`,
verifies the stored nested HWND with `IsWindow`, then packs `WPARAM` from
report bytes `+3` through `+6`:

```text
WPARAM = (byte[+5] << 24)
       | (((byte[+4] & 0x0F) | ((byte[+6] << 4) & 0xFF)) << 16)
       | (byte[+3] << 8)
       | 0x08
```

The packet fields' names and meaning are not identified by this trace.

### Shared posted message

Both decoders call `PostMessageW` with the nested HWND at
`[object+0x22C]+0x20`, message `0x07EB`, their packed value as `WPARAM`, and
`lParam=0`. The API return is not checked in these callsites. The MFC row at
`0x005DD1C0` maps message `0x07EB` to `COemDrvDlg` handler `0x0044AFF0`.

## Dialog mapping gate and macro lookup

The handler first selects its branch when the low byte of `WPARAM` is `8`.
It takes the next byte as an index, rejects index zero and values at or
above the global bound at `0x00629EE8`, and requires the top byte (category)
to be at most `3`. The mapping base is loaded from global `0x00647328`; the
selected cell address is `base + 0x10 * (0x84 * category + index)`.

For the selected cell, the handler reads the dword at `+0x38`, requires its
low 24 bits to equal `0x5B`, and requires its high byte at `+0x3B` to equal
`0x0A`. Together those checks mean the dword is exactly `0x0A00005B`, the
same discriminator written by the mapped text-macro picker save path in the
[command bridge audit](rk-v4.6-textmacro-command-bridge.md). It reads the
record key at selected cell `+0x40` and calls `0x0041F480` with allocation
flag zero. That helper searches the fixed 50-record table at `0x0060D3C4`,
using `0x404`-byte stride; a missing record returns null instead of creating
one.

When the lookup succeeds, the handler advances to record `+4` and calls
`0x00458680`. That helper builds Unicode `INPUT` records and calls
`USER32!SendInput` at `0x0045877A`. This is host OS text input. The traced
route does not call a keyboard HID feature-report writer or store the text
in keyboard firmware.

## What remains unknown

- Which physical key, key sequence, or device action produces the recognized
  report fields, and the meanings of those fields for each hardware revision.
- Which profile row and mapping cell are active at runtime, and whether a
  given model/revision reaches the tagged-cell gate.
- Whether either worker starts, whether `ReadFile` returns the selected
  reports, whether `PostMessageW` succeeds, whether the handler receives the
  message, and whether `SendInput` succeeds.
- The full source of the mapping table fields beyond the separate text-macro
  save/load path already documented.

This closes a static report-to-handler-to-host-input path for two compiled
driver classes in this image. It does not prove physical keyboard support,
runtime behavior, a universal RK model mapping, or a firmware readback path.

## Reproduction

```powershell
python scripts/audit_rk46_textmacro_device_trigger.py --binary .research/rk46-extract-full/app/DeviceDriver.exe --out docs/rk-v4.6-textmacro-device-trigger.csv
```
