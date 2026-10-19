# V4.6 brightness profile-to-writer follow-up

## Scope and evidence

This report maps the profile defaults, row-edit message handler, and static
serializer portions of the 4.6 G5-family brightness path. It is based on the
extracted `app/DeviceDriver.exe`, SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`, plus
the extracted profile catalog represented in `models-4.6.json`. Addresses
below are virtual addresses in that exact driver. The binary was inspected
statically; no vendor executable was launched and no device report was sent.

This is separate evidence from the installed 4.06 `CLedDlg` audit in
[`rk-lighting-brightness-ui-handler-audit.md`](rk-lighting-brightness-ui-handler-audit.md).
It does not establish that the 4.06 UI callbacks behave the same in 4.6.

## Profile fields and defaults

Profile setup at `0x00454D24`–`0x00454D72` reads `[OPT] LightUI` and parses
it into byte table `0x0062A564`, with a maximum of 20 entries. If no values
are parsed, it reads `BriNum`; if that is also absent, it synthesizes five or
six sequential entries according to selected-profile global `0x0062A200`.
The loader then reads `[OPT] LightHW` into `0x0062A578`. If that list is
missing or invalid, it copies the parsed `LightUI` values into the
`LightHW` table. `[OPT] DefBri` is stored at `0x0062A560`, defaulting to 4.

The same profile setup dynamically formats `LedOpt%d` and reads slots 1–24
from `[OPT]` into a table based at `0x0062A720`, with `0x3C` bytes per
profile row. The six standard parsed cells occupy row offsets `+0` through
`+0x14`; the first value is copied to both `+0` and `+4`. A separate parser
pointer at `0x0062A740` addresses the extended portion of row 0 (offset
`+0x20`) for any additional parsed values. Do not treat `0x0062A740` as a
second table base or infer tuple-cell names from the duplicated first value.

Profile `020F` (RK A70, `Fw=1`, `RGBKb=1`) demonstrates separate display and
output values: `LightUI=0,1,2,3,4,5`, `LightHW=0,4,8,12,16,20`, and no
explicit `DefBri`, so the loader's default applies. In this catalog snapshot,
92 profiles specify `LightUI`, 70 specify `LightHW`, and 101 specify
`DefBri`. These are profile-data counts, not counts of distinct physical
hardware revisions.

`FUN_004605E0`, reached from object setup at `0x00460992`, initializes 24
active lighting rows beginning at object offset `+0x4240`, with stride
`0x24`. It copies the loaded default brightness index to byte `+1` in each
row and copies nonzero profile lighting-option values into the active rows.
This proves default and profile-option row initialization; it does not
identify the control that later edits the brightness-index byte.

## UI value and output translation

Two UI paths use `LightUI` values. Selector `0x95` reads the selected byte
from `0x0062A564` and formats it for display around `0x004241D5`. The row
rebuild helper `FUN_00426B30` reads `LightUI[record+1]` around
`0x00426BE2`–`0x00426C09` while rebuilding displayed row state from the
per-mode records at `0x0062A728` and following. These edges establish display
values and row rendering, not physical brightness units. The same helper
copies `LedOpt`-derived words into dialog fields at offsets `+0x2C50`,
`+0x2C54`, `+0x2C58`, `+0x2C60`, and `+0x2C64`, then applies UI updates.
The traced helper contains no stores to the profile `LedOpt` table or the
active row's brightness-index byte; it reconstructs dialog state rather than
committing that edit.

The mode-selection handler around `0x00424340` stores the selected mode index
at active-object offset `+0x423C`, refreshes the row UI through
`0x00426B30`, and can enqueue Apply masks `0x02` or `0x22` around
`0x004243C1`–`0x00424415`. This links a mode selection to shared UI state and
the deferred settings path. It is distinct from the private-message row
mutation path below; these mode-selection instructions do not write the
active row's brightness-index byte.

A separate 4.6 message-map entry closes the row-mutation edge. In the
hash-pinned driver's `.rdata` table at `0x005D54C0`, entry `0x005D5508`
contains private message `0x0800` and handler pointer `0x004240A0`. That
handler refreshes selector display through `0x00424130`, calls row-update
helper `0x00427530`, and on its continuing path conditionally queues Apply
mask `0x02` at `0x00424102` when global `0x0062A234` permits it. That path
then calls persistence helper `0x00460DA0`; other branches return early.

`0x00427530` obtains the selected row index through `SendMessageW` with
message `0x110A` and `wParam=9` (`0x00427542`–`0x00427577`). It addresses the
row as `active+0x4238+36*index`, reads UI state through `0x004505F0` using
dialog offsets `+0x106C` and `+0x1A6C`, and stores values to row offsets
`+0x08` at `0x00427594` and `+0x09` at `0x0042759C`. It then copies values
to row `+0x0C` at `0x004275A8` and `+0x28` at `0x004275B1`. For row zero, the
`+0x09` store is active-object byte `+0x4241`, the brightness index read by
`0x00426BE8` and translated through `LightUI` for display, then read by the G5
packer at `0x004125C3`/`0x00412609` and translated through `LightHW` for
output. This statically connects the message handler's row mutation to the
existing serializer path.

The only located generic sender for `0x0800`, helper `0x00450550`, uses its
own `+0x9E0` selector field. I did not establish that sender instance's link
to this dialog's `+0x1A6C` control or identify a direct child control ID. The
visible label, semantics of the other row fields, active device target, and
firmware acceptance remain unresolved. The `ApplyNow` gate also means the
handler's row update does not by itself prove that every edit immediately
queues a hardware write.

The G5 packer at `0x00412470` reads each row's byte `+1` as an index into the
`LightHW` table at `0x0062A578`, then writes the translated byte into the LED
record. For the selected current row, the translated byte is placed at output
offset `+0x5E`. A separate firmware-2 packer at `0x00412110` also indexes the
same table. This is the boundary between profile UI indices and output
values; neither table gives the output byte a physical luminance unit.

## Deferred G5 apply and writer

`CDevG5KB::ApplySetting` at `0x004127B0` handles mask `0x02` by reading a
128-byte LED/profile block through virtual slot `+0x3C`, checking its trailing
`5A A5` signature, and choosing packer `0x00412110` for firmware 2 or
`0x00412470` for other firmware values. It then calls writer
`0x00410340` with operation `1`, command `4`, and length `0x80`. The family
selection and slot target are documented in the [G5 vtable and settings
audit](rk-v4.6-cdevg5-settings-and-vtable-audit.md).

This establishes a static path from profile defaults and per-mode state to a
conditional G5 command-4 write. It does not prove that a specific UI action
queued this mask for a particular live device object, nor that firmware
accepted or applied the output.

## Evidence status

| Link | Status | Remaining limit |
| --- | --- | --- |
| `LightUI`, `LightHW`, `BriNum`, and `DefBri` profile loading/defaults | Proven statically | Runtime profile selection and malformed-profile behavior are not observed. |
| Default value copied to 24 active rows | Proven statically | Runtime profile and current row selection are not observed. |
| `LightUI` to displayed values | Proven statically | Control identity and physical units are unresolved. |
| `LedOpt1`–`LedOpt24` profile rows to active mode and dialog state | Proven statically | Tuple-cell semantics and the exact `0x0800` sender remain unresolved. |
| `0x0800` message to active-row brightness-index store | Proven statically | Visible control identity and message sender are unresolved. |
| `LightHW` index to G5 output byte | Proven statically | Hardware brightness meaning and firmware acceptance are unresolved. |
| G5 mask `0x02` to command-4 writer | Proven statically | Active object, handler-to-worker runtime reachability, and acceptance are unobserved. |
| Specific click to live device write | Unresolved | No runtime execution or report capture. |

## Related audits

- [V4.6 G5 vtable and settings routes](rk-v4.6-cdevg5-settings-and-vtable-audit.md)
- [V4.6 profile selector and options](rk-v4.6-profile-selector-audit.md)
- [4.06 brightness UI and serializer audit](rk-lighting-brightness-ui-handler-audit.md)
- [Profile catalog and 4.6 delta](rk-profile-catalog-v4.6-delta.md)
