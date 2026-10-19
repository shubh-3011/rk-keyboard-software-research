# RK 4.06 brightness handler to writer boundary

## Scope and identity

This static follow-up narrows the unresolved brightness path in the 4.06
`DeviceDriver.exe`. The installed image was re-hashed as
`C03F88BC4E2D78AA4392D7445B0FD62182DC824F97F5D5DB40BD009E547A9AB6`.
Addresses are image virtual addresses for that exact x86 image. The app and
updater were not run; no HID interface was opened, and no device report or
command was sent.

## What the mapped UI handlers establish

The `CLedDlg` MFC map routes private message `0x0801` to `FUN_00422220`
(`0x00422220`) and `0x0800` to `FUN_00422190` (`0x00422190`). These are
Windows message IDs, not keyboard protocol commands.

**Proven statically:** `FUN_00422220` treats its `lParam` as a selector. For
selector `0x95`, it uses `wParam` as an index into the `LightUI` bytes at
`0x00611854`, formats that byte as text, and sends it to a child window
through the local UI helper. It does not store the selected byte into the
lighting record or call a device writer in this handler. This is a
display-value path; which visible widget sends this selector remains
unresolved.

`FUN_00422190` forwards the message arguments to that formatter, then calls
`FUN_00425440` with the dialog object. In the ordinary selected-row branch,
`FUN_00425440` reads values from dialog children and stores them in the
selected runtime lighting record at offsets `+0x08`, `+0x0C`, `+0x18`, and
`+0x34`. Its special row `0x1E` branch copies separate UI state to globals.
The helper does not write the brightness-index field at record offset
`+0x04` (first record at object offset `+0x2144`). Therefore this handler plus
its copy helper do not establish that a displayed `LightUI` selection changes
the value later serialized as brightness.

When its guards pass, `FUN_00422190` signals the shared worker with mask
`0x02`. The worker dispatches through virtual slot `+0x3C`; the concrete
receiver and arguments for this event remain unresolved. The worker signal
alone does not prove which family serializer runs.

## Runtime value and family-specific serialization

**Proven statically:** profile loader `FUN_004513B0` reads `[OPT] DefBri`
into `0x00611850`, `[OPT] LightUI` into the separate table at `0x00611854`,
and `[OPT] LightHW` into `0x00611868`. `FUN_0045A430` initializes runtime
lighting-record `+0x04` from `DefBri`. The UI formatter uses `LightUI`; the
serializers use the record's brightness index to select a byte from
`LightHW`. When `LightHW` is absent or invalid, the loader copies `LightUI`
bytes into it, but this fallback does not establish physical units.

The two recovered family paths are conditional code paths, not proven
continuations of the `0x0800` UI event:

- **RKKB:** `FUN_00413BF0`, when called with flag bit `0x02`, indexes
  `LightHW` using the current record's `+0x04` value. It places the resulting
  byte at offset `+0x05` in an inner LED-data payload beginning `02 29`, then
  passes `0x3C` bytes to `FUN_00413220`. The writer frames report ID `0x0A`
  feature reports in chunks of up to 62 payload bytes and calls
  `HidD_SetFeature`. The routine is exposed in the `CDevRKKB` vtable, but
  this UI event's runtime receiver and flag values are not established.
- **G5/3632:** `FUN_00411900` also indexes `LightHW` from the current record's
  `+0x04` and puts the translated byte at output offset `+0x5E`. In the
  shared `FUN_00411B90` orchestrator, mask bit `0x02` packs this 128-byte LED
  configuration and writes protocol command `4` after a read/modify step.
  The class-specific serializer selection for the UI event is unresolved.

`0x0800` and mask `0x02` are software message/worker values. `02 29` is an
inner RKKB payload prefix; command `4` belongs to the G5/3632 serializer path.
These distinctions do not establish what a connected keyboard reports or
what luminance results.

## Evidence boundary

| Claim | Status |
| --- | --- |
| Selector `0x95` reads and formats `LightUI[index]` | **Proven statically** |
| `0x0800` calls the formatter and the general state-copy helper, then can signal worker mask `0x02` | **Proven statically** |
| The helper's selected lighting-row writes include `+0x08`, `+0x0C`, `+0x18`, `+0x34`, not brightness index `+0x04` | **Proven statically for this helper** |
| Runtime record `+0x04` initializes from `DefBri`, then the two serializer families index `LightHW` with it | **Proven statically** |
| `0x0800` or selector `0x95` mutates record `+0x04` | **Not established by these handlers** |
| This UI event selects RKKB vs G5/3632, reaches a specific writer, or produces a known physical brightness | **Unresolved** |
| Values represent percent, luminance, or another measured physical unit | **Unresolved** |

For the message senders, full profile-record initialization, worker dispatch,
and writer framing, see the related [brightness UI audit](rk-lighting-brightness-ui-handler-audit.md),
[selector sender follow-up](rk-led-selector-message-sender-followup.md),
[lighting profile audit](rk-lighting-profile-record-path-audit.md), and
[serializer audit](rk-setting-serializer-audit.md).
