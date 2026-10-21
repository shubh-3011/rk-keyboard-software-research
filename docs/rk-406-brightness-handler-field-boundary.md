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

## LightUI write census and nearest UI edge

For this follow-up, `C:\Users\shubh\Downloads\sshorcale\_rk_analysis\inputs\DeviceDriver.exe`
was re-hashed and matched the installed image SHA-256 above. I disassembled
its executable code with `objdump -d -Mintel` and searched the complete
disassembly for each absolute byte address from `0x00611854` through
`0x00611878`, covering the 20-byte `LightUI` table
(`0x00611854`–`0x00611867`) and adjacent `LightHW` table. The sweep found 17
instruction operands in the LightUI range, including indexed operands such as
`[reg+0x00611854]`; the existing Ghidra global-xref export was cross-checked
for the exact `0x00611854` object.

**Observed statically:** every identified write to `LightUI` is inside profile
loader `FUN_004513B0`:

- `0x00451A85`–`0x00451A9D` clears the 20-byte table before loading profile
  data.
- At `0x00451ABE`, the loader sets `EDI` to the table base and calls the
  profile-list parser with a maximum count of `0x14` (20). Its indexed stores
  are at `0x00451B1A`, `0x00451B56`, and `0x00451B77`. The latter two are the
  fallback sequences that fill five or six entries with their indices.
- `0x00451BDC` reads the loaded table while copying it into `LightHW` when
  that profile list is missing or invalid; it does not write back to
  `LightUI`.

The other direct `LightUI` references are reads: `0x004222D1` formats the
indexed value for selector `0x95`; `0x00423630` scans entries 19 down to 0 to
choose an initial row index for a constructed UI control; and `0x00424BD8`
formats the selected record's indexed value during a UI refresh. The nearby
constructor call at `0x004236D9` passes that initial index and selector
`0x95` to `FUN_00450140`; the existing sender trace shows selector `0x95`
stored in child field `+0x9E0`. The `0x0801` handler's formatter is a read
path. The `0x0800` handler and `FUN_00425440` copy other fields and can signal
worker mask `0x02`, but this trace does not show either writing a `LightUI`
entry or runtime brightness-index field `+0x04`.

**Bounded negative result:** this full-code literal-reference sweep and the
exact-global xref export find no separate `LightUI` setter or writer outside
`FUN_004513B0`; no new path from the selected UI index to runtime record
`+0x04` was found. This is not a claim that every indirect alias or runtime
control path has been resolved: the visible control's sender-instance
association, changing `wParam` source, the actual `+0x04` UI setter if one
exists, and its worker-to-family-writer edge remain unresolved. No runtime
execution or device interaction was performed.

## Runtime brightness-index write census

This follow-up also checked the runtime record field independently of the
`LightUI` table. The exact input remained
`C:\Users\shubh\Downloads\sshorcale\_rk_analysis\inputs\DeviceDriver.exe`
with SHA-256
`C03F88BC4E2D78AA4392D7445B0FD62182DC824F97F5D5DB40BD009E547A9AB6`.
The scan searched the full `objdump -d -Mintel` disassembly for record-base
operands `0x2138`, `0x2140`, and `0x2144`, then traced the observed dynamic
row calculation and every direct call to `FUN_00425440`. The complete
recovered `CLedDlg` MFC map was used to include handlers that do not call that
copy helper. This bounds the negative result to these record references and
candidate UI callbacks; it does not resolve every possible indirect alias.

**Proven statically — initialization:** profile loader `FUN_004513B0` stores
`[OPT] DefBri` in global `0x00611850` at `0x00451C2A`. Construction routine
`FUN_0045A7D0` calls `FUN_0045A430` at `0x0045A7FD`. The initializer clears
the lighting-record area, reads `0x00611850` at `0x0045A4B5`, forms the first
record base at `config + 0x2140`, and stores the default to that record's
`+0x04` at `0x0045A505`. Its loop advances by `0x30` bytes for each of 24
records, so this is a profile-derived initializer, not evidence of a later
user edit.

**Candidate UI writer checked — no `+0x04` store:** the selected-row helper
`FUN_00425440` forms a row pointer as `config + 0x2138 + index * 0x30`. Its
stores are to offsets `+0x08` (`0x004254F1`), `+0x0C` (`0x004254F9`),
`+0x18` (`0x00425505`), and `+0x34` (`0x00425514`). For special row
`0x1E`, it copies separate fields to globals. It never stores row offset
`+0x04`. A full direct-call search found these five callsites:

- `0x004221A6`, from `FUN_00422190`, the `CLedDlg` private-message handler
  `0x0800`.
- `0x00422601`, from `FUN_00422580`, mapped to private messages `0x0461` and
  `0x05D1`.
- `0x004226E2`, from `FUN_00422640`, mapped to private message `0x0482`.
- `0x00422883`, from `FUN_00422780`, mapped to private message `0x0481`.
- `0x00424A97`, from child-HWND callback `FUN_004248C0`; its particular
  control and message-map owner remain unresolved.

The other likely row-selection callbacks do not establish a brightness edit.
`FUN_00422430` (message `0x0594`) stores the selected row number at object
offset `+0x213C` and refreshes UI through `FUN_00424B10`. `FUN_004251E0`
(message `0x08B3`) also changes `+0x213C`, then calls refresh helper
`FUN_00425340`. These fields identify the active row; they are before the
record array at `+0x2140`. `FUN_00422220` formats the value read from
`record +0x04` through `LightUI`; `FUN_00424B10` likewise reads that field
for display at `0x00424BCA`. Neither is a setter. The remaining entries in
the recovered `CLedDlg` map are paint, generic pointer routing, cleanup, or
no-op handlers; no additional `+0x04` store was found in those candidate
callbacks.

**Bounded negative result:** the full-image search found `0x0045A505` as the
runtime record `+0x04` store in the traced construction path. The two literal
`0x2144` memory operands, at `0x00411A9B` and `0x00424BCA`, are reads by a
serializer and a UI formatter. The only inspected dynamic selected-row
writer is `FUN_00425440`, whose direct callers are listed above and whose
stores exclude `+0x04`. No subsequent UI edit to the runtime brightness
index is established by this census. An untraced indirect alias or callback
outside the recovered candidate set remains possible; runtime dispatch and
device behavior were not observed.

## Parent-handler continuation: save path and conditional apply

The `0x0800` handler continues beyond the state-copy helper. `FUN_00422190`
first forwards the same `wParam`/`lParam` to `FUN_00422220`; for `lParam`
`0x95`, that callee reads `LightUI[wParam]` and formats it for a child
control. The handler then calls `FUN_00425440`, whose selected-record stores
and special-row global copies are summarized above.

After those calls, the handler checks global `0x00611794`. If it is zero, it
returns without the worker signal or save call. If nonzero, it queries the
child at `this+0xAC` with `SendMessageW(0x110A, 9, 0)` and searches the linked
rows at `this+0x1B0`. When the matched row has `+0x10 == 0x1E`, the handler
returns before both the worker signal and save. Otherwise it rechecks
`0x00611794`; if still nonzero, it calls `FUN_00401080(0x02)` at
`0x004221F7`. It then calls `FUN_0045ABF0(0x0061175C)` at `0x00422202`.
These guards and calls are visible in `0x004221AB`–`0x00422207`.

`FUN_0045ABF0` builds a `%s%04X\\%s` path using the supplied active ID and
the filename `pro.dct`, opens it with `CreateFileW` using `CREATE_ALWAYS`,
and loops over eligible objects in the list rooted at `0x006035B4`. For each,
it calls `WriteFile` with the object pointer and length `0x3E74`. The known
configuration layout places the runtime record array, including its first
record's `+0x04` value at object offset `+0x2144`, inside that range. Thus the
save path can persist the current brightness-index bytes as part of the raw
object. In this loop the only explicit object mutation observed is changing
selected-row field `+0x213C` from `0x1E` to the byte at `0x00612B01` before
the write; there is no explicit store to record `+0x04`. The file write is
therefore evidence of persistence of the current value, not evidence that
this handler selected or changed that value. The `.dct` path and full-file
behavior are also recorded in the [UI event and worker audit](rk-ui-event-worker-path-audit.md).

For the optional mask-`0x02` branch, `FUN_00401080` stores the mask with bit
`0x8000` cleared at `0x0061972C` and releases semaphore `0x00619724`. The
worker `FUN_00401170` later dispatches through the active root object's
virtual slot `+0x3C` at `0x004012A0`. RTTI-backed class targets include
`CDevRKKB` → `FUN_00413BF0`, `CDevG5KB` → `FUN_00411B90`, and
`CDev3632` → `FUN_0040E690` (which enters the G5/3632 orchestrator). In the
recovered mask-`0x02` LED paths, the serializers can read record `+0x04`,
index `LightHW`, and place the translated byte into a device payload. This
is a conditional serialization of the value already in the record; it does
not show that selector `0x95` supplied that value. The worker's concrete
receiver and the execution of this handler's mask through a specific family
serializer remain unresolved. The shared worker stores one mask value rather
than a distinct queued record per signal, as detailed in the
[Apply worker audit](rk-settings-apply-worker-audit.md).

## Evidence boundary

| Claim | Status |
| --- | --- |
| Selector `0x95` reads and formats `LightUI[index]` | **Proven statically** |
| `0x0800` calls the formatter and the general state-copy helper, then can signal worker mask `0x02` | **Proven statically** |
| `0x0800` can save eligible configuration objects to `pro.dct` as raw `0x3E74`-byte records | **Proven statically; active path is guard/row dependent** |
| That raw save contains the existing record `+0x04` bytes for objects with this layout | **Proven from the recovered object layout and copy length** |
| The `0x0800` save loop assigns a new brightness index | **Not found; its observed field mutation is selected-row `+0x213C`** |
| The `0x0800` mask-`0x02` signal reaches a particular family serializer | **Unresolved; worker receiver is indirect/runtime-dependent** |
| A family serializer conditionally reads `+0x04` through `LightHW` | **Proven statically for the recovered class paths; connection to this event is conditional** |
| The helper's selected lighting-row writes include `+0x08`, `+0x0C`, `+0x18`, `+0x34`, not brightness index `+0x04` | **Proven statically for this helper** |
| Runtime record `+0x04` initializes from `DefBri`, then the two serializer families index `LightHW` with it | **Proven statically** |
| Full code reference sweep finds LightUI writes only in `FUN_004513B0` | **Proven within the stated sweep and xref boundary** |
| Separate UI path mutates runtime record `+0x04` | **Not found in this pass; unresolved outside the traced handlers** |
| `0x0800` or selector `0x95` mutates record `+0x04` | **Not established by these handlers** |
| `FUN_0045A430` initializes each record `+0x04` from profile `DefBri` | **Proven statically** |
| Candidate selected-row UI helper `FUN_00425440` writes record `+0x04` | **Not found; its stores are at `+0x08`, `+0x0C`, `+0x18`, `+0x34`** |
| UI callback edits runtime record `+0x04` after initialization | **Not established by this bounded census** |
| This UI event selects RKKB vs G5/3632, reaches a specific writer, or produces a known physical brightness | **Unresolved** |
| Values represent percent, luminance, or another measured physical unit | **Unresolved** |

For the message senders, full profile-record initialization, worker dispatch,
and writer framing, see the related [brightness UI audit](rk-lighting-brightness-ui-handler-audit.md),
[selector sender follow-up](rk-led-selector-message-sender-followup.md),
[lighting profile audit](rk-lighting-profile-record-path-audit.md), and
[serializer audit](rk-setting-serializer-audit.md).
