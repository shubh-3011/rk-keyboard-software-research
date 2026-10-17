# RK macro format and path audit

This report traces the macro record and the import, export, local persistence,
edit-validation, and model-family serialization paths found in RK Keyboard
Software 4.06. It is a static analysis of the installed package-matched PE and
resources. No RK process was launched and no keyboard interface was opened or
sent data.

## Evidence basis

The main native target is the installed
`C:\Program Files (x86)\RK Keyboard Software\DeviceDriver.exe`:

| Evidence | SHA-256 | Relevant detail |
| --- | --- | --- |
| `DeviceDriver.exe` | `c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6` | x86 PE, image base `0x00400000`, 2,326,528 bytes; this matches the immutable copy in `_rk_analysis/inputs/DeviceDriver.exe`. `Cfg.ini` labels the package `RK Keyboard`, version `0x406`. |
| `Cfg.ini` | `1a9796e706fa64b1821417efda080d481e202ffcf941aa97e6a78efe3a32badd` | Installed profile and application options. |
| `Text/en/text.xml` | `85b26e0c7cd8317adeb136d37b6877601b0c3e7f6fb072867f937aa46c73de8c` | English macro and mouse-event labels. |

Addresses below are image virtual addresses (VA), with the PE image base above.
The instruction-level checks used `objdump -d -Mintel` over this exact PE, plus
the existing Ghidra 12.1.4 analysis artifacts and the manifest-backed resource
and profile inventories. “Proven” means the instruction/data relation appears
directly in the static image. “Inferred” means separate native and resource
evidence suggests a relationship but does not link it directly. “Unresolved”
marks a gap that remains open.

No `.mck` or `mac.dct` sample is shipped under the installed Program Files
tree, so the file-format observations below come from parser/writer code rather
than a corpus of captured files.

## Record and file layout

The native macro record has a fixed size of `0x342` bytes (834 decimal).
Creation, import, export, and local persistence all use that same size.

| Offset | Observed use | Confidence and limits |
| --- | --- | --- |
| `+0x00` | 32-bit magic `0xFAFB88A0`, checked by import and record-insert routines. On disk it is little-endian `A0 88 FB FA` before the `.mck` byte transform. | Proven. |
| `+0x04` | Must be nonzero for a record to be included in the `mac.dct` save loop. | Proven as an eligibility check; field meaning unresolved. |
| `+0x08` | High workflow bits are used as dirty/new flags. UI and import paths set `0x40000000` and/or `0x80000000`; `.mck` save requires at least one bit in mask `0xC0000000`, then clears those two bits before the file write. | Proven for bit operations; other bits and ownership semantics unresolved. |
| `+0x0C`, `+0x14`, `+0x68` | Touched by the record-construction/name routines. The code shows these locations participate in generated metadata and string handling, but their complete field schemas are not established here. | Partly observed; meanings unresolved. |
| `+0x6A` | First 16-bit event code. Rows advance by eight bytes and the event walk stops when this code is zero. | Proven. |
| `+0x6C` | 16-bit row field. | Proven to be part of each 8-byte stride; meaning unresolved. |
| `+0x6E` | 32-bit row field. The size validator reads it and compares it with `0x7F`. | Proven access; event meaning and encoding unresolved. |

The first four bytes of a valid encoded `.mck` are derivable from the magic and
the observed transform: each record byte is rotated right by two bits on save,
so the magic becomes `28 22 FE BE`. This is a calculation from code, not a
byte sequence verified against a shipped sample.

### `.mck` individual macro file

`FUN_0042E320` (`0x0042E320`) writes one transformed macro record to a local
file. It requires a high dirty/new flag in record `+8`, then clears those two
flag bits, applies `ROR8(byte, 2)` to all `0x342` bytes, calls `WriteFile` for
exactly `0x342`, and treats a short write as failure. The path is opened with
create-always semantics. The inverse is `FUN_0042E830` (`0x0042E830`), which
applies `ROL8(byte, 2)` to exactly `0x342` bytes. This is a reversible byte
rotation, not evidence of encryption or integrity protection.

`FUN_0042D960` (`0x0042D960`) is the export handler. It resolves the selected
macro record, constructs the destination filename with the `.mck` suffix, and
uses `CopyFileW` (`0x0042DA96`) to copy the internal encoded file to the
user-selected path. Export therefore preserves the stored encoded bytes rather
than serializing the in-memory record again.

The import paths open a selected file with `CreateFileW` using read access and
`OPEN_EXISTING`, request exactly `0x342` bytes with `ReadFile`, and reject a
read that fails or returns a different byte count. They rotate each byte left
by two bits, require the decoded magic, run mouse-capability and size checks,
then add or update an in-memory macro record. The inspected file routines use
file APIs; they do not themselves invoke HID.

The main macro command dispatcher at `0x0042C0E7`–`0x0042C10E` routes command
`0x08` to export (`0x0042D960`) and command `0x10` to the import chooser
(`0x0042D490`). English UI resources label these actions `Export` and
`Import`. This links the native command branches to import/export behavior;
the visible control IDs and exact click route remain unresolved.

Two import implementations are visible. The chooser path at
`FUN_0042D490` (`0x0042D490`) performs the fixed-size read, decode, magic,
compatibility, and capacity checks before inserting and persisting the record.
The helper at `FUN_0042E480` (`0x0042E480`) also performs a fixed-size read and
decode; it is called from `0x0042A94C` and has a self-call at `0x0042E64F` in
its multi-item branch. `MacroDir` is passed into that helper. The exact meaning
of the flag and the control flow that chooses between these import routes are
not fully resolved.

### `mac.dct` profile storage

`FUN_0045A310` (`0x0045A310`) opens the profile-local `mac.dct` with read/write
access and create-always semantics. It walks the macro list and writes each
eligible in-memory record unchanged as one `0x342`-byte block. The output is a
concatenation of raw records: this writer adds no file header and applies no
per-record `.mck` rotation. Its eligibility checks require nonzero fields at
record offsets `+0x04` and `+0x6A`.

The paired loader `FUN_0045A1E0` (`0x0045A1E0`) opens `mac.dct` for reading,
derives a record count from its byte length using the `0x342` stride, reads
fixed-size records, allocates copies, and adds them to the global macro list.
`FUN_0045A0A0` (`0x0045A0A0`) also copies exactly `0x342` bytes when inserting
one record. The `CMacroDlg` destructor path reaches `FUN_0045A310` before
teardown. This proves a local persistence path; it does not prove that every
window close or every profile switch reaches it.

## Event compatibility and size validation

`FUN_0042DEC0` (`0x0042DEC0`) walks 8-byte event rows from `record + 0x6A`.
For event codes `0x110` through `0x116`, it requires the corresponding bit in
the `MacroHasMsKey` mask loaded into global `0x00611FBC`; the code-to-bit map is
`0x110 → 0x01`, `0x111 → 0x02`, through `0x116 → 0x40`. A missing bit rejects
the record. Other event codes pass this specific check. The profile loader
reads `OPT/MacroHasMsKey` with default zero.

The English resource contains seven mouse labels: left, right, middle,
forward, back, scroll up, and scroll down. Their count matches the seven gated
event codes, so those codes likely represent the seven mouse actions. The
one-to-one label ordering is **inferred**, not proven by a recovered
event-code-to-control binding.

`FUN_0042A980` (`0x0042A980`) estimates macro size and rejects when the
estimate is greater than or equal to the global capacity at `0x00611FE4`. Its
static rule is:

```text
estimate = 4 + 2 * number_of_rows
           + 4 * count(rows where value_at_+0x6E > 0x7F
                      and the following row has a nonzero event code)
reject when estimate >= capacity
```

The following-row condition is part of the machine code: the validator checks
the next row's 16-bit event code at the current row address `+8` before adding
the extra four bytes. A zero event code terminates the event walk. This is an
observed validation-size heuristic; it does not decode the corresponding
device payload.

## Edit and dirty-state behavior

RTTI and the MFC message map associate handlers with `CMacroDlg`:

| Map row | Handler | Static behavior |
| --- | --- | --- |
| `0x005CD558`, control ID `0x0107`, `EN_CHANGE` | `0x0042B3B0` | Reads the integer edit child at `this + 0x2FA0`. Accepts `1..DAT_00611FEC`; otherwise resets to `1` and formats `Loop Count = 1 ~ %d`. Sets bit `0x40000000` on the state node returned by `FUN_0042CC20`. The visible control label and state-node owner are unresolved. |
| `0x005CD570`, control ID `0x0117`, `EN_CHANGE` | `0x0042B530` | Reads the child at `this + 0x2FA8`, clamps to `1..1,048,575`, and moves the caret to the end. The field's visible label and semantic role are unresolved. |

The record-save routine checks bits `0x40000000`/`0x80000000` at record `+8`;
one edit handler's `0x40000000` update is a direct static link to save-state
tracking. Another macro-list handler sets `0x80000000`. The `.mck` writer
clears both bits before attempting the write, so the static path does not show
that a failed/short write restores the dirty state. The exact distinction
between new, edited, and cloned records is not fully recovered.

English resources also expose recording start/stop, macro list, event list,
recording delay, default/fixed delay, event insertion before/after, and cycle
modes. `FUN_004513B0` reads `OPT/DefDelay` (default 30), `OPT/MinDelay`
(default 10), `OPT/InsertBefore` (default 1), `OPT/ListTrans` (default 0),
and `OPT/MacroDir` (default 0). Names and UI labels suggest their purpose, but
the complete option-to-control mapping is unresolved.

Although the PE imports keyboard-state and hook-related APIs, the inspected
static call graph does not tie a particular capture API call to the macro
recorder. How raw keyboard/mouse input becomes an 8-byte record row remains
unresolved.

## Key-to-buffer mapping and apply serializers

Macro records connect to matrix key mappings through a separate apply path:

1. `FUN_00411260` (`0x00411260`) translates four layers of 132 key records.
   A runtime record with tag byte `+3 == 5` is treated as macro-tagged. Its
   DWORD at `+8` is matched against macro nodes, and a sequential macro-buffer
   ID is assigned.
2. The translated matrix DWORD stores `(bufferID - 1)` in its high byte. This
   establishes the key-to-macro-buffer association in the packed matrix; the
   rest of the DWORD and model key-position translation remain incomplete.
3. The macro record serializer is called through the device-family vtable
   slot `+0x64`. A table of `(uint16 offset, uint16 length)` pairs is built for
   unique macros, followed by concatenated serialized event blobs. The total
   is `4*n + sum(blob lengths)`; the macro count is passed separately. The
   serializer that defines these blobs is not identified, so the event rows
   are not decoded into the G5/3632 wire schema.
4. The shared apply worker `FUN_00411B90` sends key matrix data and, when
   macros are present and dirty, macro data. The G5 path uses command `5`
   through `FUN_0040F700`; the 3632 path uses command `3` through
   `FUN_0040DD60`, which chunks at up to 512 bytes before its 14-byte transport
   and waits 100 ms between successful outer chunks. These are statically
   identified code paths, not verified live keyboard behavior.

The RKKB family has a distinct macro-event helper. In the key/layer apply
branch, tag-5 records reach `FUN_00413870` at `0x004140A3`. It compacts a
WORD-counted structure with an 8-byte input stride into three-byte rows in a
`0x1FF` temporary buffer. This helper does not call HID itself. The event
subfields and the semantic meaning of the three output bytes remain
unresolved. Its presence shows that the record-to-wire transformation differs
by driver family; it does not establish which catalog model uses the helper.

## Coverage and open questions

This pass adds static coverage for the record-size and magic checks, reversible
`.mck` byte transform, `mac.dct` raw concatenation, import/export file APIs,
seven-bit mouse compatibility gate, precise capacity-size condition,
macro edit dirty flags, and G5/3632/RKKB serializer handoff paths.

The following remain unresolved:

- Full field meanings at `+0x0C`, `+0x14`, `+0x68`, and event-row offsets
  `+0x6C`/`+0x6E`.
- The recorder's input-capture and event-row construction path.
- The exact association between event IDs `0x110`–`0x116` and localized mouse
  actions.
- The vtable `+0x64` implementations that serialize macro event blobs for
  G5/3632, and the complete RKKB three-byte row schema.
- The meaning of `MacroDir`, exact macro-count limits and capacity units,
  duplicate/clone policy, and complete control-to-handler binding.
- Runtime behavior, device acceptance, model/firmware variation, and any
  correspondence between the software's size estimate and physical device
  storage.

For related evidence, see the [main reverse-engineering report](reverse-engineering.md#keymap-and-macro-mapping-details),
[serializer audit](rk-setting-serializer-audit.md),
[profile tuple semantics](rk-profile-tuple-semantics.md), and
[MFC message-map audit](rk-mfc-message-map-audit.md).
