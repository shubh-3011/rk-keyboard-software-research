# RK keymap profile-to-UI and serializer path audit

## Scope and evidence

This report follows the dynamic keymap path in the installed RK Keyboard
Software 4.06 `DeviceDriver.exe`: `[KEY]` profile tuples, generated UI state,
key translation, and known Apply events. It is a static-only audit of the
snapshot below. The application and updater were not run, no keyboard HID or
other device interface was opened, and no report or command was sent.

| Artifact | Scope |
| --- | --- |
| `<local-workspace>\_rk_analysis\inputs\DeviceDriver.exe` | SHA-256 `C03F88BC4E2D78AA4392D7445B0FD62182DC824F97F5D5DB40BD009E547A9AB6`; PE32 x86; image base `0x00400000`. Addresses below are VAs in this exact image. |
| Installed `Dev\022F\KB.ini` | RK-S98 profile used for tuple examples; corpus-wide counts come from the 189 installed profiles. |
| Static exports | `_rk_analysis/reports/brightness-global-xrefs.txt`, `device-targeted-functions.txt`; dialog, localization, profile-schema, UI-control, and serializer audits linked below. |

**Proven statically** means a direct parser, memory, call, resource, or message-map edge exists in this snapshot. **Inferred** means the interpretation fits the recovered structures but an end-to-end consumer edge is missing. **Unresolved** means the available evidence does not identify a reliable path. No label here claims observed keyboard behavior.

## Recovered `[KEY]` parser bridge

### Profile selection and tuple parsing

**Proven statically.** `FUN_004513B0` (`0x004513B0`) logs `InitKBSeting`, accepts a profile identifier, and formats the selected file path as `%sDev\\%04X\\KB.ini`. It clears `0x2100` bytes beginning at `0x006169CC`, then loops from `K1` toward `K132`. For each key it calls `GetPrivateProfileStringW` with section `KEY`; an empty/missing row ends the loop. The count is capped at 132 rows.

The parser tokenizes each row on commas and calls `wcstoul`. Its radix expression gives decimal for tuple cells 1–4 and 8–10, and hexadecimal for cells 5–7. A malformed numeric token triggers a `Data parse error` message. The resulting field paths are:

| `[KEY]` cell (1-based) | Direct parser destination | Evidence and limit |
| --- | --- | --- |
| 1–4 | Four separate arrays at `0x00618ACC`, `0x00618AD0`, `0x00618AD4`, and `0x00618AD8`, each advancing 4 bytes per row. | **Proven statically.** These are separate from the 16-byte action record. They match the profile rectangle fields described in the [profile schema audit](rk-profile-schema-audit.md); a specific draw routine consuming each array was not recovered here. |
| 5 | The top byte/type used to build the record at `0x006169CC + 0x10*(K-1)`. | **Proven statically.** Type `2` takes a special branch; other values form the top byte of the first DWORD. The type's complete semantic enum is unresolved. |
| 6 | Action/code input to the type-2 special-key branch or the low 24 bits of the first DWORD for other types. | **Proven statically** as data flow. **Inferred** as an action or key code; familiar VK-like values match standard keys, but not all types are decoded. |
| 7 | Auxiliary/extended input. For type `2`, it can feed record byte `+8` or DWORD `+0x0C`; for types `9` and `0x0B`, it is copied to `+0x0C`. | **Proven statically** as data flow. Its general meaning remains unresolved. |
| 8 | Byte `+4` of the 16-byte record, initialized from the parsed value. | **Proven statically.** This is the important mapping-slot bridge detailed below. |
| 9–10, when present | Bytes `+5` and `+6` respectively, replacing the default copies of cell 8. | **Proven statically.** The parser checks each of bytes `+4`, `+5`, and `+6` is below `0x84` (132). Their individual roles beyond cell 8 are unresolved. |

For type `2`, the loader sets the record's first DWORD to `0x02000000`, stores the cell-6 value at byte `+9`, and applies special handling for several values (`0x10`, `0x11`, `0x12`, `0x5B`, `0x5C`, and `0xA1`–`0xA5`). Values from 1 through 5 instead take a branch that stores cell 7 at `+0x0C`. For other types, the first DWORD is `(cell5 << 24) | (cell6 & 0xFFFFFF)`; types `9` and `0x0B` also copy cell 7 to `+0x0C`. This establishes action-dependent construction, but it does not decode every action or prove every tuple field's device meaning.

### Confirmed matrix/output-slot relationship

**Proven statically.** The parsed cell 8 is copied into record byte `+4`. The RKKB translator `FUN_00413B20` (`0x00413B20`) reads its output index from byte `+4` of the corresponding 16-byte record in the table at `0x006169D0 + index*0x10`. That table begins four bytes into the parser's record area (`0x006169CC + 4`). The translator bounds the resulting output index at `0x83` and uses it to place each translated DWORD into one of 132 output slots. Thus the previous “column 8 may be an output/matrix index” hypothesis is strengthened: **cell 8 directly populates the global slot-index byte used by this RKKB translation path.**

The parser validates all three index bytes `+4` through `+6` against the 132-slot bound. For the ordinary eight-cell row, it initially copies cell 8 into all three bytes; optional ninth/tenth cells override `+5`/`+6`. The exact purpose of those optional fields is not established.

The parser also sets up a `0x2100`-byte four-layer-sized region, but the visible `[KEY]` loop writes the base 132-row region. RKKB apply `FUN_00413BF0` (`0x00413BF0`) calls the translator four times on input layers spaced `0x840` bytes apart. **Unresolved:** the constructor/copy path that populates those four runtime input layers from profile defaults and any edited UI state. The shared slot-index table does not, by itself, prove that the parser's action record is the translator's per-layer input record.

### `[FN1]`, `[FN2]`, and `[TAP]` profile parsing

**Proven statically.** After the inline `[KEY]` loop, at
`0x004522D4`–`0x00452323`, `FUN_004513B0` calls the shared `FUN_00450D70`
parser with section names `FN1`, `FN2`, and `TAP`
and destination tables `0x0061720C`, `0x00617A4C`, and `0x0061828C`.
`FUN_00450D70` formats dynamic `K%d` keys and processes up to 132 entries;
each destination spans `0x840` bytes at the same 16-byte record stride.
This closes the earlier parser/storage gap: the Fn and tap profile sections
are read into their own tables. It does not identify the semantic meaning of
each tuple cell or prove how those tables populate the four layer records read
by the translators or reach the `10 F8` output path.

The later `FUN_00450820` call is a separate helper. Its dynamic profile keys
are `[OPT]` `GaoshouKey%d` and `GaoshouKeyColor%d`, not the `[FN1]` or `[FN2]`
sections. Do not use that call as evidence for Fn-row parsing or layer
population.

## UI and event crosswalk

The main feature UI is built dynamically; static resources do not expose a complete set of remapping control IDs. The [UI control crosswalk](rk-ui-control-command-crosswalk.md) and [localization audit](rk-resource-localization-audit.md) establish these specific edges:

| UI surface/event | Proven static edge | What remains open |
| --- | --- | --- |
| Profile key layout | The profile loader writes the first four cells into per-key coordinate arrays and builds the action records described above. The profile schema identifies these four cells as rectangle coordinates. | Which exact paint/hit-test function reads these arrays, how it maps a mouse selection to `K<n>`, and the generated key control/HWND IDs. |
| Key/function picker `Apply` | A separate generated control is built at `0x0041EC32`–`0x0041EC3F`, stored at `this+0x204`; the RTTI-backed `CKeyFunPickDlg` vtable slot `+0xF0` reaches handler `0x0041F810`. The handler checks the clicked HWND and updates local selection/dirty fields. | How this local picker state is copied into the four-layer map object or serialized later. No direct call to the settings signal helper or a device writer was found from this handler. |
| Main window `Apply` | Another `tc_apply` control is built at `0x0040A3F8`–`0x0040A404`, stored at `this+0x1DD8`. Its handler reaches `0x0040AE1D`, updates an in-memory row via `0x0040B3B0`, and under the `ApplyNow` gate signals `FUN_00401080` with mask `1`. The semaphore worker later calls a virtual `+0x3C` method. | The actual receiver/profile at the virtual call and the concrete writer reached for this individual event. The picker Apply and main Apply must remain distinct despite the shared caption. |

The main Apply's signal and family vtable targets are described in the [Apply worker audit](rk-settings-apply-worker-audit.md). If the receiver is RKKB, vtable slot `+0x3C` reaches `FUN_00413BF0`; if it is G5, the target is `FUN_00411B90`. This is a conditional static route, not proof that a specific click reached either writer.

## Serializer connection and family boundary

**Proven statically.** For RKKB, the four-layer translator processes 132 records of 16 bytes per layer, calls action-specific translation, uses the parser-populated 132-slot mapping byte at `0x006169D0 + i*0x10`, and emits 132 DWORDs per layer. The family apply function also has separate LED, per-key color, macro-staging, matrix, and conditional Fn branches. The separate `04 00` + `0x780` transfer belongs to the observed macro-staging context; it is not established as the profile keymap block. See the [keymap translation audit](rk-keymap-translation-audit.md) and [serializer audit](rk-setting-serializer-audit.md).

**Proven statically, different family implementation.** G5/3632 applies also translate four 132-record layers through `FUN_00411260`, which calls a device-specific virtual translator at `+0x60`, rejects `-1` results and indices above `0x83`, and forms 132-DWORD layers. The G5 route uses command `3` for each selected layer; the 3632 route dispatches command `1`. No evidence here establishes that the RKKB global record parser, action translation table, or UI bridge is identical across these families. See the [profile-family coverage report](rk-profile-family-protocol-coverage.md).

## Explicit unresolved items

- **`[FN1]` and `[FN2]` profile rows:** parser and destination tables are now mapped through `FUN_00450D70`; no recovered consumer maps a specific row to a layer record or writer. Tuple-cell meanings and the relationship between the per-section tables and the four runtime layers remain unresolved. `FUN_00450820` is a separate `[OPT]` Gaoshou-key/color reader, not the Fn parser.
- **Mouse/key selection path:** no reliable mapping from a clicked rendered key to a `K<n>` record, popup choice, or `CKeyFunPickDlg` input field was recovered.
- **Picker commit path:** the local dirty/selection update in `0x0041F810` is statically visible, but its later consumer is not linked to the runtime four-layer records.
- **Layer population:** the four runtime layers consumed by the family translators are known, but their complete construction from `[KEY]`, `[FN1]`, `[FN2]`, and UI edits is not.
- **All-model coverage:** this is one installed 4.06 binary and 189 local profiles. It cannot establish that all Royal Kludge models, revisions, or later software use the same parser or writer.
- **Protocol semantics:** translated DWORD meanings and several type/action cases remain undecoded. No packet capture or hardware validation was performed.

## Related reports

- [Profile tuple semantics](rk-profile-tuple-semantics.md)
- [Keymap translation and packet sizes](rk-keymap-translation-audit.md)
- [UI control-to-command crosswalk](rk-ui-control-command-crosswalk.md)
- [Settings Apply signaling and family dispatch](rk-settings-apply-worker-audit.md)
- [Profile schema and corpus coverage](rk-profile-schema-audit.md)

