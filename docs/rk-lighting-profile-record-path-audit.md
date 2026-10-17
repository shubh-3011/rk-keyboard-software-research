# RK 4.06 lighting profile-to-record path audit

This report follows the installed `DeviceDriver.exe` profile reader from
`LedOpt%d` and RGB-related `OPT` fields into the runtime lighting records
consumed by the G5/3632 packers. It is an offline static analysis. Neither RK
software nor its updater was executed, and no keyboard, HID, GATT, serial, or
bootloader interface was opened or contacted.

## Evidence identity and scope

The analyzed x86 PE is `DeviceDriver.exe`, SHA-256
`C03F88BC4E2D78AA4392D7445B0FD62182DC824F97F5D5DB40BD009E547A9AB6`.
Addresses below are image virtual addresses for that exact file. The profile
examples are the installed 4.06 S98 files:

| File | SHA-256 |
| --- | --- |
| `Dev/0174/KB.ini` | `BBD82E2F538A0FC1BFF8AF26454470418362DBAD16287D8DD755342FD595DB5F` |
| `Dev/022F/KB.ini` | `C0D2D796ABBC46D35ED61E9010AF839175D9A6B33F314274AFABF6EE5F06E7B4` |

The `LedOpt%d` string is UTF-16LE at file offset `0x1D6468`, image address
`0x005D7068`. The code reference at `0x004530F9` is inside
`FUN_004513B0`. Assembly around the dynamic reader was rechecked directly
against the hashed PE because the available decompiler export truncates before
this part of the function. The supporting existing reports are the
[lighting payload audit](rk-rgb-lighting-color-payload-audit.md),
[settings serializer audit](rk-setting-serializer-audit.md),
[profile schema audit](rk-profile-schema-audit.md). The local Ghidra text
export used as corroboration is in
`<local-workspace>\_rk_analysis\reports\lighting-control-trace.txt`;
that workspace artifact is not included in the research repository.

Evidence labels:

- **Proven, static:** directly present as file bytes, a decoded instruction,
  or a control/data-flow operation in the identified PE.
- **Inferred:** the address or data association is supported by names and
  neighboring code, but the exact user-visible or device meaning is unknown.
- **Unresolved:** no direct path or semantic mapping was recovered.

## `LedOpt%d` is read dynamically

**Proven, static.** `FUN_004513B0` constructs the key using the UTF-16 format
string `LedOpt%d` at `0x005D7068`. The counter starts at 1 and the loop
advances its destination pointer by `0x3C` bytes until it reaches
`0x00611FB4`; this yields 24 iterations, for generated keys `LedOpt1` through
`LedOpt24`. For each iteration, it calls `GetPrivateProfileStringW` through
the import pointer at `0x0059E3D8`, with section `OPT`, the generated key, an
empty default, a local output buffer, and the active profile path previously
constructed as `Dev\\%04X\\KB.ini`. An empty result skips the tuple parser.

The destination table starts at `0x00611A10`; the per-slot stride is
`0x3C` bytes (15 DWORD positions). For slot `n`, the table row starts at
`0x00611A10 + (n - 1) * 0x3C`. The parse call is at `0x004531B5`, followed by
stores through the row pointer initialized at `0x00611A14`. For the six-cell
tuples present in the installed profiles, the first six parsed byte values
are stored as follows:

| Profile tuple cell | Table row offset | Notes |
| --- | ---: | --- |
| 1 | `+0x00`, and duplicated at `+0x04` | The loader makes both stores. |
| 2 | `+0x08` | |
| 3 | `+0x0C` | |
| 4 | `+0x10` | This is the cell later consulted by `FUN_0045A430`. |
| 5 | `+0x14` | |
| 6 | `+0x18` | |

The code has an additional branch when the parse result exceeds six: it
assembles up to seven groups of three parsed bytes into DWORDs at row offsets
`+0x1C` through `+0x34`. The installed `KB.ini` corpus has six-value
`LedOptN` assignments, so that extension is code capability, not observed
profile data. The RGB/channel interpretation of those optional groups is not
established.

The table has 24 rows even though installed profiles contain at most 21
`LedOptN` keys. The reader's 1–24 range is a binary fact; the number of rows
used by the UI and serializers is separately controlled by
`DAT_00612B00`.

This resolves the specific dynamic-key question: `LedOpt1`–`LedOpt21` need
not appear as individual string literals because the driver formats
`LedOpt%d`. The previous inventory statement that no individual
`LedOpt1`–`LedOpt21` literals were found remains correct; its suggestion
that a dynamic reader might exist is now confirmed for this function.

## One `LedOpt` cell initializes one runtime field

**Proven, static.** `FUN_0045A430` at `0x0045A430` first clears the
configuration area beginning at `config + 0x2138`. It then walks 24 runtime
records, starting at `config + 0x2140` and advancing by `0x30` bytes per
record. Its profile-table pointer starts at `0x00611A20` and advances by
`0x3C` bytes per iteration, matching the row count and slot order of the
`LedOpt%d` loader. For each corresponding row, the routine checks the DWORD at
table-row offset `+0x10`, which the loader populated from tuple cell 4:

- if that value is `1`, it writes `1` to runtime-record offset `+0x08`;
- if that value is `2`, it writes `2` to runtime-record offset `+0x08`;
- for other values, the cleared record keeps zero at `+0x08`.

The installed S98 examples have tuple cell 4 set to zero in their shown
`LedOpt` rows, so this branch leaves their corresponding `+0x08` fields at
zero during this initialization. This does not establish what the values
mean in the UI or firmware.

Other record fields are initialized independently of the six-cell tuple:

| Runtime record offset | Static initializer behavior |
| ---: | --- |
| `+0x00` | Copies `DAT_0061187E`, the byte at offset `+2` of the profile-loaded `SpeedParam` DWORD; its unit/meaning is unresolved. |
| `+0x04` | Copies `DAT_00611850`, loaded from profile `DefBri`. |
| `+0x08` | Conditionally receives `1` or `2` from `LedOpt` table row `+0x10`, as above. |
| `+0x0C` | Set to zero. |
| `+0x10` through `+0x28` | Initialized from seven fixed DWORD color constants in the local palette. |
| `+0x2C` | Set to one. |

The seven palette DWORDs are `0x000000FF`, `0x0000FF00`, `0x00FF0000`,
`0x0000FFFF`, `0x00FF00FF`, `0x00FFFF00`, and `0x00FFFFFF`. These are the
initializer's stored integer values; byte/channel names and visible swatch
ordering are not inferred here.

This is a **partial** profile-to-record bridge: tuple cell 4 influences the
record's `+0x08`; the other five tuple values are not copied wholesale into
that record by `FUN_0045A430`. The remaining tuple values are read by UI-side
code described below. No static evidence in this trace shows them being
copied into runtime record fields.

## Packager offsets and RGB fields

**Proven, static.** The record base for index `i` is `config + 0x2140 + i *
0x30`. The shared packers address the same records through a pointer starting
at `config + 0x214C + i * 0x30`, which is record offset `+0x0C`:

- `FUN_00411900` reads the record's `+0x00` mode/index value and `+0x04`
  brightness index. It translates the brightness index through the profile's
  `LightHW` table and builds mode/item pairs. It reads fields at `+0x0C`,
  `+0x2C`, and the selected-mode fields while packing the 128-byte command-4
  buffer.
- `FUN_00411700` is the separate firmware-2 layout and reads the same
  `+0x00`, `+0x04`, `+0x0C`, and `+0x2C` fields for its mode-specific pairs.
- The RGB table branch in `FUN_00411B90` takes seven DWORDs from record
  offsets `+0x10` through `+0x28`. It splits their low three bytes into
  output channel positions selected by globals `0x00612B48`–`0x00612B4A`.
  The output row is 21 bytes. This is the path already documented as G5
  command 10 / 3632 command 9 in the [RGB payload audit](rk-rgb-lighting-color-payload-audit.md).

`FUN_004513B0` reads profile `RGBIndex` into those three globals. When the
key is absent or parsing produces no values, the code supplies the default
triple `0,1,2`; after a successful parse it warns if the three bytes do not
sum to 3. `MusicRGBIndex` and
`GameRGBIndex` load into separate globals. These channel-index values control
byte placement during packing; they are not copied into the 0x30-byte
lighting records by the traced initializer. The tuple parser and the
`RGBIndex` loader are adjacent profile-loading operations, but adjacency is
not evidence that `RGBIndex` is a `LedOpt` tuple column.

For S98 profiles 0174 and 022F, the installed values include
`DefBri=5`, `LightUI=0,4,8,12,16,20`, `LightHW=0,4,8,12,16,20`,
`RGBIndex=0,1,2`, and `MusicRGBIndex=1,0,2`. Therefore the static default
record receives brightness index 5; the serializer then maps that index
through `LightHW`. This indicates the stored/serialized value for the shown
profile configuration, not a measured brightness percentage.

## UI-facing reads and setters

**Proven, static.** The UI-related routine `FUN_00424B10` reads five fields
from the selected row in the `0x3C`-stride profile table:
`0x00611A18`, `0x00611A1C`, `0x00611A20`, `0x00611A24`, and
`0x00611A28`, scaled by the row index (`0x0F` DWORDs, or `0x3C` bytes per
row). These are table offsets `+0x08` through `+0x18`, corresponding to
`LedOpt` tuple cells 2–6. In order, the values are copied to dialog-object
fields `+0x2C4C`, `+0x2C54`, `+0x2C50`, `+0x2C5C`, and `+0x2C60`. The routine
then calls `CWnd::ShowWindow` on related controls. For the currently selected
lighting index, it applies additional visibility overrides. This supports a
tuple-to-UI-availability path for cells 2–6.

The available decompilation of `FUN_00424B10` shows table/configuration reads
and UI updates, but no store from those five values into the 0x30-byte
runtime record. The exact Windows message handler that calls this routine,
the identity/labels of each control, and any separate event callback that
updates runtime record fields remain unresolved. `FUN_00422220` has a separate
selector-`0x95` path that formats the `LightUI` value at
`0x00611854 + index` for a runtime control; it is not evidence of a
`LedOpt`-to-record setter.

`DAT_00612B00` is assigned the return value of `FUN_00422DA0` during dialog
construction. The settings and RGB packers use it as their runtime row
count. The exact construction logic that decides this count, its relation to
localized label lists, and whether every one of the 24 initialized records
is displayed are not proven by this focused trace.

## Evidence summary and remaining gaps

| Link | Status | Evidence |
| --- | --- | --- |
| Active profile path to `OPT\LedOpt%d` reads | **Proven, static** | `FUN_004513B0`, format-string reference at `0x004530F9`, profile API call at `0x00453177`. |
| Dynamic slot range and table stride | **Proven, static** | Counter starts at 1; 24 iterations; pointer stride `0x3C`; table begins at `0x00611A10`. |
| Tuple cell 4 to runtime-record `+0x08` | **Proven, static** | Loader stores cell 4 at table row `+0x10`; `FUN_0045A430` tests that DWORD and sets record `+0x08` for values 1 or 2. |
| `DefBri` to record `+0x04`, then through `LightHW` in packers | **Proven, static** | `FUN_004513B0`, `FUN_0045A430`, `FUN_00411700`, `FUN_00411900`. |
| `RGBIndex` to RGB-byte placement in the table packer | **Proven, static** | Profile parser at `FUN_004513B0`; use in `FUN_00411B90`. |
| `LedOpt` tuple cells 2–6 to UI control state | **Proven, static** | Reads and window visibility/state updates in `FUN_00424B10`; exact controls are not named. |
| Meaning of all six tuple cells / effect and firmware enums | **Unresolved** | No complete label-to-value-to-firmware crosswalk. |
| UI event callback that writes the full runtime record | **Unresolved** | No direct setter chain established in the available static exports. |
| All 24 runtime rows displayed or serialized on every model | **Unresolved** | Reader/initializer iterate 24; packers use separate `DAT_00612B00` count and profile masks. |

This closes the direct dynamic INI reader and the single recovered tuple-cell
to runtime-record field. It does not close the complete lighting UI write
workflow, define the tuple's semantics, or establish hardware behavior on any
physical model or firmware revision.
