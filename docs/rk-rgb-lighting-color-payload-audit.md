# RK 4.06 lighting, RGB, and color payload audit

This is a static trace of the installed RK Keyboard Software 4.06 lighting
configuration and native packers. It identifies several configuration-to-
buffer paths in `DeviceDriver.exe`; it does not identify every visible mode
with a wire value, decode every byte, or establish behavior on every keyboard
revision. No RK executable or updater was run, and no keyboard interface was
opened or sent data.

## Evidence scope and labels

Addresses below are x86 virtual addresses in the byte-identified driver. The
primary binary SHA-256 is
`C03F88BC4E2D78AA4392D7445B0FD62182DC824F97F5D5DB40BD009E547A9AB6`.
Evidence labels mean:

- **High — file/config:** directly read from the installed INI/XML bytes.
- **High — static code:** directly visible in the identified function's
  control flow or stores.
- **Moderate — association:** supported by names, logging, or adjacent
  configuration, but the exact UI or device meaning is not proven.
- **Unresolved:** no reliable crosswalk was recovered.

| Installed evidence | SHA-256 |
| --- | --- |
| `DeviceDriver.exe` | `C03F88BC4E2D78AA4392D7445B0FD62182DC824F97F5D5DB40BD009E547A9AB6` |
| `Dev/en/led.xml` | `3BE84EE40A92471744A17A5F514F49028D4FA3E6E29AFFDD93508A1021BC0882` |
| `Dev/sc/led.xml` | `E14DF6FE59C0B6F3A140EAD0AC345D9895251B1A7AF17BFDF45271D71D1A3A61` |
| `Dev/0174/KB.ini` (RK S98RGB profile) | `BBD82E2F538A0FC1BFF8AF26454470418362DBAD16287D8DD755342FD595DB5F` |
| `Dev/022F/KB.ini` (RK-S98 profile) | `C0D2D796ABBC46D35ED61E9010AF839175D9A6B33F314274AFABF6EE5F06E7B4` |

The broader profile corpus and file-by-file hashes are recorded in the
[installed-package manifest](rk-installed-package-manifest.csv),
[profile schema audit](rk-profile-schema-audit.md), and
[option inventory](rk-profile-option-field-inventory.csv). The related
[lighting serializer audit](rk-setting-serializer-audit.md) and
[resource/localization audit](rk-resource-localization-audit.md) cover the
surrounding paths.

## Mode and effect labels are UI resources, not command IDs

**High — file/config.** `Dev/en/led.xml` contains three independent indexed
label families: 21 `tc_led_mode*` labels, 20 `tc_led*` alternate labels, and
19 `tc_eft*` effect labels. Examples include `tc_led_mode1=Neon_Stream`,
`tc_led_mode17=Steady`, `tc_led1=Steady`, `tc_led2=Customize`,
`tc_eft1=Fixed_on`, and `tc_eft19=OFF`. Matching dictionaries exist for
Simplified Chinese and three other generic locales. Five model directories
also contain local dictionaries; S98 profiles 0174 and 022F use the generic
locale fallback.

**High — static code.** `FUN_00422AF0` builds label lookup keys from these
families. It tries the active profile's
`Dev\\<profile>\\<locale>\\led.xml` path at `0x00422B84`, then the generic
`Dev\\<locale>\\led.xml` path at `0x00422BDB`. `FUN_00422DA0` builds the
associated list/controls, with `LedMask` (`0x00611798`) participating in
selection. The driver also probes keys `tc_led_mode22`–`tc_led_mode25`, which
are not present in the shipped generic dictionaries.

**Unresolved.** The mode/effect suffix is not proven to be a wire command,
firmware enum, or `LedOptN` slot. The three label families are not
interchangeable just because their numeric suffixes overlap. The installed
`ET`/`Cartoon` pattern text and profile-local pattern files document effect
assets, but this audit did not recover a complete asset-to-packet path.

## Profile fields and runtime option records

**High — file/config.** Across all 189 installed profiles there are 3,765
`LedOpt*` assignments. Every stored value is a six-integer comma tuple; slot
presence is irregular (some profiles omit slot 18 or higher slots). The S98
profiles 0174 and 022F share, for example, `LedOpt1=0,0,1,0,1,1`,
`LedOpt2=0,1,1,0,1,1`, `LedOpt3=0,1,1,0,0,0`, and zero-filled `LedOpt19` and
`LedOpt20`. These are stored configuration values, not decoded semantics.

`FUN_004513B0` at `0x004513B0` reads profile lighting fields. It loads
`LightUI` into byte table `0x00611854`, `LightHW` into `0x00611868` (copying
the UI list if the hardware list is absent/invalid), and `DefBri` into
`0x00611850`. It also reads `RGBIndex` into `0x00612B48` onward,
`MusicRGBIndex` into `0x00612B4C` onward, and `GameRGBIndex` into
`0x00612B50` onward. `GameRGBIndex` falls back to the `RGBIndex` triple when
absent. The shown parser checks that each triple sums to 3; that check does
not prove channel names or a valid permutation.

The profile corpus has `RGBIndex` in 96 profiles: 75 store `0,1,2`, 20 store
`1,0,2`, and one stores `2,0,1`; 93 omit it and use the binary default
`0,1,2`. `MusicRGBIndex` appears in 29 profiles, all with `1,0,2`; the
initializer's absent-value behavior is zero initialization rather than a
copy from `RGBIndex`. All 189 profiles store `RGBKb` as 0 or 1. `LedMask`
appears in 39 profiles, `DefLedIndex` in 67, and `GameGroupNum` in 70.

The initializer also reads `StartGp`, `SameGp`, `GaoshouAddr`,
`GaoshouGroupNum`, `CustomGp`, `LedModeSelectOffset`, `EffectOffset`,
`DefLedIndex`, and `LEDParam`. In the installed profile corpus,
`GaoshouGroupNum`, `GameRGBIndex`, `LEDParam`, `LedModeSelectOffset`,
`EffectOffset`, `StartGp`, `SameGp`, and `CustomGp` are not stored keys;
their code defaults therefore matter. The serializer consumers for most of
these globals were not fully resolved.

**Partial static crosswalk.** The driver contains no individual
`LedOpt1`–`LedOpt21` string literals, but the profile loader formats
`LedOpt%d` and reads 24 slots dynamically. The new
[profile-to-record trace](rk-lighting-profile-record-path-audit.md) confirms
that tuple cell 4 can initialize runtime-record offset `+0x08` for values 1
or 2; it also maps tuple cells 2–6 into lighting-dialog control state. It
does not define those values' visible labels or firmware meaning, nor does it
show the full tuple copied into the record. The serializers use 0x30-byte
records from `config+0x214C`; the G5 RGB-table path below reads seven DWORD
values at record-relative offsets `+4` through `+0x1C`, including a run of six
values. Their relationship to the corresponding tuple columns remains
unresolved. Do not equate a label suffix, profile slot, runtime record index,
or payload offset without that remaining bridge.

## G5 and 3632 lighting-settings command 4

**High — static code.** The shared apply routine `FUN_00411B90` reads
128 bytes of LED configuration and selects `FUN_00411700` when the device
profile's firmware value is 2, otherwise `FUN_00411900`. Both pack into the
128-byte buffer used by G5 command `4` or the 3632 command `4` path. The
transport write is performed through `FUN_0040F700` (G5) or `FUN_0040D7E0`
(3632). This is an active write path; it was not called.

`FUN_00411900` reads current profile index at config `+0x213C`, lighting
records beginning at `+0x214C` with a `0x30` stride, and mode-option rows at
`0x00611A10` with a 15-DWORD stride. It translates each record's brightness
index through `LightHW`. It places mode/index and packed nibble values in
two-byte entries beginning around output `+0x3A`; the current selected
profile's translated brightness is also written to output `+0x5E`.
`FUN_00411700` is a distinct firmware-2 layout: its mode-specific pairs are
written at output `+0x53 + 2*index` and related offsets. Exact UI labels,
tuple columns, nibble meanings, and firmware-side semantics remain
unresolved. See the existing [brightness and serializer traces](reverse-engineering.md#brightness-profile-ui-and-serializer-path).

## G5/3632 RGB mode table: commands 10 and 9

**High — static code.** In `FUN_00411B90`, dirty flag `0x20` enters a table
builder. The code iterates a runtime count stored in `0x00612B00`, checks
the profile `LedMask` bit for each row, and writes a 21-byte row. For an
enabled row it splits seven DWORD values (the DWORD at record-relative `+4`
and six DWORDs at `+8` through `+0x1C`) into three byte positions selected
by `RGBIndex` (`0x00612B48`–`0x00612B4A`). The resulting row has seven
three-byte entries. `FUN_0040CD70` is called with an output length of
`(rowCount+1)*0x15`, row width `0x15`, and channel argument `3`.

The final wrapper is `FUN_004101B0` at `0x004101B0`: G5 uses command `10`,
3632 uses command `9`. The packet length is passed from the caller. Static
code proves the packing arithmetic and command selection, but not that each
row corresponds to one XML label, that the seven values mean seven colors,
or which byte plane means red, green, or blue. This path is distinct from
the 128-byte command-4 settings write.

## Per-key colors: RKKB and G5/3632 groups

### RKKB key-color path

**High — static code.** `FUN_00413BF0` flag `0x04` writes a per-key color
buffer through `FUN_00413220`, using the inner prefix `03 7E`. It only builds
the payload when the configured profile index matches `GaoshouIndex`
(`0x006117CC`). The selected group comes from config `+0x25C0`; the emitted
group selector is that value plus one, with 10 mapped to zero. A group/key
DWORD is read from `config + 0x25C8 + group*0x210 + key*4`, and the 132-entry
mapping records at `0x006169D1` supply the output key index.

When `RGBKb` (`0x006117C4`) is zero, the packer writes a one-byte on/off
value: nonzero color becomes `7`, zero becomes `0`, at output offset
`keyIndex+3`. When `RGBKb` is nonzero, it splits the DWORD's low, middle, and
high bytes into three positions selected by `RGBIndex`, beginning at
`(keyIndex+1)*3`. The chosen inner length is `0x81` or `0x17D`, respectively.
`FUN_00413220` wraps this data with feature report ID `0x0A`, at most 62
payload bytes per report, and one-based chunk indices. The helper is a
one-way writer with no ACK/readback branch. No report was emitted.

The same RKKB apply routine's flag `0x02` builds an LED-data buffer with
prefix `02 29`, selected record/index fields, translated `LightHW` value,
and optional channel bytes when `RGBKb` is nonzero. It sends `0x3C` bytes
through `FUN_00413220`. Field names and physical lighting meanings are not
fully known; this is separate from the `03 7E` per-key color payload.

### G5/3632 color groups

**High — static code.** `FUN_00411B90` has a separate dirty-group path for
flag `0x04` (under its selected-profile guard) or flag `0x10`. It reads
per-key DWORD colors from the group arrays at `config+0x25C8 +
group*0x210 + key*4`, maps profile key records through `0x006169D1`, then
splits the low three color bytes into three `0x7E`-byte planes at offsets
selected by `GameRGBIndex` (`0x00612B50`–`0x00612B52`). When `GameRGBIndex`
is absent, the initializer copies the `RGBIndex` triple. The writer sends
`layoutKeyCount*3` bytes per dirty group: G5 command `6` with group index as
the command argument, or 3632 command `2` with group index as the option.
The log string `ColorGroup[%d]` supports the group association.

The loop count is global `0x00612AF8`, read from `GaoshouGroupNum` with a
default of 5 and clamped to 10. This differs from `GameGroupNum` at
`0x00612AF4`, also read by the profile initializer and used in a separate
UI-construction loop. Although S98 profiles store `GameGroupNum=1`, that
alone does not prove the number or label of serialized color groups.

**Unresolved.** The profile fields `GaoshouKey1`, `GaoshouKey2`,
`GaoshouIndex`, and `clrGaoshou` are present in many/all installed profiles,
but their complete path into these group arrays was not recovered. The
runtime mapping proves key-index placement, not visible group names, color
picker events, RGB channel names, or model support. The RKKB per-key `03 7E`
path and G5/3632 group command paths must not be assumed to share the same
wire schema.

## Practical boundary

The strongest static reconstruction is a partial packer map: command `4`
lighting state for G5/3632; commands `10`/`9` for an RGB table; commands
`6`/`2` for G5/3632 color groups; and RKKB's `02 29` LED-data and `03 7E`
per-key-color payloads. The XML and profile corpus add label order and
configuration values, but do not close the `LedOpt`-to-runtime-record or
label-to-wire-value gaps. These are version- and family-specific findings
for the hashed 4.06 driver; they do not establish support for all RK models
or firmware revisions.
