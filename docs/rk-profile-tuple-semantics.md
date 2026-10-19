# RK profile tuple semantics

This is a confidence-ranked interpretation of mapping and lighting tuples
stored in the installed RK Keyboard Software 4.06 profiles. It is based on the
189 `KB.ini` files and the hash-matched `DeviceDriver.exe` snapshot documented
in the [profile schema audit](rk-profile-schema-audit.md). The `[KEY]` parser
and RKKB slot-byte dataflow are now traced in the
[keymap UI/serializer audit](rk-keymap-ui-path-audit.md); `LedOpt%d` parsing
and selected record/UI consumers are traced in the
[lighting profile-to-record audit](rk-lighting-profile-record-path-audit.md).
No RK process or keyboard interface was run or opened.

The repository preserves every source tuple. The descriptions below do not
authorize normalizing, dropping, or rewriting cells whose meanings remain
uncertain.

## `[KEY]` rows

Each row begins with four values that the catalog extractor parses as
`x,y,x2,y2`, deriving rectangle width and height as `x2-x` and `y2-y`.
These are visual layout coordinates in the profile projection. They are not
established as keyboard matrix coordinates. Zero-sized rectangles can still
have mapping records and must not be dropped from device-related data.

Most rows then have further values. Standard S98 profile `022F` examples show
values that match familiar Windows virtual-key codes: Esc is `0x1B`, F1 is
`0x70`, Tab is `0x09`, and Q is `0x51`. The native parser's direct field
destinations are now known; those familiar values remain evidence for a
candidate key-code interpretation, not proof of how every type is understood
or encoded:

| Cell after `x,y,x2,y2` | Observed pattern | Candidate interpretation | Confidence and limit |
| --- | --- | --- | --- |
| 5 | Mostly `0x02` | Action/type tag | **Parser destination proven:** used to build the top byte/type in the 16-byte base action record. Full type enum remains unresolved. |
| 6 | Common keys match Windows VK values | Action/code input | **Parser dataflow proven:** enters the type-2 special-key branch or low 24 bits of the first DWORD. Windows-VK meaning remains inferred for familiar values; translation varies by type. |
| 7 | Mostly zero | Auxiliary/extended input | **Parser dataflow proven:** can enter record byte `+8` or DWORD `+0x0C` depending on type. General meaning remains unresolved. |
| 8 | Values from 0 through 131, 126 distinct values in the corpus | Output-slot index | **Direct link proven:** copied to base record byte `+4`, which is the bounded 0–131 slot byte read by the RKKB `FUN_00413B20` translation path. It is not proven to be a physical switch-matrix position. |
| 9–10, when present | Values constrained below 132 by the parser | Additional slot/index bytes | **Parser destination proven:** override record bytes `+5`/`+6`; their downstream roles are unresolved. |

The separate G5/3632 translator at `FUN_00411260` (`0x00411260`) processes
four layers of 132 16-byte records and calls a device-specific virtual method
at object vtable offset `+0x60`. It bounds its selected slot at `0x83` and
uses the name `MatrixInx` in an error path. The parser-to-slot-byte relation
above is specifically confirmed for the shared RKKB table at
`0x006169D0`; it does not establish that G5/3632 receives the same parsed
record or that the slot corresponds to a physical matrix coordinate.

The corpus has nonstandard row widths that carry additional values:

- Profiles `0106` and `010F` have 87 nine-cell rows each; their ninth value is
  zero. A reserved/padding role is plausible but unproven.
- Profiles `0175`, `01AC`, `0203`, `0227`, and `0228` have 40 ten-cell rows
  with nonzero or varying extra fields. Preserve them verbatim. For example,
  `0203` K15 includes `...,0x02,0x01,0x06000100,1,1,5`; none of those tail
  cells has a confirmed field mapping.

## `[FN1]` and `[FN2]` rows

The section names and `K<n>` association make per-key alternate-layer
actions a high-confidence interpretation. There are 2,274 three-cell
`[FN1]` rows and 603 three-cell `[FN2]` rows. Four S85 rows in profiles
`0193` and `01FA` contain a trailing comma, which is an empty fourth lexical
cell rather than an additional numeric value.

The three cells likely encode action class, subtype, and value, but the exact
schema is not decoded. Values such as `0x07000005` and `0x07000010` resemble
a packed HID usage-page and usage convention; that remains a candidate
interpretation. The profile initializer `FUN_004513B0` calls the shared
`FUN_00450D70` parser separately for `[FN1]`, `[FN2]`, and `[TAP]`, with
destinations `0x0061720C`, `0x00617A4C`, and `0x0061828C`, respectively.
`FUN_00450D70` formats `K%d` keys and reads up to 132 entries into the
corresponding 0x840-byte tables. This proves those sections are parsed and
stored. `FUN_0041D7E0` conditionally copies matching `[KEY]`, `[FN1]`, and
`[FN2]` rows into layer-0, layer-1, and layer-2 state when the selected record
has type 2 and subcode `0xFA` or `0xFB`. This shared map is passed to the
RKKB worker's `+0x3C` method and supplies the four layers translated by
`FUN_00413BF0` when that family route is selected. The general layer-
construction path, the meaning of those subcodes, and the relationship
between translated layers and the separate `01 F8`/`10 F8` regions remain
unresolved. A full `objdump -d` text search found no direct consumer reference
to the parsed `[TAP]` table at `0x0061828C`; computed and indirect uses remain
possible. The separate `FUN_00450820` helper reads `[OPT]`
`GaoshouKey%d` and `GaoshouKeyColor%d` values; it is not the `[FN1]`/`[FN2]`
parser.

`FUN_00411260` identifies runtime macro records by tag byte `+3 == 5` and
reads a macro buffer ID at `+8`. This proves macro dispatch in the translated
runtime record, not a direct correspondence between any particular `FN` cell
and those offsets.

## `LedOpt*` rows

The installed profiles contain 3,765 six-cell `LedOpt*` tuples. The driver
formats `LedOpt%d` and reads keys 1–24 dynamically in `FUN_004513B0`; it does
not need individual `LedOpt1`–`LedOpt21` string literals. The six parsed cells
are placed into a 24-row table. Cell 4 conditionally initializes runtime
record field `+0x08` to 1 or 2; cells 2–6 are also copied into dialog state
and affect related control visibility. Comments and profile-localized labels
identify some effects: profile `020B`, for example, annotates `LedOpt1=1` as
steady lighting, `LedOpt2=2` as breathing, `LedOpt3=3` as a fantasy effect,
and `LedOpt18=19` as custom lighting. These annotations and the partial
parser/UI/record paths do not establish a universal cell-to-effect or
cell-to-command mapping. Zero and duplicate values, including custom value
`19`, rule out assuming a direct slot-to-enum mapping. The record initializer,
packer consumers, and remaining tuple limits are detailed in the
[lighting profile-to-record audit](rk-lighting-profile-record-path-audit.md)
and [settings serializer audit](rk-setting-serializer-audit.md).

## `OPT` fields and end-to-end gap

The exhaustive [schema ledger](rk-profile-schema-fields.csv) records 88
option names, all 6,506 assignments, value forms, omissions, and comments.
Some individual runtime paths are well-supported: `Fw` selects the initial
RKKB versus G5 handler family; model-table initialization reads VID/PID,
`ShowScreen`, `Fw`, `DevTy`, wireless IDs, and six `OPT/Psd` bytes; and the
3632 companion path compares a six-byte device-helper result with those profile
bytes. `Psd` semantics and actual runtime row selection remain unresolved. A targeted exception traces
`DefBri`, `LightUI`, and `LightHW` from profile loading into brightness-value
display and serializer data; the physical scale and specific UI event handler
remain unresolved. A field name or literal match alone does not establish
units or device behavior.

Storage coverage is exhaustive for the installed profile corpus, and several
important partial paths are now direct: `[KEY]` cells 1–10 populate coordinate
arrays or base action-record fields; cell 8 supplies the RKKB slot byte;
`LedOpt%d` values populate table/UI state and selected serializer fields; and
specific `OPT` settings reach family serializers. The complete construction
of four runtime layers from `[KEY]`, `[FN1]`, `[FN2]`, and UI edits remains
unresolved. Full action enums, `LedOpt` meanings, `OPT` field semantics, and
model-specific wire schemas are only partly decoded. No profile-field map
proves physical behavior across all keyboards or firmware revisions.

