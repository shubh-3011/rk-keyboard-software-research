# RK profile tuple semantics

This is a confidence-ranked interpretation of the mapping tuples stored in
the installed RK Keyboard Software 4.06 profiles. It is based on the 189
`KB.ini` files and the hash-matched `DeviceDriver.exe` snapshot documented in
the [profile schema audit](rk-profile-schema-audit.md). No RK process or
keyboard interface was run or opened.

The repository preserves every source tuple. The descriptions below do not
authorize normalizing, dropping, or rewriting cells whose meanings remain
uncertain.

## `[KEY]` rows

Each row begins with four values that the catalog extractor parses as
`x,y,x2,y2`, deriving rectangle width and height as `x2-x` and `y2-y`.
These are visual layout coordinates in the profile projection. They are not
established as keyboard matrix coordinates. Zero-sized rectangles can still
have mapping records and must not be dropped from device-related data.

Most rows then have four further DWORD-like values. Standard S98 profile
`022F` examples show values that match familiar Windows virtual-key codes:
Esc is `0x1B`, F1 is `0x70`, Tab is `0x09`, and Q is `0x51`. Corpus-wide
patterns support the following candidate roles, but the raw `KB.ini` columns
have not been traced end-to-end into the native runtime records:

| Cell after `x,y,x2,y2` | Observed pattern | Candidate interpretation | Confidence and limit |
| --- | --- | --- | --- |
| 5 | Mostly `0x02` | Action or mapping type | Inference from repeated values; no source-to-runtime conversion recovered. |
| 6 | Common keys match Windows VK values | Primary key/action code | Strong pattern match for standard keys; other action values and device-specific translations remain open. |
| 7 | Mostly zero | Auxiliary or extension code | Candidate only; zero frequency does not define its role. |
| 8 | Values from 0 through 131, 126 distinct values in the corpus | Matrix/output index | Candidate only. `FUN_00411260` rejects runtime matrix indices above `0x83`, but no load path proves this raw cell becomes that runtime field. |

The runtime translator at `FUN_00411260` (`0x00411260`) processes 132-entry
layers of 16-byte records and calls a device-specific virtual method at object
vtable offset `+0x60`. It also reads a byte from a separate global table and
reports invalid entries using the name `MatrixInx`. This proves a
device-specific translation stage exists; it does not prove how `[KEY]`
columns 5–8 populate the translated record.

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
a packed HID usage-page and usage convention; that is a candidate
interpretation only because device-specific virtual translators sit between
profile data and packets.

`FUN_00411260` identifies runtime macro records by tag byte `+3 == 5` and
reads a macro buffer ID at `+8`. This proves macro dispatch in the translated
runtime record, not a direct correspondence between any particular `FN` cell
and those offsets.

## `LedOpt*` rows

The installed profiles contain 3,765 six-cell `LedOpt*` tuples. Comments and
profile-localized labels identify some effects: for example, profile `020B`
annotates `LedOpt1=1` as steady lighting, `LedOpt2=2` as breathing,
`LedOpt3=3` as a fantasy effect, and `LedOpt18=19` as custom lighting. The
labels corroborate slot names in that profile but do not establish that a
cell value universally selects a device effect. Zero and duplicate values,
including the custom value `19`, rule out assuming a direct slot-to-enum
mapping.

The first cell is a plausible effect/mode value. The remaining five cells
often look boolean, but their per-device behavior and command positions are
unknown. The driver has no individual string literals `LedOpt1` through
`LedOpt21`; generic INI access or an indirect consumer is still possible.
See the [settings serializer audit](rk-setting-serializer-audit.md) for
lighting command paths and packet limitations.

## `OPT` fields and end-to-end gap

The exhaustive [schema ledger](rk-profile-schema-fields.csv) records 88
option names, all 6,506 assignments, value forms, omissions, and comments.
Some individual runtime paths are well-supported: `Fw` selects the initial
RKKB versus G5 handler family; model-table initialization reads VID/PID,
`ShowScreen`, `Fw`, `DevTy`, and wireless IDs; and the 3632 companion path
compares six bytes whose origin is unresolved. A targeted exception traces
`DefBri`, `LightUI`, and `LightHW` from profile loading into brightness-value
display and serializer data; the physical scale and specific UI event handler
remain unresolved. A field name or literal match alone does not establish
units or device behavior.

No complete path has been recovered from the `KB.ini` parser through every
`KEY`, `FN`, `LedOpt`, and `OPT` cell into UI state, device-family virtual
translation, and serialized packet bytes. The data is exhaustive at the
storage level; behavioral meaning is only partially decoded.

