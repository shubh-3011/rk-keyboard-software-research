# RK keymap translation and packet-size audit

This note narrows the gap between the installed `KB.ini` mapping tuples and
the native mapping/serializer code in RK Keyboard Software 4.06. It is a
static analysis of the installed profile files and the hash-identified
`DeviceDriver.exe`; no RK process or keyboard interface was opened, and no
report was sent.

The binary analyzed is
`<local-workspace>\_rk_analysis\inputs\DeviceDriver.exe`,
SHA-256
`C03F88BC4E2D78AA4392D7445B0FD62182DC824F97F5D5DB40BD009E547A9AB6`, loaded
at image base `0x00400000`. Addresses below are virtual addresses in that
image. The installed profile example is
`C:\Program Files (x86)\RK Keyboard Software\Dev\022F\KB.ini` (RK S98
profile). Existing native decompiler excerpts are in
`_rk_analysis/reports/device-targeted-functions.txt` and
`_rk_analysis/reports/brightness-global-xrefs.txt`.

## Findings by confidence

### Proven statically: the runtime conversion is not a byte-for-byte copy

The installed `022F` profile contains, for example:

```ini
[KEY]
K1=30,31,59,65, 0x02,0x1B,0x00,0
K2=118,31,147,65, 0x02,0x70,0x00,12

[FN1]
K2=0x09,0x01,0x02000194
```

The first four `[KEY]` values are the visual rectangle coordinates described
in the [profile schema audit](rk-profile-schema-audit.md). In this profile,
the next value is usually `0x02`; the following value matches familiar
Windows virtual-key values for standard keys (Esc `0x1B`, F1 `0x70`). A new
[profile-to-UI path audit](rk-keymap-ui-path-audit.md) confirms that tuple
cell 8 is copied into record byte `+4`, which the RKKB translator reads as its
132-slot output index. The remaining action and auxiliary fields still need
semantic decoding.

In the RKKB path, `FUN_00413B20` (`0x00413B20`) walks exactly `0x84` (132)
records, advancing the input by `0x10` (16) bytes per record. For each record
with a nonzero first DWORD, it calls `FUN_00413410` (`0x00413410`). That
helper reads a tag byte at record offset `+3`, the low 24 bits of the first
DWORD, and further bytes/DWORDs at offsets `+6` through `+0x0C`; it has
tag-specific branches and embedded lookup/jump tables at `0x00413710`,
`0x00413724`, `0x00413768`, `0x004137C4`, `0x004137E8`, and `0x00413800`.
The returned value is a translated 32-bit value, not an unchanged copy of
the raw code byte. Some branches return fixed packed constants; others use
the record's extended fields or a table. This establishes an action
translation stage, but not that any particular raw profile column lands at
the corresponding runtime-record offset.

`FUN_00413B20` uses the byte at
`0x006169D0 + (record_index * 0x10)` as an output index. It rejects an index
above `0x83`, checks whether the destination DWORD is already nonzero, stores
the translated value at `destination[index]`, and finally copies 132 DWORDs
(`0x210` bytes) to its output. The repeated 16-byte stride and 132-entry
bound establish a 132-slot lookup/translation table rooted at `0x006169D0`;
the precise initialization and model-specific contents of every table entry
remain unresolved.

The caller in `FUN_00413BF0` (`0x00413BF0`) invokes `FUN_00413B20` four times.
The source advances by `0x840` bytes and destination by `0x210` bytes each
time. Thus the observed runtime shape is four layers of 132 16-byte input
records, translated into four layers of 132 DWORD values. The complete
translated output size is `4 * 0x210 = 0x840` bytes. This proves the sizes and
loop structure, not that the four runtime inputs are populated directly from
the `[KEY]`, `[FN1]`, or `[FN2]` text sections.

The other family path, `FUN_00411260` (`0x00411260`), also loops over four
layers and 132 16-byte records. For nonzero records it calls a virtual
translator at vtable offset `+0x60`, uses a 132-slot index, and rejects
indices above `0x83` or a translator result of `-1`. This is separate
family-specific translation evidence; it does not demonstrate that its
runtime records or table contents are identical to RKKB's.

### Proven statically: the `0x780` write is a different path from the four-layer buffer

`FUN_004143F0` (`0x004143F0`) constructs a buffer with prefix `04 00`, copies
exactly `0x780` bytes from its caller-supplied pointer, then calls
`FUN_00413220` with total length `0x782`. Its failure string at `0x005CBDB0`
is “SendKey Failed”. The fixed copy length is therefore proven; `0x780` is
not the size of the four translated layers (`0x840`).

The RKKB apply caller's surrounding control flow matters for interpreting
that length. In `FUN_00413BF0`, the `FUN_004143F0` call is reached only when
the macro-processing loop has counted at least one macro association. That
loop builds a staging buffer by calling `FUN_00413870` for macro objects and
advances the staging pointer by global stride `0x00611FE4`. The `04 00`
wrapper therefore carries the buffer assembled in the macro-processing
path. The log string says “SendKey”, but does not establish that the 1920-byte
payload is the full keymap or explain its internal record layout. In
particular, `0x780 = 4 * 480` is arithmetic only; it is not evidence of 120
records per layer.

Separately, the apply function constructs report prefixes `01 F8` and,
conditionally, `10 F8`, each followed by a `0x1F8`-byte copied region and
sent with total length `0x1F9` through `FUN_00413220`. The second write is
gated by global `0x006117E4`, loaded from profile `OPT/Show10FNLayer` at
`0x00452BD0` and read at `0x00414294`. The exact data-source relationship
between these fixed-size regions, all four translated layers, and the
profile's `[FN1]`/`[FN2]` rows has not been recovered.

### Proven statically: macro rows are associated with key slots inside the apply path

During `FUN_00413BF0`, the code scans the four per-layer mapping regions for
records whose byte `+3` is `5`. For such a record it searches the macro list
at global `0x0060359C`. The match compares the macro object's DWORD at `+4`
with a DWORD read from the apply configuration at
`local_107c + ((layer_offset + 4 + slot) * 0x10)`. When a match is found, the
code obtains a matrix/output index from the 132-entry table and incorporates
the macro object's buffer ID (field `+0x64`) into that translated slot. A new
buffer ID is assigned when the object does not already have one. The exact
meaning of the compared configuration DWORD and its relation to a textual
profile cell are unresolved.

The macro serializer `FUN_00413870` (`0x00413870`) reads a WORD count at
object offset `+0x6A`, starts event records at `+0x72`, and advances through
8-byte event records. It compacts events into three-byte entries in a
`0x1FF`-byte temporary buffer and returns the produced byte count. The
individual event fields are transformed by a lookup/switch path; they are
not copied as a sequence of eight-byte records. The outer macro staging
stride and capacity policy are not fully recovered. The call-site ordering
supports the inference that the `04 00` fixed-size transmission uses this
macro staging buffer, but does not by itself prove how each returned length
is placed in the 0x780-byte block.

## Candidate interpretations and unresolved mapping

- **Candidate: `[KEY]` column 6 is a Windows virtual-key-like value.**
  Standard keys match familiar VK constants, but no path proves that column 6
  becomes a specific native record field or is used as a Windows VK in the
  serialized output.
- **Confirmed: `[KEY]` column 8 supplies the RKKB slot-index byte.** The
  profile parser copies this cell to byte `+4` of a 16-byte action record;
  the RKKB translator reads that byte as a bounded 0–131 output slot. See the
  [profile-to-UI path audit](rk-keymap-ui-path-audit.md). The purpose of the
  optional ninth and tenth cells remains unresolved.
- **Candidate: `[FN1]`/`[FN2]` tuples describe alternate actions at the same
  visual key IDs.** Their section/key naming supports that reading, but no
  static parser trace connects a sample row such as `FN1/K2` to one of the
  four native 16-byte records or to the `10 F8` payload.
- **Partially resolved: profile tuple columns to runtime records.** The
  `[KEY]` parser's base action record and cell-8 slot-index path are mapped.
  Construction of the four translated runtime layers from `[KEY]`, `[FN1]`,
  `[FN2]`, and edited UI state remains unresolved.
- **Unresolved: full `0x780` payload schema.** The wrapper length and prefix
  are proven; caller context ties it to macro staging, while the error string
  says “SendKey”. No runtime capture is available, and this static audit does
  not resolve those semantics.
- **Unresolved: model variation and behavior.** The evidence is one installed
  4.06 binary and its 189 profiles. It does not establish that every RK model,
  firmware revision, or later software version uses these paths.

No hardware behavior, report ACK, or firmware effect was tested. Nothing in
this audit is a recommendation to replay the writes.
