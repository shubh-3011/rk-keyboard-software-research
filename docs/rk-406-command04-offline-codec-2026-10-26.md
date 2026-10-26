# Installed 4.06 command-4 offline patch codec — 2026-10-26

## Scope and artifact identity

This is a conservative, pure offline reconstruction of two 128-byte patching
functions in the installed `C:\Program Files (x86)\RK Keyboard Software\DeviceDriver.exe`:

- SHA-256: `c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6`.
- Firmware-2 body: `[0x00411700, 0x004118F4)`, 500 bytes, SHA-256
  `54371ac6a9c5ba64aab87c2dac661b406bdb1e5d492b902cc2c8103c77475f9b`.
- Ordinary body: `[0x00411900, 0x00411B4B)`, 587 bytes, SHA-256
  `72814998b7e7ef359266102808b3c9943bed53921ec4aaaba6c9218ff783cd55`.

Addresses are preferred-image VAs in this exact 32-bit PE, image base `0x400000`.
Inspection used existing Python `pefile` and Capstone 5.0.7, decoding complete
functions from their true entries, not interpreting unaligned byte searches as
instructions. No vendor application, updater, HID interface, or device command
was executed. Builds and tests execute only the independent reconstruction.

The separate 4.6 driver in `rk-v4.6-brightness-profile-to-writer-follow-up.md`
has SHA-256 `8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`.
Its addresses and compact row layout must not be substituted here.

## Implementation and inputs

- Production: `rebuild/windows/LightingPacketCodec.cs`.
- Dependency-free executable tests: `rebuild/windows/tests/LightingPacket.Tests.csproj`
  and `rebuild/windows/tests/LightingPacketTests.cs`.
- Read-only binary evidence verifier: `scripts/audit_rk406_command04_codec.py`.

`LightingPacketCodec.Patch` accepts an exact 128-byte seed; explicit layout and
scalar state in `LightingPacketInputs`; canonical `LightingPacketRow` values;
profile mapping DWORDs; `LightHW` and `DebounceHW` byte tables; and exactly the
three `(offset,value)` byte pairs consumed by the native reset overlay.
These are already-parsed state, not an INI parser or raw configuration loader.
`GaoshouIndex` and `RgbOffIndex` must reflect resolved profile state; the codec
does not infer firmware families, synthesize profile tables, or apply loader
fallbacks. The input class defaults are explicit construction conveniences,
not a claim that an absent profile selects a hardware-compatible configuration.

Canonical notation:

```text
R(i) = config + 0x2140 + 0x30*i
S(i) = DWORD[R(i)+0x00]      (LightingPacketRow.Field00)
B(i) = DWORD[R(i)+0x04]      (Field04, LightHW index)
Q(i) = DWORD[R(i)+0x0C]      (Field0C)
F(i) = DWORD[R(i)+0x2C]      (Field2C)
M(i) = DWORD[0x611A10+0x3C*i]
N    = BYTE[0x612B00]
selected = BYTE[config+0x213C]
q(i) = F(i) != 0 ? 7 : low8(Q(i))
p(i) = ((S(i)&15)<<4) | (q(i)&15)
```

Brightness is **canonical record +4, absolute config+0x2144+0x30*i**.
`config+0x2138+0x30*i`, followed by `[base+0x0C]`, yields the same address;
it does not yield `config+0x2140`. This report does not repeat the slider-path
investigation or rely on its earlier no-brightness-store conclusion.

The row layout is consistent with the initializer at `0x45A430` and existing
`rk-lighting-profile-record-path-audit.md`. The output packers independently
establish the source accesses below. `S`, `Q`, and `F` remain neutral names:
initialization from a speed-related profile value does not establish units,
and packing into a nibble does not establish a user-facing control identity.

## Native write order and layout

### Initial ResetItem overlay, both layouts

At `0x41173B–0x41178F` / `0x411960–0x4119AF`, apply the overlay only when
`flags & 0x10` and the first DWORD at `0x612B84` is nonzero. Process pairs
at byte offsets 0/1, 2/3, and 4/5 in order. Skip only `(0,0)`; otherwise
write `out[offset] = value`. A third nonzero pair alone does not enable the
overlay. Both an offset-zero/nonzero-value pair and a nonzero-offset/zero-value
pair are real writes. Normal packing follows and wins on overlaps.

The profile loader reads `[OPT] ResetItem` and passes destination `0x612B84`
at `0x451EEE–0x451F21`. This identifies the profile key; it is not a complete
specification of the generic parser or a reason to consume more than the three
pairs used by these packers.

### Ordinary entry 0x411900

`0x41191C–0x411937` sums **only M(0) through M(14)** with 32-bit wrapping.
The loop starts at `0x611A4C`, processes three cells per iteration, advances by
`0xB4`, and terminates before `0x611DD0`: five groups of three, not 24 cells.
Interpret the final sum as signed; `mapped = signed32(sum32) > 0`.

Header writes, in order:

1. `out[9] = (selected == GaoshouIndex)`, `0x4119BD–0x4119C6`.
2. `out[0x0A] = low8(mapped ? M(selected) : selected+1)`,
   `0x4119C9–0x4119D8`.
3. If selected equals `RGBOFFIndex`, overwrite `out[0x0A] = 0`,
   `0x4119DB–0x4119E3`.
4. `out[0x0B] = low8(BYTE[config+0x25C0]+0x20)`, `0x4119E7–0x4119EF`.
5. `out[0x39] = 0xFF`, then `out[0x38] = 0xFF`, `0x4119F2–0x4119F7`.

For each `i` in `[0,N)`, a set `LedMask` bit skips the row
(`0x411A20–0x411A2F`). Otherwise:

```text
d = mapped ? 0x38+2*M(i) : 0x3A+2*i
out[d]   = LightHW[B(i)]
out[d+1] = p(i)
```

Destination selection: `0x411A31–0x411A41`; override/source selection:
`0x411A43–0x411A50`; stores: `0x411A57`, `0x411A65`.
Zero mappings in mapped mode are **not skipped**: they overwrite `0x38/0x39`.
Duplicate mappings are last-row-wins. After the loop, when selected equals
`GaoshouIndex`, write `out[0x5E] = LightHW[B(selected)]`, at
`0x411A8D–0x411AA8`. This lies outside the mask loop and can overwrite a row
byte, including a no-op same-value write. The selected special row may be
outside `[0,N)` provided its explicit source row is available.

### Firmware-2 entry 0x411700

There is no sum gate or sequential fallback. Write `out[0x21] = low8(M(selected))`
at `0x411795–0x41179B`; overwrite with zero on `RGBOFFIndex` equality at
`0x41179E–0x4117A6`.

For each `i` in `[0,N)`, skip when its mask bit is set **or M(i) is zero**
(`0x4117D0–0x4117E7`). Otherwise write, in native order:

```text
out[0x54+2*M(i)] = p(i)
out[0x53+2*M(i)] = LightHW[B(i)]
if i == M(i):
    out[0x22] = q(i)          # full low byte, NOT the nibble-masked value
    out[0x23] = LightHW[B(i)]
    out[0x24] = S(i)&15
```

Source selection and pair construction: `0x4117E9–0x411820`.
The comparison at `0x411824` uses the **loop ordinal**, not selected ordinal.
Triplet stores: `0x41182C`, `0x41182F`, `0x411832`. Multiple matching rows
overwrite this triplet; no matching eligible row leaves it unchanged.

### Following scalar writes

- If `DWORD[0x6117E8] != 0`, translate `BYTE[config+0x3E02]` through
  `DebounceHW` at `0x6117EC`. Ordinary writes only `out[3]`
  (`0x411AAB–0x411AC1`). Firmware-2 writes `out[3]` then `out[2]`
  (`0x411855–0x411875`). Gate zero preserves the existing bytes.
- Set the low-byte tap-like field to zero when `DWORD[config+0x3E04] != 0`,
  otherwise to `low8(DWORD[config+0x3E08])`. Ordinary destination is `0x16`
  (`0x411AC4–0x411AD7`); firmware-2 destination is `8`
  (`0x411878–0x41188B`).
- For signed `DWORD[config+0x3E14]` in `1..5`, translate respectively to
  `10,20,40,60,0`. Ordinary destination is `0x18`
  (`0x411ADA–0x411B07`); firmware-2 destination is `9`
  (`0x41188E–0x4118BB`). Every other input **preserves** the seed/overlay byte.
- Ordinary writes `out[0x1B] = (BYTE[config+0x3E20] == 0)` at
  `0x411B0A–0x411B19`. Firmware-2 instead writes constant zero to `out[5]`
  at `0x4118D1`.

The embedded logging supports debounce/tap/sleep-like descriptions, not physical
units, enumerations of accepted firmware values, or particular visible labels.

## Profile gates and caller context

- `LedOpt(i+1)` tuple cell 1 is duplicated into mapping row offsets `+0/+4`
  by stores `0x4531CA/0x4531CD`; six-cell stores continue to `0x453202`.
- `LedMask` loads at `0x4514C4–0x4514E8`, global `0x611798`.
- `GaoshouIndex` loads with default 1 at `0x45169F–0x4516B5`, global `0x6117CC`.
- `RGBOFFIndex` loads with default -1 at `0x4516BA–0x4516D0`, global
  `0x6117D0`. The -1 fallback at `0x4516DA–0x4516F2` resolves to 14 for
  profile `Fw==0` or 18 otherwise. `Fw` loads to `0x611760` at
  `0x45140F–0x451426`.
- `DebounceUI` gate/table setup: `0x451735–0x451781`; `DebounceHW` setup:
  `0x45178B–0x4517CB`. The actual gate is the first DWORD, not an inferred
  count or simply the textual key's presence.
- Runtime count `N` is assigned at `0x423434–0x42343E` from helper
  `0x422DA0`. That helper counts consecutive nonempty generated labels up to
  24. Empty-label exit is `0x422E39–0x422E3E`; count increment is
  `0x422E49`, before mask test `0x422E51–0x422E57`; bound is
  `0x422F82–0x422F90`. Masked rows still contribute to `N`.
- Apply routine `0x411B90` selects firmware-2 when device field `+0x24C==2`,
  otherwise ordinary, at `0x412121–0x41214E`. That is a device-object field
  comparison, not proof that any particular installed profile/device is active.
- The G5 writer call at `0x41239D–0x4123B0` supplies operation 1, command 4,
  length `0x80`, to `0x40F700`. Neither the codec nor its tests call it.
- The caller's existing-block read and `5A A5` check at
  `0x4120D4–0x4120E5` are not guaranteed successful on every continuation
  path: bypass/error-continuation paths exist. The patch functions themselves
  do not validate or generate a block signature.
- `CmdReset` is distinct from the overlay. Its loader store is `0x451EF8`
  to `0x612B8C`; the caller's guarded reset virtual call and subsequent flag
  clearing occur at `0x411C9B–0x411CD1`. The codec only patches bytes for
  supplied flags; it does not emulate this orchestrator or any reset operation.

## Safety contract, provenance, and deliberate differences

The codec first constructs a write plan. It validates every accessed mapping,
row/table index, and destination before cloning or mutating the seed copy.
Failures throw an `ArgumentException` subtype and return no partial result.
Rows are limited to 24; selected ordinals are limited to 0..23. Source checks
follow actual branch accesses: masked rows and firmware-2 zero mappings do not
access their brightness table index. Ordinary always requires at least the
first 15 mapping cells, even with zero runtime rows. Additional selected mapping
and special-row checks occur when their branches access those sources.

Destination arithmetic uses a wider type to prevent multiply/add wrapping from
turning invalid mappings into valid seed indices. Native unchecked memory
accesses are deliberately **not** emulated. Ordinary mapped pairs fit only for
`M<=35`; firmware-2 pairs fit only for `M<=21`. Disabled overlay bytes are not
treated as accesses; enabled offsets outside 0..127 are rejected. Inputs never
authorize a write outside the seed, even if the original executable would do so.

`LightingPacketResult` provides:

- `Bytes`: a new exact 128-byte result; caller seed is unchanged.
- `Writes`: ordered individual stores with previous/new byte and source/address
  attribution, including stores that do not change the current byte.
- `Collisions`: every repeated destination, linking preceding and overwriting
  write indices. This includes ordinary initialization replacement, explicit
  header overrides, duplicate mapped rows, overlay replacement, and special-byte
  replacement. A collision is an observation, not automatically a defect.
- `Changes`: only final bytes different from the original seed, each linked
  to its final writer. Intermediate changes later undone are in `Writes`, not
  misreported as final changes.

No checksum or signature is invented. Unknown bytes are preserved unless an
explicit evidenced write targets them. This is a patch codec, not a complete
128-byte semantic decoder, a safe hardware protocol, or proof of binary-wide
equivalence. It is not connected to the UI, existing framing codecs, or send APIs.

## Exact byte witnesses and reproducibility

The verifier pins the whole executable, both complete function bodies, and 33
instruction witnesses decoded from their true entries. Representative checked
instructions include:

```text
00411929 05b4000000      add eax, 0xb4
0041192E 3dd01d6100      cmp eax, 0x611dd0
004119CB 7e08            jle 0x4119d5
00411A3B 8d7c3f38        lea edi, [edi + edi + 0x38]
00411A50 0fb68968186100  movzx ecx, byte ptr [ecx + 0x611868]
00411A9B 8b941944210000  mov edx, dword ptr [ecx + ebx + 0x2144]
00411824 3b13            cmp edx, dword ptr [ebx]
00411826 750d            jne 0x411835
0041182C 885622          mov byte ptr [esi + 0x22], dl
```

From the repository root, in PowerShell:

```powershell
python scripts\audit_rk406_command04_codec.py
# Optional explicit target (read-only):
python scripts\audit_rk406_command04_codec.py 'C:\Program Files (x86)\RK Keyboard Software\DeviceDriver.exe'
.\rebuild\windows\.dotnet\dotnet.exe run --project rebuild\windows\tests\LightingPacket.Tests.csproj
.\rebuild\windows\.dotnet\dotnet.exe build rebuild\windows\RKRebuild.csproj --no-restore
```

Recorded validation on this pass:

- **119 assertions passed**, no third-party test framework/dependencies.
- Main application build succeeded: **0 warnings, 0 errors**. Its existing
  compile glob includes the new production file and excludes test sources.
- Verifier passed executable identity, **2 complete bodies**, and **33 instruction
  witnesses**. It performs no target execution or file writes. It is an evidence
  regression check, not a formal proof that the C# implementation is equivalent.

Hand-computed complete-packet fixtures cover both layouts, fallback/mapped
selection, signed overflow/zero/negative sums, the first-15 bound, zero/duplicate
mappings, masks, the exact triplet condition, repeated triplet stores, overlay
order/gates, nibble and byte truncation, special brightness overlap, scalar
translations/preservation, final-byte destination bounds, no-op provenance, and
signature preservation/non-generation. Invalid cases cover seed size, layout,
row count, selected ordinal, missing mapping/row/table sources, large unsigned
indices, overflowing destination candidates, reset length/offsets, and errors
after earlier valid planned writes. Caller seeds remain unchanged on failures.

## Unresolved boundaries

`Q(i)`, `F(i)`, `config+0x25C0`, and `config+0x3E20` retain unresolved
user-facing semantics. Brightness, speed, debounce, tap, and sleep physical
units/allowed hardware values remain unproved. Profile mapping collisions and
the firmware-2 ordinal-equality condition may be intentional or unusual; this
codec reproduces their bounded static behavior rather than correcting them.
Unknown preserved bytes, full profile parser semantics, active runtime objects,
message delivery, transport acknowledgements, and firmware acceptance are outside
the evidence. No hardware compatibility or safety claim follows from passing
these offline tests.
