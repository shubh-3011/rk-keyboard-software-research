# 4.06 ordinary G5 keymap: static recovery and the readback boundary

## Outcome

The command-`03` writer, ordinary-key encoding, local-map layers, matrix-slot
order, macro fix-up, and profile layer-count source can be identified for the
installed 4.06 image. A command-`83` current-keymap query **cannot yet be
identified**. Do not infer it by setting bit 7 of command `03`.

No codec or tests were added: the requested device-current-settings schema and
readback identity are insufficiently established. In particular, accepting an
arbitrary caller buffer as a device-current seed would conceal the largest
remaining gap. This document supplies numeric encoding examples and exact next
investigation targets instead of a guessed current-settings implementation.

Only this new document was written. Existing files, the native mapping UI draft,
vendor processes, hardware, and git were not modified or invoked. All observations
in this follow-up are static; no command or report was sent.

## Identity, reused evidence, and verification

Target: `C:\Program Files (x86)\RK Keyboard Software\DeviceDriver.exe`,
2,326,528 bytes, PE32 x86, image base `0x00400000`, SHA-256:

`c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6`.

Reused first:

- [Settings serializer](rk-setting-serializer-audit.md), especially flag `01`.
- [Keymap translation](rk-keymap-translation-audit.md).
- [Profile/UI bridge](rk-keymap-ui-path-audit.md).
- [G5 vtable ledger](rk-406-cdevg5-vtable-map.csv).
- Existing local decompiler export
  `../_rk_analysis/reports/device-targeted-functions.txt` (outside this repo).
- Retained REA objdump record `.research/rk406-rea-objdump-2026-10-26.json`,
  Evidence ID
  `ev_3cd9be563f80334bed8ef1a62351127206977c720e5f87b695d9c1574454eb74`,
  whose subject digest matches the target above.

REA MCP/native tools were not available in this child session. No installation
or configuration repair was attempted. New checks used installed Python
`pefile` and Capstone directly, and are **independent static checks**, not newly
issued REA Evidence. 2,387 retained REA raw-byte lines in the eight ranges below
were compared against the installed PE and matched. This checks instruction/data
bytes, not every decompiler type or semantic interpretation.

A rooted Capstone traversal of `004107A0` followed fallthrough, direct branches,
and all destinations of these six indirect jumps:

```text
jump VA   pointer-table VA   number of DWORD destinations
004107C7  00410CF4           9
004108AA  00410D18           17
00410ACE  00410DB8           10
00410B3F  00410DE0           5
00410BB7  00410DF4           18
00410C66  00410E9C           25
```

Result: **579 reachable instructions, 1,361 instruction bytes, 64 returns**;
exact coverage of `[004107A0,00410CF1)`. Calls were treated as returning and
not recursively executed or followed. `00410CF1` is alignment; subsequent bytes
through `00410EFF` include the selector/pointer tables. This is full translator
body verification, not a full-program CFG or a hardware acceptance test.

The following are exact SHA-256 ranges, **end exclusive**. They include complete
functions through their final instruction (translator range also includes its
tables/padding). They are not hashes of selected witness snippets:

```text
0040ECB0..0040EDB3 constructor
35dc6c84d6d65cc87a9724806df602a6b1c6fa17e46dde8c5ed33f62125b1df4
0040F700..0040F9B4 AccessData
441b7426da3207d624b5711f8b14ebf12fa286da33d51e0f6f022e88e3bbf728
0040F9C0..0040FA45 SetMatrix
d1e28f3da99030f68eae09576e409d9aa508250541ece4cdec857c257a403472
004107A0..00410F00 action translator plus tables
013d4d5440f6f5b0e672bcb82e6b0b6315e7b0d66fb32eba01629161b5bf1f9a
00411260..0041164C FillMatrix
e4cc480682b7a54de61fbdf8bbb6ea4889c301cc464458ecb93dba750357d429
00411650..004116F5 matrix debug formatter
de2e2d43cb30fbdab8d178ad716346a9c447bfe21508865fef48f29b75009397
00411B90..0041288C ApplySetting
9191f985a987218e0410d1023fe9ae9aad2c35a670a19c039cb73e8a3498936a
00463EE0..00463F00 numeric key lookup
b9b102c086b39075e7a9f67045864794b0aa7cb89f305e9ce095454f81d6fef8
005D2FC0..005D30A4 numeric key lookup data (114 two-byte pairs)
b6f313df4299451aac121648bb8759081c141bec7bb74a399f162e95574beae1
```

For the `.text` ranges above, file offset is `VA - 00400000 - 0C00`.
For other sections, use the PE section mapping, not that shortcut.

## Recovered entries and byte witnesses

- `00411B90`: shared G5/3632 apply orchestrator; G5 vtable slot `+3C`.
- `00411260`: map-to-matrix conversion, followed by macro reference fix-up.
- `004107A0`: G5 vtable slot `+60`, action descriptor to DWORD.
- `0040F9C0`: matrix writer; not a query.
- `0040F700`: generic feature transport; read operation exists, but does not
  establish the existence or schema of any particular command.
- `00463EE0`: numeric key lookup used by the ordinary descriptor branch.
- **Command `83` query entry: unresolved.** No function may be named as that
  query based on this investigation.

Selected executable-byte witnesses (VAs specific to the pinned hash):

```text
0040ED10 B8 7E 00 00 00             mov eax,126
0040ED1B 89 86 D4 02 00 00          mov [esi+2D4],eax
004107A7 0F B6 4E 03                movzx ecx,byte [esi+3]
0041084C 83 F9 02                   cmp ecx,2
00410965 0F B6 4E 0A                movzx ecx,byte [esi+0A]
0041096B E8 70 35 05 00             call 00463EE0
00410976 E8 65 35 05 00             call 00463EE0
004109D3 C1 E0 08                   shl eax,8
004112BD 8B 81 D4 02 00 00          mov eax,[ecx+2D4]
004112D5 8D 45 38                   lea eax,[ebp+38]
00411300 FF D0                      call eax ; resolved slot +60
0041131F 89 04 8A                   mov [edx+ecx*4],eax
00411327 83 C6 10                   add esi,10
0041132A 81 FB 84 00 00 00          cmp ebx,132
00411343 81 C6 40 08 00 00          add esi,840
0041134F 83 F8 04                   cmp eax,4
00411D7E 0F B6 2D C9 69 61 00       movzx ebp,byte [006169C9]
00411DE5 8B 83 D4 02 00 00          mov eax,[ebx+2D4]
00411DF0 8D 0C 85 00 00 00 00       lea ecx,[eax*4]
00411EF3 E8 C8 DA FF FF             call 0040F9C0
00411F16 03 74 24 20                add esi,[esp+20] ; wire layer stride
0040FA10 6A 03                      push 3 ; command
0040FA12 6A 01                      push 1 ; write operation
0040FA18 E8 E3 FC FF FF             call 0040F700
0045290C 6A 04                      push 4 ; LayerNum default
0045290E 68 30 6E 5D 00             push 005D6E30 ; UTF-16 LayerNum
00452932 A2 C9 69 61 00             mov [006169C9],al
```

## Local current settings versus device-current settings

The existing profile/UI audit establishes a **local map object**, not a
device-read response:

- Dirty layer mask: map `+30`; selected local layer: map `+34`.
- Source records: `map + 38 + layer*840 + keyIndex*10`.
- Four layers, 132 records each, 16 bytes per record.
- Layer starts: `+0038`, `+0878`, `+10B8`, `+18F8`.
- End of these four source arrays: map `+2138`, exclusive.
- Profile source starts: `006169CC`, `0061720C`, `00617A4C`, `0061828C` for
  `[KEY]`, `[FN1]`, `[FN2]`, `[TAP]` respectively. Conditional restoration and
  unmatched-macro fallback prove these correspondences, not complete default
  initialization or physical Fn/tap behavior.

Do not label `pro.dct`, this map object, or a zero-filled matrix as a current
device snapshot. There is no recovered device-response-to-map inverse here.

## Matrix size, index, order, and layer option

`FillMatrix` scans all four source layers even though Apply's write loop uses
the separate byte global `006169C9`. For source row `k`:

```text
source = map + 0x38 + layer*0x840 + k*16
slot   = byte at 0x006169D0 + k*16
output = translatedBuffer + layer*(this[+0x2D4]*4) + slot*4
```

The apparent `00616998` constant in the decompiler is a difference-base
calculation: adding source offset `+38` reaches `006169D0`. It is the
profile `[KEY]` cell-8 mapping-slot byte, **not** a direct visual-key order.
Nonempty records are translated; `-1` and slot `>=132` fail the conversion.
Rows are visited in ascending source order; this G5 store has no recovered
RKKB-style destination-nonzero/duplicate rejection. A later source row can
overwrite an earlier row mapped to the same slot. A UI must not silently
assume one-to-one slot mapping.

Important correction/qualification to existing prose: `this[+2D4]` is a
**device-object DWORD**, not a proved profile field. Its constructor value is
`0x7E` (126), which yields a **504-byte** command-3 layer. 132 source records
do not imply a 528-byte wire layer. The existing documentation's 528-byte
example is conditional on `this[+2D4] == 132`; it is not evidence that the
installed G5 constructor selects that value. The bounded retained-disassembly
search found the constructor store and three G5 reads, but no additional
direct `+2D4` store attributed to this class. Indirect field initialization or
aliasing is not exhausted. This is a further reason not to publish a universal
fixed-size codec.

The vendor conversion only checks slot `<132`, **not** slot `<this[+2D4]`.
A safe future codec must reject slots outside the actual selected wire-layer
capacity; reproducing this loose vendor bound would allow cross-layer writes.

At `00411EF3`, the writer receives byte length `this[+2D4]*4`, ESI points to
the current translated layer, and EDI is the zero-based layer index. In the
direct G5 branch of `0040F9C0`, command is `03`, option is that layer index,
operation is write `1`, report ID is object byte `+2D0`, and delay is 25 ms.
There is no extra per-key header in this layer payload: it is little-endian
DWORDs in matrix-slot order. The child path is separate: command `1` through
`0040D7E0`, not G5 framing.

Generic G5 framing is 520 bytes: report ID, command, option, zero, packet count,
zero-based packet index, little-endian chunk length, then up to 512 payload
bytes. For the constructor's 504 bytes there is one chunk; the hypothetical
528-byte case has chunks 512 and 16. Do not emit reports from these facts alone.

## Ordinary numeric key encoding, not guessed labels

The ordinary branch is tag/record byte `+3 == 2`, after the translator's special
subcode checks. Relevant input bytes are:

- `+08`: modifier bitmask (all eight bits preserved in the ordinary branch).
- `+09`: primary numeric key value.
- `+0A`: secondary numeric key value.

`00463EE0` searches **114 literal pairs** at `005D2FC0`. For each pair the first
byte is the output usage, the second is the input key value. It returns the
first match, or zero if absent. For the ordinary path, let `H(x)` be that
lookup. The return value is:

```text
DWORD = (H(record[9]) << 24) | (H(record[10]) << 16) | (record[8] << 8)
little-endian payload bytes = 00, modifier, H(secondary), H(primary)
```

This order follows the shifts/ORs at `004109BC..004109D8`; notably, a single
primary usage is in the **fourth**, not third, byte. It is not a four-byte
standard USB keyboard input report.

Examples below are binary lookup/packing facts, not deductions from artwork
or localized captions. Input descriptors have tag 2, secondary zero and
modifier zero, and pass the special-case checks:

```text
input +09   table pair (usage,input)   matrix DWORD   little-endian payload
41          04 41                     04000000       00 00 00 04
42          05 42                     05000000       00 00 00 05
1B          29 1B                     29000000       00 00 00 29
70          3A 70                     3A000000       00 00 00 3A
0D          28 0D                     28000000       00 00 00 28
20          2C 20                     2C000000       00 00 00 2C
```

These numeric pairs correspond to familiar VK-to-HID keyboard-page mappings,
but the evidence is the embedded bytes and called lookup, not that familiarity.
For example primary `41`, secondary `42`, modifiers `02` yields DWORD
`04050200`, bytes `00 02 05 04`. This describes packing only; simultaneous-key
device behavior was not tested.

Do not apply that formula indiscriminately to every tag-2 descriptor:

- `+08==0, +09==FA` returns `0000000D` (`0041085C..00410869`).
- `+08==0, +09==FB` returns `0000010D` (`00410870..0041087F`).
- `+09` in `1..5` returns descriptor DWORD `+0C` via `00410B9A`.
- `+09` in `88..E0` passes through the selector table at `00410D5C`; several
  selectors return fixed packed actions rather than the ordinary lookup.
- Other tags have their own switches, macro references, or passthrough values.

The FA/FB constants are proved encodings; calling them “Fn1” and “Fn2” solely
from their labels or adjacency is not justified. Unknown/unmapped input values
returning zero must not automatically become an editable “disabled key.”

## Profile guards and Fn/layer limits

The loader reads `[OPT] LayerNum` with default `4` (UTF-16 key at `005D6E30`)
and stores only AL to `006169C9` at `00452932`. Apply reads that byte at
`00411D7E` for the write/macro-dirty loops. `[OPT] LayerMask` is read next
(key at `005D6E44`) and stored at `006169C8`; its name is not proof that it
filters every Apply write. The concrete write gate is dirty mask `map+30`.

Do not conflate `LayerNum` with the hard-coded four-layer translator, the
selected UI layer at `map+34`, or RKKB's `Show10FNLayer`/`10 F8` path.
A defensive future offline API should require layer count 1..4, layer index
below that count, resolved wire capacity, and a validated G5 route; these
are proposed safety checks, not claims that vendor code enforces all of them.

The existing UI audit proves `[OPT] Fw` selects the special G5-style updater:
global `00611760`, loaded at `00451419/00451426`; updater `0041D7E0` can
restore or propagate FA/FB source records to layers 0..2 and mark mask `7`.
The general route then writes the selected layer. This does not establish
hardware Fn/tap acceptance or a universal profile-to-wire inverse.

## Macro-reference safety boundary

`FillMatrix` performs a second four-layer traversal for descriptor tag `5`.
It matches descriptor DWORD `+08` to macro object `+04`, assigns/uses buffer
IDs at macro object `+64`, and invokes serializer slot `+64` (`00410F00`).
It clears byte 3 of the mapped matrix DWORD, then ORs `(bufferID-1)<<24`.
The high byte is therefore **not always a primary HID usage**. The lower action
bytes determine its interpretation.

The generated macro buffer contains a `uint16 offset,uint16 length` table
followed by event blobs. The orchestrator may dirty additional macro-containing
layers and send command `5`; replacing a single matrix DWORD is not equivalent
to maintaining these references. A future ordinary-key patcher must preserve
all unedited opaque DWORDs, reject macro/unknown source actions as editable
ordinary keys, and neither synthesize nor garbage-collect macro IDs. It must
not clear macro state or emit command `5` as a side effect.

## Command 83: bounded negative evidence, not a protocol denial

The retained full `.text` disassembly and an independent raw `E8 rel32` scan
agree on these **12 direct calls** to `0040F700`:

```text
0040FA18 0040FA85 004101FC 00410279 00410314 004103AB
004106D4 0041209E 004123B0 00412845 0041293A 00412A21
```

Their recovered command immediates are `03,04,0A,0B,11,12,08,05,04,06,0D,0D`.
None selects read operation 2 or command `83`. The single `push 00000083`
in the retained linear sweep is `0040BD25`: a `memset` length, not a command.
Other immediate-83 candidates are comparisons or unrelated local stores.
The G5 27-slot ledger likewise has no named matrix-query slot. Existing
`82`, `84`, `87`, and `88` helpers are not evidence for `83`.

This does **not** prove firmware lacks command `83`, or exhaust computed
commands, indirect calls, other executables, later versions, or dynamically
obtained code. It establishes that the examined direct paths do not supply
the missing query entry, output length, option semantics, response validation,
or response-to-map conversion. Generic AccessData read behavior (SetFeature
before GetFeature) is not a passive backup mechanism.

## Exact next step toward mapping UI integration

1. Recover a hash-pinned current-matrix reader/consumer, if present, including
   its caller-selected command, option, exact requested byte length, per-chunk
   validation, and which returned bytes represent one layer. A protocol label
   or a guessed `83` constant is insufficient. If this binary has no such
   reachable reader, explicitly choose a separately authorized evidence source
   rather than presenting local settings as readback.
2. Resolve every initialization/alias of G5 object `+2D4` and profile selection
   for its matrix capacity. Reconcile 132 source rows against the constructor's
   126 wire slots and reject out-of-capacity mappings.
3. Join the profile rectangle row to `[KEY]` cell 8, with duplicate-slot checks,
   then join the selected layer to the exact wire-layer option. Use layer names
   only after their behavior is established; initially show numeric layer IDs.
4. Only then add an offline seed-preserving API. Suggested shape (design, **not
   an implemented API**): `ParseValidatedLayer(seed, provenance, capacity)` and
   `PatchOrdinaryKey(layer, slot, expectedOldBytes, numericKey)` returning a
   new payload plus an immutable list of offset/old/new/evidence changes.
   Require explicit source digest/profile/seed origin; preserve unknown bytes;
   check lengths, slot bounds, action kind, duplicate edits, and expected-old
   bytes. Reject undocumented usages and all macro edits. Do not expose an
   arbitrary command argument, a transport handle, or a hardware writer.
5. Offline tests should cover the numeric packing vectors above, immutable
   input/output ownership, unchanged unknown bytes, malformed/short/oversized
   seeds, mismatched provenance/old bytes, capacity 126 versus row bound 132,
   duplicate slots, all layer boundaries, unknown actions, and macro refusal.
   An optional installed-binary argument can verify the source hash and full
   function/table ranges above without executing the binary.

Until steps 1 and 2 are answered, the mapping UI can honestly display profile
defaults or local drafts with explicit provenance, but must not claim “read
current mapping” or enable hardware Apply based on a speculative command-83
codec. This boundary applies to the general replacement project, not only one
keyboard model.
