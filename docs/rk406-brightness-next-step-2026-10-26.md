# Installed 4.06 brightness: bounded next observation (2026-10-26)

## Outcome and scope

The next useful observation is **selected profile code + 24 mapping DWORDs +
selected lighting-row brightness index**, not another device query. Prepared
[`snapshot_rk406_brightness_mapping.js`](../scripts/snapshot_rk406_brightness_mapping.js)
for that purpose; **it was not run or attached**. No vendor function, runtime
process, hardware interface, or UI was operated in this investigation. Only this
report and that new script were written. No commit was made.

Static target: installed `C:\Program Files (x86)\RK Keyboard Software\DeviceDriver.exe`,
SHA-256 `c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6`.
All VAs below use preferred image base `0x400000`; relocate them against the
selected process's main-module base. Do not use 4.6 addresses or its row layout.
Existing Python `pefile`/Capstone were used for read-only file inspection.

**Selected profile identity is still unobserved.** The retained wireless
round-trip establishes root `CDevG5KB`, ordinary packer entry, and 20-byte child
reports, but contains no profile-code or mapping-table snapshot. Neither its
transport nor an S98 label identifies one of the eight S98 INI variants. Reading
installed Cfg/KB files cannot recover the current process's selection.

## Identity and table origin

- `WORD[0x61158E]` is the selected profile code used by the constructor scan.
  Exact witness `0x4465E0: 8b158e156100` loads a DWORD, but the subsequent
  `0x4465F0: 663b10` compares **DX**, so the bounded probe needs only two bytes.
- Correction to the wording in
  `rk-406-active-profile-apply-dispatch-follow-up.md`: the scan starts with
  `EAX=0x6102A2` (`0x4465E8: b8a2026100`), advances by `0x12`, and on match
  reconstructs the record base `0x6102A0+0x12*ordinal` at `0x446605–0x446608`.
  Thus it compares the profile-code WORD at **record+2**, not record+0.
  The `Fw`-aligned family discriminator remains record+0x0A.
- `FUN_004513B0` receives a profile identifier in ECX, saves it in EDI, and
  formats `%sDev\\%04X\\%s` (UTF-16 at `0x5D4EC4`) with `KB.ini`
  (`0x5D4EB4`) and its application-root string. This is a static path template,
  not permission to read or emit a live path.
- The mapping source is **`[OPT] LedOpt%d` in that KB.ini**, not a `[LIGHT]`
  section. Runtime profile table: `0x611A10 + 0x3C*i`, `0<=i<24`.
  Mapping `M(i)` is just the first DWORD of each row; do not dump each whole
  0x3C-byte row. Tuple cell 1 is zero-extended and stored at row `+0` and `+4`:
  `0x4531CA: 894dfc`, `0x4531CD: 894d00`, with EBP initially `0x611A14`.
- The generic byte-list parser is `0x44DC70`, called for LedOpt at `0x4531B5`
  with limit `0x1A` and radix register EBX=10. EBP advances by `0x3C` at
  `0x45323D: 83c53c`, bounded by `0x611FB4` at
  `0x453242: 81fdb41f6100`: at most 24 generated keys.
- **Missing-key early exit matters:** `0x45317F` tests the returned string's
  first WORD; `0x453187: 0f84c1000000` branches to `0x45324E`, after the loop.
  It does not skip only one tuple and continue. The earlier profile-record
  report's “empty result skips the tuple parser” is insufficiently precise.
  Built-in assignments at `0x452DDC–0x4530ED` precede these overrides; one
  must not synthesize the whole live table by filling missing INI rows with zero.

The ordinary packer's **gate sums only the first 15 M cells** (32-bit wrap,
then signed `>0`), not all 24. It starts EAX at `0x611A4C` (`0x41191C`), adds
cells at -0x3C/0/+0x3C, increments by 0xB4 (`0x411929`), and compares to
`0x611DD0` (`0x41192E`). The selected mapping or row loop can still access
indices 15..23. Therefore a 24-cell snapshot is appropriate even though a
15-cell snapshot would suffice for the gate alone.

## Installed configuration: candidates, not runtime selection

Installed UTF-16 `Cfg.ini` SHA-256:
`1a9796e706fa64b1821417efda080d481e202ffcf941aa97e6a78efe3a32badd`.
Its `[OPT]` reports `Ver=0x406` and lists profile codes in `PID`; that list is
registration/order, **not current selection**. It has no `[LIGHT]` section.

Checked installed `Dev/<code>/KB.ini` lighting options for all eight S98 rows:

- `0174`: `bbd82e2f538a0fc1bff8af26454470418362dbad16287d8dd755342fd595db5f`
- `01AF`: `7764882e813660dc0fc1b0ac9e95307faed300b4fd36731612261e37cc03e1db`
- `01BF`: `e72b4ee0a1869e8030790d52a30cfe818abbcb19ad854965fe0928ac8e742310`
- `0223`: `40a4479b358a68f974a7d4dd8a24d4ffdf92febf4df61aee8544a15e2fd19532`
- `0224`: `829825de9a6b00e0d84adcb757df71e487b8fd137180cdece4134388d7e07919`
- `022B`: `26d5dde16d756c654a8d139d62a57ebe749d884098d839cf96ee8803bbc4d449`
- `022F`: `c0d2d796abbc46d35ed61e9010af839175d9a6b33f314274afabf6ee5f06e7b4`
- `0230`: `9bbce12d3a849694cbe27ed7136a21319e7fff169cb8d32ce59d879414428565`

All eight have the same relevant values: `Fw=1`, `RGBKb=1`, `GaoshouIndex=17`,
`DefBri=5`, `LightUI=0,4,8,12,16,20`, `LightHW=0,4,8,12,16,20`,
`SpeedParam=0x010500`, `DefLedIndex=10`. No active `LedMask`, `RGBOFFIndex`,
or `EffectHw` assignment was found in these files' lighting options.
`LedOpt1..17` all have first cell zero. `LedOpt18` is absent;
`LedOpt19` and `LedOpt20` exist with all six cells zero, but the loader above
does not reach them after the missing 18. Do not mistake their textual
presence for an executed override.

**Conditional static consequence:** if one of these files was loaded through
this path without later mutation, M(0)..M(14)=0, the ordinary gate is false,
and mode selection uses `selected+1` rather than M(selected). The loader
resolves missing RGBOFFIndex to 18 for Fw!=0 (`0x4516DA–0x4516F2`), so selecting
that ordinal overrides the serialized mode byte to zero. This is consistent
with, but does not identify the profile in, the retained 1/0 mode round-trip.

## Brightness state and exact bounds

- `0x611850`: DWORD DefBri; profile loader store
  `0x451C2A: a350186100`, profile default argument 4 at `0x451C1C`.
- **`0x611854` is LightUI, not LightHW.** LightHW is `0x611868`.
  Both parser limits are `0x14` bytes (`0x451AB8`, `0x451BC8`);
  destinations are `0x451ABE: bf54186100` and
  `0x451BCB: bf68186100`. The maximum bounded regions are respectively
  `[0x611854,0x611868)` and `[0x611868,0x61187C)`.
- A successful LightUI parse leads to the separate LightHW read. An absent
  or nonpositive LightHW parse copies all 20 LightUI bytes at
  `0x451BDC–0x451C0E`. Absent/invalid LightUI takes a different `BriNum`/Fw
  fallback path (`0x451AD5–0x451B8D`), not necessarily the explicit INI lists.
  The 20-byte capacity is **not** the valid parsed length; no length global
  was established here. S98 explicit lists above have exactly six entries,
  so their semantically valid indices are **0..5**, not 0..19.
- `DWORD[0x62B388]` is the selected config pointer. Static UI witness
  `0x424B48: a188b36200`. No need to read active root/list/device/vtable.
- Selected ordinal: DWORD `config+0x213C`, bounded **0..23**. Initializer
  `0x45A551: 89953c210000`; ordinary serializer reads its low byte at
  `0x411939: 0fb68b3c210000`. Probe rejects DWORD>=24 rather than silently
  truncating anomalous high bytes.
- Canonical row `R(i)=config+0x2140+0x30*i`; selected brightness index is
  DWORD **`config+0x2144+0x30*selected`**, not config+0x2140.
  Exact UI load `0x424BCA: 8b841144210000`; initializer row base
  `0x45A4FB: 8d8540210000`, brightness store `0x45A505: 894804`, and
  stride `0x45A53F: 83c030`. Default source is loaded at `0x45A4B5`.
  At selected=23, the only row DWORD read is `[config+0x2594,+0x2598)`.
- `BYTE[0x612B00]` is runtime row count N; store witness
  `0x42343E: a2002b6100`. Probe rejects N>24. N is not the translation-list
  length, nor proof that selected<N; special selected rows may lie outside N.

For the eight candidate defaults, index 5 translates to byte 20. This is not
a percentage or luminance measurement, and DefBri does not prove the current
selected row still has index 5 after persisted configuration loading.

## Prepared probe's contract

The new script exposes one `rpc.exports.snapshot(hostVerifiedSha256)` method,
with **no automatic snapshot or hook installation**. The host must independently
hash the executable belonging to the intended process and pass the exact
lowercase digest above. A caller-supplied digest is an attestation, not an
in-process identity measurement. A same-named executable is not sufficient.

Before reading any state it checks x86/pointer size/main-module name and **24
exact instruction witnesses** covering every global/row-layout source used.
Each absolute operand is explicitly rebased; this avoids false failures under
ASLR and avoids wildcard address matching. Static validation on this pass
matched all 24 byte witnesses against the hashed PE and confirmed **every
listed relocated operand has a PE HIGHLOW relocation entry**. The JavaScript
was not executed; Frida compatibility/runtime validation remains pending.

It reads exactly 24 mapping DWORDs at stride 0x3C (96 bytes, not the intervening
table contents), selected code, Fw, LedMask, GaoshouIndex, resolved RGBOFFIndex,
N, DefBri, one config pointer, one selected ordinal, and one selected-row
brightness DWORD. It translates only the selected/default indices if <20;
indices >=20 produce an explicit out-of-capacity result with **no table read**.
The selected INI must subsequently constrain semantic indices (six for the
eight candidates); trailing capacity bytes are not declared usable levels.

Every main-image source is checked for image containment and readable range;
the two heap scalar locations are range-checked individually. No config block
dump, other lighting rows, keymaps, macros, user text, paths, handles, device
objects, or transport reports are read/emitted. It returns only bounded scalar
and mapping data, with zero vendor calls/commands. There are no writes, hooks,
timers, polling, or native calls. Anchor rereads reject detected changes in
profile/config/selection/brightness; they **do not make the snapshot atomic** or
prove mappings did not change concurrently. Errors abort without a partial result.

## What remains to observe before a brightness-change implementation

### Later bounded runtime observation (same date)

The host subsequently hash-checked the running image and executed the guarded
snapshot through REA. Retained record:
[`rk406-brightness-mapping-2026-10-26.json`](runtime-evidence/rk406-brightness-mapping-2026-10-26.json),
Evidence `ev_b64657daf81575fbbc168c69b59f2f3143c54012629637620ceb4f4a95af9499`.
All 24 relocated instruction witnesses passed. Observed values: Fw 1, mask 0,
GaoshouIndex 17, Off index/selected ordinal 18, row count 19, all 24 mappings zero,
selected/default brightness index 5 translating to UI/HW byte 20. Cleanup reported
no error; no vendor function or device command was called by the script.

The profile-code scalar was `023D`. **Do not infer the physical model or selected
INI from that scalar:** installed `Cfg.ini` lists `DevName188=023D,RK G98 Keyboard`,
whereas the observed vendor UI displayed an S98-labelled device/layout. Binding
this global to the active profile remains unresolved. The table/row observations
do not resolve that discrepancy or establish the selected INI's valid list length.
The script's “PREPARED ONLY” header describes its original static-authoring pass;
this paragraph records the separate subsequent execution. REA still lacks native
artifact identity metadata; the host digest check is a separate attestation.

### Still required

1. Obtain the bounded snapshot under separately authorized passive attachment;
   preserve host executable digest, script digest, selected code, all 24 M cells,
   first-15 signed sum, N, mask, special indices and selected brightness. Compare
   to the exact selected installed KB.ini, rather than choosing S98/0174 by guess.
2. Associate UI first/Off ordinals with the actual selected-row samples. The
   earlier local state-classification artifact reports ordinal18/index5 but its
   root interpretation was wrong and its REA record lacks artifact identity;
   it must not substitute for a hash-bound mapping/profile snapshot.
3. Only after the selected non-Off row and valid brightness indices are known,
   plan a separately authorized single-step change/restoration observation.
   No such action is authorized by this report or performed by the new script.
   The retained round-trip changes mode, not brightness: wire byte2=10 is its
   child-transfer block count, **not the 128-byte block's mode at offset10**.
4. Ordinary selected-row brightness destination is mapped `0x38+2*M(i)` or
   fallback `0x3A+2*i`, conditional on mask/N; pair destinations must remain
   within 128 bytes (mapped M<=35). Special selected==GaoshouIndex additionally
   writes offset0x5E and can collide with fallback row18's brightness. Firmware-2
   uses `0x53+2*M(i)` (M<=21 for the whole pair), skips zero mappings, and has a
   separate i==M(i) triplet. These are not interchangeable “brightness offsets.”
5. RKKB's serializer path uses the same translated brightness source but a
   different inner payload. The 20-byte observed child path under a G5 root
   does not validate RKKB, firmware-2, or other protocol families. UI setter,
   routing, complete report preservation, transport and physical acceptance
   still require their own evidence; do not implement a cross-family hardware
   write based solely on this static mapping.

Supporting existing reports: `rk-406-command04-offline-codec-2026-10-26.md`,
`rk-406-brightness-record-base-correction-2026-10-26.md`,
`rk-lighting-profile-record-path-audit.md`, and retained
`runtime-evidence/rk406-wireless-lighting-roundtrip-frida-2026-10-26.json`.
