# Remaining native API path audit

This note follows the ten import rows that remained without a recovered
invocation or callback path in the installed RK Keyboard Software 4.06 static
audit. It records what can be established from the local PE snapshots and
existing cross-reference artifacts. It does not treat a failed reference scan
as proof that an import is unused.

## Scope and evidence

The inspected files are the installed-package-matched local snapshots
`_rk_analysis/inputs/Update.exe` and `_rk_analysis/inputs/unins000.exe`.
Their SHA-256 values, respectively,
`27894463b0dfe5bc3f5dc19d4d3351d9dfb692c402bf277bde3889d37e4a206c` and
`b4ca28b192d5a50307d2b28f3323b58b39cb51edd6682e75706cac2dd69a4a14`, are
recorded in the [installed package manifest](rk-installed-package-manifest.csv).
Evidence was checked against the PE import and callsite cross-reference CSVs,
the indirect-call audit, the dynamic-loader target list and audit, and targeted
GNU `objdump` disassembly/data dumps. No vendor executable was launched, and
no keyboard interface was opened.

Labels below mean:

- **Proven:** directly represented by an import row, instruction, static data
  reference, or examined control-flow sequence.
- **Inferred:** a plausible interpretation of that evidence, not a proved
  runtime purpose or execution.
- **Unresolved:** the static evidence reviewed here does not settle the
  question.

## `Update.exe`: ANSI loader imports

The import inventory contains `KERNEL32.dll!LoadLibraryA` at IAT VA
`0x005603FC` and `KERNEL32.dll!GetModuleHandleA` at IAT VA `0x00560404`.
Their imported wrapper/thunk references are recorded at `0x00417442` and
`0x004165B0`, respectively, in the
[native API cross-reference](rk-native-api-xrefs.csv) and
[callsite-gap inventory](rk-native-api-callsite-gaps.csv).

| API | Proven static evidence | Inference and remaining unknowns |
| --- | --- | --- |
| `LoadLibraryA` | The thunk at `0x00417442` tail-jumps through IAT VA `0x005603FC`. The helper at `0x00416570` calls a descriptor's module-resolver pointer and then calls `GetProcAddress`; all nine direct helper calls pass wide descriptors, and the three ANSI `LoadLibraryA` descriptor bases have zero exact pointer matches in the pinned image. See the [updater ANSI loader call-boundary audit](rk-update-ansi-loader-call-boundary-audit.md). | **Inferred:** the A thunk and alternate A descriptors may be compatibility or generated-library paths. **Unresolved:** whether a computed/indirect or outside-image caller supplies an A descriptor, and whether this import executes in any run. |
| `GetModuleHandleA` | The thunk at `0x004165B0` tail-jumps through IAT VA `0x00560404`. The helper's nine recovered direct callers use wide descriptors; the adjacent Kernel32 A descriptor at `0x00561DD4` has zero exact pointer matches in the pinned image. The focused [call-boundary audit](rk-update-ansi-loader-call-boundary-audit.md) lists each caller and exact descriptor. | **Inferred:** the A record is not selected through the recovered direct caller set. **Unresolved:** computed references, external callers, runtime-generated pointers, and execution. A missing scan reference does not establish dead code. |

The nearby W-form helper setup demonstrates use of a shared loader descriptor
mechanism, not use of these A imports. The wrapper symbols and loader API
names alone do not reveal a runtime module name. See the
[dynamic API resolution audit](rk-dynamic-api-resolution-audit.md) for the
caller and descriptor summaries.

## `unins000.exe`: eight USER32 scrollbar imports

The unresolved imports are USER32 fallback API rows, distinct from the
separately imported `comctl32.dll!FlatSB_*` entrypoints. The
[cross-reference CSV](rk-native-api-xrefs.csv) records one IAT thunk reference
per USER32 row and no recovered direct, thunk-call, tail-jump, or other
invocation site. Static disassembly of resolver `0x0044B5E0` shows it resolving
the corresponding `FlatSB_*` exports through helper `0x00409128`, storing the
results in globals, and placing a USER32 thunk address in the same global when
resolution returns null. It is reached directly from `0x004F8645`.

| USER32 import row | IAT RVA | Fallback thunk | FlatSB name resolved by the adjacent resolver | Global receiving resolved/fallback pointer |
| --- | --- | --- | --- | --- |
| `EnableScrollBar` | `0x00103D6C` | `0x0040976C` | `FlatSB_EnableScrollBar` | `0x0050209C` |
| `ShowScrollBar` | `0x00103B68` | `0x00409BB4` | `FlatSB_ShowScrollBar` | `0x005020A0` |
| `GetScrollRange` | `0x00103CBC` | `0x004098CC` | `FlatSB_GetScrollRange` | `0x005020A4` |
| `GetScrollInfo` | `0x00103CC4` | `0x004098BC` | `FlatSB_GetScrollInfo` | `0x005020A8` |
| `GetScrollPos` | `0x00103CC0` | `0x004098C4` | `FlatSB_GetScrollPos` | `0x005020AC` |
| `SetScrollPos` | `0x00103B8C` | `0x00409B64` | `FlatSB_SetScrollPos` | `0x005020B0` |
| `SetScrollInfo` | `0x00103B90` | `0x00409B5C` | `FlatSB_SetScrollInfo` | `0x005020B4` |
| `SetScrollRange` | `0x00103B88` | `0x00409B6C` | `FlatSB_SetScrollRange` | `0x005020B8` |

**Proven:** resolver `0x0044B5E0` performs the dynamic lookups and fallback
stores at `0x0044B64D`–`0x0044B739`; its direct caller is `0x004F8645`. The
separate import rows for `comctl32.dll!FlatSB_GetScrollInfo`,
`FlatSB_GetScrollPos`, `FlatSB_SetScrollPos`, `FlatSB_SetScrollInfo`, and
`FlatSB_SetScrollProp` have direct callers recorded in the cross-reference
CSV. For example, `FlatSB_GetScrollInfo` is called through thunk
`0x0040A088` at `0x00470D03`, while `FlatSB_GetScrollPos` and
`FlatSB_SetScrollPos` use thunks `0x0040A090` and `0x0040A0A0` at
`0x00471128` and `0x00471142`. This confirms separate statically imported
FlatSB call paths exist; it does not establish that the eight USER32 fallback
pointer globals are read or invoked.

An earlier linear-disassembly scan printed a possible indexed reference at
`0x0044B2C0`. A boundary-aware recheck shows that byte is the final `0xFF` of
the relative displacement for `call 0x00409A8C` at `0x0044B2BC`; the next
instruction starts at `0x0044B2C1` and is `mov [0x00502094],eax`. The apparent
`jmp DWORD PTR [ebx+0x00502094]` is therefore a misaligned decode, and no EBX
provenance or fallback-table use follows from it. This correction removes the
candidate but does not locate a consumer. See the focused
[candidate correction](rk-unins000-scrollbar-fallback-indexed-candidate.md)
and the [deep-scan report](rk-remaining-native-api-gap-deep-scan.md).

**Unresolved:** the reviewed disassembly and whole-file little-endian address
scan found the fallback globals only at resolver initialization stores, not at
later direct reads, indirect calls, or callback handoffs. Their true runtime
consumers, if any, may be computed or external to the examined path. The
indexed candidate at `0x0044B2C0` was reclassified as a misaligned decode
inside a call displacement; it does not supply a consumer. It is also
unresolved why this image contains both direct FlatSB imports and the dynamic
resolver/fallback table, and which route is used by each UI flow. Therefore
none of these eight USER32 imports is classified as unused.

## Cross-version package boundary

The updater result carries over to the 4.6-labeled package because its
`Dev/01AF/Update.exe` is byte-identical to the installed 4.06 updater (same
2,109,952-byte size and SHA-256). The eight scrollbar fallback rows belong
only to the 4.06 `unins000.exe`: the 4.6 package path/hash delta lists that
file as absent. The 4.6 package's `uninstall.dll` is a separate PE and does
not make those eight import findings apply to it. This boundary is confirmed
by [`rk-file-manifest-delta-v4.06-v4.6.csv`](rk-file-manifest-delta-v4.06-v4.6.csv)
and [`rk-4.6-package-manifest.csv`](rk-4.6-package-manifest.csv). It does not
replace the separate, version-specific 4.6 `DeviceDriver.exe` import and
hook-callsite audits.

## Limits and reproduction trail

The relevant source artifacts are:

- [`rk-native-api-callsite-gaps.csv`](rk-native-api-callsite-gaps.csv) and
  [`rk-native-api-xrefs.csv`](rk-native-api-xrefs.csv): import rows, IAT
  references, thunk sites, and recovered callsites.
- [`rk-native-api-indirect-call-audit.md`](rk-native-api-indirect-call-audit.md):
  previous per-row review, including the resolver/fallback table and the
  caveat that the eight USER32 rows remain unresolved.
- [`rk-dynamic-api-targets.csv`](rk-dynamic-api-targets.csv) and
  [`rk-dynamic-api-resolution-audit.md`](rk-dynamic-api-resolution-audit.md):
  loader callsites, descriptor families, and caller summaries.
- [Native API import inventory](rk-native-api-imports.md): import-table and
  scan-method definitions.

Targeted review commands used GNU `objdump` on the local snapshots, for
example `objdump -d --start-address=0x004164E0 --stop-address=0x00416620
_rk_analysis/inputs/Update.exe` and `objdump -d
--start-address=0x0044B5C0 --stop-address=0x0044B960
_rk_analysis/inputs/unins000.exe`. Raw whole-file scanning is a candidate
finder, not a proof of absence: it cannot establish full control flow, infer
all computed pointer expressions, account for every runtime patch or outside
caller, or describe other installer versions. Static imports and candidate
paths also do not prove the API executed.
