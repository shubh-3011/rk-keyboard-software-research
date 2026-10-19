# Deep scan of remaining 4.06 native API import gaps

## Scope

This follow-up checks the ten native-import rows still unresolved in the 4.06
callsite ledger: `Update.exe!LoadLibraryA`, `Update.exe!GetModuleHandleA`, and
the eight `unins000.exe` USER32 scrollbar fallback imports. It uses the
package-matched snapshots listed below. Neither binary was run, and no RK
application, updater, HID interface, keyboard, or bootloader was contacted.

| Binary | SHA-256 |
| --- | --- |
| `Update.exe` | `27894463b0dfe5bc3f5dc19d4d3351d9dfb692c402bf277bde3889d37e4a206c` |
| `unins000.exe` | `b4ca28b192d5a50307d2b28f3323b58b39cb51edd6682e75706cac2dd69a4a14` |

The reproducible scan is [`audit_remaining_native_api_gaps.py`](../scripts/audit_remaining_native_api_gaps.py); its output is [`rk-remaining-api-reference-scan.csv`](rk-remaining-api-reference-scan.csv). It verifies both hashes, then searches the full file bytes for exact little-endian DWORD values at all alignments. The CSV records target VA, file offset, mapped reference VA, section, and hit count. Each match is only a candidate; the interpretation below also checks targeted `objdump` disassembly and the existing static xref reports.

## Findings

### `Update.exe`: ANSI loader imports

The raw-byte scan distinguishes the two imports more clearly than the earlier gap summary:

| Import | Exact reference evidence | Assessment |
| --- | --- | --- |
| `LoadLibraryA` | Its IAT slot `0x005603FC` occurs once, in the import thunk at `0x00417442`. The wrapper entry `0x0041743E` is stored in three ANSI descriptor records at `0x00562220`, `0x005645AC`, and `0x00584510`. Those records describe Comctl32, Comdlg32, and the property-sheet Comctl32 module paths. | The ANSI thunk and three records are present. No reference to any of those ANSI descriptor bases was found, and the helper callers reviewed so far pass Unicode descriptor bases. **Invocation unresolved.** |
| `GetModuleHandleA` | Its IAT slot `0x00560404` occurs once in the thunk at `0x004165B0`. The thunk entry `0x004165AC` is stored in the Kernel32 ANSI descriptor at `0x00561DD4`. | The ANSI descriptor is present, but its base has no exact in-image pointer reference. The nine recovered direct calls to resolver `0x00416570` pass Unicode descriptor bases: six Kernel32 paths, one Comctl32 path, one Comdlg32 path, and one property-sheet Comctl32 path. **Invocation unresolved.** |

The records are not interchangeable evidence for both imports: the Kernel32
ANSI record uses the `GetModuleHandleA` thunk, while the three ANSI common
control/dialog records use the `LoadLibraryA` thunk. The surrounding helper
sequence at `0x00416570` calls the descriptor's first field with its module
name field, then passes the result and export-name parameter to
`GetProcAddress` at `0x00416592`. This explains what the records would do if
selected; it does not prove selection. A focused, instruction-level census
now maps all nine direct calls to that helper to their exact wide descriptor
and export-name source, and records zero exact in-image pointer matches to the
four ANSI descriptor bases; see the [updater ANSI loader call-boundary audit](rk-update-ansi-loader-call-boundary-audit.md).

Recovered direct-call sites to `0x00416570` are `0x004163C1`, `0x004163F1`,
`0x004164BB`, `0x004164EB`, `0x004165FE`, `0x0041664F`, `0x004171CE`,
`0x00421793`, and `0x00519C90`. Their static arguments identify Unicode
descriptor bases at `0x00561DCC`, `0x00562218`, `0x005645A4`, and
`0x00584508`. No direct call to either ANSI descriptor was recovered. The
helper could still be reached through an indirect or outside-image path, so
the imports are not classified as unused.

### `unins000.exe`: scrollbar fallback globals

The resolver at `0x0044B5E0` calls helper `0x00409128` to resolve eight
`comctl32!FlatSB_*` functions. For each API it first stores the returned
address in a global at `0x0050209C`–`0x005020B8`; if that result is null, it
stores the corresponding USER32 import-thunk address instead. The resolver
is directly called at `0x004F8645` according to the existing callsite audit.

Each pointer global has exactly two raw DWORD references in the whole image,
both inside the resolver: one successful-resolution store and one fallback
store. Each fallback thunk address has exactly one raw hit, at its immediate
load into `EAX` before the fallback store. The targeted disassembly confirms
these are writes, not direct loads or invocations. No later direct global
read, indirect call, or callback handoff was recovered in this image.

An earlier linear-disassembly scan printed a possible indexed reference at
`0x0044B2C0`, but a boundary-aware recheck rejected that decode. The call at
`0x0044B2BC` has bytes `E8 CB E7 FB FF`; the alleged jump begins at its final
displacement byte. The next valid instruction boundary is `0x0044B2C1`, where
`A3 94 20 50 00` stores EAX to global `0x00502094`. No EBX range or fallback
slot access can be inferred from the misaligned decode. See the focused
[candidate correction](rk-unins000-scrollbar-fallback-indexed-candidate.md).

The separate imported `comctl32!FlatSB_*` functions do have direct callsites,
including `FlatSB_GetScrollInfo` at `0x00470D03`, `FlatSB_GetScrollPos` at
`0x00471128`, `FlatSB_SetScrollPos` at `0x00471142`, and
`FlatSB_SetScrollInfo` at `0x004713D3`. Those calls do not establish use of
the USER32 fallback slots. The false indexed candidate no longer keeps a
possible in-image reference open; confidence remains **high** that no direct
global consumer was recovered and **moderate** that no reachable in-image
consumer has been established. Computed aliases, callback handoffs, and
external consumers remain unresolved. The eight imports are therefore
unresolved rather than unused.

**Independent installed-binary re-audit (2026-10-19):** the live
`C:\Program Files (x86)\RK Keyboard Software\unins000.exe` is 1,316,301
bytes with SHA-256
`b4ca28b192d5a50307d2b28f3323b58b39cb51edd6682e75706cac2dd69a4a14`, matching
the pinned 4.06 snapshot. A full raw-file address scan plus `objdump -d` and
`objdump -D` found exactly two raw references to each global
`0x0050209C`–`0x005020B8`, both resolver stores, and one raw hit per fallback
thunk address, each loaded only as the fallback value in that resolver.
Each thunk then tail-jumps through its corresponding USER32 IAT slot. The
suspected `0x0044B2C0` use remains a misaligned decode in the relative call at
`0x0044B2BC`; the next instruction boundary is `0x0044B2C1`. No additional
in-image consumer or invocation path was found. Runtime use, computed aliases,
and external consumers remain unresolved. The uninstaller was not executed.

## Status and limits

The scan adds pointer-level evidence but closes none of the ten unresolved
rows. It does not discover APIs that are resolved at runtime outside the
static imports, recover complete program call graphs, prove a branch runs, or
describe runtime behavior. The byte scan can also find pointer-shaped data
that is not code, which is why every hit needs instruction/data context.
GNU `objdump` and the installed-package-matched snapshots are needed to
reproduce the address-level review; the proprietary binaries are not included
in the research repository.
