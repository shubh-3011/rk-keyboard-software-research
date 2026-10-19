# Relative-reference follow-up for the ten unresolved native API rows

## Scope and exact inputs

This static follow-up extends the unresolved-import scans in
[`rk-remaining-native-api-gap-deep-scan.md`](rk-remaining-native-api-gap-deep-scan.md)
to check raw executable-section `E8`/`E9` relative transfers and exact RVA
values in addition to absolute VAs. The local package-matched inputs were
re-hashed before analysis:

| PE | SHA-256 |
| --- | --- |
| `Update.exe` | `27894463b0dfe5bc3f5dc19d4d3351d9dfb692c402bf277bde3889d37e4a206c` |
| `unins000.exe` | `b4ca28b192d5a50307d2b28f3323b58b39cb51edd6682e75706cac2dd69a4a14` |

Neither program was launched. No RK application, keyboard, HID interface, or
bootloader was contacted.

## Transfer and pointer checks

The executable sections were scanned for five-byte `E8` and `E9` candidates
whose signed `rel32` target equals one of the unresolved import-thunk entries.
No direct relative call or jump to either `Update.exe` ANSI loader thunk or to
any of the eight `unins000.exe` USER32 scrollbar thunks was found. In
`Update.exe`, the same scan recovered the nine known direct calls to loader
helper `0x00416570`; inspection of each call boundary and setup confirms that
they pass Unicode descriptors. No direct relative jump to that helper was
found.

For `Update.exe`, absolute and RVA encodings of the two ANSI IAT slots, thunk
entries, descriptor bases, and resolver entry were checked. Absolute matches
for the IAT slots are only their import-thunk jumps; absolute matches for the
A-thunk entries are only the ANSI descriptor fields. No exact RVA value for
those targets was found. The four ANSI descriptor bases still have no exact
in-image pointer references; the helper's nine direct callers pass the four
W-form descriptors listed in the focused
[call-boundary audit](rk-update-ansi-loader-call-boundary-audit.md).

For `unins000.exe`, each of the eight fallback globals has exactly two
absolute-VA references in the image. Boundary-aware disassembly identifies
both as stores in resolver `0x0044B5E0`: one stores the resolved FlatSB
function pointer and one stores its USER32 thunk fallback. Each fallback
thunk address has one absolute-VA reference, its immediate load in that
resolver. The import-slot addresses occur only in their import thunk's
indirect jump. There are no additional exact RVA references to the fallback
globals or USER32 import slots.

Two thunk-RVA-shaped byte values do occur in `.text`, but neither is a pointer
or a call to the corresponding thunk:

| Candidate value | File offset / mapped VA | Boundary-aware decode | Interpretation |
| --- | --- | --- | --- |
| `EnableScrollBar` thunk RVA `0x976C` | file offset `0x95334`, VA `0x495F34` | The bytes are the `rel32` field of `E8 6C 97 00 00` at `0x495F33`, which calls `0x49F6A4`. | Coincidental displacement; target is not thunk `0x0040976C`. |
| `GetScrollPos` thunk RVA `0x98C4` | file offset `0x9527C`, VA `0x495E7C` | The bytes are the `rel32` field of `E8 C4 98 00 00` at `0x495E7B`, which calls `0x49F744`. | Coincidental displacement; target is not thunk `0x004098C4`. |

The disassembly checks used GNU `objdump -d -Mintel -j .text` on the
hash-pinned files, with the reported `E8` instruction boundaries decoded at
their exact VAs. These raw RVA matches do not add API callsites.

## Per-row disposition

No row is proven unused or absent from runtime behavior. Each remains
**unresolved dynamic/runtime**: the static scan found no in-image invocation,
callback passage, or consumer beyond the loader records and fallback-pointer
initialization described below.

| Binary / API | Static result | Disposition |
| --- | --- | --- |
| `Update.exe` / `LoadLibraryA` | Its thunk is present in three ANSI loader descriptors. The nine recovered direct calls to the shared resolver pass W-form descriptors; no direct relative transfer to the A thunk was found. | Unresolved dynamic/runtime selection of an A descriptor, computed or external callers, and execution. |
| `Update.exe` / `GetModuleHandleA` | Its thunk is present in the Kernel32 ANSI descriptor. The nine recovered direct calls to the shared resolver pass W-form descriptors; no direct relative transfer to the A thunk was found. | Unresolved dynamic/runtime selection of the A descriptor, computed or external callers, and execution. |
| `unins000.exe` / `ShowScrollBar` | USER32 thunk is stored as the resolver's fallback value in global `0x005020A0`; no static consumer of that global was recovered. | Unresolved dynamic/runtime read or invocation of the fallback slot. |
| `unins000.exe` / `SetScrollRange` | USER32 thunk is stored as the resolver's fallback value in global `0x005020B8`; no static consumer of that global was recovered. | Unresolved dynamic/runtime read or invocation of the fallback slot. |
| `unins000.exe` / `SetScrollPos` | USER32 thunk is stored as the resolver's fallback value in global `0x005020B0`; no static consumer of that global was recovered. | Unresolved dynamic/runtime read or invocation of the fallback slot. |
| `unins000.exe` / `SetScrollInfo` | USER32 thunk is stored as the resolver's fallback value in global `0x005020B4`; no static consumer of that global was recovered. | Unresolved dynamic/runtime read or invocation of the fallback slot. |
| `unins000.exe` / `GetScrollRange` | USER32 thunk is stored as the resolver's fallback value in global `0x005020A4`; no static consumer of that global was recovered. | Unresolved dynamic/runtime read or invocation of the fallback slot. |
| `unins000.exe` / `GetScrollPos` | USER32 thunk is stored as the resolver's fallback value in global `0x005020AC`; no static consumer of that global was recovered. | Unresolved dynamic/runtime read or invocation of the fallback slot. |
| `unins000.exe` / `GetScrollInfo` | USER32 thunk is stored as the resolver's fallback value in global `0x005020A8`; no static consumer of that global was recovered. | Unresolved dynamic/runtime read or invocation of the fallback slot. |
| `unins000.exe` / `EnableScrollBar` | USER32 thunk is stored as the resolver's fallback value in global `0x0050209C`; no static consumer of that global was recovered. | Unresolved dynamic/runtime read or invocation of the fallback slot. |

“No static consumer recovered” is bounded by the address and instruction
forms checked here. Computed pointers, runtime-generated state, outside-image
callers, and other package versions remain outside this static audit. The
existing [deep scan](rk-remaining-native-api-gap-deep-scan.md) retains the
resolver dataflow and exact absolute-reference locations.
