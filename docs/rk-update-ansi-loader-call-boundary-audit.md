# RK updater ANSI loader call-boundary audit

## Scope and target identity

This static follow-up narrows the unresolved `Update.exe!LoadLibraryA` and
`Update.exe!GetModuleHandleA` rows in the [remaining native API path audit](rk-remaining-native-api-path-audit.md).
It uses the installed-package-matched `Update.exe` snapshot at
`../../_rk_analysis/inputs/Update.exe` relative to this document (a local
research input outside the published repository), SHA-256
`27894463b0dfe5bc3f5dc19d4d3351d9dfb692c402bf277bde3889d37e4a206c`,
2,109,952 bytes. The hash matches the installed package manifest. The binary
was not executed; no RK application, updater, keyboard, HID interface, or
bootloader was contacted.

## Shared loader helper

At `0x00416570`, the helper receives three stack arguments and returns with
`ret 0x0C`:

| Stack slot | Proven use in helper |
| --- | --- |
| `[EBP+8]` | Descriptor pointer. Its first DWORD is called as a module-resolver function; its second DWORD is pushed as the module-name pointer. |
| `[EBP+0x0C]` | Address of a cached module-handle DWORD. The helper reads and, after a successful load, writes through this pointer. |
| `[EBP+0x10]` | Export-name pointer passed to `GetProcAddress`. |

The instruction sequence at `0x0041657A`–`0x00416592` proves this dataflow:
it checks the cached handle, calls the descriptor's first field with its
second field if needed, stores a non-null module handle, then calls the
`GetProcAddress` IAT slot at `0x0056040C` with the handle and export name.
The descriptor's first-field thunk determines ANSI versus wide module
resolution (`GetModuleHandle*` for Kernel32, `LoadLibrary*` for the other
records).

## Descriptor records and exact references

The descriptor contents below are static `.rdata` bytes decoded as 32-bit
pointers. Module-name encodings are identified from the pointed-to bytes.
The exact little-endian DWORD scan covered the full pinned file; its hit count
is evidence about literal pointer references, not about computed references or
runtime-generated addresses.

| Descriptor base | Module-resolver field | Module-name field | Module-name bytes | Exact base-pointer matches in file |
| --- | --- | --- | --- | ---: |
| `0x00561DCC` | `0x004165A2` (`GetModuleHandleW` thunk) | `0x00561DDC` | UTF-16 `Kernel32.dll` | 6 |
| `0x00561DD4` | `0x004165AC` (`GetModuleHandleA` thunk) | `0x00561DF8` | ANSI `Kernel32.dll` | 0 |
| `0x00562218` | `0x00417434` (`LoadLibraryW` thunk) | `0x00561D74` | UTF-16 `Comctl32.dll` | 1 |
| `0x00562220` | `0x0041743E` (`LoadLibraryA` thunk) | `0x005621C8` | ANSI `Comctl32.dll` | 0 |
| `0x005645A4` | `0x00417434` (`LoadLibraryW` thunk) | `0x005645B4` | UTF-16 `Comdlg32.dll` | 1 |
| `0x005645AC` | `0x0041743E` (`LoadLibraryA` thunk) | `0x005645D0` | ANSI `Comdlg32.dll` | 0 |
| `0x00584508` | `0x00417434` (`LoadLibraryW` thunk) | `0x00561D74` | UTF-16 `Comctl32.dll` | 1 |
| `0x00584510` | `0x0041743E` (`LoadLibraryA` thunk) | `0x005621C8` | ANSI `Comctl32.dll` | 0 |

For the Kernel32 records, the thunk at `0x004165A2` jumps through the
`GetModuleHandleW` IAT slot `0x00560410`; the ANSI counterpart at `0x004165AC`
jumps through `GetModuleHandleA` IAT slot `0x00560404`. The `LoadLibraryA`
thunk entry begins at `0x0041743E` and jumps through IAT
VA `0x005603FC` at `0x00417442`. The `GetModuleHandleA` thunk begins at
`0x004165AC` and jumps through IAT VA `0x00560404` at `0x004165B0`. The
descriptor records are valid-looking ANSI alternatives: each points to a
matching thunk and an ANSI module-name string. They are not evidence that the
helper selects them.

## Complete direct-call census for this helper

`objdump -d -j .text Update.exe` produced nine direct `call 0x00416570`
instructions. The call instruction bytes and argument setup were checked in
targeted disassembly. In each case the last pushed value is the descriptor
argument at helper `[EBP+8]`.

| Direct callsite | Descriptor passed | Static module | Export-name argument |
| --- | --- | --- | --- |
| `0x004163C1` | `0x00561DCC` | `Kernel32.dll` (wide) | `ActivateActCtx` (`0x00561D10`) |
| `0x004163F1` | `0x00561DCC` | `Kernel32.dll` (wide) | `CreateActCtxW` (`0x00561D00`) |
| `0x004164BB` | `0x00561DCC` | `Kernel32.dll` (wide) | `DeactivateActCtx` (`0x00561D20`) |
| `0x004164EB` | `0x00561DCC` | `Kernel32.dll` (wide) | `FindActCtxSectionStringW` (`0x00561D34`) |
| `0x004165FE` | `0x00561DCC` | `Kernel32.dll` (wide) | `QueryActCtxW` (`0x00561D50`) |
| `0x0041664F` | `0x00561DCC` | `Kernel32.dll` (wide) | `GetModuleHandleExW` (`0x00561D60`) |
| `0x004171CE` | `0x00562218` | `Comctl32.dll` (wide) | Caller value `[EBP+8]` |
| `0x00421793` | `0x005645A4` | `Comdlg32.dll` (wide) | Caller value `[EBP+8]` |
| `0x00519C90` | `0x00584508` | `Comctl32.dll` (wide) | Caller value `[EBP+8]` |

The full-file pointer scan found the three non-Kernel32 wide descriptor bases
once each and the Kernel32 wide descriptor base six times, matching these
nine argument pushes. It found no exact pointer to any of the four ANSI
descriptor bases. The per-hit file offsets are retained in the
[reference-scan CSV](rk-remaining-api-reference-scan.csv), generated by the
[hash-checking scanner](../scripts/audit_remaining_native_api_gaps.py). The
[import cross-reference ledger](rk-native-api-xrefs.csv) separately records
only the import-thunk references for the two ANSI IAT slots.

## Evidence classification and residual gap

- **Proven:** the helper's descriptor ABI and loader/GetProcAddress dataflow;
  the ANSI and wide descriptor contents; exactly nine direct helper call
  instructions in `.text`; and the descriptor argument at each direct call.
- **Inferred:** the ANSI records may be retained compatibility/generated
  descriptors that are not selected by the recovered direct-call set. The
  static evidence does not establish why they are present.
- **Unresolved:** computed or indirect selection of an ANSI descriptor,
  outside-image callers, runtime mutation/generation, and whether either ANSI
  import executes. A zero exact-pointer count is not proof that an import is
  unused.

This narrows the earlier gap from “all helper callers use W-form descriptors”
to an instruction-level callsite and descriptor census, but does not close
either import row. The updated cross-reference discussion is in the [deep
scan](rk-remaining-native-api-gap-deep-scan.md); the broader unresolved-import
ledger remains in the [remaining native API path audit](rk-remaining-native-api-path-audit.md).

## Independent binary re-audit (2026-10-19)

An independent whole-image scan and disassembly rechecked the installed
`Update.exe` at SHA-256
`27894463b0dfe5bc3f5dc19d4d3351d9dfb692c402bf277bde3889d37e4a206c`
(2,109,952 bytes), matching the package snapshot. The `LoadLibraryA` and
`GetModuleHandleA` IAT slots each have one thunk reference, and no direct
relative call or jump to either ANSI thunk was found. The ANSI thunk pointers
appear only as descriptor fields; the four ANSI descriptor-base addresses
have no exact little-endian pointer references elsewhere in the image.

The full `.text` scan found the same nine direct calls to resolver
`0x00416570` listed above. Every recovered call passes one of the four W-form
descriptor bases: six use Kernel32-W, and one each use Comctl32-W,
Comdlg32-W, and property-sheet Comctl32-W. The corresponding four W descriptor
bases have 6, 1, 1, and 1 exact pointer occurrences. This strengthens the
static conclusion that no in-image direct call path selecting the ANSI
descriptors was recovered. Computed or indirect descriptor selection,
runtime mutation, outside-image callers, and actual API execution remain
unresolved; the imports are not classified as unused. The updater was not
launched for this audit.
