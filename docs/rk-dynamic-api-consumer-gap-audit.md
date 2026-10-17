# Focused dynamic API consumer gap audit

## Scope and method

This note follows the unresolved argument and consumer questions for the
`DeviceDriver.exe` and `Update.exe` dynamic API paths in the 4.06 installed
package. It uses the package-matched PE snapshots under the local
`_rk_analysis/inputs` directory and x86 static disassembly/data inspection
with GNU `objdump`; it does not execute either program. The snapshot hashes
are:

| PE | SHA-256 |
| --- | --- |
| `DeviceDriver.exe` | `c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6` |
| `Update.exe` | `27894463b0dfe5bc3f5dc19d4d3351d9dfb692c402bf277bde3889d37e4a206c` |

The main question was whether resolver helpers that accept an export-name
argument actually receive arbitrary runtime strings, and whether the cached
function pointers have identifiable local consumers. Direct `CALL`/`JMP`
references and the bytes at referenced string/data VAs were checked. These
findings establish static argument and transfer paths only; they do not
establish that guards pass or that Windows loads any optional export.

## `DeviceDriver.exe`: UxTheme resolver

The `GetProcAddress` call at `0x00556B66` is inside helper
`0x00556B26`. The helper initializes a shared `UxTheme.dll` handle through
`0x0047B316` using UTF-16 name `UxTheme.dll` at `0x005A2E08`, caches the
handle at `0x0060886C`, then resolves the helper's first argument. Its second
argument is the fallback pointer returned when the module or export lookup
does not produce a pointer. The helper's direct callers below pass literal
export-name VAs and literal fallback code addresses; the name is not an
unresolved runtime value at these call boundaries.

| Resolver wrapper | Export string VA | Cached pointer | Local indirect call | Direct wrapper caller(s) |
| --- | --- | --- | --- | --- |
| `0x00556B7A` | `0x005BD720` `IsAppThemed` | `0x00608874` | `0x00556BB4` | `0x004FBD0E`, `0x004FC433`, `0x0055F103` |
| `0x00556BC0` | `0x005A67EC` `OpenThemeData` | `0x0060887C` | `0x00556C00` | `0x004FBCDB`, `0x004FC444`, `0x0055F118` |
| `0x00556C0C` | `0x005A67DC` `CloseThemeData` | `0x00608884` | `0x00556C49` | `0x004FBCCD`, `0x004FBD1A`, `0x0055F217` |
| `0x00556C55` | `0x005A67C8` `DrawThemeBackground` | `0x0060888C` | `0x00556CA1` | `0x004FC845`, `0x004FCB98`, `0x004FD2D3`, `0x0055F1FC` |
| `0x00556CAD` | `0x005BD72C` `GetThemePartSize` | `0x00608894` | `0x00556CFC` | `0x004FCA96`, `0x004FCB16`, `0x0055F15E` |
| `0x00556D08` | `0x005BD740` `IsThemeBackgroundPartiallyTransparent` | `0x0060889C` | `0x00556D4B` | `0x004FC817`, `0x004FD2A5` |
| `0x00556D57` | `0x005A2DEC` `DrawThemeParentBackground` | `0x006088A4` | `0x00556D9A` | no direct call reference recovered |

The seven wrapper initializers call `0x00556B26` with the name addresses shown
above. The first six wrappers also have in-image direct callers shown in the
table. For `DrawThemeParentBackground`, the cached pointer is directly
invoked inside its wrapper, but a direct caller of wrapper `0x00556D57` was
not found by disassembly call-target search or a little-endian absolute-VA
scan of the snapshot. A computed reference or a call from code outside this
image is not ruled out. The lookup name, cache slot, and local pointer
consumer are resolved; the wrapper's higher-level entry path remains open.

Fallback addresses observed in the wrappers include `0x00556B20` (which
returns `E_FAIL`) and `0x00558D2B`; the exact intended compatibility behavior
of the latter was not established here. The static import table also contains
UxTheme APIs, so these dynamic wrappers should not be treated as proof that
the main application relies exclusively on this optional-resolution path.

## `Update.exe`: caller-provided resolver arguments reduce to literals

The shared resolver `0x00416570` obtains or reuses a module handle from a
descriptor, calls `GetProcAddress` at `0x00416592` with its third argument,
and returns the result. In three helper families that previously appeared
to pass runtime export names, the direct callers load fixed string addresses
before entering the helper. The export names and pointer consumers can
therefore be identified from the installed snapshot.

### Common-controls and image-list helpers

Helper `0x0041718B` passes its export-name argument to the common-controls
descriptor block at `0x00562218`; the block contains UTF-16
`Comctl32.dll` at `0x00561D74` and ANSI `Comctl32.dll` at `0x005621C8`.
Its 12 direct callers push these fixed names and cache or
invoke the returned pointer as follows:

| Caller / lookup | Export | Pointer slot | Static indirect consumer |
| --- | --- | --- | --- |
| `0x00417262` | `ImageList_Create` (`0x005621D8`) | `0x005BFB50` | `0x00417282` |
| `0x00417313` | `ImageList_Destroy` (`0x005621EC`) | `0x005BFB54` | `0x00417327` |
| `0x004173B8` | `ImageList_LoadImageW` (`0x00562200`) | `0x005BFB58` | `0x004173DE` |
| `0x0041F05F` | `InitCommonControlsEx` (`0x005639A8`) | `0x005C1574` | `0x0041F073` |
| `0x00436DA4` | `ImageList_Draw` (`0x0056629C`) | `0x005C198C` | `0x00436DC7` |
| `0x00436E58` | `ImageList_GetImageInfo` (`0x005662AC`) | `0x005C1990` | `0x00436E72` |
| `0x00441382` | `ImageList_AddMasked` (`0x00567F30`) | `0x005C1A68` | `0x0044139C` |
| `0x00441436` | `ImageList_ReplaceIcon` (`0x00567F18`) | `0x005C1A64` | `0x00441450` |
| `0x004583C0` | `ImageList_GetIcon` (`0x0056B3F8`) | `0x005C1E60` | `0x004583DA` |
| `0x0045846B` | `ImageList_GetImageCount` (`0x0056B3E0`) | `0x005C1E5C` | `0x0045847F` |
| `0x004603BF` | `ImageList_GetIconSize` (`0x0056B598`) | `0x005C2550` | `0x004603D9` |
| `0x004F6CE2` | `ImageList_Remove` (`0x0057E3B4`) | `0x005C4170` | `0x004F6CF9` |

At each listed site the literal string is pushed immediately before calling
`0x0041718B`; its returned pointer is stored or returned to the caller. The
pointer transfers shown are static. A table entry in an unlisted caller or
runtime-only invocation is not inferred from this scan.

### Common-dialog helpers

Helper `0x00421750` resolves through the descriptor at `0x005645A4`, whose
module-name field points to `Comdlg32.dll` at `0x005645B4`. The helper accepts
an export-name parameter, but all five direct callers pass fixed names:

| Caller / lookup | Export | Pointer slot | Static indirect consumer |
| --- | --- | --- | --- |
| `0x00421827` | `GetOpenFileNameW` (`0x0056457C`) | `0x005C15B8` | `0x0042183B` |
| `0x004218CC` | `GetSaveFileNameW` (`0x00564590`) | `0x005C15BC` | `0x004218E0` |
| `0x004321FE` | `GetFileTitleW` (`0x00565A00`) | `0x005C1938` | `0x00432218` |
| `0x004D43C1` | `ChooseColorW` (`0x00579D54`) | `0x005C3D2C` | `0x004D43D5` |
| `0x004D8E6E` | `PrintDlgW` (`0x0057AEA8`) | `0x005C3E30` | `0x004D8E82` |

This resolves the export argument and consumer for the `GetProcAddress`
instruction at `0x00416592` reached through `0x00421793`. The helper's
module and export are fixed for all five recovered call paths; the callsite
does not establish that the associated dialog is displayed at runtime.

### Property-sheet helpers

Helper `0x00519C4D` resolves against the Comctl32 descriptor at
`0x00584508`. Its three direct callers use fixed names and global slots:

| Caller / lookup | Export | Pointer slot | Static indirect consumer |
| --- | --- | --- | --- |
| `0x00519A56` | `CreatePropertySheetPageW` (`0x005844C0`) | `0x005C469C` | `0x00519AA0` |
| `0x00519B35` | `DestroyPropertySheetPage` (`0x005844DC`) | `0x005C46A0` | `0x00519B49` |
| `0x00519BE2` | `PropertySheetW` (`0x005844F8`) | `0x005C46A4` | `0x00519BF6` |

Thus the export-name parameter forwarded to the `GetProcAddress` call at
`0x00519C90` is static at every recovered direct caller. The property-sheet
operation's UI caller and runtime guard behavior are outside this static
argument/consumer trace.

## Other formerly open cached paths in `Update.exe`

- `GetThreadPreferredUILanguages` resolves from `kernel32.dll` using the
  fixed name at `0x00564C38` and is cached at `0x005C1864`. Wrapper
  `0x004253B2` decodes and invokes it at `0x00425421`; its direct caller is
  `0x00413573`, which passes flags `0x38`, a language-count output, a buffer,
  and a buffer-length value. If the export is absent, the wrapper constructs
  a language-list fallback using the imported user/system default-language
  calls and local locale/string helpers. Exact runtime locale results depend
  on the host OS and user settings.
- The first `TaskDialogIndirect` lookup, at `0x004255DF`, stores its result at
  `0x005C18B8` and only returns an availability boolean in helper
  `0x004255C0`; the helper does not call that pointer. Its entry is reached
  by tail-jump from `0x004386F0`. Separately, the actual-call wrapper at
  `0x00425779` caches `TaskDialogIndirect` at `0x005C18BC`, invokes that
  pointer when present, and has a direct caller at `0x004384BF`. These are
  distinct slots and paths.
- `AfxmReleaseManagedReferences` is resolved from `mfcm120u.dll` at
  `0x004223F3`, then called through the returned pointer at `0x004223FE`.
  The wrapper's direct callers are `0x004291C2`, `0x0042AB17`, and
  `0x0042AB3A`; this path is already connected at the static callsite level.

The five optional UxTheme wrappers in the MFC table and their direct caller
addresses are listed in the broader [dynamic API resolution audit](rk-dynamic-api-resolution-audit.md).
This pass found no new unknown export string for those rows.

## Remaining limits

- No runtime execution was used to test guard outcomes, module availability,
  or UI behavior.
- `DeviceDriver.exe`'s `DrawThemeParentBackground` resolver wrapper has a
  local indirect call but no recovered in-image direct caller.
- Code/data references assembled arithmetically, invoked through an external
  module, or supplied by a runtime callback can evade direct-call and
  absolute-address scans.
- The suite's `IMM32` dynamic initializer is in `unins000.exe` rather than
  either PE scoped here. Its unresolved IMM cached slots remain governed by
  the separate [dynamic API resolution audit](rk-dynamic-api-resolution-audit.md).
- None of these Windows API findings establishes a keyboard protocol path or
  says anything about a particular keyboard's firmware behavior.
