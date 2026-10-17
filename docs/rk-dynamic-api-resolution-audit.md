# RK dynamic API resolution audit

## Scope

The installed PE inventory identifies 128 `LoadLibrary*` and
`GetProcAddress` callsites across five binaries. This note follows seven
main-app sites with no nearby literal candidate and a further four updater
and eleven uninstaller resolver sites. It uses static x86 disassembly only;
none of the applications was executed and no device was contacted. The
additional snapshots are `Update.exe` SHA-256
`27894463B0DFE5BC3F5DC19D4D3351D9DFB692C402BF277BDE3889D37E4A206C` and
`unins000.exe` SHA-256
`B4CA28B192D5A50307D2B28F3323B58B39CB51EDD6682E75706CAC2DD69A4A14`.
The main-app hash is recorded in [`rk-native-api-imports.md`](rk-native-api-imports.md).

An empty nearby-string list means the resolver's name is supplied at runtime
or was not found by the adjacent-string scan. It does not mean the call is
unresolved at the instruction level, nor does an API import prove that its
branch runs. The argument/dataflow findings below are separate from runtime
execution.

## Main app sites

| Callsite | API | Static argument and result flow | Status |
| --- | --- | --- | --- |
| `0x00473B25` | `LoadLibraryA` | Passes caller argument `[EBP+8]` as the ANSI module name. Saves the returned module handle in a local and returns it through cleanup logic. | **Proven:** module name is a function argument. **Unresolved:** its caller-provided value and target module. |
| `0x00589485` | `LoadLibraryA` | Passes the runtime ANSI name at `[EBP-0x38]`; stores the returned handle in `EDI`. | **Proven:** dynamically sourced module name and handle. **Unresolved:** exact string value and caller source. |
| `0x0058955C` | `GetProcAddress` | Uses the handle in `EDI` and runtime export-name pointer `[EBP-0x30]`; the returned function pointer is called at `0x00589580`. | **Proven:** both module and export names are runtime data, and the returned pointer is invoked. **Unresolved:** precise export name and higher-level function purpose. |
| `0x00474F91` | `LoadLibraryW` | A small module wrapper first calls `GetModuleHandleW` with the wide name at `[ESI+0x0C]`; if that returns null, it calls `LoadLibraryW` with the same name. It caches the resulting handle at `[ESI+4]` and records whether it loaded the module at `[ESI+8]`. | **Proven:** existing-module lookup, fallback load, and handle/ownership bookkeeping. **Unresolved:** name value and higher-level consumer. |
| `0x0047B34F` | `LoadLibraryW` | Passes `[EBP+8]` and saves the returned handle for the return path. The cleanup block at `0x0047B36F` preserves last-error state through `GetLastError`/`SetLastError` calls (`0x0047B383`/`0x0047B39D`); it does not call `FreeLibrary` at this site. | **Proven:** parameter-driven load and last-error cleanup. **Unresolved:** module name, caller context, and whether another owner later releases the handle. |
| `0x0047F568` | `LoadLibraryW` | Passes a temporary wide-character buffer at `[EBP-0x230]`. A preceding helper fills the `0x112`-character buffer from runtime arguments and checks the produced length before loading. | **Proven:** generated/runtime module name is passed to the loader. **Unresolved:** buffer contents, helper semantics, and caller. |
| `0x0055F001` | `LoadLibraryW` | Loads the caller-provided wide module name from `[EBP+8]`. The wrapper resolves the literal export `DllGetVersion` at `0x0055EFDD` with `GetProcAddress`, calls the resolved pointer with the caller's version structure, and releases the module with `FreeLibrary`. | **Proven:** load → `DllGetVersion` lookup/call → free sequence. **Unresolved:** caller-supplied module name and branch reachability. |

The `DllGetVersion` string at `0x005A55EC` is directly passed to
`GetProcAddress`; the nearby-string scan omitted it because it is not close
enough to the `LoadLibraryW` callsite. The code does not prove which library
is loaded by callers of `0x0055F001`.

## What this resolves

These seven sites are not simply unclassified `LoadLibrary`/`GetProcAddress`
byte matches. The disassembly establishes the source of each parameter at the
call boundary, handle caching/cleanup in several wrappers, and one named
export call. It still does not recover every caller, runtime module string,
export string, or whether each branch executes. Thus the empty-string count
in the generated CSV remains unchanged as a scan result.

## Updater resolver paths

| Callsite | API | Static argument and result flow | Status |
| --- | --- | --- | --- |
| `0x00416769` | `LoadLibraryW` | Loads the fixed UTF-16 name `Comctl32.dll` at `0x00561D74`, behind the activation-context check at `0x00416764`; the returned module handle is discarded. | **Mapped:** module name and guard. **Unresolved:** runtime reachability. |
| `0x0041F0FA` | `LoadLibraryW` | Generic wrapper passes `[EBP+8]` as the module name, returns the resulting handle. Caller `0x0041A502` builds a `%SystemDirectory%\\<caller DLL>` fallback path; caller `0x00423A43` passes `comctl32.dll`, then resolves and calls `DllGetVersion`. | **Mapped:** wrapper and two callers. **Unresolved:** values at other callers and runtime reachability. |
| `0x0041A492` | `LoadLibraryExW` | Passes `[EBP+8]` as `lpLibFileName`, NULL as `hFile`, and `0x800` as flags. The path is gated by the encoded `SetDefaultDllDirectories` pointer resolved at `0x0041A467`; that pointer is checked for availability but not invoked. The fallback constructs a system-directory path and calls the loader wrapper. | **Mapped:** argument sources, gate, and fallback shape. **Unresolved:** general caller-supplied module name and execution. |
| `0x00416592` | `GetProcAddress` | Helper `0x00416570` lazily obtains Kernel32, Comctl32, or Comdlg32 handles and returns/caches export pointers. Fixed Kernel32 exports at callers are `ActivateActCtx`, `CreateActCtxW`, `DeactivateActCtx`, `FindActCtxSectionStringW`, `QueryActCtxW`, and `GetModuleHandleExW`. Other callers use runtime export names against Comctl32 (`0x004171CE`, `0x00519C90`) or Comdlg32 (`0x00421793`). | **Mapped:** module families, fixed names, and pointer flow. **Unresolved:** caller-fed export names and runtime reachability. |

The export `SetDefaultDllDirectories` is resolved by the separate call at
`0x0041A467` from `kernel32.dll`. Its pointer is encoded and used only as a
feature-availability test in the observed path; the analysis did not recover
an invocation of it.

## Uninstaller resolver paths

### Locale-aware module loading

`LoadLibraryExW` callsites `0x00408082`, `0x004080C2`, and `0x00408101` are
branches of a Borland locale-aware loader. A UTF-16 buffer at `[EBP-0x22A]`
is built from the caller record plus values under
`Software\\Borland\\Locale`; the code tries up to three path/extension
variants with `hFile = NULL` and flags `2`. Caller `0x00407C17` caches the
result in record field `+0x10`. The exact module remains dependent on runtime
record and registry values.

### Package/import loader

| Callsite | API | Static argument and result flow | Status |
| --- | --- | --- | --- |
| `0x004A1596`, `0x004A15A8` | `LoadLibraryExA`, `LoadLibraryA` | Conditional branches use the module-name pointer in local `-8` (descriptor field `+0x18`); the ExA path passes flags `8`. The returned handle is cached in entry field `+8`. | **Mapped:** branch arguments and handle cache. **Unresolved:** exact module name. |
| `0x004A1618` | `GetProcAddress` | Uses the cached module and descriptor-derived export-name pointer in local `-0xC`; caches the result in descriptor field `+8`, later invoked at `0x004A1882`. | **Mapped:** pointer flow and indirect invocation. **Unresolved:** exact export name. |

### Shared dynamic-loader wrappers and named API groups

- `LoadLibraryW` at `0x00413C39` is a common wrapper that converts a caller
  string, loads the module, and returns the handle. Representative traced
  callers load a registry-selected keyboard layout and resolve
  `KbdLayerDescriptor` (`0x00451EEC`); `sfc.dll` and
  `SfcIsFileProtected` (`0x004AE103`); `Fusion.dll` and
  `CreateAssemblyCache` (`0x004B2EF1`); `shfolder.dll` and
  `SHGetFolderPathW` (`0x004D8B10`); `_isetup\\_isdecmp.dll`
  (`0x004DB4EA`); `_isetup\\_iscrypt.dll` (`0x004DB702`); a
  script/record-supplied library (`0x004F0282`); and `shell32.dll` with
  `SHPathPrepareForWriteW` (`0x004F8BB0`). Additional shell32 preload sites
  have no recovered consumer.
- `GetProcAddress` at `0x0040914C` and `0x0040916E` are ordinal and string
  branches of wrapper `0x00409128`. Both module and export are wrapper inputs;
  the target caller-supplied values are not fixed in the inspected code.
- `GetProcAddress` at `0x00415359` resolves 22 named oleaut32 exports after
  loading `oleaut32.dll`: `VariantChangeTypeEx`, `VarNeg`, `VarNot`, `VarAdd`,
  `VarSub`, `VarMul`, `VarDiv`, `VarIdiv`, `VarMod`, `VarAnd`, `VarOr`,
  `VarXor`, `VarCmp`, `VarI4FromStr`, `VarR4FromStr`, `VarR8FromStr`,
  `VarDateFromStr`, `VarCyFromStr`, `VarBoolFromStr`, `VarBstrFromCy`,
  `VarBstrFromDate`, and `VarBstrFromBool`. Their pointers are stored in
  globals `0x00501D84` through `0x00501DD8` and used by wrappers with
  fallbacks.
- `GetProcAddress` at `0x0042D100` resolves exports from `USER32.DLL`, whose
  handle is stored at `0x00501E98`. The fixed exports are `GetMonitorInfoA`,
  `GetSystemMetrics`, `MonitorFromRect`, `MonitorFromWindow`,
  `MonitorFromPoint`, `GetMonitorInfoW`, and `EnumDisplayMonitors`; the
  resolved pointers are cached and called indirectly.

These traces map the selected resolver sites and many values passed through
them; they do not establish that every path executes. Runtime-supplied names,
other callers, indirect control flow, and the remaining untraced resolver
sites in the 128-callsite inventory remain open. See the
[system API crosswalk](rk-system-api-crosswalk.md) for aggregate scope and
limits.
