# RK dynamic API resolution audit

## Scope

The installed PE inventory identifies 128 `LoadLibrary*` and
`GetProcAddress` callsites across five binaries. This note records static
reviews of the 47 driver, four installer-helper, 54 updater, and 23
uninstaller sites in that inventory. It uses x86 disassembly only; none of
the applications was executed and no device was contacted. The
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
| `0x00589485` | `LoadLibraryA` | Part of the shared delay-load helper `0x0058938F`; it passes the DLL name rebased from the delay-import descriptor at `0x005F90BC`. | **Proven:** the descriptor names `OLEACC.dll`, and the returned module handle is used for export lookup. See the [delay-loaded accessibility API audit](rk-main-delayload-api-audit.md). |
| `0x0058955C` | `GetProcAddress` | The same helper selects an export name from the descriptor's INT entry matching the IAT slot passed by its thunk. The result is stored in that IAT slot at `0x005895A3`, returned to the shared delay thunk, and tail-dispatched at `0x00589367`. | **Proven:** the three possible names are `AccessibleObjectFromWindow`, `LresultFromObject`, and `CreateStdAccessibleObject`. At `0x00589580`, the helper instead calls through function-pointer global `0x00609A50`; this is not a call through the resolved export pointer. See the [delay-loaded accessibility API audit](rk-main-delayload-api-audit.md). |
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

### Additional driver callers and consumers

The inventory contains 47 dynamic-loader callsites for this PE. A static
review of all rows found these additional argument and pointer-use paths:

- The ANSI loader wrapper at `0x00473B25` is reached through helper
  `0x00473AEC`. Callers load `hhctrl.ocx` (`0x00476AD1`) and
  `RICHED20.DLL` (`0x0054DB60`). The HTML Help path resolves `HtmlHelpW`
  (`0x00476AE8`), caches the module/function, and releases the module if
  export lookup fails.
- The wide loader wrapper at `0x0047B34F` is reached through
  `0x0047B316`. Callers pass `Shell32.dll`, `UxTheme.dll`, `USER32.DLL`,
  `Dwmapi.dll`, and `GDIPPlus.dll` at `0x0047C0EA`, `0x00488F5D`,
  `0x0048A3E1`, `0x004BB17D`, `0x00556B4B`, `0x00488FDB`, `0x0048A473`,
  `0x0048901D`, `0x0048A496`, and `0x0048A395`. These handles feed UI and
  compatibility API lookups; the GDI+ path releases its handle after an
  availability check.
- `SHCreateItemFromParsingName` resolves at `0x0047C124` from the cached
  Shell32 handle at `0x0060594C`; the pointer is stored at `0x00605948` and
  called at `0x0047C14F` with a path, null bind context, interface ID, and
  output pointer. `RegDeleteKeyExW` resolves at `0x004A5418`, is cached at
  `0x00606B8C`, and is called at `0x004A543D`, with imported
  `RegDeleteKeyW` as the fallback.
- `NotifyWinEvent` is resolved from user32 at `0x00487B60`, cached at
  `0x006057BC`, and called at `0x0055F0A2`; `MonitorFromPoint` resolves and
  is invoked at `0x004904E4` and `0x004904F6`. The optional
  `AfxmReleaseManagedReferences` export is looked up from `mfcm90u.dll` at
  `0x0048498A` and called at `0x00484995` when present.
- The resolver block around `0x00582150` initializes optional USER32
  pointers for `MessageBoxA`, `GetActiveWindow`, `GetLastActivePopup`,
  `GetUserObjectInformationA`, and `GetProcessWindowStation`. It encodes and
  caches the pointers, then decodes and calls them later in the same routine.
- Common-controls, common-dialog, image-list, and property-sheet lookups
  share module-state helper `0x00474F73`: the module name is at object offset
  `+0x0C`, the handle is cached at `+0x04`, and ownership state at `+0x08`.
  The `UxTheme.dll` lookup at `0x00556B66` accepts an export name and fallback
  function from the caller. Exact module-state objects and all later cached
  pointer consumers were not recovered for every export.
- Additional optional compatibility lookups include `HeapQueryInformation`
  (`0x00573F65`, cached at `0x00608E60`), `SetThreadStackGuarantee`
  (`0x00574936`), `EncodePointer`/`DecodePointer` (`0x00575FC2`,
  `0x0057603D`), `IsProcessorFeaturePresent` (`0x0057EB7D`),
  `GetUserDefaultUILanguage` (`0x00567907`), and `CorExitProcess`
  (`0x00573867`). The inspected wrappers call these when available or retain
  a documented fallback.

The delay-load helper at `0x00589485`/`0x0058955C` is resolved in the
[focused accessibility API audit](rk-main-delayload-api-audit.md). The
separate `DllGetVersion` wrapper at `0x0055F001` still has no direct call
reference to its entry at `0x0055EFFA`, so its static reachability remains
unresolved. Static inspection of the 47 rows does not establish runtime
branch execution or calls made inside Windows libraries.

## Installer helper resolver paths

`InitSetup.dll` has four dynamic-loader callsites. The installed snapshot hash
is `59DB7BFD9A92CC9A0998260807F17C536EC71159B727DF10D08B998BC94DE301`;
the PE image base is `0x10000000`, and its sole named export is `SetupInit`
at `0x10001080`.

- `GetProcAddress` at `0x10002A04` resolves `EncodePointer` from
  `KERNEL32.DLL` (`0x1000B1A8`, `0x1000B198`). The wrapper at `0x100029AA`
  invokes the pointer on its argument and returns the transformed value; if
  unavailable, it returns the input unchanged. Its fallback retries
  `GetModuleHandleW` every second for up to 60 seconds and does not call
  `LoadLibrary`. Seventeen direct wrapper callers were found; at the USER32
  resolver path they encode pointers before storing them in globals.
- `GetProcAddress` at `0x10002A7F` similarly resolves `DecodePointer` from
  the same module, calls it on the wrapper argument, and uses the input
  unchanged if unavailable. Twenty-seven direct wrapper callers were found;
  five decode cached USER32 pointers in the helper path below. The TLS/cache
  alternate path reads callback-result fields at offsets `+0x1F8` and
  `+0x1FC`; the result-object producer/layout remains unresolved.
- `GetProcAddress` at `0x10003195` conditionally resolves
  `mscoree.dll!CorExitProcess`. The wrapper calls it when available, then
  unconditionally calls imported `ExitProcess` with the same exit code.
  Direct wrapper callers are `0x100033A5`, `0x10005C5B`, and `0x1000686B`;
  branch execution is not established.
- `LoadLibraryA` at `0x10009450` loads fixed `USER32.DLL`. The containing
  routine resolves and encodes `MessageBoxA`, `GetActiveWindow`,
  `GetLastActivePopup`, `GetUserObjectInformationA`, and
  `GetProcessWindowStation` into globals `0x1000F894`, `0x1000F898`,
  `0x1000F89C`, `0x1000F8A4`, and `0x1000F8A0`, then decodes and invokes
  those pointers in a modal-error path. Resolution sites and consumers are:
  `MessageBoxA` `0x1000946C` → `0x10009586`, `GetActiveWindow`
  `0x10009489` → `0x10009545`, `GetLastActivePopup` `0x1000949E` →
  `0x10009565`, `GetUserObjectInformationA` `0x100094B3` → `0x1000951C`,
  and `GetProcessWindowStation` `0x100094CB` → `0x10009509`.
  However, the routine at `0x1000942A`
  has no direct CALL/JMP xref or literal address reference in the image and
  is not exported. Its internal behavior is mapped, but static reachability
  from `SetupInit` is unresolved.

These address-level paths identify names, arguments, fallbacks, and local
consumers but do not demonstrate that the installer helper executed them.

## Updater resolver paths

| Callsite | API | Static argument and result flow | Status |
| --- | --- | --- | --- |
| `0x00416769` | `LoadLibraryW` | Loads the fixed UTF-16 name `Comctl32.dll` at `0x00561D74`, behind the activation-context check at `0x00416764`; the returned module handle is discarded. | **Mapped:** module name and guard. **Unresolved:** runtime reachability. |
| `0x0041F0FA` | `LoadLibraryW` | Generic wrapper passes `[EBP+8]` as the module name, returns the resulting handle. Caller `0x0041A502` builds a `%SystemDirectory%\<caller DLL>` fallback path; caller `0x00423A43` passes `comctl32.dll`, then resolves `DllGetVersion` at `0x00423A5C`, calls it, and frees the module. | **Mapped:** wrapper and two callers. **Unresolved:** values at other callers and runtime reachability. |
| `0x0041A492` | `LoadLibraryExW` | Passes `[EBP+8]` as `lpLibFileName`, NULL as `hFile`, and `0x800` as flags. The path is gated by the encoded `SetDefaultDllDirectories` pointer resolved at `0x0041A467`; that pointer is checked for availability but not invoked. The fallback constructs a system-directory path and calls the loader wrapper. | **Mapped:** argument sources, gate, and fallback shape. **Unresolved:** general caller-supplied module name and execution. |
| `0x00416592` | `GetProcAddress` | Helper `0x00416570` lazily obtains Kernel32, Comctl32, or Comdlg32 handles and returns/caches export pointers. Fixed Kernel32 exports at callers are `ActivateActCtx`, `CreateActCtxW`, `DeactivateActCtx`, `FindActCtxSectionStringW`, `QueryActCtxW`, and `GetModuleHandleExW`. Other callers use runtime export names against Comctl32 (`0x004171CE`, `0x00519C90`) or Comdlg32 (`0x00421793`). | **Mapped:** module families, fixed names, and pointer flow. **Unresolved:** caller-fed export names and runtime reachability. |

The export `SetDefaultDllDirectories` is resolved by the separate call at
`0x0041A467` from `kernel32.dll`. Its pointer is encoded and used only as a
feature-availability test in the observed path; the analysis did not recover
an invocation of it.

### Additional updater resolver paths

All 54 updater rows in the loader inventory were reviewed. Beyond the four
callsite entries above, these paths map to direct consumers and compatibility
fallbacks:

- The transaction-aware wrappers resolve `RegCreateKeyTransactedW`
  (`0x00415508`), `RegOpenKeyTransactedW` (`0x0041556B`),
  `RegDeleteKeyTransactedW` (`0x00418236`), and
  `FindFirstFileTransactedW` (`0x004189BD`). Each calls the returned pointer
  when available and falls back respectively to `RegCreateKeyExW`,
  `RegOpenKeyExW`, `RegDeleteKeyW`, or `FindFirstFileW` when no transaction
  API is available. The first three resolve from Advapi32; the file search
  export resolves from Kernel32. Caller addresses are recorded in the table
  below.
- The `HtmlHelpW` lookup at `0x0041998D` loads `hhctrl.ocx` through wrapper
  `0x0041A431`, caches the module and function in object offsets `+4`/`+8`,
  releases the module and clears state if lookup fails, and calls the cached
  pointer. Wrapper entry `0x0041994B` is called at `0x0041B3C3`.
- `RegisterTouchWindow` (`0x0041CF9C`) and `UnregisterTouchWindow`
  (`0x0041CFCF`) resolve from USER32. Their module, pointers, and state are
  cached at `0x005C1584`, `0x005C158C`, `0x005C1590`, and `0x005C1588`;
  wrapper `0x0041CF47` is called at `0x0041B7F3`.
- `AfxmReleaseManagedReferences` resolves from `mfcm120u.dll` at
  `0x004223F3` and is called with `EBX` when found. Wrapper `0x004223BA` has
  callers `0x004291C2`, `0x0042AB17`, and `0x0042AB3A`.
- `RegDeleteKeyExW` (`0x004261B9`) is lazily cached at `0x005C18C0` with a
  presence flag at `0x005C18C4`; it falls back to `RegDeleteKeyW`.
  `CreateFileTransactedW` (`0x00431A50`) falls back to `CreateFileW` when no
  transaction object is supplied. `GetFileAttributesTransactedW`
  (`0x004377CA`) falls back to `GetFileAttributesExW`.

The 24-site MFC optional-API block stores encoded function pointers in globals;
wrappers decode and invoke them with forwarded arguments. `GetModuleHandleW`
is used for Kernel32, User32, Comctl32, and UxTheme; DWM exports use loader
helper `0x0041A431`. Each row lists the `GetProcAddress` callsite, export,
encoded global slot, wrapper entry, and direct callers. A blank caller field
means no direct static call reference was found.

| GetProcAddress | Export | Module | Encoded slot | Wrapper entry | Direct caller(s) |
| --- | --- | --- | --- | --- | --- |
| `0x00424DFB` | `ApplicationRecoveryFinished` | Kernel32 | `0x005C1878` | `0x00424DD9` | `0x00413654` |
| `0x00424E48` | `ApplicationRecoveryInProgress` | Kernel32 | `0x005C1874` | `0x00424E26` | `0x00413628` |
| `0x00424E9C` | `BeginBufferedPaint` | UxTheme | `0x005C1898` | `0x00424E7A` | `0x00450F0E` |
| `0x00424EF6` | `BufferedPaintInit` | UxTheme | `0x005C1890` | `0x00424ED7` | `0x00450EE0` |
| `0x00424F43` | `BufferedPaintUnInit` | UxTheme | `0x005C1894` | `0x00424F24` | `0x00451362` |
| `0x00424F93` | `ChangeWindowMessageFilter` | User32 | `0x005C187C` | `0x00424F71` | `0x0049E832`, `0x0049E83E` |
| `0x00424FE7` | `CompareStringEx` | Kernel32 | `0x005C1868` | `0x00424FC5` | `0x00419A0A` |
| `0x00425069` | `DrawThemeTextEx` | UxTheme | `0x005C188C` | `0x00425047` | `0x0045165A` |
| `0x004250F0` | `DwmDefWindowProc` | DWM API | `0x005C18A0` | `0x004250CE` | `0x004C6AC8` |
| `0x0042514D` | `DwmInvalidateIconicBitmaps` | DWM API | `0x005C18B0` | `0x0042512B` | `0x004A23AB` |
| `0x004251A1` | `DwmIsCompositionEnabled` | DWM API | `0x005C18A4` | `0x0042517F` | `0x00451977` |
| `0x004251F8` | `DwmSetIconicLivePreviewBitmap` | DWM API | `0x005C18B4` | `0x004251D6` | `0x004A2DC3` |
| `0x00425255` | `DwmSetIconicThumbnail` | DWM API | `0x005C18AC` | `0x00425233` | `0x004A2E27` |
| `0x004252AF` | `DwmSetWindowAttribute` | DWM API | `0x005C18A8` | `0x0042528D` | `0x004A3BAF`, `0x004A3BC7` |
| `0x0042530C` | `EndBufferedPaint` | UxTheme | `0x005C189C` | `0x004252EA` | `0x0045116F` |
| `0x00425363` | `GetLocaleInfoEx` | Kernel32 | `0x005C1860` | `0x00425341` | `0x00413E5A` |
| `0x004253F5` | `GetThreadPreferredUILanguages` | Kernel32 | `0x005C1864` | `0x004253CD` | — |
| `0x00425595` | `InitNetworkAddressControl` | Shell32 | `0x005C1888` | `0x00425576` | `0x004199DC` |
| `0x004255DF` | `TaskDialogIndirect` availability probe | Comctl32 | `0x005C18B8` | `0x004255C0` | — |
| `0x0042562D` | `RegisterApplicationRecoveryCallback` | Kernel32 | `0x005C1870` | `0x0042560B` | `0x00413D18` |
| `0x0042568A` | `RegisterApplicationRestart` | Kernel32 | `0x005C186C` | `0x00425668` | `0x00413CFC` |
| `0x004256E1` | `SHCreateItemFromParsingName` | Shell32 | `0x005C1880` | `0x004256BF` | `0x004208F1` |
| `0x0042573E` | `SHGetKnownFolderPath` | Shell32 | `0x005C1884` | `0x0042571C` | `0x004266CA` |
| `0x0042579B` | `TaskDialogIndirect` | Comctl32 | `0x005C18BC` | `0x00425779` | `0x004384BF` |

Two `LoadLibraryExW` calls initialize WinRT from `combase.dll` with NULL
`hFile` and flags `0x800`: the `RoInitialize` pointer from `0x00537476` is
encoded at `0x005C5218` and called from `0x005374A5`; `RoUninitialize` from
`0x0053754B` is encoded at `0x005C5220` and returned by tail-jump at
`0x00537577`. Their initialization/cleanup wrappers are `0x00537455` and
`0x0053752A`; module release was not observed in this path. A separate
`CorExitProcess` lookup at `0x0053799E` uses a handle from
`GetModuleHandleExW(mscoree.dll)` and calls the pointer with the caller's
exit code.

The fatal-error UI path loads `USER32.DLL` at `0x00549B06` with flags
`0x800`, retrying at `0x00549B28` with flags 0 if the last error is 87. In
routine `0x00549AB8`, it resolves `MessageBoxW`, `GetActiveWindow`,
`GetLastActivePopup`, `GetUserObjectInformationW`, and
`GetProcessWindowStation` at `0x00549B3E`, `0x00549B5A`, `0x00549B6E`,
`0x00549B82`, and `0x00549B9A`. The encoded pointers are cached at
`0x005C5E40–0x005C5E50` and decoded for calls in that routine; its direct
caller is `0x0053D561`.

`CreateFile2` resolves at `0x0054A6D7` from Kernel32. The returned pointer
receives a locally built `CREATEFILE2_EXTENDED_PARAMETERS` value; if absent,
the wrapper falls back to imported `CreateFileW`. Its wrapper `0x0054A6B7`
has callers `0x0054AA55`, `0x0054AA96`, and `0x0054AEF3`.

These paths account for all 47 `GetProcAddress` and seven `LoadLibrary*`
rows in the updater CSV, including caller, export and fallback data where
recovered. The two MFC entries with no direct caller and the runtime branch
conditions remain unresolved; an indirect/function-table edge may exist.

## Uninstaller resolver paths

### Locale-aware module loading

`LoadLibraryExW` callsites `0x00408082`, `0x004080C2`, and `0x00408101` are
branches of a Borland locale-aware loader. A UTF-16 buffer at `[EBP-0x22A]`
is built from the caller record plus values under
`Software\Borland\Locale`; the code tries up to three path/extension
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
  `SHGetFolderPathW` (`0x004D8B10`); `_isetup\_isdecmp.dll`
  (`0x004DB4EA`); `_isetup\_iscrypt.dll` (`0x004DB702`); a
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

### Additional uninstaller callsites

The full `unins000.exe` inventory contains 23 resolver callsites. The
additional 12 callsites map as follows:

- `GetProcAddress` at `0x00407CC8` gets `kernel32.dll` at `0x00407CAC` and
  resolves `GetLongPathNameW` at `0x00407CBF`. The function pointer is called
  at `0x00407CE3` with the input path, a 261-character buffer, and its size.
  The caller chain is `0x00407F53` → `0x00407E90` → `0x00407C17`.
- `LoadLibraryW` at `0x00437F1D` loads `uxtheme.dll`, caches the module at
  `0x00501FE8`, and resolves these 47 exports in order into
  `0x00501F28–0x00501FE0`: `OpenThemeData`, `CloseThemeData`,
  `DrawThemeBackground`, `DrawThemeText`, `GetThemeBackgroundContentRect`,
  `GetThemeBackgroundExtent`, `GetThemePartSize`, `GetThemeTextExtent`,
  `GetThemeTextMetrics`, `GetThemeBackgroundRegion`, `HitTestThemeBackground`,
  `DrawThemeEdge`, `DrawThemeIcon`, `IsThemePartDefined`,
  `IsThemeBackgroundPartiallyTransparent`, `GetThemeColor`, `GetThemeMetric`,
  `GetThemeString`, `GetThemeBool`, `GetThemeInt`, `GetThemeEnumValue`,
  `GetThemePosition`, `GetThemeFont`, `GetThemeRect`, `GetThemeMargins`,
  `GetThemeIntList`, `GetThemePropertyOrigin`, `SetWindowTheme`,
  `GetThemeFilename`, `GetThemeSysColor`, `GetThemeSysColorBrush`,
  `GetThemeSysBool`, `GetThemeSysSize`, `GetThemeSysFont`, `GetThemeSysString`,
  `GetThemeSysInt`, `IsThemeActive`, `IsAppThemed`, `GetWindowTheme`,
  `EnableThemeDialogTexture`, `IsThemeDialogTextureEnabled`,
  `GetThemeAppProperties`, `SetThemeAppProperties`, `GetCurrentThemeName`,
  `GetThemeDocumentationProperty`, `DrawThemeParentBackground`, and
  `EnableTheming`.
  `LoadLibraryW` at `0x004A482F` loads `uxtheme.dll` again and resolves a
  second 47-slot table at `0x005021F4–0x005022AC`. It has the same ordered
  names except slot 6 (`0x00502208`) repeats `GetThemeBackgroundContentRect`
  instead of `GetThemeBackgroundExtent`. The first initializer is reached
  from `0x0046A673`; the second is called at `0x004F8897` and `0x004F8B2D`.
  Direct use of the first table was not recovered; the second table has
  direct consumers for `IsAppThemed` (`0x004A5282`) and `IsThemeActive`
  (`0x004A528C`).
- `LoadLibraryW` at `0x00438A62` loads `DWMAPI.DLL`, caches its handle at
  `0x00502008`, resolves `DwmExtendFrameIntoClientArea` to `0x0050200C`,
  and calls it at `0x00438A4A` or `0x00438A9A`; its wrapper is called at
  `0x00478238`. A second DWM loader at `0x00438B22` resolves
  `DwmIsCompositionEnabled` to `0x00502010` and calls it at `0x00438B0A`
  or `0x00438B59`; the loader helper is reached at `0x00438BBD`.
- `LoadLibraryW` at `0x004688E6` loads `imm32.dll` and resolves ten fixed
  exports: `ImmGetContext`, `ImmReleaseContext`, `ImmGetConversionStatus`,
  `ImmSetConversionStatus`, `ImmSetOpenStatus`, `ImmSetCompositionWindow`,
  `ImmSetCompositionFontA`, `ImmGetCompositionStringA`, `ImmIsIME`, and
  `ImmNotifyIME`. Direct calls were found for the first five and `ImmIsIME`;
  direct reads for the other four were not found. The same initializer
  resolves `USER32!WINNLSEnableIME` at `0x00502140` and calls it at
  `0x00468BD1`.
- `LoadLibraryW` at `0x004A5D6B` loads `oleacc.dll`, resolves
  `LresultFromObject` and `CreateStdAccessibleObject` into `0x005022CC` and
  `0x005022D0`, then calls them at `0x004A88B3` and `0x004A8905`.
- `LoadLibraryW` at `0x004A94B4` loads `RICHED20.DLL` on first reference,
  caches the handle at `0x005022DC`, and maintains its reference count at
  `0x004FC280`. It frees and clears the handle when the count reaches zero;
  acquire/release callers include `0x004A95A7`, `0x004A9573`, and
  `0x004A96E3`.
- `LoadLibraryW` at `0x004F8B3C` loads `shell32.dll`, resolves
  `SHPathPrepareForWriteW` at `0x004F8B50`, stores the pointer at
  `0x00502B34`, and calls it at `0x004BB77C`. The separate shared-wrapper
  path at `0x004F8BB0` resolves the same export into `0x00502B48` and calls
  it at `0x004C5473`.
- The ACL path uses the existing Advapi32 handle to resolve
  `GetNamedSecurityInfoW`, `SetNamedSecurityInfoW`, and `SetEntriesInAclW`
  at `0x004B6BED`, `0x004B6BFA`, and `0x004B6C08`; their pointers are
  invoked at `0x004B6C4E`, `0x004B6D68`, and `0x004B6D27`. The path is reached
  from `0x004B6EA9`, called at `0x004B6E54` by `0x004B6FE4` and
  `0x004B70C5`.

The DWM, keyboard-layout, accessibility, and ACL paths have statically
identified pointer consumers. Some resolved UxTheme and IMM slots have no
direct read in the disassembly, and indirect/data-driven consumers remain
possible. None of these callsite traces proves runtime reachability or
Windows-version-specific export availability.

These traces account for all 128 loader callsite rows in the installed
inventory, but they do not prove every path executes. Runtime-supplied names,
some cached-pointer consumers, indirect control flow, and callers outside
the inspected images remain unresolved. See the
[system API crosswalk](rk-system-api-crosswalk.md) for aggregate scope and
limits.
