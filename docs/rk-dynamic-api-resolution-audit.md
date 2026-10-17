# RK dynamic API resolution audit

## Scope

The installed PE inventory identifies 128 `LoadLibrary*` and
`GetProcAddress` callsites across five binaries. This note follows the seven
main-app callsites that had no nearby literal module/export candidate in
[`rk-dynamic-api-targets.csv`](rk-dynamic-api-targets.csv). The analysis uses
static x86 disassembly of the installed `DeviceDriver.exe` hash recorded in
[`rk-native-api-imports.md`](rk-native-api-imports.md); it does not execute
the application or contact a device.

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

The four `Update.exe` and eleven `unins000.exe` callsites with no nearby
literal candidates have not received the same argument-by-argument follow-up
in this note. Their callsite addresses remain listed in the dynamic-loader
CSV and the broader limitations remain in the
[system API crosswalk](rk-system-api-crosswalk.md).
