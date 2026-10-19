# Static audit of imports without direct call references

This note follows up on the 62 rows in the [native API callsite-gap inventory](rk-native-api-callsite-gaps.csv). It maps indirect call paths where static instructions provide enough evidence and records the remaining gaps. The broader [native API cross-reference](rk-native-api-xrefs.csv) and [system API crosswalk](rk-system-api-crosswalk.md) cover the full import set and scan method.

## Scope and method

The analyzed package is the installed `C:\Program Files (x86)\RK Keyboard Software` snapshot. Local PE snapshots under `_rk_analysis/inputs` were SHA-256 checked against their installed counterparts; all hashes match. Those vendor binaries are not redistributed in this repository; readers need the same package version to reproduce address-level findings:

| PE | Installed relative path | SHA-256 |
| --- | --- | --- |
| `DeviceDriver.exe` | `DeviceDriver.exe` | `c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6` |
| `Update.exe` | `Dev/01AF/Update.exe` | `27894463b0dfe5bc3f5dc19d4d3351d9dfb692c402bf277bde3889d37e4a206c` |
| `InitSetup.dll` | `InitSetup.dll` | `59db7bfd9a92cc9a0998260807f17c536ec71159b727df10d08b998bc94de301` |
| `uninstall.dll` | `uninstall.dll` | `9ca1ebc49998b8b2971debc1776e7aff6086aeb86adcca6cfb95e9fb399eb03c` |
| `unins000.exe` | `unins000.exe` | `b4ca28b192d5a50307d2b28f3323b58b39cb51edd6682e75706cac2dd69a4a14` |

GNU `objdump -d` disassembly was inspected for the IAT-reference locations and their surrounding control flow. A row is mapped as a register-indirect call when an instruction loads the row's absolute IAT address into a register and a later instruction calls through that same register. The exception paths use a separate function-pointer global; the common-dialog paths pass thunk addresses to a helper that calls through its function-pointer parameter. `_adjust_fdiv` is an imported data value, not a function call. These are static transfer and data-flow observations only.

No RK executable or updater was run. No keyboard HID interface, serial port, firmware writer, or bootloader was opened or used. The updater binary itself was inspected statically.

## Coverage summary

Of the 62 gap rows, 52 are mapped: 51 function-call or callback targets and one imported data reference. Ten rows remain unresolved. Four additional imported-API paths were recovered as conditional tail-jumps through their IAT entries; they do not change the count of register-indirect call instructions. A separate `DeviceDriver.exe` `PostQuitMessage` wrapper is now mapped through its callers and unconditional IAT tail-jump. A later 4.06 revalidation found three register-indirect call instructions omitted from the original DeviceDriver list; the corrected total is 109 across the five binaries.

| Binary | Gap rows | Mapped call/callback rows | Mapped data rows | Unresolved rows | Register-indirect call sites |
| --- | ---: | ---: | ---: | ---: | ---: |
| `DeviceDriver.exe` | 32 | 32 | 0 | 0 | 80 |
| `Update.exe` | 12 | 10 | 0 | 2 | 16 |
| `InitSetup.dll` | 2 | 2 | 0 | 0 | 3 |
| `uninstall.dll` | 3 | 2 | 1 | 0 | 10 |
| `unins000.exe` | 13 | 5 | 0 | 8 | 0 |
| **Total** | **62** | **51** | **1** | **10** | **109** |

The mapped transfers break down as follows:

- **109 register-indirect API calls:** 80 in `DeviceDriver.exe`, 16 in `Update.exe`, 3 in `InitSetup.dll`, and 10 in `uninstall.dll`. The 4.06 [gap revalidation follow-up](rk-406-native-api-gap-revalidation-follow-up.md) identifies three call instructions omitted from the earlier DeviceDriver list.
- **9 exception-helper calls through global function pointers:** six calls to `RaiseException` and three to `RtlUnwind` in `unins000.exe`.
- **One indirect tail-jump** through the `RaiseException` global function pointer.
- **One DeviceDriver import tail-jump wrapper:** `PostQuitMessage` at
  `0x0047F29C` is reached through wrapper `0x0047F280`, called directly at
  seven sites (`0x00474EDD`, `0x0047547D`, `0x0047F75F`, `0x00486FBC`,
  `0x004B542D`, `0x004D8681`, and `0x004DEB91`). The wrapper may call a
  context object's vtable `+0x3C` with `(1,1)`, then tail-jumps through the
  `PostQuitMessage` IAT slot `0x0059E58C` with its original stack argument.
  The exact higher-level teardown/message-loop cases remain unknown.
- **Four conditional IAT tail-jumps:** `OleFlushClipboard` in
  `DeviceDriver.exe`, and `PostQuitMessage`, `GetThemeSysColor`, and
  `OleFlushClipboard` in `Update.exe`.
- **One `DefMDIChildProcW` callback route:** its thunk is supplied to `CallWindowProcW` at the listed call site.
- **Two common-dialog target routes through one shared instruction:** `GetOpenFileNameW` and `GetSaveFileNameW` are passed by separate wrappers to a helper that calls its function-pointer argument at one machine instruction.
- **One imported data reference:** `_adjust_fdiv` in `uninstall.dll`.

These counts describe distinct import rows, disassembled transfer instructions, or static callback routes as labeled. They are not runtime call counts. The two common-dialog rows share one call instruction; the callback route depends on `CallWindowProcW` dispatching the supplied procedure.

## Mapped call and callback sites

The compact address lists below are instruction addresses in the corresponding x86 PE. For register-indirect rows, each listed address is a `call` through a register loaded from that API's IAT slot. For `unins000.exe`, the notes identify callback and function-pointer dispatch paths that do not use direct calls to the import thunk.

### `DeviceDriver.exe`

| API | Indirect call instruction addresses |
| --- | --- |
| `VirtualFree` | `0x005795E7`, `0x00579642` |
| `GetProfileIntW` | `0x0050DADB`, `0x0050DAED`, `0x0055D07B`, `0x0055D08A`, `0x0055D099` |
| `SetErrorMode` | `0x00487AF9`, `0x00487B01` |
| `GlobalGetAtomNameW` | `0x004B593D`, `0x004B5962` |
| `ConvertDefaultLocale` | `0x0047F8D8`, `0x0047F8E6`, `0x0047F92E`, `0x0047F937`, `0x0047F9A0`, `0x0047F9A9` |
| `RegisterDeviceNotificationW` | `0x00447019`, `0x00447060` |
| `UnregisterDeviceNotification` | `0x00446167`, `0x00446170` |
| `DeleteMenu` | `0x0049CE2F`, `0x0049CE3B`, `0x0049CE47`, `0x004E52AB`, `0x004E52B7`, `0x004E52DF`, `0x004FDBBF`, `0x004FDBCB`, `0x004FDBD7`, `0x004FDBE3`, `0x004FDC0C` |
| `CharNextW` | `0x004AB3A5`, `0x004AB3C7` |
| `RestoreDC` | `0x00470C78`, `0x00470C89` |
| `SetBkMode` | `0x00470CEC`, `0x00470CF9` |
| `SetPolyFillMode` | `0x00470D1E`, `0x00470D2B` |
| `SetROP2` | `0x00470D50`, `0x00470D5D` |
| `ExcludeClipRect` | `0x00470E08`, `0x00470E1D` |
| `SetTextAlign` | `0x00470EC3`, `0x00470ED0` |
| `SelectClipRgn` | `0x00471429`, `0x0047143F` |
| `OffsetViewportOrgEx` | `0x00471253`, `0x00471266` |
| `ScaleViewportExtEx` | `0x004712D7`, `0x004712F0` |
| `OffsetWindowOrgEx` | `0x0047135B`, `0x0047136E` |
| `ScaleWindowExtEx` | `0x004713DF`, `0x004713F8` |
| `ExtSelectClipRgn` | `0x00471532`, `0x0047154B` |
| `SaveDC` | `0x00470C3E`, `0x00470C4B` |
| `LPtoDP` | `0x0055272D`, `0x00552745`, `0x0055275D` |
| `EnumFontFamiliesW` | `0x00489F36`, `0x00489F61` |
| `RemoveFontResourceW` | `0x00454A86`, `0x00454AB3`, `0x00454AE0`, `0x00454B0D` |
| `RegEnumKeyExW` | `0x004A59A3` |
| `DragQueryFileW` | `0x004B57EE`, `0x004B5821` |
| `SHAppBarMessage` | `0x00488955`, `0x00488975`, `0x00488991`, `0x004889B1` |
| `SetupDiGetDeviceInterfaceDetailW` | `0x004165A1`, `0x004165EF` |
| `PlaySoundW` | `0x0050DE0B`, `0x0050DE2A` |

The five `GetProfileIntW` calls are described in the focused
[`GetProfileIntW call-path audit`](rk-device-driver-getprofileintw-callpath.md).
Static argument and literal recovery identifies the `windows` profile keys
`DragMinDist`, `DragDelay`, `DragScrollInset`, `DragScrollDelay`, and
`DragScrollInterval`, their numeric defaults, and the global destinations for
the returned values. This resolves the call arguments and immediate dataflow;
the active profile values, backing store on this machine, and downstream UI
effects remain unknown.

The device-related paths corroborate the documented SetupAPI and notification routes: `SetupDiGetDeviceInterfaceDetailW` is loaded from its IAT slot at `0x00416580` in the function beginning at `0x00416570`; notification registration loads `RegisterDeviceNotificationW` at `0x00446FE6` in the function beginning at `0x00446FC0`; and cleanup loads `UnregisterDeviceNotification` at `0x00446160` before two calls.

The remaining DeviceDriver gap row, `PostQuitMessage`, is also mapped beyond
its IAT reference. Wrapper `0x0047F280` invokes a context object's vtable
`+0x3C` with `(1,1)` when available, then tail-jumps through the import at
`0x0047F29C`. Seven call instructions target the wrapper:
`0x00474EDD`, `0x0047547D`, `0x0047F75F`, `0x00486FBC`, `0x004B542D`,
`0x004D8681`, and `0x004DEB91`. Static inspection does not establish which
window or thread shutdown cases reach these callers.

### `Update.exe`

| API | Indirect call instruction addresses |
| --- | --- |
| `VerSetConditionMask` | `0x0045190F`, `0x00451913` |
| `SetErrorMode` | `0x00437581`, `0x00437589` |
| `EnumFontFamiliesW` | `0x00451D9C`, `0x00451DC5` |
| `LPtoDP` | `0x005318A8`, `0x005318C3`, `0x005318DE` |
| `RegEnumValueW` | `0x00426E16` |
| `SHAppBarMessage` | `0x004C5BED`, `0x004C5C07`, `0x004C5C1D`, `0x004C5C36` |
| `PlaySoundW` | `0x004D28F5`, `0x004D2934` |

For `RegEnumValueW`, the IAT address is loaded into `EBX` at `0x00426D72`; control flow jumps to a shared block at `0x00426E10`, which calls through `EBX` at `0x00426E16`.

Three Update rows and one DeviceDriver row have conditional IAT tail-jump
paths, rather than register-indirect call instructions:

| Binary/API | Recovered path |
| --- | --- |
| `DeviceDriver.exe` — `OleFlushClipboard` | Caller `0x0051EB2E` invokes wrapper `0x0050D86D`. If helper `0x0050D804` returns nonzero, `0x0050D876` tail-jumps through IAT VA `0x0059EA54`; otherwise it returns. |
| `Update.exe` — `PostQuitMessage` | Wrapper `0x004135E7` optionally calls the object's `+0x3C` method with `(1, 1)`, then tail-jumps through IAT VA `0x0056074C` at `0x00413601`. Six direct callers were found: `0x00413D70`, `0x0041BE31`, `0x0041D36C`, `0x004350A8`, `0x00469F42`, and `0x00497AC7`; caller `0x00413D70` passes exit code 0. |
| `Update.exe` — `GetThemeSysColor` | Wrapper `0x004E92C5` tail-jumps through IAT VA `0x005608C0` at `0x004E92CF` when the theme handle argument is nonzero. Otherwise it calls `GetSysColor` with its second argument. There are 21 direct callers; `0x004E90F0` passes color `0x1D` and `[ecx+4]` as the theme handle. |
| `Update.exe` — `OleFlushClipboard` | Caller `0x004141D2` invokes helper `0x00427F18`; helper `0x00427FE1` gates a tail-jump through IAT VA `0x00560968`. |

Update's `LoadLibraryA` and `GetModuleHandleA` thunk addresses appear in
alternate ANSI descriptor records, but no invocation path for those rows was
recovered. Helper `0x00416570` dispatches through a descriptor's loader
pointer and then calls `GetProcAddress`; all nine direct callers pass W
descriptors. Six pass the Kernel32 W record at `0x00561DCC`; the other three
pass W records at `0x00562218`, `0x005645A4`, and `0x00584508`. Adjacent A
records at `0x00561DD4`, `0x00562220`, `0x005645AC`, and `0x00584510` have no
code-immediate or raw-pointer references in the analyzed image. That leaves
the two ANSI imports unresolved; it does not prove they are unused. See the
separate [dynamic API resolution audit](rk-dynamic-api-resolution-audit.md).

### `InitSetup.dll`

| API | Indirect call instruction addresses |
| --- | --- |
| `DeleteFileW` | `0x10001273` |
| `GetEnvironmentStringsW` | `0x10003A28`, `0x10003A63` |

### `uninstall.dll`

| API | Indirect call instruction addresses | Notes |
| --- | --- | --- |
| `_decode_pointer` | `0x100011D9`, `0x100011ED`, `0x10001214`, `0x1000122A`, `0x10001235`, `0x100014EF`, `0x10001518`, `0x10001523` | IAT pointer is loaded into `ESI` before these calls. |
| `InterlockedCompareExchange` | `0x100010D2`, `0x100011A7` | IAT pointer is loaded into `ESI` before each call. |

`_adjust_fdiv` is not called. Its IAT slot at `0x10002054` is loaded and dereferenced at `0x10001086`–`0x1000108C`, and the retrieved value is stored at global `0x1000334C` by `0x10001091`. This is categorized as a data import.

### `unins000.exe`

| API | Static transfer or callback evidence |
| --- | --- |
| `RaiseException` | Its thunk `0x0040125C` is assigned to global function-pointer slot `0x004FD014` at `0x00404D7C` and `0x004F8019`. Calls through the slot occur at `0x00404598`, `0x004045B6`, `0x004045CE`, `0x00404640`, `0x00404660`, and `0x0040467D`; an indirect tail-jump through the slot occurs at `0x00404A82`. |
| `RtlUnwind` | Its thunk `0x00401264` is assigned to global slot `0x004FD018` at `0x00404D86` and `0x004F8023`. Calls through the slot occur at `0x0040475A`, `0x004048E2`, and `0x00404C08`. |
| `DefMDIChildProcW` | Thunk `0x004096CC` is stored in an object field at `0x00474FF8` and passed as the window-procedure argument at `0x004771EE`; the following call at `0x004771F3` targets the `CallWindowProcW` thunk `0x00409654` (IAT VA `0x00503DE4`). This is a callback dispatch route, not a direct call instruction to `DefMDIChildProcW`. |
| `GetOpenFileNameW` | Thunk `0x00448848` is passed to helper `0x004BA25C` at `0x004BA3DC`; that helper calls its function-pointer argument at `0x004BA32A`. |
| `GetSaveFileNameW` | Thunk `0x00448850` is passed to helper `0x004BA25C` at `0x004BA400`; that helper calls its function-pointer argument at the same instruction, `0x004BA32A`. |

The eight remaining `unins000.exe` rows are scrollbar APIs. Resolver
`0x0044B5E0` loads `comctl32` through helper `0x00409108`, resolves each
`FlatSB_*` export through `0x00409128`, and stores either the resolved address
or the matching USER32 thunk fallback in a global. Its direct caller is
`0x004F8645`. Static disassembly and a whole-file little-endian address scan
found only the resolver's initialization stores to globals `0x0050209C`–
`0x005020B8`; no later direct read, indirect invocation, or callback passage
was recovered. These pointers remain unresolved because computed references,
external callers, and other binary versions are outside the scan.

| Fallback thunk | Pointer global | `GetProcAddress` export | Fallback stores |
| --- | --- | --- | --- |
| `0x0040976C` (`EnableScrollBar`) | `0x0050209C` | `FlatSB_EnableScrollBar` at `0x0044B804` | `0x0044B64D`, `0x0044B652` |
| `0x00409BB4` (`ShowScrollBar`) | `0x005020A0` | `FlatSB_ShowScrollBar` at `0x0044B834` | `0x0044B66E`, `0x0044B673` |
| `0x004098CC` (`GetScrollRange`) | `0x005020A4` | `FlatSB_GetScrollRange` at `0x0044B860` | `0x0044B68F`, `0x0044B694` |
| `0x004098BC` (`GetScrollInfo`) | `0x005020A8` | `FlatSB_GetScrollInfo` at `0x0044B88C` | `0x0044B6B0`, `0x0044B6B5` |
| `0x004098C4` (`GetScrollPos`) | `0x005020AC` | `FlatSB_GetScrollPos` at `0x0044B8B8` | `0x0044B6D1`, `0x0044B6D6` |
| `0x00409B64` (`SetScrollPos`) | `0x005020B0` | `FlatSB_SetScrollPos` at `0x0044B8E0` | `0x0044B6F2`, `0x0044B6F7` |
| `0x00409B5C` (`SetScrollInfo`) | `0x005020B4` | `FlatSB_SetScrollInfo` at `0x0044B908` | `0x0044B713`, `0x0044B718` |
| `0x00409B6C` (`SetScrollRange`) | `0x005020B8` | `FlatSB_SetScrollRange` at `0x0044B934` | `0x0044B734`, `0x0044B739` |

## Unresolved rows

These 10 rows have no recovered invocation or callback path in the reviewed disassembly. “Unresolved” does not mean unused.

| Binary | Unresolved API rows |
| --- | --- |
| `DeviceDriver.exe` | None |
| `Update.exe` | `LoadLibraryA`, `GetModuleHandleA` |
| `InitSetup.dll` | None |
| `uninstall.dll` | None |
| `unins000.exe` | `ShowScrollBar`, `SetScrollRange`, `SetScrollPos`, `SetScrollInfo`, `GetScrollRange`, `GetScrollPos`, `GetScrollInfo`, `EnableScrollBar` |

## Limits

The listed instructions and data flows prove that a code path can transfer to the named import or pass its thunk as a callback/function pointer. They do not establish that any branch is reachable in a particular session, that Windows invokes a callback, that the user selects a corresponding UI workflow, or that any API actually ran. They do not replace a full call graph: indirect control flow, dynamically resolved targets, COM/vtable dispatch, and behavior in other package versions remain outside this specific follow-up.
