# 4.06 uninstaller scrollbar fallback import and thunk audit

## Scope and identity

This is a static follow-up for the eight unresolved USER32 scrollbar imports in
the 4.06 Inno Setup uninstaller. The package-matched snapshot is
`C:\Users\shubh\Downloads\sshorcale\_rk_analysis\inputs\unins000.exe`;
the installed copy is
`C:\Program Files (x86)\RK Keyboard Software\unins000.exe`. Both are 1,316,301
bytes and SHA-256
`b4ca28b192d5a50307d2b28f3323b58b39cb51edd6682e75706cac2dd69a4a14`.
The disassembly and PE import table were inspected offline. The uninstaller
was not launched, and no HID or keyboard interface was opened.

## USER32 import thunk route

The import table identifies each API under `user32.dll`. The thunk is a
one-instruction indirect tail jump to that API's IAT slot. The resolver can
store the thunk address as a fallback value; this proves a route from the
resolver to the import if a consumer later calls through the fallback pointer,
but does not itself prove such a consumer exists or executes.

| USER32 API | IAT RVA / VA | Import thunk | Resolver export name / address | Fallback pointer global | Null-result fallback load / store |
|---|---|---|---|---|---|
| `EnableScrollBar` | `0x00103D6C` / `0x00503D6C` | `0x0040976C` | `FlatSB_EnableScrollBar` / `0x0044B804` | `0x0050209C` | `0x0044B64D` / `0x0044B652` |
| `ShowScrollBar` | `0x00103B68` / `0x00503B68` | `0x00409BB4` | `FlatSB_ShowScrollBar` / `0x0044B834` | `0x005020A0` | `0x0044B66E` / `0x0044B673` |
| `GetScrollRange` | `0x00103CBC` / `0x00503CBC` | `0x004098CC` | `FlatSB_GetScrollRange` / `0x0044B860` | `0x005020A4` | `0x0044B68F` / `0x0044B694` |
| `GetScrollInfo` | `0x00103CC4` / `0x00503CC4` | `0x004098BC` | `FlatSB_GetScrollInfo` / `0x0044B88C` | `0x005020A8` | `0x0044B6B0` / `0x0044B6B5` |
| `GetScrollPos` | `0x00103CC0` / `0x00503CC0` | `0x004098C4` | `FlatSB_GetScrollPos` / `0x0044B8B8` | `0x005020AC` | `0x0044B6D1` / `0x0044B6D6` |
| `SetScrollPos` | `0x00103B8C` / `0x00503B8C` | `0x00409B64` | `FlatSB_SetScrollPos` / `0x0044B8E0` | `0x005020B0` | `0x0044B6F2` / `0x0044B6F7` |
| `SetScrollInfo` | `0x00103B90` / `0x00503B90` | `0x00409B5C` | `FlatSB_SetScrollInfo` / `0x0044B908` | `0x005020B4` | `0x0044B713` / `0x0044B718` |
| `SetScrollRange` | `0x00103B88` / `0x00503B88` | `0x00409B6C` | `FlatSB_SetScrollRange` / `0x0044B934` | `0x005020B8` | `0x0044B734` / `0x0044B739` |

For each row, the corresponding thunk ends in `jmp dword ptr [IAT VA]`; for
example, `0x0040976C` jumps through `0x00503D6C`, and `0x00409BB4` jumps
through `0x00503B68`. The thunk addresses and call-site inventory agree with
[`rk-native-api-xrefs.csv`](rk-native-api-xrefs.csv) and
[`rk-native-api-callsite-gaps.csv`](rk-native-api-callsite-gaps.csv).

## Resolver and caller path

At `0x0044B5E0`, the resolver passes the UTF-16 literal `comctl32.dll` at
`0x0044B744` to thunk `0x00409108`, which jumps through the `GetModuleHandleW`
IAT slot at `0x00504068`. If the returned module handle is null, the resolver
returns at `0x0044B73E` without entering the lookup sequence.

With a non-null handle, the resolver makes symbol-name lookups through helper
`0x00409128`. The helper's string path reaches thunk `0x00409120`, which jumps
through the `GetProcAddress` IAT slot at `0x0050405C`. The PE also contains
static `comctl32.dll` imports; this resolver does not call `LoadLibrary*` to
load that module. The lookup sequence includes `InitializeFlatSB`,
`UninitializeFlatSB`, `FlatSB_GetScrollProp`, and `FlatSB_SetScrollProp` in
globals `0x005020C8`, `0x005020CC`, `0x005020C0`, and `0x005020C4`, followed by
the eight names in the table above.

For every fallback row, the resolver first stores the `GetProcAddress` result
to its global and tests that result. A non-null result skips the fallback
branch. A null result loads the USER32 thunk address as an immediate and stores
it to the same global. The exact load/store pairs are in the last column of the
table. The direct callsite known for the resolver is `0x004F8645`; immediately
before it, code at `0x004F863C` decrements state at `0x005020BC` and branches
around the call on the carry condition. The state variable's wider lifecycle
and the user-interface path that reaches this wrapper are not established by
that local sequence.

## Separate direct FlatSB imports

The executable also has ordinary `comctl32.dll` imports, with direct callsites
recorded in the same cross-reference CSV. They are separate IAT-thunk paths;
no static transfer from these calls to fallback globals `0x0050209C` through
`0x005020B8` was recovered.

| `comctl32.dll` import | Import thunk | Direct callsites |
|---|---|---|
| `InitializeFlatSB` | `0x0040A0B0` | `0x00471518` |
| `FlatSB_SetScrollProp` | `0x0040A0A8` | `0x00471246`, `0x00471277`, `0x004712A8`, `0x004712D9`, `0x00471307` |
| `FlatSB_GetScrollInfo` | `0x0040A088` | `0x00470D03` |
| `FlatSB_GetScrollPos` | `0x0040A090` | `0x00471128` |
| `FlatSB_SetScrollPos` | `0x0040A0A0` | `0x00471142` |
| `FlatSB_SetScrollInfo` | `0x0040A098` | `0x004713D3` |

These imports prove the binary contains direct FlatSB operations. Their names
suggest scrollbar setup, property changes, and information/position access,
but those names do not prove a particular UI workflow or runtime execution.
They do not establish that the eight USER32 fallback pointers are read.

## Status: proven, inferred, unresolved

**Proven statically:** binary identity and installed/snapshot hash match; the
eight USER32 import names, IAT slots, thunk tail jumps, resolver symbol-name
references, per-row success/null stores, and the resolver's known direct call
site; separate direct callsites for the six listed `comctl32` imports. These
facts describe available code paths and data flow, not observed execution.

**Inferred:** the eight globals implement compatibility fallbacks for the
corresponding dynamically resolved `FlatSB_*` functions. This interpretation
follows from the paired export names and null-result thunk stores. The exact
UI controls and the reason for keeping both imported and dynamically resolved
scrollbar paths are not proven.

**Unresolved:** no in-image load, indirect call, or callback handoff from any
of the eight fallback globals was recovered. The full-image exact-DWORD scan
finds two references to each global, both resolver stores, and one raw hit per
fallback thunk address, at its immediate fallback load. This does not rule out
computed addressing, an alias, runtime patching, an external consumer, or a
different uninstaller version. The suspected indexed decode at `0x0044B2C0`
was rejected as a misaligned decode within a relative-call displacement; see
[`rk-unins000-scrollbar-fallback-indexed-candidate.md`](rk-unins000-scrollbar-fallback-indexed-candidate.md).
The imports remain unresolved, not unused.

## Reproduction trail

The reviewed image is outside the repository and is not redistributed. The
relevant checked-in evidence includes the two CSV files linked above, the
[remaining native API path audit](rk-remaining-native-api-path-audit.md), and
the [deep-scan note](rk-remaining-native-api-gap-deep-scan.md). Targeted
offline commands used GNU `objdump` over `unins000.exe`, including:

```text
objdump -d -Mintel --start-address=0x0044B5E0 --stop-address=0x0044B741 unins000.exe
objdump -d -Mintel --start-address=0x00409128 --stop-address=0x0040919B unins000.exe
objdump -d -Mintel --start-address=0x004F863C --stop-address=0x004F864B unins000.exe
```

The CSV reference scan is a candidate finder over bytes, not a whole-program
control-flow proof. No vendor executable was run as part of this follow-up.
