# Updater native API gap-row reconciliation

## Scope and identity

This note reconciles the 12 `Update.exe` rows in
[`rk-native-api-callsite-gaps.csv`](rk-native-api-callsite-gaps.csv) whose
direct-call and direct-call-to-thunk columns are blank. The ledger can still
record the thunk's own indirect jump in `iat_thunk_sites` (as for the two
ANSI imports) or a code reference to an IAT slot in
`other_iat_reference_sites`. Those references can feed register-indirect
calls or wrapper tail-jumps that the two call columns do not encode.

The target is the installed x86 `Dev/01AF/Update.exe`, SHA-256
`27894463b0dfe5bc3f5dc19d4d3351d9dfb692c402bf277bde3889d37e4a206c`
(2,109,952 bytes). The installed file and `_rk_analysis/inputs/Update.exe`
were both hashed during this pass and matched that value. The executable was
not launched. This is a static crosswalk, not evidence that any branch ran.

## Reconciliation

Ten of the twelve rows already have static invocation or wrapper routes in
the [indirect-call audit](rk-native-api-indirect-call-audit.md): seven use
register-indirect calls and three use IAT tail-jump wrappers. This pass
rechecked the row references and the adjacent instructions in the hash-matched
image; the table summarizes that evidence without replacing the detailed
callsite records in the existing audit. The two ANSI loader rows remain
unresolved as documented by the [ANSI loader boundary audit](rk-update-ansi-loader-call-boundary-audit.md)
and the [relative-reference follow-up](rk-unresolved-native-api-relative-reference-followup.md).

| Import row | Gap-ledger IAT reference | Recovered static route and nearby behavior | Result |
|---|---:|---|---|
| `VerSetConditionMask` | `0x0045190B` | Loads IAT VA `0x00560320` into `ESI`; calls through it at `0x0045190F` and `0x00451913`. The returned mask values are then passed to imported `VerifyVersionInfoW` at `0x00451920`. | **Mapped:** register-indirect; a Windows-version-condition path. |
| `SetErrorMode` | `0x0043757B` | Loads IAT VA `0x00560358` into `ESI`; calls `SetErrorMode(0)` at `0x00437581`, then calls it again at `0x00437589` with the first return value ORed with `0x8001`. | **Mapped:** register-indirect; the second call derives its argument from the first call's prior-mode result. |
| `LoadLibraryA` | `0x00417442` | The IAT reference is in the import thunk. The thunk is named in three ANSI loader descriptors, but all nine direct calls to shared helper `0x00416570` pass W-form descriptors; no direct transfer to this thunk or exact pointer to an ANSI descriptor base was recovered. | **Unresolved:** computed/indirect selection, generated state, external caller, and runtime use. |
| `GetModuleHandleA` | `0x004165B0` | The IAT reference is in the import thunk. Its ANSI Kernel32 descriptor exists, but the nine direct calls to helper `0x00416570` use W-form descriptors; no direct transfer to this thunk or exact pointer to its ANSI descriptor base was recovered. | **Unresolved:** computed/indirect selection, generated state, external caller, and runtime use. |
| `PostQuitMessage` | `0x00413601` | Wrapper `0x004135E7` optionally calls an object method, then tail-jumps through IAT VA `0x0056074C`. Its six callers are recorded in the indirect-call audit. | **Mapped:** wrapper tail-jump; caller workflows and execution conditions remain branch-dependent. |
| `EnumFontFamiliesW` | `0x00451D98` | Loads IAT VA `0x00560110` into `EBX`; calls it at `0x00451D9C` and `0x00451DC5` using callback address `0x0045169F`. The second enumeration is conditional on the first result. | **Mapped:** register-indirect; font-family enumeration path. |
| `LPtoDP` | `0x00531893` | Loads IAT VA `0x00560170` into `ESI`; calls it at `0x005318A8`, `0x005318C3`, and `0x005318DE` for three two-point buffers assembled from object fields/arguments. | **Mapped:** register-indirect; coordinate conversion path. |
| `RegEnumValueW` | `0x00426D74` | Loads IAT VA `0x00560028` into `EBX` at `0x00426D72`; control flow reaches shared block `0x00426E10`, which calls `EBX` at `0x00426E16` and branches on the returned status. | **Mapped:** register-indirect; registry-value enumeration loop. |
| `SHAppBarMessage` | `0x004C5BDC` | Loads IAT VA `0x0056050C` into `EDI`; four calls at `0x004C5BED`, `0x004C5C07`, `0x004C5C1D`, and `0x004C5C36` pass message value 7 and an `APPBARDATA`-shaped stack record. Its edge field is varied and successful return values set separate result bits. | **Mapped:** register-indirect. The API's conventional message-7 meaning is an interpretation of the argument, not proof of runtime behavior. |
| `GetThemeSysColor` | `0x004E92CF` | Wrapper `0x004E92C5` tail-jumps through IAT VA `0x005608C0` when its theme-handle argument is nonzero; otherwise it calls `GetSysColor`. | **Mapped:** conditional wrapper tail-jump; 21 direct wrapper callers are listed in the indirect-call audit. |
| `OleFlushClipboard` | `0x00427F21` | Caller `0x004141D2` calls helper `0x00427F18`; its helper conditionally tail-jumps through IAT VA `0x00560968` at `0x00427F21`. | **Mapped:** gated wrapper tail-jump. |
| `PlaySoundW` | `0x004D28D8` | Loads IAT VA `0x005608EC` into `EDI`; calls it at `0x004D28F5` and `0x004D2934`. The first call selects between two fixed pointer arguments; a polling loop invokes imported `Sleep(5)` before the follow-up branch. | **Mapped:** register-indirect; audio helper path. The sound data contents and runtime trigger are outside this crosswalk. |

The route count reconciles exactly: **7 register-indirect import rows, 3
conditional or unconditional tail-jump rows, and 2 unresolved ANSI loader
rows**. The 16 register-indirect call instructions are the seven rows'
callsite counts (2 + 2 + 2 + 3 + 1 + 4 + 2). This agrees with the existing
indirect-call inventory rather than increasing its callsite total.

## Evidence limits

**Proven statically:** the binary identity, IAT-reference and call/wrapper
instruction addresses listed above, the register or argument flow visible in
the targeted disassembly, and the route classification against the existing
ledger. The ANSI descriptors and nine W-descriptor calls are documented with
their complete exact-reference census in the focused ANSI loader audit.

**Inferred:** the likely Windows-version, font-enumeration, coordinate,
registry, appbar, and audio roles from imported API names and local argument
shapes. These observations do not establish the user workflow or prove an
API executes.

**Unresolved:** whether any branch executes in an actual run; indirect or
computed selection of the ANSI descriptors; external callers or runtime
generated references; and behavior in any updater build other than this
hash-matched image. Neither ANSI API is proven unused. No device interface,
report, firmware, or bootloader behavior is established by this import audit.
