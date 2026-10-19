# RK 4.6 package helper native API and syscall crosswalk

## Scope and safety

This audit covers the three helper PEs in the extracted 4.6-labeled package:
`Dev/01AF/Update.exe`, `InitSetup.dll`, and `uninstall.dll`. It compares each
file with the installed 4.06 manifest and reuses 4.06 instruction-level API
and syscall findings only where the file hashes match exactly. The extracted
package also contains `DeviceDriver.exe`, which changed between these
snapshots and has a separate [4.6 main-driver audit](rk-v4.6-native-api-call-path-audit.md).

Neither the installer nor any vendor executable was launched. No HID, serial,
Bluetooth, or other device interface was opened, and no keyboard report,
command, firmware, updater, or bootloader operation was performed.

## Hash-pinned helper inventory

The input is the extracted 1,249-file snapshot described in the
[4.6 package report](rk-v4.6-package-snapshot.md). Its manifest has four PE
files total: the changed main driver and the three helper files below. For
each helper, the package manifest, the installed 4.06 manifest, and the
extracted file bytes agree on both size and SHA-256:

| 4.6 package path | Bytes | SHA-256 | 4.06 identity | Result |
| --- | ---: | --- | --- | --- |
| `app/Dev/01AF/Update.exe` | 2,109,952 | `27894463b0dfe5bc3f5dc19d4d3351d9dfb692c402bf277bde3889d37e4a206c` | `Dev/01AF/Update.exe`, same size and hash | Byte-identical |
| `app/InitSetup.dll` | 69,000 | `59db7bfd9a92cc9a0998260807f17c536ec71159b727df10d08b998bc94de301` | `InitSetup.dll`, same size and hash | Byte-identical |
| `app/uninstall.dll` | 146,944 | `9ca1ebc49998b8b2971debc1776e7aff6086aeb86adcca6cfb95e9fb399eb03c` | `uninstall.dll`, same size and hash | Byte-identical |

`pefile` parsed the import tables from those exact files. Their import sets
match every row in the 4.06 IAT cross-reference: 618 ordinary imports in
`Update.exe`, 76 in `InitSetup.dll`, and 30 in `uninstall.dll`, for 724 rows.
The reproducible generator verifies both manifests and the extracted hashes,
then emits one row per import in the
[4.6 helper API/callsite crosswalk](rk-v4.6-helper-api-callsite-crosswalk.csv):

```powershell
py scripts/audit_rk46_helper_api_crosswalk.py
```

The generator joins each imported DLL/API/IAT RVA with the existing 4.06
direct-call, thunk-call, tail-jump-to-thunk, and other-IAT-reference ledger,
then adds the reviewed register-indirect call and direct `jmp [IAT]` sites
from the [4.06 indirect-call audit](rk-native-api-indirect-call-audit.md).
This is an exact byte-level carry-forward for these three hashes, not a new
decompilation or claim that every transfer executes. The full named import
inventory remains in [the API inventory](rk-native-api-imports.md).

## Recovered static transfer coverage

The existing 4.06 ledger reports direct calls to IAT slots or relative calls
to identified import thunks for 606 of the updater's 618 import rows, 74 of
the setup helper's 76 rows, and 27 of the uninstaller helper's 30 rows. The
hash-pinned follow-up accounts for the remaining rows as follows:

| PE | Imports with direct/thunk calls | Additional register-indirect call sites | Direct `jmp [IAT]` sites | Data reference | Remaining unresolved import rows |
| --- | ---: | ---: | ---: | --- | --- |
| `Update.exe` | 606 | 16 across 7 APIs | 3: `PostQuitMessage` at `0x00413601`, `GetThemeSysColor` at `0x004E92CF`, `OleFlushClipboard` at `0x00427FE1` | — | `LoadLibraryA`, `GetModuleHandleA` |
| `InitSetup.dll` | 74 | 3: `DeleteFileW` at `0x10001273`; `GetEnvironmentStringsW` at `0x10003A28`, `0x10003A63` | — | — | None identified |
| `uninstall.dll` | 27 | 10 across 2 APIs | — | `_adjust_fdiv` is read as imported data, not called | None identified |

The updater's 16 register calls are listed per API in the CSV; they cover
`VerSetConditionMask`, `SetErrorMode`, `EnumFontFamiliesW`, `LPtoDP`,
`RegEnumValueW`, `SHAppBarMessage`, and `PlaySoundW`. The uninstaller-helper
register calls are eight `_decode_pointer` calls and two
`InterlockedCompareExchange` calls. Its `_adjust_fdiv` import is dereferenced
and copied to process state. The two unresolved updater rows are the ANSI
loader imports; their presence in the import table is not proof of use or
non-use. See the [ANSI loader boundary audit](rk-update-ansi-loader-call-boundary-audit.md)
and [updater import reconciliation](rk-updater-native-import-gap-reconciliation.md).

The separate dynamic-API ledger contains 94 rows for `Update.exe` and 15 for
`InitSetup.dll`, including direct loader calls and resolved `GetProcAddress`
targets. Since these PEs are byte-identical to 4.06, their instruction
addresses carry over; those rows are not duplicated in the imported-API CSV.
See [dynamic API targets](rk-dynamic-api-targets.csv) and the
[resolver audit](rk-dynamic-api-resolution-audit.md). These findings identify
static resolver paths and candidate exports, not runtime-resolved addresses
or execution.

## Direct syscall/sysenter boundary

The 4.06 raw-byte ledger and instruction-boundary audit apply byte-for-byte to
these same helper hashes. The raw candidates are:

| PE | Raw candidates | Boundary result |
| --- | --- | --- |
| `Update.exe` | Four `0F 05` candidates at `0x0045C641`, `0x004E5B81`, `0x004E632B`, `0x005124D2`; two `0F 34` candidates at `0x0049828E`, `0x004F10C1` | Five are bytes in ordinary call displacements; `0x005124D2` crosses an `AND` immediate and following `ADD` opcode. No direct `syscall` or `sysenter` instruction identified. |
| `InitSetup.dll` | One `0F 34` candidate at `0x100045E0` | SIB/displacement bytes of `MOV BYTE PTR [EDI+ECX+0x34],DL`, not an instruction. |
| `uninstall.dll` | None | No raw `0F 05`, `0F 34`, or `CD 2E` candidate recorded. |

The imported-API inventory also records no `ntdll.dll` import or named `Nt*`/
`Zw*` import for these PEs. **For these exact user-mode images**, no direct
`syscall`, `sysenter`, or `int 2e` instruction was identified. This cannot
account for transitions inside Windows DLLs, COM servers, kernel drivers, or
other external components. The complete candidate evidence is in the
[4.06 syscall boundary report](rk-406-system-call-byte-audit.md) and
[raw candidate ledger](rk-native-syscall-byte-matches.csv).

## Package boundaries and remaining gaps

The 4.6 extracted application manifest has no `unins000.exe`; the separately
installed 4.06 uninstaller is therefore not evidence about a generated 4.6
uninstaller. The 4.6 installer metadata and callback-recovery limits are
documented in the [4.6 package report](rk-v4.6-package-snapshot.md). This
crosswalk also says nothing about other model-specific updater packages or
whether any static path runs on a connected keyboard.

**Proven statically:** the package file identities, imported API rows, and
the call/reference instruction addresses in the hash-pinned 4.06 audits for
the three byte-identical helpers. The seven raw syscall-like byte matches
above are not direct syscall instructions according to the recorded
instruction-boundary review.

**Unresolved:** the two updater ANSI-loader rows, full dynamic-call target
reachability, complete CFGs, installer-generated 4.6 uninstaller contents,
and any runtime branch or external component behavior. These helper findings
close only this package slice; they do not complete the broader RK suite
reverse engineering or establish firmware readback.
