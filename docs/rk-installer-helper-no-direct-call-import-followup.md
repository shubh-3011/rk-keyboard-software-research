# Installer helper no-direct-call import follow-up

This note resolves the five `InitSetup.dll` and `uninstall.dll` rows in the
[native API callsite-gap inventory](rk-native-api-callsite-gaps.csv) that have
no recovered direct `call [IAT]` or relative call to an import thunk. It checks
whether the import references instead participate in register-indirect calls
or an imported-data access. The source is the same RK 4.6 package snapshot
listed in the [native API indirect-call audit](rk-native-api-indirect-call-audit.md)
and [4.6 package snapshot](rk-v4.6-package-snapshot.md).

## Inputs and method

The two analysis copies and the matching files in the package extraction have
these SHA-256 values and sizes:

| PE | Size | SHA-256 |
| --- | ---: | --- |
| `InitSetup.dll` | 69,000 bytes | `59db7bfd9a92cc9a0998260807f17c536ec71159b727df10d08b998bc94de301` |
| `uninstall.dll` | 146,944 bytes | `9ca1ebc49998b8b2971debc1776e7aff6086aeb86adcca6cfb95e9fb399eb03c` |

For each row, the audit checked the IAT slot, scanned the complete file for
little-endian references to that slot's image address, mapped matches to PE
sections, and decoded the containing x86 instructions. The instruction
addresses and register flow below were checked against the exact hash-pinned
bytes. The broader direct-call and register-indirect-call census remains in
[`rk-native-api-indirect-call-audit.md`](rk-native-api-indirect-call-audit.md).

## Evidence and classification

| Import | IAT RVA | `.text` reference operand(s) | Decoded use | Classification |
| --- | ---: | --- | --- | --- |
| `InitSetup.dll!KERNEL32.DeleteFileW` | `0xB010` | `0x100011F0` | Instruction `0x100011EE` loads the IAT value into `EDI`; `call EDI` at `0x10001273`. | Register-indirect function call. The surrounding recursive file-enumeration path sets attributes, then calls this target for a selected file. |
| `InitSetup.dll!KERNEL32.GetEnvironmentStringsW` | `0xB098` | `0x10003A1B` | Instruction `0x10003A19` loads the IAT value into `ESI`; `call ESI` at `0x10003A28` and `0x10003A63`. | Two register-indirect function calls in the wide-environment parsing path. The block is later released through the separate `FreeEnvironmentStringsW` IAT call at `0x10003AD6`. |
| `uninstall.dll!MSVCR90._adjust_fdiv` | `0x2054` | `0x10001088` | Instruction `0x10001086` loads the IAT value, `0x1000108C` dereferences it, and `0x10001091` stores the result at global `0x1000334C`. | Imported data reference; no call through this import was recovered. |
| `uninstall.dll!MSVCR90._decode_pointer` | `0x2064` | `0x100011D5`, `0x100014EB` | The IAT value is loaded into `ESI` at `0x100011D3` and `0x100014E9`. Calls through `ESI` occur at `0x100011D9`, `0x100011ED`, `0x10001214`, `0x1000122A`, `0x10001235`, `0x100014EF`, `0x10001518`, and `0x10001523`. | Register-indirect function calls in the runtime pointer-table path. In that path, a separately decoded entry is invoked indirectly at `0x10001221`; that is callback-table processing, not an invocation of `_decode_pointer` as a callback. |
| `uninstall.dll!KERNEL32.InterlockedCompareExchange` | `0x2024` | `0x100010A9`, `0x10001189` | The IAT value is loaded into `ESI` at `0x100010A7` and `0x10001187`; calls through `ESI` occur at `0x100010D2` and `0x100011A7`. Both calls pass the address `0x10003354`, the current thread ID, and zero. | Register-indirect function calls in a retry/ownership path. The code compares the return value with the current thread ID and has a 1,000 ms sleep on retry; the exact higher-level caller/runtime scenario is not established here. |

For the first four function imports, the import target is reached by an
indirect call through a register populated from the corresponding IAT slot.
These are not unresolved imports merely because the direct-call census has no
`call [IAT]` or relative import-thunk edge. `_adjust_fdiv` is different: the
observed use is an imported value read and stored in process state, not a
function transfer. The existing cross-reference ledger records one or two
IAT references per row and agrees with the instruction evidence above.

## Limits

This resolves the static reference type for these five imports in the two
hash-pinned files. It does not prove a branch is reachable, that any API ran,
or which process loads the helper DLLs at runtime. The callback-table
interpretation for `_decode_pointer` is supported by the local table walk and
indirect invocation, but the runtime engine's dispatch conditions remain
unobserved. No binary was launched, and this analysis opened no HID interface
and sent no device report or command.
