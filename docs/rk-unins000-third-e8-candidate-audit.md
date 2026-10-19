# `unins000.exe` third raw `E8` candidate audit

## Scope and target identity

This static follow-up resolves the third uninstaller executable-section
`E8` byte candidate listed in the [system API crosswalk](rk-system-api-crosswalk.md):
`0x004F4D04`. The target is the installed-package-matched 4.06
`unins000.exe`, 1,316,301 bytes, SHA-256
`b4ca28b192d5a50307d2b28f3323b58b39cb51edd6682e75706cac2dd69a4a14`.
The hash was revalidated before using these addresses. The executable was not
launched; no RK app, updater, HID interface, keyboard, or bootloader was
accessed.

## Instruction boundary and imported target

The candidate is in `.text` (VA range `0x00401000`–`0x004F6868`, raw file
offset `0x00000400`). Its file offset is `0x000F4104`, where the bytes are
`E8 FB 45 F1 FF`. Decoding from the surrounding handler-block entry at
`0x004F4D00` gives:

| VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x004F4D00` | `8B 40 18` | `mov eax, [eax+0x18]` |
| `0x004F4D03` | `50` | `push eax` |
| `0x004F4D04` | `E8 FB 45 F1 FF` | `call 0x00409304` |

The signed relative displacement is `-0x000EBA05`, so the call target is
`0x004F4D09 - 0x000EBA05 = 0x00409304`. That address is an import thunk in
`.text`; its instruction is `jmp dword ptr [0x00503FA4]`. The import ledger
maps IAT RVA `0x00103FA4` to `KERNEL32.dll!SetLastError`. Thus the byte
candidate is an actual instruction when decoded at the handler boundary,
and it calls the `SetLastError` import thunk.

The earlier linear sweep beginning before this block decodes the table bytes
as instructions and absorbs the `E8` byte into a preceding instruction's
displacement. That misaligned sweep is why the candidate was previously
described as an unvalidated data-like-region match.

## Owner function, exception table, and reachability

The owner function begins at `0x004F4C9C` (standard `push ebp; mov ebp,esp`
prologue) and is in the same `.text` section. Its recovered direct callers
are `0x004F4D82`, `0x004F54CD`, and `0x004F55B8`. In particular, caller
`0x004F4D82` is in the function beginning at `0x004F4D50`; that function
branches to `0x004F4EAB` when byte `[0x00502F44]` is nonzero, otherwise it
calls `0x004F4C9C`.

The call at `0x004F4D04` is on an exception-dispatch path, not the owner's
ordinary success path. The owner installs a second FS-based exception frame
at `0x004F4CBF`–`0x004F4CC8`, with handler address `0x004F4CEF`. The handler
is a relative jump to dispatcher `0x004047B4`. Its inline scope table is:

| VA | DWORD | Static role from the dispatcher access pattern |
| --- | ---: | --- |
| `0x004F4CF4` | `1` | One scope record |
| `0x004F4CF8` | `0x004A9B98` | Exception type descriptor pointer |
| `0x004F4CFC` | `0x004F4D00` | Scope action/landing address |

Dispatcher `0x004047B4` reads the record count at handler `+5`, starts records
at handler `+9`, examines each record's first DWORD as a type descriptor, and
advances by eight bytes per record (`0x004047FC`–`0x00404804` and
`0x0040483E`). On a matching type it preserves the matching record pointer,
calls the `RtlUnwind` function-pointer slot at `0x004FD018`, then transfers
through `[record+4]` at `0x00404911`. For this one-record table, that second
DWORD is `0x004F4D00`, the entry of the block containing the candidate call.

Therefore, **proven statically:** a caller can enter owner function
`0x004F4C9C`, and the function's exception dispatcher has an explicit
matching-scope route to `0x004F4D00`; the candidate `SetLastError` call is
reachable on that exceptional route. The normal path at `0x004F4CED` instead
jumps directly to `0x004F4D26`, skipping the handler data and action block.
Whether the owner is called in a particular run, whether an exception of the
matching type occurs, and what user operation raises it remain unresolved.

## Evidence boundary

- **Proven:** pinned file identity; candidate instruction boundary and
  relative target; target thunk and `SetLastError` import; owner function
  entry and three direct caller sites; one-entry exception-scope table; and
  dispatcher transfer through the table's action DWORD.
- **Inferred:** the entry at `0x004F4D00` is an exception action/landing block,
  based on its being the table's second DWORD and the dispatcher's
  eight-byte-record and `[record+4]` transfer behavior.
- **Unresolved:** the human-readable identity of type descriptor
  `0x004A9B98`, runtime exception occurrence, and runtime execution of
  `SetLastError` from this action.

This resolves the third raw candidate as a valid conditional import call.
The other two raw `E8` candidates remain the UTF-16 string-data matches
described in the crosswalk. No runtime uninstall path was exercised.
