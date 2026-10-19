# RK 4.06 native system-call byte-boundary audit

## Scope and evidence

This static follow-up rechecks every raw `syscall` (`0F 05`), `sysenter`
(`0F 34`), and `int 2e` (`CD 2E`) byte-pattern candidate in the five installed
4.06 package PEs. It uses their current installed identities, GNU
`objdump -d -M intel` instruction decoding, the
[raw-byte candidate ledger](rk-native-syscall-byte-matches.csv), and the
saved Ghidra classification for the two embedded lookup-table locations.

| PE | SHA-256 | Raw candidates |
| --- | --- | ---: |
| `DeviceDriver.exe` | `c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6` | 10 |
| `Dev/01AF/Update.exe` | `27894463b0dfe5bc3f5dc19d4d3351d9dfb692c402bf277bde3889d37e4a206c` | 6 |
| `InitSetup.dll` | `59db7bfd9a92cc9a0998260807f17c536ec71159b727df10d08b998bc94de301` | 1 |
| `Dev/01AF/uninstall.dll` | `9ca1ebc49998b8b2971debc1776e7aff6086aeb86adcca6cfb95e9fb399eb03c` | 0 |
| `unins000.exe` | `b4ca28b192d5a50307d2b28f3323b58b39cb51edd6682e75706cac2dd69a4a14` | 1 |

The RK application and updater were not launched. No device interface was
opened, and no keyboard, serial, firmware, or bootloader operation was
performed. **Proven statically** means the bytes and containing instruction
boundary are present in the hash-pinned PE. **Unresolved** means a byte scan
does not establish runtime execution or behavior in Windows, a kernel driver,
or an external COM/provider component.

## Candidate classification

| PE | Pattern VA | Containing instruction or data classification | Result |
| --- | ---: | --- | --- |
| `DeviceDriver.exe` | `0x0041E9FA` (`0F 05`) | `CALL` at `0x0041E9F8`, bytes `E8 09 0F 05 00`, target `0x0046F906`; match is in rel32 displacement. | Not an instruction. |
| `DeviceDriver.exe` | `0x00464224` (`0F 05`) | Embedded lookup-table data in saved Ghidra listing; surrounding bytes show a repeated `0F` pattern with sparse entries. | Data, not an instruction. Table purpose unresolved. |
| `DeviceDriver.exe` | `0x00464354` (`0F 05`) | Embedded lookup-table data in saved Ghidra listing; the neighboring table has the same sparse-byte pattern. | Data, not an instruction. Table purpose unresolved. |
| `DeviceDriver.exe` | `0x004E6445` (`0F 05`) | `0F` is the immediate byte of `AND EAX,0x0F` at `0x004E6443`; `05` begins `ADD EAX,0xEA00` at `0x004E6446`. | Crosses ordinary instruction bytes. |
| `DeviceDriver.exe` | `0x00501AE4` (`0F 05`) | `CALL` at `0x00501AE2`, bytes `E8 6F 0F 05 00`, target `0x00552A56`; match is in rel32 displacement. | Not an instruction. |
| `DeviceDriver.exe` | `0x00511FE8` (`0F 34`) | `CALL` at `0x00511FE7`, bytes `E8 0F 34 00 00`, target `0x005153FB`; match is in rel32 displacement. | Not an instruction. |
| `DeviceDriver.exe` | `0x00523045` (`0F 34`) | `CALL` at `0x00523044`, bytes `E8 0F 34 F5 FF`, target `0x00476458`; match is in rel32 displacement. | Not an instruction. |
| `DeviceDriver.exe` | `0x0052FE81` (`0F 34`) | `CALL` at `0x0052FE80`, bytes `E8 0F 34 F7 FF`, target `0x004A3294`; match is in rel32 displacement. | Not an instruction. |
| `DeviceDriver.exe` | `0x0057B790` (`0F 34`) | Part of `MOV BYTE PTR [EDI+ECX+0x34],DL` at `0x0057B78E`, encoding `88 54 0F 34`; match spans SIB/displacement bytes. | Not an instruction. |
| `DeviceDriver.exe` | `0x0058E82F` (`CD 2E`) | `JMP` at `0x0058E82E`, bytes `E9 CD 2E E7 FF`, target `0x00401700`; match is in rel32 displacement. | Not an instruction. |
| `InitSetup.dll` | `0x100045E0` (`0F 34`) | Part of `MOV BYTE PTR [EDI+ECX+0x34],DL` at `0x100045DE`, encoding `88 54 0F 34`; match spans SIB/displacement bytes. | Not an instruction. |
| `Update.exe` | `0x0045C641` (`0F 05`) | `CALL` at `0x0045C63F`, bytes `E8 86 0F 05 00`, target `0x004AD5CA`; match is in rel32 displacement. | Not an instruction. |
| `Update.exe` | `0x0049828E` (`0F 34`) | `CALL` at `0x0049828D`, bytes `E8 0F 34 00 00`, target `0x0049B6A1`; match is in rel32 displacement. | Not an instruction. |
| `Update.exe` | `0x004E5B81` (`0F 05`) | `CALL` at `0x004E5B7F`, bytes `E8 E0 0F 05 00`, target `0x00536B64`; match is in rel32 displacement. | Not an instruction. |
| `Update.exe` | `0x004E632B` (`0F 05`) | `CALL` at `0x004E6329`, bytes `E8 82 0F 05 00`, target `0x005372B0`; match is in rel32 displacement. | Not an instruction. |
| `Update.exe` | `0x004F10C1` (`0F 34`) | `CALL` at `0x004F10C0`, bytes `E8 0F 34 F4 FF`, target `0x004344D4`; match is in rel32 displacement. | Not an instruction. |
| `Update.exe` | `0x005124D2` (`0F 05`) | `0F` is immediate of `AND EAX,0x0F` at `0x005124D0`; `05` begins `ADD EAX,0xEA00` at `0x005124D3`. | Crosses ordinary instruction bytes. |
| `unins000.exe` | `0x0041A1DF` (`CD 2E`) | `JMP` at `0x0041A1DE`, bytes `E9 0F 05 00 00`, target `0x0041A6F2`; match is in rel32 displacement. | Not an instruction. |

The 18 raw matches reduce to two data-table locations and 16 matches inside
ordinary instruction encodings: 12 relative call/jump displacements, two
instruction-boundary crossings, and two SIB/displacement operands. The
separate `uninstall.dll` has no candidate row. The PE import inventory also
contains no `ntdll.dll` import and no imported API name beginning with `Nt` or
`Zw`.

## Conclusion and limits

**Supported for these five 4.06 PEs:** this pass found no direct
`syscall`, `sysenter`, or `int 2e` instruction at the inspected candidate
boundaries. The raw byte-pattern hits do not demonstrate inline system-call
wrappers in these images.

This does not account for system calls performed inside Windows DLLs, kernel
drivers, COM servers, or other external components. It is not a runtime trace,
does not establish reachability for all application code, and does not close
the remaining indirect-call and callback paths. The separately audited 4.6
driver has its own hash-pinned
[byte-boundary report](rk-v4.6-system-call-byte-audit.md); its addresses must
not be mixed with these 4.06 addresses.

The instructions were checked with GNU `objdump -d -M intel` around each
candidate. The raw offset, surrounding bytes, and existing linear-decoder
record are preserved in the
[candidate ledger](rk-native-syscall-byte-matches.csv).
