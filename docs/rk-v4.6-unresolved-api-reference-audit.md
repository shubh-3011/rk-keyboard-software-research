# RK 4.6 DeviceDriver unresolved import-reference follow-up

## Scope and safety

This follow-up checks only the 16 `DeviceDriver.exe` import rows marked
`none_decoded` by the existing direct/thunk/register scan. The examined file is
the 4.6-labeled package's `app/DeviceDriver.exe`, 2,418,176 bytes, SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`.
The hash was verified locally before examining the matching disassembly.

The executable was not run. No HID interface, serial port, firmware path,
updater, or bootloader was opened or used. This is a static reference audit;
it does not establish that any containing function is reachable in a live
session or that an API succeeds.

The machine-readable results are in
[`rk-v4.6-unresolved-api-references.csv`](rk-v4.6-unresolved-api-references.csv).

## Method

For each unresolved IAT VA, I searched the exact binary for its four-byte
little-endian absolute address, then checked the corresponding GNU objdump
instruction and surrounding sequence. Each of the 16 IAT values has exactly
one raw byte occurrence in the image, and each occurrence decodes as a
`mov reg,[IAT]` load in executable code. The loaded register is then used by
one or more `call reg` instructions. The paths use preserved x86 registers
(`EBX`, `ESI`, or `EDI`); several calls follow conditional/unconditional
branches or loop edges and so were not found by the previous
same-straight-line-block heuristic.

## Recovered references

The follow-up recovers all 16 rows as static register-indirect call candidates,
with 31 call instruction sites total:

| Import | IAT load | Register | `call reg` sites |
| --- | ---: | --- | --- |
| `USER32!CharNextW` | `0x004B29A7` | EBX | `0x004B29B0`, `0x004B29D2` |
| `GDI32!RestoreDC` | `0x004783CE` | EDI | `0x004783DD`, `0x004783EE` |
| `GDI32!SetBkMode` | `0x00478442` | EDI | `0x00478451`, `0x0047845E` |
| `GDI32!SetPolyFillMode` | `0x00478474` | EDI | `0x00478483`, `0x00478490` |
| `GDI32!SetROP2` | `0x004784A6` | EDI | `0x004784B5`, `0x004784C2` |
| `GDI32!ExcludeClipRect` | `0x0047854A` | EBX | `0x0047856D`, `0x00478582` |
| `GDI32!SetTextAlign` | `0x00478619` | EDI | `0x00478628`, `0x00478635` |
| `GDI32!SelectClipRgn` | `0x00478B7A` | EDI | `0x00478B8E`, `0x00478BA4` |
| `GDI32!OffsetViewportOrgEx` | `0x004789A3` | EDI | `0x004789B8`, `0x004789CB` |
| `GDI32!ScaleViewportExtEx` | `0x00478A21` | EDI | `0x00478A3C`, `0x00478A55` |
| `GDI32!OffsetWindowOrgEx` | `0x00478AAB` | EDI | `0x00478AC0`, `0x00478AD3` |
| `GDI32!ScaleWindowExtEx` | `0x00478B29` | EDI | `0x00478B44`, `0x00478B5D` |
| `GDI32!ExtSelectClipRgn` | `0x00478C80` | EDI | `0x00478C97`, `0x00478CB0` |
| `GDI32!SaveDC` | `0x00478398` | EDI | `0x004783A3`, `0x004783B0` |
| `ADVAPI32!RegEnumKeyExW` | `0x004ACF65` | EBX | `0x004ACFAC` |
| `WINMM!PlaySoundW` | `0x005155BD` | ESI | `0x005155E4`, `0x00515603` |

The grouped GDI sites lie in a contiguous set of small wrappers that load one
GDI import into `EDI` or `EBX`, forward object fields and stack arguments, and
call through that register. This is consistent with GDI device-context/state
helpers (**inferred**); exact class names and which UI operations reach them
were not established here.

`CharNextW` is loaded into `EBX` at `0x004B29A7`; an unconditional jump reaches
a shared loop block, which calls through `EBX` at `0x004B29B0` and, on a later
branch, at `0x004B29D2`. The surrounding instructions process wide characters,
so character-navigation/string parsing is a likely role (**inferred**).

`RegEnumKeyExW` is loaded into `EBX` at `0x004ACF65`. A branch reaches a shared
argument-setup block and calls through `EBX` at `0x004ACFAC`; the return value
feeds a loop condition. This supports a registry-key enumeration call path,
but the exact key and purpose are unresolved.

`PlaySoundW` is loaded into `ESI` at `0x005155BD` and called at
`0x005155E4` and `0x00515603` along branches in the same routine. This supports
two possible sound-playback calls in code; the trigger, sound identities, and
runtime reachability remain unresolved.

## Conclusion and limits

The prior 16-row `none_decoded` set is now statically mapped to 16 IAT-register
loads and 31 indirect call instructions in this exact 4.6 executable. These
are decoded transfer candidates, not runtime call counts. They do not close
full control-flow reachability, dynamic callback/COM targets, UI-to-handler
mapping, per-model behavior, or the broader reverse-engineering goal. No
firmware readback or keyboard write capability is established by this audit.
