# RK updater UART file API call-graph reconciliation

This note reconciles the stdio-style package parser with the conditional UART
response sink and the generic `CreateFileW` path. It adds a whole-`.text`
direct-call census and the parser's complete close-site list to the existing
[UART state map](rk-updater-uart-state-machine.md),
[file-sink audit](rk-uart-file-sink-reachability-audit.md), and
[file-open crosswalk](rk-uart-file-open-path-crosswalk.md).

## Exact image and method

The inspected x86 file is the installed
`C:\Program Files (x86)\RK Keyboard Software\Dev\01AF\Update.exe`,
2,109,952 bytes, SHA-256
`27894463b0dfe5bc3f5dc19d4d3351d9dfb692c402bf277bde3889d37e4a206c`.
The pinned analysis copy and installed file hash identically. The 4.6 package
manifest records the same path, size, and SHA-256, so these address-level
results apply to that bundled profile image as well. They do not establish
behavior for different updater hashes or every RK profile.

I disassembled the complete `.text` section with GNU `objdump` and repeated
the direct-call/reference census over decoded x86 instructions with Capstone.
The executable was not launched. No keyboard, HID, serial, GATT, or
bootloader I/O occurred. Addresses below are VAs in this exact image. The
census covers direct calls visible in `.text`; computed or externally
supplied call targets remain outside that proof.

## Direct stdio-style call census

| Target | Direct callsites in `.text` | Reconciled role |
| --- | --- | --- |
| `FUN_00536011` (open-like) | `0x0040A97A` | The `.upf` parser's only direct open-like call. |
| `FUN_00535EAC` (write-like) | `0x00408761`, `0x00408798`, `0x0040903D` | The two state-7 alternatives and the state-11 response sink; all use `0x005C5F30`. |
| `FUN_00535F9A` (close-like) | `0x004088C6`, `0x00408962`, `0x004089A7`, `0x004090F9`, `0x0040AA3F`, `0x0040AFD3`, `0x0040B003`, `0x0040B033`, `0x0040B08B` | Four UART sink closes and five parser-stream cleanup closes. |

For clarity, the exact close sites are:

| VA | Caller path | Stream argument evidence |
| --- | --- | --- |
| `0x004088C6` | UART state 7 | Pushes global `0x005C5F30`. |
| `0x00408962` | UART state 7 | Pushes global `0x005C5F30`. |
| `0x004089A7` | UART state 7 | Pushes global `0x005C5F30`. |
| `0x004090F9` | UART state 11 | Pushes global `0x005C5F30`. |
| `0x0040AA3F` | `.upf` parser, invalid package-marker path | Pushes local `EBX`, which received the opener result. |
| `0x0040AFD3` | `.upf` parser, mode 0 cleanup | Pushes local `EBX`. |
| `0x0040B003` | `.upf` parser, mode 1 cleanup | Pushes local `EBX`. |
| `0x0040B033` | `.upf` parser, mode 2 cleanup | Pushes local `EBX`. |
| `0x0040B08B` | `.upf` parser, mode 3 cleanup | Pushes local `EBX`. |

The opener at `0x0040A97A` receives the caller-supplied package path and
mode-string address `0x005942AC`; that string is exactly `r\0`. Its return
value moves from `EAX` to `EBX` at `0x0040A97F`. The parser's subsequent
read-like calls pass `EBX`. The five close sites above also pass `EBX`,
covering the marker-rejection exit and each of four parsed mode branches.
This is package input handling: it does not assign the returned stream to
`0x005C5F30`, which the direct-reference inventory shows only as an argument
to the UART write/close sites.

This refines the earlier crosswalk's parser description, which named the
`0x0040AA3F` close site but did not enumerate the four mode-specific cleanup
sites. It does not change the conclusion that the only recovered stdio-style
open is a read-only input open.

## `CreateFileW` output-looking candidate

The direct `CreateFileW` call at `0x00480B1D` is inside helper
`0x00480A60`. Its arguments decoded at the call are:

| Argument | Value | Static interpretation |
| --- | --- | --- |
| Path | Caller-supplied `EDI` | Generic file-object path. |
| Desired access | `0xC0000000` | `GENERIC_READ | GENERIC_WRITE`. |
| Share mode | `0` | No sharing flags. |
| Creation disposition | `2` | `CREATE_ALWAYS`. |
| Flags and attributes | `0x04000100` | `FILE_FLAG_DELETE_ON_CLOSE | FILE_ATTRIBUTE_TEMPORARY`. |
| Template handle | `0` | No template handle. |

The returned `HANDLE` is first held in a local and then stored into a generic
file-object field; it is not stored into the UART `FILE*` global. The
delete-on-close flag makes this callsite evidence of a temporary/generic file
object, not evidence of a persistent firmware-export destination.

A complete decoded direct-call scan found 18 calls to `0x00480A60`, at
`0x004CF550`, `0x004CFCE4`, `0x004CFD3C`, `0x004CFD92`, `0x004CFE0F`,
`0x004D056B`, `0x004D05D8`, `0x004D060D`, `0x004D086D`, `0x004D09D6`,
`0x004D0A86`, `0x004D0C01`, `0x004D161E`, `0x004D173D`, `0x004D1E18`,
`0x004D1ED7`, `0x004D220E`, and `0x004D23A9`. None is in the UART
state-handler region. The full direct-call scan found no direct call from the
UART handlers to this helper or to the sole `FUN_00536011` opener.

## Static indirect-reference boundary

The direct-call scan also checked unconditional relative jumps to the four
internal targets above; it found none. A raw whole-file search for absolute
little-endian VA entries for `0x00536011`, `0x00535EAC`, `0x00535F9A`, and
`0x00480A60` found no stored-pointer copies. The decoded calls are relative
`CALL` instructions, not function pointers in a static table. This narrows
the static caller inventory, but does not rule out a target computed at
runtime, a caller outside this image, or altered code/data.

## Reconciled finding and limits

**Proven for this exact image:** the only direct stdio-style opener is the
`.upf` parser's `"r"` open; its stream is held locally and closed on the
visible parser exits. The only direct write-like calls to
`FUN_00535EAC` are the three UART state-7/state-11 sites. Those use the
separate `0x005C5F30` global behind gate `0x005C5F12`. The generic
`CreateFileW` helper is called through a separate file-object path and marks
its created handle delete-on-close.

**Not established:** computed call targets or aliases, external callers,
runtime patching, whether an undocumented path changes the gate or stream
global, and whether a particular UART state is reachable from initialization.
The parser close-site expansion and `CreateFileW` argument decoding do not
resolve those gaps or demonstrate a complete firmware export.

For the direct global store/reference census and the state transition graph,
see the linked file-sink and state-machine audits.
