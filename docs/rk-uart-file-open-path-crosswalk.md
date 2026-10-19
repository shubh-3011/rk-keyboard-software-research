# RK 4.06 UART sink and file-open path crosswalk

This note cross-checks whether the conditional UART response sink in the
installed `Dev/01AF/Update.exe` has a static host-file open/setup path. It
supplements the [firmware readback audit](rk-firmware-readback-audit.md),
[UART state-machine map](rk-updater-uart-state-machine.md), and [file-sink
reachability audit](rk-uart-file-sink-reachability-audit.md).

The inspected executable is
`C:\Program Files (x86)\RK Keyboard Software\Dev\01AF\Update.exe`,
2,109,952 bytes, SHA-256
`27894463b0dfe5bc3f5dc19d4d3351d9dfb692c402bf277bde3889d37e4a206c`.
Only the installed image was read. No RK program or updater was launched;
no keyboard HID, serial, GATT, or bootloader I/O was performed.

**Proven** below means directly present in the image or decoded instructions;
**inferred** means supported by static call/data flow but not runtime-tested;
**unresolved** marks what this audit cannot decide.

## Absolute-reference rescan

The PE `.data` section has VA `0x005B3000`, virtual size `0x15200`, and raw
size `0xCA00`. The UART gate `0x005C5F12`, stream pointer `0x005C5F30`,
state `0x005C5F58`, total length `0x005C5F54`, and offset `0x005C5F2C` are
all inside the zero-filled virtual tail. A raw whole-file scan for each
little-endian VA, cross-checked against the complete `objdump -d -Mintel`
listing, found these occurrences:

| Target VA | Raw occurrences | Section distribution | Direct code roles |
| --- | ---: | --- | --- |
| Gate `0x005C5F12` | 11 | 11 `.text`; none in other sections | One zero store at `0x004071BB`; ten comparisons in diagnostics and state 7/11. |
| Stream `0x005C5F30` | 9 | 9 `.text`; none in other sections | Nine loads passed to the state 7/11 write/close wrappers; no store or address-take. |
| State `0x005C5F58` | 11 | 11 `.text`; none in other sections | One dispatcher read and ten direct stores, including initialization to zero. |
| Total length `0x005C5F54` | 13 | 13 `.text`; none in other sections | Reads only; no direct initialization store. |
| Offset `0x005C5F2C` | 6 | 6 `.text`; none in other sections | Reads and two `+0x1000` updates; no direct initialization store. |

The scan also found 16 occurrences of block-index global `0x005C5F48` and
five occurrences of buffer pointer global `0x005C6F8C`; these were likewise
all in `.text`. For the listed addresses, the raw scan found no encoded
pointer in `.rdata`, `.data`, resources, or relocation data that could serve
as a static indirect reference. The executable can still compute an alias at
runtime, so this does not rule out every possible indirect write.

The decoded gate references match the earlier exact inventory: diagnostic
comparison at `0x0040424D`, zero store at `0x004071BB`, state-7 branches at
`0x00408744`/`0x0040877D` and completion branches at `0x004088B7`,
`0x00408953`, `0x00408998`; state-11 branches at `0x00408FF8`,
`0x00409010`, `0x00409026`, and completion at `0x004090EA`. No direct
nonzero store was found.

## File streams and the UART sink

**Proven:** the sole direct call in `.text` to the stdio-style opener at
`0x00536011` is from `.upf` parser `FUN_0040A940`, at `0x0040A97A`. It passes
the selected input path and a string at `0x005942AC` whose exact bytes are
`r\0`. The returned stream is kept in local `EBX`; the parser makes reads
through `FUN_0053652B` and closes that local stream through
`FUN_00535F9A` at `0x0040AA3F`, `0x0040AFD3`, `0x0040B003`, `0x0040B033`,
or `0x0040B08B`, depending on the parser path. These are package-input
cleanup paths, not a firmware file opened for output. The complete direct
stdio caller census is in the [file API call-graph reconciliation](rk-uart-file-api-callgraph-reconciliation.md).

**Proven:** all three application-level calls to fwrite-like
`FUN_00535EAC` are in the UART response handlers: `0x00408761` and
`0x00408798` in state 7, and `0x0040903D` in state 11. They pass
`0x005C5F30` as the stream. The corresponding close-like calls are also in
states 7/11 and use that same pointer. The pointer is only read at these
sites; no direct setup, open, filename, or assignment path to it is present.

The stream sink is therefore a real conditional `fwrite` path in the binary,
but the image provides neither a proven open stream nor an enabled direct
gate. With the PE zero-fill and initialization store, the statically
established state has gate zero and stream pointer zero. The earlier state
map also finds no direct edge from initialized state 0 into either the
state-7 subgraph or the state-10/11 cycle.

## Imported and late-bound open paths

The import crosswalk and the exact disassembly contain 11 direct
`CreateFileW` calls. Their visible argument/use patterns group as follows:

| Callsite(s) | Static interpretation |
| --- | --- |
| `0x00404F09` | Opens the configured serial path with read/write access, `OPEN_EXISTING`, and overlapped I/O; the returned handle is stored in serial-object state. |
| `0x00406803`, `0x004069CA`, `0x00409B9D`, `0x0040D100` | Open paths held at device-object `+4`, with read/write access, shared access, `OPEN_EXISTING`, and overlapped I/O. The surrounding code performs device capability checks. These are device-handle paths, not host output-file setup. |
| `0x00431A8F`, `0x00431DBF` | Generic MFC-style file-object open paths. The latter stores the returned Windows handle in object field `[esi+4]` and marks object state; it does not store into `0x005C5F30`. |
| `0x00455F31` | Opens a caller path read-only with `OPEN_EXISTING`. |
| `0x00480B1D` | Opens a caller path with read/write access and `CREATE_ALWAYS`; its purpose is not identified here. Its handle is local/object state, with no direct reference to the UART stream global. |
| `0x0054A735` | Generic argument-forwarding `CreateFileW` wrapper; the specific caller path is unresolved. |
| `0x0054D221` | Opens the literal `CONOUT$` with write access for console output. |

Two additional file-open names are resolved dynamically in generic wrappers:
`CreateFileTransactedW` at `0x00431A50` and `CreateFile2` at `0x0054A6D7`.
Their function pointers are invoked by wrapper code, but no target-global
reference or UART-handler call path was recovered. The import table does not
name `fopen`; the identified stdio-style opener is statically linked at
`0x00536011` as described above.

The `WriteFile` import has nine direct callsites:
`0x0040572A`, `0x00431F9C`, `0x0053D5BC`, `0x00541FF3`, `0x00542052`,
`0x0054222C`, `0x00542341`, `0x00542480`, and `0x00542502`. The first is in
the serial worker; `0x00431F9C` writes using a generic file object's handle.
The later sites are in the statically linked runtime, which is also used by
stdio. This is consistent with the UART sink eventually using ordinary file
I/O if supplied a valid stream, but no analyzed call or initialization path
connects those generic file handles to the UART stream global.

## Assessment

**Proven:** this exact image contains state-7/state-11 conditional stdio
writes, a gate directly initialized to zero, a stream pointer in zero-filled
data with no direct initializer, and a read-only `"r"` stream open in the
separate `.upf` parser. The state transition table has no direct entry from
the initialized state into states 7 or 10/11.

**Inferred:** the UART code may be incomplete or dormant file-export logic.
The generic `CREATE_ALWAYS` path is a host-file creation path, but its static
handle/object flow is separate from the UART `FILE*` global. No complete
readback-to-host-file path is established.

**Unresolved:** computed aliases, indirect callbacks or writes, code outside
this exact updater image, runtime patching, the UART protocol/target, and
whether external state can activate the closed state subgraphs. These gaps
are not evidence that a backup feature works. The firmware-readback question
remains unanswered positively; resolving it must not involve running the
updater, opening keyboard HID, sending reports or serial commands, or entering
bootloader mode.
