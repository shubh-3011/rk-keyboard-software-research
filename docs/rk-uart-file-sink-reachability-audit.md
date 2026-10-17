# RK updater UART file-sink reachability audit

This focused note checks direct references to the UART response-to-file gate
and stream pointer in the installed x86 `Dev/01AF/Update.exe`. It supplements
the state/protocol analysis in
[`rk-updater-uart-state-machine.md`](rk-updater-uart-state-machine.md) with
an exhaustive direct-reference inventory and PE-section evidence. It does
not establish an executable firmware-export workflow.

## Scope and method

The inspected file is `C:\Program Files (x86)\RK Keyboard Software\Dev\01AF\Update.exe`,
2,109,952 bytes, SHA-256
`27894463b0dfe5bc3f5dc19d4d3351d9dfb692c402bf277bde3889d37e4a206c`.
That hash matches the updater analyzed in the related reports. I inspected
its PE section map with `pefile` and its full x86 `.text` disassembly with
`objdump -d -Mintel`, then enumerated absolute operands referencing the gate,
stream pointer, UART state, and nearby globals. No executable was launched;
no serial, HID, keyboard, or bootloader I/O occurred.

Addresses below are VAs in this exact image. **Direct reference** means an
instruction whose decoded absolute memory operand names the given address;
it does not include a possible computed alias, runtime patch, injected code,
or undocumented external caller.

## Gate `DAT_005C5F12`

The byte at `0x005C5F12` is tested by the diagnostic path and the two UART
response handlers. The full disassembly contains one direct store to this
byte, an assignment of zero at `0x004071BB`; all other direct references are
comparisons:

| VA | Instruction role |
| --- | --- |
| `0x0040424D` | Compare gate with zero in `FUN_00404220`, the diagnostic formatter. |
| `0x004071BB` | Store byte value `0` during the updater initialization path. |
| `0x00408744`, `0x0040877D` | State-7 branches that skip the stream-write call when zero. |
| `0x004088B7`, `0x00408953`, `0x00408998` | State-7 completion/error branches that skip close when zero. |
| `0x00408FF8`, `0x00409010`, `0x00409026` | State-11 branches that skip the stream-write call when zero. |
| `0x004090EA` | State-11 completion branch that skips close when zero. |

The nearest direct references were also checked for overlapping writes. The
DWORD at `0x005C5F0C` ends at byte `0x005C5F0F`; `0x005C5F10` is read as a
WORD at `0x004020B6`; bytes `0x005C5F10` and `0x005C5F11` are stored
individually at `0x0040AD17` and `0x0040AD1C`; and byte `0x005C5F13` has
separate state-handler stores at `0x00408978`, `0x004089BD`, and
`0x00409936`. Those decoded direct stores do not overlap the gate byte at
`0x005C5F12`.

**Finding (high confidence for direct references):** no nonzero direct setter
for `0x005C5F12` exists in the inspected `.text`. Its sole direct assignment
sets it to zero. This does not prove no computed alias or runtime alteration
can affect it.

## Stream pointer `0x005C5F30`

The full disassembly has these nine direct references to the stream global:

| VA | Decoded use |
| --- | --- |
| `0x00408753`, `0x00408786` | Push the stream value before state-7 calls to `FUN_00535EAC` at `0x00408761` and `0x00408798`. |
| `0x004088C0`, `0x0040895C`, `0x004089A1` | Push the stream value before state-7 calls to close-like `FUN_00535F9A` at `0x004088C6`, `0x00408962`, and `0x004089A7`. |
| `0x00409007`, `0x00409019`, `0x0040902F` | Push the stream value before state-11's conditional call to `FUN_00535EAC` at `0x0040903D`. These are mutually selected count branches. |
| `0x004090F3` | Push the stream value before state-11's conditional close-like call at `0x004090F9`. |

There is no direct store to `0x005C5F30`, no direct reference that takes its
address for an initializer, and no direct file-open callsite that names this
global. The three `FUN_00535EAC` call instructions are the only direct calls
to that wrapper from the UART handlers. They are dominated by checks of the
zero-initialized gate. The close-like calls have the same gate checks.

## PE initialization and activation

In this image, `.data` starts at VA `0x005B3000`, has virtual size `0x15200`,
and has only `0xCA00` raw bytes. Both `0x005C5F12` (offset `0x12F12` within
the section) and `0x005C5F30` (offset `0x12F30`) lie beyond the raw-data
extent but inside the virtual section. The PE loader therefore zero-fills
these locations from the section's virtual tail. The explicit initialization
store to the gate at `0x004071BB` is consistent with that image state. No
stream initialization, filename derivation, or open-to-stream assignment is
visible through direct references.

This is not a claim that `Update.exe` has no file APIs. Its import crosswalk
lists eleven `CreateFileW` direct callsites, including the serial `CreateFileW`
call at `0x00404F09`; the static references inspected here do not tie those
handles to `0x005C5F30`. Similarly, generic file-wrapper methods elsewhere in
the updater do not by themselves initialize this stream global.

## Relation to direct UART state reachability

The state global `0x005C5F58` is set to zero at `0x00407231`. The direct-store
inventory in the companion state-machine report places state 7 behind the
state-3/4/6/7 transfer subgraph, and states 10/11 in a closed two-state
cycle. It identifies no direct transition from initialization/state 0 into
either sink-bearing path. This note independently verified the gate and
stream operands but does not repeat the full transition analysis.

## Conclusion and confidence limits

**Proven from the inspected image:** it contains conditional UART
response-to-stream calls in states 7 and 11; the sole direct assignment to
their gate is zero; the stream global lies in the zero-filled `.data` tail;
and the direct transition map has no entry from initialized state 0 into the
sink-bearing state paths.

**Not established:** any complete firmware image read, the identity of the
UART target or address range, a direct nonzero gate setter, stream/file-name
setup, or a reachable route that activates the sink. A computed global alias,
indirect callback path, runtime code modification, or external process/thread
intervention cannot be disproved by this direct-reference audit. Those
possibilities are unresolved, not evidence that an export feature works.

Accordingly, **a complete read-only firmware export for the connected RK S98
is not established**. Do not try to resolve the gap by running the updater,
opening HID/serial, sending commands, or entering bootloader mode. For the
broader protocol and device-identity limits, see
[`rk-firmware-readback-audit.md`](rk-firmware-readback-audit.md) and
[`rk-uart-firmware-path-semantics-audit.md`](rk-uart-firmware-path-semantics-audit.md).
