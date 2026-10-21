# 4.06 CDevG5 active-object caller scope

## Scope and evidence

This note follows one statically identified `CDevG5KB` construction path into
the application-wide active-object holder, then records the virtual slots used
by nearby decoded callers. The input is the installed 4.06
`C:\Program Files (x86)\RK Keyboard Software\DeviceDriver.exe`,
SHA-256 `C03F88BC4E2D78AA4392D7445B0FD62182DC824F97F5D5DB40BD009E547A9AB6`.
The executable was read and decoded with GNU `objdump -d -Mintel`; it was not
launched, and no device or HID interface was accessed.

Addresses below are virtual addresses in this exact PE. The evidence establishes
static instructions and data flow, not execution, selected runtime profile,
device acceptance, or physical behavior.

## Constructor to holder to global

At `0x0044665E`, a conditional branch allocates `0x2E0` bytes and calls the
constructor at `0x0040ECB0`. That constructor installs the `CDevG5KB` vtable
address point `0x005CBA2C` at `0x0040ECE3` (`mov dword ptr [esi],0x5cba2c`).
The RTTI-backed vtable identity and 27-slot extent are documented in the
[G5 vtable audit](rk-406-cdevg5-vtable-audit.md).

The caller then passes the address of its temporary object pointer to
`0x004597D0` at `0x0044667A`. In this wrapper, `0x004597D9` allocates four
bytes; `0x004597EA` loads the pointee from the argument; and `0x004597F2`
stores it at `[edi]`, where `edi` is the new holder. On success, the wrapper
returns that holder in `eax` at `0x00459824`.

Back in the caller, `edi` receives the wrapper result at `0x00446686`.
Instructions `0x0044668D`–`0x004466B3` dereference `[edi]` to update fields on
the contained device object. `0x004466B9` stores `edi` at global
`0x0062B380`. This proves that this constructor branch can place a holder for
a `CDevG5KB` object in the global. It does not prove that the global always
contains G5; other construction/replacement branches exist.

## Decoded dispatches through this global holder

The following callsites load `0x0062B380`, dereference the holder to obtain the
device object, load its vtable, and dispatch the listed slot:

| Global read | Indirect call | Slot | G5 table target | Method evidence |
| --- | --- | --- | --- | --- |
| `0x0040109A` | `0x004010B0` | `+0x28` | `0x0040F6D0` | Checks the direct handle and, when absent, delegates to a child object's `+0x14`; exact higher-level predicate meaning is unresolved. |
| `0x0040354D` | `0x00403568` | `+0x14` | `0x0040EFE0` | Returns the DWORD at `this+4`, the primary handle field. |
| `0x00404387` | `0x004043A3` | `+0x14` | `0x0040EFE0` | Same primary-handle getter. |
| `0x0046D3AE` | `0x0046D3BE` | `+0x28` | `0x0040F6D0` | Same child/handle predicate method. |

The targets and method descriptions are corroborated by the row-level
[27-slot vtable ledger](rk-406-cdevg5-vtable-map.csv). These four dispatches
do not call the G5 `+0x68` `GetRealData` slot at `0x00410700`.

## Additional selected-entry setter path

A second static path writes the same global from a selected list entry in
`0x00465A20`. The caller scans ten dialog child records at stride `0x184`,
comparing the incoming value at `[ebp+0x0C]` with each record's child ID at
`+0x20` (`0x00465B17`–`0x00465B2D`). The matching ordinal in `EBX` selects a
node from the list rooted at `0x00603554`; the alternate branch starts from
`0x0060356C` and subtracts the list base/count field at `0x0060354C`
(`0x00465B33`–`0x00465B81`). The selected list node's first DWORD is loaded
into `ESI`, and the following dereference `[ESI]` yields the device object
(`0x00465B81`–`0x00465B89`).

When the selected object exists, the setter applies several object-field
checks (`+0x268`, `+0x24C`, `+0x254`) and may dispatch virtual slot `+0x2C`
(`0x00465B8D`–`0x00465BB9`). The 4.06 G5 vtable maps that slot to
`0x00410640`, a direct-handle/child predicate whose higher-level meaning is
unresolved. The branch reaching `0x00465BBF` stores the selected holder `ESI`
at global `0x0062B380` (`0x00465BC1`) and calls `0x00465830` with the matching
ordinal and dialog pointer. The helper iterates ten stride-`0x184` records and
conditionally clears a field/calls an imported function; its broader UI or
resource semantics are not established here.

This proves an additional selected-entry assignment to the active-holder
global, but it does not identify the dialog's user-facing feature, prove that
the selected list is populated by the profile routine at `0x00415900`, or
establish the concrete object family chosen at runtime. The instruction at
`0x00465BC1` stores the holder, not the bare device object. These limitations
also mean this path does not close the `GetRealData` caller/buffer-consumer
question.

## Direct active-root cross-check for `+0x68`

The hash-pinned [active-profile Apply follow-up](rk-406-active-profile-apply-dispatch-follow-up.md)
enumerates 21 direct read/compare references and five stores to
`0x0062B380`; its verifier checks each listed instruction's bytes against the
same 4.06 image. I rechecked the 21 read/compare sites for a local `+0x68`
method load. For each site, the bounded interval was the decoded linear
instruction sequence beginning at that reference and ending at the first
decoded `RET`. No non-stack `[register+0x68]` load appeared in those intervals,
and the full decoded `.text` contains no direct call to `0x00410700`.

This is a bounded cross-check, not recovered control-flow graphs or proof that
all aliases of the active object were found. A branch that skips a linear
`RET`, a pointer passed to another routine, or an alternate indirect-call
shape may escape this interval check. Combined with the separately documented
decoded-callsite sweep, it adds no attributable `CDevG5KB +0x68` caller and no
return-buffer consumer. The `0x88` helper's caller and downstream use of its
copied bytes therefore remain unresolved; a complete firmware export is not
established.

## Negative-result boundary

This is a bounded caller-scope result. The search used decoded `.text` from
the hash-pinned image and inspected the direct global-holder/dereference/vtable
dispatch patterns at the callsites above. Those uses dispatch `+0x14` or
`+0x28`; no `+0x68` dispatch was identified in this traced global-holder path.
The broader `+0x68` candidate census, false-positive exclusions, and
unresolved caller/buffer-consumer status are in the
[GetRealData audit](rk-406-cdevg5-vtable-audit.md).

The search does not prove that no `GetRealData` caller exists. It does not
exhaust all object aliases, copied pointers, callbacks, alternate dispatch
shapes, selected-profile paths, or runtime-generated references. Accordingly,
the command-`0x88` helper's caller, selector/range, returned-data meaning, and
downstream buffer consumer remain unresolved; this finding does not establish
firmware extraction or a complete firmware backup path.

