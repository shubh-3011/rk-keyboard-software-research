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

