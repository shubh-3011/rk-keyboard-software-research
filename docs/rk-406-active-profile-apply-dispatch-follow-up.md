# RK 4.06 active-profile Apply dispatch follow-up

## Scope and binary

This follow-up narrows the receiver gap in the
[semaphore-backed Apply audit](rk-settings-apply-worker-audit.md). It inspects
the installed RK 4.06 `DeviceDriver.exe` only, SHA-256
`C03F88BC4E2D78AA4392D7445B0FD62182DC824F97F5D5DB40BD009E547A9AB6`.
Evidence is static. The program was not launched, and no keyboard interface,
report, or command was used.

## Selected profile row and object construction

At `0x004465E0`, the code scans 0x12-byte records beginning at `0x006102A0`
and compares each record's first WORD to the current profile-code WORD at
`0x0061158E`. On a match, `EBP` points at the record (`0x00446605`–
`0x00446608`). The branch at `0x00446617` tests its WORD at `+0x0A`:

- Zero selects the constructor call at `0x00446632` to
  `CDevRKKB` initializer `0x00412FA0`.
- Nonzero selects the constructor call at `0x0044665E` to
  `CDevG5KB` initializer `0x0040ECB0`.

The field aligns with the `Fw` value in the extracted profile map; its semantic
name inside the binary is not independently recovered here. The created
object is wrapped as a list node by `0x004597D0`; the node's first pointer is
the inner device object. VID, PID, and the row's `+0x0A` value are copied to
that object at `0x0044668D`–`0x004466B3`. The node is stored to the active-root
global `0x0062B380` at `0x004466B9`. If the profile scan falls through, the
fallback at `0x004466C1` calls `0x00459830` and stores its returned list node
to the same global at `0x004466C8`.

## Apply signal and worker call arguments

The main Apply handler's path at `0x0040AE1D` calls `0x0040B3B0`, checks
`0x00611794`, then calls `0x00401080` with `EAX=1` at `0x0040AE32`. The
signal helper clears bit `0x8000` from the mask, stores the result at
`0x0061972C`, and calls the imported semaphore-release function with the
semaphore at `0x00619724`, release count `1`, and a null previous-count
pointer. This proves the host-side wake path for that handler; it does not by
itself identify which serializer the worker will choose.

On a semaphore wake, the worker at `0x00401170` loads `0x0062B380`, takes the
first pointer from that node, and invokes the resulting object's vtable slot
`+0x3C` at `0x004012A0`. At the call, `ESI` is the receiver (`this`). The
explicit arguments in callee stack order are the opaque global
`0x0062B388`, `EDI`, `[thread+0x10]` (initialized to `0x42B` in the observed
context setup), `[thread+0x0C]` (the shared Apply mask), and zero. `EDI` is
zero on the ordinary mask-1 path; a high-bit/special path can change it. The
parameter meanings and their runtime values are not recovered. In particular,
the name or meaning of `0x0062B388` remains unknown.

## Worker dispatch and S98 profile connection

The installed static profile map contains eight S98-labeled rows, all with
`fw_raw=1` and `static_handler=CDevG5KB`: `0174`, `01AF`, `01BF`, `0223`,
`0224`, `022B`, `022F`, and `0230`. For a selected one of those profile rows,
if this constructor path creates the active node, the worker's `+0x3C`
dispatch resolves through the `CDevG5KB` vtable to `FUN_00411B90`, the G5
settings orchestrator already mapped in the
[worker/vtable audit](rk-settings-apply-worker-audit.md). This is a
conditional static path; it is not evidence that the connected physical S98
was identified, that an Apply event ran, or that a particular report was
accepted.

The active-root global is mutable. A full `.text` disassembly scan found these
five direct absolute stores to `0x0062B380`:

| Address | Observed role |
| --- | --- |
| `0x004466B9` | Store the profile-selected wrapper constructed above. |
| `0x004466C8` | Store the fallback list node returned by `0x00459830`. |
| `0x0044792A` | Clear the root while removing the node held there. |
| `0x00465BC1` | Store a wrapper selected from the enumerated list. |
| `0x00465E13` | Store caller-provided `EAX`; its source/selection semantics remain opaque. |

The same direct-operand scan found 21 reads/compares at `0x0040109A`,
`0x004011E6`, `0x0040354D`, `0x00403660`, `0x004038B4`, `0x00404387`,
`0x0040B601`, `0x0040B7C1`, `0x0042251B`, `0x00422720`, `0x004228BF`,
`0x00439217`, `0x00439C54`, `0x004477DC`, `0x00457079`, `0x00458D46`,
`0x004593F5`, `0x00465568`, `0x00466471`, `0x004667D2`, and `0x0046D3AE`.
The hash-pinned verifier checks the bytes of all 26 listed instructions. This
is an inventory of direct references in this binary's decoded `.text`; it
does not cover computed pointers, data-table references, other versions, or
runtime state. The other nearby globals `0x0062B384` and `0x0062B388` are
separate addresses and are not included in this active-root reference count.
Consequently, profile construction alone does not establish the root object
active during every later Apply event.

## Conclusion and remaining gaps

The earlier unresolved worker receiver can now be narrowed: profile
construction conditionally creates either the RKKB or G5 class, and the
worker dispatches to that object's `+0x3C` method through the active list
node. For the eight S98 profile records in this installed catalog, the
conditional branch and vtable map indicate the G5 settings path. Still
unresolved are the physical device/profile match at runtime, competing active
root updates, the meaning of the call's context arguments, which UI event or
mask reaches each serializer branch, and the meaning or acceptance of the
resulting data by any physical keyboard.

The [hash-pinned verifier](../scripts/audit_rk406_active_profile_apply.py)
checks the PE bytes, the 26 direct active-root reference instructions, the G5
vtable slot, and the eight profile rows. It does not execute the software or
contact a keyboard.
