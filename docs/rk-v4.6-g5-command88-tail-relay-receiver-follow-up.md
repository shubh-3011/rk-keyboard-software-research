# V4.6 command-0x88 tail-relay receiver follow-up

## Scope and pinned input

This is a static-only follow-up for the 0x004EDD8D tail relay and its eight
direct callsites in the V4.6 DeviceDriver.exe. The input is the extracted
image at
C:\Users\shubh\Downloads\sshorcale\.research\rk4_6_official_extract_20261015\app\DeviceDriver.exe,
size 2,418,176 bytes, SHA-256
8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9.
Addresses are preferred-base x86 VAs. The executable was read as PE bytes
and disassembly only. No device interface was opened, no report was sent,
and no keyboard data was read.

The standalone verifier and evidence ledger are
[audit_rk46_g5_cmd88_relay_receivers.py](../scripts/audit_rk46_g5_cmd88_relay_receivers.py)
and [rk-v4.6-g5-command88-tail-relay-evidence.csv](rk-v4.6-g5-command88-tail-relay-evidence.csv).
From the repository root, run:

    python scripts/audit_rk46_g5_cmd88_relay_receivers.py ..\.research\rk4_6_official_extract_20261015\app\DeviceDriver.exe

The verifier checks the PE hash/architecture, the exact eight direct call
addresses, caller prologue/call instruction bytes, and the class,
constructor, field, and vtable entries used below. It does not execute the
PE or prove runtime reachability.

**Receiver correction:** a later direct-caller review resolves the receiver
class at `0x004A5CD6` and the known relay-capable path to `0x004A64D5` as
`CPaneDivider`-compatible. See the
[receiver-type correction](rk-v4.6-g5-command88-receiver-type-corrections-2026-10-25.md)
and its hash-pinned [verifier](../scripts/audit_rk46_g5_cmd88_receiver_type_corrections.py).

## Relay contract

At 0x004EDD8D, the helper reads [ECX+0x138]. A null field branches to
0x004EDDA1, returns EAX=0, and uses plain ret. Otherwise it loads the
nested object's vptr and tail-jumps through [vptr+0x70] at 0x004EDD9E.
The tail jump preserves the caller's return address and stack.

The G5 CDevG5KB wrapper at 0x00411030 consumes two caller stack arguments
and ends with ret 8; it is installed at G5 vtable slot +0x70. None of the
eight direct callers pushes an output-buffer/length pair immediately before
the relay call. Their active frame or saved-register words remain under the
call. This caller-side shape does not establish a G5 read; in particular, the
five callers with typed CPaneDivider receivers below resolve the relay's
+0x138 member through a CPaneContainerManager type check.

## [this+0x138] owner and initialization evidence

The MFC runtime-class record at 0x005B4F40 names CPaneDivider, declares
size 0x13C, points to constructor thunk 0x004EE783, and names CBasePane at
0x005B8DB4 as its base descriptor. The constructor thunk allocates 0x13C
bytes and calls 0x004EE0F6; that constructor installs vptr 0x005B4F64 at
this+0 and calls initializer 0x004EDC17. The initializer sets
[this+0x138] to zero at 0x004EDC52. The member is the last four-byte field
within the declared object size.

The CPaneDivider vtable address point is 0x005B4F64. Its entry at
0x005B51E4 (slot +0x280) points to method 0x004EE952. This method sets
ESI=ECX, obtains a candidate through 0x0048BF28, passes runtime class
record 0x005BB590 to 0x0048BFBB, then stores the returned pointer or null
into [ESI+0x138] at 0x004EE9D6.

Helper 0x0048BFBB is an MFC-style runtime-class filter: it calls the
object's slot-zero IsKindOf method with the requested class descriptor and
returns the input object only when that check succeeds; otherwise it returns
zero. Record 0x005BB590 names CPaneContainerManager, declares size 0x50,
and points to constructor thunk 0x005194AA. That thunk allocates 0x50
bytes and calls 0x00518AEC; the constructor writes vptr 0x005BB5B4. Its
+0x70 vtable entry at 0x005BB624 is 0x00518C91, not G5 wrapper
0x00411030.

The exact runtime instance and any derived manager vptr are not observed.
The code-level successful cast is to CPaneContainerManager; it does not
identify a CDevG5KB object. In the pinned RTTI map, CDevG5KB is a CHidDev
family class, separate from the pane-manager class route.

Additional CPaneDivider-associated writes corroborate the member's role:

- 0x004EDE1F clears [ESI+0x138] in a CPaneDivider vtable method after
  conditionally releasing the nested pointer.
- 0x00518B89 clears the field on a pointer returned from a dynamic cast to
  CPaneDivider.
- 0x00518D78 and 0x0051F8D2 store through CPaneDivider pointers returned
  from CPaneDivider runtime-class filters.
- 0x00519611 and 0x0051A646 store through objects obtained from a
  container/list accessor, without a separate type check at the store. They
  are consistent with the manager/divider relationship but are not used as
  standalone type proof here.

Other executable code also uses displacement +0x138 on different registers
and objects. A raw displacement census is not treated as one global field
definition; the owner claim above is restricted to the vptr, constructor,
and typed code paths shown here.

## Direct caller ledger

“No explicit arguments” means no buffer/length values are pushed for the
direct relay call. The indirect tail target inherits whatever frame words
are live at the caller's current ESP; those words are not established as
the G5 wrapper's API arguments. The returned value is consistently used as
an object pointer or null.

| Relay callsite | Caller entry / frame evidence | ECX receiver provenance | Stack at direct call | Returned EAX use | Receiver conclusion |
| --- | --- | --- | --- | --- | --- |
| 0x004A5521 | 0x004A54DE; frame-pointer prologue, two local slots, saved EBX/ESI/EDI | 0x0048BF9D checks class 0x005B4F40; 0x0048BFBB returns the CPaneDivider-compatible object | No explicit args; top frame words are saved EDI, ESI, EBX | EAX to ESI, null check, object helper 0x004800AD, compare returned value to [EBP+8] | **CPaneDivider receiver proven; nested field is manager-typed** |
| 0x004A587F | 0x004A585D; frame-pointer prologue, local slot, saved ESI/EDI | ECX=[EAX] after accessor 0x004E288B on [caller-this+0x3C] | No explicit args; top frame words are saved EDI, ESI | EAX to ESI, compare to [EBP+8]; object helper and conditional vtable +0x320 call | **Receiver type unresolved** |
| 0x004A5CD6 | 0x004A5B8E; frame-pointer prologue, 0x10 local bytes, saved EBX/ESI/EDI | The CBasePane-filtered candidate is subsequently filtered to CPaneDivider at 0x004A5CC9; non-null result is passed in ECX | No explicit args; top frame words are saved EDI, ESI, EBX | Returned EAX is checked/used by the later slot-zero comparison and 0x004E87FA path | **CPaneDivider-compatible receiver proven on the checked path** |
| 0x004A64D5 | 0x004A63D5; frame-pointer prologue, 0x34 local bytes, saved EBX/ESI/EDI; branch to site is 0x004A6425 | ESI is arg1 [EBP+8]. Both direct callers pass a CPaneDivider-filtered pointer; one passes arg2=1 and skips the relay branch, while the other does not explicitly supply arg2 | No arguments are pushed at the relay call | EAX+0x20 is read; EAX is saved to [EBP+8] and passed as a record/object to function pointer EDI | **CPaneDivider-compatible receiver on the known relay-capable path; branch/reachability remains conditional** |
| 0x004A700B | 0x004A6D8F; frame-pointer prologue, 0x28 local bytes, saved ESI/EDI | 0x0048BFBB filters to class 0x005B4F40 (CPaneDivider) | No explicit args; top frame words are saved EDI, ESI | EAX is filtered to class 0x00609718, checked, then fields +0x2FC and +0xE4 are followed | **CPaneDivider receiver proven; nested field is manager-typed** |
| 0x004A90B7 | 0x004A8FB6; EH prologue with 0x94 local bytes | 0x0048BFBB filters the object to CPaneDivider at 0x004A9091; result is in EDI | No explicit args; active EH/local frame remains under the call | Null check; nonnull result gets vtable slot +0x208 with -1, -1, [EBP+8] | **CPaneDivider receiver proven; nested field is manager-typed** |
| 0x004A9316 | 0x004A9230; EH prologue with 0x9C local bytes | 0x0048BF9D/0x0048BFBB filter to CPaneDivider; result is passed in ECX | No explicit args; active EH/local frame remains under the call | EAX to EBX, null check, IsKindOf(0x00609718), then vtable slot +0x204 with -1, -1, [EBP+8] | **CPaneDivider receiver proven; nested field is manager-typed** |
| 0x004A9952 | 0x004A95B2; EH prologue with 0x7C local bytes | 0x0048BFBB filters to CPaneDivider at 0x004A9945; result is passed in ECX | No explicit args; active EH/local frame remains under the call | EAX is filtered to class 0x00609718, stored at [EBP-0x44], null-checked, then used by 0x004A8560 | **CPaneDivider receiver proven; nested field is manager-typed** |

The first five callsites have conventional frame-pointer boundaries at the
listed addresses. The final three are in separate functions with the
0x005781B4/0x005781E7 exception-frame prologues. In particular,
0x004A90B7 is inside the function beginning at 0x004A8FB6; the preceding
routine beginning at 0x004A8F17 ends at 0x004A8FB3 (ret 4). The three sites
are not one long function rooted at 0x004A8EDE.

## Conclusion and remaining limits

The type and field evidence narrows the eight callers materially:

- Seven direct relay callsites have CPaneDivider-compatible receivers on the
  statically established paths. For those
  calls, the +0x138 field is initialized and written as a
  CPaneContainerManager-compatible member. The base manager vtable's +0x70
  entry is 0x00518C91, distinct from the G5 GetRealData wrapper at
  0x00411030. The manager's dynamic subtype is not established.
- `0x004A587F` remains receiver-unresolved. Its return-value use is recovered,
  but the static slice does not prove the relay's `[this+0x138]` dynamic type.
- The receiver at `0x004A64D5` is typed on the known relay-capable direct path,
  but its zero-argument gate and possible computed callers remain unresolved.
- All eight make a nullary direct call to the relay and provide no
  caller-pushed output buffer and byte length. Therefore the eight sites do
  not establish invocation of the G5 two-argument wrapper or an attributable
  response buffer. The unresolved receiver is not declared unreachable or
  conclusively excluded from every computed path.

This does not resolve the meaning of command 0x88, establish firmware
bytes, or trace a full response range to a persistent sink. The separate
[response/sink audit](rk-v4.6-g5-command-0x88-response-sink-audit.md) remains
the scope for those questions. The broader
[caller/alias census](rk-v4.6-g5-command88-caller-alias-census.md) still
records scan limits, including the fact that CFG absence is not proof of
unreachability.
