# V4.6 command-0x88 receiver-type corrections — 2026-10-25

## Scope and pinned input

This static follow-up rechecks two receiver classifications in the
[tail-relay caller audit](rk-v4.6-g5-command88-tail-relay-receiver-follow-up.md):
relay calls `0x004A5CD6` and `0x004A64D5`. The input is the extracted 4.6
`DeviceDriver.exe`, SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`, size
2,418,176 bytes. It was read as PE bytes and disassembly only. No device
interface was opened and no report was sent.

The hash-pinned verifier is
[`audit_rk46_g5_cmd88_receiver_type_corrections.py`](../scripts/audit_rk46_g5_cmd88_receiver_type_corrections.py);
it emits the [evidence ledger](rk-v4.6-g5-command88-receiver-type-corrections-evidence-2026-10-25.csv).
Run from the repository root:

```powershell
python scripts/audit_rk46_g5_cmd88_receiver_type_corrections.py `
  '..\.research\rk4_6_official_extract_20261015\app\DeviceDriver.exe'
```

## `0x004A5CD6`: CPaneDivider filter immediately precedes relay

Function `0x004A5B8E` initially filters a nested object to `CBasePane`. In the
subsequent branch, it loads runtime-class descriptor `0x005B4F40` (identified
by the prior RTTI audit as `CPaneDivider`), checks the candidate with
`IsKindOf`, and calls the MFC runtime-class filter at `0x0048BFBB`. The
non-null returned pointer is moved into `ECX` and passed to relay
`0x004EDD8D` at `0x004A5CD6`. Therefore the receiver at this callsite is
statically **CPaneDivider-compatible**, not merely an unresolved
`CBasePane`-derived object.

This conclusion is conditional on the visible type-check branch succeeding.
It does not identify the dynamic type of the nested object at
`[CPaneDivider+0x138]` or prove the relay's virtual destination at runtime.

## `0x004A64D5`: the known relay-capable direct caller passes CPaneDivider

The relay callsite is inside function `0x004A63D5`. Its prologue assigns
`ESI=[EBP+8]`; the branch to `0x004A64D5` loads `ECX=ESI` and calls the
relay. A hash-pinned linear disassembly shows two direct callers of
`0x004A63D5`:

- At `0x004A8057`, the caller passes `EBX` as `[EBP+8]` and literal `1` as
  `[EBP+0xC]`. `EBX` came from helper `0x004FCB2B`, which filters its result
  to runtime class `CPaneDivider`. The callee compares `[EBP+0xC]` with zero
  before the relay branch; this caller's literal `1` bypasses that branch.
- At `0x004FE0C1`, the caller pushes the result of `0x004FCB2B` as
  `[EBP+8]`. The helper returns only a pointer accepted by the
  `CPaneDivider` runtime-class filter. The next argument that controls the
  zero test at `0x004A641E` is not explicitly pushed at this callsite, so
  whether this caller reaches `0x004A64D5` is unresolved. If it does, the
  relay receiver is the filtered `CPaneDivider` pointer.

These direct-call slices supersede the earlier “receiver unresolved” label
for `0x004A64D5` on the enumerated direct path. They do not prove that the
branch executes, rule out a computed caller to `0x004A63D5`, or determine the
runtime type stored at the divider's `+0x138` member.

## Updated bounded conclusion

The prior eight-call report had five `CPaneDivider` receivers and three
unresolved/base-only receivers. This follow-up resolves `0x004A5CD6` and
`0x004A64D5` as `CPaneDivider`-compatible on their statically established
relay paths. Of the eight direct relay callsites, seven are now
`CPaneDivider`-compatible and `0x004A587F` remains receiver-unresolved. For
the seven typed callers, the other report shows that `CPaneDivider+0x138` is
initialized and assigned through a `CPaneContainerManager` runtime-class
filter; that class's base vtable slot `+0x70` is `0x00518C91`, not G5 wrapper
`0x00411030`. The dynamic manager subtype and indirect target remain
unobserved, so this does not claim that every possible runtime override is
excluded.

No output-buffer/length pair, complete response range, or file sink is
established by these corrections. The command `0x88` response meaning and
firmware-export question remain unresolved.
