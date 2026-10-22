# 4.06 stack-alias corrections — 2026-10-22

## Scope and correction

The 2026-10-21 G5 caller audit incorrectly compared textual `[esp+offset]`
operands across pushed arguments and caller cleanup. That caused five local
text calls to be treated as having overwritten receivers, and a sixth to be
attributed to an opaque GDI+ object. Those claims are retracted here and
corrected in the main audit and census.

The exact input is `DeviceDriver.exe`, SHA-256
`C03F88BC4E2D78AA4392D7445B0FD62182DC824F97F5D5DB40BD009E547A9AB6`.
All addresses are x86 virtual addresses in that image. Evidence is static
GNU objdump disassembly and PE bytes; the application and keyboard were not
accessed at runtime.

For each routine, `S` below denotes ESP at its adapter constructor's `LEA`.
It is a local frame origin, not the entry ESP shared across different functions.

## `0x00457F4B`: store is four bytes before the receiver

Constructor setup `0x00457517` / `0x0045751B` passes `S+0x48` to
`0x0047105C`. That constructor installs vptr `0x0059F314`.

`0x00457AC2` pushes `ESI`, so the store at `0x00457ACF` to textual
`[esp+0x48]` writes `(S-4)+0x48 = S+0x44`. It does not overwrite the
adapter's vptr at `S+0x48`. The following helper `0x00405260` returns with
`ret 4` on both exits (`0x004052B7` and `0x004052BC`), restoring that argument
allocation. Its separate object receiver is not the adapter.

Four text-call arguments move ESP to `S-0x10`. The vptr load and ECX address
at the candidate use `[esp+0x58] = S+0x48`. Flags are `0x8135`.

## Four `0x00464...` calls: stores are eight bytes before the receiver

Constructor `0x0046473B`, with `LEA` at `0x00464737`, initializes the local
at `S+0x1C`. Before store `0x00464896`, instructions `0x00464894` and
`0x00464895` push two DWORDs. Its `[esp+0x1C]` destination is therefore
`S+0x14`. Likewise, pushes at `0x00464957` and `0x00464958` make store
`0x00464959` target `S+0x14`, not `S+0x1C`.

Calls `0x00464B47`, `0x00464BB0`, `0x00464C8D`, and `0x00464D1D` each stage
four arguments and load/address the adapter through `[esp+0x2C] = S+0x1C`.
The first uses flags `0x8134`; the other three use `0x8135`.

## `0x0046A00B`: pending formatting arguments explain the apparent GDI+ alias

Constructor setup `0x00469CD7` / `0x00469CDB` initializes the adapter at
`S+0x3C`. The genuine `GdipCreateFromHDC` output is separately stored at
`S+0x50` by `0x00469D60`.

Five pushes at `0x00469FD8`, `0x00469FD9`, `0x00469FDA`, `0x00469FDF`, and
`0x00469FE4` allocate `0x14` bytes before the formatting call at
`0x00469FE5`. Its target `0x00405590` uses a plain `ret` at `0x004055A3`, so
those arguments remain allocated when `0x00469FF1` loads `[esp+0x50]` into
EDX. The effective address is `(S-0x14)+0x50 = S+0x3C`: the adapter's vptr.
The GDI+ pointer at `S+0x50` would instead be at `[esp+0x64]` at this point.

`0x00469FF5` adds `0x14` to ESP. Four text arguments then leave ESP at
`S-0x10`; `0x0046A007` computes ECX from `[esp+0x4C] = S+0x3C`. Thus the
target load and receiver refer to the same constructor-established adapter.
The flags are `0x8135`.

The reviewed adapter helpers preserve its vptr: `0x00471728` writes object
`+4` and dispatches slot `+0x0C` to `0x0051828A`, which writes object `+8`.
The color/selection helpers `0x00471B35`, `0x00470CCF`, and `0x00470D65`
also preserve the vptr. No intervening normalized vptr overwrite was found
in these reviewed paths.

## Resolution, reproduction, and limits

All six calls use vptr `0x0059F314`, whose slot `+0x68` targets
`0x0047111A`. That adapter calls IAT `0x0059E6B8` (`USER32!DrawTextW`) and
returns with `ret 0x10`. These sites therefore provide no G5 command-`0x88`
caller or firmware-buffer consumer.

The [54-site checker](../scripts/audit_rk406_g5_vcall_resolution.py) now pins
the corrective constructor, push, store, cleanup, and return instructions. It
also replays 32-bit pushes/pops and immediate ADD/SUB ESP changes within each selected call
setup to require the vptr source and ECX receiver to have equal effective
addresses. It rejects other stack-pointer writes and unsupported instructions,
and invalidates full-register provenance on partial-register writes. A call or
branch resets tracked values; both addresses must be established in the final
suffix. This
local replay does not construct a complete function CFG or
prove every possible alias/lifetime path. Constructor provenance and the
intervening helper review remain scoped manual evidence.

```powershell
python scripts/audit_rk406_g5_vcall_resolution.py --binary <DeviceDriver.exe> --objdump <objdump.exe> --out docs/rk-406-vtable-68-resolution.csv
python -m unittest discover -s tests -p test_rk406_stack_alias.py
```

The regression cases cover the real cleanup, omitted cleanup, the distinct
GDI+ slot, source/target clobbers, unsupported stack-pointer writes, partial
register writes, implicit writes, branch boundaries, and non-DWORD stack
operations. See the separate
[forwarded-receiver report](rk-406-forwarded-text-receivers.md) for five
additional calls resolved only on listed caller paths.
