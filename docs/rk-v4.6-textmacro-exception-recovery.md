# 4.6 text-macro TLS exception recovery (static follow-up)

**Finding date:** 2026-10-25  
**Artifact:** `DeviceDriver.exe`, 2,418,176 bytes  
**SHA-256:** `8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`

This follow-up closes one bounded static recovery gap from the text-macro picker TLS accessor. It does not establish that the failure occurs at runtime or that exception dispatch reaches the catch handler.

## Static route

1. Picker handler `0x00480C2C` (the `CKeyFunPickDlg` vtable slot `+0x158`) calls validation helper `0x0047C312` at `0x00480C33`. The helper calls the TLS guard `0x0048A529` at `0x0047C32E`.
2. The guard calls lazy helper `0x0048CA84`, tests its result at `0x0048A538`, and jumps to shared stub `0x00477A84` on null at `0x0048A53C`. The helper also has a failure edge to that stub at `0x0048CA9E`.
3. Stub `0x00477A84` supplies object address `0x006073C8` and ThrowInfo `0x005EF1B0` to `0x005782BE`. That helper calls the `KERNEL32!RaiseException` import at IAT slot `0x005A62A4`; the exception-code template at `0x005CC030` begins with `0xE06D7363` (MSVC C++ exception code).
4. ThrowInfo at `0x005EF1B0` points to the five-entry catchable-type array at `0x005EF1C0`. Its entries include type descriptors `.PAVCInvalidArgException@@` (`0x006070E8`) and `.PAVCException@@` (`0x00619F3C`). The latter is compatible, at static MSVC type-metadata level, with the modal wrapper's `CException*` handler record.
5. The validation helper has its own one-entry try map, but the TLS accessor call happens at `0x0047C32E` before the helper sets EH state 0 at `0x0047C350`. Its local catches therefore are not active at that call site. The TLS helper's FuncInfo has `nTryBlocks=0`.
6. Modal wrapper `0x004811E6` registers FuncInfo `0x005EF910`. Its try map at `0x005EF8FC` covers state 0 and names a `CException*` handler at `0x00481331`. The wrapper sets state 0 at `0x004812CD`, then calls modal-loop helper `0x0047C55D` at `0x0048130E` before resetting state on normal return. **If** a picker callback's exception propagates through this active modal-loop frame without an intermediate handler intercepting it, this is a matching static catch route.
7. The handler reads the caught pointer from `[ebp-0x30]`, calls helper `0x0047797C` when non-null, writes `-1` to dialog result field `+0x44` at `0x00481340`, and returns through the modal wrapper's common epilogue, which loads that field at `0x004813A9`.
8. Parent handler `0x0041CF20` has FuncInfo `0x006019B8` with zero try blocks. It compares the modal result to 1 at `0x0041D15C`; the non-1 branch at `0x0041D15F` reaches cleanup at `0x0041D2B2` and calls the picker destructor. That branch skips the result-1 follow-up call to `0x0041EC50` at `0x0041D267`.

The resulting bounded claim is: **a matching CException-pointer catch is statically active around the modal-loop call; its handler sets the modal result to -1, and the picker parent routes that result to cleanup.** It does not prove all exceptions from the helper take this route, or that this one was raised, dispatched, or caught in any process.

## Evidence and reproduction

The [56-row evidence ledger](rk-v4.6-textmacro-exception-recovery.csv) pins the exact binary digest and records the instruction bytes, ThrowInfo and catchable-type records, FuncInfo/try maps/handler records, RTTI strings, and RaiseException import mapping. The focused [verifier](../scripts/audit_rk46_textmacro_exception_recovery.py) checks the input size and SHA-256 before validating those facts.

```powershell
python scripts\audit_rk46_textmacro_exception_recovery.py --binary C:\Users\shubh\Downloads\sshorcale\.research\rk4_6_official_extract_20261015\app\DeviceDriver.exe --out docs\rk-v4.6-textmacro-exception-recovery.csv
```

The verifier passed against the hash-pinned artifact and emitted 56 rows. The PE was read statically; RK software was not run and no HID/device interface was opened.

## Remaining uncertainty

- Whether the TLS helper returns null or takes an internal failure edge at runtime.
- Whether the picker handler is invoked while this wrapper's modal-loop call is active, and whether an intermediate callback/dispatch frame intercepts or transforms the exception.
- Whether the matching catch executes, what helper `0x0047797C` does semantically, and what the user sees after cleanup.

This finding closes only the previously open **static recovery-table/parent-result slice** for this TLS failure path. Runtime occurrence and dispatch remain open; overall reverse-engineering coverage remains bounded and incomplete.
