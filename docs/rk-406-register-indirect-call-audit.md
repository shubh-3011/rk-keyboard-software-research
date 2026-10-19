# 4.06 main-driver register-indirect call supplement

## Scope and reproducibility

This supplement scans the installed 4.06 `DeviceDriver.exe`, 2,326,528 bytes,
SHA-256
`c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6`.
It complements the [native API IAT cross-reference](rk-native-api-xrefs.csv)
and [62-row direct/thunk gap audit](rk-native-api-indirect-call-audit.md).
Those artifacts record direct calls and known paths for import rows; this
supplement records the `mov register,[IAT]` followed by `call register`
pattern, including for APIs that already have direct/thunk callers.

Reproduce from the repository root with the same installed package and GNU
`objdump` available on `PATH`:

```powershell
python scripts/audit_rk406_register_indirect_calls.py `
  "C:\Program Files (x86)\RK Keyboard Software\DeviceDriver.exe" `
  docs/rk-406-register-indirect-call-candidates.csv
```

The script verifies the PE hash and architecture, reads its import table,
disassembles it, and writes one row per imported entry with a candidate or a
`no_candidate_detected` result. Candidate rows preserve the import DLL/name,
IAT RVA/VA, IAT-load instruction/VA, and transfer instruction/VA. The
`baseline_direct_or_thunk_site_present` field records whether the existing
scanner also found a direct IAT call or a call to an IAT thunk for that import
row.

## Results

The scanner found **866 register-indirect call candidates across 130 import
rows**. Of those, **833 candidates across 116 import rows** also have a
direct/thunk call path in the existing cross-reference. The other **33
candidates across 14 import rows** had no direct/thunk call recorded by that
cross-reference. These are instruction-pattern counts, not distinct runtime
calls or proof of execution. The latter 33 rows should be reconciled with the
earlier hand-reviewed gap paths before changing their classifications.

Three representative candidate transfers were checked against exact
instruction bytes and boundaries in `objdump` output:

| Imported API | IAT load | Register transfer |
| --- | --- | --- |
| `USER32!SetRectEmpty` | `mov 0x59e77c,%edi` at `0x00496BAD` | `call *%edi` at `0x00496BB9` (`FF D7`) |
| `USER32!GetSystemMetrics` | `mov 0x59e7d4,%edi` at `0x00446B94` | `call *%edi` at `0x00446B9C` and `0x00446BA2` (`FF D7`) |
| `USER32!GetParent` | `mov 0x59e82c,%esi` at `0x004031CD` | `call *%esi` at `0x004031D7` and `0x004031E3` (`FF D6`) |

The complete candidate and no-candidate rows are in
[`rk-406-register-indirect-call-candidates.csv`](rk-406-register-indirect-call-candidates.csv).

## Interpretation limits

The scan accepts only the exact decoded absolute-IAT load forms implemented in
the script, followed by a register call in the scanner's same-region taint
heuristic. GNU `objdump` performs a linear sweep; a decoded instruction can
still be unreachable or overlap data. The heuristic is not a control-flow
graph and does not prove a same-thread, same-object, or runtime path. It can
miss computed IAT addresses, branch-spanning uses, callbacks, COM/vtable
dispatch, or other indirect forms. A `no_candidate_detected` row is not proof
that an API is unused.

This report expands one static transfer pattern for one hash-pinned 4.06
binary. It does not complete the system-call map, reconstruct the changed 4.6
main binary, or establish behavior on other releases or keyboards.
