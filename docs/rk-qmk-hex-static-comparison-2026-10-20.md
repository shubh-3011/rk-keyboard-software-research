# RK QMK HEX static validation and comparison

This report parses the seven official QMK Intel HEX downloads recorded in the adjacent artifact ledger. It verifies file SHA-256 against that ledger, validates record framing/checksums and EOF records, builds sparse address maps, and compares bytes at shared addresses. No firmware was executed, disassembled, flashed, or sent to a keyboard.

## Aggregate results

- Artifacts: 7; model labels: R65 QMK, R75 QMK, R87PRO QMK.
- Parsed Intel HEX records: 31623; mapped data bytes summed across images: 505320.
- Files with record/checksum/EOF errors: 0.
- Pairwise image comparisons: 21.
- Row-level results: [`rk-qmk-hex-record-validation-2026-10-20.csv`](rk-qmk-hex-record-validation-2026-10-20.csv) and [`rk-qmk-hex-image-overlap-2026-10-20.csv`](rk-qmk-hex-image-overlap-2026-10-20.csv).

## Per-image layout

| Model | Mode / PID | File | Records | Mapped bytes | Address ranges | Validation |
|---|---|---|---:|---:|---|---|
| R65 QMK | USB / `E508` | `20260811092153_5697.hex` | 4393 | 70200 | `0x08000000-0x08011238` | valid (0 errors) |
| R65 QMK | Tri mode / `E453` | `20260811092233_1324.hex` | 4518 | 72204 | `0x08000000-0x08011A0C` | valid (0 errors) |
| R75 QMK | USB / `E484` | `20260811092303_9713.hex` | 4284 | 68452 | `0x08000000-0x08010B64` | valid (0 errors) |
| R75 QMK | USB / `E483` | `20260811092507_6532.hex` | 4358 | 69616 | `0x08000000-0x08010FF0` | valid (0 errors) |
| R75 QMK | Tri mode / `E487` | `20260811092538_1945.hex` | 4557 | 72812 | `0x08000000-0x08011C6C` | valid (0 errors) |
| R87PRO QMK | USB / `E48E` | `20260811093052_8435.hex` | 4722 | 75464 | `0x08000000-0x080126C8` | valid (0 errors) |
| R87PRO QMK | USB / `E4CF` | `20260811135140_8329.hex` | 4791 | 76572 | `0x08000000-0x08012B1C` | valid (0 errors) |

## Comparison limits

Address overlap and byte equality are structural comparisons only. They do not identify code/data boundaries, CPU instruction semantics, a boot protocol, model compatibility, or keyboard acceptance. The selector labels and adjacent QMK source package declarations are not hardware verification. Detailed pairwise shared-address counts are preserved in the CSV.

## Reproduction

Run from the repository root after the seven official HEX artifacts are present in the ignored sibling research cache:

```powershell
python scripts/audit_qmk_hex_records.py
```
