# 4.06 brightness UI setter: record-base correction

## Finding

The prior claim that `FUN_00425440` does not write the runtime brightness
field was **incorrect**. It compared member displacements relative to two
different bases without normalizing them:

```text
Canonical lighting record = config + 0x2140 + row * 0x30
Setter EBX alias          = config + 0x2138 + row * 0x30

EBX + 0x0C = config + 0x2144 + row * 0x30 = canonical record + 0x04
```

At **`0x004254F9`**, `mov [ebx+0x0C], eax` writes the value returned by
the brightness child getter into precisely the field initialized from
`DefBri` and subsequently translated through `LightHW` by the serializers.
The UI does not need to modify the `LightUI` lookup table to change its
selected index. A negative search for `LightUI` stores could not establish
absence of a brightness setter.

This correction applies to installed `DeviceDriver.exe`, SHA-256
`c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6`.
No RK executable or device operation was run.

## Verified conditional UI-to-state path

1. `CLedDlg+0x1A6C` is the previously RTTI-identified `CPngSliderBar` child.
   Construction at `0x004236BB` selects that object; `0x004236B3` passes
   selector `0x95`, and setup stores the selector at child `+0x9E0`.
2. The slider's MFC row at `0x005D5E00` binds **`WM_LBUTTONUP (0x0202)`**
   to `0x0044D150`. The handler retains the receiver in EBX, forms the
   embedded control at `slider+0x54`, calculates the selected value and calls
   `0x0044C5D0` at `0x0044D235`.
3. That setter stores the selected position at its receiver `+0x94C`
   (`0x0044C63E`). Because the receiver is `slider+0x54`, the stored address
   is **`slider+0x9A0`**.
4. If its changed-value and other gates pass, the mouse handler obtains the
   parent HWND and posts private message `0x0800` at `0x0044D299`, with
   selected value in `wParam` and stored selector in `lParam`.
5. The parent `CLedDlg` MFC row at `0x005CD030` maps `0x0800` to
   `0x00422190`. That handler calls the value formatter and then the state
   copy helper `0x00425440` at `0x004221A6`.
6. For a nonnull selected config and ordinary row (not special row `0x1E`),
   the helper forms its `config+0x2138+row*0x30` alias. At `0x004254EB`,
   ECX is `dialog+0x1A6C`; `0x004254F4` calls getter `0x0044DB20`.
7. The getter reads child `+0x9A0`, checks selection bounds, and can map the
   position through an optional value table. The helper then stores the
   getter result at alias `+0x0C`, which is canonical brightness **`+0x04`**.
8. The parent can conditionally signal worker mask `2` at `0x004221F7`
   and call the local `pro.dct` writer at `0x00422202`. Apply gating and
   special-row checks still apply. The state-copy call precedes those gates.

These are **static message-map, call and field-identity relationships**.
Windows event delivery and the current HWND/receiver/config contents were
not observed. They establish a conditional program path, not an execution.

## Other corrected setter members

All four ordinary-row stores must use the same normalization:

- Alias `+0x08` at `0x004254F1` = canonical `+0x00` (speed/profile-derived field).
- Alias `+0x0C` at `0x004254F9` = canonical `+0x04` (brightness index/value).
- Alias `+0x18` at `0x00425505` = canonical `+0x10` (first palette DWORD).
- Alias `+0x34` at `0x00425514` = canonical `+0x2C` (other selection/state field).

The raw displacements in the earlier report were accurate, but its conclusion
that they excluded canonical `+0x04` was not. This is the same class of error
as comparing stack locations without accounting for a changed stack base.

## Matching refresh, initialization and serializer consumers

- Initialization forms `config+0x2140` at `0x0045A4FB`, writes the
  `DefBri`-derived value at `+0x04` at `0x0045A505`, and advances by `0x30`.
- UI refresh reads `config+0x2144+row*0x30` at `0x00424BCA`, translates it
  through `LightUI` at `0x00424BD8`, and restores the slider from the alias
  `+0x0C` field at `0x00424FF3`–`0x00424FFD`.
- G5/3632 packer `0x00411900` reads `config+0x2144+row*0x30` at
  `0x00411A9B`, translates it through `LightHW` at `0x00411AA2`, and writes
  output `+0x5E` at `0x00411AA8` on its gated branch.
- RKKB Apply forms the canonical record base at `0x00413CBA`, reads
  canonical `+0x04` at `0x00413CCA`, then indexes `LightHW` at `0x00413CD4`.

Thus setter, refresh, initializer and selected serializers address the same
brightness field. The concrete runtime family selected by the asynchronous
worker, valid model/revision range, exact physical units, firmware acceptance,
and all possible control configurations remain unverified. This does not
close every lighting path or authorize device writes.

## Reproducible evidence

The [verifier](../scripts/audit_rk406_brightness_record_alias.py) checks the
exact executable hash, **53 instruction byte sequences** and **three MFC
message rows**. It checks each instruction decodes as exactly one instruction.
[Five regression tests](../tests/test_brightness_record_alias.py) cover
normalization, all four field stores, every normal row, and slider subobject
aliasing.

- [Instruction ledger](rk406-brightness-alias-2026-10-26/instructions.csv).
- [Normalized-offset and Evidence summary](rk406-brightness-alias-2026-10-26/summary.json).

REA 6.7.0 `inspect-with-objdump` independently retained all 53 selected exact
instruction lines in Evidence
`ev_3cd9be563f80334bed8ef1a62351127206977c720e5f87b695d9c1574454eb74`.
Its **overall output is partial/truncated and completion is unknown**; it is
not a complete disassembly or CFG. Before/after subject hashes match. The
36 MB original JSON remains local at
`.research/rk406-rea-objdump-2026-10-26.json`; the committed ledger contains
derived, exact selected lines and the summary preserves the original record
digest and limitations. The excerpt is not relabeled as canonical REA Evidence.

```powershell
python scripts/audit_rk406_brightness_record_alias.py `
  --output ".research\my-brightness-check"
python -m unittest discover -s tests -v
```

To additionally corroborate the selected lines against the saved REA record,
pass `--rea-evidence ".research\rk406-rea-objdump-2026-10-26.json"`.

The earlier [field-boundary report](rk-406-brightness-handler-field-boundary.md)
is retained as historical evidence of the mistaken reasoning, with an explicit
supersession notice. Its no-brightness-write conclusions must not be reused.
