# S98 `CFile::Write` cross-build comparison — 2026-10-24

This follow-up compares the S98 Tri-mode RGB updater packages for profile IDs
`01BF` and `0223` at their static host-file-write boundary. It checks whether
the RTTI-attributed class and wrapper shape found in `01BF` also occur in the
Thai `0223` package. It does not infer full code or behavior equivalence.

## Inputs and method

Both files are 2,140,176-byte x86 PE images with preferred base `0x00400000`:

| Profile | File | SHA-256 | `.text` SHA-256 |
| --- | --- | --- | --- |
| `01BF` | `S98-Tri-RGB-01BF-L10-20260527170338_1467.exe` | `475e8d7b97adfbd861c3b7b16721ad598df04095b81228e381319b6be23129e6` | `3643f4d710a296b62598d3d8b71c7dd9dcab049ebbb540588b11757ccd5f03ed` |
| `0223` | `S98-Tri-RGB-0223-L7-20260527164526_9235.exe` | `399020b7b66fda67cc6c69ae81336d67024204cbc9e15ffabde26a2cccd072ca` | `bfc4506d668ee1ff8809a0455abd5f589545e45ff1d0b358a5fe3d4871e85ff2` |

The `.text` hashes differ. The reproduction script pins both full-file and code
section hashes, reads x86 MSVC RTTI and import records, counts the vtable code
entries, then disassembles the method and its `.text` call references. It does
not start either updater or communicate with a keyboard.

## Matched static structure

Both images have a 22-entry code vtable at `0x0055F878`. Its preceding pointer
leads to a Complete Object Locator whose TypeDescriptor is `CFile`; the static
hierarchy records `CFile` with base `CObject`. Slot 15 (`+0x3C`) points to the
following build-specific method:

| Profile | COL | Slot `+0x3C` method | `WriteFile` import call |
| --- | --- | --- | --- |
| `01BF` | `0x00590578` | `0x0042D26F` | `0x0042D28A` |
| `0223` | `0x005905A8` | `0x0042CFDD` | `0x0042CFF8` |

Both import the same `KERNEL32.DLL!WriteFile` entry at IAT address
`0x0055A378`. The decoded wrapper instruction shape agrees across builds: the
object arrives in `ECX`, the buffer and requested byte count are stack
arguments at `[EBP+8]` and `[EBP+0xC]`, the file handle is loaded from
`[this+4]`, and the ordinary return uses `ret 8`. Each code section has 24
generic indirect `call [reg+0x3C]` candidates.

This establishes a repeated host-file `CFile::Write` implementation structure
in these two S98 updater builds. The 24 generic slot calls in each image are
not attributed to this method by this comparison: it does not establish their
runtime receiver classes. The differing code hashes also mean other methods,
callers, branches, and error behavior must be compared independently. This
finding does not establish that keyboard readback or firmware data reaches a
file writer.

A separate 01BF-only caller audit later identifies two archive-shaped
`CFile`-family slot calls and bounds the other 22 01BF candidates. That analysis
does not transfer to the Thai build: its `.text` hash differs and its own
24-site receiver census has not been performed. The 01BF concrete target and
any readback-to-file relationship remain unresolved; see the
[01BF virtual-call attribution](rk-s98-cfile-vcall-attribution-2026-10-24.md).

## Reproduction

From the research repository root, with the two hash-matching extracted package
files available beside the checkout under `.research`:

```powershell
python scripts\audit_s98_cfile_crossbuild.py `
  --01bf-binary "..\.research\rk-selector-software-2026-10-19\S98-firmware-packages\S98-Tri-RGB-01BF-L10-20260527170338_1467.exe" `
  --0223-binary "..\.research\rk-selector-software-2026-10-19\S98-firmware-packages\S98-Tri-RGB-0223-L7-20260527164526_9235.exe" `
  --out docs\rk-s98-cfile-crossbuild-evidence-2026-10-24.csv
```

The generated evidence ledger records the checks for each build in
[`rk-s98-cfile-crossbuild-evidence-2026-10-24.csv`](rk-s98-cfile-crossbuild-evidence-2026-10-24.csv).
The implementation is in
[`audit_s98_cfile_crossbuild.py`](../scripts/audit_s98_cfile_crossbuild.py).
