# S98 01BF `CFile::Write` virtual-call attribution — 2026-10-24

This follow-up classifies all 24 `call [reg+0x3C]` candidates from the
hash-pinned 01BF `.text` scan. It narrows the potential host-file-write routes
without treating every use of the same slot offset as a `CFile::Write` call.

## Inputs and method

Target: `S98-Tri-RGB-01BF-L10-20260527170338_1467.exe`, size 2,140,176 bytes,
SHA-256
`475e8d7b97adfbd861c3b7b16721ad598df04095b81228e381319b6be23129e6`, with
`.text` SHA-256
`3643f4d710a296b62598d3d8b71c7dd9dcab049ebbb540588b11757ccd5f03ed`.

The audit uses the RTTI-identified base `CFile` vtable at `0x0055F878`,
whose slot `+0x3C` points to the `WriteFile` wrapper at `0x0042D26F`. Its
thiscall shape is `ECX=this`, then buffer and byte count on the stack; the base
implementation calls `KERNEL32!WriteFile` through IAT `0x0055A378` and returns
with `ret 8`. The verifier hash-pins the PE, checks exact instruction bytes at
the candidate sites, validates the call/argument facts below, and checks the
RTTI identities and slot targets of the derived vtables listed below. No
updater was executed and no keyboard interface was opened.

## Candidate census

| Classification | Count | Evidence |
| --- | ---: | --- |
| CFile-compatible virtual slot calls in archive-shaped paths | 2 | `0x0041CA16`, `0x0041CD65` |
| Incompatible receiver or argument use on the bounded path | 7 | 6 receiver paths have a conflicting `CFile` `+0x24` signature; 1 passes `this` and a path where `CFile::Write` requires buffer and byte count |
| Stack-argument arity does not match | 15 | Candidate callsites supply 0, 1, 4, or 6 stack words rather than the two required by `CFile::Write` |
| **Total generic `+0x3C` candidates** | **24** | Every site is classified once in the evidence ledger |

The two archive-shaped paths share a constructor-supplied pointer stored at
`[archive+0x24]`. The constructor at `0x0041C3F5` retains its first parameter
there. The same field is used for a `+0x38` virtual call in an archive read
path. At the write candidates, the code loads that field as `ECX`, gets the
vptr, and calls slot `+0x3C` with the observed buffer/count order. This proves
the path is compatible with a `CFile`-family `Write` slot; it does not prove
the runtime object's concrete class.

The checked RTTI shows that `CMemFile` (`vtable 0x0055F284`), `CSharedFile`
(`0x00576AD0`), and `COleStreamFile` (`0x005769D8`) each have a distinct
implementation in slot `+0x3C`. Therefore the two archive paths cannot be
resolved to the base `CFile::Write`/`WriteFile` implementation from their
static slot offset and `CFile*`-shaped field alone. Their exact runtime vptr,
storage destination, and whether either route writes bytes to disk remain
unknown.

The other six two-argument-shaped callsites cannot be assigned to the CFile
family on the bounded receiver paths: each same receiver is also called at
`+0x24` with one explicit argument, while the verified base `CFile` slot there
is `Open`, which takes three stack parameters and returns with `ret 0x0C`.
Fifteen further sites fail the base method's two-argument stack shape, and one
passes the wrong argument roles. These conclusions are callsite-local; the
audit does not attempt to name every other class using `+0x3C`.

## What this narrows

The prior vtable audit found zero direct calls to the base wrapper and 24
generic slot candidates. This trace narrows those 24 to two plausible
`CFile`-family archive virtual calls and provides bounded reasons to exclude
the other 22. It still establishes no path from `HidD_GetFeature` readback to
the archive writer, no arbitrary firmware export, and no concrete disk-write
target for the two archive calls.

## Reproduction

```powershell
python scripts\audit_s98_cfile_vcall_attribution.py `
  --binary "..\.research\rk-selector-software-2026-10-19\S98-firmware-packages\S98-Tri-RGB-01BF-L10-20260527170338_1467.exe" `
  --out docs\rk-s98-cfile-vcall-attribution-evidence-2026-10-24.csv
```

The 01BF callsite classifications and checked derived-vtable rows are in the
[evidence ledger](rk-s98-cfile-vcall-attribution-evidence-2026-10-24.csv); the
hash-pinned reproduction logic is in
[`audit_s98_cfile_vcall_attribution.py`](../scripts/audit_s98_cfile_vcall_attribution.py).
