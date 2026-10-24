# S98 01BF `CFile::Write` vtable and caller boundary — 2026-10-24

This static follow-up identifies the S98 updater's generic file-writing method
and checks whether its read consumers have a proven route to that method. It
does not establish a firmware export path.

## Scope and method

The inspected file is
`S98-Tri-RGB-01BF-L10-20260527170338_1467.exe`, 2,140,176 bytes, SHA-256
`475e8d7b97adfbd861c3b7b16721ad598df04095b81228e381319b6be23129e6`.
I used PE/RTTI data and an x86 Capstone sweep of `.text`; the reproduction
script checks the artifact hash and the exact structural and instruction
facts below. No updater was launched, and no device interface was opened.

## Class and method identity

The `.rdata` vftable at `0x0055F878` has the preceding MSVC Complete Object
Locator at `0x00590578`. Its TypeDescriptor names `.?AVCFile@@`; the associated
hierarchy lists `CFile` and base `CObject`. The table has 22 consecutive code
entries. Entry 15, byte offset `+0x3C`, points to `CFile::Write` at
`0x0042D26F`. Three `.text` stores install this vftable at
`0x0042C9E4`, `0x0042CA10`, and `0x0042CA9A`.

The method loads its byte count from `[EBP+0x0C]`, its buffer from
`[EBP+0x08]`, and the file handle from `[this+4]`, then calls
`KERNEL32!WriteFile` through IAT slot `0x0055A378`. It compares the reported
bytes-written value with the requested count. The failure and short-write
branches use the object's error state and reach the file-exception helper;
the ordinary success epilogue returns with `ret 8`.

## Caller boundary

The decoded `.text` contains zero direct relative calls to `0x0042D26F`; the
method pointer occurs once as the `CFile` vtable entry. A full instruction
sweep finds 24 indirect calls using a memory displacement of `+0x3C`. Those
are candidate virtual dispatch sites only. Without proving each receiver's
runtime class and the method signature at that site, none can be counted as
a `CFile::Write` caller merely because the slot offset matches.

A later hash-pinned caller audit provides bounded receiver and argument
evidence for two archive-shaped sites, `0x0041CA16` and `0x0041CD65`, as
`CFile`-family `+0x3C` virtual calls; 22 other sites fail bounded receiver,
argument-role, or stack-arity checks. The archive field's runtime vptr remains
unknown, and RTTI identifies `CMemFile`, `CSharedFile`, and `COleStreamFile`
overrides at the same slot. Neither archive site therefore establishes a call
to the base `CFile::Write`/`WriteFile` implementation. See the
[virtual-call attribution audit](rk-s98-cfile-vcall-attribution-2026-10-24.md).

The earlier 01BF feature-read audit identifies three bounded read consumers,
including the `0x00402880` path that forwards selected response bytes into a
later `05 77` feature report. No direct or receiver-proven edge from those
consumers to `CFile::Write` is established in this audit. A generic file
writer exists, but its presence alone says nothing about what data reaches
it. This finding neither proves nor rules out an export route through a
computed dispatch or a different routine.

## Reproduction

From the repository root:

```powershell
python scripts\audit_s98_cfile_write_vtable.py `
  --binary ..\.research\rk-selector-software-2026-10-19\S98-firmware-packages\S98-Tri-RGB-01BF-L10-20260527170338_1467.exe `
  --out docs\rk-s98-cfile-write-vtable-evidence-2026-10-24.csv
```

The generated ledger lists the structural facts and all 24 generic `+0x3C`
call candidates, explicitly scoped as unattributed. See also the [feature-read
consumer audit](rk-s98-feature-read-consumer-audit-2026-10-24.md) and its
[source scanner](../scripts/audit_s98_feature_read_consumer.py).
