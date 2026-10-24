# RK 4.6 text-macro record reclamation

## Scope and result

This static follow-up maps helper `0x00401AD0` in the hash-pinned 4.6-labeled
`DeviceDriver.exe` (`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`,
2,418,176 bytes). It scans each nonempty record in the fixed text-macro table
and searches mapping cells for the record's tag and key. If no matching cell is
found in the examined linked-list nodes, it calls a fill helper with a zero
byte and the full `0x404`-byte record size. A matching reference branches past
the fill call.

The mapping-cell discriminator `0x0A00005B`, key offset, and 50-record table
match the previously documented picker save and device-trigger paths. The
helper therefore statically supports orphan-record reclamation for that
text-macro table. It does not prove that a particular call ran, that a record
was actually cleared, or that a later file write persisted the cleared table.

The binary was inspected as bytes/disassembly only. It was not executed; no RK
program or keyboard interface was opened, and no message, report, or command
was sent. The verifier pins the helper, its zero-fill paths, and the three
direct-call candidates found by a byte-linear sweep of executable sections.
That sweep is not a complete control-flow graph proof.

## Reference-scan algorithm

The helper starts at `0x0060D3C4`, skips a record if its first DWORD is zero,
and advances records by `0x404` bytes until the exclusive end address
`0x00619C8C`. This is 50 records, each containing a key/metadata DWORD and a
`0x400`-byte text field.

For a nonzero record key, the helper starts at the pointer stored in global
`0x00619DCC` and follows linked nodes through each node's `+4` pointer. For a
non-null mapping base found in a node's first DWORD, it checks four groups of
`0x84` cells. Each cell is `0x10` bytes; group starts are `0x840` bytes apart.
The tag is read at mapping-base `+0x38` within each cell and the key at
`+0x40`. A cell counts as a reference only when its DWORD tag is exactly
`0x0A00005B` and its key equals the current record key.

If any node contains a matching cell, control jumps to the next macro record
without clearing the current one. If all examined cells fail to match, the
helper calls `0x005785F0` with the current record pointer, fill byte zero, and
length `0x404`. The fill helper's ordinary path writes the zero byte across
the requested range. Its large-fill fast path clears XMM0 and stores zeroed
16-byte blocks, then clears any tail bytes. This clears the key and all text
bytes in that record.

The follow-up [list-lifecycle trace](rk-v4.6-textmacro-list-lifecycle.md)
identifies `0x00619DCC` as the head field of a global list-like object and maps
its generic append/remove/clear/destruction helpers. The exact semantic type
and runtime contents of each node payload, and whether the list covers every
profile or keyboard model in every state, remain unresolved. The cleanup code
proves only the pointer traversal and cell layout it examines.

## Direct-call contexts

The executable-section byte-linear decoder finds these three direct calls to
`0x00401AD0`:

| Callsite | Static local gate/context | Limit |
| --- | --- | --- |
| `0x0040381B` | The preceding branch tests global byte `0x0062B8B3`; the call is reached when it is nonzero. | The containing action's complete event ownership and the global's runtime value are not observed here. |
| `0x0041D0A4` | The existing MFC ledger identifies containing handler `0x0041CF20` as `CKeyDlg` message `0x0477`. Its branch requires the first explicit argument to be zero, global byte `0x0062B8B3` to be nonzero, and the selected mapping cell tag to equal `0x0A00005B`. | Call execution and the loaded active selection are unobserved. |
| `0x00421640` | In the previously mapped `CKeyFunPickDlg` command path, global byte `0x0062B8B3` must be nonzero, picker state must differ from `5`, and the selected cell tag must match. | The actual command/state, callback delivery, and subsequent persistence are unobserved. |

These callers are consistent with pruning text-macro records after certain
mapping or selection changes, but the user action and exact lifecycle timing
are not established by the static callsites alone. A follow-up branch trace
finds no direct `textmacro.dct` writer call on the cleanup branches; it also
finds separate `pro.dct` profile persistence and one unresolved virtual call
after cleanup. See the [list-lifecycle trace](rk-v4.6-textmacro-list-lifecycle.md)
for per-caller details. The routine scans the linked-list nodes it is given;
it cannot prove that no external or unlisted reference exists.

## Evidence and reproduction

The [instruction ledger](rk-v4.6-textmacro-record-reclamation.csv) records
the exact image hash, instruction bytes, stage, and scope for each guard. The
[verifier](../scripts/audit_rk46_textmacro_reclamation.py) checks the pinned
PE, helper loop, zero-fill implementations, and those three direct-call
operands. The `0x0041CF20` owner/message attribution is cross-checked against
the existing [MFC message-map ledger](rk-v4.6-mfc-message-map-entries.csv).

```powershell
python scripts/audit_rk46_textmacro_reclamation.py --binary .research/rk46-extract-full/app/DeviceDriver.exe --out docs/rk-v4.6-textmacro-record-reclamation.csv
```

The next open questions are the runtime contents/completeness of the linked
list, the device/profile meaning of its mapping cells, which user actions
reach each caller, and whether unresolved virtual dispatch can later persist
the cleared table to `textmacro.dct`.
