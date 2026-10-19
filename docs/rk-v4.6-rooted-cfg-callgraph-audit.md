# 4.6 `DeviceDriver.exe`: root-seeded CFG and call-edge audit

## Scope and artifact identity

This audit builds a bounded static control-flow and call-edge view for the
4.6-labeled `DeviceDriver.exe`, SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`, size
2,418,176 bytes, PE32 x86, image base `0x00400000`, entrypoint
`0x005750DB`. This is the same input as the existing
[linear-sweep inventory](rk-v4.6-driver-linear-sweep-inventory.md).

No RK executable was launched. No HID, serial, Bluetooth, firmware, or
updater interface was opened or written.

The traversal roots are intentionally limited to:

- the PE entrypoint;
- handler addresses from 145 structurally validated MFC message-map
  candidates (1,214 entry rows; 1,033 unique handler addresses); and
- the 37 unique executable targets among 50 `proven` entries in the audited
  `CDevG5KB` and `CDevRKKB` vtable maps.

The MFC map scanner is
[`audit_rk46_mfc_message_maps.py`](../scripts/audit_rk46_mfc_message_maps.py),
SHA-256 `daa5de4f086feb16af840a8ac80b9e5f6228bdcf9ff45a0a85da027194afa4ab`.
The CFG scanner is
[`audit_rk46_rooted_cfg_callgraph.py`](../scripts/audit_rk46_rooted_cfg_callgraph.py),
SHA-256 `bb42b82011458fcb52bbebd36d98de8a091d3988087cd4cb2b02b86997132497`.
The two vtable-map inputs are hash-checked by the new scanner:

| Root evidence input | SHA-256 |
| --- | --- |
| `rk-v4.6-cdevg5-vtable-map.csv` | `6c994b3f91c0d40e4302e9e29d2e9e5da4a0d74b82635662a579e86ae71384e1` |
| `rk-v4.6-cdevrkbb-vtable-map.csv` | `7086073683dd51e8531ca607ab3afa9b1a7508fed4e46e964a40fd8af42bd862` |

The scan follows decoded conditional branches both ways and recursively adds
internal direct-call targets as function-root candidates. Exact absolute IAT
memory operands are matched to this PE's ordinary/delay import tables.
Unconditional jumps into another seed or a common x86 frame prologue are
recorded as tail-jump candidates; other direct unconditional jumps are followed
as branch candidates. It does not evaluate branch conditions or resolve
register, vtable, callback, COM, or computed targets.

## Results

The hash-pinned run processed 3,433 root addresses: 1,070 initial roots plus
2,363 additional direct-call or tail-jump candidates. These are candidate
entry addresses, **not** 3,433 validated function boundaries. It decoded
187,221 unique instruction addresses spanning 580,139 unique bytes, or 33.66%
of the 1,723,392 raw bytes in `.text`. The linear sweep remains the source for
section-wide byte decoding; this percentage means only that those bytes were
visited by the selected recursive paths.

| Static graph observation | Unique instruction/address count |
| --- | ---: |
| Processed root addresses | 3,433 |
| Basic-block candidates | 31,520 |
| Direct-call edges to executable targets | 13,652 |
| Conditional-branch sites, both sides explored | 15,850 |
| Exact IAT `call [address]` sites | 3,019 |
| Exact IAT tail-jump sites | 73 |
| Imported API names with at least one rooted transfer | 447 |
| Unresolved indirect calls | 3,537 |
| Unresolved indirect jumps | 123 |
| Unconditional-jump tail-call candidates | 147 |
| Instruction addresses attributed to multiple roots | 402 |

Among unresolved indirect calls, 1,632 use a register operand and 1,905 use a
memory operand. Of the 123 unresolved indirect jumps, 9 use a register operand
and 114 use a memory operand. Operand form does not establish whether a site
is a virtual call, callback, table lookup, or another dispatch mechanism. The
402 multiply attributed instruction addresses can reflect shared code or
function-boundary ambiguity; the scanner does not decide between them.

The machine-readable outputs preserve the seeded paths and their limitations:

- [Root/function candidates](rk-v4.6-rooted-cfg-functions.csv)
- [Call, import, branch, and unresolved-dispatch edges](rk-v4.6-rooted-cfg-edges.csv)
- [Basic-block candidates](rk-v4.6-rooted-cfg-blocks.csv)
- [Tool/input identities, detailed counts, imported API names, and limitations](rk-v4.6-rooted-cfg-summary.json)

## Rooted path from the dialog timer to HID enumeration

The newly seeded graph also links one `COemDrvDlg` `WM_TIMER` handler to the
existing HID-enumeration routine through decoded direct-call candidates:

| Step | Address evidence | Static interpretation |
| --- | --- | --- |
| MFC message-map seed | Handler `0x00449F80`, map entry `0x005DD1F0`, message `0x0113` | `COemDrvDlg` timer handler, as recorded in `rk-v4.6-mfc-message-map-entries.csv`. |
| Dialog to pool/enumerator setup | Call at `0x00449F9F` → `0x004497C0`; call at `0x004497D6` → `0x00417330` | Direct-call edges visited from the timer handler; `0x004497C0` is the table setup routine in the existing enumeration lifecycle audit. |
| HID interface enumeration | `0x00417330` calls wrapper `0x00590A14` at `0x0041734C`, `SetupDiGetClassDevsW` at `0x0041735C`, and `SetupDiEnumDeviceInterfaces` at `0x00417380` and `0x004173AF`; it calls `0x004173F0` at `0x00417396` | The wrapper tail-jumps to `HID.DLL!HidD_GetHidGuid`; the enumerator iterates present interfaces and delegates each interface to the per-interface helper. |
| Per-interface open and descriptor query | `0x004173F0` calls `CreateFileW` at `0x004174A1`/`0x004174B2`, `HidD_GetPreparsedData` at `0x004174CD`, `HidD_GetAttributes` at `0x004174DC`, and `HidP_GetCaps` at `0x004174EB` | The helper opens a matching path and queries descriptor metadata. Existing static analysis gives the access-mask and cleanup details; no interface was opened in this research. |

This is a **static candidate path**, not evidence that a timer fired or that a
keyboard was enumerated at runtime. The graph explores both sides of
conditional branches without evaluating conditions. The 4.6
`WM_DEVICECHANGE` handler `0x00449DF0` is a different root with four unresolved
indirect calls; this pass found no resolved direct-call route from it to the
enumerator, so that connection remains open. The per-interface helper's two
register-indirect `SetupDiGetDeviceInterfaceDetailW` calls at `0x00417421` and
`0x0041746F` are also still unresolved in this graph; their IAT load/use pattern
is documented in the [cross-version enumeration lifecycle audit](rk-device-enumeration-handle-lifecycle-cross-version.md).

## Reproduction

From the repository root, with Python 3, `pefile`, and Capstone 5.x available:

```powershell
python scripts/audit_rk46_rooted_cfg_callgraph.py `
  .research/rk4_6_official_extract_20261015/app/DeviceDriver.exe `
  --docs-dir docs --output-dir docs
```

The scanner refuses a different executable hash and refuses changed or missing
vtable-map CSV inputs. It regenerates the four machine-readable outputs above.

## Remaining graph gap and evidence limits

The original 4.6 full-function-map/CFG gap remains open. This pass does not
validate function starts or endings, classify all code versus embedded data,
or cover bytes outside its selected roots. The image's debug record names a
PDB path, but no matching PDB was available in this workspace. The MFC scan is
bounded to its accessor/table signature and does not prove complete MFC or
runtime dispatch coverage.

The principal unresolved remainder is 3,537 register/memory indirect-call
sites, 123 register/memory indirect-jump sites, 147 possible tail transfers,
and the 66.34% of `.text` raw bytes not visited from the selected roots. That
unvisited portion is not evidence of dead code or unreachable behavior. Direct
calls, IAT references, and explored branches are static candidates, not proof
that a path runs in a particular process state. Import presence does not prove
API success, device access, or keyboard effect.

This report narrows the function/dispatch gap with reproducible root-seeded
evidence; it does not close it or supersede the
[full-suite gap matrix](reverse-engineering-gap-matrix-2026-10-19.md).
