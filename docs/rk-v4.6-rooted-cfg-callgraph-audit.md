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
  `CDevG5KB` and `CDevRKKB` vtable maps; and
- all 27 entries in the RTTI-identified `CDev3632` vtable associated by the
  selector with profile `0208`/M20.

The MFC map scanner is
[`audit_rk46_mfc_message_maps.py`](../scripts/audit_rk46_mfc_message_maps.py),
SHA-256 `daa5de4f086feb16af840a8ac80b9e5f6228bdcf9ff45a0a85da027194afa4ab`.
The CFG scanner is
[`audit_rk46_rooted_cfg_callgraph.py`](../scripts/audit_rk46_rooted_cfg_callgraph.py),
SHA-256 `5c0a723102c59817bac022f45a4fb26b78a2f41fe7149524de307e7fb69ebd21`.
The three vtable-map inputs are hash-checked by the scanner:

| Root evidence input | SHA-256 |
| --- | --- |
| `rk-v4.6-cdevg5-vtable-map.csv` | `6c994b3f91c0d40e4302e9e29d2e9e5da4a0d74b82635662a579e86ae71384e1` |
| `rk-v4.6-cdevrkbb-vtable-map.csv` | `7086073683dd51e8531ca607ab3afa9b1a7508fed4e46e964a40fd8af42bd862` |
| `rk-v4.6-cdev3632-vtable-map.csv` | `9f51961237cee31fce47d174ce0872b66569ab87ff6bb5697771fa5d33f16f1a` |

The `CDev3632` entries come from the separate [Fw=3 vtable audit](rk-v4.6-fw3-cdev3632-vtable-audit.md), which proves the table address and RTTI name from the same image hash. The row-level root input is [here](rk-v4.6-cdev3632-vtable-map.csv). Its inclusion expands the seed evidence to the `Fw=3`/M20 class; it does not prove that this physical model was connected or that a branch ran.

The scan follows decoded conditional branches both ways and recursively adds
internal direct-call targets as function-root candidates. Exact absolute IAT
memory operands are matched to this PE's ordinary/delay import tables.
Unconditional jumps into another seed or a common x86 frame prologue are
recorded as tail-jump candidates; other direct unconditional jumps are followed
as branch candidates. It does not evaluate branch conditions or resolve
register, vtable, callback, COM, or computed targets.

## Results

The hash-pinned run processed 3,450 root addresses: 1,085 initial roots plus
2,365 additional direct-call or tail-jump candidates. The initial set contains
77 proven vtable-entry rows that reduce to 52 unique executable targets. These
are candidate entry addresses, **not** 3,450 validated function boundaries.
It decoded 187,974 unique instruction addresses spanning 582,534 unique bytes,
or 33.80% of the 1,723,392 raw bytes in `.text`. The linear sweep remains the
source for section-wide byte decoding; this percentage means only that those
bytes were visited by the selected recursive paths.

| Static graph observation | Edge contexts / roots | Unique sites or addresses |
| --- | ---: | ---: |
| Processed root candidates | 3,450 | — |
| Unique initial roots | 1,085 | — |
| Proven vtable-entry rows / executable targets | 77 | 52 |
| Decoded instruction addresses | — | 187,974 |
| Decoded instruction bytes | — | 582,534 (33.80% of `.text`) |
| Basic-block candidates | — | 31,639 |
| Direct calls to executable targets | 13,723 | 13,677 |
| Conditional-branch sites, both sides explored | 15,930 | 15,902 |
| Exact IAT `call [address]` sites | 3,034 | 3,030 |
| Exact IAT tail-jump sites | — | 73 |
| Rooted IAT transfer sites, including tail jumps | — | 3,103 |
| Imported API names with at least one rooted transfer | — | 447 |
| Unresolved indirect-call contexts / sites before manual review | 3,568 | 3,564 |
| Unresolved indirect-jump sites | — | 123 |
| Unconditional-jump tail-call candidates | — | 147 |
| Instruction addresses attributed to multiple roots | — | 402 |

The generated scanner ledger labels 3,568 edge contexts (3,564 distinct
instruction sites) as unresolved indirect calls before manual review. This
report now reclassifies six sites: four in `WM_DEVICECHANGE` and the two
`SetupDiGetDeviceInterfaceDetailW` transfers below. Four `SHAppBarMessage`
transfers are also resolved below, leaving 3,558 contexts (3,554 distinct
sites) unresolved by the combined evidence. The
generated CSV remains unchanged and conservatively retains the two SetupAPI
calls as unresolved because its automated register analysis does not
propagate the `EBP` definition across this branch-spanning sequence.

A separate [global callback audit](rk-v4.6-global-log-callback-audit-2026-10-25.md)
finds 234 rooted callsites through absolute cell `0x0063BE2C` and constrains
their candidate targets to two logger-shaped routines assigned by
`0x0040D140`. This adds 232 sites to the earlier two callback observations.
Targeted decoding verifies a direct startup-to-config-loader-to-initializer
chain (`0x00448188 -> 0x00456520 -> 0x00456597 -> 0x0040D140`) and a
`GetPrivateProfileIntW` result store to selector `0x0063BE28`. The linear sweep
missed these instruction boundaries, so its zero-reference conclusion was
incorrect. The actual runtime config selection and callback target remain
unobserved; the conservative 3,558 / 3,554 unresolved totals below are retained
because the callback target is conditional. The follow-up also records 258
full-section linear-sweep calls and explains the different instruction-boundary
counts between scans.

Before the manual follow-up, the raw call ledger had 1,648 register-operand and
1,920 memory-operand unresolved call contexts. Reclassifying the two `ESI`
calls to `SetTimer`, two absolute-global logger calls, the two `EBP` calls to
`SetupDiGetDeviceInterfaceDetailW`, and four `EDI` calls to
`SHAppBarMessage` leaves 1,640 register-operand and 1,918 memory-operand
contexts unresolved. Of the 123
unresolved indirect jumps, 9 use a register operand and 114 use a memory
operand. Operand form does not establish whether a site is a virtual call,
callback, table lookup, or another dispatch mechanism. The 402 multiply
attributed instruction addresses can reflect shared code or function-boundary
ambiguity; the scanner does not decide between them.

### Four auto-hide appbar probes

Function `0x0048FF62` loads the `SHAppBarMessage` IAT slot at `0x005A6544` and
makes four indirect calls at `0x0049003D`, `0x0049005D`, `0x00490079`, and
`0x00490099`. Each call uses message `7` (`ABM_GETAUTOHIDEBAR`) and a local
`APPBARDATA` whose `cbSize` is `0x24`; the code sets `uEdge` in order to
`3`, `1`, `0`, and `2`, then sets bits `0x08`, `0x04`, `0x01`, and `0x02` in
the receiver's field `+0x1B4` when the corresponding call returns nonzero.
The message retrieves an auto-hide appbar for the specified edge, and the
`APPBARDATA.uEdge` field identifies that edge ([message documentation](https://learn.microsoft.com/en-us/windows/win32/shell/abm-getautohidebar),
[structure documentation](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/ns-shellapi-appbardata)).
The later meaning and use of the accumulated mask remain unresolved. This
manual classification reduces the unresolved indirect-call count by four;
the original scanner CSV/JSON are preserved and still show their pre-review
counts. Exact bytes and the import mapping are in the [focused ledger](rk-v4.6-appbar-edge-probe.csv)
and [hash-pinned verifier](../scripts/audit_rk46_appbar_edges.py).

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
conditional branches without evaluating conditions.

### `WM_DEVICECHANGE` to the rescan timer

The four indirect calls initially reported for the 4.6 `WM_DEVICECHANGE`
handler `0x00449DF0` can be resolved from its local code and data references:

| Callsite | Static target evidence | Interpretation |
| --- | --- | --- |
| `0x00449E84` and `0x00449F1E` | Both call `[0x0063BE2C]`. Initializer `0x0040D140` writes `0x0040D000` to that cell at `0x0040D18D`; on the non-2 selector branch it writes `0x0040D090` at `0x0040D23F`. The handler passes log strings including `OnDeviceChange: Device %04x_%04x %s` and `Device: path_string_to_id failed`. | Conditional logging callback; the callback value depends on the initialized selector at `0x0063BE28`. These calls are not HID transfers. |
| `0x00449ED3` and `0x00449EEB` | `0x00449EB6` loads `ESI` from IAT VA `0x005A67D4`, which is `USER32.dll!SetTimer`; both indirect calls invoke that register value. | Resolved timer API calls. The first requests timer `0x844` at 2,000 ms and saves the return value at object offset `+0x120C`; the second requests timer `0x845` at 500 ms and saves the return at `+0x1210`. |

The handler first filters the HID interface path using `StrStrIW` and the
wide-string marker `pid&fa07`. For device-arrival/removal event values
`0x8000`/`0x8004`, if its busy field at `+0x120C` is clear, it schedules those
two timers; the removal branch also calls `0x0044A040`. The `WM_TIMER` handler
`0x00449F80` compares its timer ID with the saved `+0x120C` value. For that
rescan timer it calls table setup `0x004497C0`, which calls HID enumerator
`0x00417330`; for timer `0x845` it calls the separate follow-up handler
`0x00438150`. Thus the static call chain now connects a filtered
`WM_DEVICECHANGE` notification to a delayed HID rescan, with all four indirect
calls in the notification handler resolved. Branch conditions, timer success,
Windows message delivery, and actual rescan results remain unobserved.

### Per-interface SetupAPI detail calls

The two register-indirect calls in `FUN_004173F0` are both statically
attributed to `SETUPAPI!SetupDiGetDeviceInterfaceDetailW`, not left as unknown
indirect transfers. The image import table places the function at IAT VA
`0x005A6510`; instruction `0x00417400` loads that pointer into `EBP`. No
instruction writes `EBP` between that load and calls at `0x00417421` and
`0x0041746F`. The later `lea ebp,[esi+4]` at `0x00417494` occurs only after
both API calls. The generated rooted-CFG edge CSV still labels these rows
`unresolved_indirect_call`: its automated pass does not propagate this register
definition across the branch. This section records the separate manual
instruction-level resolution.

At `0x00417413`–`0x00417421`, the helper copies incoming `ECX` and `EDX` to
`EDI` and `EBX`, then pushes six parameters in reverse order:

| API parameter | Value at the first call (`0x00417421`) | Value at the second call (`0x0041746F`) |
| --- | --- | --- |
| `DeviceInfoSet` | `EDI`, copied from incoming `ECX` | same `EDI` |
| `DeviceInterfaceData` | `EBX`, copied from incoming `EDX` | same `EBX` |
| `DeviceInterfaceDetailData` | `NULL` | allocated detail buffer in `ESI` |
| `DeviceInterfaceDetailDataSize` | `0` | required size cached at `[ESP+0x10]` before argument pushes |
| `RequiredSize` | pointer formed by `lea eax,[esp+0x18]` at `0x0041740A` and pushed at `0x0041740E` | pointer to the same local DWORD, formed by `lea ecx,[esp+0x18]` at `0x00417460` and pushed at `0x00417464` |
| `DeviceInfoData` | `NULL` | `NULL` |

After the first call, the helper reads the DWORD written through `RequiredSize`
at `[ESP+0x14]`, pushes that value, and passes it to helper `0x00575360`; the
helper's return is retained in `ESI` as the second call's detail buffer. The
first API call's Boolean return in `EAX` is not tested. The caller checks
whether the helper returned a buffer at `0x00417436`, taking its error path
only if `ESI` is null. The helper has no explicit zero-size rejection: its
strategy-1 branch substitutes one for a zero request (`0x005753A5`–
`0x005753B1`), its strategy-3 branch passes the value to another allocator
before falling back, and the fallback path changes zero to one and aligns it
to 16 (`0x005753C3`–`0x005753D7`). Thus the caller does not directly reject a
zero `RequiredSize`.
Before the second API call, `mov dword ptr [esi],6` sets the detail
structure's leading `cbSize` field; the second API call's Boolean return is
tested at `0x00417471`.

This matches the documented two-call SetupAPI size-query and retrieval
pattern: the first call uses a null detail pointer, size zero, and valid
`RequiredSize`; the second supplies a buffer sized from that output. On the
success branch, the path pointer `ESI+4` is passed to `CreateFileW` at
`0x004174A1` or `0x004174B2`. The code therefore statically connects the
imported API pointer through both calls to the interface-path buffer used by
the subsequent open attempt. The API's runtime return values, actual path,
open result, selected physical device, and Windows message reachability remain
unobserved. See the [cross-version enumeration lifecycle audit](rk-device-enumeration-handle-lifecycle-cross-version.md)
for the surrounding handle and capability path and the
[Microsoft API reference](https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdigetdeviceinterfacedetailw)
for the function signature and documented size-query procedure.

## Reproduction

From the repository root, with Python 3, `pefile`, and Capstone 5.x available:

```powershell
python scripts/audit_rk46_rooted_cfg_callgraph.py `
  ..\.research\rk4_6_official_extract_20261015\app\DeviceDriver.exe `
  --docs-dir docs --output-dir docs
```

The scanner refuses a different executable hash and refuses changed or missing
vtable-map CSV inputs. It regenerates the four machine-readable outputs above.
The extracted vendor binary is kept outside the public repository; provide its
local path in place of the example path when reproducing this audit elsewhere.

## Remaining graph gap and evidence limits

The original 4.6 full-function-map/CFG gap remains open. This pass does not
validate function starts or endings, classify all code versus embedded data,
or cover bytes outside its selected roots. The image's debug record names a
PDB path, but no matching PDB was available in this workspace. The MFC scan is
bounded to its accessor/table signature and does not prove complete MFC or
runtime dispatch coverage.

The principal unresolved remainder is 3,558 register/memory indirect-call
edge contexts (3,554 distinct sites), 123 register/memory indirect-jump sites,
147 possible tail transfers, and 1,140,858 bytes (66.20%) of `.text` not
visited from the selected roots. The CSV and JSON outputs preserve the
scanner's pre-follow-up raw counts of 3,568 call contexts and 3,564 distinct
sites; this report reclassifies the four resolved handler sites, two resolved
SetupAPI calls, and four resolved `SHAppBarMessage` calls. That
unvisited portion is not evidence of dead code or unreachable
behavior. Direct calls, IAT references, and explored branches are static
candidates, not proof that a path runs in a particular process state. Import
presence does not prove API success, device access, or keyboard effect.

The shared callback follow-up identifies a static initializer call chain and a
conditional logger target set for 232 additional rooted callsites, but does not
reclassify those as single-target resolved edges because the runtime selector
and log setup outcome are unknown. Its separate 258-call linear-sweep count is
not added to the rooted totals; 31 rooted call addresses are absent from that
sweep, and 55 swept addresses are absent from the rooted edge ledger.

This report narrows the function/dispatch gap with reproducible root-seeded
evidence; it does not close it or supersede the
[full-suite gap matrix](reverse-engineering-gap-matrix-2026-10-19.md).
