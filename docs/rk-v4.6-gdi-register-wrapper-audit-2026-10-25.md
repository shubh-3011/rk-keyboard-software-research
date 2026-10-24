# RK 4.6 GDI register-call wrapper audit

## Scope and evidence

This note follows the 13 `GDI32.dll` rows in the unresolved API-reference
ledger for the 4.6-labeled `DeviceDriver.exe`. The inspected PE is 2,418,176
bytes, SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`.
The file was disassembled statically; the RK program was not run and no HID
interface or keyboard was accessed.

The wrappers use `ECX` as an object pointer and read two handle-shaped fields
at object offsets `+4` and `+8`. The table below records the actual API
argument order after x86 stack pushes, rather than assigning unverified C++
parameter names. `arg` refers to the wrapper's stack argument at `[EBP+...]`.

| Imported API | Wrapper; IAT load; API call sites | API arguments, in call order | Wrapper result handling | Caller evidence |
| --- | --- | --- | --- | --- |
| `SaveDC` | `0x47838C`; `0x478398`; `0x4783A3`, `0x4783B0` | First `HDC=[ECX+8]` if nonzero, then `HDC=[ECX+4]` if distinct. | Saves the first call's EAX; if the second call succeeds, returns `-1`; otherwise returns the saved value (initially 0). | Vftable slot candidate; no direct caller found in the bounded CFG. |
| `RestoreDC` | `0x4783BF`; `0x4783CE`; `0x4783DD`, `0x4783EE` | `(HDC=[ECX+4], nSavedDC=arg[+8])`, then `(HDC=[ECX+8], same)`; second call is conditional on prior success. | Returns the API BOOL from the last call, with failure normalized to 0; the initialized 1 is returned if no call executes. | Vftable slot candidate; no direct caller found in the bounded CFG. |
| `SetBkMode` | `0x478434`; `0x478442`; `0x478451`, `0x47845E` | For each distinct/nonzero HDC: `(HDC, mode=arg[+8])`. | Returns EAX from the last API call, or 0 if no call. | 30 direct-call sites in the bounded CFG; listed in the evidence CSV. |
| `SetPolyFillMode` | `0x478466`; `0x478474`; `0x478483`, `0x478490` | For each distinct/nonzero HDC: `(HDC, mode=arg[+8])`. | Returns EAX from the last API call, or 0 if no call. | No direct caller or exact vftable pointer found in the bounded evidence. |
| `SetROP2` | `0x478498`; `0x4784A6`; `0x4784B5`, `0x4784C2` | For each distinct/nonzero HDC: `(HDC, mode=arg[+8])`. | Returns EAX from the last API call, or 0 if no call. | Direct-call sites `0x55FE55`, `0x560030`. |
| `ExcludeClipRect` | `0x478544`; `0x47854A`; `0x47856D`, `0x478582` | For each HDC: `(HDC, left=rect[0], top=rect[+4], right=rect[+8], bottom=rect[+0xC])`, with the rectangle pointer at `arg[+8]`. | Returns EAX from the last API call, or 0 if no call; the result is not combined across handles. | 7 direct-call sites in the bounded CFG; listed in the evidence CSV. |
| `SetTextAlign` | `0x478609`; `0x478619`; `0x478628`, `0x478635` | For each HDC: `(HDC, flags=arg[+8])`. | Ignores the first call's result; returns the second-HDC result, or initialized `-1` if that call is skipped. | No direct caller or exact vftable pointer found in the bounded evidence. |
| `SelectClipRgn` | `0x478B68`; `0x478B7A`; `0x478B8E`, `0x478BA4` | For each HDC: `(HDC, regionHandle)`, where `regionHandle` is `[regionObject at arg[+8] + 4]`, or NULL when the object is NULL. | Returns EAX from the last API call, or 0 if no call. | 15 direct-call sites in the bounded CFG; listed in the evidence CSV. |
| `OffsetViewportOrgEx` | `0x478997`; `0x4789A3`; `0x4789B8`, `0x4789CB` | For each HDC: `(HDC, x=arg[+0xC], y=arg[+0x10], lppt=arg[+8])`. | Discards the API result and returns `arg[+8]`. | Vftable slot candidate; no direct caller found in the bounded CFG. |
| `ScaleViewportExtEx` | `0x478A15`; `0x478A21`; `0x478A3C`, `0x478A55` | For each HDC: `(HDC, xNum=arg[+0xC], xDenom=arg[+0x10], yNum=arg[+0x14], yDenom=arg[+0x18], lpSize=arg[+8])`. | Discards the API result and returns `arg[+8]`. | Vftable slot candidate; no direct caller found in the bounded CFG. |
| `OffsetWindowOrgEx` | `0x478A9F`; `0x478AAB`; `0x478AC0`, `0x478AD3` | For each HDC: `(HDC, x=arg[+0xC], y=arg[+0x10], lppt=arg[+8])`. | Discards the API result and returns `arg[+8]`. | No direct caller or exact vftable pointer found in the bounded evidence. |
| `ScaleWindowExtEx` | `0x478B1D`; `0x478B29`; `0x478B44`, `0x478B5D` | For each HDC: `(HDC, xNum=arg[+0xC], xDenom=arg[+0x10], yNum=arg[+0x14], yDenom=arg[+0x18], lpSize=arg[+8])`. | Discards the API result and returns `arg[+8]`. | Vftable slot candidate; no direct caller found in the bounded CFG. |
| `ExtSelectClipRgn` | `0x478C6E`; `0x478C80`; `0x478C97`, `0x478CB0` | For each HDC: `(HDC, regionHandle, mode=arg[+0xC])`; `regionHandle` is `[regionObject at arg[+8] + 4]`, or NULL. | Returns EAX from the last API call, or 0 if no call. | Direct-call sites `0x48FDBD`, `0x48FDF2`. |

The vftable observations are static address-taking evidence, not proof that
any method was invoked. The RTTI-bearing address points are `CDC` at
`0x005A739C`, `CClientDC` at `0x005A741C`, `CWindowDC` at `0x005A749C`, and
`CPaintDC` at `0x005A751C`. Each has the same five relevant slots: `SaveDC`
at `+0x1C`, `RestoreDC` at `+0x20`, `OffsetViewportOrgEx` at `+0x3C`,
`ScaleViewportExtEx` at `+0x44`, and `ScaleWindowExtEx` at `+0x4C`. Their
type descriptors and slots are checked by the companion verifier.

The caller lists are limited to direct-call edges in the selected
root-seeded CFG ledger. Its traversal covers 33.80% of raw `.text` bytes and
does not resolve arbitrary indirect calls or establish runtime reachability.
Accordingly, “no direct caller found” means no caller was found in those
bounded inputs; it is not proof that a wrapper is unused. The machine-readable
per-row evidence is in
[`rk-v4.6-gdi-register-wrapper-evidence-2026-10-25.csv`](rk-v4.6-gdi-register-wrapper-evidence-2026-10-25.csv).
The hash-pinned checks are in
[`audit_rk46_gdi_register_wrappers.py`](../scripts/audit_rk46_gdi_register_wrappers.py).
The existing reconciled API-site ledger is unchanged; this report does not
duplicate its API call rows.

Run the verifier from the repository root with:

```powershell
python scripts/audit_rk46_gdi_register_wrappers.py `
  --binary ..\.research\rk4_6_official_extract_20261015\app\DeviceDriver.exe `
  --evidence docs/rk-v4.6-gdi-register-wrapper-evidence-2026-10-25.csv `
  --edges docs/rk-v4.6-rooted-cfg-edges.csv
```
