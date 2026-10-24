# 4.6 `CClrPanelDlg` indirect string-manager dispatch

## Scope

This bounded static trace covers one `CClrPanelDlg` message handler in the
hash-pinned 4.6 `DeviceDriver.exe` (SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`). It
does not establish runtime delivery or feature semantics. No RK executable,
keyboard interface, or updater was run.

## Evidence

- The existing [MFC message-map ledger](rk-v4.6-mfc-message-map-entries.csv)
  maps `CClrPanelDlg` message `0x0801` at map row `0x005D0A90` to handler
  `0x004065E0`.
- At `0x00406609`, the handler calculates its second argument minus `0x0877`
  and compares the result with 2. Thus the selected dispatch is gated on
  argument values `0x0877` through `0x0879`.
- At `0x0040662E–0x00406635`, the handler loads the object vtable, reads slot
  `+0x0C`, and calls it indirectly. The object vtable is at `0x005A711C`;
  slot `+0x0C` points to `0x00477DED`.
- The vtable's MSVC Complete Object Locator at `0x005E4A38` points to Type
  Descriptor `0x006074E0`, whose decorated name is `.?AVCAfxStringMgr@@`.
- The target at `0x00477DED` is `33 D2 8D 41 10 42 F0 0F C1 10 8D 41 04 C3`.
  It atomically increments the 32-bit value at `this+0x10` and returns
  `this+4`. The caller adds `0x10` to that result and passes it to an internal
  string helper.

The trace identifies this indirect edge as a `CAfxStringMgr` reference-count
operation; it does not decode the caller's user-visible string or infer a
keyboard action from the private message values. No direct device report is
visible in the selected dispatch.

## Reproduction

From the repository root:

```powershell
python scripts\audit_rk46_clr_string_manager_dispatch.py --binary ..\.research\rk4_6_official_extract_20261015\app\DeviceDriver.exe
```

The verifier checks the input hash, MFC map row, handler bytes, vtable slot,
RTTI name, and helper bytes.
