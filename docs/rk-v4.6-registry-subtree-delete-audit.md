# V4.6 registry child-walk and delete path

## Evidence boundary

This static follow-up examines the `RegEnumKeyExW` reference in the exact
2,418,176-byte V4.6-labeled `DeviceDriver.exe`, SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`. The
binary was disassembled from disk. The RK executable was not run, and no
keyboard interface or registry key was opened or modified during this audit.

## Statically visible path

- IAT `0x005A6020` (`ADVAPI32!RegEnumKeyExW`) is loaded into `EBX` at
  `0x004ACF65` and called at `0x004ACFAC`. The call uses the current key handle,
  index zero, a child-name buffer, and a name-length pointer initialized to
  `0x100`.
- When enumeration returns success, the name buffer is passed at
  `0x004ACF6D` to `0x004ACEF8`. That helper opens a child key through
  `RegOpenKeyExW` at `0x004367A3` using a temporary local key wrapper. The
  visible helper returns a status, but does not directly call itself or pass
  the opened handle into a recursive call; the exact child-walk behavior is
  unresolved.
- When enumeration returns nonzero, the code closes the current key through
  `0x004367E0` and calls `0x004AC9FB` with the caller-fed path at
  `0x004ACFC5`.
- `0x004AC9FB` looks up `RegDeleteKeyExW` using `GetModuleHandleW` and
  `GetProcAddress`, caching the result. If that export is absent, it falls back
  to imported `RegDeleteKeyW` at `0x004ACA4F` / IAT `0x005A6030`.
- A `CSettingsStore` method at `0x004AD28B` reaches `0x004ACEF8` with a
  caller-provided string (call sequence `0x004AD2BB`–`0x004AD2C4`). The exact
  root key and caller strings are not established by this path trace.

## Interpretation and limits

The child-key enumeration/open sequence followed by a caller-path delete helper
places these APIs in a deletion-related path. It is consistent with an attempt
to handle keys with child entries, but the visible code does not establish
correct recursive traversal or removal of every descendant. The exact registry
branch, the role of the temporary opened handle, which UI action reaches the
method, and whether the code succeeds at runtime remain unresolved. Treat
“subtree deletion” as a purpose hypothesis, not proof of a working registry
cleanup workflow.

The import ledger classified this row as unresolved because its purpose was
not visible from the IAT load alone. This follow-up refines that classification
without claiming full control-flow reachability. See the
[unresolved-reference audit](rk-v4.6-unresolved-api-reference-audit.md),
[API call-site ledger](rk-v4.6-native-api-call-sites.csv), and
[unresolved API ledger](rk-v4.6-unresolved-api-references.csv).
