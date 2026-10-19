# RK DeviceDriver 4.6 recursive registry-key removal follow-up

## Scope and correction

This static follow-up rechecks the registry path in the 2,418,176-byte Hub
4.6-labeled `DeviceDriver.exe`, SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`.
The binary was extracted from the dated official installer without running the
installer or application. Neither the Windows registry nor a keyboard/device
interface was accessed.

The earlier [registry child-walk note](rk-v4.6-registry-subtree-delete-audit.md)
left recursion unresolved and said that `0x004ACEF8` did not call itself. That
reading was incorrect: the exact instruction at `0x004ACF7A` is a direct
relative call back to `0x004ACEF8`. The code contains a recursive child walk.
This addendum corrects that specific conclusion; it does not establish which
UI action reaches the method or which registry root/path is supplied at
runtime.

The hash-pinned reproduction script is
[`audit_rk46_registry_recursive_delete.py`](../scripts/audit_rk46_registry_recursive_delete.py).
Its 40-row instruction and call-edge ledger is
[`rk-v4.6-registry-recursive-delete-edge-ledger-2026-10-20.csv`](rk-v4.6-registry-recursive-delete-edge-ledger-2026-10-20.csv).

## Recovered call path

The relevant caller is the `CSettingsStore`-associated method already
identified at `0x004AD28B`. It passes a path derived from its arguments to
`0x004ACEF8` at `0x004AD2C4`. The address and arguments are static code
evidence; this pass does not identify the caller's visible UI action or the
actual registry path.

`0x004ACEF8` is a recursive routine with this behavior:

1. It calls the wrapper at `0x00436780` (`RegOpenKeyExW` IAT
   `0x005A6000`) to open the requested path under the wrapper's current parent
   HKEY. The requested access mask is the inherited wrapper flags OR
   `0x2001F`; the wrapper passes registry options `0` and stores the returned
   HKEY in its local wrapper.
2. It loads `ADVAPI32!RegEnumKeyExW` from IAT `0x005A6020` into `EBX` at
   `0x004ACF65`. At `0x004ACFAC` it enumerates the currently opened key from
   index zero, using a 0x100-WCHAR name capacity and null optional class/time
   arguments.
3. On status zero, it passes the child-name buffer to itself at
   `0x004ACF7A`, with the just-opened child key as the next parent HKEY. If a
   recursive call returns nonzero, the caller exits through cleanup and
   returns that error without deleting the current ancestor. If it returns
   zero, the loop starts again at index zero. This lets the parent revisit the
   first remaining child after the completed child was deleted.
4. When enumeration returns nonzero, it closes the currently opened HKEY and
   calls `0x004AC9FB` at `0x004ACFC5` to delete the original path from its
   parent. This is a post-order traversal in the decoded control flow: nested
   names are processed before their parent name.
5. The caller receives the delete status and converts zero to `true` and
   nonzero to `false` at `0x004AD2CE`–`0x004AD2D6`.

## Delete API selection and arguments

The helper at `0x004AC9FB` performs a one-time cached lookup. It calls
`GetModuleHandleW` with the UTF-16 string `Advapi32.dll` at `0x004ACA11`, then
`GetProcAddress` with the ASCII string `RegDeleteKeyExW` at `0x004ACA21`. The
strings are embedded in the same PE at `0x005ACE10` and `0x005ACE00`.

When the lookup returns a function pointer, the stack setup at
`0x004ACA3C`–`0x004ACA46` calls it as
`RegDeleteKeyExW(parentHKey, subKey, viewFlags, 0)`. The view flags come from
the registry wrapper's `+4` field. If the pointer is null, the helper calls
the imported `ADVAPI32!RegDeleteKeyW` at `0x004ACA4F` with
`(parentHKey, subKey)`. Import-table identities for `RegOpenKeyExW`,
`RegEnumKeyExW`, `RegCloseKey`, `RegDeleteKeyW`, `GetProcAddress`, and
`GetModuleHandleW` are pinned and emitted by the script.

The two cleanup calls on the current wrapper do not imply a second
`RegCloseKey`: wrapper code at `0x004367E0` closes a non-null HKEY and zeros
both the HKEY and stored flags. The later cleanup therefore sees a null handle
and is a no-op.

## Error behavior and remaining uncertainty

The enumeration branch tests only whether the returned `LSTATUS` is zero. Any
nonzero result follows the same close-and-delete path; this code does not
distinguish normal exhaustion from another `RegEnumKeyExW` error. A delete
failure is returned to the caller, and a child failure stops recursion and is
propagated upward. These branches describe the implementation, not whether a
particular operation succeeds against a real registry.

This closes the earlier static question of whether this helper recursively
walks and removes child keys: the decoded routine does. It does **not** prove
that the code is reachable in an ordinary run, that the parent HKEY is a
particular RK configuration hive, that the supplied names are safe or
expected, or that the algorithm succeeds for every registry state. The exact
UI-to-method route, concrete caller strings, indirect callers, concurrent
mutation behavior, and runtime results remain outside this static pass.

## Reproduction

After statically extracting the official package, run from the repository
root:

```powershell
python scripts/audit_rk46_registry_recursive_delete.py `
  .research/rk46-extract-full/app/DeviceDriver.exe `
  --output docs/rk-v4.6-registry-recursive-delete-edge-ledger-2026-10-20.csv
```

The script verifies the PE size and SHA-256, checks x86 PE32/import identities
and the two resolver strings, decodes executable sections with Capstone 5, and
emits only the selected boundaries, direct call xrefs, and import callsites.
It does not establish a complete CFG or execute any code.
