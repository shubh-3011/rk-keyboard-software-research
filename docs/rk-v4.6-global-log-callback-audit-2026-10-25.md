# 4.6 `DeviceDriver.exe`: shared global callback target-set audit

## Artifact and scope

This audit examines the 4.6-labeled `DeviceDriver.exe`, SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`, size
2,418,176 bytes, PE32 x86, image base `0x00400000`. The local extracted input
is `.research/rk46-extract-full/app/DeviceDriver.exe`; it is not committed to
the public repository.

The audit reconciles absolute references to callback cell `0x0063BE2C` in a
full `.text` linear sweep and the existing hash-pinned root-seeded CFG edge
ledger. It inspects the two code stores and nearby target bodies, then directly
decodes the startup/config-loader instruction starts that the linear sweep
misses. This is static evidence of a direct initializer call path, not proof
that the path executes in a running process or that any callback callsite runs.
No RK program or updater was launched, and no keyboard interface was opened.

## Reproducible census

Run from the repository root with the exact local binary present:

```powershell
python scripts\audit_rk46_global_log_dispatch.py
```

The script verifies the executable hash and the rooted-edge CSV hash
(`e0aa66be6a217ed04674457af9e5520ff5e8ff0645301810c2defa244b00ac6c`),
then writes the [callsite ledger](rk-v4.6-global-log-callback-callsite-ledger-2026-10-25.csv).
The ledger contains 289 addresses observed by one or both decoders; it retains
which evidence source found each address.

| Evidence source | Callback-call contexts/sites | Notes |
| --- | ---: | --- |
| Full `.text` linear sweep | 258 call instructions | Also found two direct stores to the cell; 260 absolute memory references total. |
| Existing root-seeded CFG ledger | 234 contexts / 234 distinct sites | The raw ledger labels these unresolved indirect calls. Each site has one root context. |
| Both scans at the same address | 203 sites | Same address and call operand found by both passes. |
| Rooted CFG only | 31 sites | The recursive pass decoded these at instruction starts absent from the linear sweep. |
| Linear sweep only | 55 sites | These do not appear as callback edges in the rooted ledger. |

These counts are not interchangeable coverage measures. The two passes start
decoding at different boundaries, so subtracting 234 from 258 would give a
false “missing callsite” count. The full-section sweep can decode embedded
data as instructions; the rooted scan is limited to its selected paths.

## Candidate callback targets

The full `.text` linear sweep found two immediate stores to the cell, both in
`0x0040D140`:

| Store | Value | Static interpretation |
| --- | --- | --- |
| `0x0040D18D` | `0x0040D000` | First assigned target; its body formats text and calls `KERNEL32!OutputDebugStringW` at `0x0040D068`. |
| `0x0040D23F` | `0x0040D090` | Later assignment on a selector-2 path after the `Log.txt` setup branch. |

The branch at `0x0040D186` compares global selector `0x0063BE28` with 2. The
nearby code calls `SHELL32!SHGetSpecialFolderPathW`, constructs a path using
`%s\\Log.txt`, and passes the mode string `w` to internal helper
`0x005761BA`. On the helper's failure branch it calls the debug-output target
with the string `Open Log failed`; on the other branch it can install
`0x0040D090` as the shared callback. The helper is a CRT-style wide-file-open
wrapper. Its nested open path reaches `KERNEL32!CreateFileW` at `0x0058AAC0`.
The callback body then formats timestamped text through the CRT stream helpers;
its conditional stream-flush path reaches `KERNEL32!WriteFile` at
`0x00582D95`. This establishes a static file-sink path in the binary, though
not a successful runtime write.

The `0x0040D090` body checks the selector, passes mode string `a` to the same
internal helper, emits `Open Log failed` through `OutputDebugStringW` on its
failure branch, and otherwise calls `KERNEL32!GetLocalTime` and formats a
timestamp. The stream path is `0x0040D120 -> 0x00576334 -> 0x005762A1`, with a
conditional flush through `0x0057ADEE -> 0x00583268 -> 0x00582B35` and
`WriteFile` callsites in that writer. This supports an append-style text-log
sink inference; flush conditions, API success, and runtime file contents are
not observed.

## Targeted initialization path

The prior linear-sweep negative result was caused by a missed instruction
boundary. Targeted disassembly from the known routine starts verifies this
direct chain:

| Address | Static evidence |
| --- | --- |
| `0x00448188` | `call 0x00456520` from the startup routine at `0x00448030`. |
| `0x00456573` | Loads the IAT entry at `0x005A63E0` (`KERNEL32!GetPrivateProfileIntW`) into `EBP`. |
| `0x00456590` | Calls that import indirectly after pushing section `OPT`, key `Debug`, default `0`, and the constructed `cfg.ini` path. |
| `0x00456592` | Stores the returned selector into `[0x0063BE28]`. |
| `0x00456597` | Directly calls the callback initializer `0x0040D140`. |

The package `app/Cfg.ini` is hash-pinned in the native API path report and
contains `[OPT] Debug=0`. If the reader selects that file, the selector is zero
and the initializer keeps the `OutputDebugStringW` callback target
`0x0040D000`; a missing key also uses the code's default zero. A non-package
configuration with selector 2 can take the conditional `Log.txt` branch and
replace that target with `0x0040D090` if the internal setup helper succeeds.
The initializer calls `SHGetSpecialFolderPathW` with `CSIDL=0` and
`fCreate=0`, then formats `%s\\Log.txt` into `0x00620948`; it does not test the
API's Boolean return before using that buffer. Microsoft defines `CSIDL=0` as
the virtual Desktop, while `CSIDL_DESKTOPDIRECTORY` (`0x10`) is the filesystem
directory, and documents that `SHGetSpecialFolderPathW` fails for virtual
folders ([CSIDL table](https://learn.microsoft.com/en-us/windows/win32/shell/csidl),
[API documentation](https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shgetspecialfolderpathw)).
Therefore the static path expression is known, but the resolved filename and
whether this branch can open a usable file are not established. The global path
prefix at `0x006354B8`, actual config-file selection, execution, and runtime
callback value remain unobserved; see the [native API path report](rk-v4.6-native-api-call-path-audit.md).

Thus the 234 rooted callsites have a constrained **candidate** target set of
`0x0040D000` or `0x0040D090` if this initializer runs and the cell is not
changed through another path. Two of these rooted sites, `0x00449E84` and
`0x00449F1E`, were already described as conditional logger callbacks in the
[rooted CFG audit](rk-v4.6-rooted-cfg-callgraph-audit.md); this follow-up
adds 232 more rooted sites with the same candidate set. These calls appear to
be logging dispatches, not keyboard transfers.

## What remains unknown

- The targeted `call 0x0040D140` at `0x00456597` is not present in the existing
  rooted edge ledger or the full-section linear-sweep decode. The linear sweep
  therefore still reports zero branch/immediate references, but that is a
  decoder-boundary miss, not evidence that no direct caller exists. A raw
  section search found no embedded 32-bit VA or RVA pointer to the initializer;
  the PE has no exports or TLS callback table. The relative direct call does
  not require an embedded absolute pointer.
- The linear sweep's 14 references to selector `0x0063BE28` are comparisons,
  but targeted decode finds a missed store at `0x00456592`. The 14-hit sweep is
  not a complete selector xref count; additional instruction-boundary misses
  or aliases have not been excluded.
- The callback cell's runtime value, initialization order, caller-specific
  message argument semantics, actual config-file selection, and whether the
  conditional CRT flush reaches a successful `WriteFile` are unobserved. The
  initializer uses `SHGetSpecialFolderPathW(CSIDL=0)` without checking its
  return, so the path buffer's runtime contents are unresolved.

The call chain narrows the 232 additional rooted sites to a shared callback
whose statically identified target selection depends on the selector and log
setup branch. They remain in the root CFG's conservative unresolved total
because a unique runtime target has not been established. The separate
callsite ledger is evidence for this specific executable hash only; it is not
a complete function map or a claim about other RK builds.
