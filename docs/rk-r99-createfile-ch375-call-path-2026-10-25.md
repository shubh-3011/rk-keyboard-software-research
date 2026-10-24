# R99 CreateFileA-to-CH375 transport path — 2026-10-25

## Scope and binary identity

This static follow-up traces one imported native API call in the R99
`RK Driver.exe` into its CH375 helper calls and request/response worker. The
pinned x86 PE is the extracted R99 package's `RK Driver.exe`, SHA-256
`61dd118400a4652ba053db6ceb87cdd865e183f59822948ea9018da218aec2e5`. It was
not launched. No keyboard HID interface, device report, updater, or bootloader
was accessed.

The reproduction script is
[`audit_r99_createfile_ch375_path.py`](../scripts/audit_r99_createfile_ch375_path.py).
The 37-row instruction/import ledger is
[`rk-r99-createfile-ch375-path-evidence-2026-10-25.csv`](rk-r99-createfile-ch375-path-evidence-2026-10-25.csv).
Run it against the matching extracted executable:

```powershell
python scripts\audit_r99_createfile_ch375_path.py `
  --binary '..\.research\rk-selector-software-2026-10-19\R99-Inno-extracted\app\RK Driver.exe'
```

## Import and callsites

The import table maps `KERNEL32!CreateFileA` to IAT VA `0x0057B0A8`. The hash-
pinned executable has three direct calls at `0x0041AED9`, `0x00475020`, and
`0x00475358`, plus the IAT tail-jump thunk at `0x00487760`. The latter two
direct calls sit in separate SetupAPI enumeration routines; this report
expands only the CH375 path at `0x0041AED9`. The per-binary native API ledger
contains the complete direct-call inventory.

The worker at `0x0041A9D0` calls opener `0x0041AE40` at `0x0041AA99`. That
opener enumerates CH375 indices `0..15` through the imported helper thunks:

1. `CH375OpenDevice(index)` at `0x0041AE56`.
2. `CH375GetUsbID(index)` at `0x0041AE61`; the low word is compared to
   `0x4348`, and the high word to `0x55E0`.
3. On a match, `CH375GetDeviceName(index)` at `0x0041AE7B` returns a path
   copied into the worker object's inline path list, whose first string begins
   at `object+5` (`0x0041AE48` establishes the base).

The function later passes that first string pointer as `lpFileName` to
`CreateFileA`. The listed VID/PID values and path source are facts about this
R99 binary, not a universal RK identity rule or a claim about the connected
S98.

## CreateFileA arguments and handle flow

At `0x0041AED9`, the seven pushed arguments decode to:

| Parameter | Value established from stack setup |
|---|---|
| `lpFileName` | First candidate path at `object+5` |
| `dwDesiredAccess` | `0xC0000000` (`GENERIC_READ | GENERIC_WRITE`) |
| `dwShareMode` | `3` (`FILE_SHARE_READ | FILE_SHARE_WRITE`) |
| `lpSecurityAttributes` | `NULL` |
| `dwCreationDisposition` | `3` (`OPEN_EXISTING`) |
| `dwFlagsAndAttributes` | `0x80` (`FILE_ATTRIBUTE_NORMAL`) |
| `hTemplateFile` | `NULL` |

On the successful branch, the return value is saved in `ESI`, passed with
exclusive flag `1` to `CH375SetExclusive` (`0x0041AEF2`), and passed twice as
`1000` to `CH375SetTimeout` (`0x0041AF02`). The opener returns that handle in
`EAX` at `0x0041AF17`. Its only direct caller stores `EAX` into the worker
object at `0x0041AA9E`; the worker then passes the stored value to transfer
routine `0x0041AF20` at `0x0041AACB`.

That routine calls the imported `CH375WriteData` thunk at `0x0041AF64` with a
four-byte local request containing `0x0281`, then calls `CH375ReadData` at
`0x0041AFA1` and checks response bytes. Other worker paths contain a separate
`0x0283` request (`0x0041B009`, `0x0041B024`) and a chunked write loop
(`0x0041B0D6`). The CH375 export-to-`DeviceIoControl` buffer contracts are
documented in the [helper IOCTL follow-up](rk-r99-ch375-ioctl-read-write-audit-2026-10-25.md).
The purpose and device-side meaning of `0x0281`/`0x0283` remain unresolved.

## Error-path observation

The opener compares `CreateFileA`'s result with `-1` at `0x0041AEE1`; on that
branch it returns the unchanged value `-1`. Its caller checks only whether the
returned value is zero (`test eax,eax` at `0x0041AAA0`). The `-1` result
therefore passes that zero-only check and is carried into the transfer path.
Microsoft's [CreateFileA reference](https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-createfilea)
documents `INVALID_HANDLE_VALUE` as the failure result. This is a statically
proven control-flow discrepancy with a likely invalid-handle continuation; it
does not prove that an open failed in a real run or that any device request
was accepted. The ignored return values from the `SetExclusive` and
`SetTimeout` calls are also visible in the successful-open block.

## Evidence classification and remaining unknowns

- **Proven statically:** the IAT entry, the three direct call addresses, the
  selected caller chain, the path source, all seven `CreateFileA` arguments,
  the return-value stores/checks, and the downstream CH375 helper calls.
- **Inferred:** the API opens the selected CH375 path for host read/write
  transport; the function names and request construction suggest the intended
  setup/handshake roles.
- **Unresolved:** whether any branch ran, whether the path was a keyboard on a
  particular PC, why the caller only checks for zero, the meaning of request
  values `0x0281` and `0x0283`, device acceptance, cleanup on each worker exit,
  and the two separate SetupAPI `CreateFileA` call paths.

The trace advances one R99 native API path; it is not a complete R99 call
graph or a complete import-use audit.
