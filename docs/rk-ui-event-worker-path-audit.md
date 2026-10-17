# RK UI event and device worker path audit

This audit traces one app-owned `WM_COMMAND` handler through profile-file
persistence, device lookup, and a background worker. It is a static analysis
of the installed x86 executable. The RK application was not run and no
keyboard interface or report was opened or used.

## Command `0x6401`: close, save, and signal

The `COemDrvDlg` message map associates command `0x6401` with handler
`0x00446820`. The handler looks up top-level windows named
`OemDrvMacroTopWindow` and `OemDrvMsgTopWindow`. For each found window it calls
`SendMessageW(hwnd, 0x10, 0, 0)`, where `0x10` is `WM_CLOSE`.

If global profile-state flag `0x00611794` is nonzero, the handler calls
`0x0045ABF0` and `0x0045AD40` with active ID `0x0061175C`:

- `0x0045ABF0` formats a path using `%s%04X\\%s` and filename `pro.dct`. It
  opens the path with `CreateFileW` for read/write and `CREATE_ALWAYS`, then
  loops over device objects and passes each eligible object address and a
  `0x3E74`-byte length to `WriteFile`. The internal layout of this file range
  is not decoded.
- `0x0045AD40` uses the same path format with filename `curid.dct` and writes
  four bytes from global `0x0062B38C`. The meaning of those four bytes is not
  established.

The handler then scans 18-byte records beginning at `0x006102A0`. It compares
the active ID against the 16-bit word at record offset `+2`; on a match it
passes the word at offset `+0` and the active ID to `0x004598A0`. That lookup
compares the candidate VID and PID against live device-object fields at
`+0x248` and `+0x24A`. If it finds an object whose event field at `+0x25C` is
nonzero, the handler calls `SetEvent` on that handle. If global flag
`0x0061973C` is set, a separate branch sleeps for `0x7D0` milliseconds before
the dialog sends itself `WM_CLOSE`.

## What receives the event

The device-family setup path at `0x00456F90` checks the `OPT\\SendSysParam`
value loaded into global `0x00611820`. If the value is positive, it creates an
unnamed event with all `CreateEventW` arguments zero, stores the handle in
device-object field `+0x25C`, and starts thread function `0x004566C0` with that
device node as its parameter. The thread logs `SysParam_Thread start` with its
PID and timeout. It calls `WaitForSingleObject` on `+0x25C`, using
`SendSysParam` as the timeout.

When the wait returns `WAIT_OBJECT_0`, the thread calls `CoUninitialize`, logs
`SysParam_Thread exit`, and returns. This is the event set by command `0x6401`:
the direct effect of that event branch is to stop the worker. A failed or
other unexpected wait result takes an error/logging exit. If the event is set
while a timed operation is already running, static analysis cannot establish
whether that operation finishes before the next wait observes the signal.

On `WAIT_TIMEOUT`, the worker reads `OPT\\SysParamMask` (default `7`) and
`OPT\\SendOnlyDataChanged`, constructs a 14-byte buffer from host-side state,
and dispatches a virtual method at device vtable offset `+0x48`. The timeout
branch returns to the wait, so the code statically implements a repeated wait
cycle until signaled or an error occurs. Actual runtime cadence was not
observed; the configured wait timeout does not include time spent in the
sampling and family operation. The exact meaning of every buffer byte is not
recovered.

## Values in the installed profiles

The installed catalog has 21 profiles with a `SendSysParam` value: 15 use
`1000` and six (`0147`, `0163`, `0169`, `0175`, `01AC`, and `01FB`) use `2000`.
The 15 profiles with value `1000` also set `SendOnlyDataChanged=1` and
`SysParamMask=5`. All eight installed S98 profiles are in this group:

| S98 profile | `SendSysParam` | `SendOnlyDataChanged` | `SysParamMask` |
| --- | ---: | ---: | ---: |
| `0174` | `1000` | `1` | `5` |
| `01AF` | `1000` | `1` | `5` |
| `01BF` | `1000` | `1` | `5` |
| `0223` | `1000` | `1` | `5` |
| `0224` | `1000` | `1` | `5` |
| `022B` | `1000` | `1` | `5` |
| `022F` | `1000` | `1` | `5` |
| `0230` | `1000` | `1` | `5` |

These are stored profile values, not proof that a particular profile is
selected for the connected keyboard. In the worker, the `SendSysParam` value
is passed as the `WaitForSingleObject` timeout; Windows measures that timeout
in milliseconds. The active configuration and observed dispatch cadence
remain unverified.

## Family-specific timed operation

RTTI-backed vtable entries give different `+0x48` implementations:

| Device class | Vtable slot `+0x48` | Static path |
| --- | --- | --- |
| `CDevRKKB` | `0x0040D060` | Returns false without an identified HID operation in this slot. |
| `CDevG5KB` | `0x00410720` | Waits 30 ms, reads 128 bytes through `FUN_0040FAD0` (G5 command `0x84`), waits 30 ms, then calls `FUN_0040FA50` to write that buffer with G5 `SetLED` command `4`. |
| `CDev3632` | `0x0040E5D0` | Waits 30 ms, reads 128 bytes through command `0x44`, then writes the buffer through command `4`. |

The worker's timeout path can therefore perform an active read-modify-write
for the G5 and 3632 families. Each family method reads and writes its own
128-byte LED configuration buffer. How that operation relates to the worker's
14-byte candidate buffer is unresolved. This is a static call-path finding,
not an observed run. The profile-family map places the named S98 profiles in
`CDevG5KB`, so a matching S98 worker would select the G5 implementation if
this path runs.

## Evidence status and limits

- **Proven statically:** command-to-handler mapping; the two helper-window
  titles and `WM_CLOSE` calls; the `.dct` filenames, path format, file API
  calls, and byte counts; the PID-to-VID lookup flow; the `SetEvent` call; the
  event wait/exit branch; the `OPT` key names; and the family-specific vtable
  targets and G5/3632 HID read/write paths.
- **Inferred from API and class structure:** the event is an unnamed
  auto-reset event. The timeout loop is statically repeated, but the active
  object instance and its observed scheduling were not examined at runtime.
- **Unresolved:** the on-disk schema for the `0x3E74`-byte range, the meaning
  of the four bytes written to `curid.dct`, every field in the worker's
  14-byte buffer, how that buffer relates to the family LED read/write,
  whether other runtime branches complete an in-flight keyboard operation
  before the worker exits, and observed runtime scheduling.

No keyboard I/O, report capture, RK application launch, or updater launch was
performed. See the [main reverse-engineering report](reverse-engineering.md)
for the broader HID and model-family analysis, and the
[profile-to-driver-family map](rk-profile-driver-family-map.csv) for the
installed model catalog's static selection rule.
