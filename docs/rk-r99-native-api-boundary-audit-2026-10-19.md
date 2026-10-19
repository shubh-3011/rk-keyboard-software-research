# R99 RK Driver native API boundary audit — 2026-10-19

## Scope and identity

This static pass analyzes the seven PE files in the extracted R99 `app/`
folder. The main app is `RK Driver.exe`, SHA-256
`61dd118400a4652ba053db6ceb87cdd865e183f59822948ea9018da218aec2e5`.
The other package binaries are `CH375DLL.DLL`, `mui.dll`,
`driver/CH372DRV.EXE`, `mfc140u.dll`, `msvcp140.dll`, and `vcruntime140.dll`;
each file hash is repeated on its rows in the CSV ledgers. No binary was run.

The reproducible scanner is
[`audit_r99_native_api_surface.py`](../scripts/audit_r99_native_api_surface.py).
It uses the existing Python `pefile` and Capstone packages, inventories normal
and delay imports, linearly decodes sections marked executable, maps direct
IAT calls/tail jumps and calls to one-instruction IAT thunks, and checks for
decoded x86 `sysenter`/`int 0x2e` sites. It does not recover function starts,
resolve general register-indirect calls, or prove reachability.

## Package-wide results

- Seven 32-bit PEs produced 2,559 import rows, including 157 delay-import
  rows. The complete API ledger is
  [`rk-r99-native-api-imports.csv`](rk-r99-native-api-imports.csv).
- The bounded linear sweep emitted 4,110 imported-call/tail-jump candidates:
  3,948 calls through IAT slots, 146 tail jumps through IAT slots, and 16
  calls to one-instruction IAT thunks. The row-level ledger is
  [`rk-r99-native-api-callsite-candidates.csv`](rk-r99-native-api-callsite-candidates.csv).
- The main app alone has 735 import rows. The package includes 345 imports
  from `mui.dll`, nine from `CH375DLL.DLL`, four from `HID.DLL`, and six from
  SetupAPI. These import declarations identify available entry points; the
  callsite ledger supplies candidate instructions where found.
- The scan recognized zero direct `sysenter` or `int 0x2e` instructions in
  these seven executable-section sweeps. The empty candidate ledger is
  [`rk-r99-native-syscall-candidates.csv`](rk-r99-native-syscall-candidates.csv).
  This does not cover dynamically resolved code, imported NT APIs, OS/kernel
  drivers, or code/data classification beyond linear-sweep section flags.

## Main application to transport helpers

`RK Driver.exe` imports these nine named `CH375DLL.DLL` functions:

`CH375OpenDevice`, `CH375ReadData`, `CH375WriteData`, `CH375SetTimeout`,
`CH375SetExclusive`, `CH375CloseDevice`, `CH375GetDeviceName`,
`CH375GetUsbID`, and `CH375SetDeviceNotify`.

Static call candidates include two `CH375OpenDevice` calls at `0x0041A961`
and `0x0041AE56`; USB-ID/name checks around `0x0041A96C`–`0x0041A986` and
`0x0041AE61`–`0x0041AE7B`; `CH375WriteData` at `0x0041AF64`, `0x0041B024`,
and `0x0041B0D6`; and `CH375ReadData` at `0x0041AFA1` and `0x0041B102`.
The candidate at `0x0041AED9` calls `CreateFileA` with
`GENERIC_READ | GENERIC_WRITE`, `OPEN_EXISTING`, and
`FILE_ATTRIBUTE_NORMAL`, using the path previously obtained from the CH375
helper. The following calls set exclusive access and request 1,000 ms for
each timeout argument. These are static code paths; device acceptance is
unobserved.

One enumeration path loops across 16 CH375 indices and compares the returned
USB-ID value against `0x4348` in the low word or `0x55E0` in the high word
before using a returned device name. This establishes those comparisons in
this exact binary, not a universal model-to-VID/PID map. Another path opens
the selected path and uses the read/write helper. The caller-side wrapper
builds local request data containing `0x281` and `0x283`; their protocol
meaning is unresolved.

The helper DLL exports 37 functions. Its `DeviceIoControl` import has 30
direct call candidates; the 30 call neighborhoods all contain an immediate
push of `0x00223CDC`. Under the Windows `CTL_CODE` bit layout this decodes to
device type `0x22`, function `0xF37`, method `METHOD_BUFFERED` (`0`), and
access `FILE_ANY_ACCESS` (`0`). This is strong static evidence that the helper
funnels its named operations through one private control code. The IOCTL's
input/output structure meanings and kernel-driver implementation are not in
this package evidence set.

The main app also imports four HID parser/attribute APIs. Candidate callsites
at `0x0043E088`–`0x0043E0CB` call `HidD_GetAttributes`,
`HidD_GetPreparsedData`, `HidP_GetCaps`, and `HidD_FreePreparsedData`; a
`CreateFileW` candidate precedes them at `0x0043E067`. A
`RegisterDeviceNotificationW` candidate appears at `0x0043E19E`. Separately,
the app calls SetupAPI at `0x00474ED6`, `0x00474EF5`, and nearby sites to
enumerate device interfaces and registry properties, then opens a returned
path. These findings indicate both CH375-helper and HID/SetupAPI paths are
present in the same binary; exact selector gates and which models reach each
path remain open.

Other candidate API sites include five `SetWindowsHookExW` calls, four
`RegisterRawInputDevices` calls, and six `Shell_NotifyIconW` calls. They are
not yet mapped from UI controls to their callbacks or lifecycle. The import
and callsite counts do not establish that keyboard input is captured, that
tray behavior works, or that an API call succeeds.

## Remaining call-path work

- Recover function boundaries and validated control flow in `RK Driver.exe`,
  `mui.dll`, and `CH375DLL.DLL`; classify candidate callsites as reachable or
  unresolved rather than treating linear-sweep matches as a CFG.
- Map all 37 CH375 exports to parameter/structure layouts and all 30
  `DeviceIoControl` calls to buffer sizes/contents; locate the corresponding
  driver protocol and install behavior.
- Trace the HID/SetupAPI enumeration branches, VID/PID selection, and returned
  handles into device operations; reconcile with the 20 layout XML profile
  families without assuming names imply compatibility.
- Resolve dynamic `LoadLibrary`/`GetProcAddress` and the 3,073 register-
  indirect call/jump candidates in the main app; map global-hook and raw-input
  registrations to message handlers and actual macro/key-test behavior.
- Analyze `CH372DRV.EXE` without executing it; the current callsite scan did
  not resolve its import callers.

This report covers one exact R99 package build and its packaged PE files. It
does not establish runtime behavior or provide a universal RK API/protocol
map.
