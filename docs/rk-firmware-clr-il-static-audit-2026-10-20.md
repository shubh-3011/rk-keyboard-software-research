# RK updater IL static audit

## Scope and method

This pass statically decodes method bodies from the eight SHA-256-pinned CLR images in [the profile inventory](rk-firmware-clr-profile-inventory-2026-10-20.csv). The scanner reads PE/CLI bytes and metadata without loading a CLR, running vendor code, unpacking embedded files, or contacting a device. It decodes instruction streams linearly, validates instruction bounds and branch targets, resolves token operands to metadata rows or `#US` strings, and stores package hashes, method-body hashes, file offsets, and instruction bytes in the ledgers.

All eight images were parsed. All **1,456/1,456** MethodDef bodies decoded: **30,774** instructions, **6,332** method-reference instructions, and **12,476** token-bearing instructions. There were **zero** unsupported or invalid opcodes, malformed bodies, invalid branch targets, or unresolved call tokens. The call-reference targets resolved as 4,290 MemberRef, 1,810 MethodDef, and 232 MethodSpec references. No `calli` sites were present. The eight inputs are v4.0.30319 assemblies.

The six X87/X104 images each have 791 call-reference instructions. The two R108 images each have 793; each has one additional `Process.Start` call in `linklabel_LinkClicked`. All eight contain the common updater, extraction, command, and USB-monitor code described below.

## Static links found

Examples below cite IL offsets from representative X87 package `20260701135217_3418.exe` (SHA-256 `392b0ed26d6105e2bae7995c835eca6ebd699d3bfc7d2f57fdadf7706b1a4732`). The CSV ledgers contain equivalent per-image rows and exact file offsets.

### Embedded updater and native-library extraction

- `WestberryFlasher::.ctor` stores the literal `wb32_f022_hid_dfu_updater_V0.0.5.exe` as `driver_program` (`ldstr`, token `0x700005B9`, IL+`0x17`). The manifest includes V0.0.4 and V0.0.5 updater resources; the constructor selects V0.0.5 by name.
- `ExtractEmbeddedFiles` constructs the resource name from `WestberryFlasher.executable.` plus `driver_program`, calls `ExtractResource`, and also passes the exact embedded names `WestberryFlasher.executable.libhidapi-0.dll` and `WestberryFlasher.executable.libusb-1.0.dll` with output names `libhidapi-0.dll` and `libusb-1.0.dll`. Both native-library literals match manifest-resource names in the same package.
- `ExtractResource` calls `Assembly.GetExecutingAssembly` and `Assembly.GetManifestResourceStream` (IL+`0x06`), then constructs a `FileStream` under `resourceDirectory` (IL+`0x4B`) and calls `Stream.CopyTo` (IL+`0x53`). The method also contains a missing-resource exception path. This is static evidence of code that reads embedded resources and writes a file if that method executes.
- `ExtractInit` calls `Path.GetTempPath`, creates a GUID-named directory with `Directory.CreateDirectory`, calls `ExtractEmbeddedFiles`, and builds `driver_program_path` and `update_firmware_path`. The latter is `resourceDirectory/firmware.hex`; the extracted `firmware.hex` bytes come from the embedded `config_file` resource.

### External process launch

- The `RunCommand` async state machine (`<<RunCommand>b__0>d::MoveNext`) sets `ProcessStartInfo.FileName` from `driver_program_path` (IL+`0x36`) and `Arguments` from `program_arg` (IL+`0x47`), sets the working directory to `./`, disables shell execution, redirects standard output and error, then calls `Process.Start` (IL+`0x154`) and waits for exit.
- The `btn_update_Click` state machine contains direct call references to `CmdUpdate` and `CmdJump`; `CmdUpdate` and `CmdJump` state machines each reference `RunCommand`. This establishes static call links in IL, not that a user action occurred or that the call is reachable in a particular run.
- Eight helper-process `Process.Start` references occur in the updater command path. R108 adds one `Process.Start` reference per image in `linklabel_LinkClicked`; the destination is not treated as updater behavior.

### USB device discovery and model gates

- `USBDeviceMonitor::.ctor` contains WMI event queries for `Win32_PnPEntity` USB device insertion/removal, constructs `ManagementEventWatcher` instances, registers callbacks, and calls `Start` on both watchers. The queries include `WITHIN 1` and `DeviceID LIKE 'USB%'`.
- `EnumerateDevices` contains `SELECT * FROM Win32_PnPEntity WHERE DeviceID LIKE 'USB%'`, constructs a `ManagementObjectSearcher`, enumerates results, reads `Name` and `DeviceID`, and passes parsed identifiers to `GetDeviceType`.
- `GetDeviceID` references the pattern `VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})` and converts the two captures from hexadecimal. `GetDeviceType` compares the resulting VID/PID pair against `boot_vid`/`boot_pid` and `app_vid`/`app_pid`, returning different integer classifications.
- `WestberryFlasher_Load` sets boot VID/PID to decimal 13357/57251 (`0x342D`/`0xDFA3`) and initializes app VID/PID to zero before calling `ExtractInit` and `firmware_update`. `firmware_update` parses `firmware.hex` through `firmware_init`, then assigns app VID/PID and usage page/id from the resulting `FirmwareInfo` before calling `EnumerateDevices`. The resulting app identifiers depend on the embedded firmware data and are not hard-coded in this method.

### Native loading limits

This managed IL contains explicit extraction of `libhidapi-0.dll` and `libusb-1.0.dll`, but no call references to `LoadLibrary`, `GetProcAddress`, `NativeLibrary.Load`, or `Assembly.LoadFrom`/`LoadFile`. The companion metadata audit records zero ImplMap/PInvoke rows. The IL pass therefore establishes a managed resource-extraction and helper-process path, but does not show how the external helper loads or calls those native libraries. The embedded updater EXEs and DLL payloads remain unanalyzed here; no HID/USB transfer implementation or device-side effect is established by this pass.

## Evidence outputs

- [Reproducible IL scanner](../scripts/audit_rk_clr_il_static.py)
- [Call-reference ledger](rk-firmware-clr-il-call-reference-ledger-2026-10-20.csv) — resolved `call`, `callvirt`, `newobj`, `jmp`, `ldftn`, `ldvirtftn`, and `calli` sites.
- [Token-reference ledger](rk-firmware-clr-il-token-reference-ledger-2026-10-20.csv) — all token-bearing IL operands, including `ldstr`, exact instruction bytes, package/method hashes, and resource-name literal matches.
- [Method summary](rk-firmware-clr-il-method-summary-2026-10-20.csv) — method tokens, RVA/file offsets, IL sizes/hashes, counts, and decode status.
- [Image summary](rk-firmware-clr-il-image-summary-2026-10-20.csv) — per-package totals and feature-candidate counts.
- [Decode issues ledger](rk-firmware-clr-il-decode-issues-2026-10-20.csv) — header-only; no issues were found.

Run from the repository root with Python 3:

```powershell
python scripts/audit_rk_clr_il_static.py
```

The default input root is the sibling `.research/rk-firmware-catalog-2026-10-19`; an alternate cached copy can be selected with `--research-root PATH`.

## Limits

The decoder validates instruction encodings, operand widths, method-body bounds, and branch-target boundaries, but it does not build a control-flow graph, evaluate branches, analyze exception-handler behavior, perform stack/type verification, or infer method reachability. Token resolution is complete for the observed call references; MemberRefs owned by a TypeSpec retain a `TypeSpec#RID` placeholder because TypeSpec signatures are not expanded. This is a static IL pass, not complete reverse engineering of the updater suite. Native payload internals, dynamic API behavior, runtime file/process effects, updater protocol details, and actual keyboard behavior remain outside this evidence.
