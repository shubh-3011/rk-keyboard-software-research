# X87 CLR updater static-chain follow-up

## Scope and sample identity

This follow-up traces one hash-pinned CLR updater image from its managed entry point through USB discovery and model-pair classification, resource extraction, and the helper-process launch code. The input is:

- File: `.research/rk-firmware-catalog-2026-10-19/20260701135217_3418.exe`
- Profile: X87
- SHA-256: `392b0ed26d6105e2bae7995c835eca6ebd699d3bfc7d2f57fdadf7706b1a4732`
- Managed assembly namespace: `WestberryFlasher`; CLR metadata version: `v4.0.30319`

The package hash and method-body hashes are recorded in [the CLR profile inventory](rk-firmware-clr-profile-inventory-2026-10-20.csv) and [the IL method summary](rk-firmware-clr-il-method-summary-2026-10-20.csv). Offsets below distinguish an IL offset within a method body from the corresponding IL byte's file offset.

## Entry and monitor setup

`WestberryFlasher.Program::Main` (`0x06000050`, IL starts at file offset `0x1D08`) calls `Application.EnableVisualStyles` at IL+`0x0`, sets text rendering at +`0x6`, constructs `WestberryFlasher` at +`0xB`, and passes it to `Application.Run` at +`0x10`.

The form constructor (`WestberryFlasher.WestberryFlasher::.ctor`, `0x06000034`, IL starts at `0xB48`) selects the updater filename `wb32_f022_hid_dfu_updater_V0.0.5.exe` at IL+`0x17`. It initializes both auto-update and auto-jump flags, then derives the final values from `config_file[320]` by comparing it with byte `0x58` (`'X'`); if equal, both flags are cleared, otherwise both are set (IL+`0xC9`–`0x108`). It constructs `USBDeviceMonitor` at +`0x116`, then subscribes the form's insertion and removal callbacks at +`0x120`–`0x149`. `InitializeComponent` binds `WestberryFlasher_Load` to the form Load event at IL+`0x667`–`0x672`.

`USBDeviceMonitor::.ctor` (`0x06000074`, IL starts at `0x1FB0`) creates WMI watchers for `__InstanceCreationEvent` and `__InstanceDeletionEvent`, filtered to `Win32_PnPEntity` objects whose `DeviceID` starts with `USB%`. It registers event handlers and calls `ManagementEventWatcher.Start` for both watchers at IL+`0x80`–`0x97` and +`0x9D`–`0xB4`. The constructor delegates route to `OnDeviceInserted` and `OnDeviceRemoved` (`0x0600007B`/`0x0600007C`, each calls its target at IL+`0x3`).

## Device identification and classification

The form Load handler (`WestberryFlasher_Load`, `0x06000035`, IL starts at `0xCBC`) sets boot VID/PID to decimal `13357/57251` (`0x342D/0xDFA3`) at IL+`0x0`–`0x1B`, initializes app VID/PID to zero at +`0x20`–`0x33`, then calls `ExtractInit` at +`0x39` and `firmware_update` at +`0x3F`.

`firmware_update` (`0x0600003D`, IL starts at `0xE5C`) calls `firmware_init` at IL+`0x7`, assigns the returned VID, PID, UsagePage and UsageId to the monitor at +`0x85`–`0xBD`, and calls `EnumerateDevices` at +`0xC8`.

`USBDeviceMonitor::EnumerateDevices` (`0x06000077`, IL starts at `0x21D8`) queries `SELECT * FROM Win32_PnPEntity WHERE DeviceID LIKE 'USB%'`, reads each result's `Name` and `DeviceID`, and calls `GetDeviceID` at IL+`0x6D`. `GetDeviceID` (`0x06000079`, IL starts at `0x2304`) applies the static regex `VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})`, converts both captures from hexadecimal to `UInt16`, and returns a nullable pair. The regex is initialized in `USBDeviceMonitor::.cctor` (`0x0600007A`, IL+`0x0`; string at file offset `0x235E`).

`GetDeviceType` (`0x06000078`, IL starts at `0x22C5`) returns 0 when the pair matches boot VID/PID, 1 for app VID/PID, and 2 otherwise. `EnumerateDevices` skips classification 2 at IL+`0xA2`; for the other two values it invokes the insertion delegate at +`0xBC`. `OnDeviceInserted` (`0x06000075`, IL starts at `0x2078`) extracts the event's `Name` and `DeviceID`, parses the IDs, and invokes the registered event callback when one is present.

### Correction: `firmware_init` does not parse `firmware.hex` in this image

`firmware_update` passes `update_firmware_path` to `firmware_init`, but the decoded body of `WestberryFlasher::firmware_init` (`0x0600003E`, IL starts at `0xF38`) never reads that argument. It constructs `FirmwareInfo` from `config_file` bytes at fixed offsets: VendorId 288, ProductId 292, UsagePage 296, UsageId 300, FlashAddr 304, FlashSize 308, PageSize 312, and Version 316. Thus, for this X87 sample, the app VID/PID and HID usage values are sourced from `config_file`, not parsed from the path argument. The earlier audit's description that this call parses `firmware.hex` was incorrect for this method body; this correction applies only to this hash-pinned image unless other profiles are compared at the method-body level.

The separate `ExtractEmbeddedFiles` method (`0x06000045`, IL starts at `0x1234`) does create `firmware.hex`: it reads a length from `config_file` offset 576, then writes that many bytes starting at offset 580. This extraction does not change the `firmware_init` data source described above.

## Extraction and helper command path

`ExtractInit` (`0x06000048`, IL starts at `0x139C`) obtains the temp path, creates a GUID-derived directory, calls `Directory.CreateDirectory`, then calls `ExtractEmbeddedFiles` at IL+`0x36`. It builds `driver_program_path` from that directory plus the selected helper filename and sets `update_firmware_path` to the same directory plus `firmware.hex`.

`ExtractEmbeddedFiles` calls `ExtractResource` (`0x06000047`) with the prefixed V0.0.5 manifest name and the output filename, and also requests `libhidapi-0.dll` and `libusb-1.0.dll`. `ExtractResource` calls `Assembly.GetExecutingAssembly` and `GetManifestResourceStream` at IL+`0x0`–`0x6`, combines `resourceDirectory` with the output name at +`0x3D`–`0x48`, creates a `FileStream`, and calls `Stream.CopyTo` at +`0x53`. A missing resource branches to a message/exit/exception path at +`0xD`–`0x3C`.

The V0.0.5 helper resource is present in the package manifest as `WestberryFlasher.executable.wb32_f022_hid_dfu_updater_V0.0.5.exe`; its in-place payload hash is `e98cb301502891f6b5c37c4fb8fe8a05893ad1fac6def0d49676b5198f46d819` (metadata row ledger entry for this sample, row 757). It was hashed in place, not extracted or run.

The insertion state machine (`<UsbMonitor_DeviceInserted>d__24::MoveNext`, `0x060000AA`, IL starts at `0x2AF4`) can call `CmdUpdate` for boot devices under its update/stage gates (calls at IL+`0x74` and +`0xEB`) or `CmdJump` for app devices under its jump gates (call at +`0x19C`). `CmdUpdate` (`<CmdUpdate>d__31::MoveNext`, `0x060000A8`) constructs `-D "<update_firmware_path>" -M <dev_erase_mode>` at IL+`0x51`–`0x6C`; the form constructor initializes `dev_erase_mode` to `page`. `CmdJump` (`<CmdJump>d__33::MoveNext`, `0x060000A6`) constructs `-j -v <app VID> -p <app PID> -P <UsagePage> -I <UsageId>` at IL+`0x4B`–`0xA7`.

Both methods call `RunCommand` (`0x06000044`); its async worker (`<<RunCommand>b__0>d::MoveNext`, `0x060000B5`, IL starts at `0x2F84`) sets `ProcessStartInfo.FileName` from `driver_program_path` at IL+`0x36`, `Arguments` from the command string at +`0x47`, working directory `./`, shell execution false, no window, and redirects stdout/stderr. It calls `Process.Start` at +`0x154`, begins asynchronous output reads, waits for exit, and returns the process exit code. The command state machines branch on that result to report success or error.

## Evidence and limits

Method tokens, IL offsets, body hashes, and call targets can be checked in the [method summary](rk-firmware-clr-il-method-summary-2026-10-20.csv), [call-reference ledger](rk-firmware-clr-il-call-reference-ledger-2026-10-20.csv), and [token-reference ledger](rk-firmware-clr-il-token-reference-ledger-2026-10-20.csv). Resource name, location, size, and hash are in the [metadata row ledger](rk-firmware-clr-metadata-row-ledger-2026-10-20.csv).

This is static evidence only. No app or helper was executed; no HID interface, USB device, keyboard, or firmware was accessed. The IL decoder validates branch targets but does not build a control-flow graph, evaluate exception-handler flow, or prove framework event delivery or method reachability in a live run. The trace follows decoded calls and branch targets; it does not establish that any helper process starts or that any keyboard is updated. The embedded helper's protocol and the meaning of its command-line options remain outside this follow-up.
