# RK 4.06 host update, download, and installer paths

## Scope and evidence

This is an offline static trace of the installed RK Keyboard Software 4.06
snapshot. The main target is `DeviceDriver.exe`, SHA-256
`c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6`
(2,326,528 bytes). Related installed inputs are `Cfg.ini`, SHA-256
`1a9796e706fa64b1821417efda080d481e202ffcf941aa97e6a78efe3a32badd`;
`Dev/01AF/Update.exe`, SHA-256
`27894463b0dfe5bc3f5dc19d4d3351d9dfb692c402bf277bde3889d37e4a206c`;
`InitSetup.dll`, SHA-256
`59db7bfd9a92cc9a0998260807f17c536ec71159b727df10d08b998bc94de301`;
and `unins000.dat`, SHA-256
`584440eb2154bcc6881846d824c45b2c3074929d653bb0f5e3f306a746aa8f20`.
Addresses below are VAs in these particular x86 files.

No RK application, updater, setup executable, or uninstaller was run. No
network endpoint was contacted, no installer or update payload was downloaded,
and no keyboard interface, serial port, or bootloader was used. **Direct**
means the bytes, imports, resources, or disassembly show the item. **Inferred**
means the interpretation follows that static control/data flow. Runtime
execution and server contents remain unobserved.

## Main-app software update check

### Configuration and endpoint selection

**Direct:** the main app reads `OPT\UpdateURL` from its configuration using
the wide INI API. The key string is at VA `0x005D71D4`; the read call is at
`0x00453716`, and the returned value is stored in the update URL buffer at
`0x00611394`. `UpdateURL` is optional: the installed `Cfg.ini` has no such
entry. The same configuration contains `NoUpdate=0`.

**Direct:** `NoUpdate` is read as an integer from section `OPT` at
`0x00453572`, using the key at `0x005D714C` and a zero default. The value is
retained in global `0x00611764`. The update worker at `0x00403E5B` exits early
when that global is nonzero and emits the `gVar.nNoUpdate=1` diagnostic
(`0x005C8118`). Thus the installed `NoUpdate=0` does not take that skip
branch in the statically recovered logic; this is not evidence that an update
check actually ran.

When `UpdateURL` is empty, the main app chooses a built-in base according to
the `RGBKb` configuration value: `http://www.rkgaming.com/Work/Update-RGB/`
at VA `0x005C8258`, or
`http://www.rkgaming.com/Work/Update-Single/` at `0x005C82B0`. The app builds
the manifest URL from that base and `update_version.xml` (VA `0x005C81D8`).
If a custom `UpdateURL` is present, it is used as the base instead. In both
cases the format string at `0x005C8230` appends
`?timestamp=%x`; the timestamp argument comes from `GetTickCount` at
`0x00403FF0`. The code also clears the URL cache for the URL before download.
These are endpoint strings and argument paths recovered from the binary, not
verified live endpoints or a description of the server's current contents.

### Download and local file path

**Direct:** the call at `0x00403DFB` reaches the main executable's
`URLDownloadToFileW` import thunk at `0x00588F5E`. At the call boundary its
arguments are: null caller, URL in `EDI`, destination filename in `EBX`,
reserved value zero, and callback object in `ESI`. `DeleteUrlCacheEntryW` is
called with the URL at `0x00403DEE`; if the download returns `0x80004004`,
the error path clears that URL's cache entry again at `0x00403E0B`. The call
returns its HRESULT to the worker. These are host-side file/network calls;
they do not themselves write to a keyboard.

The update worker builds its local download directory in `FUN_00450630`
(entry VA `0x00450630`). It calls `SHGetSpecialFolderPathW` with CSIDL `0x1C`
(`CSIDL_APPDATA`) at `0x0045064F`, then formats a directory into global
`0x00619310` using `%s\\%s\\` at `0x00450673`. The second path component is
provided through runtime data at `0x00611550`; its concrete value is not
recovered as a literal by this trace. The worker obtains the final component
of the remote URL in `FUN_00404D10`: it scans backward for `/` and copies the
suffix. It combines that basename with the `0x00619310` directory at
`0x004042CC` or `0x004047D4`. **Inferred from these data flows:** the manifest
and later update downloads are saved under the app's per-user AppData
directory using the URL's final path component. The exact realized subfolder
and full destination string remain runtime-dependent.

The worker deletes an existing destination file before a fetch
(`DeleteFileW` call at `0x00404063`) and can remove a failed/consumed download
later (`0x00404321`, `0x00404843`). It does not establish a `%TEMP%` destination
for these downloads. The main PE does import `GetTempPathW` and
`GetTempFileNameW`, but their direct callsites are `0x004D4F0C` and
`0x004D4F3D`, in a separate local file/stream helper; this audit did not find
a static edge from those calls to the update worker. Treating the update file
as a Windows temporary file would therefore be unsupported.

### Manifest fields and subsequent downloads

**Direct:** after a successful manifest download, the worker parses XML via
helpers including `FUN_0042F180` and `FUN_0042FF40`; it logs `Load XML Failed`
at VA `0x005C8344` on one failure path. The inspected strings and callers
show separate driver and firmware checks. Driver-related tag literals
include `drv`, `version`, and `url`; firmware-related literals include `fw`,
`pid`, `version`, and `url`. The worker logs driver-version comparison
(`0x005C83B0`), `Driver have update` (`0x005C83FC`), firmware checks, and
profile/PID-specific version comparisons (`0x005C84A8`, `0x005C8518`).

When a later remote `url` is accepted, `FUN_00404D10` extracts its basename
and the worker downloads it to the same AppData-rooted directory path. The
condition and exact XML schema for each model/server combination are not
fully reconstructed here. This is an app/firmware update-check and
host-download path; it does not prove that a downloaded firmware file is
compatible or that a later hardware transfer succeeds. The separate
`Dev/01AF/Update.exe` is a bundled model-specific updater with a neighboring
`.upf` input; the reviewed `DeviceDriver.exe` `CreateProcessW` call below does
not name that binary.

## Process launch and optional per-device helper

The main PE has one recovered direct `CreateProcessW` callsite, at
`0x00465D00`. In its conditional online/device-processing branch, code reads
VID and PID words from object offsets `+0x248` and `+0x24A` and formats two
paths with these literal templates:

- command line: `%sOther\\%04X_%04X\\start.exe` at VA `0x005D9534`;
- current directory: `%sOther\\%04X_%04X` at VA `0x005D956C`.

The `%s` prefix is supplied from runtime data at `0x00619518`; its resolved
value and the exact branch predicate's business meaning are not established.
The `CreateProcessW` arguments statically pass a null application-name
pointer, the first formatted path as the mutable command-line buffer, null
process/thread security attributes, `bInheritHandles=FALSE`, creation flags
zero, null environment, the second formatted path as current directory, a
local `STARTUPINFOW` structure (`cb=0x44`), and a local
`PROCESS_INFORMATION` structure. The source does not append a separately
recovered command-line argument. If creation fails, the code logs
`Run failed: %s` at VA `0x005D9590`.

**Inferred:** this is an optional helper launch under an `Other\\<VID>_<PID>`
directory, not a launch of `Dev/01AF/Update.exe` or a setup installer. No
`Other` helper executable is present in the 810-file installed package
manifest, so the helper's behavior cannot be examined from this snapshot. The
app has `ShellExecuteW` imports/calls elsewhere; this report does not equate
those untraced UI calls with the `CreateProcessW` route or claim a complete
launch graph for every MFC callback.

## Installer helper and missing setup payload

The installed package includes `InitSetup.dll`, but no original setup
executable or its source. The 810-file manifest has three `.exe` files:
`DeviceDriver.exe`, `Dev/01AF/Update.exe`, and `unins000.exe`. The last is the
Inno Setup uninstaller engine, not the missing installer program. The
installer's source project, compiler inputs, and original setup payload are
not present in this installed snapshot, so these artifacts do not provide a
basis for rebuilding an identical official installer executable.

**Direct:** `InitSetup.dll` exports `SetupInit` at RVA `0x1080` (VA
`0x10001080` in its `0x10000000` image). It accepts one path; for an existing
directory the worker enumerates `path\\*.*`, recurses, normalizes attributes,
deletes files, and removes nested directories. The compiled script records in
`unins000.dat` contain a `MyAfterInstall` callback that expands
`{localappdata}\\RKKB` and passes it to the delayed `SetupInit` import.
The callback bodies and helper path are proven in bytecode/disassembly; no
setup or uninstaller was executed, so invocation and filesystem effects were
not observed. See the dedicated
[installer/uninstaller script audit](rk-installer-uninstaller-script-audit.md)
and [native API crosswalk](rk-system-api-crosswalk.md).

## Boundaries and unresolved items

- No URL, update manifest, driver package, firmware package, setup program,
  or helper binary was downloaded or launched.
- The `UpdateURL` custom-base case, `RGBKb` selection, and `NoUpdate` gate are
  statically evidenced; actual configuration branches and HTTP responses
  were not observed.
- The AppData prefix is constructed from `CSIDL_APPDATA`, but the runtime
  subdirectory value at `0x00611550` is unresolved. The update basename is
  extracted from a URL; the exact final path is therefore not a single
  fixed literal.
- The XML parser's complete schema, signature/authentication checks,
  payload-version policy, and any follow-on launch/installation behavior are
  unresolved. A static download path is not proof that any update is
  trustworthy, valid, or installed.
- The optional `Other\\<VID>_<PID>\\start.exe` binary is absent. The exact
  meaning of the path prefix and predicate is unresolved.
- There is no original setup executable/source in the installed package.
  `InitSetup.dll` plus the uninstaller's script log document only a helper
  and callback path, not a complete buildable installer project.

## Related reports

- [Main static reverse-engineering report](reverse-engineering.md)
- [System API and call crosswalk](rk-system-api-crosswalk.md)
- [Native API imports and IAT references](rk-native-api-imports.md)
- [Installer/uninstaller script audit](rk-installer-uninstaller-script-audit.md)
- [Firmware readback/update audit](rk-firmware-readback-audit.md)
