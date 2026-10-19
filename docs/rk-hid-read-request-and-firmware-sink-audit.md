# RK 4.06/4.6 HID feature-read request and firmware-file sink audit

## Scope and method

This static audit enumerates the `HidD_GetFeature` callsites in the installed
RK 4.06 main driver and updater, and in the separately extracted 4.6-labeled
main driver and updater. It checks whether each read participates in a preceding
`HidD_SetFeature` request flow and whether the returned data reaches a firmware
file sink in the analyzed routines.

The exact input hashes are:

| Image | SHA-256 | Identity check |
| --- | --- | --- |
| Installed 4.06 `DeviceDriver.exe` | `c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6` | Matches the installed manifest and `_rk_analysis/inputs/DeviceDriver.exe`. |
| Installed 4.06 `Dev/01AF/Update.exe` | `27894463b0dfe5bc3f5dc19d4d3351d9dfb692c402bf277bde3889d37e4a206c` | Matches the installed manifest and `_rk_analysis/inputs/Update.exe`. |
| Extracted 4.6 `DeviceDriver.exe` | `8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9` | Matches the 4.6 package snapshot. |
| Extracted 4.6 `Dev/01AF/Update.exe` | `27894463b0dfe5bc3f5dc19d4d3351d9dfb692c402bf277bde3889d37e4a206c` | Byte-identical to the installed 4.06 updater. |

The executable images were not run. No HID interface was opened, no report was
sent or read, and no updater or bootloader was used. Addresses below are virtual
addresses in the hash-pinned images. “Request write” means a preceding
`HidD_SetFeature` operation in the same statically recovered transaction; it
does not establish runtime reachability, device acceptance, or command meaning.

## Callsite inventory

The installed 4.06 import cross-reference inventory records six calls from
`DeviceDriver.exe` to its `HidD_GetFeature` thunk. The 4.6 main-driver native
callsite inventory records six `HidD_GetFeature` thunk calls. `Update.exe` has
nine direct calls and two register-indirect calls through a loaded import
pointer. The indirect pair is in `FUN_00402E80`; a direct-call-only xref count
would omit it. The same updater image is present in both package snapshots, so
its callsite results apply byte-for-byte to both.

### Main drivers

| Image and `GetFeature` site | Earlier `SetFeature` site | Static request/response relationship |
| --- | --- | --- |
| 4.06 `DeviceDriver.exe` `0x0040F1A5` | `0x0040F14D` | Screen-profile descriptor request, followed by a six-byte response comparison. |
| 4.06 `DeviceDriver.exe` `0x0040F8F1` | `0x0040F87F` | Generic G5 `AccessData` operation 2; the response is command-checked and copied to caller memory. |
| 4.06 `DeviceDriver.exe` `0x0040FC19` | `0x0040FBBE` | G5 LED configuration query; 128 response bytes are copied into a caller buffer. |
| 4.06 `DeviceDriver.exe` `0x0040FE5C` | `0x0040FE01` | G5 power query; two response bytes are copied to output values. |
| 4.06 `DeviceDriver.exe` `0x004100C1` | `0x00410062` | G5 command `0x88` read helper; response chunks are copied to caller memory. |
| 4.06 `DeviceDriver.exe` `0x0041054E` | `0x004104EF` | G5 command `0x82` path; response chunks are copied to caller memory. |
| 4.6 `DeviceDriver.exe` `0x0040F975` | `0x0040F91D` | Profile/Psd path; same handle is used for the write and read. |
| 4.6 `DeviceDriver.exe` `0x004101C1` | `0x0041014F` | Generic operation-2 helper; same saved handle is used for the write and read. |
| 4.6 `DeviceDriver.exe` `0x0041054E` | `0x004104EF` | Command `0x84`; same saved handle is used for the write and read. |
| 4.6 `DeviceDriver.exe` `0x0041078C` | `0x00410731` | Command `0x87`; response bytes are copied to separate outputs. |
| 4.6 `DeviceDriver.exe` `0x004109F1` | `0x00410992` | Command `0x88`; conditional response copying is chunked up to `0x200` bytes. |
| 4.6 `DeviceDriver.exe` `0x00410E7E` | `0x00410E1F` | Command `0x82`; conditional response copying is chunked up to `0x200` bytes. |

For these 12 main-driver callsites, static disassembly shows a preceding
feature write in the same helper/request flow. This is not a passive capture
path. The command `0x88` methods contain response-to-memory copies, but those
copies do not by themselves identify firmware data or a complete image.

### Shared updater in both snapshots

| `GetFeature` site(s) | Earlier request write | Static data path and limit |
| --- | --- | --- |
| `0x004023CF` | `0x00402317` on the selected retry path | In `FUN_004021C0`; parses short status bytes. |
| `0x0040269B` | `0x004025E7` on the selected retry path | In `FUN_004021C0`; parses short status bytes. |
| `0x0040289C` | `0x00402853` | In `FUN_004021C0`; parses short status bytes. |
| `0x00402985` | `0x0040292F` | In `FUN_004021C0`; parses short status bytes after the command-`0x70` request. |
| `0x00402ED3`, `0x00402EFB` | `0x00402EBA` | Two six-byte reads in `FUN_00402E80`. They share one earlier request write; there is no second `SetFeature` between the two reads. The returned bytes are extracted into local values and the helper continues with short feature writes. |
| `0x0040308C` | `0x0040302E` | Section-B verifier; reads chunks and compares them in RAM with the selected host image buffer. |
| `0x0040389C` | `0x0040383E` | Section-C verifier; reads chunks and compares them in RAM with the selected host image buffer. |
| `0x0040980D` | `0x004097A8` | Mode/connection helper; short status response is checked in memory. |
| `0x0040BC16` | `0x00401F9D`, through caller `FUN_0040BB10` → `FUN_00401F30` | `FUN_00401F30` sends a `0x408`-byte feature request before the report-ID-6 polling loop. The returned fields are checked as version/status data. |
| `0x0040BF57` | `0x0040215E`, through `FUN_00401FD0` called from `0x0040BF0B` | A request write is sent on the retry path before this report-ID-5 status read; the response is parsed in memory. |

Thus every enumerated updater `HidD_GetFeature` transaction has a statically
visible earlier feature request/write in its transaction, including the
status/version polling paths whose request is sent by a helper. The two reads
at `0x00402ED3` and `0x00402EFB` are a notable shared-request case: the second
read is not preceded by another feature write of its own.

The site list is hash-pinned and reconciles the direct-IAT references plus the
single loaded IAT pointer used by the two indirect calls. It does not rule out
computed dispatch or dynamically resolved APIs that do not reference this
import; those are outside this callsite census.

## Firmware-file sink assessment

**Proven in the traced HID routines:**

- The 4.06/4.6 main-driver response buffers in the listed helpers are compared,
  decoded, or copied into caller-provided memory. No firmware-file open/write
  sink appears in those helpers.
- The updater's section-B and section-C feature reads compare bounded response
  chunks in RAM against buffers parsed from the selected host `.upf`. They are
  post-write verification reads, not output-file writes.
- The other updater HID reads are status/version or short protocol exchanges
  consumed in memory. No traced `HidD_GetFeature` result is written to a
  firmware file.

**Unresolved main-driver persistence:** the 4.06 G5 command-`0x88` helper's
caller and downstream consumer were not attributed. The 4.6 G5 `+0x70`
command-`0x88` caller, requested range, and downstream consumer are also
unresolved. The helpers themselves have no file sink. Static evidence therefore
does not establish firmware-file export, but an untraced caller or indirect
consumer cannot be excluded.

**Separate updater UART sink:** the updater has conditional serial receive
handlers that call a fwrite-like wrapper in states 7 and 11. This is not a
`HidD_GetFeature` result path. The stream pointer and filename/open flow were
not recovered; the file gate is directly initialized to zero with no nonzero
direct `.text` store found, and the direct state graph has no path from its
initialized state into either sink subgraph. These facts show conditional
response-to-stream code, not an active firmware export. UART command meaning,
indirect initialization, and runtime reachability remain unresolved.

## What this establishes about a connected S98

**Proven:** the analyzed official feature-read implementations use active
feature-request writes before their reads. Update verifiers read bounded data
after staging writes and compare it against the host package in RAM. No
analyzed `HidD_GetFeature` path writes its return data to a firmware file.

**Inferred:** the updater's HID verification path is host-image-to-device
transfer followed by bounded response verification. The UART state-7/11
handlers may process chunked serial responses if their unresolved gates and
state setup are supplied.

**Unresolved:** whether command `0x88` returns flash contents, whether any
untraced caller requests a full firmware range, whether a separate indirect
or model-specific export exists, whether the UART stream code can be activated,
and which exact physical model/protocol is represented by the connected
`258A:0150` receiver. Static code cannot prove extraction impossible. It also
does not demonstrate a complete read-only export of the connected S98 firmware
or establish that such an export could be performed without modifying the
keyboard.

## Supporting evidence

- [4.06 G5 vtable audit](rk-406-cdevg5-vtable-audit.md)
- [4.6 GetFeature argument audit](rk-v4.6-hid-getfeature-argument-audit.md)
- [Main updater and firmware readback audit](rk-firmware-readback-audit.md)
- [Updater UART state map](rk-updater-uart-state-machine.md)
- 4.06 import/call xrefs: [`rk-native-api-xrefs.csv`](rk-native-api-xrefs.csv)
- 4.6 main-driver callsites: [`rk-v4.6-native-api-call-sites.csv`](rk-v4.6-native-api-call-sites.csv)
- Saved 4.06 static caller exports: `_rk_analysis/reports/DeviceDriver-hid-callers.txt` and `_rk_analysis/reports/Update-hid-callers.txt` (local analysis artifacts, not included in the public repository).
