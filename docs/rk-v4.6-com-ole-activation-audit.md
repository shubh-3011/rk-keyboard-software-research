# RK 4.6 COM/OLE activation callsite audit

## Scope and evidence

This static pass resolves the six `CoCreateInstance` / `CoGetClassObject`
callsites recorded for the 4.6-labeled `DeviceDriver.exe`. The inspected
executable is SHA-256
`8D8538DE3ADA5FCF80E00C13B364B17ACEFA708480E102EC1E6A0B1309639AE9`
(2,418,176 bytes). Addresses are virtual addresses in that image and match
[`rk-v4.6-native-api-call-sites.csv`](rk-v4.6-native-api-call-sites.csv).

The executable was not run for this audit. COM activation targets and nearby
call paths were identified from static disassembly and GUID arguments. The
results describe callsite intent, not successful runtime activation or device
behavior.

## Resolved callsites

| VA | Activation request | Context / outer | Recovered call path and interpretation |
| ---: | --- | --- | --- |
| `0x00404DF4` | CLSID Shell Link `{00021401-0000-0000-C000-000000000046}`, IID `IShellLinkW` `{000214F9-0000-0000-C000-000000000046}` | `CLSCTX_INPROC_SERVER` (`1`); outer `NULL` | Sets the target executable and `-s` arguments, optionally sets an icon, queries `IPersistFile`, and saves a shortcut. Its caller obtains CSIDL 7 (Startup); a sibling path deletes a shortcut there. This supports a host Startup-folder shortcut enable/disable path. The controlling UI field's meaning is not recovered. |
| `0x0043EBFD` | CLSID MMDeviceEnumerator `{BCDE0395-E52F-467C-8E3D-C4579291692E}`, IID `IMMDeviceEnumerator` `{A95664D2-9614-4F35-A746-DE8DB63617E6}` | `CLSCTX_ALL` (`0x17`); outer `NULL` | Gets the default render endpoint, activates `IAudioEndpointVolume` and `IAudioClient`, initializes loopback capture with stream flag `0x20000`, and requests `IAudioCaptureClient`. This is a host audio capture path. |
| `0x00461244` | Same MMDeviceEnumerator and `IMMDeviceEnumerator` pair | `CLSCTX_ALL` (`0x17`); outer `NULL` | Gets the default render/console endpoint and reads `IAudioEndpointVolume::GetMasterVolumeLevelScalar`. This is a Windows host-volume query; the callsite is not evidence of keyboard brightness control. |
| `0x00483496` | `CLSID_FileOpenDialog` `{DC1C5A9C-E88A-4DDE-A5A1-60F82A20AEF7}` or `CLSID_FileSaveDialog` `{C0B4E2F3-BA21-4773-8DBA-5E338BC946EB}`, IID `IFileDialog` `{42F85136-DB7E-439C-85F1-E4075D135FC8}` | `CLSCTX_INPROC_SERVER` (`1`); outer `NULL` | Follows `CoInitializeEx(NULL, COINIT_APARTMENTTHREADED)` at `0x0048344F`. A state field selects open versus save. The code queries `IFileDialogCustomize` `{E6FDD21A-163F-4975-9C8C-A69F1BA37034}` and advises an event sink. This is a Windows common-item dialog path. |
| `0x004B4052` | Caller-provided CLSID; IID `IClassFactory` | Caller-provided context and outer | Generic helper obtains a class factory. The class, runtime arguments, direct caller, and resulting operation remain unresolved. |
| `0x004B408C` | Caller-provided CLSID; IID `IClassFactory2` when a license BSTR is supplied | Caller-provided context and outer | The licensed branch calls through `IClassFactory2` / `CreateInstanceLic`. The shape is consistent with generic OLE licensing support, but no concrete class or feature is identified. |

No recovered callsite in this set directly identifies an RK keyboard transport
or device service. The Shell Link, audio, and file-dialog paths are host-side
Windows functionality. That conclusion is limited to these six static
callsites; indirect activation targets and runtime arguments are not fully
resolved.

## Version comparison and open questions

The 4.6 updater executable and `.upf` payload have the same hashes as their
4.06 counterparts in the package comparison, so this pass found no distinct
updater COM path to add. The generic factory helper still needs caller and
argument resolution, and the Startup shortcut's controlling UI state remains
unknown. None of those gaps establishes device access.

## Reproduction references

- Main executable: 4.6 package manifest and package snapshot.
- Callsite ledger: [`rk-v4.6-native-api-call-sites.csv`](rk-v4.6-native-api-call-sites.csv).
- Package/version comparison: [`rk-package-file-delta-v4.06-v4.6.md`](rk-package-file-delta-v4.06-v4.6.md).
- Static-only scope: no RK executable launch or keyboard interface access was
  part of this COM/OLE callsite review.
