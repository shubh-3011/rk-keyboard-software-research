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
| `0x004B4052` | Caller-provided CLSID; IID `IClassFactory` | Caller-provided context and outer | Generic helper obtains a class factory. Its six stack arguments and subsequent `IClassFactory::CreateInstance` call are detailed below. The class, runtime arguments, direct caller, and resulting operation remain unresolved. |
| `0x004B408C` | Caller-provided CLSID; IID `IClassFactory2` when a license BSTR is supplied | Caller-provided context and outer | The licensed branch calls `IClassFactory2::CreateInstanceLic`. This proves a generic licensed-activation path exists in the image; it does not identify a concrete class or feature. |

## Generic class-factory helper at `0x004B402C`

The inspected image's `.text` section was searched for relative `CALL` and
`JMP` encodings to `0x004B402C`, and the whole file was searched for an
embedded absolute pointer to that VA. Neither scan found a reference. The
disassembly also contains no direct call instruction naming the helper. Thus
no direct caller or static function-pointer registration was recovered. This
does not rule out a dynamically computed target or runtime callback; those
remain unresolved. The two `CoGetClassObject` xrefs in the API ledger are both
inside this helper.

At the x86 stack boundary, the helper consumes six 32-bit arguments and
returns with `ret 0x18`:

| Stack slot | Inferred parameter | Evidence / use |
| ---: | --- | --- |
| `[ebp+0x08]` | CLSID pointer | Passed as `rclsid` to both `CoGetClassObject` calls. The CLSID is caller supplied; no concrete value is embedded here. |
| `[ebp+0x0C]` | `pUnkOuter` | Passed to `IClassFactory::CreateInstance` or `IClassFactory2::CreateInstanceLic`. |
| `[ebp+0x10]` | `dwClsContext` | Passed as the class context to both `CoGetClassObject` calls. |
| `[ebp+0x14]` | Requested interface IID pointer | Passed to the selected factory's create-instance method. |
| `[ebp+0x18]` | Created-object output pointer | Passed as `ppvObject` to the selected factory method. |
| `[ebp+0x1C]` | Optional license BSTR, reused as the nonlicensed factory output slot | `SysStringLen` chooses the branch. In the empty-string branch this slot is zeroed and its address receives the `IClassFactory` pointer; in the licensed branch its BSTR value is passed as `bstrKey`. |

The empty-license branch calls `CoGetClassObject` with `IID_IClassFactory`
at VA `0x005CF4C4` (the standard IID bytes), `pvReserved = NULL`, and the
caller-supplied CLSID/context. On success it calls vtable offset `+0x0C`
(`IClassFactory::CreateInstance`) with the caller's outer object, requested
IID, and output pointer, then calls `Release` at `+0x08`.

The nonempty-license branch calls `CoGetClassObject` with `IID_IClassFactory2`
at VA `0x005CF3D4` (bytes `8F B2 96 B1 B4 BA 1A 10 B6 9C 00 AA 00 34 1D 07`),
again with `pvReserved = NULL` and caller-supplied CLSID/context. It then calls
vtable offset `+0x1C` (`IClassFactory2::CreateInstanceLic`), passing a null
reserved argument and the caller's BSTR license key, before releasing the
factory at `+0x08`. These call shapes establish generic COM activation and
licensing support only.

Because no caller edge was recovered, the concrete CLSID, context flags,
requested interface, license key source, caller resource/dialog, and the
created object's purpose cannot be tied to an RK device feature. The helper's
two embedded IIDs identify factory interfaces, not the product class being
created. A printable ASCII/UTF-16 scan found no class or license string that
identifies this path, and the resource/localization indexes do not link it to
a specific dialog; this is not proof that no indirect runtime association
exists.

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
