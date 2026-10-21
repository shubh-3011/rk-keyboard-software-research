# RK 4.6 HID interface enumeration and rescan path

## Scope and evidence boundary

This report statically traces the HID interface rescan path in the 4.6-labeled
`DeviceDriver.exe` (2,418,176 bytes; SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`). The
file hash was rechecked locally. Addresses below are VAs for image base
`0x00400000` and were confirmed against GNU `objdump -d -Mintel` output from
that exact file.

The executable was not run. No HID interface, keyboard, updater, or bootloader
was opened, and no device communication was performed. The call path below is
static evidence; it does not prove Windows delivered the event, that an
enumeration succeeded, or that the enumerated interface was the user's S98.

## Rescan call path

The existing [root-seeded CFG audit](rk-v4.6-rooted-cfg-callgraph-audit.md#rooted-path-from-the-dialog-timer-to-hid-enumeration)
links the `COemDrvDlg` timer handler at `0x00449F80` to a table setup routine
at `0x004497C0`, which calls the HID enumerator at `0x00417330` (`0x00449F9F`
and `0x004497D6` are the direct callsites). Its companion
[`WM_DEVICECHANGE` trace](rk-v4.6-rooted-cfg-callgraph-audit.md#wm_devicechange-to-the-rescan-timer)
statically connects the notification handler at `0x00449DF0` to delayed
rescan timers. That handler checks the interface-path marker `pid&fa07` and,
for the recorded arrival/removal event values, schedules timer IDs `0x844`
and `0x845`; the timer handler routes the rescan timer through `0x004497C0`.
Timer delivery and branch execution were not observed.

## SetupAPI enumeration and per-interface path

At `0x0041734C`, a wrapper tail-jumps to `HID.DLL!HidD_GetHidGuid`. At
`0x0041735C`, `SetupDiGetClassDevsW` receives that GUID, null window and
enumerator arguments, and flags `0x12` (consistent with present HID device
interfaces). The code initializes an index to zero, calls
`SetupDiEnumDeviceInterfaces` at `0x00417380`, and passes each returned
interface record to helper `0x004173F0` at `0x00417396`. When the helper
returns zero, the loop increments the index and calls the enumerator again at
`0x004173AF`. The device-info set is destroyed on the normal end path at
`0x004173BA` or after a helper returns a nonzero object at `0x004173D5`.

For each interface, `0x004173F0` calls
`SetupDiGetDeviceInterfaceDetailW` through the loaded IAT pointer at
`0x00417421`, first with a null detail buffer and zero size to obtain the
required size. It allocates using helper `0x00575360`, writes detail
`cbSize = 6`, then calls the API again at `0x0041746F`. The resulting device
path is at the detail buffer's `+4` and is passed to `CreateFileW` at
`0x004174A1` or `0x004174B2`.

The two `CreateFileW` sites share these statically reconstructed arguments:

| Argument | Value/evidence |
| --- | --- |
| File name | Device-interface path at detail buffer `+4` |
| Desired access | `0x12019F` when global `0x00646BF0` is zero; otherwise `0` |
| Share mode | `3` |
| Security attributes | `NULL` |
| Creation disposition | `3` (`OPEN_EXISTING`) |
| Flags and attributes | `0` |
| Template handle | `NULL` |

The handle is rejected if it equals `INVALID_HANDLE_VALUE` at `0x004174BE`.
The meaning and runtime value of global `0x00646BF0` remain unknown; this
report records the two branches without assigning a product meaning to the
access-mask change.

## HID metadata, object creation, and cleanup

After a valid handle is returned, the helper calls:

1. `HidD_GetPreparsedData` at `0x004174CD` and checks its Boolean result at
   `0x004174D2`.
2. `HidD_GetAttributes` at `0x004174DC`.
3. `HidP_GetCaps` at `0x004174EB`; a successful status enters capability
   processing at `0x00417504`.

The code passes a local buffer to `HidD_GetAttributes`, but this helper does
not visibly branch on or compare a vendor/product ID from that buffer. The
capability path calls `HidP_GetSpecificButtonCaps` at `0x00417673` and
`HidP_GetSpecificValueCaps` at `0x004176A5` when the corresponding counts are
nonzero. It then searches a global record table through `0x00417300`, creates
or initializes an internal object at `0x00417534`, and copies HID capability
words into fields at offsets `+0x208` through `+0x224`.

The opened handle reaches `CloseHandle` at `0x00417597`; the allocated detail
buffer is released through `0x00575283` at `0x0041759E`. The failure branch
after `HidP_GetCaps` calls `HidD_FreePreparsedData` at `0x004174F9`. A matching
free is not visible on the successful branch within this helper, so its
successful-path lifetime is unresolved by this trace.

## What this establishes

**Proven statically:** this binary contains a timer-triggered rescan path, HID
GUID lookup, SetupAPI enumeration of present interfaces, device-path opens,
HID attribute/capability queries, and internal object construction based on
capability data. The exact imported callsites are also listed in the
[reconciled API ledger](rk-v4.6-native-api-call-sites-reconciled.csv).

**Still unresolved:** whether the rescan executes in a normal session; which
enumerated interface is accepted and how that maps to a profile/model; whether
any returned object represents the connected S98; the meaning of the access
mode global; and runtime success or device behavior. This does not establish
S98 identity, feature-report semantics, or firmware readback.

For the broader version comparison, see the
[4.06/4.6 enumeration handle-lifecycle crosswalk](rk-device-enumeration-handle-lifecycle-cross-version.md)
and the [full-suite gap matrix](reverse-engineering-gap-matrix-2026-10-19.md).
