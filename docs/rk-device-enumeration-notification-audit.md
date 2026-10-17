# RK HID enumeration and device-notification audit

## Scope and evidence

This note follows the installed `DeviceDriver.exe` enumeration and
hot-plug-notification paths to clarify three imports that appear in the
no-direct-callsite CSV. The working PE is byte-identical to the installed
4.06 main executable (SHA-256 in
[`rk-native-api-imports.md`](rk-native-api-imports.md)). The findings combine
the saved Ghidra decompilation and x86 instruction bytes. The program was not
run, no HID handle was opened, and no keyboard report was sent.

`rk-native-api-xrefs.csv` lists `SetupDiGetDeviceInterfaceDetailW`,
`RegisterDeviceNotificationW`, and `UnregisterDeviceNotification` without a
direct `call [IAT]` instruction. They are reachable through register-indirect
calls in the analyzed code. These examples show why “no direct callsite” is
not equivalent to “unused API.”

## Present HID-interface enumeration

`FUN_004164B0` obtains the HID interface GUID with `HidD_GetHidGuid`, then
calls `SetupDiGetClassDevsW` with a null enumerator/window and flags `0x12`.
These bits are `DIGCF_PRESENT` (`0x2`) and `DIGCF_DEVICEINTERFACE` (`0x10`),
which selects currently present devices that expose the requested interface
class. Windows documents those flag meanings in the
[`SetupDiGetClassDevsW` reference](https://learn.microsoft.com/en-us/windows/desktop/api/setupapi/nf-setupapi-setupdigetclassdevsw).

The function initializes `SP_DEVICE_INTERFACE_DATA.cbSize` to `0x1C`, starts
at member index zero, and loops over `SetupDiEnumDeviceInterfaces`. Each
interface is passed to `FUN_00416570`. The helper loads the IAT pointer for
`SetupDiGetDeviceInterfaceDetailW` into `EBP` at `0x00416580` and calls it
indirectly at `0x004165A1` and `0x004165EF`: first to obtain the required
detail-buffer size, then after allocating and initializing the detail buffer
to obtain the interface path. The parent enumeration function destroys the
device-information set on its normal and early-success exits.

The remainder of this path is covered in the main report: it opens matching
interface paths, queries HID attributes/preparsed data/capabilities, and
records descriptor metadata before the profile matcher selects a device
family. The binary's `CreateFileW` access mask includes read/write access;
that is a static code property and was not exercised in this audit.

## USB and HID hot-plug notification filters

`FUN_004466D7` calls `FUN_00446FC0` during main-window setup. Before the call,
it loads the window handle from object field `+0x20` into `EDI`. The
registration routine constructs two device-interface filters with `dbcc_size`
`0x20`, device type `5` (`DBT_DEVTYP_DEVICEINTERFACE`), and flags argument
`0`. The two embedded class GUIDs decode from `.rdata` as:

| Filter | GUID bytes in the PE | Windows interface class |
| --- | --- | --- |
| First filter | `A5DCBF10-6530-11D2-901F-00C04FB951ED` | `GUID_DEVINTERFACE_USB_DEVICE` |
| Second filter | `4D1E55B2-F16F-11CF-88CB-001111000030` | `GUID_DEVINTERFACE_HID` |

The first GUID is matched by Microsoft's
[`GUID_DEVINTERFACE_USB_DEVICE` definition](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/guid-devinterface-usb-device);
the second matches
[`GUID_DEVINTERFACE_HID`](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/guid-devinterface-hid).
Microsoft documents type 5 as a device-interface filter and flags `0` as
`DEVICE_NOTIFY_WINDOW_HANDLE`; the recipient is therefore interpreted as a
window handle from the callsite.
([filter structure](https://learn.microsoft.com/en-us/windows/win32/api/dbt/ns-dbt-dev_broadcast_deviceinterface_w),
[registration API](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-registerdevicenotificationw)).

The routine loads `RegisterDeviceNotificationW` from its IAT slot into `EBX`
and calls `EBX` twice, storing the returned notification handles in object
fields `+0x690` and `+0x694`. Cleanup helper `FUN_00446110` loads
`UnregisterDeviceNotification` into `EDI` and calls it once for each saved
handle. This statically resolves the import references at `0x00446FE8` and
`0x00446162` shown in the xref CSV.

## Device-change path

`FUN_00447591` contains branches on event values `0x8000` and `0x8004`,
which Windows defines as `DBT_DEVICEARRIVAL` and
`DBT_DEVICEREMOVECOMPLETE` in `WM_DEVICECHANGE` processing
([Microsoft event table](https://learn.microsoft.com/en-us/windows/win32/devio/wm-devicechange)).
It parses a device interface path into VID/PID on the ordinary branch, checks
known wireless/companion IDs or the configured profile table, and logs the
result as `IN` or `OUT`. A path branch beginning with the `HID` marker has an
additional `pid&fa07` string check and a global-state guard.

For arrival/removal events, if its rescan timer field is clear, the handler
sets a device-state value, invokes a removal helper on removal, starts
two-second and 500-millisecond timers, and calls `FUN_00446EE0` for follow-up
processing. These are code paths, not evidence that either notification was
received on this PC or that a particular keyboard was selected. The exact
message-map route is now identified statically: the RTTI-attributed
`COemDrvDlg` MFC map contains a `WM_DEVICECHANGE` (`0x0219`) entry at row
`0x005D4C50`, targeting handler entry `0x00447580`; the main body begins at
`FUN_00447591`. Its `WM_TIMER` entry is at `0x005D4C98` and targets
`0x00447710`, which handles the retry-state and `0x845` timer branches. See
the [full recovered MFC message-map audit](rk-mfc-message-map-audit.md).
Runtime registration success, event delivery, and timer cadence remain
unobserved.

## Updater HID notification

The bundled updater has a separate, direct registration path. Dialog setup
`FUN_00406FE0` obtains the HID GUID, constructs one filter with size `0x20`
and device type `5`, calls `RegisterDeviceNotificationW` at `0x004071FB`
with flags `0`, and stores the returned handle in dialog field `+0x8DEC`.
Unlike the main app, this filter uses only the HID interface GUID; no second
USB-device-class filter is built in this setup routine.

Updater handler `FUN_00409250` checks message ID `0x0219` (`WM_DEVICECHANGE`)
and event values `0x8000`/`0x8004`. On removal-complete, when its internal
busy/state field is clear, it attempts its report-size-specific HID
enumeration/open helpers for `0x408` and then `0x802` bytes. If both paths
fail, the static branch disables updater button `0x0419` and changes the
status control; if a path is available, it enables the upgrade button. Other
event handling reads the “Specify” VID/PID edit control and enters a path
validation/selection branch. The complete arrival branch and runtime control
state are not recovered here.

This updater-specific registration and event flow is distinct from the main
application's two class notifications. Static code shows how the updater
reacts to device changes but does not establish which device the user had
connected or whether any event occurred during this audit.

## Confidence and open points

- **Proven statically:** HID GUID acquisition; `SetupDiGetClassDevsW` flags
  `0x12`; interface enumeration; the two-stage indirect detail API calls;
  the two notification GUID byte sequences; two indirect registration calls;
  stored/removed handles; the updater's direct HID notification registration;
  its `WM_DEVICECHANGE` code path; event-value branches; timer/setup calls;
  and the main-app `COemDrvDlg` message-map entry to its device-change handler.
- **Inferred from Windows API definitions:** the symbolic GUID names, the
  device-interface filter interpretation, and that flag `0` means a window
  recipient. These interpretations are linked to Microsoft documentation.
- **Unresolved:** whether either program's notification registration
  succeeded at runtime, the observed cadence of follow-up enumeration, and
  how each discovered USB/HID collection maps to a physical RK
  keyboard/receiver.

The main app's registration is class-wide for USB and HID interface
notifications; the updater registers only the HID interface class. Neither
registration by itself identifies an RK model. Descriptor, ID, profile, and
family checks still govern the later selection path. See the
[main reverse-engineering report](reverse-engineering.md) for that matcher and
the [system API crosswalk](rk-system-api-crosswalk.md) for import-reference
coverage.
